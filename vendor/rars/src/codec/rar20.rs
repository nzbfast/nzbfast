use super::match_index::MatchIndex;
use super::{huffman, Error, Result};
use std::io::{Read, Write};

const MAIN_COUNT: usize = 298;
const OFFSET_COUNT: usize = 48;
const LENGTH_SLOTS: usize = 28;
const LEVEL_COUNT: usize = 19;
const TABLE_COUNT: usize = MAIN_COUNT + OFFSET_COUNT + LENGTH_SLOTS;
const AUDIO_COUNT: usize = 257;
const MAX_CHANNELS: usize = 4;
const OLD_LEVEL_COUNT: usize = AUDIO_COUNT * MAX_CHANNELS;
const MAX_HISTORY: usize = 1024 * 1024;

const LENGTH_BASES: [usize; LENGTH_SLOTS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_BITS: [u8; LENGTH_SLOTS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const OFFSET_BASES: [usize; OFFSET_COUNT] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const OFFSET_BITS: [u8; OFFSET_COUNT] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
const SHORT_BASES: [usize; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];
const MAX_ENCODER_MATCH_OFFSET: usize = MAX_HISTORY;
const MAX_ENCODER_MATCH_LENGTH: usize = 258;
const MATCH_HASH_BUCKETS: usize = 4096;
const MAX_MATCH_CANDIDATES: usize = 256;

pub fn decode_rar20(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Rar20Decoder::new();
    decoder.decode_member(input, output_size)
}

pub fn encode_rar20_literals(input: &[u8]) -> Result<Vec<u8>> {
    encode_rar20_literals_with_options(input, EncodeOptions::default())
}

pub fn encode_rar20_literals_with_options(input: &[u8], options: EncodeOptions) -> Result<Vec<u8>> {
    encode_member(input, &[], None, options, None)
}

pub fn encode_rar20_auto(input: &[u8]) -> Result<Vec<u8>> {
    encode_rar20_auto_with_options(input, EncodeOptions::default())
}

pub fn encode_rar20_auto_with_options(input: &[u8], options: EncodeOptions) -> Result<Vec<u8>> {
    let lz = encode_rar20_literals_with_options(input, options)?;
    let mut best = lz;
    if options.try_audio {
        for channels in 1..=MAX_CHANNELS {
            if input.len() < channels * 64 {
                continue;
            }
            let audio = encode_audio_member(input, channels)?;
            if audio.len() < best.len() {
                best = audio;
            }
        }
    }
    Ok(best)
}

pub(crate) fn encode_rar20_auto_with_options_and_progress(
    input: &[u8],
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    let mut best = encode_member(input, &[], None, options, Some(progress))?;
    if options.try_audio {
        for channels in 1..=MAX_CHANNELS {
            if input.len() < channels * 64 {
                continue;
            }
            let audio = encode_audio_member(input, channels)?;
            if audio.len() < best.len() {
                best = audio;
            }
        }
    }
    Ok(best)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeOptions {
    pub max_match_candidates: usize,
    pub max_match_distance: usize,
    pub lazy_matching: bool,
    pub lazy_lookahead: usize,
    pub try_audio: bool,
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            lazy_matching: false,
            lazy_lookahead: 1,
            try_audio: true,
        }
    }

    pub const fn with_max_match_distance(mut self, distance: usize) -> Self {
        self.max_match_distance = if distance > MAX_ENCODER_MATCH_OFFSET {
            MAX_ENCODER_MATCH_OFFSET
        } else {
            distance
        };
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

    pub const fn with_try_audio(mut self, enabled: bool) -> Self {
        self.try_audio = enabled;
        self
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new(MAX_MATCH_CANDIDATES)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Rar20Encoder {
    history: Vec<u8>,
    table: Option<FixedEncodeTable>,
    options: EncodeOptions,
}

impl Rar20Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            history: Vec::new(),
            table: None,
            options,
        }
    }

    pub fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.encode_member_inner(input, None)
    }

    pub(crate) fn encode_member_with_progress(
        &mut self,
        input: &[u8],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        self.encode_member_inner(input, Some(progress))
    }

    fn encode_member_inner(
        &mut self,
        input: &[u8],
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let table = match self.table {
            Some(table) => table,
            None => {
                let table = FixedEncodeTable::new()?;
                self.table = Some(table);
                table
            }
        };
        let packed = encode_member(input, &self.history, Some(table), self.options, progress)?;
        self.remember(input);
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

fn encode_member(
    input: &[u8],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let tokens = match progress.as_mut() {
        Some(report) => {
            encode_tokens_with_progress(input, history, options, None, Some(&mut **report))?
        }
        None => encode_tokens_with_progress(input, history, options, None, None)?,
    };
    let table_lengths = table_lengths_for_tokens(&tokens, fixed_table)?;
    let packed = encode_member_with_tables(&tokens, history, fixed_table, &table_lengths)?;
    if fixed_table.is_some() {
        return Ok(packed);
    }

    let cost_model = CostModel::new(&table_lengths);
    let refined_tokens = match progress.as_mut() {
        Some(report) => encode_tokens_with_progress(
            input,
            history,
            options,
            Some(&cost_model),
            Some(&mut **report),
        )?,
        None => encode_tokens_with_progress(input, history, options, Some(&cost_model), None)?,
    };
    if refined_tokens == tokens {
        return Ok(packed);
    }
    let refined_table_lengths = table_lengths_for_tokens(&refined_tokens, fixed_table)?;
    let refined_packed = encode_member_with_tables(
        &refined_tokens,
        history,
        fixed_table,
        &refined_table_lengths,
    )?;
    if refined_packed.len() < packed.len() {
        Ok(refined_packed)
    } else {
        Ok(packed)
    }
}

fn table_lengths_for_tokens(
    tokens: &[PackedToken],
    fixed_table: Option<FixedEncodeTable>,
) -> Result<[u8; TABLE_COUNT]> {
    let mut main_frequencies = [0usize; MAIN_COUNT];
    let mut offset_frequencies = [0usize; OFFSET_COUNT];
    let mut length_frequencies = [0usize; LENGTH_SLOTS];
    for token in tokens {
        match token.view() {
            EncodeToken::Literal(byte) => main_frequencies[byte as usize] += 1,
            EncodeToken::RepeatLast => main_frequencies[256] += 1,
            EncodeToken::OldOffset {
                index,
                length,
                offset,
            } => {
                main_frequencies[257 + index] += 1;
                let (slot, _) = old_length_slot_for_match(length, offset)?;
                length_frequencies[slot] += 1;
            }
            EncodeToken::ShortOffset { offset } => {
                let (slot, _) = short_slot_for_match(offset)?;
                main_frequencies[261 + slot] += 1;
            }
            EncodeToken::Match { length, offset } => {
                let encoded_length = length.checked_sub(match_length_adjustment(offset)).ok_or(
                    Error::InvalidData("RAR 2.0 adjusted match length underflows"),
                )?;
                let (slot, _) = length_slot_for_match(encoded_length)?;
                main_frequencies[270 + slot] += 1;
                let (offset_slot, _) = offset_slot_for_match(offset)?;
                offset_frequencies[offset_slot] += 1;
            }
        }
    }
    let mut table_lengths = [0u8; TABLE_COUNT];
    let literal_len = if let Some(table) = fixed_table {
        table.length
    } else {
        let main_symbol_count = main_frequencies
            .iter()
            .filter(|&&frequency| frequency != 0)
            .count()
            + offset_frequencies
                .iter()
                .filter(|&&frequency| frequency != 0)
                .count()
            + length_frequencies
                .iter()
                .filter(|&&frequency| frequency != 0)
                .count();
        literal_code_len(main_symbol_count)?
    };

    if fixed_table.is_some() {
        for len in &mut table_lengths[..256] {
            *len = literal_len;
        }
        table_lengths[256] = literal_len;
        for len in &mut table_lengths[270..270 + LENGTH_SLOTS] {
            *len = literal_len;
        }
        for len in &mut table_lengths[257..269] {
            *len = literal_len;
        }
        for len in &mut table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT] {
            *len = literal_len;
        }
        for len in &mut table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT] {
            *len = literal_len;
        }
    } else {
        table_lengths[..MAIN_COUNT]
            .copy_from_slice(&validated_lengths_for_frequencies(&main_frequencies, 15));
        table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT]
            .copy_from_slice(&validated_lengths_for_frequencies(&offset_frequencies, 15));
        table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT]
            .copy_from_slice(&validated_lengths_for_frequencies(&length_frequencies, 15));
    }
    Ok(table_lengths)
}

fn encode_member_with_tables(
    tokens: &[PackedToken],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    table_lengths: &[u8; TABLE_COUNT],
) -> Result<Vec<u8>> {
    let level_tokens = encode_table_level_tokens(table_lengths);
    let level_lengths = level_code_lengths_for_tokens(&level_tokens);
    let level_codes = canonical_codes(&level_lengths)?;
    let main_codes = canonical_codes(&table_lengths[..MAIN_COUNT])?;

    let mut bits = BitWriter::default();
    if fixed_table.is_none() || history.is_empty() {
        bits.write_bits(0, 2); // LZ block, do not keep previous tables.
        for &len in &level_lengths {
            bits.write_bits(len as u32, 4);
        }
        for token in level_tokens {
            let code = level_codes[token.symbol].ok_or(Error::InvalidData(
                "RAR 2.0 encoder missing level Huffman code",
            ))?;
            bits.write_bits(code.code as u32, code.len);
            if token.extra_bits != 0 {
                bits.write_bits(token.extra_value as u32, token.extra_bits);
            }
        }
    }
    let offset_codes = canonical_codes(&table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT])?;
    let length_codes = canonical_codes(&table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT])?;
    for token in tokens {
        match token.view() {
            EncodeToken::Literal(byte) => {
                let code = main_codes[byte as usize].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing literal Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
            }
            EncodeToken::RepeatLast => {
                let code = main_codes[256].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing repeat-last Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
            }
            EncodeToken::OldOffset {
                index,
                length,
                offset,
            } => {
                let code = main_codes[257 + index].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing old-offset Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                let (slot, extra) = old_length_slot_for_match(length, offset)?;
                let length_code = length_codes[slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing old-offset length Huffman code",
                ))?;
                bits.write_bits(length_code.code as u32, length_code.len);
                if LENGTH_BITS[slot] != 0 {
                    bits.write_bits(extra as u32, LENGTH_BITS[slot]);
                }
            }
            EncodeToken::ShortOffset { offset } => {
                let (slot, extra) = short_slot_for_match(offset)?;
                let code = main_codes[261 + slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing short-offset Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                if SHORT_BITS[slot] != 0 {
                    bits.write_bits(extra as u32, SHORT_BITS[slot]);
                }
            }
            EncodeToken::Match { length, offset } => {
                let encoded_length = length.checked_sub(match_length_adjustment(offset)).ok_or(
                    Error::InvalidData("RAR 2.0 adjusted match length underflows"),
                )?;
                let (slot, extra) = length_slot_for_match(encoded_length)?;
                let code = main_codes[270 + slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing match Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                if LENGTH_BITS[slot] != 0 {
                    bits.write_bits(extra as u32, LENGTH_BITS[slot]);
                }
                let (offset_slot, offset_extra) = offset_slot_for_match(offset)?;
                let offset = offset_codes[offset_slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing offset Huffman code",
                ))?;
                bits.write_bits(offset.code as u32, offset.len);
                if OFFSET_BITS[offset_slot] != 0 {
                    bits.write_bits(offset_extra as u32, OFFSET_BITS[offset_slot]);
                }
            }
        }
    }
    Ok(bits.finish())
}

#[derive(Debug, Clone, Copy)]
struct FixedEncodeTable {
    length: u8,
}

impl FixedEncodeTable {
    fn new() -> Result<Self> {
        Ok(Self {
            length: literal_code_len(256 + LENGTH_SLOTS + OFFSET_COUNT)?,
        })
    }
}

/// What one planned token means, as the consumers read it.
///
/// Never stored: the planner keeps [`PackedToken`], and this is the view it
/// hands out one token at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodeToken {
    Literal(u8),
    RepeatLast,
    OldOffset {
        index: usize,
        length: usize,
        offset: usize,
    },
    ShortOffset {
        offset: usize,
    },
    Match {
        length: usize,
        offset: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Literal,
    RepeatLast,
    OldOffset,
    ShortOffset,
    Match,
}

/// One planned token in eight bytes.
///
/// The planner holds one of these per literal or match for the whole
/// member, and [`encode_member`] holds two such vectors at once while it
/// compares a refined plan with its first, so this struct's width IS the
/// planner's per-input-byte cost. It was five `usize` words - 32 bytes, 64
/// with both vectors live - until 16 Sep 2026.
///
/// Each field is as wide as the planner's own limits need and no wider.
/// `index` carries either a literal byte or an old-offset slot 0..=3;
/// `length` is capped at [`MAX_ENCODER_MATCH_LENGTH`] by every `max_length`
/// the search computes; `offset` at [`MAX_ENCODER_MATCH_OFFSET`], which
/// [`EncodeOptions::with_max_match_distance`] clamps to and which
/// `best_old_offset_match` inherits by only ever replaying an offset an
/// earlier match already passed. The constructors `debug_assert` all three,
/// so a planner change that broke one would fail the debug test suites
/// rather than truncate quietly.
///
/// Every field a token does not use is zero. That is what lets the derived
/// equality stand in for the view's: `encode_member` compares two whole
/// plans with `==`, and two packed tokens are equal exactly when their
/// views are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PackedToken {
    kind: TokenKind,
    index: u8,
    length: u16,
    offset: u32,
}

impl PackedToken {
    fn literal(byte: u8) -> Self {
        Self {
            kind: TokenKind::Literal,
            index: byte,
            length: 0,
            offset: 0,
        }
    }

    fn repeat_last() -> Self {
        Self {
            kind: TokenKind::RepeatLast,
            index: 0,
            length: 0,
            offset: 0,
        }
    }

    fn old_offset(index: usize, length: usize, offset: usize) -> Self {
        debug_assert!(index < 4, "old-offset slot {index} is out of range");
        Self {
            kind: TokenKind::OldOffset,
            index: index as u8,
            length: packed_length(length),
            offset: packed_offset(offset),
        }
    }

    fn short_offset(offset: usize) -> Self {
        Self {
            kind: TokenKind::ShortOffset,
            index: 0,
            length: 0,
            offset: packed_offset(offset),
        }
    }

    fn match_at(length: usize, offset: usize) -> Self {
        Self {
            kind: TokenKind::Match,
            index: 0,
            length: packed_length(length),
            offset: packed_offset(offset),
        }
    }

    fn view(self) -> EncodeToken {
        match self.kind {
            TokenKind::Literal => EncodeToken::Literal(self.index),
            TokenKind::RepeatLast => EncodeToken::RepeatLast,
            TokenKind::OldOffset => EncodeToken::OldOffset {
                index: self.index as usize,
                length: self.length as usize,
                offset: self.offset as usize,
            },
            TokenKind::ShortOffset => EncodeToken::ShortOffset {
                offset: self.offset as usize,
            },
            TokenKind::Match => EncodeToken::Match {
                length: self.length as usize,
                offset: self.offset as usize,
            },
        }
    }
}

fn packed_length(length: usize) -> u16 {
    debug_assert!(
        length <= MAX_ENCODER_MATCH_LENGTH,
        "match length {length} is out of range"
    );
    length as u16
}

fn packed_offset(offset: usize) -> u32 {
    debug_assert!(
        offset <= MAX_ENCODER_MATCH_OFFSET,
        "match offset {offset} is out of range"
    );
    offset as u32
}

#[cfg(test)]
fn encode_tokens(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    cost_model: Option<&CostModel>,
) -> Vec<PackedToken> {
    encode_tokens_with_progress(input, history, options, cost_model, None)
        .expect("encoding without cancellation cannot be cancelled")
}

fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    cost_model: Option<&CostModel>,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<PackedToken>> {
    let mut tokens = Vec::new();
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let mut combined = Vec::with_capacity(history.len() + input.len());
    combined.extend_from_slice(history);
    combined.extend_from_slice(input);
    let mut buckets = MatchIndex::new(
        MATCH_HASH_BUCKETS,
        combined.len(),
        options.max_match_candidates,
    );
    for history_pos in 0..history.len().saturating_sub(2) {
        insert_match_position(&combined, history_pos, &mut buckets);
    }

    let mut pos = history.len();
    let end = combined.len();
    let mut last_match = None;
    let mut old_offsets = [0usize; 4];
    let mut next_report = 0usize;
    while pos < end {
        let selected = select_match(
            &combined,
            pos,
            end,
            &buckets,
            options,
            &old_offsets,
            cost_model,
        );
        if let Some(selected) = selected {
            let lazy = LazyMatchContext {
                input: &combined,
                end,
                buckets: &buckets,
                options,
                old_offsets: &old_offsets,
                cost_model,
            };
            if should_lazy_emit_literal(pos, selected, lazy) {
                tokens.push(PackedToken::literal(combined[pos]));
                insert_match_position(&combined, pos, &mut buckets);
                pos += 1;
                continue;
            }
            let (length, offset) = match selected {
                SelectedMatch::Fresh { length, offset } => {
                    if last_match == Some((length, offset)) {
                        tokens.push(PackedToken::repeat_last());
                    } else {
                        tokens.push(PackedToken::match_at(length, offset));
                        last_match = Some((length, offset));
                    }
                    (length, offset)
                }
                SelectedMatch::OldOffset {
                    index,
                    length,
                    offset,
                } => {
                    if last_match == Some((length, offset)) {
                        tokens.push(PackedToken::repeat_last());
                    } else {
                        tokens.push(PackedToken::old_offset(index, length, offset));
                        last_match = Some((length, offset));
                    }
                    (length, offset)
                }
                SelectedMatch::ShortOffset { offset } => {
                    let length = 2;
                    tokens.push(PackedToken::short_offset(offset));
                    last_match = Some((length, offset));
                    (length, offset)
                }
            };
            push_old_offset(&mut old_offsets, offset);
            for history_pos in pos..pos + length {
                insert_match_position(&combined, history_pos, &mut buckets);
            }
            pos += length;
        } else {
            tokens.push(PackedToken::literal(combined[pos]));
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

#[derive(Debug, Clone, Copy)]
struct CostModel<'a> {
    main: &'a [u8],
    offsets: &'a [u8],
    lengths: &'a [u8],
}

impl<'a> CostModel<'a> {
    fn new(table_lengths: &'a [u8; TABLE_COUNT]) -> Self {
        Self {
            main: &table_lengths[..MAIN_COUNT],
            offsets: &table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT],
            lengths: &table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT],
        }
    }

    fn selected_cost(self, selected: SelectedMatch) -> Option<usize> {
        match selected {
            SelectedMatch::Fresh { length, offset } => {
                let encoded_length = length.checked_sub(match_length_adjustment(offset))?;
                let (length_slot, _) = length_slot_for_match(encoded_length).ok()?;
                let (offset_slot, _) = offset_slot_for_match(offset).ok()?;
                Some(
                    usize::from(self.main[270 + length_slot])
                        + usize::from(LENGTH_BITS[length_slot])
                        + usize::from(self.offsets[offset_slot])
                        + usize::from(OFFSET_BITS[offset_slot]),
                )
            }
            SelectedMatch::OldOffset {
                index,
                length,
                offset,
            } => {
                let (length_slot, _) = old_length_slot_for_match(length, offset).ok()?;
                Some(
                    usize::from(self.main[257 + index])
                        + usize::from(self.lengths[length_slot])
                        + usize::from(LENGTH_BITS[length_slot]),
                )
            }
            SelectedMatch::ShortOffset { offset } => {
                let (slot, _) = short_slot_for_match(offset).ok()?;
                Some(usize::from(self.main[261 + slot]) + usize::from(SHORT_BITS[slot]))
            }
        }
    }

    fn selected_score(self, selected: SelectedMatch) -> Option<isize> {
        let cost = self.selected_cost(selected)?;
        Some(selected.length() as isize * 8 - cost as isize)
    }
}

#[derive(Debug, Clone, Copy)]
enum SelectedMatch {
    Fresh {
        length: usize,
        offset: usize,
    },
    OldOffset {
        index: usize,
        length: usize,
        offset: usize,
    },
    ShortOffset {
        offset: usize,
    },
}

impl SelectedMatch {
    fn length(self) -> usize {
        match self {
            SelectedMatch::Fresh { length, .. } | SelectedMatch::OldOffset { length, .. } => length,
            SelectedMatch::ShortOffset { .. } => 2,
        }
    }

    fn score(self) -> isize {
        let length_score = self.length() as isize * 8;
        let cost = match self {
            SelectedMatch::OldOffset { .. } | SelectedMatch::ShortOffset { .. } => 4,
            SelectedMatch::Fresh { offset, .. } => 8 + OFFSET_BITS[offset_slot_index(offset)],
        };
        length_score - isize::from(cost)
    }
}

fn select_match(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &MatchIndex,
    options: EncodeOptions,
    old_offsets: &[usize; 4],
    cost_model: Option<&CostModel<'_>>,
) -> Option<SelectedMatch> {
    let fresh = best_match(input, pos, end, buckets, options, cost_model)
        .map(|(length, offset)| SelectedMatch::Fresh { length, offset });
    let old = best_old_offset_match(input, pos, end, old_offsets, cost_model).map(
        |(index, length, offset)| SelectedMatch::OldOffset {
            index,
            length,
            offset,
        },
    );
    if let Some(cost_model) = cost_model {
        return [fresh, old, best_short_offset_match(input, pos, end)]
            .into_iter()
            .flatten()
            .max_by_key(|&selected| {
                (
                    cost_model.selected_score(selected).unwrap_or(isize::MIN),
                    selected.length(),
                )
            });
    }

    let fresh = fresh.and_then(|selected| match selected {
        SelectedMatch::Fresh { length, offset } => Some((length, offset)),
        _ => None,
    });
    let old = old.and_then(|selected| match selected {
        SelectedMatch::OldOffset {
            index,
            length,
            offset,
        } => Some((index, length, offset)),
        _ => None,
    });
    match (fresh, old) {
        (Some((fresh_length, _)), Some((index, old_length, old_offset)))
            if old_length + 1 >= fresh_length =>
        {
            Some(SelectedMatch::OldOffset {
                index,
                length: old_length,
                offset: old_offset,
            })
        }
        (Some((length, offset)), _) => Some(SelectedMatch::Fresh { length, offset }),
        (None, Some((index, length, offset))) => Some(SelectedMatch::OldOffset {
            index,
            length,
            offset,
        }),
        (None, None) => best_short_offset_match(input, pos, end),
    }
}

struct LazyMatchContext<'a> {
    input: &'a [u8],
    end: usize,
    buckets: &'a MatchIndex,
    options: EncodeOptions,
    old_offsets: &'a [usize; 4],
    cost_model: Option<&'a CostModel<'a>>,
}

fn should_lazy_emit_literal(
    pos: usize,
    current: SelectedMatch,
    context: LazyMatchContext<'_>,
) -> bool {
    if !context.options.lazy_matching || pos + 1 >= context.end {
        return false;
    }
    let lookahead = context.options.lazy_lookahead.max(1);
    (1..=lookahead)
        .take_while(|offset| pos + offset < context.end)
        .any(|offset| {
            select_match(
                context.input,
                pos + offset,
                context.end,
                context.buckets,
                context.options,
                context.old_offsets,
                context.cost_model,
            )
            .is_some_and(|next| {
                let current_score = context
                    .cost_model
                    .and_then(|cost_model| cost_model.selected_score(current))
                    .unwrap_or_else(|| current.score());
                let next_score = context
                    .cost_model
                    .and_then(|cost_model| cost_model.selected_score(next))
                    .unwrap_or_else(|| next.score());
                let skipped_literal_score = offset as isize * 8;
                next_score > current_score + skipped_literal_score
            })
        })
}

fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &MatchIndex,
    options: EncodeOptions,
    cost_model: Option<&CostModel<'_>>,
) -> Option<(usize, usize)> {
    let max_offset = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0
        || max_offset == 0
        || max_length < 3
        || pos + 2 >= input.len()
    {
        return None;
    }
    let mut best = None;
    let mut checked = 0usize;
    for candidate in buckets.candidates(match_hash(input, pos)) {
        if candidate >= pos {
            continue;
        }
        let offset = pos - candidate;
        if offset > max_offset {
            break;
        }
        checked += 1;
        let mut length = 0usize;
        while length < max_length && input[pos + length] == input[pos + length - offset] {
            length += 1;
        }
        let encodable = length >= 3 + match_length_adjustment(offset);
        if encodable && is_better_fresh_match(cost_model, length, offset, best) {
            best = Some((length, offset));
            if length == max_length {
                break;
            }
        }
        if checked >= options.max_match_candidates {
            break;
        }
    }
    best
}

fn offset_slot_index(offset: usize) -> usize {
    offset_slot_for_match(offset)
        .map(|(slot, _)| slot)
        .unwrap_or(OFFSET_BITS.len() - 1)
}

fn is_better_fresh_match(
    cost_model: Option<&CostModel<'_>>,
    length: usize,
    offset: usize,
    best: Option<(usize, usize)>,
) -> bool {
    let Some((best_length, best_offset)) = best else {
        return true;
    };
    if let Some(cost_model) = cost_model {
        let candidate = SelectedMatch::Fresh { length, offset };
        let best = SelectedMatch::Fresh {
            length: best_length,
            offset: best_offset,
        };
        let candidate_score = cost_model.selected_score(candidate).unwrap_or(isize::MIN);
        let best_score = cost_model.selected_score(best).unwrap_or(isize::MIN);
        return candidate_score > best_score
            || (candidate_score == best_score
                && (length > best_length || (length == best_length && offset < best_offset)));
    }
    length > best_length || (length == best_length && offset < best_offset)
}

fn best_old_offset_match(
    input: &[u8],
    pos: usize,
    end: usize,
    old_offsets: &[usize; 4],
    cost_model: Option<&CostModel<'_>>,
) -> Option<(usize, usize, usize)> {
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    let mut best = None;
    for (index, &offset) in old_offsets.iter().enumerate() {
        if offset == 0 || offset > pos {
            continue;
        }
        let length = match_length_at_offset(input, pos, max_length, offset);
        if old_length_slot_for_match(length, offset).is_ok()
            && is_better_old_offset_match(cost_model, index, length, offset, best)
        {
            best = Some((index, length, offset));
        }
    }
    best
}

fn is_better_old_offset_match(
    cost_model: Option<&CostModel<'_>>,
    index: usize,
    length: usize,
    offset: usize,
    best: Option<(usize, usize, usize)>,
) -> bool {
    let Some((best_index, best_length, best_offset)) = best else {
        return true;
    };
    if let Some(cost_model) = cost_model {
        let candidate = SelectedMatch::OldOffset {
            index,
            length,
            offset,
        };
        let best = SelectedMatch::OldOffset {
            index: best_index,
            length: best_length,
            offset: best_offset,
        };
        let candidate_score = cost_model.selected_score(candidate).unwrap_or(isize::MIN);
        let best_score = cost_model.selected_score(best).unwrap_or(isize::MIN);
        return candidate_score > best_score
            || (candidate_score == best_score
                && (length > best_length || (length == best_length && offset < best_offset)));
    }
    length > best_length || (length == best_length && offset < best_offset)
}

fn best_short_offset_match(input: &[u8], pos: usize, end: usize) -> Option<SelectedMatch> {
    if end - pos < 2 {
        return None;
    }
    let max_offset = pos.min(256);
    (1..=max_offset)
        .find(|&offset| {
            input[pos] == input[pos - offset] && input[pos + 1] == input[pos + 1 - offset]
        })
        .map(|offset| SelectedMatch::ShortOffset { offset })
}

fn match_length_at_offset(input: &[u8], pos: usize, max_length: usize, offset: usize) -> usize {
    let mut length = 0usize;
    while length < max_length && input[pos + length] == input[pos + length - offset] {
        length += 1;
    }
    length
}

fn match_length_adjustment(offset: usize) -> usize {
    usize::from(offset >= 0x2000) + usize::from(offset >= 0x40000)
}

fn old_length_adjustment(offset: usize) -> usize {
    usize::from(offset >= 0x101) + usize::from(offset >= 0x2000) + usize::from(offset >= 0x40000)
}

fn push_old_offset(old_offsets: &mut [usize; 4], offset: usize) {
    old_offsets[3] = old_offsets[2];
    old_offsets[2] = old_offsets[1];
    old_offsets[1] = old_offsets[0];
    old_offsets[0] = offset;
}

fn insert_match_position(input: &[u8], pos: usize, buckets: &mut MatchIndex) {
    if pos + 2 < input.len() {
        buckets.insert(pos, match_hash(input, pos));
    }
}

fn match_hash(input: &[u8], pos: usize) -> usize {
    let value =
        ((input[pos] as usize) << 8) ^ ((input[pos + 1] as usize) << 4) ^ input[pos + 2] as usize;
    value & (MATCH_HASH_BUCKETS - 1)
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 3 {
        return Err(Error::InvalidData("RAR 2.0 match length is too short"));
    }
    let adjusted = length - 3;
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData("RAR 2.0 match length is too long"))
}

fn old_length_slot_for_match(length: usize, offset: usize) -> Result<(usize, usize)> {
    let encoded = length
        .checked_sub(old_length_adjustment(offset))
        .ok_or(Error::InvalidData(
            "RAR 2.0 adjusted old-offset length underflows",
        ))?;
    if encoded < 2 {
        return Err(Error::InvalidData(
            "RAR 2.0 old-offset match length is too short",
        ));
    }
    let adjusted = encoded - 2;
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData(
        "RAR 2.0 old-offset match length is too long",
    ))
}

fn offset_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 {
        return Err(Error::InvalidData("RAR 2.0 match offset is zero"));
    }
    let adjusted = offset - 1;
    for (slot, &base) in OFFSET_BASES.iter().enumerate() {
        let extra_bits = OFFSET_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData("RAR 2.0 match offset is too large"))
}

fn short_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 || offset > 256 {
        return Err(Error::InvalidData(
            "RAR 2.0 short match offset is out of range",
        ));
    }
    let adjusted = offset - 1;
    for (slot, &base) in SHORT_BASES.iter().enumerate() {
        let extra_bits = SHORT_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData(
        "RAR 2.0 short match offset is out of range",
    ))
}

fn literal_code_len(symbol_count: usize) -> Result<u8> {
    if symbol_count == 0 {
        return Err(Error::InvalidData("RAR 2.0 encoder has no literal symbols"));
    }
    let len = usize::BITS - (symbol_count - 1).leading_zeros();
    u8::try_from(len.max(1)).map_err(|_| Error::InvalidData("RAR 2.0 literal table is too large"))
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

    const fn repeat_previous(count: usize) -> Self {
        Self {
            symbol: 16,
            extra_bits: 2,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_short(count: usize) -> Self {
        Self {
            symbol: 17,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_long(count: usize) -> Self {
        Self {
            symbol: 18,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }
}

fn encode_table_level_tokens(lengths: &[u8; TABLE_COUNT]) -> Vec<LevelToken> {
    encode_level_tokens(lengths)
}

fn encode_level_tokens(lengths: &[u8]) -> Vec<LevelToken> {
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
            let mut remaining = run;
            while remaining != 0 {
                let chunk = remaining.min(6);
                if chunk >= 3 {
                    tokens.push(LevelToken::repeat_previous(chunk));
                    remaining -= chunk;
                } else {
                    tokens.extend(std::iter::repeat_n(
                        LevelToken::plain(value as usize),
                        chunk,
                    ));
                    remaining = 0;
                }
            }
            pos += run;
            continue;
        }

        tokens.push(LevelToken::plain(value as usize));
        previous = Some(value);
        pos += 1;
    }
    tokens
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

fn level_code_lengths_for_tokens(tokens: &[LevelToken]) -> [u8; LEVEL_COUNT] {
    let mut used = [false; LEVEL_COUNT];
    for token in tokens {
        used[token.symbol] = true;
    }
    level_code_lengths_for_used_symbols(used)
}

fn validated_lengths_for_frequencies<const N: usize>(
    frequencies: &[usize; N],
    max_bits: u8,
) -> [u8; N] {
    let mut lengths = [0u8; N];
    lengths.copy_from_slice(&huffman::lengths_for_frequencies(frequencies, max_bits));
    if canonical_codes(&lengths).is_ok() {
        return lengths;
    }

    lengths.copy_from_slice(&huffman::uniform_lengths_for_frequencies(frequencies));
    lengths
}

fn encode_audio_member(input: &[u8], channels: usize) -> Result<Vec<u8>> {
    if channels == 0 || channels > MAX_CHANNELS {
        return Err(Error::InvalidData("RAR 2.0 audio channel count is invalid"));
    }
    let mut deltas = vec![0u8; input.len()];
    AudioModel::fresh().bytes_to_residuals(input, &mut deltas, 0, channels);
    let mut levels = vec![0u8; AUDIO_COUNT * channels];
    for channel in 0..channels {
        let mut frequencies = [0usize; AUDIO_COUNT];
        for index in (channel..deltas.len()).step_by(channels) {
            frequencies[deltas[index] as usize] += 1;
        }
        let channel_lengths = huffman::lengths_for_frequency_array(&frequencies, 15);
        for (symbol, len) in channel_lengths.into_iter().enumerate() {
            levels[channel * AUDIO_COUNT + symbol] = len;
        }
    }

    let level_symbols = encode_audio_table_level_symbols(&levels);
    let level_lengths = level_code_lengths_for_symbols(&level_symbols);
    let level_codes = canonical_codes(&level_lengths)?;
    let mut bits = BitWriter::default();
    bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
    bits.write_bits((channels - 1) as u32, 2);
    for &len in &level_lengths {
        bits.write_bits(len as u32, 4);
    }
    for symbol in level_symbols {
        let code = level_codes[symbol].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing audio-level Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
        match symbol {
            17 => bits.write_bits(0, 3),
            18 => bits.write_bits(127, 7),
            _ => {}
        }
    }

    for channel in 0..channels {
        let table = &levels[channel * AUDIO_COUNT..(channel + 1) * AUDIO_COUNT];
        validate_audio_table(table)?;
    }
    let audio_codes = (0..channels)
        .map(|channel| canonical_codes(&levels[channel * AUDIO_COUNT..(channel + 1) * AUDIO_COUNT]))
        .collect::<Result<Vec<_>>>()?;
    for (index, &delta) in deltas.iter().enumerate() {
        let channel = index % channels;
        let code = audio_codes[channel][delta as usize].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing audio Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
    }
    Ok(bits.finish())
}

fn encode_audio_table_level_symbols(levels: &[u8]) -> Vec<usize> {
    levels.iter().map(|&len| len as usize).collect()
}

fn level_code_lengths_for_symbols(symbols: &[usize]) -> [u8; LEVEL_COUNT] {
    let mut used = [false; LEVEL_COUNT];
    for &symbol in symbols {
        used[symbol] = true;
    }
    level_code_lengths_for_used_symbols(used)
}

fn level_code_lengths_for_used_symbols(used: [bool; LEVEL_COUNT]) -> [u8; LEVEL_COUNT] {
    let used_count = used.iter().filter(|&&used| used).count();
    let len = huffman::bits_for_symbol_count(used_count);
    let mut lengths = [0u8; LEVEL_COUNT];
    for (symbol, is_used) in used.into_iter().enumerate() {
        if is_used {
            lengths[symbol] = len;
        }
    }
    lengths
}

fn validate_audio_table(lengths: &[u8]) -> Result<()> {
    let mut count = [0u16; 16];
    for &len in lengths {
        if len > 15 {
            return Err(Error::InvalidData("RAR 2.0 Huffman length is too large"));
        }
        if len != 0 {
            count[len as usize] += 1;
        }
    }
    validate_huffman_counts(&count)
}

#[derive(Debug, Clone, Copy)]
struct HuffmanCode {
    code: u16,
    len: u8,
}

fn canonical_codes(lengths: &[u8]) -> Result<Vec<Option<HuffmanCode>>> {
    let mut count = [0u16; 16];
    for &len in lengths {
        if len > 15 {
            return Err(Error::InvalidData("RAR 2.0 Huffman length is too large"));
        }
        if len != 0 {
            count[len as usize] += 1;
        }
    }
    validate_huffman_counts(&count)?;

    let mut next_code = [0u16; 16];
    let mut code = 0u16;
    for len in 1..=15 {
        code = (code + count[len - 1]) << 1;
        next_code[len] = code;
    }

    let mut codes = vec![None; lengths.len()];
    for (symbol, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let code = next_code[len as usize];
        next_code[len as usize] += 1;
        codes[symbol] = Some(HuffmanCode { code, len });
    }
    Ok(codes)
}

#[derive(Debug, Clone)]
pub struct Rar20Decoder {
    bits: BitReader,
    levels: [u8; OLD_LEVEL_COUNT],
    main: Huffman,
    offsets: Huffman,
    lengths: Huffman,
    audio_tables: [Huffman; MAX_CHANNELS],
    audio_block: bool,
    channels: usize,
    cur_channel: usize,
    audio_model: AudioModel,
    old_offsets: [usize; 4],
    last_offset: usize,
    previous_match_length: usize,
    pending_match: Option<(usize, usize)>,
    in_block: bool,
    output: Vec<u8>,
    base_offset: usize,
}

impl Rar20Decoder {
    pub fn new() -> Self {
        Self {
            bits: BitReader::new(),
            levels: [0; OLD_LEVEL_COUNT],
            main: Huffman::empty(),
            offsets: Huffman::empty(),
            lengths: Huffman::empty(),
            audio_tables: std::array::from_fn(|_| Huffman::empty()),
            audio_block: false,
            channels: 1,
            cur_channel: 0,
            audio_model: AudioModel::fresh(),
            old_offsets: [0; 4],
            last_offset: 0,
            previous_match_length: 0,
            pending_match: None,
            in_block: false,
            output: Vec::new(),
            base_offset: 0,
        }
    }

    pub fn decode_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.0 output size overflows"))?;
        if !input.is_empty() {
            self.bits = BitReader::new();
        }
        self.bits.append(input);
        self.decode_until(target).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
            error => error,
        })?;
        self.take_trailing_table_switch()?;
        let out = self.raw_range(start, target)?.to_vec();
        self.trim_history(target, target);
        Ok(out)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        let decoded = self.decode_member(input, output_size)?;
        out.write_all(&decoded)
            .map_err(|_| Error::InvalidData("RAR 2.0 output write failed"))
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.0 output size overflows"))?;
        self.bits = BitReader::new();
        let mut packed = Vec::new();
        input
            .read_to_end(&mut packed)
            .map_err(|_| Error::InvalidData("RAR 2.0 input read failed"))?;
        self.bits.append(&packed);
        if !self.in_block && self.bits.remaining_bytes_from_current() > 0 {
            self.read_code_length_tables()
                .map_err(|error| match error {
                    Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
                    error => error,
                })?;
            self.in_block = true;
        }
        self.decode_until(target).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
            error => error,
        })?;
        self.take_trailing_table_switch()?;

        let decoded = self.raw_range(start, target)?;
        out.write_all(decoded)
            .map_err(|_| Error::InvalidData("RAR 2.0 output write failed"))?;
        self.trim_history(target, target);
        Ok(())
    }

    fn decode_until(&mut self, target: usize) -> Result<()> {
        while self.current_pos() < target {
            self.drain_pending_match(target)?;
            if self.current_pos() >= target {
                break;
            }
            if !self.in_block {
                self.read_code_length_tables()?;
                self.in_block = true;
            }
            self.decode_lz(target)?;
        }
        Ok(())
    }

    fn read_code_length_tables(&mut self) -> Result<()> {
        let bit_field = self.bits.peek_bits(16)?;
        self.audio_block = bit_field & 0x8000 != 0;
        let keep_tables = bit_field & 0x4000 != 0;
        self.bits.read_bits(2)?;
        if !keep_tables {
            self.levels = [0; OLD_LEVEL_COUNT];
        }

        let table_size = if self.audio_block {
            self.channels = ((bit_field >> 12) as usize & 3) + 1;
            if self.cur_channel >= self.channels {
                self.cur_channel = 0;
            }
            self.bits.read_bits(2)?;
            AUDIO_COUNT * self.channels
        } else {
            TABLE_COUNT
        };

        let level_lengths = Self::read_level_lengths(&mut self.bits)?;
        let level_decoder = Huffman::from_lengths(&level_lengths)?;
        let mut new_levels = [0u8; OLD_LEVEL_COUNT];
        let mut pos = 0usize;
        while pos < table_size {
            let symbol = level_decoder.decode(&mut self.bits)?;
            match symbol {
                0..=15 => {
                    new_levels[pos] = (self.levels[pos].wrapping_add(symbol as u8)) & 0x0f;
                    pos += 1;
                }
                16 => {
                    if pos == 0 {
                        return Err(Error::InvalidData("RAR 2.0 table repeat at start"));
                    }
                    let count = 3 + self.bits.read_bits(2)? as usize;
                    let value = new_levels[pos - 1];
                    fill_levels(&mut new_levels, &mut pos, count, value)?;
                }
                17 => {
                    let count = 3 + self.bits.read_bits(3)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                18 => {
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.0 invalid level symbol")),
            }
        }

        self.levels = new_levels;
        if self.audio_block {
            for channel in 0..self.channels {
                let start = channel * AUDIO_COUNT;
                self.audio_tables[channel] =
                    Huffman::from_lengths(&self.levels[start..start + AUDIO_COUNT])?;
            }
        } else {
            self.main = Huffman::from_lengths(&self.levels[..MAIN_COUNT])?;
            self.offsets =
                Huffman::from_lengths(&self.levels[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT])?;
            self.lengths =
                Huffman::from_lengths(&self.levels[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT])?;
        }
        Ok(())
    }

    fn read_level_lengths(bits: &mut BitReader) -> Result<[u8; LEVEL_COUNT]> {
        let mut lengths = [0u8; LEVEL_COUNT];
        for length in &mut lengths {
            *length = bits.read_bits(4)? as u8;
        }
        Ok(lengths)
    }

    fn decode_lz(&mut self, output_size: usize) -> Result<()> {
        // The block mode only changes in `read_code_length_tables`, which runs between
        // calls, so each mode gets its own loop.
        if self.audio_block {
            while self.current_pos() < output_size {
                self.decode_audio_byte()?;
                if !self.in_block {
                    return Ok(());
                }
            }
            return Ok(());
        }
        while self.current_pos() < output_size {
            let symbol = self.main.decode(&mut self.bits)?;
            match symbol {
                0..=255 => self.output.push(symbol as u8),
                256 => {
                    if self.previous_match_length != 0 {
                        let length = self.previous_match_length;
                        let offset = self.last_offset;
                        self.push_old_offset(offset);
                        self.copy_match(length, offset, output_size)?;
                    }
                }
                257..=260 => {
                    let index = symbol - 257;
                    let offset = self.old_offsets[index];
                    let length_slot = self.lengths.decode(&mut self.bits)?;
                    if length_slot >= LENGTH_SLOTS {
                        return Err(Error::InvalidData("RAR 2.0 invalid repeat length slot"));
                    }
                    let mut length = LENGTH_BASES[length_slot] + 2;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    if offset >= 0x101 {
                        length += 1;
                    }
                    if offset >= 0x2000 {
                        length += 1;
                    }
                    if offset >= 0x40000 {
                        length += 1;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.previous_match_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                261..=268 => {
                    let index = symbol - 261;
                    let mut offset = SHORT_BASES[index] + 1;
                    if SHORT_BITS[index] != 0 {
                        offset += self.bits.read_bits(SHORT_BITS[index])? as usize;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.previous_match_length = 2;
                    self.copy_match(2, offset, output_size)?;
                }
                269 => {
                    self.in_block = false;
                    return Ok(());
                }
                270..=297 => {
                    let length_slot = symbol - 270;
                    let mut length = LENGTH_BASES[length_slot] + 3;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    let offset = self.read_offset()?;
                    if offset >= 0x2000 {
                        length += 1;
                    }
                    if offset >= 0x40000 {
                        length += 1;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.previous_match_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.0 invalid main symbol")),
            }
        }
        Ok(())
    }

    fn decode_audio_byte(&mut self) -> Result<()> {
        let symbol = self.audio_tables[self.cur_channel].decode(&mut self.bits)?;
        if symbol == 256 {
            self.in_block = false;
            return Ok(());
        }
        if symbol > 256 {
            return Err(Error::InvalidData("RAR 2.0 invalid audio symbol"));
        }
        let byte = self
            .audio_model
            .residual_to_byte(self.cur_channel, symbol as u8);
        self.output.push(byte);
        self.cur_channel += 1;
        if self.cur_channel == self.channels {
            self.cur_channel = 0;
        }
        Ok(())
    }

    fn read_offset(&mut self) -> Result<usize> {
        let slot = self.offsets.decode(&mut self.bits)?;
        if slot >= OFFSET_COUNT {
            return Err(Error::InvalidData("RAR 2.0 invalid offset slot"));
        }
        let mut offset = OFFSET_BASES[slot] + 1;
        if OFFSET_BITS[slot] != 0 {
            offset += self.bits.read_bits(OFFSET_BITS[slot])? as usize;
        }
        Ok(offset)
    }

    fn copy_match(&mut self, length: usize, offset: usize, output_size: usize) -> Result<()> {
        let offset = if offset == 0 { 1 } else { offset };
        let current = self.current_pos();
        if offset > current {
            return Err(Error::InvalidData("RAR 2.0 match distance is out of range"));
        }
        for index in 0..length {
            if self.current_pos() >= output_size {
                self.pending_match = Some((length - index, offset));
                break;
            }
            let src = self.current_pos() - offset;
            let byte = *self
                .raw_byte(src)
                .ok_or(Error::InvalidData("RAR 2.0 match distance is out of range"))?;
            self.output.push(byte);
        }
        Ok(())
    }

    fn drain_pending_match(&mut self, output_size: usize) -> Result<()> {
        let Some((length, offset)) = self.pending_match.take() else {
            return Ok(());
        };
        self.copy_match(length, offset, output_size)
    }

    /// Runs once a member's output is complete. In a RAR 2.0 solid chain the
    /// packed data of one member may end with a block terminator followed by
    /// the tables of the next member's first block, because that member's own
    /// data starts with coded symbols. When enough trailing data remains, read
    /// one symbol from the active table; if it ends the block, take the tables
    /// with the ordinary mid-stream table read. Any other symbol is ignored and
    /// the reader is put back where it was.
    fn take_trailing_table_switch(&mut self) -> Result<()> {
        #[cfg(test)]
        tests::observe_trailing_check(self);
        let remaining = self.bits.remaining_bytes_from_current();
        let table = if self.audio_block {
            &self.audio_tables[self.cur_channel]
        } else {
            &self.main
        };
        let table_empty = table.symbols.is_empty();
        if trailing_table_step(remaining, self.audio_block, table_empty, None)
            != TrailingStep::DecodeSymbol
        {
            return Ok(());
        }
        let resume_at = self.bits.bit_pos;
        let symbol = table.decode(&mut self.bits)?;
        match trailing_table_step(remaining, self.audio_block, table_empty, Some(symbol)) {
            TrailingStep::ReadTables => {
                self.read_code_length_tables()?;
                self.in_block = true;
            }
            TrailingStep::Nothing | TrailingStep::DecodeSymbol => self.bits.bit_pos = resume_at,
        }
        Ok(())
    }

    fn push_old_offset(&mut self, offset: usize) {
        self.old_offsets[3] = self.old_offsets[2];
        self.old_offsets[2] = self.old_offsets[1];
        self.old_offsets[1] = self.old_offsets[0];
        self.old_offsets[0] = offset;
    }

    fn current_pos(&self) -> usize {
        self.base_offset + self.output.len()
    }

    fn raw_byte(&self, position: usize) -> Option<&u8> {
        self.output.get(position.checked_sub(self.base_offset)?)
    }

    fn raw_range(&self, start: usize, end: usize) -> Result<&[u8]> {
        if start < self.base_offset || end < start {
            return Err(Error::InvalidData(
                "RAR 2.0 retained history is unavailable",
            ));
        }
        let rel_start = start - self.base_offset;
        let rel_end = end - self.base_offset;
        self.output
            .get(rel_start..rel_end)
            .ok_or(Error::InvalidData(
                "RAR 2.0 retained history is unavailable",
            ))
    }

    fn trim_history(&mut self, flushed_pos: usize, current_pos: usize) {
        let keep_from = current_pos.saturating_sub(MAX_HISTORY).min(flushed_pos);
        if keep_from <= self.base_offset {
            return;
        }
        let drain = keep_from - self.base_offset;
        self.output.drain(..drain);
        self.base_offset = keep_from;
    }
}

impl Default for Rar20Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Least trailing packed data, in bytes counted from the byte holding the next
/// unread bit, for a finished member to be inspected for a table switch.
///
/// Every compressed RAR 2.0 fixture member ends with at most one such byte,
/// and a well-formed trailing table (terminator, block header, 76-bit level
/// table and at least a few level symbols) needs at least 13. Any value in
/// 2..=13 reads every well-formed trailing table and leaves every fixture
/// alone; 5 is pinned so that no archive changes outcome.
const TRAILING_SWITCH_MIN_BYTES: usize = 5;

/// What to do next while checking the end of a finished member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrailingStep {
    /// Leave the decoder as it is.
    Nothing,
    /// Decode one symbol from the active table, then decide again with it.
    DecodeSymbol,
    /// That symbol ended the block: read the next block's tables.
    ReadTables,
}

/// The whole trailing table switch rule. `remaining_bytes` counts packed
/// bytes from the one holding the next unread bit, `table_empty` says the
/// active table (the current channel's in multimedia mode, the main table in
/// LZ mode) has no symbols, and `symbol` is the one already decoded, if any.
fn trailing_table_step(
    remaining_bytes: usize,
    audio_block: bool,
    table_empty: bool,
    symbol: Option<usize>,
) -> TrailingStep {
    if remaining_bytes < TRAILING_SWITCH_MIN_BYTES || table_empty {
        return TrailingStep::Nothing;
    }
    let terminator = if audio_block { 256 } else { 269 };
    match symbol {
        None => TrailingStep::DecodeSymbol,
        Some(symbol) if symbol == terminator => TrailingStep::ReadTables,
        Some(_) => TrailingStep::Nothing,
    }
}

/// Weight bounds of the multimedia predictor. The range is asymmetric: a
/// weight may fall to -17 but never rise above 16.
const AUDIO_WEIGHT_MIN: i16 = -17;
const AUDIO_WEIGHT_MAX: i16 = 16;
/// A channel reconsiders its weights after every this many of its samples.
const AUDIO_ADAPT_PERIOD: u32 = 32;
/// Width of a channel's lanes: the five multiplier terms, padded with zero
/// lanes to a vector width.
const AUDIO_LANES: usize = 8;
/// The weight change each adaptation candidate stands for, as a lane-wise
/// step, in tie-break order: candidate 0 keeps the weights, and candidates
/// `2j + 1` and `2j + 2` move weight `j` one lower and one higher. Rows 11 to
/// 15 are never chosen; they only make every 4-bit index valid.
const AUDIO_CANDIDATE_STEP: [[i16; AUDIO_LANES]; 16] = {
    let mut table = [[0i16; AUDIO_LANES]; 16];
    let mut weight = 0;
    while weight < 5 {
        table[2 * weight + 1][weight] = -1;
        table[2 * weight + 2][weight] = 1;
        weight += 1;
    }
    table
};

/// One channel of the multimedia predictor. Terms, weights and error totals
/// are fixed-width lane arrays, so each per-sample update is one lane
/// operation.
#[derive(Debug, Clone, Copy)]
struct AudioChannel {
    /// The current sample's multiplier terms: the previous first difference,
    /// three generations of its change, the cross-channel difference, then
    /// zero lanes.
    terms: [i16; AUDIO_LANES],
    /// One weight per term; the padding lanes stay zero.
    weights: [i16; AUDIO_LANES],
    /// This channel's most recent first difference.
    last_diff: i16,
    /// This channel's most recent predicted byte (LZ output never enters).
    last_byte: i16,
    /// Samples taken; only its residue modulo the adaptation period matters.
    samples: u32,
    /// Error totals since the last adaptation with each weight one lower
    /// (`below`) and one higher (`above`). A padding lane adds the error of
    /// the unchanged weights. A term is at most 1024 + 255 and a period holds
    /// 32 of them, so no lane can wrap.
    below: [u16; AUDIO_LANES],
    above: [u16; AUDIO_LANES],
}

impl AudioChannel {
    const FRESH: Self = Self {
        terms: [0; AUDIO_LANES],
        weights: [0; AUDIO_LANES],
        last_diff: 0,
        last_byte: 0,
        samples: 0,
        below: [0; AUDIO_LANES],
        above: [0; AUDIO_LANES],
    };

    /// Shifts in this sample's terms (`cross` is the stream-wide last
    /// difference) and returns the channel's prediction.
    #[inline(always)]
    fn predict(&mut self, cross: i16) -> u8 {
        self.samples = self.samples.wrapping_add(1);
        let old = self.terms;
        let diff = self.last_diff;
        // Rebuilt and stored as a whole, so the lane loads that follow
        // forward from one store instead of stalling on scalar writes.
        let terms = [diff, diff - old[0], old[1], old[2], cross, 0, 0, 0];
        self.terms = terms;
        // |weight| <= 17 and the terms sum to at most 1021 in magnitude, so
        // the dot product fits an i16.
        let mut dot = 0i16;
        for (&weight, &term) in self.weights.iter().zip(&terms) {
            dot += weight * term;
        }
        // The arithmetic shift floors; the cast reduces modulo 256.
        ((8 * i32::from(self.last_byte) + i32::from(dot)) >> 3) as u8
    }

    /// Scores the sample just predicted, records its byte, adapts at the end
    /// of a period, and returns the sample's first difference.
    #[inline(always)]
    fn learn(&mut self, residual: u8, byte: u8) -> i16 {
        let error = i16::from(residual as i8) * 8;
        let terms = self.terms;
        let (mut below, mut above) = (self.below, self.above);
        for ((lower, higher), &term) in below.iter_mut().zip(above.iter_mut()).zip(&terms) {
            *lower += (error - term).unsigned_abs();
            *higher += (error + term).unsigned_abs();
        }
        (self.below, self.above) = (below, above);
        let diff = i16::from((i16::from(byte) - self.last_byte) as i8);
        self.last_diff = diff;
        self.last_byte = i16::from(byte);
        if self.samples.is_multiple_of(AUDIO_ADAPT_PERIOD) {
            self.adapt();
        }
        diff
    }

    /// Keeps the single one-step weight change whose total was lowest over
    /// the period (the earliest candidate on a tie), then opens a new period.
    /// Branch-free: each key packs a total above its candidate number, so the
    /// minimum key is the lowest total with ties to the earliest candidate.
    #[inline(never)]
    fn adapt(&mut self) {
        // The sixth lane is padding: its total is the unchanged weights' error.
        let [below0, below1, below2, below3, below4, unchanged, ..] = self.below;
        let [above0, above1, above2, above3, above4, ..] = self.above;
        let key = |total: u16, candidate: u32| (u32::from(total) << 4) | candidate;
        let best = [
            key(unchanged, 0),
            key(below0, 1),
            key(above0, 2),
            key(below1, 3),
            key(above1, 4),
            key(below2, 5),
            key(above2, 6),
            key(below3, 7),
            key(above3, 8),
            key(below4, 9),
            key(above4, 10),
        ]
        .into_iter()
        .fold(u32::MAX, u32::min);
        self.below = [0; AUDIO_LANES];
        self.above = [0; AUDIO_LANES];
        let step = AUDIO_CANDIDATE_STEP[(best & 0xf) as usize];
        for (weight, step) in self.weights.iter_mut().zip(step) {
            *weight = (*weight + step).clamp(AUDIO_WEIGHT_MIN, AUDIO_WEIGHT_MAX);
        }
    }
}

/// The RAR 2.0 multimedia (audio) delta predictor, shared by the decoder and
/// the encoder: up to four channels plus the stream-wide last difference. A
/// multimedia symbol is a residual, and the byte it stands for is the
/// channel's prediction minus the residual, modulo 256. Fixed-size state, no
/// heap use.
#[derive(Debug, Clone, Copy)]
struct AudioModel {
    channels: [AudioChannel; MAX_CHANNELS],
    /// First difference of the most recent sample in any channel.
    last_diff: i16,
}

impl AudioModel {
    const fn fresh() -> Self {
        Self {
            channels: [AudioChannel::FRESH; MAX_CHANNELS],
            last_diff: 0,
        }
    }

    /// Decoder step: the byte `residual` stands for on `channel`.
    #[inline]
    fn residual_to_byte(&mut self, channel: usize, residual: u8) -> u8 {
        debug_assert!(channel < MAX_CHANNELS);
        let cross = self.last_diff;
        let state = &mut self.channels[channel];
        let byte = state.predict(cross).wrapping_sub(residual);
        self.last_diff = state.learn(residual, byte);
        byte
    }

    /// Encoder step: the residual for which `residual_to_byte` on an identical
    /// model returns `byte`, leaving the model in the state that call would.
    #[inline]
    fn byte_to_residual(&mut self, channel: usize, byte: u8) -> u8 {
        debug_assert!(channel < MAX_CHANNELS);
        let cross = self.last_diff;
        let state = &mut self.channels[channel];
        let residual = state.predict(cross).wrapping_sub(byte);
        self.last_diff = state.learn(residual, byte);
        residual
    }

    /// `byte_to_residual` over interleaved bytes starting on `first_channel`,
    /// writing one residual per byte. Returns the channel after the last byte.
    fn bytes_to_residuals(
        &mut self,
        bytes: &[u8],
        residuals: &mut [u8],
        first_channel: usize,
        channel_count: usize,
    ) -> usize {
        debug_assert!(residuals.len() >= bytes.len());
        debug_assert!(first_channel < channel_count && channel_count <= MAX_CHANNELS);
        // Finish the frame the run starts inside, then walk whole frames, so
        // a byte's channel is its position in the frame.
        let head = ((channel_count - first_channel) % channel_count).min(bytes.len());
        for (offset, (residual, &byte)) in residuals.iter_mut().zip(&bytes[..head]).enumerate() {
            *residual = self.byte_to_residual(first_channel + offset, byte);
        }
        let frames = bytes[head..].chunks(channel_count);
        for (frame, frame_out) in frames.zip(residuals[head..].chunks_mut(channel_count)) {
            for (channel, (residual, &byte)) in frame_out.iter_mut().zip(frame).enumerate() {
                *residual = self.byte_to_residual(channel, byte);
            }
        }
        (first_channel + bytes.len()) % channel_count
    }
}

fn fill_levels(levels: &mut [u8], pos: &mut usize, count: usize, value: u8) -> Result<()> {
    let end = pos
        .checked_add(count)
        .ok_or(Error::InvalidData("RAR 2.0 table run overflows"))?;
    let end = end.min(levels.len());
    for item in &mut levels[*pos..end] {
        *item = value;
    }
    *pos = end;
    Ok(())
}

#[derive(Debug, Clone)]
struct Huffman {
    symbols: Vec<HuffmanSymbol>,
    first_code: [u16; 16],
    first_index: [usize; 16],
    counts: [u16; 16],
    // Primary decode LUT, the RAR 2.9 layout: top HUFF20_LUT_BITS of the
    // stream -> packed (symbol << 8) | code_len, 0 = miss (long code).
    lut: Vec<u32>,
}

/// Same width as the RAR 2.9 LUT: covers virtually every real code.
const HUFF20_LUT_BITS: usize = 12;

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    code: u16,
    len: u8,
    symbol: usize,
}

impl Huffman {
    fn empty() -> Self {
        Self {
            symbols: Vec::new(),
            first_code: [0; 16],
            first_index: [0; 16],
            counts: [0; 16],
            lut: Vec::new(),
        }
    }

    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &len in lengths {
            if len > 15 {
                return Err(Error::InvalidData("RAR 2.0 Huffman length is too large"));
            }
            if len != 0 {
                count[len as usize] += 1;
            }
        }
        if count.iter().all(|&value| value == 0) {
            return Ok(Self::empty());
        }
        validate_huffman_counts(&count)?;

        let mut first_code = [0u16; 16];
        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code + count[len - 1]) << 1;
            first_code[len] = code;
            next_code[len] = code;
        }

        let mut first_index = [0usize; 16];
        let mut index = 0usize;
        for len in 1..=15 {
            first_index[len] = index;
            index += usize::from(count[len]);
        }

        let mut symbols = Vec::new();
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            symbols.push(HuffmanSymbol { code, len, symbol });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));
        let mut lut = vec![0u32; 1 << HUFF20_LUT_BITS];
        for item in &symbols {
            let len = usize::from(item.len);
            if len <= HUFF20_LUT_BITS {
                let shift = HUFF20_LUT_BITS - len;
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

    fn decode(&self, bits: &mut BitReader) -> Result<usize> {
        if self.symbols.is_empty() {
            return Err(Error::InvalidData("RAR 2.0 empty Huffman table"));
        }
        // LUT-first, per-length fallback, then the bit-serial tail walk -
        // the RAR 2.9 decode shape, which replaced a bit-at-a-time loop
        // that paid up to 15 bounds-checked reads per symbol.
        if let Ok(peek) = bits.peek_bits(15) {
            let entry = self.lut[(peek >> (15 - HUFF20_LUT_BITS)) as usize];
            if entry != 0 {
                bits.consume((entry & 0xff) as u8);
                return Ok((entry >> 8) as usize);
            }
            for len in (HUFF20_LUT_BITS + 1)..=15 {
                let count = self.counts[len];
                if count != 0 {
                    let code = (peek >> (15 - len)) as u16;
                    let offset = code.wrapping_sub(self.first_code[len]);
                    if offset < count {
                        bits.consume(len as u8);
                        let index = self.first_index[len] + usize::from(offset);
                        return Ok(self.symbols[index].symbol);
                    }
                }
            }
            return Err(Error::InvalidData("RAR 2.0 invalid Huffman code"));
        }
        self.decode_slow(bits)
    }

    // Bit-by-bit canonical walk for the input tail, where fewer than 15
    // peekable bits remain but a shorter valid code may still complete.
    fn decode_slow(&self, bits: &mut BitReader) -> Result<usize> {
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code << 1) | bits.read_bit()? as u16;
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
        Err(Error::InvalidData("RAR 2.0 invalid Huffman code"))
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    let mut available = 1i32;
    for &len_count in count.iter().skip(1) {
        available = (available << 1) - i32::from(len_count);
        if available < 0 {
            return Err(Error::InvalidData("RAR 2.0 oversubscribed Huffman table"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct BitReader {
    input: Vec<u8>,
    bit_pos: usize,
}

impl BitReader {
    fn new() -> Self {
        Self {
            input: Vec::new(),
            bit_pos: 0,
        }
    }

    fn append(&mut self, input: &[u8]) {
        self.compact();
        self.input.extend_from_slice(input);
    }

    fn compact(&mut self) {
        let bytes = self.bit_pos / 8;
        if bytes == 0 {
            return;
        }
        self.input.drain(..bytes);
        self.bit_pos -= bytes * 8;
    }

    fn read_bit(&mut self) -> Result<u8> {
        self.read_bits(1).map(|value| value as u8)
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let value = self.peek_bits(count)?;
        self.bit_pos += count as usize;
        Ok(value)
    }

    fn peek_bits(&self, count: u8) -> Result<u32> {
        if count > 24 {
            return Err(Error::InvalidData("RAR 2.0 bit read is too wide"));
        }
        // One 32-bit load replaces up to 24 bounds-checked single-bit
        // reads; the byte-wise tail keeps the exact NeedMoreInput behavior
        // when fewer than four whole bytes remain.
        let byte_pos = self.bit_pos / 8;
        let bit_offset = self.bit_pos % 8;
        if count != 0 {
            if let Some(window) = self.input.get(byte_pos..byte_pos + 4) {
                let word = u32::from_be_bytes(window.try_into().expect("window is 4 bytes"));
                return Ok((word << bit_offset) >> (32 - u32::from(count)));
            }
        }
        let mut value = 0u32;
        for i in 0..count as usize {
            let bit_index = self.bit_pos + i;
            let byte = *self.input.get(bit_index / 8).ok_or(Error::NeedMoreInput)?;
            let bit = (byte >> (7 - (bit_index % 8))) & 1;
            value = (value << 1) | bit as u32;
        }
        Ok(value)
    }

    #[inline]
    fn consume(&mut self, count: u8) {
        self.bit_pos += usize::from(count);
    }

    fn remaining_bytes_from_current(&self) -> usize {
        self.input.len().saturating_sub(self.bit_pos / 8)
    }
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn write_bits(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            self.write_bit(((value >> shift) & 1) != 0);
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if self.bit_pos.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit {
            let shift = 7 - (self.bit_pos % 8);
            *self.bytes.last_mut().unwrap() |= 1 << shift;
        }
        self.bit_pos += 1;
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_codes, decode_rar20, encode_rar20_literals, encode_tokens, trailing_table_step,
        AudioModel, BitReader, BitWriter, EncodeOptions, EncodeToken, Error, Huffman, HuffmanCode,
        PackedToken, Rar20Decoder, Rar20Encoder, TrailingStep, AUDIO_COUNT, LEVEL_COUNT,
        MAX_CHANNELS, TABLE_COUNT, TRAILING_SWITCH_MIN_BYTES,
    };
    use crate::crc32::crc32;
    use std::cell::RefCell;

    /// The planner stores packed tokens; the assertions below read views.
    fn token_views(tokens: &[PackedToken]) -> Vec<EncodeToken> {
        tokens.iter().map(|token| token.view()).collect()
    }

    /// The planner holds one of these per literal or match for the whole
    /// member, twice over while it compares two plans, so the width is the
    /// point of the type. A field widened back to a word would double the
    /// planner's heap without failing anything else here.
    #[test]
    fn packed_token_is_eight_bytes() {
        assert_eq!(std::mem::size_of::<PackedToken>(), 8);
    }

    /// Packed equality stands in for the view's, which is what lets
    /// `encode_member` compare two whole plans with `==`.
    #[test]
    fn packed_token_equality_matches_the_view() {
        let tokens = [
            PackedToken::literal(b'a'),
            PackedToken::literal(b'b'),
            PackedToken::repeat_last(),
            PackedToken::old_offset(0, 3, 7),
            PackedToken::old_offset(1, 3, 7),
            PackedToken::old_offset(0, 4, 7),
            PackedToken::short_offset(7),
            PackedToken::match_at(3, 7),
            PackedToken::match_at(3, 8),
        ];
        for left in tokens {
            for right in tokens {
                assert_eq!(
                    left == right,
                    left.view() == right.view(),
                    "{:?} against {:?}",
                    left.view(),
                    right.view()
                );
            }
        }
    }

    const AUTOREJ_PACKED: &[u8] = &[
        0x09, 0x14, 0x0c, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0xce, 0xf8, 0x1f, 0xc1, 0xe6, 0x05,
        0xfc, 0x39, 0xc3, 0x50, 0x65, 0x08, 0x41, 0x94, 0xc4, 0x1d, 0xf3, 0xcd, 0x0d, 0x8e, 0x20,
        0xf5, 0x9d, 0x8e, 0x76, 0x1d, 0xc5, 0x19, 0xde, 0x16, 0x5b, 0x52, 0xb8, 0x8e, 0x75, 0xcd,
        0xaf, 0x1f, 0xfc, 0x9e, 0xf7, 0x00, 0x01, 0xbe, 0x90,
    ];

    #[test]
    fn decodes_rar20_lz_member() {
        assert_eq!(
            decode_rar20(AUTOREJ_PACKED, expected_text().len()).unwrap(),
            expected_text()
        );
    }

    #[test]
    fn rejects_oversubscribed_rar20_huffman_tables() {
        assert!(matches!(
            Huffman::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidData("RAR 2.0 oversubscribed Huffman table"))
        ));
    }

    #[test]
    fn decode_member_from_reader_accepts_incremental_input() {
        struct TinyReader<'a> {
            input: &'a [u8],
        }

        impl std::io::Read for TinyReader<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.input.is_empty() {
                    return Ok(0);
                }
                let len = self.input.len().min(out.len()).min(3);
                out[..len].copy_from_slice(&self.input[..len]);
                self.input = &self.input[len..];
                Ok(len)
            }
        }

        let mut decoder = Rar20Decoder::new();
        let mut reader = TinyReader {
            input: AUTOREJ_PACKED,
        };
        let mut output = Vec::new();
        decoder
            .decode_member_from_reader(&mut reader, expected_text().len(), &mut output)
            .unwrap();

        assert_eq!(output, expected_text());
    }

    #[test]
    fn decodes_synthetic_audio_block() {
        let packed = synthetic_audio_block(8);
        let mut decoder = Rar20Decoder::new();

        assert_eq!(decoder.decode_member(&packed, 8).unwrap(), vec![0; 8]);
    }

    #[test]
    fn audio_encoder_round_trips_interleaved_pcm_like_payload() {
        let input = interleaved_pcm_like_payload();
        let packed = super::encode_audio_member(&input, 4).unwrap();
        let decoded = decode_rar20(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn auto_encoder_uses_audio_when_it_beats_lz() {
        let input = interleaved_pcm_like_payload();
        let lz = encode_rar20_literals(&input).unwrap();
        let auto = super::encode_rar20_auto(&input).unwrap();
        let decoded = decode_rar20(&auto, input.len()).unwrap();

        assert!(auto.len() < lz.len());
        assert_eq!(decoded, input);
    }

    #[test]
    fn default_encode_options_match_legacy_entry_points() {
        let input = b"rar20 option plumbing preserves default output ".repeat(128);
        assert_eq!(
            encode_rar20_literals(&input).unwrap(),
            super::encode_rar20_literals_with_options(&input, EncodeOptions::default()).unwrap()
        );
        assert_eq!(
            super::encode_rar20_auto(&input).unwrap(),
            super::encode_rar20_auto_with_options(&input, EncodeOptions::default()).unwrap()
        );

        let first = b"solid rar20 option seed ".repeat(64);
        let second = b"solid rar20 option seed with suffix ".repeat(32);
        let mut legacy = Rar20Encoder::new();
        let mut explicit = Rar20Encoder::with_options(EncodeOptions::default());
        assert_eq!(
            legacy.encode_member(&first).unwrap(),
            explicit.encode_member(&first).unwrap()
        );
        assert_eq!(
            legacy.encode_member(&second).unwrap(),
            explicit.encode_member(&second).unwrap()
        );
    }

    #[test]
    fn encode_options_can_disable_fresh_lz_matches() {
        let input = b"abcdefabcdefabcdefabcdef";
        let default_tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let literalish_tokens = encode_tokens(input, &[], EncodeOptions::new(0), None);

        assert!(default_tokens
            .iter()
            .any(|token| matches!(token.view(), EncodeToken::Match { .. })));
        assert!(!literalish_tokens
            .iter()
            .any(|token| matches!(token.view(), EncodeToken::Match { .. })));
    }

    #[test]
    fn table_level_encoder_uses_rar20_run_symbols() {
        let lengths = [0, 0, 0, 0, 5, 5, 5, 5, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let tokens = super::encode_level_tokens(&lengths);

        assert_eq!(
            tokens,
            vec![
                super::LevelToken::zero_run_short(4),
                super::LevelToken::plain(5),
                super::LevelToken::repeat_previous(3),
                super::LevelToken::plain(7),
                super::LevelToken::zero_run_short(10),
                super::LevelToken::plain(2),
            ]
        );
    }

    #[test]
    fn decodes_back_to_back_fresh_audio_blocks() {
        // No real RAR 2.x encoder we tested emits a mid-stream `audio_block,
        // !keep_tables` transition; reference encoders always either keep the
        // existing audio tables across boundaries or switch out to LZ. The
        // decoder branch that rebuilds `audio_tables` from a freshly-read level
        // table inside an audio sequence is therefore only reachable via a
        // hand-crafted fixture.
        let mut bits = BitWriter::default();
        write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ true);
        write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ false);
        let packed = bits.finish();

        let mut decoder = Rar20Decoder::new();

        assert_eq!(decoder.decode_member(&packed, 8).unwrap(), vec![0; 8]);
    }

    fn expected_text() -> Vec<u8> {
        b"Hello text not audio.\r\n".repeat(100)
    }

    fn interleaved_pcm_like_payload() -> Vec<u8> {
        let mut input = Vec::new();
        for sample in 0..8192i16 {
            let left = sample.wrapping_mul(3).wrapping_add(200);
            let right = sample.wrapping_mul(3).wrapping_sub(200);
            input.extend_from_slice(&left.to_le_bytes());
            input.extend_from_slice(&right.to_le_bytes());
        }
        input
    }

    fn synthetic_audio_block(samples: usize) -> Vec<u8> {
        let mut bits = BitWriter::default();

        bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
        bits.write_bits(0, 2); // one channel.

        for symbol in 0..19 {
            let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
            bits.write_bits(len, 4);
        }

        bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
        bits.write_bit(true); // level symbol 18: 138 zeros.
        bits.write_bits(127, 7);
        bits.write_bit(true); // level symbol 18: 118 zeros.
        bits.write_bits(107, 7);

        for _ in 0..samples {
            bits.write_bit(false); // audio delta 0.
        }

        bits.finish()
    }

    fn write_fresh_audio_block(bits: &mut BitWriter, samples: usize, emit_end_sentinel: bool) {
        bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
        bits.write_bits(0, 2); // one channel.

        for symbol in 0..19 {
            let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
            bits.write_bits(len, 4);
        }

        // Audio table: symbol 0 (delta 0) = "0", symbol 256 (block end) = "1".
        bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
        bits.write_bit(true); // level symbol 18: 138 zeros (audio symbols 1..=138).
        bits.write_bits(127, 7);
        bits.write_bit(true); // level symbol 18: 117 zeros (audio symbols 139..=255).
        bits.write_bits(106, 7);
        bits.write_bit(false); // level symbol 1: block-end (256) has code length 1.

        for _ in 0..samples {
            bits.write_bit(false); // audio delta 0.
        }
        if emit_end_sentinel {
            bits.write_bit(true); // audio symbol 256: end of audio block.
        }
    }

    #[test]
    fn literal_encoder_round_trips_rar20_lz_blocks() {
        let input = b"literal-only RAR 2.0 baseline\nwith repeated text literal-only\n";
        let packed = encode_rar20_literals(input).unwrap();

        assert_eq!(decode_rar20(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_offset_one_matches_for_repeated_bytes() {
        let input = b"A".repeat(1024);
        let packed = encode_rar20_literals(&input).unwrap();

        assert!(packed.len() < input.len() / 4);
        assert_eq!(decode_rar20(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_dictionary_matches_for_repeated_sequences() {
        let input = b"abc123xyz-".repeat(128);
        let packed = encode_rar20_literals(&input).unwrap();

        assert!(packed.len() < input.len() / 2);
        assert_eq!(decode_rar20(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_repeat_last_matches_for_regular_streams() {
        let input = b"\x00\x01\x02\x03".repeat(4096);
        let tokens = encode_tokens(&input, &[], EncodeOptions::default(), None);
        let packed = encode_rar20_literals(&input).unwrap();

        assert!(tokens
            .iter()
            .any(|token| matches!(token.view(), EncodeToken::RepeatLast)));
        assert!(packed.len() < input.len() / 8);
        assert_eq!(decode_rar20(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_minimum_length_fresh_matches() {
        let input = b"abcabc";
        let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let packed = encode_rar20_literals(input).unwrap();

        assert!(matches!(
            token_views(&tokens).as_slice(),
            [
                EncodeToken::Literal(b'a'),
                EncodeToken::Literal(b'b'),
                EncodeToken::Literal(b'c'),
                EncodeToken::Match {
                    length: 3,
                    offset: 3
                }
            ]
        ));
        assert_eq!(decode_rar20(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_short_offset_matches() {
        let input = b"abab";
        let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let packed = encode_rar20_literals(input).unwrap();

        assert!(matches!(
            token_views(&tokens).as_slice(),
            [
                EncodeToken::Literal(b'a'),
                EncodeToken::Literal(b'b'),
                EncodeToken::ShortOffset { offset: 2 }
            ]
        ));
        assert_eq!(decode_rar20(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_old_offset_matches() {
        let input = b"abcdabcdXYZXYZwxyzwxyz";
        let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let packed = encode_rar20_literals(input).unwrap();

        assert!(tokens
            .iter()
            .any(|token| matches!(token.view(), EncodeToken::OldOffset { .. })));
        assert_eq!(decode_rar20(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_finds_rar20_matches_beyond_near_offsets() {
        let phrase = b"long-distance repeated phrase for rar20 match finder.";
        let mut input = Vec::new();
        input.extend_from_slice(phrase);
        input.extend(std::iter::repeat_n(0, 300 * 1024));
        input.extend_from_slice(phrase);
        input.extend_from_slice(phrase);
        let tokens = encode_tokens(&input, &[], EncodeOptions::default(), None);
        let packed = encode_rar20_literals(&input).unwrap();

        assert!(tokens.iter().any(|token| matches!(
            token.view(),
            EncodeToken::Match { offset, .. } if offset > 0x40000
        )));
        assert!(packed.len() < input.len());
        let decoded = decode_rar20(&packed, input.len()).unwrap();
        assert!(
            decoded == input,
            "RAR 2.0 long-distance match round-trip failed"
        );
    }

    #[test]
    fn solid_encoder_emits_rar20_matches_against_previous_member_history() {
        let first = b"solid rar20 shared phrase alpha beta gamma ".repeat(4);
        let second = b"solid rar20 shared phrase alpha beta gamma ".repeat(2);
        let independent = encode_rar20_literals(&second).unwrap();
        let mut encoder = Rar20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();

        assert!(second_packed.len() < independent.len());
        let mut decoder = Rar20Decoder::new();
        assert_eq!(
            decoder.decode_member(&first_packed, first.len()).unwrap(),
            first
        );
        assert_eq!(
            decoder.decode_member(&second_packed, second.len()).unwrap(),
            second
        );
    }

    #[test]
    fn solid_encoder_reuses_rar20_tables_at_member_boundary() {
        let first: Vec<_> = (0u8..=255).cycle().take(4096).collect();
        let second = b"short literal member after reused rar20 table boundary\n";
        let independent = encode_rar20_literals(second).unwrap();
        let mut encoder = Rar20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(second).unwrap();

        assert!(second_packed.len() < independent.len());
        let mut decoder = Rar20Decoder::new();
        assert_eq!(
            decoder.decode_member(&first_packed, first.len()).unwrap(),
            first
        );
        assert_eq!(
            decoder.decode_member(&second_packed, second.len()).unwrap(),
            second
        );
    }

    #[test]
    fn solid_encoder_matches_immediately_after_rar20_table_boundary() {
        let phrase = b"rar20 table boundary match phrase with enough bytes ";
        let first = phrase.repeat(128);
        let second = phrase.repeat(8);
        let independent = encode_rar20_literals(&second).unwrap();
        let mut encoder = Rar20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();
        let tokens = encode_tokens(&second, &first, EncodeOptions::default(), None);

        assert!(matches!(
            tokens.first().map(|token| token.view()),
            Some(EncodeToken::Match { .. })
        ));
        assert!(second_packed.len() < independent.len());
        let mut decoder = Rar20Decoder::new();
        assert_eq!(
            decoder.decode_member(&first_packed, first.len()).unwrap(),
            first
        );
        assert_eq!(
            decoder.decode_member(&second_packed, second.len()).unwrap(),
            second
        );
    }

    #[test]
    fn solid_encoder_carries_rar20_history_across_multiple_members() {
        let first = b"rar20 multi member solid seed ".repeat(512);
        let second = b"rar20 multi member solid seed with middle tail ".repeat(128);
        let third = b"with middle tail ".repeat(64);
        let independent = encode_rar20_literals(&third).unwrap();
        let mut encoder = Rar20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();
        let third_packed = encoder.encode_member(&third).unwrap();

        assert!(third_packed.len() < independent.len());
        let mut decoder = Rar20Decoder::new();
        assert_eq!(
            decoder.decode_member(&first_packed, first.len()).unwrap(),
            first
        );
        assert_eq!(
            decoder.decode_member(&second_packed, second.len()).unwrap(),
            second
        );
        assert_eq!(
            decoder.decode_member(&third_packed, third.len()).unwrap(),
            third
        );
    }

    #[test]
    fn decode_member_to_streams_decoded_payload_through_writer_sink() {
        let input = b"abcabcabcabcabcabcabcabcabcabcabcabc";
        let packed = encode_rar20_literals(input).unwrap();

        let mut decoder = Rar20Decoder::new();
        let mut sink = Vec::new();
        decoder
            .decode_member_to(&packed, input.len(), &mut sink)
            .unwrap();
        assert_eq!(sink, input);

        // The error-mapping closure inside decode_member_to fires when the
        // sink's write_all returns Err — feed it a writer that always fails.
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut decoder = Rar20Decoder::new();
        let err = decoder
            .decode_member_to(&packed, input.len(), &mut FailingWriter)
            .unwrap_err();
        assert_eq!(err, Error::InvalidData("RAR 2.0 output write failed"));
    }

    // ---------------------------------------------------------------------
    // Shared helpers: a seeded generator and hand-built RAR 2.0 blocks.
    // ---------------------------------------------------------------------

    struct TestRng(u64);

    impl TestRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound as u64) as usize
        }

        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next_u64() as u8).collect()
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    fn repeat_to(pattern: &[u8], len: usize) -> Vec<u8> {
        pattern.iter().copied().cycle().take(len).collect()
    }

    /// Every residual at 9 bits and the terminator at 1 bit: a complete table.
    fn full_audio_lengths() -> Vec<u8> {
        let mut lengths = vec![9u8; AUDIO_COUNT];
        lengths[256] = 1;
        lengths
    }

    /// Every literal at 9 bits and the terminator 269 at 1 bit: a complete main
    /// table; the offset and length tables stay empty.
    fn full_main_lengths() -> Vec<u8> {
        let mut lengths = vec![0u8; TABLE_COUNT];
        lengths[..256].fill(9);
        lengths[269] = 1;
        lengths
    }

    fn codes_for(lengths: &[u8]) -> Vec<Option<HuffmanCode>> {
        canonical_codes(lengths).unwrap()
    }

    fn write_code(bits: &mut BitWriter, codes: &[Option<HuffmanCode>], symbol: usize) {
        let code = codes[symbol].expect("test table codes every symbol it writes");
        bits.write_bits(u32::from(code.code), code.len);
    }

    /// A block header that does not keep previous tables, a level table whose
    /// symbols 0..=15 are all 4 bits long (so each is written as itself), and
    /// one plain level symbol per code length. `audio_channels` selects
    /// multimedia mode; `lengths` then holds 257 lengths per channel.
    fn write_block_header(bits: &mut BitWriter, audio_channels: Option<usize>, lengths: &[u8]) {
        match audio_channels {
            Some(channels) => {
                bits.write_bits(0b10, 2);
                bits.write_bits((channels - 1) as u32, 2);
                assert_eq!(lengths.len(), AUDIO_COUNT * channels);
            }
            None => {
                bits.write_bits(0b00, 2);
                assert_eq!(lengths.len(), TABLE_COUNT);
            }
        }
        for symbol in 0..LEVEL_COUNT {
            bits.write_bits(if symbol < 16 { 4 } else { 0 }, 4);
        }
        for &len in lengths {
            bits.write_bits(u32::from(len), 4);
        }
    }

    fn write_padding_to_bytes(bits: &mut BitWriter, byte_len: usize, bit: bool) {
        assert!(bits.bit_pos <= byte_len * 8);
        while bits.bit_pos < byte_len * 8 {
            bits.write_bit(bit);
        }
    }

    #[derive(Debug, Clone)]
    enum TestBlock {
        Audio { channels: usize, residuals: Vec<u8> },
        Lz(Vec<u8>),
    }

    /// Writes blocks back to back, each after the previous block's terminator,
    /// with complete tables throughout.
    fn write_blocks(bits: &mut BitWriter, blocks: &[TestBlock]) {
        let audio = codes_for(&full_audio_lengths());
        let main = codes_for(&full_main_lengths());
        for (index, block) in blocks.iter().enumerate() {
            if index > 0 {
                match blocks[index - 1] {
                    TestBlock::Audio { .. } => write_code(bits, &audio, 256),
                    TestBlock::Lz(_) => write_code(bits, &main, 269),
                }
            }
            match block {
                TestBlock::Audio {
                    channels,
                    residuals,
                } => {
                    write_block_header(
                        bits,
                        Some(*channels),
                        &full_audio_lengths().repeat(*channels),
                    );
                    for &residual in residuals {
                        write_code(bits, &audio, usize::from(residual));
                    }
                }
                TestBlock::Lz(literals) => {
                    write_block_header(bits, None, &full_main_lengths());
                    for &literal in literals {
                        write_code(bits, &main, usize::from(literal));
                    }
                }
            }
        }
    }

    fn member_for(blocks: &[TestBlock]) -> Vec<u8> {
        let mut bits = BitWriter::default();
        write_blocks(&mut bits, blocks);
        bits.finish()
    }

    fn output_len(blocks: &[TestBlock]) -> usize {
        blocks
            .iter()
            .map(|block| match block {
                TestBlock::Audio { residuals, .. } => residuals.len(),
                TestBlock::Lz(literals) => literals.len(),
            })
            .sum()
    }

    /// What the blocks decode to by the rules of the model and of channel
    /// rotation: LZ bytes pass through, a multimedia header resets the channel
    /// only when it is out of range.
    fn expected_output(blocks: &[TestBlock]) -> Vec<u8> {
        let mut model = AudioModel::fresh();
        let mut channel = 0;
        let mut out = Vec::new();
        for block in blocks {
            match block {
                TestBlock::Audio {
                    channels,
                    residuals,
                } => {
                    if channel >= *channels {
                        channel = 0;
                    }
                    for &residual in residuals {
                        out.push(model.residual_to_byte(channel, residual));
                        channel = (channel + 1) % channels;
                    }
                }
                TestBlock::Lz(literals) => out.extend_from_slice(literals),
            }
        }
        out
    }

    // ---------------------------------------------------------------------
    // Multimedia predictor: model-level vectors.
    // ---------------------------------------------------------------------

    /// Decodes `residuals` on a fresh model with channel `i mod C`, checks the
    /// encoder direction round-trips, and checks the decoder gives the same
    /// bytes for the residuals wrapped in a multimedia member. (Every vector was
    /// also confirmed against the replaced decoder before it was deleted; see
    /// the vectors' section of the specification.)
    fn model_decode(channel_count: usize, residuals: &[u8]) -> Vec<u8> {
        let mut model = AudioModel::fresh();
        let bytes: Vec<u8> = residuals
            .iter()
            .enumerate()
            .map(|(index, &residual)| model.residual_to_byte(index % channel_count, residual))
            .collect();

        let mut back = vec![0u8; bytes.len()];
        let next = AudioModel::fresh().bytes_to_residuals(&bytes, &mut back, 0, channel_count);
        assert_eq!(next, bytes.len() % channel_count);
        assert_eq!(back, residuals, "encoder direction must round-trip");

        let blocks = [TestBlock::Audio {
            channels: channel_count,
            residuals: residuals.to_vec(),
        }];
        let packed = member_for(&blocks);
        assert_eq!(decode_rar20(&packed, residuals.len()).unwrap(), bytes);
        bytes
    }

    /// Weights of every channel after each sample.
    fn weight_trace(channel_count: usize, residuals: &[u8]) -> Vec<[[i32; 5]; MAX_CHANNELS]> {
        let mut model = AudioModel::fresh();
        residuals
            .iter()
            .enumerate()
            .map(|(index, &residual)| {
                model.residual_to_byte(index % channel_count, residual);
                model.channels.map(|channel| {
                    let [w0, w1, w2, w3, w4, ..] = channel.weights;
                    [w0, w1, w2, w3, w4].map(i32::from)
                })
            })
            .collect()
    }

    #[test]
    fn audio_model_vector_v1_unit_ramp_adapts_without_visible_effect() {
        let residuals = vec![0xff; 40];
        let expected: Vec<u8> = (1..=40).collect();
        assert_eq!(model_decode(1, &residuals), expected);
        let trace = weight_trace(1, &residuals);
        assert_eq!(trace[30][0], [0; 5]);
        assert_eq!(trace[31][0], [1, 0, 0, 0, 0]);
    }

    #[test]
    fn audio_model_vector_v2_first_adaptation_boundary() {
        let residuals = repeat_to(&[0xfe, 0x02], 40);
        let expected = hex("02 00 02 00 02 00 02 00 02 00 02 00 02 00 02 00
             02 00 02 00 02 00 02 00 02 00 02 00 02 00 02 00
             02 ff 01 fe 00 fd ff fc");
        assert_eq!(model_decode(1, &residuals), expected);
        let trace = weight_trace(1, &residuals);
        assert_eq!(trace[30][0], [0; 5]);
        assert_eq!(trace[31][0], [0, -1, 0, 0, 0]);
    }

    #[test]
    fn audio_model_vector_v3_arithmetic_residuals() {
        let residuals: Vec<u8> = (0..40u32).map(|i| ((37 * i + 11) % 256) as u8).collect();
        let expected = hex("f5 c5 70 f6 57 93 aa 9c 69 11 94 f2 2b 3f 2e f8
             9d 1d 78 ae bf ab 72 14 91 e9 1c 2a 13 d7 76 f0
             60 8e 90 70 2c c3 35 a2");
        assert_eq!(model_decode(1, &residuals), expected);
        let trace = weight_trace(1, &residuals);
        assert_eq!(trace[30][0], [0; 5]);
        assert_eq!(trace[31][0], [0, 1, 0, 0, 0]);
    }

    #[test]
    fn audio_model_vector_v4_two_channels_and_cross_weight() {
        let residuals = repeat_to(&[0xff, 0x01], 68);
        let expected = hex("01 ff 02 fe 03 fd 04 fc 05 fb 06 fa 07 f9 08 f8
             09 f7 0a f6 0b f5 0c f4 0d f3 0e f2 0f f1 10 f0
             11 ef 12 ee 13 ed 14 ec 15 eb 16 ea 17 e9 18 e8
             19 e7 1a e6 1b e5 1c e4 1d e3 1e e2 1f e1 20 e0
             21 de 22 dc");
        assert_eq!(model_decode(2, &residuals), expected);
        let trace = weight_trace(2, &residuals);
        assert_eq!(trace[61][0], [0; 5]);
        assert_eq!(trace[62][0], [1, 0, 0, 0, 0]);
        assert_eq!(trace[62][1], [0; 5]);
        assert_eq!(trace[63][1], [0, 0, 0, 0, -1]);
    }

    #[test]
    fn audio_model_vector_tie_goes_to_the_lowest_lane() {
        let residuals = repeat_to(&[0x01, 0x00], 64);
        let expected = hex("ff ff fe fe fd fd fc fc fb fb fa fa f9 f9 f8 f8
             f7 f7 f6 f6 f5 f5 f4 f4 f3 f3 f2 f2 f1 f1 f0 f0
             ef ef ee ee ed ed ec ec eb eb ea ea e9 e9 e8 e8
             e7 e7 e6 e6 e5 e5 e4 e4 e3 e3 e2 e2 e1 e1 e0 e0");
        assert_eq!(model_decode(1, &residuals), expected);
    }

    fn check_clamp_vector(pattern: &[u8], crc: u32, first: &str, last: &str, bound: i32) {
        let residuals = repeat_to(pattern, 2048);
        let output = model_decode(1, &residuals);
        assert_eq!(crc32(&output), crc);
        assert_eq!(&output[..8], hex(first).as_slice());
        assert_eq!(&output[2040..], hex(last).as_slice());
        let trace = weight_trace(1, &residuals);
        let reached = trace
            .iter()
            .position(|weights| weights[0][0] == bound)
            .expect("weight 0 reaches its bound");
        // The clamp holds the weight at its bound: it never passes it, though
        // later periods may step it back inside the range.
        assert!(trace
            .iter()
            .all(|weights| (-17..=16).contains(&weights[0][0])));
        let at_bound = trace
            .iter()
            .filter(|weights| weights[0][0] == bound)
            .count();
        let leaves = trace[reached..]
            .iter()
            .position(|weights| weights[0][0] != bound)
            .map(|offset| reached + offset);
        println!("bound {bound}: first at {reached}, {at_bound} samples at it, first leaves at {leaves:?}");
    }

    #[test]
    fn audio_model_vector_c1_weight_floor_is_minus_17() {
        check_clamp_vector(
            &[0xc0, 0xfc, 0x80],
            0x5552_116b,
            "40 44 c4 04 08 88 c8 cc",
            "e4 24 17 69 ca 7d 4a bd",
            -17,
        );
        let trace = weight_trace(1, &repeat_to(&[0xc0, 0xfc, 0x80], 2048));
        assert_eq!(
            trace.iter().position(|weights| weights[0][0] == -17),
            Some(1151)
        );
    }

    #[test]
    fn audio_model_vector_c2_weight_ceiling_is_16() {
        check_clamp_vector(
            &[0x7f, 0x7f, 0x40],
            0x63e1_072d,
            "81 02 c2 43 c4 84 05 86",
            "db a0 10 71 60 f6 2b 2f",
            16,
        );
    }

    #[test]
    fn audio_model_vector_v7_four_channels_pseudorandom() {
        let mut x: u64 = 12345;
        let residuals: Vec<u8> = (0..8192)
            .map(|_| {
                x = (1_103_515_245 * x + 12345) % (1 << 31);
                (x >> 16) as u8
            })
            .collect();
        assert_eq!(crc32(&residuals), 0x43f5_2e59);
        assert_eq!(&residuals[..8], hex("dc 04 65 aa 1f ad 1d 5a").as_slice());
        let output = model_decode(4, &residuals);
        assert_eq!(crc32(&output), 0x78f8_40af);
        assert_eq!(&output[..8], hex("24 fc 9b 56 05 4f 7e fc").as_slice());
    }

    /// The model cannot own heap memory: a `Copy` type holds no `Vec` or `Box`,
    /// so no step, block or member can allocate on its behalf. (A counting
    /// global allocator would need `unsafe`, which this crate confines to two
    /// files; see `unsafe_is_confined_to_the_neon_entry`.)
    #[test]
    fn audio_model_state_is_fixed_size() {
        fn is_copy<T: Copy>() {}
        is_copy::<AudioModel>();
        assert!(std::mem::size_of::<AudioModel>() <= 512);
    }

    // ---------------------------------------------------------------------
    // Multimedia predictor: block level and differentials against the old code.
    // ---------------------------------------------------------------------

    #[test]
    fn audio_model_state_skips_lz_blocks_between_multimedia_blocks() {
        let mut rng = TestRng(0xb1);
        let blocks = [
            TestBlock::Audio {
                channels: 2,
                residuals: rng.bytes(101),
            },
            TestBlock::Lz(rng.bytes(57)),
            TestBlock::Audio {
                channels: 2,
                residuals: rng.bytes(90),
            },
        ];
        let packed = member_for(&blocks);
        let len = output_len(&blocks);
        let expected = expected_output(&blocks);
        assert_eq!(decode_rar20(&packed, len).unwrap(), expected);
    }

    #[test]
    fn audio_channel_count_switch_resets_only_an_out_of_range_channel() {
        let mut rng = TestRng(0xb2);
        // Four channels leaving c = 3, then two channels: c resets to 0.
        let reset = [
            TestBlock::Audio {
                channels: 4,
                residuals: rng.bytes(3),
            },
            TestBlock::Audio {
                channels: 2,
                residuals: rng.bytes(1),
            },
        ];
        // Four channels leaving c = 1, then two channels: c stays 1.
        let keep = [
            TestBlock::Audio {
                channels: 4,
                residuals: rng.bytes(1),
            },
            TestBlock::Audio {
                channels: 2,
                residuals: rng.bytes(1),
            },
        ];
        for (blocks, channel_used, channel_after) in [(&reset, 0, 1), (&keep, 1, 0)] {
            let mut decoder = Rar20Decoder::new();
            let packed = member_for(blocks);
            let len = output_len(blocks);
            let out = decoder.decode_member(&packed, len).unwrap();
            assert_eq!(decoder.cur_channel, channel_after);
            let mut model = AudioModel::fresh();
            let TestBlock::Audio {
                residuals: first, ..
            } = &blocks[0]
            else {
                unreachable!()
            };
            let TestBlock::Audio {
                residuals: second, ..
            } = &blocks[1]
            else {
                unreachable!()
            };
            let mut expected: Vec<u8> = first
                .iter()
                .enumerate()
                .map(|(channel, &residual)| model.residual_to_byte(channel, residual))
                .collect();
            expected.push(model.residual_to_byte(channel_used, second[0]));
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn audio_model_persists_across_solid_members_and_not_across_fresh_ones() {
        let mut rng = TestRng(0xb3);
        let first = rng.bytes(77);
        let second = rng.bytes(45);
        let audio = codes_for(&full_audio_lengths());

        let member1 = member_for(&[TestBlock::Audio {
            channels: 1,
            residuals: first.clone(),
        }]);
        let mut continuation = BitWriter::default();
        for &residual in &second {
            write_code(&mut continuation, &audio, usize::from(residual));
        }
        let member2 = continuation.finish();

        let mut decoder = Rar20Decoder::new();
        let mut model = AudioModel::fresh();
        let expected1: Vec<u8> = first
            .iter()
            .map(|&r| model.residual_to_byte(0, r))
            .collect();
        let expected2: Vec<u8> = second
            .iter()
            .map(|&r| model.residual_to_byte(0, r))
            .collect();
        assert_eq!(
            decoder.decode_member(&member1, first.len()).unwrap(),
            expected1
        );
        assert_eq!(
            decoder.decode_member(&member2, second.len()).unwrap(),
            expected2
        );

        let fresh = member_for(&[TestBlock::Audio {
            channels: 1,
            residuals: second.clone(),
        }]);
        let fresh_out = Rar20Decoder::new()
            .decode_member(&fresh, second.len())
            .unwrap();
        assert_eq!(
            fresh_out,
            expected_output(&[TestBlock::Audio {
                channels: 1,
                residuals: second.clone(),
            }])
        );
        assert_ne!(fresh_out, expected2);
    }

    fn residual_stream(rng: &mut TestRng, shape: usize, len: usize) -> Vec<u8> {
        match shape {
            0 => rng.bytes(len),
            1 => (0..len)
                .map(|_| (rng.below(9) as u8).wrapping_sub(4))
                .collect(),
            _ => (0..len)
                .map(|_| {
                    if rng.below(16) == 0 {
                        rng.next_u64() as u8
                    } else {
                        0
                    }
                })
                .collect(),
        }
    }

    type CodecFn = fn(&[u8], usize) -> crate::codec::Result<Vec<u8>>;

    /// Folds one case's outcome into a digest input: the error, or the
    /// output's length and CRC-32.
    fn fold_outcome(digest: &mut Vec<u8>, outcome: &crate::codec::Result<Vec<u8>>) {
        let line = match outcome {
            Ok(bytes) => format!("ok {} {:08x};", bytes.len(), crc32(bytes)),
            Err(error) => format!("err {error:?};"),
        };
        digest.extend_from_slice(line.as_bytes());
    }

    // Digests of the replaced RAR 2.0 codec over the generated cases below,
    // captured from its clean-room oracle (`legacy_rar20_*`) on 15 Sep 2026
    // immediately before the oracle was deleted. They equalled this code's
    // own digests then, and the per-case differentials they replace ran green
    // in CI with the oracle still present.
    const FROZEN_MULTIMEDIA_MEMBERS: u32 = 0xb08e_320b;
    const FROZEN_BLOCK_SEQUENCES: u32 = 0xc5e5_5c10;
    const FROZEN_AUDIO_ENCODER: u32 = 0x3d98_baa8;
    const FROZEN_AUTO_ENCODER: u32 = 0x588b_d226;
    const FROZEN_TRAILING_TAILS: u32 = 0x2121_b366;

    /// Random multimedia members of 1..70,000 samples for C = 1..4 in three
    /// residual shapes, each decoded with `decode` and checked against the
    /// model; returns the digest of the outcomes.
    fn random_multimedia_member_digest(decode: CodecFn) -> u32 {
        let mut digest = Vec::new();
        let mut rng = TestRng(0x5eed_0d20);
        for channels in 1..=4 {
            let mut lengths = vec![1usize, 2, 3, 31, 32, 33, 63, 64, 65, 1000, 70_000];
            lengths.extend((0..3).map(|_| 1 + rng.below(70_000)));
            for &len in &lengths {
                for shape in 0..3 {
                    let blocks = [TestBlock::Audio {
                        channels,
                        residuals: residual_stream(&mut rng, shape, len),
                    }];
                    let packed = member_for(&blocks);
                    let outcome = decode(&packed, len);
                    assert_eq!(
                        outcome.as_ref().ok(),
                        Some(&expected_output(&blocks)),
                        "C={channels} len={len}"
                    );
                    fold_outcome(&mut digest, &outcome);
                }
            }
        }
        crc32(&digest)
    }

    #[test]
    fn random_multimedia_members_decode_as_the_replaced_decoder_did() {
        assert_eq!(
            random_multimedia_member_digest(decode_rar20),
            FROZEN_MULTIMEDIA_MEMBERS
        );
    }

    /// 60 random block sequences mixing LZ and multimedia blocks with
    /// channel-count switches; returns the digest of the outcomes.
    fn random_block_sequence_digest(decode: CodecFn) -> u32 {
        let mut digest = Vec::new();
        let mut rng = TestRng(0x5eed_b10c);
        for case in 0..60 {
            let block_count = 1 + rng.below(8);
            let blocks: Vec<TestBlock> = (0..block_count)
                .map(|_| {
                    if rng.below(3) == 0 {
                        let len = rng.below(200);
                        TestBlock::Lz(rng.bytes(len))
                    } else {
                        let len = rng.below(3000);
                        let shape = rng.below(3);
                        TestBlock::Audio {
                            channels: 1 + rng.below(4),
                            residuals: residual_stream(&mut rng, shape, len),
                        }
                    }
                })
                .collect();
            let packed = member_for(&blocks);
            let len = output_len(&blocks);
            let outcome = decode(&packed, len);
            if let Ok(decoded) = &outcome {
                assert_eq!(decoded, &expected_output(&blocks), "case {case}");
            }
            fold_outcome(&mut digest, &outcome);
        }
        crc32(&digest)
    }

    #[test]
    fn random_block_sequences_decode_as_the_replaced_decoder_did() {
        assert_eq!(
            random_block_sequence_digest(decode_rar20),
            FROZEN_BLOCK_SEQUENCES
        );
    }

    fn pcm_payload(frames: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        let mut payload = Vec::with_capacity(frames * 4);
        for t in 0..frames {
            x = (1_103_515_245 * x + 12345) % (1 << 31);
            let phase = std::f64::consts::TAU * t as f64 / 44_100.0;
            let noise = ((x >> 20) % 64) as i32 - 32;
            let left = (9000.0 * (440.0 * phase).sin()).round() as i32 + noise;
            let right = (7000.0 * (660.0 * phase).sin()).round() as i32;
            payload.extend_from_slice(&(left as i16).to_le_bytes());
            payload.extend_from_slice(&(right as i16).to_le_bytes());
        }
        payload
    }

    fn encoder_payloads() -> Vec<Vec<u8>> {
        let mut rng = TestRng(0x5eed_e2c0);
        let mut payloads = vec![
            Vec::new(),
            vec![0x80],
            rng.bytes(3),
            rng.bytes(63),
            rng.bytes(64),
            rng.bytes(255),
            vec![0u8; 4096],
            (0..=255u8).cycle().take(5000).collect(),
            interleaved_pcm_like_payload(),
            pcm_payload(12_000, 12345),
            rng.bytes(70_001),
        ];
        payloads.push(pcm_payload(3001, 777)[1..].to_vec());
        payloads
    }

    /// Every encoder payload through `encode` for channel counts 0..=5
    /// (including the two invalid ones); returns the digest of the outcomes.
    fn audio_encoder_digest(encode: CodecFn) -> u32 {
        let mut digest = Vec::new();
        for payload in encoder_payloads() {
            for channels in 0..=MAX_CHANNELS + 1 {
                fold_outcome(&mut digest, &encode(&payload, channels));
            }
        }
        crc32(&digest)
    }

    /// The encoder payloads up to 20,000 bytes through an automatic
    /// (LZ or multimedia) member encoder; the `usize` argument is unused.
    fn auto_encoder_digest(encode: CodecFn) -> u32 {
        let mut digest = Vec::new();
        for payload in encoder_payloads() {
            if payload.len() <= 20_000 {
                fold_outcome(&mut digest, &encode(&payload, 0));
            }
        }
        crc32(&digest)
    }

    fn new_auto_encoder(input: &[u8], _: usize) -> crate::codec::Result<Vec<u8>> {
        super::encode_rar20_auto_with_options(input, EncodeOptions::default())
    }

    #[test]
    fn audio_encoder_packs_as_the_replaced_encoder_did() {
        assert_eq!(
            audio_encoder_digest(super::encode_audio_member),
            FROZEN_AUDIO_ENCODER
        );
        assert_eq!(auto_encoder_digest(new_auto_encoder), FROZEN_AUTO_ENCODER);
        for payload in encoder_payloads() {
            for channels in 1..=MAX_CHANNELS {
                if let Ok(packed) = super::encode_audio_member(&payload, channels) {
                    assert_eq!(decode_rar20(&packed, payload.len()).unwrap(), payload);
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // End-of-member table switch.
    // ---------------------------------------------------------------------

    #[test]
    fn trailing_table_step_covers_the_whole_rule() {
        use TrailingStep::{DecodeSymbol, Nothing, ReadTables};
        // S3: below the threshold nothing is read, whatever follows.
        assert_eq!(trailing_table_step(4, false, false, None), Nothing);
        assert_eq!(trailing_table_step(0, true, false, None), Nothing);
        // S2 and S1: at or above the threshold one symbol is read, and the
        // mode's terminator takes the tables.
        assert_eq!(trailing_table_step(5, false, false, None), DecodeSymbol);
        assert_eq!(trailing_table_step(5, false, false, Some(269)), ReadTables);
        assert_eq!(trailing_table_step(13, false, false, Some(269)), ReadTables);
        // S4: any other symbol is ignored.
        assert_eq!(trailing_table_step(5, false, false, Some(65)), Nothing);
        assert_eq!(trailing_table_step(5, false, false, Some(256)), Nothing);
        // S5: in multimedia mode the terminator is 256.
        assert_eq!(trailing_table_step(9, true, false, None), DecodeSymbol);
        assert_eq!(trailing_table_step(9, true, false, Some(256)), ReadTables);
        assert_eq!(trailing_table_step(9, true, false, Some(0)), Nothing);
        assert_eq!(trailing_table_step(9, true, false, Some(269)), Nothing);
        // S6: an active table without symbols is never read.
        assert_eq!(trailing_table_step(9, false, true, None), Nothing);
        assert_eq!(trailing_table_step(9, true, true, None), Nothing);
        // S7: an incomplete table is still read; the decode itself fails.
        assert_eq!(trailing_table_step(9, false, false, None), DecodeSymbol);

        for remaining in 0..32 {
            for audio in [false, true] {
                for empty in [false, true] {
                    let step = trailing_table_step(remaining, audio, empty, None);
                    let reads = remaining >= TRAILING_SWITCH_MIN_BYTES && !empty;
                    assert_eq!(step == DecodeSymbol, reads);
                    assert_ne!(step, ReadTables);
                }
            }
        }
        assert_eq!(TRAILING_SWITCH_MIN_BYTES, 5);
    }

    /// An LZ member: complete main table, `literals`, then `tail` written by the
    /// caller. Returns the writer and the bit position where the output ends.
    fn lz_member_head(literals: &[u8], main_lengths: &[u8]) -> (BitWriter, usize) {
        let main = codes_for(main_lengths);
        let mut bits = BitWriter::default();
        write_block_header(&mut bits, None, main_lengths);
        for &literal in literals {
            write_code(&mut bits, &main, usize::from(literal));
        }
        let end = bits.bit_pos;
        (bits, end)
    }

    fn main_codes_bits(bytes: &[u8]) -> Vec<u8> {
        let main = codes_for(&full_main_lengths());
        let mut bits = BitWriter::default();
        for &byte in bytes {
            write_code(&mut bits, &main, usize::from(byte));
        }
        bits.finish()
    }

    #[test]
    fn trailing_switch_s1_takes_the_next_members_tables() {
        let (mut bits, end) = lz_member_head(b"abc", &full_main_lengths());
        write_code(&mut bits, &codes_for(&full_main_lengths()), 269);
        let mut residual_table = vec![0u8; AUDIO_COUNT];
        residual_table[0] = 1;
        residual_table[256] = 1;
        write_block_header(&mut bits, Some(1), &residual_table);
        let member1 = bits.finish();
        assert!(member1.len() - end / 8 >= 13);

        let mut decoder = Rar20Decoder::new();
        assert_eq!(decoder.decode_member(&member1, 3).unwrap(), b"abc");
        assert!(decoder.audio_block && decoder.in_block);
        // Five codes for residual 0 ("0") on a fresh model: five zero bytes.
        assert_eq!(decoder.decode_member(&[0x00], 5).unwrap(), vec![0; 5]);
    }

    fn threshold_member(remaining: usize) -> (Vec<u8>, usize) {
        let (mut bits, end) = lz_member_head(b"q", &full_main_lengths());
        assert_ne!(end % 8, 0, "the next unread bit sits mid-byte");
        write_code(&mut bits, &codes_for(&full_main_lengths()), 269);
        write_padding_to_bytes(&mut bits, end / 8 + remaining, false);
        (bits.finish(), end)
    }

    #[test]
    fn trailing_switch_s2_reads_at_five_remaining_bytes_and_fails_short() {
        let (member1, _) = threshold_member(5);
        let mut decoder = Rar20Decoder::new();
        assert_eq!(
            decoder.decode_member(&member1, 1),
            Err(Error::NeedMoreInput)
        );
    }

    #[test]
    fn trailing_switch_s3_skips_at_four_remaining_bytes() {
        let (member1, end) = threshold_member(4);
        let mut decoder = Rar20Decoder::new();
        assert_eq!(decoder.decode_member(&member1, 1).unwrap(), b"q");
        assert_eq!(decoder.bits.bit_pos, end);
        assert_eq!(
            decoder.decode_member(&main_codes_bits(b"xy"), 2).unwrap(),
            b"xy"
        );
    }

    #[test]
    fn trailing_switch_s4_ignores_any_other_symbol() {
        let (mut bits, end) = lz_member_head(b"hello", &full_main_lengths());
        write_code(
            &mut bits,
            &codes_for(&full_main_lengths()),
            usize::from(b'!'),
        );
        write_padding_to_bytes(&mut bits, end / 8 + 8, false);
        let member1 = bits.finish();

        let mut decoder = Rar20Decoder::new();
        assert_eq!(decoder.decode_member(&member1, 5).unwrap(), b"hello");
        assert!(decoder.in_block && !decoder.audio_block);
        assert_eq!(
            decoder.bits.bit_pos, end,
            "an ignored symbol leaves the reader"
        );
        assert_eq!(
            decoder
                .decode_member(&main_codes_bits(b"world"), 5)
                .unwrap(),
            b"world"
        );
    }

    #[test]
    fn trailing_switch_s5_leaves_the_channel_across_an_lz_header() {
        let audio = codes_for(&full_audio_lengths());
        let main = codes_for(&full_main_lengths());
        let residuals = [0x13u8, 0xf0, 0x2a, 0x81];

        let mut bits = BitWriter::default();
        write_block_header(&mut bits, Some(2), &full_audio_lengths().repeat(2));
        for &residual in &residuals[..3] {
            write_code(&mut bits, &audio, usize::from(residual));
        }
        write_code(&mut bits, &audio, 256);
        write_block_header(&mut bits, None, &full_main_lengths());
        let member1 = bits.finish();

        let mut bits = BitWriter::default();
        write_code(&mut bits, &main, usize::from(b'a'));
        write_code(&mut bits, &main, usize::from(b'b'));
        write_code(&mut bits, &main, 269);
        write_block_header(&mut bits, Some(2), &full_audio_lengths().repeat(2));
        write_code(&mut bits, &audio, usize::from(residuals[3]));
        let member2 = bits.finish();

        let mut model = AudioModel::fresh();
        let expected1: Vec<u8> = residuals[..3]
            .iter()
            .enumerate()
            .map(|(index, &residual)| model.residual_to_byte(index % 2, residual))
            .collect();
        let mut on_channel_0 = model;
        let expected_last = model.residual_to_byte(1, residuals[3]);
        assert_ne!(
            on_channel_0.residual_to_byte(0, residuals[3]),
            expected_last
        );

        let mut decoder = Rar20Decoder::new();
        assert_eq!(decoder.decode_member(&member1, 3).unwrap(), expected1);
        assert!(!decoder.audio_block && decoder.in_block);
        assert_eq!(decoder.cur_channel, 1);
        assert_eq!(
            decoder.decode_member(&member2, 3).unwrap(),
            vec![b'a', b'b', expected_last]
        );
        assert_eq!(decoder.cur_channel, 0);
    }

    fn s6_member() -> (Vec<u8>, usize) {
        let mut lengths = full_audio_lengths();
        lengths.extend(std::iter::repeat_n(0u8, AUDIO_COUNT));
        let mut bits = BitWriter::default();
        write_block_header(&mut bits, Some(2), &lengths);
        write_code(&mut bits, &codes_for(&full_audio_lengths()), 0x42);
        let end = bits.bit_pos;
        write_padding_to_bytes(&mut bits, end / 8 + 9, true);
        (bits.finish(), end)
    }

    #[test]
    fn trailing_switch_s6_never_reads_an_empty_active_table() {
        let (member1, end) = s6_member();
        let mut decoder = Rar20Decoder::new();
        assert_eq!(decoder.decode_member(&member1, 1).unwrap().len(), 1);
        assert_eq!(decoder.cur_channel, 1);
        assert_eq!(decoder.bits.bit_pos, end);
        assert!(decoder.audio_block && decoder.in_block);
        assert_eq!(
            Rar20Decoder::new()
                .decode_member(&member1, 1)
                .map(|out| out.len()),
            Ok(1)
        );
    }

    fn s7_member() -> Vec<u8> {
        let mut lengths = vec![0u8; TABLE_COUNT];
        lengths[..256].fill(9);
        let (mut bits, end) = lz_member_head(b"zz", &lengths);
        write_padding_to_bytes(&mut bits, end / 8 + 8, true);
        bits.finish()
    }

    #[test]
    fn trailing_switch_s7_fails_on_a_code_in_an_incomplete_tables_hole() {
        let member1 = s7_member();
        let invalid = Err(Error::InvalidData("RAR 2.0 invalid Huffman code"));
        assert_eq!(Rar20Decoder::new().decode_member(&member1, 2), invalid);
    }

    /// 500+ member tails: LZ members (complete and incomplete main tables)
    /// ending in nothing, a terminator, a literal, or a terminator and a table,
    /// padded with zeros or ones to every length; then a multimedia member
    /// ending on channel 1 with a trailing LZ table cut at every length.
    /// Returns the digest of the outcomes and the case count.
    fn trailing_tail_digest(decode: CodecFn) -> (u32, usize) {
        let mut digest = Vec::new();
        let main = codes_for(&full_main_lengths());
        let audio = codes_for(&full_audio_lengths());
        let mut incomplete = vec![0u8; TABLE_COUNT];
        incomplete[..256].fill(9);
        let mut compared = 0;
        for literals in [&b"q"[..], b"ab", b"hello"] {
            for lengths in [full_main_lengths(), incomplete.clone()] {
                for tail in 0..4 {
                    for fill in [false, true] {
                        for extra in 0..24 {
                            let (mut bits, end) = lz_member_head(literals, &lengths);
                            match tail {
                                0 if lengths[269] != 0 => write_code(&mut bits, &main, 269),
                                1 => write_code(&mut bits, &main, usize::from(b'!')),
                                2 if lengths[269] != 0 => {
                                    write_code(&mut bits, &main, 269);
                                    write_block_header(&mut bits, None, &full_main_lengths());
                                }
                                _ => {}
                            }
                            let byte_len = (end / 8 + extra).max(bits.bit_pos.div_ceil(8));
                            write_padding_to_bytes(&mut bits, byte_len, fill);
                            let mut member = bits.finish();
                            member.truncate(end / 8 + extra.max(1));
                            fold_outcome(&mut digest, &decode(&member, literals.len()));
                            compared += 1;
                        }
                    }
                }
            }
        }
        // Multimedia members ending on channel 1 with a trailing LZ table cut at
        // every length.
        let mut bits = BitWriter::default();
        write_block_header(&mut bits, Some(2), &full_audio_lengths().repeat(2));
        for residual in [9usize, 200, 31] {
            write_code(&mut bits, &audio, residual);
        }
        let end = bits.bit_pos;
        write_code(&mut bits, &audio, 256);
        write_block_header(&mut bits, None, &full_main_lengths());
        let full = bits.finish();
        for cut in end.div_ceil(8)..=full.len() {
            fold_outcome(&mut digest, &decode(&full[..cut], 3));
            compared += 1;
        }
        (crc32(&digest), compared)
    }

    #[test]
    fn trailing_tails_end_as_they_did_with_the_replaced_decoder() {
        let (digest, cases) = trailing_tail_digest(decode_rar20);
        assert!(cases > 500);
        assert_eq!(digest, FROZEN_TRAILING_TAILS);
    }

    /// The three skip paths change nothing: no table is rebuilt (the only
    /// allocating step, `read_code_length_tables`), the mode stays and the reader is left
    /// where it was.
    #[test]
    fn trailing_switch_skip_paths_leave_the_decoder_untouched() {
        fn check(decoder: &mut Rar20Decoder, trailing: &[u8]) {
            decoder.bits = BitReader::new();
            decoder.bits.append(trailing);
            let (audio, channel, channels) =
                (decoder.audio_block, decoder.cur_channel, decoder.channels);
            let levels = decoder.levels;
            assert_eq!(decoder.take_trailing_table_switch(), Ok(()));
            assert_eq!(decoder.bits.bit_pos, 0);
            assert!(decoder.in_block);
            assert_eq!(
                (decoder.audio_block, decoder.cur_channel, decoder.channels),
                (audio, channel, channels)
            );
            assert!(decoder.levels == levels);
        }

        // Path 1: fewer than five bytes remain.
        let (member1, _) = threshold_member(4);
        let mut decoder = Rar20Decoder::new();
        decoder.decode_member(&member1, 1).unwrap();
        check(&mut decoder, &[0xff; 4]);
        // Path 3c: a literal is read and ignored.
        check(&mut decoder, &main_codes_bits(b"literal!"));
        // Path 2: the current channel's table is empty.
        let (member1, _) = s6_member();
        let mut decoder = Rar20Decoder::new();
        decoder.decode_member(&member1, 1).unwrap();
        check(&mut decoder, &[0xff; 16]);
    }

    // ---------------------------------------------------------------------
    // Test-only probe: what the trailing check sees on the real fixtures.
    // ---------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProbeRead {
        /// No packed data left at all.
        NotAttempted,
        /// The active table has no symbols.
        Empty,
        /// One symbol decoded that is not the terminator.
        Ignored(usize),
        /// The terminator, and the following table read succeeds.
        Switched,
        /// The terminator, and the following table read runs out of input.
        RunsOut,
        /// The decode or the table read fails otherwise.
        Failed,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ProbeRow {
        remaining_bytes: usize,
        unread_bits: usize,
        audio_block: bool,
        /// What one symbol read would give if the threshold were ignored.
        read: ProbeRead,
    }

    thread_local! {
        static PROBE_ROWS: RefCell<Option<Vec<ProbeRow>>> = const { RefCell::new(None) };
    }

    pub(super) fn observe_trailing_check(decoder: &Rar20Decoder) {
        PROBE_ROWS.with(|rows| {
            if let Some(rows) = rows.borrow_mut().as_mut() {
                rows.push(probe_row(decoder));
            }
        });
    }

    fn probe_row(decoder: &Rar20Decoder) -> ProbeRow {
        let remaining_bytes = decoder.bits.remaining_bytes_from_current();
        let unread_bits = (decoder.bits.input.len() * 8).saturating_sub(decoder.bits.bit_pos);
        let mut probe = decoder.clone();
        let table = if probe.audio_block {
            &probe.audio_tables[probe.cur_channel]
        } else {
            &probe.main
        };
        let read = if remaining_bytes == 0 {
            ProbeRead::NotAttempted
        } else if table.symbols.is_empty() {
            ProbeRead::Empty
        } else {
            let terminator = if probe.audio_block { 256 } else { 269 };
            match table.decode(&mut probe.bits) {
                Err(Error::NeedMoreInput) => ProbeRead::RunsOut,
                Err(_) => ProbeRead::Failed,
                Ok(symbol) if symbol != terminator => ProbeRead::Ignored(symbol),
                Ok(_) => match probe.read_code_length_tables() {
                    Ok(()) => ProbeRead::Switched,
                    Err(Error::NeedMoreInput) => ProbeRead::RunsOut,
                    Err(_) => ProbeRead::Failed,
                },
            }
        };
        ProbeRow {
            remaining_bytes,
            unread_bits,
            audio_block: decoder.audio_block,
            read,
        }
    }

    fn probe_fixture(path: &str) -> Vec<ProbeRow> {
        let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar15_40")
            .join(path);
        let bytes = std::fs::read(full).unwrap();
        let archive = crate::rar15_40::Archive::parse(&bytes).unwrap();
        PROBE_ROWS.with(|rows| *rows.borrow_mut() = Some(Vec::new()));
        let extracted = archive.extract_to(crate::ArchiveReadOptions::default(), |_| {
            Ok(Box::new(std::io::sink()))
        });
        let rows = PROBE_ROWS.with(|rows| rows.borrow_mut().take()).unwrap();
        extracted.unwrap();
        rows
    }

    #[test]
    fn trailing_check_sees_what_the_fixture_table_records() {
        use ProbeRead::{Ignored, NotAttempted, RunsOut};
        let row = |remaining_bytes, unread_bits, audio_block, read| ProbeRow {
            remaining_bytes,
            unread_bits,
            audio_block,
            read,
        };
        let cases = [
            ("rar250/AUTOREJ.RAR", vec![row(1, 2, false, Ignored(256))]),
            ("rar250/AUDIO.RAR", vec![row(1, 1, false, Ignored(256))]),
            (
                "rar250/SOLID.RAR",
                vec![
                    row(0, 0, false, NotAttempted),
                    row(1, 2, false, Ignored(256)),
                ],
            ),
            (
                "rar250/unpack20_multiblock.rar",
                vec![row(1, 1, false, RunsOut)],
            ),
            (
                "rar250/unpack20_keep_tables.rar",
                vec![row(1, 3, false, RunsOut), row(1, 2, false, RunsOut)],
            ),
            (
                "rar250/unpack20_audio_text.rar",
                vec![row(1, 4, true, Ignored(0))],
            ),
            ("rar250/BIGLZ.RAR", vec![row(1, 3, false, Ignored(256))]),
            (
                "external/rar2_unix_owner.rar",
                vec![row(0, 0, false, NotAttempted)],
            ),
        ];
        for (path, expected) in cases {
            let rows = probe_fixture(path);
            println!("{path}: {rows:?}");
            assert!(
                rows.iter()
                    .all(|row| row.remaining_bytes < TRAILING_SWITCH_MIN_BYTES),
                "{path}: every fixture member stays below the threshold"
            );
            assert_eq!(
                &rows[..expected.len().min(rows.len())],
                &expected[..],
                "{path}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Throughput (spec D 1.4 item 3). Release only:
    //   cargo test -p rars --lib --release --features parallel -- \
    //     --ignored --nocapture audio_model_throughput
    // ---------------------------------------------------------------------

    #[test]
    #[ignore = "64 MiB throughput measurement; run in release with --ignored --nocapture"]
    fn audio_model_throughput_64mib_four_channels() {
        use std::hint::black_box;
        use std::time::Instant;

        let payload = pcm_payload(16_777_216, 12345);
        let packed = super::encode_audio_member(&payload, 4).unwrap();
        let mut residuals = vec![0u8; payload.len()];
        AudioModel::fresh().bytes_to_residuals(&payload, &mut residuals, 0, 4);
        let mut scratch = vec![0u8; payload.len()];
        let median = |mut samples: Vec<f64>| {
            samples.sort_by(f64::total_cmp);
            samples[samples.len() / 2]
        };
        let mib = payload.len() as f64 / (1024.0 * 1024.0);
        let (mut decode, mut model, mut encode) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..15 {
            let start = Instant::now();
            let out = black_box(decode_rar20(black_box(&packed), payload.len()).unwrap());
            decode.push(start.elapsed().as_secs_f64());
            assert!(out == payload);

            let start = Instant::now();
            let mut state = AudioModel::fresh();
            for (index, (byte, &residual)) in
                scratch.iter_mut().zip(black_box(&residuals)).enumerate()
            {
                *byte = state.residual_to_byte(index & 3, residual);
            }
            model.push(start.elapsed().as_secs_f64());
            assert!(scratch == payload);

            let start = Instant::now();
            AudioModel::fresh().bytes_to_residuals(black_box(&payload), &mut scratch, 0, 4);
            encode.push(start.elapsed().as_secs_f64());
            assert!(scratch == residuals);
        }
        let report = |name: &str, seconds: f64| {
            println!("{name}: median {seconds:.3} s, {:.1} MiB/s", mib / seconds);
        };
        // The replaced code is no longer in the tree: the numbers of record
        // against it (cross-process, adjacent old/new pairs) are in the
        // clean-room landing commit message.
        report("decode_member", median(decode));
        report("model stage", median(model));
        report("encoder residuals C=4", median(encode));
        println!(
            "packed member crc32 {:08x}, {} bytes",
            crc32(&packed),
            packed.len()
        );
    }
}
