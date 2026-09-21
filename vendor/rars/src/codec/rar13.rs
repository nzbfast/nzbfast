//! The RAR 1.5 compression algorithm: LZ77 matches plus adaptive-rank
//! coding, used by every compressed member of a RAR 1.3/1.4 archive and by
//! members with unpack version 15 in RAR 1.5-4.x archives.
//!
//! Written from the clean-room specification in nzbfast's
//! `research/cleanroom/SPEC-A-rar15-codec.md`. The adaptive state and its
//! update rules live once, in `model`, and drive both the decoder and the
//! encoder. The encoder's match search and token planning below choose
//! items; the model writes them.

mod bits;
mod codes;
mod decoder;
mod model;

#[cfg(test)]
mod fixture_tests;
#[cfg(test)]
mod spec_tests;
#[cfg(test)]
mod tests;

pub use decoder::Rar15Decoder;

use super::{Error, Result};
use bits::{BitCounter, BitSink, BitWriter};
use model::{literal_preference, Model, NONE};

const MATCH_HASH_BUCKETS: usize = 4096;
/// The most positions [`MatchIndex`] remembers: twice [`MAX_LONG_DISTANCE`],
/// which buys match QUALITY and not correctness. At this size every link the
/// candidate walk reads inside its distance bound is still the one its own
/// position wrote, so the chain the walk follows is the real one, ordered
/// newest first. Shrinking it to `1 << 14` breaks that and passes the whole
/// suite (census leg K5, 16 Sep 2026): the walk verifies every candidate's
/// bytes before accepting one, so a stale link cannot make the encoder
/// wrong, and it cannot make the walk run away either - see the termination
/// argument on [`find_long_match_bucketed`]. What a stale link costs is a
/// candidate slot, spent walking an unrelated chain.
const MATCH_WINDOW: usize = 1 << 16;
/// An empty [`MatchIndex`] link.
const NO_POSITION: usize = usize::MAX;
const MAX_LONG_MATCH_CANDIDATES: usize = 64;
/// The largest distance a long match can express.
const MAX_LONG_DISTANCE: usize = 0x7fff;

/// Encodes `input` as one member with the default options.
pub fn encode_rar15(input: &[u8]) -> Result<Vec<u8>> {
    encode_rar15_with_options(input, EncodeOptions::default())
}

/// Encodes `input` as one member with a fresh encoder.
pub fn encode_rar15_with_options(input: &[u8], options: EncodeOptions) -> Result<Vec<u8>> {
    Rar15Encoder::with_options(options).encode_member(input)
}

/// Decodes one non-solid member of `output_size` bytes.
pub fn decode_rar15(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    Rar15Decoder::new().decode_member(input, output_size, false)
}

/// Planner knobs for [`Rar15Encoder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions {
    ring_matches: bool,
    lazy_matching: bool,
    run_mode_literals: bool,
    max_long_match_distance: usize,
}

impl EncodeOptions {
    pub const fn new() -> Self {
        Self {
            ring_matches: true,
            lazy_matching: true,
            run_mode_literals: true,
            max_long_match_distance: MAX_LONG_DISTANCE,
        }
    }

    /// Whether the planner may reuse one of the four recent distances.
    pub const fn with_old_distance_tokens(mut self, enabled: bool) -> Self {
        self.ring_matches = enabled;
        self
    }

    /// Whether a match may be skipped for a literal when the next position
    /// holds a clearly longer one.
    pub const fn with_lazy_matching(mut self, enabled: bool) -> Self {
        self.lazy_matching = enabled;
        self
    }

    /// Whether the encoder emits run-mode literals once the decoder enters
    /// run mode, rather than leaving run mode at once.
    pub const fn with_stmode_literal_runs(mut self, enabled: bool) -> Self {
        self.run_mode_literals = enabled;
        self
    }

    /// Caps the distance the long-match search considers.
    pub const fn with_max_long_match_distance(mut self, distance: usize) -> Self {
        self.max_long_match_distance = distance;
        self
    }

    pub const fn old_distance_tokens_enabled(self) -> bool {
        self.ring_matches
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A RAR 1.5 algorithm encoder. Each [`Self::encode_member`] call after the
/// first produces the next SOLID member.
pub struct Rar15Encoder {
    options: EncodeOptions,
    model: Model,
    #[cfg(test)]
    run_literal_count: usize,
    /// Input positions of items whose two-bit flag straddled two flag bytes
    /// in [`Self::encode_member`], so a test can show a stream carries one.
    #[cfg(test)]
    straddle_positions: Vec<usize>,
}

impl Default for Rar15Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Rar15Encoder {
    pub fn new() -> Self {
        Self::with_options(EncodeOptions::default())
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            options,
            model: Model::new(),
            #[cfg(test)]
            run_literal_count: 0,
            #[cfg(test)]
            straddle_positions: Vec::new(),
        }
    }

    /// Encodes `input` with literal items only (plus run-mode literals and
    /// exits); a size baseline.
    pub fn encode_literals_only(mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.model.begin_member(true);
        let mut bits = BitWriter::default();
        let mut pos = 0usize;
        let mut straddle = false;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_pref_literal = self.model.pref_literal();
            let mut plan_pref_long = self.model.pref_long();
            let mut plan_run = self.model.run_length();
            let mut group_enters_run_mode = false;
            if std::mem::take(&mut straddle) {
                open_with_straddling_token(
                    &mut flags,
                    &mut flag_bits,
                    &mut payloads,
                    EncodedToken::Literal(input[pos]),
                    true,
                );
                plan_run = plan_run.saturating_add(1);
                pos += 1;
                literal_preference(&mut plan_pref_literal, &mut plan_pref_long);
            }

            while flag_bits < 8 && pos < input.len() {
                let flag = literal_flag_bits(plan_pref_long <= plan_pref_literal);
                if flag_bits + flag.len() > 8 {
                    straddle = true;
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                payloads.push(EncodedToken::Literal(input[pos]));
                flag_bits += flag.len();
                if flag_bits == 8 && plan_run >= 16 && pos + 1 < input.len() {
                    group_enters_run_mode = true;
                }
                plan_run = plan_run.saturating_add(1);
                pos += 1;
                literal_preference(&mut plan_pref_literal, &mut plan_pref_long);
            }

            self.model.put_flag_byte(&mut bits, flags)?;
            self.emit_payloads(&mut bits, payloads)?;
            if group_enters_run_mode {
                if self.options.run_mode_literals {
                    self.emit_run_mode_literals(&mut bits, input, None, &mut pos)?;
                }
                self.model.put_run_exit(&mut bits)?;
            }
        }
        Ok(bits.finish())
    }

    /// Encodes the next member. Empty input returns an empty vector and
    /// changes no state.
    pub fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.encode_member_inner(input, None)
    }

    /// As [`Self::encode_member`], calling `progress(position)` about once
    /// per MiB and once at the end; a `false` return cancels.
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
        mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        // Each member starts with the decoder's member reset (spec 5.3.3):
        // run mode off, no repeats pending, no flag bits left.
        self.model.begin_member(true);
        let mut bits = BitWriter::default();
        let mut index = MatchIndex::new(input.len());
        let mut pos = 0usize;
        let mut next_report = 0usize;
        // An item whose two-bit flag came up at bit 7, with its second bit.
        let mut straddle: Option<(EncodedToken, bool)> = None;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan = self.model;
            plan.open_planning_group();
            let mut group_enters_run_mode = false;
            if let Some((token, second_bit)) = straddle.take() {
                open_with_straddling_token(
                    &mut flags,
                    &mut flag_bits,
                    &mut payloads,
                    token,
                    second_bit,
                );
                #[cfg(test)]
                self.straddle_positions.push(pos);
                pos += token.length() as usize;
                emit_token(&mut plan, &mut BitCounter::default(), token)?;
            }

            while flag_bits < 8 && pos < input.len() {
                let state = plan_state(&plan);
                if let Some(token) =
                    choose_token(&plan, self.options, input, pos, &mut index, state).filter(
                        |token| {
                            !self.options.lazy_matching
                                || !should_lazy_emit_literal(
                                    input,
                                    pos,
                                    &mut index,
                                    *token,
                                    state.threshold,
                                    self.options,
                                )
                        },
                    )
                {
                    let flag = token.flag_bits(state.pref_long, state.pref_literal);
                    if flag_bits + flag.len() > 8 {
                        // Only a two-bit flag can overflow a byte the loop
                        // keeps under 8 bits, so `second` is always present
                        // here. A `None` would leave `pos` where it is and
                        // re-plan the item in the next group, which is
                        // correct too; what it never does is index past the
                        // flag (target 8.5).
                        straddle = flag.second().map(|second_bit| (token, second_bit));
                        break;
                    }
                    write_planned_flag_bits(&mut flags, flag_bits, flag);
                    flag_bits += flag.len();
                    pos += token.length() as usize;
                    emit_token(&mut plan, &mut BitCounter::default(), token)?;
                    payloads.push(token);
                    continue;
                }

                // Through `get`, not `input[pos]`: the loop's own guard says
                // it is in range, but the compiler does not prove it across
                // the token branch's `continue` and emits a bounds check
                // (target 8.5). The `else` arm is the loop's own exit.
                let Some(&literal) = input.get(pos) else {
                    break;
                };
                let flag = literal_flag_bits(plan.pref_long() <= plan.pref_literal());
                if flag_bits + flag.len() > 8 {
                    // As above: a one-bit flag always fits, so this is the
                    // two-bit form and `second` is present.
                    straddle = flag
                        .second()
                        .map(|second_bit| (EncodedToken::Literal(literal), second_bit));
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                payloads.push(EncodedToken::Literal(literal));
                flag_bits += flag.len();
                if flag_bits == 8 && plan.run_length() >= 16 && pos + 1 < input.len() {
                    group_enters_run_mode = true;
                }
                pos += 1;
                plan.put_literal(&mut BitCounter::default(), literal)?;
            }

            self.model.put_flag_byte(&mut bits, flags)?;
            self.emit_payloads(&mut bits, payloads)?;
            if group_enters_run_mode {
                if self.options.run_mode_literals {
                    self.emit_run_mode_literals(&mut bits, input, Some(&mut index), &mut pos)?;
                }
                self.model.put_run_exit(&mut bits)?;
            }
            if pos >= next_report {
                if progress.as_deref_mut().is_some_and(|report| !report(pos)) {
                    return Err(Error::Cancelled);
                }
                next_report = pos.saturating_add(1024 * 1024);
            }
        }
        if progress.is_some_and(|report| !report(input.len())) {
            return Err(Error::Cancelled);
        }
        Ok(bits.finish())
    }

    fn emit_payloads(&mut self, bits: &mut BitWriter, payloads: Vec<EncodedToken>) -> Result<()> {
        for payload in payloads {
            emit_token(&mut self.model, bits, payload)?;
        }
        Ok(())
    }

    /// Emits run-mode literals until the member's last byte, or until a
    /// match is available when there is an `index` to search.
    fn emit_run_mode_literals(
        &mut self,
        bits: &mut BitWriter,
        input: &[u8],
        mut index: Option<&mut MatchIndex>,
        pos: &mut usize,
    ) -> Result<()> {
        while *pos + 1 < input.len() {
            // Read the byte through `get`, not `input[*pos]`: the loop's own
            // guard implies it is in range, but the compiler does not prove
            // it and emits a bounds check (target 8.5).
            let Some(&literal) = input.get(*pos) else {
                break;
            };
            if let Some(index) = index.as_deref_mut() {
                if find_token(input, *pos, index, plan_state(&self.model), self.options).is_some() {
                    break;
                }
            }
            self.model.put_run_literal(bits, literal)?;
            #[cfg(test)]
            {
                self.run_literal_count += 1;
            }
            *pos += 1;
        }
        Ok(())
    }
}

/// A RAR 1.5 encoder with a decoder in lockstep, for the archive writers.
/// Every member is decoded back before it is handed out, so a stream the
/// decoder would not reproduce never reaches an archive. The solid writers
/// need this most: they cannot retry a member with other options once the
/// encoder has moved past it.
pub(crate) struct Rar15CheckedEncoder {
    encoder: Rar15Encoder,
    /// Built once the first non-empty member is encoded, so its window is
    /// not live while the planner is at its peak on that member.
    decoder: Option<Rar15Decoder>,
}

impl Rar15CheckedEncoder {
    pub(crate) fn with_options(options: EncodeOptions) -> Self {
        Self {
            encoder: Rar15Encoder::with_options(options),
            decoder: None,
        }
    }

    /// The next member, or `None` when it does not decode back. After a
    /// `None` the two halves are out of step, so no further member may be
    /// encoded with this value.
    pub(crate) fn encode_member_with_progress(
        &mut self,
        input: &[u8],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        let packed = self.encoder.encode_member_with_progress(input, progress)?;
        if input.is_empty() {
            return Ok(Some(packed));
        }
        let mut expected = MatchingWriter { rest: input };
        let started = self.decoder.is_some();
        let decoded = self
            .decoder
            .get_or_insert_with(Rar15Decoder::new)
            .decode_member_to(&packed, input.len(), started, &mut expected);
        Ok((decoded.is_ok() && expected.rest.is_empty()).then_some(packed))
    }

    /// As [`Self::encode_member_with_progress`], with a member that does not
    /// decode back reported as an error.
    pub(crate) fn encode_solid_member_with_progress(
        &mut self,
        input: &[u8],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        self.encode_member_with_progress(input, progress)?
            .ok_or(Error::InvalidData(
                "RAR 1.5 encoder produced a member that does not decode back",
            ))
    }
}

/// Accepts exactly the bytes of `rest`, in order. The archive writers use
/// it too, to decode RAR 2.0 and RAR 2.9 members back.
pub(crate) struct MatchingWriter<'a> {
    rest: &'a [u8],
}

impl<'a> MatchingWriter<'a> {
    pub(crate) fn new(expected: &'a [u8]) -> Self {
        Self { rest: expected }
    }

    /// Whether every expected byte has been written.
    pub(crate) fn is_complete(&self) -> bool {
        self.rest.is_empty()
    }
}

impl std::io::Write for MatchingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let rest = self
            .rest
            .strip_prefix(buf)
            .ok_or_else(|| std::io::Error::other("RAR 1.5 member does not decode back"))?;
        self.rest = rest;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writes one planned token through the model.
fn emit_token(model: &mut Model, sink: &mut impl BitSink, token: EncodedToken) -> Result<()> {
    match token {
        EncodedToken::Literal(byte) => model.put_literal(sink, byte),
        EncodedToken::Near(near) => model.put_near(sink, near.length, near.distance),
        EncodedToken::Repeat(repeat) => model.put_repeat(sink, repeat.length, repeat.distance),
        EncodedToken::Ring(ring) => model.put_ring(sink, ring.slot(), ring.length),
        EncodedToken::Long(long) => model.put_long(sink, long.length, long.distance),
    }
}

/// Picks the candidate with the fewest bits per byte at `pos`, wherever its
/// flag falls in the group: a two-bit flag that reaches bit 7 straddles into
/// the next flag byte (4.4). Turning candidates away by flag position, which
/// the planner did before it could straddle, kept one-bit long matches out
/// of even bit positions and cost 3.2% of packed size over the writers'
/// levels, 16% on large text (15 Sep 2026).
fn choose_token(
    model: &Model,
    options: EncodeOptions,
    input: &[u8],
    pos: usize,
    index: &mut MatchIndex,
    state: PlanState,
) -> Option<EncodedToken> {
    let candidates = find_tokens(input, pos, index, state, options);
    candidates
        .into_iter()
        .filter_map(|token| token_bit_cost(model, token, state).map(|cost| (token, cost)))
        .min_by(|(left, left_cost), (right, right_cost)| {
            let left_score = left_cost * 256 / left.length() as usize;
            let right_score = right_cost * 256 / right.length() as usize;
            left_score
                .cmp(&right_score)
                .then_with(|| right.length().cmp(&left.length()))
        })
        .map(|(token, _)| token)
}

/// Flag bits plus payload bits of `token` under `model`.
fn token_bit_cost(model: &Model, token: EncodedToken, state: PlanState) -> Option<usize> {
    let flag_cost = token.flag_bits(state.pref_long, state.pref_literal).len();
    let payload = match token {
        // Dead, and deliberately: see `EncodedToken::flag_bits`.
        EncodedToken::Literal(byte) => model.literal_bits(byte)?,
        EncodedToken::Repeat(repeat) => model.repeat_bits(repeat.length, repeat.distance)?,
        EncodedToken::Near(near) => model.near_bits(near.length, near.distance)?,
        EncodedToken::Ring(ring) => model.ring_bits(ring.slot(), ring.length)?,
        EncodedToken::Long(long) => model.long_bits(long.length, long.distance)?,
    };
    Some(flag_cost + payload as usize)
}

/// The part of the model the match finders read.
#[derive(Debug, Clone, Copy)]
struct PlanState {
    previous_distance: u32,
    previous_length: u32,
    /// Recent distances, newest first.
    recent: [u32; 4],
    threshold: u32,
    pref_long: u32,
    pref_literal: u32,
}

fn plan_state(model: &Model) -> PlanState {
    let (previous_distance, previous_length) = model.last_match();
    PlanState {
        previous_distance,
        previous_length,
        recent: model.recent(),
        threshold: model.threshold(),
        pref_long: model.pref_long(),
        pref_literal: model.pref_literal(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedToken {
    Literal(u8),
    Near(NearMatch),
    Repeat(RepeatMatch),
    Ring(RingMatch),
    Long(LongMatch),
}

impl EncodedToken {
    fn length(self) -> u32 {
        match self {
            Self::Literal(_) => 1,
            Self::Near(token) => token.length,
            Self::Repeat(token) => token.length,
            Self::Ring(token) => token.length,
            Self::Long(token) => token.length,
        }
    }

    /// `Self::Literal` reaches neither call site today, and the arm stays:
    /// `match` needs it, and it is the right answer if one ever does arrive.
    /// Both callers take their token from [`choose_token`], hence from
    /// [`find_tokens`], which offers only the four match families - pinned by
    /// `tests::find_tokens_never_offers_a_literal_candidate`, because
    /// "unreachable by inspection" is exactly the claim a new call site makes
    /// stale. A planned literal takes its flag from [`literal_flag_bits`]
    /// directly, and a straddling one is written as `FlagBits::one`.
    /// [`token_bit_cost`]'s `Literal` arm is dead for this same reason and
    /// kept for it. Census leg A3, 16 Sep 2026.
    fn flag_bits(self, pref_long: u32, pref_literal: u32) -> FlagBits {
        match self {
            Self::Literal(_) => literal_flag_bits(pref_long <= pref_literal),
            Self::Long(_) => long_flag_bits(pref_long > pref_literal),
            Self::Near(_) | Self::Repeat(_) | Self::Ring(_) => FlagBits::two(false, false),
        }
    }
}

/// A match at distance 1..=256, length 3..=10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NearMatch {
    distance: u32,
    length: u32,
}

/// The previous match again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepeatMatch {
    distance: u32,
    length: u32,
}

/// A match at one of the four recent distances; `index` is the short index
/// 10..=13 (10 = newest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RingMatch {
    distance: u32,
    length: u32,
    index: u32,
}

impl RingMatch {
    /// 1 for the newest recent distance, up to 4.
    fn slot(self) -> usize {
        (self.index - 9) as usize
    }
}

/// A match at distance 257..=32767 found by [`find_long_match_bucketed`].
///
/// `pub(crate)` since 17 Sep 2026. It was `pub` while `find_long_match` was,
/// and that function is now `#[cfg(test)] pub(crate)`, which left this a
/// public type in a public module that no public API produced or consumed.
/// A census of every public type in `codec`'s five public submodules
/// (`rar13`, `rar20`, `rar29`, `rar50`, `rarvm` - 30 types) found this the
/// ONLY one in that shape: every other either carries its own public
/// constructor or is named in a public signature. The one that looks like a
/// second instance, `rar50::DecodedChunk`, is not - it is `#[doc(hidden)]`
/// and a caller must be able to name it to write the `FnMut` sink that
/// `decode_member_from_reader_with_dictionary_to_sink` takes. So this was a
/// leftover rather than a policy question about how much of `codec` should
/// be public, and narrowing it needed no wider change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LongMatch {
    pub(crate) distance: u32,
    pub(crate) length: u32,
}

/// An item's flag bits: always one or two, never more. The count is carried
/// by the type rather than by a slice length, so [`Self::second`] - the bit
/// an item carries into the next group when its flag straddles bit 7 - needs
/// no bounds check (target 8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlagBits {
    first: bool,
    second: Option<bool>,
}

impl FlagBits {
    const fn one(first: bool) -> Self {
        Self {
            first,
            second: None,
        }
    }

    const fn two(first: bool, second: bool) -> Self {
        Self {
            first,
            second: Some(second),
        }
    }

    const fn len(self) -> usize {
        if self.second.is_some() {
            2
        } else {
            1
        }
    }

    /// The second bit, for the item whose flag did not fit the byte.
    const fn second(self) -> Option<bool> {
        self.second
    }
}

fn literal_flag_bits(one_bit: bool) -> FlagBits {
    if one_bit {
        FlagBits::one(true)
    } else {
        FlagBits::two(false, true)
    }
}

fn long_flag_bits(one_bit: bool) -> FlagBits {
    if one_bit {
        FlagBits::one(true)
    } else {
        FlagBits::two(false, true)
    }
}

/// Opens a flag group with the item whose two-bit flag did not fit in bit 7
/// of the previous group: `01` for a literal or long match, `00` for the
/// short-match family. Its `0` stays in that bit, `second_bit` is this
/// group's first bit, and its payload comes after this group's flag byte,
/// which is where the decoder reads it (D2, 4.4). A one-bit flag always
/// fits, so only a two-bit flag gets here.
fn open_with_straddling_token(
    flags: &mut u8,
    flag_bits: &mut usize,
    payloads: &mut Vec<EncodedToken>,
    token: EncodedToken,
    second_bit: bool,
) {
    write_planned_flag_bits(flags, 0, FlagBits::one(second_bit));
    *flag_bits = 1;
    payloads.push(token);
}

fn write_planned_flag_bits(flags: &mut u8, start: usize, bits: FlagBits) {
    if bits.first {
        *flags |= 1 << (7 - start);
    }
    if bits.second == Some(true) {
        *flags |= 1 << (6 - start);
    }
}

fn find_token(
    input: &[u8],
    pos: usize,
    index: &mut MatchIndex,
    state: PlanState,
    options: EncodeOptions,
) -> Option<EncodedToken> {
    find_tokens(input, pos, index, state, options)
        .into_iter()
        .next()
}

fn find_tokens(
    input: &[u8],
    pos: usize,
    index: &mut MatchIndex,
    state: PlanState,
    options: EncodeOptions,
) -> Vec<EncodedToken> {
    let mut tokens = Vec::with_capacity(4);
    if let Some(repeat) =
        find_repeat_match(input, pos, state.previous_distance, state.previous_length)
    {
        tokens.push(EncodedToken::Repeat(repeat));
    }
    if options.ring_matches {
        if let Some(ring) = find_ring_match(input, pos, state.recent) {
            tokens.push(EncodedToken::Ring(ring));
        }
    }
    if let Some(near) = find_near_match(input, pos) {
        tokens.push(EncodedToken::Near(near));
    }
    if let Some(long) = find_long_match_bucketed(
        input,
        pos,
        options.max_long_match_distance,
        index,
        MAX_LONG_MATCH_CANDIDATES,
    )
    .filter(|long| long_length_code(*long, state.threshold).is_some())
    {
        tokens.push(EncodedToken::Long(long));
    }
    tokens
}

fn should_lazy_emit_literal(
    input: &[u8],
    pos: usize,
    index: &mut MatchIndex,
    current: EncodedToken,
    threshold: u32,
    options: EncodeOptions,
) -> bool {
    if !matches!(current, EncodedToken::Near(_) | EncodedToken::Long(_)) || pos + 1 >= input.len() {
        return false;
    }

    let next = find_token(
        input,
        pos + 1,
        index,
        PlanState {
            previous_distance: NONE,
            previous_length: 0,
            recent: [NONE; 4],
            threshold,
            pref_long: 0,
            pref_literal: 0,
        },
        options,
    );
    next.is_some_and(|next| {
        matches!(next, EncodedToken::Near(_) | EncodedToken::Long(_))
            && next.length() >= current.length() + 2
    })
}

fn find_near_match(input: &[u8], pos: usize) -> Option<NearMatch> {
    if pos < 2 {
        return None;
    }

    let max_distance = pos.min(256);
    let mut best = NearMatch {
        distance: 0,
        length: 0,
    };
    for distance in 1..=max_distance {
        let mut length = 0usize;
        while length < 10
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3
            && (length > best.length as usize
                || (length == best.length as usize && distance < best.distance as usize))
        {
            best = NearMatch {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

fn find_repeat_match(
    input: &[u8],
    pos: usize,
    previous_distance: u32,
    previous_length: u32,
) -> Option<RepeatMatch> {
    if previous_distance == NONE || previous_distance == 0 || previous_length == 0 {
        return None;
    }
    let distance = usize::try_from(previous_distance).ok()?;
    let length = usize::try_from(previous_length).ok()?;
    if distance > pos || pos.checked_add(length)? > input.len() {
        return None;
    }
    let matches = (0..length).all(|offset| input[pos + offset] == input[pos + offset - distance]);
    matches.then_some(RepeatMatch {
        distance: previous_distance,
        length: previous_length,
    })
}

fn find_ring_match(input: &[u8], pos: usize, recent: [u32; 4]) -> Option<RingMatch> {
    let mut best = RingMatch {
        distance: 0,
        length: 0,
        index: 0,
    };
    for index in 10..=13 {
        let distance = recent[(index - 10) as usize];
        if distance == NONE || distance == 0 {
            continue;
        }
        let Ok(distance_usize) = usize::try_from(distance) else {
            continue;
        };
        if distance_usize > pos {
            continue;
        }
        let mut length = 0usize;
        while length < 258
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance_usize]
        {
            length += 1;
        }
        if length >= 3
            && ring_match_is_encodable(length as u32, distance, index)
            && length > best.length as usize
        {
            best = RingMatch {
                distance,
                length: length as u32,
                index,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

/// A ring match must be expressible under either threshold, because the
/// threshold can change before the planned item is written.
fn ring_match_is_encodable(length: u32, distance: u32, index: u32) -> bool {
    ring_match_length_code(length, distance, 0x2001, index).is_some()
        && ring_match_length_code(length, distance, 0x7f00, index).is_some()
}

fn ring_match_length_code(length: u32, distance: u32, threshold: u32, index: u32) -> Option<u32> {
    let bonus = u32::from(distance > 256) + u32::from(distance >= threshold);
    let length_code = length.checked_sub(2 + bonus)?;
    // Index 10 with length code 255 is the toggle, not a match.
    if index == 10 && length_code == 0xff {
        return None;
    }
    Some(length_code)
}

fn long_length_code(long: LongMatch, threshold: u32) -> Option<u32> {
    let bonus = u32::from(long.distance >= threshold) + u32::from(long.distance <= 256);
    long.length.checked_sub(3 + bonus)
}

/// The longest match at distance 257..=`max_match_distance` (capped at
/// 32767) starting at `pos`, by exhaustive search.
///
/// TEST ORACLE ONLY. The planner's long finder is
/// [`find_long_match_bucketed`]; this has no production caller and had no
/// business being `pub` in the crate's API, which is what it was until
/// 17 Sep 2026. Two tests lean on it as an oracle, so its own bounds are
/// pinned by `tests::find_long_match_holds_the_bounds_its_dependants_assume`.
#[cfg(test)]
pub(crate) fn find_long_match(input: &[u8], pos: usize, max_match_distance: usize) -> Option<LongMatch> {
    // Redundant with the `max_distance < 257` test below, which subsumes it
    // for every `pos` under 257, and kept only as the bound stated where a
    // reader looks for it. Census leg I1 reports it uncaught for that reason:
    // no input can tell the two apart, so no test here pretends to.
    if pos < 257 {
        return None;
    }

    let max_distance = pos.min(MAX_LONG_DISTANCE).min(max_match_distance);
    if max_distance < 257 {
        return None;
    }
    let mut best = LongMatch {
        distance: 0,
        length: 0,
    };
    for distance in 257..=max_distance {
        let mut length = 0usize;
        while length < 258
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3 && length > best.length as usize {
            best = LongMatch {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

/// The best long match at `pos`, by walking [`MatchIndex`]'s chain for the
/// hash of the three bytes there and verifying each candidate's bytes.
///
/// **The walk has no cycle guard and is not owed one.** Two arguments, of
/// which the second holds even if the first is broken:
///
/// * No reachable index state has a cycle. [`MatchIndex::insert_below`]
///   writes a position's link to a position strictly below it, so a chain of
///   fresh links strictly descends. A slot is reused only when the position
///   `ring.len()` later goes in, and `ring.len()` is either [`MATCH_WINDOW`],
///   which is larger than any `max_distance` this walk allows, or the
///   member's own rounded-up length, which nothing is ever that far behind.
///   So every link read inside `max_distance` is fresh. The walk reads one
///   link past the bound before it breaks, and discards it unread.
/// * A reused slot still would not hang it. A cycle needs one, a reused slot
///   needs a candidate at least `ring.len()` behind `pos`, and `ring.len()`
///   is far more than 257 - so any such cycle contains a candidate the
///   `checked` counter counts, and `checked` is capped at `max_candidates`,
///   which the entry guard refuses to let be zero.
///
/// A guard would therefore change no outcome on any state this code can
/// reach, and it would cost a real signal. Census leg K3 swaps
/// `insert_below`'s two lines so a position links to ITSELF; that is the one
/// shape neither argument covers, because a self-link at distance under 257
/// is never counted, and the suite WEDGES on it. The wedge is how that
/// mutation is detected at all - no test names it. A cycle guard would turn
/// it into a quiet pass with silently worse output.
fn find_long_match_bucketed(
    input: &[u8],
    pos: usize,
    max_match_distance: usize,
    index: &mut MatchIndex,
    max_candidates: usize,
) -> Option<LongMatch> {
    // The `pos < 257` term alone is redundant, for the same reason leg I1's
    // is in `find_long_match`: `max_distance` below is `pos.min(..)`, so a `pos`
    // under 257 fails that test too, and no input can tell the two apart. It
    // is kept as the bound stated where a reader looks for it. The other two
    // terms are NOT redundant - `pos + 2 >= input.len()` guards the
    // `match_hash` read of three bytes, and `max_candidates == 0` is what the
    // no-cycle-guard argument above leans on.
    if pos < 257 || pos + 2 >= input.len() || max_candidates == 0 {
        return None;
    }

    let max_distance = pos.min(MAX_LONG_DISTANCE).min(max_match_distance);
    if max_distance < 257 {
        return None;
    }
    let max_length = (input.len() - pos).min(258);
    let mut best = LongMatch {
        distance: 0,
        length: 0,
    };
    let mut checked = 0usize;
    index.insert_below(input, pos);
    let mut candidate = index.head[match_hash(input, pos)];
    while candidate != NO_POSITION {
        let next = index.previous(candidate);
        // A lazy look one position ahead may have inserted `pos` itself;
        // positions at or after `pos` are never candidates and never counted.
        if candidate >= pos {
            candidate = next;
            continue;
        }
        let distance = pos - candidate;
        if distance > max_distance {
            break;
        }
        candidate = next;
        if distance < 257 {
            continue;
        }
        checked += 1;
        let mut length = 0usize;
        while length < max_length && input[pos + length] == input[pos + length - distance] {
            length += 1;
        }
        if length >= 3
            && (length > best.length as usize
                || (length == best.length as usize && distance < best.distance as usize))
        {
            best = LongMatch {
                distance: distance as u32,
                length: length as u32,
            };
            if length == max_length {
                break;
            }
        }
        if checked >= max_candidates {
            break;
        }
    }

    (best.length >= 3).then_some(best)
}

/// Earlier positions by the hash of their first three bytes, for the
/// long-match search: a chain through a ring of at most [`MATCH_WINDOW`]
/// links, so it costs the same for a 64 KiB member as for a 1 GiB one.
///
/// `head` holds the newest position inserted under each hash, and a
/// position's ring slot the position inserted under that hash before it.
/// Positions go in in increasing order as the planner moves forward, so a
/// walk from `head` meets candidates newest first. A slot is reused only
/// when the position [`MATCH_WINDOW`] later goes in. The search reads the
/// link of a candidate at most `MAX_LONG_DISTANCE` behind the position it
/// searches, and inserts only below that position, so every link it reads
/// was written by its own position and not yet reused.
struct MatchIndex {
    head: [usize; MATCH_HASH_BUCKETS],
    /// Ring of links, a power of two no larger than the member needs.
    ring: Vec<usize>,
    /// Every hashable position below this is in the index.
    inserted: usize,
}

impl MatchIndex {
    fn new(member_len: usize) -> Self {
        Self {
            head: [NO_POSITION; MATCH_HASH_BUCKETS],
            ring: vec![NO_POSITION; member_len.next_power_of_two().min(MATCH_WINDOW)],
            inserted: 0,
        }
    }

    /// Inserts every hashable position below `pos`.
    fn insert_below(&mut self, input: &[u8], pos: usize) {
        let mask = self.ring.len() - 1;
        let end = pos.min(input.len().saturating_sub(2));
        while self.inserted < end {
            let at = self.inserted;
            let hash = match_hash(input, at);
            self.ring[at & mask] = self.head[hash];
            self.head[hash] = at;
            self.inserted += 1;
        }
    }

    /// The position inserted under the same hash before `position`.
    fn previous(&self, position: usize) -> usize {
        self.ring[position & (self.ring.len() - 1)]
    }
}

fn match_hash(input: &[u8], pos: usize) -> usize {
    let value =
        ((input[pos] as usize) << 8) ^ ((input[pos + 1] as usize) << 4) ^ input[pos + 2] as usize;
    value & (MATCH_HASH_BUCKETS - 1)
}
