//! The adaptive state of the RAR 1.5 algorithm and its update rules, shared
//! by the decoder and the encoder so the two cannot drift.
//!
//! Rule ids (D1-D9, L) name the rules of the clean-room specification
//! (nzbfast `research/cleanroom/SPEC-A-rar15-codec.md`, section 4). The
//! decoder reads bits, then calls an update here with the decoded values;
//! the encoder works out the values for the item it wants, writes their
//! codewords, then calls the same update. Section 5's commits live at the
//! bottom of this file.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use super::super::{Error, Result};
use super::bits::BitSink;
use super::codes::{
    PrefixCode, LENA, LENB, RK0, RK1, RK2, RK3, RK4, SHA, SHA_TOGGLED, SHB, SHB_TOGGLED,
};

/// The "none" distance: greater than every number it is compared with, and a
/// copy at it produces zero bytes.
pub(crate) const NONE: u32 = u32::MAX;

#[inline(always)]
#[allow(clippy::indexing_slicing)] // a u8 index is always inside 256 entries
fn at(table: &[u8; 256], index: u8) -> u8 {
    table[usize::from(index)]
}

#[inline(always)]
#[allow(clippy::indexing_slicing)] // a u8 index is always inside 256 entries
fn set(table: &mut [u8; 256], index: u8, value: u8) {
    table[usize::from(index)] = value;
}

#[inline(always)]
#[allow(clippy::indexing_slicing)] // a u8 index is always inside 256 entries
fn at16(table: &[u16; 256], index: u8) -> u16 {
    table[usize::from(index)]
}

#[inline(always)]
#[allow(clippy::indexing_slicing)] // a u8 index is always inside 256 entries
fn set16(table: &mut [u16; 256], index: u8, value: u16) {
    table[usize::from(index)] = value;
}

/// An adaptive rank table (4.1): 256 slots of (symbol, weight), a cursor per
/// weight, and a symbol-to-slot inverse so the encoder's lookups are O(1).
/// `CEILING` is the weight no slot may exceed.
#[derive(Clone, Copy)]
pub(crate) struct RankTable<const CEILING: u16> {
    /// Per slot, `symbol | weight << 8`, so one load reads both.
    entry: [u16; 256],
    cursor: [u8; 256],
    slot_of: [u8; 256],
}

impl<const CEILING: u16> RankTable<CEILING> {
    /// Slot `i` holds symbol `symbol_at(i)`, every weight and cursor 0.
    fn from_fn(symbol_at: impl Fn(u8) -> u8) -> Self {
        let mut table = Self {
            entry: [0; 256],
            cursor: [0; 256],
            slot_of: [0; 256],
        };
        for slot in 0..=255u8 {
            let symbol = symbol_at(slot);
            set16(&mut table.entry, slot, u16::from(symbol));
            set(&mut table.slot_of, symbol, slot);
        }
        table
    }

    /// Every slot keeps its symbol and gets weight 7 - slot/32; the cursor
    /// of weight w (0..=7) points at the first slot of that weight group.
    #[cold]
    #[inline(never)]
    fn renormalise(&mut self) {
        for slot in 0..=255u8 {
            let symbol = at16(&self.entry, slot) & 0xff;
            set16(
                &mut self.entry,
                slot,
                symbol | u16::from(7 - slot / 32) << 8,
            );
        }
        self.cursor = [0; 256];
        for weight in 0..=7u8 {
            set(&mut self.cursor, weight, 32 * (7 - weight));
        }
    }

    /// The symbol in `slot`. The decoder reads symbols through `take`, so
    /// only the tests use this.
    #[cfg(test)]
    pub(crate) fn symbol(&self, slot: u8) -> u8 {
        at16(&self.entry, slot) as u8
    }

    /// The slot holding `symbol`.
    #[inline(always)]
    pub(crate) fn slot_of(&self, symbol: u8) -> u8 {
        at(&self.slot_of, symbol)
    }

    /// Reads the symbol in `slot`, then promotes the slot (4.1): its entry
    /// trades places with the slot the cursor of its weight points at and
    /// gains one weight.
    #[inline(always)]
    fn take(&mut self, slot: u8) -> u8 {
        let mut entry = at16(&self.entry, slot);
        let symbol = entry as u8;
        if (entry >> 8) + 1 > CEILING {
            self.renormalise();
            entry = at16(&self.entry, slot);
        }
        let weight = (entry >> 8) as u8;
        let target = at(&self.cursor, weight);
        set(&mut self.cursor, weight, target.wrapping_add(1));
        let displaced = at16(&self.entry, target);
        set16(&mut self.entry, slot, displaced);
        // The weight is at most CEILING - 1 <= 254 here, so this cannot
        // overflow.
        set16(&mut self.entry, target, entry + 0x100);
        set(&mut self.slot_of, displaced as u8, slot);
        set(&mut self.slot_of, symbol, target);
        symbol
    }

    #[cfg(test)]
    fn promote(&mut self, slot: u8) {
        self.take(slot);
    }
}

/// How a long match's length code is read (D7 step 4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LengthForm {
    Lenb,
    Lena,
    /// Unary for 0..=7, or a 16-bit literal value when its top byte is 0.
    Unary,
}

/// D4's literal-preference rule: a literal's effect on the two preference
/// counters. THE ONE COPY. The decoder applies it through
/// [`Model::literal_at`]; the encoder's planner applies it to its own
/// speculative pair, ahead of the model, when choosing whether a literal's
/// flag takes the one-bit or the two-bit form. The two must agree exactly or
/// the stream desynchronises, which is why they are one function rather than
/// two - `super::plan_literal_preference` was a second, planner-private copy
/// of these four constants until 17 Sep 2026.
///
/// `codec::rar13::tests::literals_only_output_decodes_back_to_its_input`
/// checks the planner against the decoder on every literal of its second
/// case, and its comment names the entry states that make each constant
/// observable. Since the merge a broken constant reddens fixture-decoding
/// tests as well, because planner and decoder now move together.
///
/// The symmetric rule with the roles swapped lives inline in
/// [`Model::long_match`]. It has no second copy, so it is not shared here.
#[inline(always)]
pub(super) fn literal_preference(pref_literal: &mut u32, pref_long: &mut u32) {
    *pref_literal += 16;
    if *pref_literal > 0xff {
        *pref_literal = 0x90;
        *pref_long >>= 1;
    }
}

/// The adaptive model of section 3, output side excluded.
#[derive(Clone, Copy)]
pub(crate) struct Model {
    literals: RankTable<161>,
    flags: RankTable<255>,
    far: RankTable<255>,
    /// Near-match distance ranks, adjacent-swap order.
    near: [u8; 256],
    near_rank: [u8; 256],
    /// Recent match distances as a ring; `recent[head]` is the newest.
    recent: [u32; 4],
    head: u8,
    previous_distance: u32,
    previous_length: u32,
    avg_literal: u32,
    avg_far: u32,
    avg_short: u32,
    avg_long: u32,
    hits: u32,
    threshold: u32,
    pref_literal: u32,
    pref_long: u32,
    run: u32,
    run_mode: bool,
    toggle: bool,
    repeats: u8,
    /// Flag bits not yet used, most significant first.
    flag_byte: u8,
    flag_left: u8,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    /// The initial state (table 3.2).
    pub(crate) fn new() -> Self {
        let mut far = RankTable::from_fn(|slot| slot);
        far.renormalise();
        let mut near = [0u8; 256];
        for value in 0..=255u8 {
            set(&mut near, value, value);
        }
        Self {
            literals: RankTable::from_fn(|slot| slot),
            flags: RankTable::from_fn(|slot| 0u8.wrapping_sub(slot)),
            far,
            near,
            near_rank: near,
            recent: [NONE; 4],
            head: 0,
            previous_distance: NONE,
            previous_length: 0,
            avg_literal: 0x3500,
            avg_far: 0,
            avg_short: 0,
            avg_long: 0,
            hits: 0,
            threshold: 0x2001,
            pref_literal: 128,
            pref_long: 128,
            run: 0,
            run_mode: false,
            toggle: false,
            repeats: 0,
            flag_byte: 0,
            flag_left: 0,
        }
    }

    /// D1: the full reset when not solid, then the member reset. `RUN` and
    /// `TOGGLE` survive a solid continuation on purpose.
    pub(crate) fn begin_member(&mut self, solid: bool) {
        if !solid {
            *self = Self::new();
        }
        self.run_mode = false;
        self.repeats = 0;
        self.flag_byte = 0;
        self.flag_left = 0;
    }

    // ---- read-only queries -------------------------------------------------

    /// `PREF_LONG > PREF_LIT`: decides which step a single flag bit selects.
    #[inline(always)]
    pub(crate) fn prefers_long(&self) -> bool {
        self.pref_long > self.pref_literal
    }

    #[inline(always)]
    pub(crate) fn pref_literal(&self) -> u32 {
        self.pref_literal
    }

    #[inline(always)]
    pub(crate) fn pref_long(&self) -> u32 {
        self.pref_long
    }

    #[inline(always)]
    pub(crate) fn run_mode(&self) -> bool {
        self.run_mode
    }

    #[inline(always)]
    pub(crate) fn repeats(&self) -> u8 {
        self.repeats
    }

    #[inline(always)]
    pub(crate) fn run_length(&self) -> u32 {
        self.run
    }

    #[inline(always)]
    pub(crate) fn threshold(&self) -> u32 {
        self.threshold
    }

    /// D7's hit counter. The decoder only ever reads it through `threshold`
    /// (step 12's `H3 > 176`), so only the tests read it directly.
    #[cfg(test)]
    pub(crate) fn hits(&self) -> u32 {
        self.hits
    }

    /// The previous match as (distance, length); the distance may be [`NONE`].
    #[inline(always)]
    pub(crate) fn last_match(&self) -> (u32, u32) {
        (self.previous_distance, self.previous_length)
    }

    /// The four recent distances, newest first; entries may be [`NONE`].
    #[inline(always)]
    pub(crate) fn recent(&self) -> [u32; 4] {
        [self.ring(0), self.ring(1), self.ring(2), self.ring(3)]
    }

    /// The recent distance pushed `back` pushes ago (0 = newest).
    #[inline(always)]
    #[allow(clippy::indexing_slicing)] // masked to 0..=3
    fn ring(&self, back: u8) -> u32 {
        self.recent[usize::from(self.head.wrapping_sub(back) & 3)]
    }

    #[inline(always)]
    pub(crate) fn flag_left(&self) -> u8 {
        self.flag_left
    }

    /// Literal code choice (4.5), from `AVG_LIT`.
    #[inline(always)]
    pub(crate) fn literal_code(&self) -> &'static PrefixCode {
        match self.avg_literal {
            0..=3583 => &RK0,
            3584..=13823 => &RK1,
            13824..=24063 => &RK2,
            24064..=30207 => &RK3,
            _ => &RK4,
        }
    }

    /// D6b: the short index code, from `AVG_SHORT` and `TOGGLE`.
    #[inline(always)]
    pub(crate) fn short_code(&self) -> &'static PrefixCode {
        match (self.avg_short < 37, self.toggle) {
            (true, false) => &SHA,
            (true, true) => &SHA_TOGGLED,
            (false, false) => &SHB,
            (false, true) => &SHB_TOGGLED,
        }
    }

    /// D7 step 4: the long length form, from `AVG_LONG`.
    #[inline(always)]
    pub(crate) fn long_length_form(&self) -> LengthForm {
        match self.avg_long {
            122.. => LengthForm::Lenb,
            64..=121 => LengthForm::Lena,
            _ => LengthForm::Unary,
        }
    }

    /// D7 step 6: the long distance-rank code, from `AVG_FAR`.
    #[inline(always)]
    pub(crate) fn far_rank_code(&self) -> &'static PrefixCode {
        match self.avg_far {
            0..=1791 => &RK0,
            1792..=10495 => &RK1,
            _ => &RK2,
        }
    }

    // ---- update rules, driven by decoded values ---------------------------

    /// D3: a new flag byte from rank value `v` (0..=256).
    #[inline(always)]
    pub(crate) fn flag_byte(&mut self, v: u16) {
        self.flag_byte = match u8::try_from(v) {
            Ok(slot) => self.flags.take(slot),
            Err(_) => 0,
        };
        self.flag_left = 8;
    }

    /// Takes the next flag bit; the caller decodes a flag byte first when
    /// [`Self::flag_left`] is 0.
    #[inline(always)]
    pub(crate) fn take_flag_bit(&mut self) -> bool {
        let bit = self.flag_byte & 0x80 != 0;
        self.flag_byte <<= 1;
        self.flag_left = self.flag_left.saturating_sub(1);
        bit
    }

    /// Rule L: literal at slot `q`; returns the byte to output.
    #[inline(always)]
    fn literal_at(&mut self, q: u8) -> u8 {
        self.avg_literal += u32::from(q);
        self.avg_literal -= self.avg_literal >> 8;
        literal_preference(&mut self.pref_literal, &mut self.pref_long);
        self.literals.take(q)
    }

    /// D4: a normal literal from literal-code value `v` (0..=256), after its
    /// flag bits have been taken.
    #[inline(always)]
    pub(crate) fn literal(&mut self, v: u16) -> u8 {
        if self.run >= 16 && self.flag_left == 0 {
            self.run_mode = true;
        }
        self.run = self.run.saturating_add(1);
        self.literal_at(v as u8)
    }

    /// D5, v >= 1: a run-mode literal; `v` is 1..=256.
    #[inline(always)]
    pub(crate) fn run_literal(&mut self, v: u16) -> u8 {
        self.literal_at(v.wrapping_sub(1) as u8)
    }

    /// D5 exit.
    #[inline(always)]
    pub(crate) fn run_exit(&mut self) {
        self.run = 0;
        self.run_mode = false;
    }

    #[inline(always)]
    fn push_match(&mut self, distance: u32, length: u32) {
        self.head = self.head.wrapping_add(1) & 3;
        #[allow(clippy::indexing_slicing)] // masked to 0..=3
        {
            self.recent[usize::from(self.head)] = distance;
        }
        self.previous_distance = distance;
        self.previous_length = length;
    }

    /// D6 entry: every short-family step clears `RUN`.
    #[inline(always)]
    pub(crate) fn short_begin(&mut self) {
        self.run = 0;
    }

    /// D6a with escape bit 0: the repeat counter drops to 0.
    #[inline(always)]
    pub(crate) fn clear_repeats(&mut self) {
        self.repeats = 0;
    }

    /// D6c, index 9: repeat the previous match.
    #[inline(always)]
    pub(crate) fn repeat(&mut self) -> (u32, u32) {
        self.repeats = self.repeats.saturating_add(1);
        (self.previous_distance, self.previous_length)
    }

    /// D6d, index 14: length code `x` (0..=255) and 15 distance bits `g`.
    #[inline(always)]
    pub(crate) fn far_short(&mut self, x: u16, g: u32) -> (u32, u32) {
        self.repeats = 0;
        let length = u32::from(x) + 5;
        let distance = 0x8000 + (g & 0x7fff);
        self.previous_distance = distance;
        self.previous_length = length;
        (distance, length)
    }

    /// D6e, indexes 10..=13: `x` is the `LENA` value. `None` is the toggle
    /// (index 10 with x = 255): no output.
    #[inline(always)]
    pub(crate) fn ring_match(&mut self, index: u8, x: u16) -> Option<(u32, u32)> {
        self.repeats = 0;
        let distance = if (10..=13).contains(&index) {
            self.ring(index - 10)
        } else {
            NONE
        };
        if index == 10 && x == 255 {
            self.toggle = !self.toggle;
            return None;
        }
        let length =
            u32::from(x) + 2 + u32::from(distance > 256) + u32::from(distance >= self.threshold);
        self.push_match(distance, length);
        Some((distance, length))
    }

    /// D6f, indexes 0..=8: `v` is the `RK2` value (0..=256).
    #[inline(always)]
    pub(crate) fn near_match(&mut self, index: u8, v: u16) -> (u32, u32) {
        self.repeats = 0;
        self.avg_short += u32::from(index);
        self.avg_short -= self.avg_short >> 4;
        let rank = v as u8;
        let value = at(&self.near, rank);
        if rank > 0 {
            let above = at(&self.near, rank - 1);
            set(&mut self.near, rank, above);
            set(&mut self.near, rank - 1, value);
            set(&mut self.near_rank, above, rank);
            set(&mut self.near_rank, value, rank - 1);
        }
        let distance = u32::from(value) + 1;
        let length = u32::from(index) + 2;
        self.push_match(distance, length);
        (distance, length)
    }

    /// D7 steps 1-3 and 5-13: length code `c` (0..=255), distance-rank value
    /// `v` (0..=256) and the 7 low distance bits `t`. The caller chose the
    /// codes for `c` and `v` from the state before this call.
    #[inline(always)]
    pub(crate) fn long_match(&mut self, c: u32, v: u16, t: u32) -> (u32, u32) {
        self.run = 0;
        self.pref_long += 16;
        if self.pref_long > 0xff {
            self.pref_long = 0x90;
            self.pref_literal >>= 1;
        }
        let avg_long_before = self.avg_long;
        let hits_before = self.hits;
        self.avg_long += c;
        self.avg_long -= self.avg_long >> 5;
        self.avg_far += u32::from(v);
        self.avg_far -= self.avg_far >> 8;
        let high = self.far.take(v as u8);
        let distance = u32::from(high) << 7 | (t & 0x7f);
        if c != 1 && c != 4 {
            if c == 0 && distance <= self.threshold {
                self.hits += 1;
                self.hits -= self.hits >> 8;
            } else if self.hits > 0 {
                self.hits -= 1;
            }
        }
        let length =
            c + 3 + u32::from(distance >= self.threshold) + if distance <= 256 { 8 } else { 0 };
        self.threshold = if hits_before > 176 || (self.avg_literal >= 10752 && avg_long_before < 64)
        {
            32512
        } else {
            8193
        };
        self.push_match(distance, length);
        (distance, length)
    }

    // ---- section 5: encoder costs and commits -----------------------------

    /// The item's bits under the current state, or `None` when it cannot be
    /// expressed now. Every commit below writes exactly these.
    fn escape_field(&self) -> Option<(u32, u32)> {
        (self.repeats == 2).then_some((0, 1))
    }

    fn literal_code_field(&self, v: u32) -> Option<(u32, u32)> {
        self.literal_code().encode(v)
    }

    fn near_fields(&self, length: u32, distance: u32) -> Option<Fields> {
        if !(2..=10).contains(&length) || !(1..=256).contains(&distance) || self.run_mode {
            return None;
        }
        let rank = at(&self.near_rank, (distance - 1) as u8);
        let mut fields = Fields::default();
        fields.push_opt(self.escape_field());
        fields.push(self.short_code().encode(length - 2)?);
        fields.push(RK2.encode(u32::from(rank))?);
        Some(fields)
    }

    fn ring_fields(&self, k: usize, length: u32) -> Option<Fields> {
        if self.run_mode {
            return None;
        }
        let distance = *self.recent().get(k.checked_sub(1)?)?;
        let bonus = u32::from(distance > 256) + u32::from(distance >= self.threshold);
        let x = length.checked_sub(2 + bonus)?;
        if x > 255 || (k == 1 && x == 255) {
            return None;
        }
        let mut fields = Fields::default();
        fields.push_opt(self.escape_field());
        fields.push(self.short_code().encode(9 + k as u32)?);
        fields.push(LENA.encode(x)?);
        Some(fields)
    }

    fn repeat_fields(&self, length: u32, distance: u32) -> Option<Fields> {
        if self.run_mode || (self.previous_distance, self.previous_length) != (distance, length) {
            return None;
        }
        let mut fields = Fields::default();
        if self.repeats == 2 {
            fields.push((1, 1));
        } else {
            fields.push(self.short_code().encode(9)?);
        }
        Some(fields)
    }

    fn long_fields(&self, length: u32, distance: u32) -> Option<(Fields, u32, u16)> {
        if self.run_mode || distance > 0x7fff {
            return None;
        }
        let bonus = u32::from(distance >= self.threshold) + if distance <= 256 { 8 } else { 0 };
        let c = length.checked_sub(3 + bonus)?;
        if c > 255 {
            return None;
        }
        let v = self.far.slot_of((distance >> 7) as u8);
        let mut fields = Fields::default();
        fields.push(match self.long_length_form() {
            LengthForm::Lenb => LENB.encode(c)?,
            LengthForm::Lena => LENA.encode(c)?,
            LengthForm::Unary if c <= 7 => (1, c + 1),
            LengthForm::Unary => (c, 16),
        });
        fields.push(self.far_rank_code().encode(u32::from(v))?);
        fields.push((distance & 0x7f, 7));
        Some((fields, c, u16::from(v)))
    }

    /// Flag bits a literal (`true`) or a long match (`false`) takes (5.4).
    #[inline(always)]
    pub(crate) fn flag_bits_for(&self, literal: bool) -> u8 {
        if literal != self.prefers_long() {
            1
        } else {
            2
        }
    }

    /// Payload bits of a normal literal (no flag bits).
    pub(crate) fn literal_bits(&self, byte: u8) -> Option<u32> {
        if self.run_mode {
            return None;
        }
        self.literal_code_field(u32::from(self.literals.slot_of(byte)))
            .map(|(_, length)| length)
    }

    pub(crate) fn repeat_bits(&self, length: u32, distance: u32) -> Option<u32> {
        self.repeat_fields(length, distance).map(|f| f.bits())
    }

    pub(crate) fn near_bits(&self, length: u32, distance: u32) -> Option<u32> {
        self.near_fields(length, distance).map(|f| f.bits())
    }

    pub(crate) fn ring_bits(&self, k: usize, length: u32) -> Option<u32> {
        self.ring_fields(k, length).map(|f| f.bits())
    }

    pub(crate) fn long_bits(&self, length: u32, distance: u32) -> Option<u32> {
        self.long_fields(length, distance).map(|(f, _, _)| f.bits())
    }

    fn take_flags(&mut self, count: u8) -> Result<()> {
        if self.flag_left < count {
            return Err(Error::InvalidData(
                "RAR 1.5 encoder item overruns its flag byte",
            ));
        }
        self.flag_byte = self.flag_byte.checked_shl(u32::from(count)).unwrap_or(0);
        self.flag_left -= count;
        Ok(())
    }

    /// Opens a flag group on a planning copy: the next items may take up to
    /// eight flag bits plus any bit the previous group left unused (see
    /// [`Self::put_flag_byte`]), and `FLG` is left alone (its codeword is
    /// not known until the group is planned).
    pub(crate) fn open_planning_group(&mut self) {
        self.flag_byte = 0;
        self.flag_left = self.flag_left.saturating_add(8);
    }

    /// Flag byte `flags` (D3).
    ///
    /// A bit left unused in the previous flag byte is still the next flag
    /// bit the decoder reads (D2), so it stays counted: it is the first bit
    /// of a two-bit flag that straddles the two bytes (4.4). Only one bit
    /// can be left that way, because a one-bit flag always fits.
    pub(crate) fn put_flag_byte(&mut self, sink: &mut impl BitSink, flags: u8) -> Result<()> {
        let carried = self.flag_left;
        if carried > 1 {
            return Err(Error::InvalidData(
                "RAR 1.5 flag byte opened with flag bits unused",
            ));
        }
        let slot = self.flags.slot_of(flags);
        let (word, length) = RK2
            .encode(u32::from(slot))
            .ok_or(Error::InvalidData("RAR 1.5 flag byte has no codeword"))?;
        sink.write_bits(word, length);
        self.flag_byte(u16::from(slot));
        self.flag_left += carried;
        Ok(())
    }

    /// A normal literal (D4), after the planner placed its flag bits.
    pub(crate) fn put_literal(&mut self, sink: &mut impl BitSink, byte: u8) -> Result<()> {
        let slot = self.literals.slot_of(byte);
        let field = (!self.run_mode)
            .then(|| self.literal_code_field(u32::from(slot)))
            .flatten()
            .ok_or(Error::InvalidData("RAR 1.5 literal is not encodable now"))?;
        self.take_flags(self.flag_bits_for(true))?;
        sink.write_bits(field.0, field.1);
        self.literal(u16::from(slot));
        Ok(())
    }

    /// A run-mode literal (D5).
    pub(crate) fn put_run_literal(&mut self, sink: &mut impl BitSink, byte: u8) -> Result<()> {
        let v = u32::from(self.literals.slot_of(byte)) + 1;
        let field = self
            .run_mode
            .then(|| self.literal_code_field(v))
            .flatten()
            .ok_or(Error::InvalidData(
                "RAR 1.5 run literal is not encodable now",
            ))?;
        sink.write_bits(field.0, field.1);
        self.run_literal(v as u16);
        Ok(())
    }

    /// The run-mode exit (D5).
    pub(crate) fn put_run_exit(&mut self, sink: &mut impl BitSink) -> Result<()> {
        let field = self
            .run_mode
            .then(|| self.literal_code_field(0))
            .flatten()
            .ok_or(Error::InvalidData("RAR 1.5 run exit outside run mode"))?;
        sink.write_bits(field.0, field.1);
        sink.write_bits(1, 1);
        self.run_exit();
        Ok(())
    }

    /// A run match (D5): length 3 or 4, distance 0..=8223. No state changes.
    #[cfg(test)]
    pub(crate) fn put_run_match(
        &mut self,
        sink: &mut impl BitSink,
        length: u32,
        distance: u32,
    ) -> Result<()> {
        let escape = self.run_mode.then(|| self.literal_code_field(0)).flatten();
        let rank = RK2.encode(distance / 32);
        let (Some(escape), Some(rank), 3..=4) = (escape, rank, length) else {
            return Err(Error::InvalidData("RAR 1.5 run match is not encodable now"));
        };
        sink.write_bits(escape.0, escape.1);
        sink.write_bits(0, 1);
        sink.write_bits(u32::from(length == 4), 1);
        sink.write_bits(rank.0, rank.1);
        sink.write_bits(distance & 31, 5);
        Ok(())
    }

    fn short_commit(&mut self, sink: &mut impl BitSink, fields: Fields) -> Result<()> {
        self.take_flags(2)?;
        fields.write(sink);
        self.short_begin();
        if self.repeats == 2 {
            self.clear_repeats();
        }
        Ok(())
    }

    /// A repeat of the previous match (D6a bit 1, or D6c).
    pub(crate) fn put_repeat(
        &mut self,
        sink: &mut impl BitSink,
        length: u32,
        distance: u32,
    ) -> Result<()> {
        let fields = self
            .repeat_fields(length, distance)
            .ok_or(Error::InvalidData(
                "RAR 1.5 repeat does not match the last match",
            ))?;
        self.take_flags(2)?;
        fields.write(sink);
        self.short_begin();
        if self.repeats != 2 {
            self.repeat();
        }
        Ok(())
    }

    /// A near match (D6f): length 2..=10, distance 1..=256.
    pub(crate) fn put_near(
        &mut self,
        sink: &mut impl BitSink,
        length: u32,
        distance: u32,
    ) -> Result<()> {
        let fields = self
            .near_fields(length, distance)
            .ok_or(Error::InvalidData(
                "RAR 1.5 near match is not encodable now",
            ))?;
        let rank = at(&self.near_rank, (distance - 1) as u8);
        self.short_commit(sink, fields)?;
        self.near_match((length - 2) as u8, u16::from(rank));
        Ok(())
    }

    /// A match at the `k`-th recent distance (D6e), k in 1..=4.
    pub(crate) fn put_ring(
        &mut self,
        sink: &mut impl BitSink,
        k: usize,
        length: u32,
    ) -> Result<()> {
        let fields = self.ring_fields(k, length).ok_or(Error::InvalidData(
            "RAR 1.5 ring match is not encodable now",
        ))?;
        let distance = self.recent().get(k - 1).copied().unwrap_or(NONE);
        let bonus = u32::from(distance > 256) + u32::from(distance >= self.threshold);
        self.short_commit(sink, fields)?;
        self.ring_match(9 + k as u8, (length - 2 - bonus) as u16);
        Ok(())
    }

    /// The toggle (D6e, index 10 with length code 255).
    #[cfg(test)]
    pub(crate) fn put_toggle(&mut self, sink: &mut impl BitSink) -> Result<()> {
        if self.run_mode {
            return Err(Error::InvalidData("RAR 1.5 toggle in run mode"));
        }
        let mut fields = Fields::default();
        fields.push_opt(self.escape_field());
        fields.push(
            self.short_code()
                .encode(10)
                .ok_or(Error::InvalidData("no code"))?,
        );
        fields.push(LENA.encode(255).ok_or(Error::InvalidData("no code"))?);
        self.short_commit(sink, fields)?;
        self.ring_match(10, 255);
        Ok(())
    }

    /// A far short match (D6d): toggle on, distance 32768..=65535, length
    /// 5..=260.
    #[cfg(test)]
    pub(crate) fn put_far_short(
        &mut self,
        sink: &mut impl BitSink,
        length: u32,
        distance: u32,
    ) -> Result<()> {
        let not_now = Error::InvalidData("RAR 1.5 far short match is not encodable now");
        if self.run_mode || !(0x8000..=0xffff).contains(&distance) || !(5..=260).contains(&length) {
            return Err(not_now);
        }
        let mut fields = Fields::default();
        fields.push_opt(self.escape_field());
        fields.push(self.short_code().encode(14).ok_or(not_now.clone())?);
        fields.push(LENB.encode(length - 5).ok_or(not_now)?);
        fields.push((distance - 0x8000, 15));
        self.short_commit(sink, fields)?;
        self.far_short((length - 5) as u16, distance - 0x8000);
        Ok(())
    }

    /// A long match (D7).
    pub(crate) fn put_long(
        &mut self,
        sink: &mut impl BitSink,
        length: u32,
        distance: u32,
    ) -> Result<()> {
        let (fields, c, v) = self
            .long_fields(length, distance)
            .ok_or(Error::InvalidData(
                "RAR 1.5 long match is not encodable now",
            ))?;
        self.take_flags(self.flag_bits_for(false))?;
        fields.write(sink);
        self.long_match(c, v, distance & 0x7f);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_recent_for_test(&mut self, recent: [u32; 4]) {
        self.head = 0;
        self.recent = [recent[0], recent[3], recent[2], recent[1]];
    }

    #[cfg(test)]
    pub(crate) fn set_threshold_for_test(&mut self, threshold: u32) {
        self.threshold = threshold;
    }
}

/// Up to five (value, bit count) fields of one item, in stream order.
#[derive(Default, Clone, Copy)]
struct Fields {
    items: [(u32, u32); 5],
    len: usize,
}

impl Fields {
    fn push(&mut self, field: (u32, u32)) {
        if let Some(slot) = self.items.get_mut(self.len) {
            *slot = field;
            self.len += 1;
        }
    }

    fn push_opt(&mut self, field: Option<(u32, u32)>) {
        if let Some(field) = field {
            self.push(field);
        }
    }

    fn bits(&self) -> u32 {
        self.items
            .iter()
            .take(self.len)
            .map(|&(_, bits)| bits)
            .sum()
    }

    fn write(&self, sink: &mut impl BitSink) {
        for &(value, bits) in self.items.iter().take(self.len) {
            sink.write_bits(value, bits);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    fn weight_at<const K: u16>(table: &RankTable<K>, slot: u8) -> u8 {
        (table.entry[usize::from(slot)] >> 8) as u8
    }

    #[test]
    fn initial_tables_follow_table_3_2() {
        let model = Model::new();
        for slot in 0..=255u8 {
            assert_eq!(model.literals.symbol(slot), slot);
            assert_eq!(model.flags.symbol(slot), 0u8.wrapping_sub(slot));
            assert_eq!(model.far.symbol(slot), slot);
            assert_eq!(weight_at(&model.far, slot), 7 - slot / 32);
            assert_eq!(weight_at(&model.literals, slot), 0);
        }
        assert_eq!(model.far.cursor[0], 224);
        assert_eq!(model.far.cursor[6], 32);
        assert_eq!(model.far.cursor[7], 0);
        assert_eq!(model.recent, [NONE; 4]);
        assert_eq!(model.last_match(), (NONE, 0));
        assert_eq!(model.threshold, 8193);
    }

    #[test]
    fn promote_moves_the_entry_to_its_weight_cursor() {
        let mut table = RankTable::<161>::from_fn(|slot| slot);
        table.promote(5);
        assert_eq!((table.symbol(0), weight_at(&table, 0)), (5, 1));
        assert_eq!((table.symbol(5), weight_at(&table, 5)), (0, 0));
        assert_eq!(table.cursor[0], 1);
        assert_eq!(table.slot_of(5), 0);
        assert_eq!(table.slot_of(0), 5);
        // Promoting the slot the cursor points at only raises its weight.
        table.promote(1);
        assert_eq!((table.symbol(1), weight_at(&table, 1)), (1, 1));
        assert_eq!(table.cursor[0], 2);
    }

    /// Drives symbol 9 into slot 0 at the ceiling, then promotes slot 0 once
    /// more: the table renormalises first (slot 0 back to weight 7), and the
    /// cursor of weight 7 is slot 0, so it becomes weight 8 in place.
    fn check_ceiling<const K: u16>() {
        let mut table = RankTable::<K>::from_fn(|slot| slot);
        table.promote(9);
        while u16::from(weight_at(&table, 0)) < K {
            table.promote(0);
        }
        assert_eq!(table.symbol(0), 9);
        // Slot 40 has weight 0 and is not at the ceiling: no renormalise.
        assert_eq!(weight_at(&table, 40), 0);
        table.promote(0);
        assert_eq!((table.symbol(0), weight_at(&table, 0)), (9, 8));
        assert_eq!(table.cursor[7], 1);
        assert_eq!(weight_at(&table, 40), 6);
        assert_eq!(table.cursor[6], 32);
        assert_eq!(table.cursor[0], 224);
        assert_eq!(table.slot_of(9), 0);
    }

    #[test]
    fn promote_at_the_ceiling_renormalises_first() {
        check_ceiling::<161>();
        check_ceiling::<255>();
    }

    #[test]
    fn model_value_type_is_small_and_copy() {
        let size = std::mem::size_of::<Model>();
        // Three rank tables of 4 * 256 bytes, the near table and its inverse,
        // and about 60 bytes of scalars.
        assert!(size <= 3 * 1024 + 512 + 128, "Model is {size} bytes");
    }
}
