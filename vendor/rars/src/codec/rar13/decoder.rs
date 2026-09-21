//! The RAR 1.5 decoder: bit reading and the output window around the shared
//! model's update rules.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use super::super::{Error, Result};
use super::bits::{BitReader, ByteSource, ReaderSource, SliceSource};
use super::codes::{PrefixCode, LENA, LENB, PEEK_BITS, RK2};
use super::model::{LengthForm, Model};
use std::io::{Read, Write};

const WINDOW: usize = 1 << 16;

/// Block width of D8's match copy, and the number of bytes saved around it.
///
/// A match is copied in whole `WILD`-byte blocks rather than byte at a time,
/// which is what the copy costs: the mean match on a 16 MiB text member is
/// **8.6 bytes** and 42% are under 8, so the byte loop's cost there is its trip
/// count and not its bandwidth - the same loop moves 16.78 MB at 40 GB/s when
/// the matches are long. Removing the trip count takes that member from
/// 46.75 ms to 29.83 (2026-09-16, M1 Ultra, best of 5 interleaved rounds),
/// **36%**, against a copy-free floor of 25.13.
///
/// The last block writes up to `WILD - 1` bytes past the match's end, and
/// **those bytes are live**: the window is a 64 KiB ring and `far_short` (D6d)
/// expresses distances up to 65,535, which is the byte one position *ahead* of
/// the write cursor, so no byte of it is dead. Each block run is therefore
/// bracketed by saving the `WILD` bytes at the match's end and putting them
/// back - two more moves per match, measured at 1.2 ms of the 16.9 won.
/// `codec::rar13::spec_tests` gates that read from both ends: one scripted
/// far-short match placed on the boundary, and a randomised round over many
/// wraps against a flat oracle. Both fail if the overshoot is left in place.
///
/// 32 rather than 16: 16 is 2% quicker on the text members, whose matches are
/// all under 24 bytes, and it loses 11% on a repeat-block payload and 21% of
/// the win on BIG80K, whose matches are long. 32 is the uniform choice - no
/// case of the eight loses more than 3.5% against the byte loop it replaces.
///
/// The copy declines the shape, and the byte loop takes the whole match,
/// when `distance < WILD` - the overlapping-pattern match, whose output
/// depends on the bytes it is writing - or when the run would cross the
/// window's end. A distance at the far side of the ring needs no guard of its
/// own: there the source is numerically AHEAD of the destination, so each
/// block is read before anything writes near it.
///
/// Target 8.5 holds: the guards prove every index, and `--emit asm` over the
/// release lib finds no `panic_bounds_check` in the decode step's symbols.
const WILD: usize = 32;

/// Match length past which a non-overlapping copy goes to `copy_within`
/// instead of the block loop.
const LONG: usize = 64;

/// A RAR 1.5 algorithm decoder that keeps its state between members, so a
/// solid member continues where the previous one stopped.
pub struct Rar15Decoder {
    model: Model,
    /// Circular history of output bytes, on the heap so the decoder value
    /// (and every clone of a codec state holding it) stays small.
    window: Box<[u8; WINDOW]>,
    /// Next write position; a `u16` so every window index is in range.
    write_pos: u16,
    /// Whether 65,536 bytes have been written since the last full reset.
    /// Until then the bytes written equal `write_pos`.
    wrapped: bool,
}

fn new_window() -> Box<[u8; WINDOW]> {
    vec![0u8; WINDOW]
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| Box::new([0u8; WINDOW]))
}

impl Clone for Rar15Decoder {
    fn clone(&self) -> Self {
        let mut window = new_window();
        window.copy_from_slice(&self.window[..]);
        Self {
            model: self.model,
            window,
            write_pos: self.write_pos,
            wrapped: self.wrapped,
        }
    }
}

impl Default for Rar15Decoder {
    fn default() -> Self {
        Self::new()
    }
}

fn write_failed() -> Error {
    Error::InvalidData("RAR 1.5 output write failed")
}

impl Rar15Decoder {
    /// A decoder in the initial state.
    pub fn new() -> Self {
        Self {
            model: Model::new(),
            window: new_window(),
            write_pos: 0,
            wrapped: false,
        }
    }

    /// Decodes one member of exactly `target` bytes from `input`.
    pub fn decode_member(&mut self, input: &[u8], target: usize, solid: bool) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.try_reserve_exact(target)
            .map_err(|_| Error::InvalidData("RAR 1.5 member is too large to buffer"))?;
        self.decode_member_to(input, target, solid, &mut out)?;
        Ok(out)
    }

    /// Decodes one member of exactly `target` bytes from `input` into `out`.
    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        self.decode(SliceSource::new(input), target, solid, out)
    }

    /// Decodes one member of exactly `target` bytes, pulling packed bytes
    /// from `input` until it is needed no longer or reaches EOF.
    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        if target == 0 {
            self.begin_member(solid);
            return Ok(());
        }
        self.decode(ReaderSource::new(input), target, solid, out)
    }

    fn begin_member(&mut self, solid: bool) {
        if !solid {
            self.write_pos = 0;
            self.wrapped = false;
        }
        self.model.begin_member(solid);
    }

    /// D1, then the member's steps on a local copy of the state, written
    /// back when the member ends (successfully or not).
    fn decode<S: ByteSource, W: Write>(
        &mut self,
        source: S,
        target: usize,
        solid: bool,
        out: &mut W,
    ) -> Result<()> {
        self.begin_member(solid);
        let mut run = Run {
            model: self.model,
            pos: self.write_pos,
            wrapped: self.wrapped,
            bits: BitReader::new(source),
            produced: 0,
            target,
            flush_from: self.write_pos,
            window: &mut self.window,
            out,
        };
        let result = run.member();
        let (model, pos, wrapped) = (run.model, run.pos, run.wrapped);
        self.model = model;
        self.write_pos = pos;
        self.wrapped = wrapped;
        result
    }
}

/// One member in progress. Every hot quantity is a plain field of this
/// local value and no cold path takes its address, so the compiler can keep
/// the bit buffer, the positions and the model's counters in registers.
struct Run<'a, S, W> {
    model: Model,
    pos: u16,
    wrapped: bool,
    bits: BitReader<S>,
    produced: usize,
    target: usize,
    /// Window position from which bytes are still to be delivered.
    flush_from: u16,
    window: &'a mut [u8; WINDOW],
    out: &'a mut W,
}

impl<S: ByteSource, W: Write> Run<'_, S, W> {
    /// D2 and D9.
    fn member(&mut self) -> Result<()> {
        while self.produced < self.target {
            if self.model.run_mode() {
                self.run_mode_step()?;
            } else {
                self.step()?;
            }
        }
        let pending = self
            .window
            .get(usize::from(self.flush_from)..usize::from(self.pos))
            .unwrap_or_default();
        self.out.write_all(pending).map_err(|_| write_failed())?;
        self.flush_from = self.pos;
        Ok(())
    }

    /// One step of D2 outside run mode.
    #[inline(always)]
    fn step(&mut self) -> Result<()> {
        let prefers_long = self.model.prefers_long();
        if self.flag_bit()? {
            if prefers_long {
                self.long_match()
            } else {
                self.literal()
            }
        } else if self.flag_bit()? {
            if prefers_long {
                self.literal()
            } else {
                self.long_match()
            }
        } else {
            self.short_family()
        }
    }

    #[inline(always)]
    fn read_code(&mut self, code: &PrefixCode) -> Result<u16> {
        let (value, length) = code.decode(self.bits.peek(PEEK_BITS)?);
        self.bits.skip(length);
        Ok(value)
    }

    /// One flag bit, decoding a new flag byte first when none are left (D3).
    #[inline(always)]
    fn flag_bit(&mut self) -> Result<bool> {
        if self.model.flag_left() == 0 {
            let v = self.read_code(&RK2)?;
            self.model.flag_byte(v);
        }
        Ok(self.model.take_flag_bit())
    }

    /// D4.
    #[inline(always)]
    fn literal(&mut self) -> Result<()> {
        let v = self.read_code(self.model.literal_code())?;
        let byte = self.model.literal(v);
        self.put_byte(byte)
    }

    /// D5.
    #[inline(always)]
    fn run_mode_step(&mut self) -> Result<()> {
        let v = self.read_code(self.model.literal_code())?;
        if v >= 1 {
            let byte = self.model.run_literal(v);
            return self.put_byte(byte);
        }
        if self.bits.read(1)? == 1 {
            self.model.run_exit();
            return Ok(());
        }
        let length = 3 + self.bits.read(1)?;
        let u = self.read_code(&RK2)?;
        let f = self.bits.read(5)?;
        self.copy(u32::from(u) * 32 + f, length)
    }

    /// D6.
    #[inline(always)]
    fn short_family(&mut self) -> Result<()> {
        self.model.short_begin();
        if self.model.repeats() == 2 {
            if self.bits.read(1)? == 1 {
                let (distance, length) = self.model.last_match();
                return self.copy(distance, length);
            }
            self.model.clear_repeats();
        }
        let index = self.read_code(self.model.short_code())? as u8;
        let (distance, length) = match index {
            9 => self.model.repeat(),
            14 => {
                let x = self.read_code(&LENB)?;
                let g = self.bits.read(15)?;
                self.model.far_short(x, g)
            }
            10..=13 => {
                let x = self.read_code(&LENA)?;
                match self.model.ring_match(index, x) {
                    Some(found) => found,
                    None => return Ok(()),
                }
            }
            _ => {
                let v = self.read_code(&RK2)?;
                self.model.near_match(index, v)
            }
        };
        self.copy(distance, length)
    }

    /// D7.
    #[inline(always)]
    fn long_match(&mut self) -> Result<()> {
        let c = match self.model.long_length_form() {
            LengthForm::Lenb => u32::from(self.read_code(&LENB)?),
            LengthForm::Lena => u32::from(self.read_code(&LENA)?),
            LengthForm::Unary => {
                let peek = self.bits.peek(16)?;
                if peek < 256 {
                    self.bits.skip(16);
                    peek
                } else {
                    let zeros = peek.leading_zeros() - 16;
                    self.bits.skip(zeros + 1);
                    zeros
                }
            }
        };
        let v = self.read_code(self.model.far_rank_code())?;
        let t = self.bits.read(7)?;
        let (distance, length) = self.model.long_match(c, v, t);
        self.copy(distance, length)
    }

    /// One output byte (D8).
    #[inline(always)]
    fn put_byte(&mut self, byte: u8) -> Result<()> {
        #[allow(clippy::indexing_slicing)] // a u16 index is inside 65,536 bytes
        {
            self.window[usize::from(self.pos)] = byte;
        }
        self.pos = self.pos.wrapping_add(1);
        self.produced += 1;
        if self.pos == 0 {
            self.wrapped = true;
            self.flush_from = deliver_tail(self.out, self.window, self.flush_from)?;
        }
        Ok(())
    }

    /// Copies `length` bytes at `distance` (D8), in stretches that end at the
    /// window's end so the wrap is checked once per stretch, not per byte.
    #[inline(always)]
    fn copy(&mut self, distance: u32, length: u32) -> Result<()> {
        if length as usize > self.target - self.produced {
            return Err(Error::InvalidData(
                "RAR 1.5 match runs past the member's unpacked size",
            ));
        }
        self.produced += length as usize;
        let zero_fill = distance == 0
            || distance > WINDOW as u32
            || (!self.wrapped && distance > u32::from(self.pos));
        // `distance as u16` is `distance mod 65,536`; 65,536 reads the byte
        // written that many positions earlier.
        let back = distance as u16;
        let mut remaining = length;
        while remaining > 0 {
            let room = WINDOW as u32 - u32::from(self.pos);
            let stretch = remaining.min(room);
            let mut to = self.pos;
            let mut from = to.wrapping_sub(back);
            // The whole stretch in WILD-byte blocks when the shape allows it,
            // which on a text member is nearly every match. See `WILD`.
            let mut wide = false;
            if !zero_fill && usize::from(back) >= WILD {
                let source = usize::from(from);
                let target = usize::from(to);
                let span = stretch as usize;
                // `source`, `target` and `span` are each under 65,536 + 267,
                // so no sum below can overflow; the window's end is the only
                // bound that matters, and a block run may not cross it (the
                // wrap is the caller's, once per stretch).
                if span > LONG && usize::from(back) >= span && source + span <= WINDOW {
                    // A long match that does not overlap: one move of the
                    // exact length. No overshoot, so nothing to save, and the
                    // byte loop's own vectorisation is what this has to beat -
                    // on x86 it does not beat it below `LONG`, and a block
                    // loop LOSES to it above.
                    // `target + span <= WINDOW` because the caller clamps the
                    // stretch to the window's end; `source + span` is guarded
                    // above, because the SOURCE is not clamped - it may sit
                    // anywhere in the ring.
                    #[allow(clippy::indexing_slicing)] // proved by the guard above
                    self.window.copy_within(source..source + span, target);
                    from = from.wrapping_add(stretch as u16);
                    to = to.wrapping_add(stretch as u16);
                    wide = true;
                } else if source + span + WILD <= WINDOW && target + span + WILD <= WINDOW {
                    #[allow(clippy::indexing_slicing)] // proved by the guard above
                    {
                        // The bytes the last block overshoots into are LIVE -
                        // see `WILD` - so they are saved and put back.
                        let mut saved = [0u8; WILD];
                        saved.copy_from_slice(&self.window[target + span..target + span + WILD]);
                        let mut at = 0usize;
                        while at < span {
                            let mut block = [0u8; WILD];
                            block.copy_from_slice(&self.window[source + at..source + at + WILD]);
                            self.window[target + at..target + at + WILD].copy_from_slice(&block);
                            at += WILD;
                        }
                        self.window[target + span..target + span + WILD].copy_from_slice(&saved);
                    }
                    from = from.wrapping_add(stretch as u16);
                    to = to.wrapping_add(stretch as u16);
                    wide = true;
                }
            }
            if !wide {
                // Byte by byte, in order: a match may overlap the bytes it is
                // writing (distance < length repeats a pattern).
                for _ in 0..stretch {
                    #[allow(clippy::indexing_slicing)] // u16 indexes into 65,536 bytes
                    {
                        let byte = if zero_fill {
                            0
                        } else {
                            self.window[usize::from(from)]
                        };
                        self.window[usize::from(to)] = byte;
                    }
                    from = from.wrapping_add(1);
                    to = to.wrapping_add(1);
                }
            }
            self.pos = to;
            remaining -= stretch;
            if stretch == room {
                self.wrapped = true;
                self.flush_from = deliver_tail(self.out, self.window, self.flush_from)?;
            }
        }
        Ok(())
    }
}

/// The write position just wrapped: delivers the window from `from` to its
/// end and returns the new delivery start, 0.
#[cold]
#[inline(never)]
fn deliver_tail<W: Write>(out: &mut W, window: &[u8; WINDOW], from: u16) -> Result<u16> {
    let pending = window.get(usize::from(from)..).unwrap_or_default();
    out.write_all(pending).map_err(|_| write_failed())?;
    Ok(0)
}
