use alloc::{vec, vec::Vec};

use super::{
    ALIGN_BITS, ALIGN_SIZE, DIST_MODEL_END, DIST_MODEL_START, DIST_SLOTS, HIGH_SYMBOLS,
    LOW_SYMBOLS, LengthCoder, LiteralCoder, LiteralSubCoder, LzmaCoder, MATCH_LEN_MIN, MID_SYMBOLS,
    coder_get_dict_size, lz::LzDecoder, range_dec::RangeDecoder,
};
use crate::range_dec::RangeReader;

/// nzbfast: the pre-fastpath decoder is kept beside the fast one and this
/// switch selects it, so a test can decode the same stream both ways and
/// compare - the way `vendor/rars` keeps its old kernels. It is a
/// `thread_local`, not a global, so tests that flip it cannot disturb the
/// tests nextest runs beside them. Compiled out entirely in a release build.
#[cfg(test)]
mod reference_switch {
    use core::cell::Cell;

    std::thread_local! {
        static USE_REFERENCE: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn enabled() -> bool {
        USE_REFERENCE.with(Cell::get)
    }

    /// Run `f` with the reference decoder selected on this thread.
    pub(crate) fn with_reference_decoder<T>(f: impl FnOnce() -> T) -> T {
        USE_REFERENCE.with(|c| c.set(true));
        let out = f();
        USE_REFERENCE.with(|c| c.set(false));
        out
    }
}

#[cfg(test)]
pub(crate) use reference_switch::with_reference_decoder;

pub(crate) struct LzmaDecoder {
    coder: LzmaCoder,
    literal_decoder: LiteralDecoder,
    match_len_decoder: LengthCoder,
    rep_len_decoder: LengthCoder,
}

impl LzmaDecoder {
    pub(crate) fn new(lc: u32, lp: u32, pb: u32) -> Self {
        let mut literal_decoder = LiteralDecoder::new(lc, lp);
        literal_decoder.reset();
        let match_len_decoder = {
            let mut l = LengthCoder::new();
            l.reset();
            l
        };
        let rep_len_decoder = {
            let mut l = LengthCoder::new();
            l.reset();
            l
        };
        Self {
            coder: LzmaCoder::new(pb as _),
            literal_decoder,
            match_len_decoder,
            rep_len_decoder,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.coder.reset();
        self.literal_decoder.reset();
        self.match_len_decoder.reset();
        self.rep_len_decoder.reset();
    }

    pub(crate) fn end_marker_detected(&self) -> bool {
        self.coder.reps[0] == -1
    }

    pub(crate) fn decode<R: RangeReader>(
        &mut self,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) -> crate::Result<()> {
        #[cfg(test)]
        if reference_switch::enabled() {
            return self.decode_reference(lz, rc);
        }

        lz.repeat_pending()?;
        while lz.has_space() && rc.can_start_symbol() {
            let pos_state = (lz.get_pos() as u32 & self.coder.pos_mask) as usize;
            // nzbfast: the state cannot change between these two bits, so it
            // is read once instead of three times (the original re-read it
            // for every `is_*` table).
            let state = self.coder.state.get() as usize;
            if rc.decode_bit(&mut self.coder.is_match[state][pos_state]) == 0 {
                self.literal_decoder.decode(&mut self.coder, lz, rc);
            } else {
                let len = if rc.decode_bit(&mut self.coder.is_rep[state]) == 0 {
                    self.decode_match(pos_state, rc)
                } else {
                    self.decode_rep_match(state, pos_state, rc)
                };
                lz.repeat(self.coder.reps[0] as _, len as _)?;
            }
        }
        // Normalise only if we stopped because the output is full. If we
        // stopped because the input ran out, `rc` has to stay as it is, so that
        // the next call can pick up where this one left off. A reader that
        // never runs out of input, like `RangeDecoderBuffer`, always takes this
        // branch, just like before.
        if !lz.has_space() && rc.can_normalize() {
            rc.normalize();
        }
        Ok(())
    }

    #[inline(always)]
    fn decode_match<R: RangeReader>(&mut self, pos_state: usize, rc: &mut RangeDecoder<R>) -> u32 {
        self.coder.state.update_match();
        self.coder.reps[3] = self.coder.reps[2];
        self.coder.reps[2] = self.coder.reps[1];
        self.coder.reps[1] = self.coder.reps[0];

        let len = self.match_len_decoder.decode(pos_state, rc);
        let slots: &mut [u16; DIST_SLOTS] =
            &mut self.coder.dist_slots[coder_get_dict_size(len as usize)];
        let dist_slot = rc.decode_bit_tree_fixed(slots) as i32;

        if dist_slot < DIST_MODEL_START as i32 {
            self.coder.reps[0] = dist_slot;
        } else {
            let limit = (dist_slot >> 1) - 1;
            self.coder.reps[0] = (2 | (dist_slot & 1)) << limit;
            if dist_slot < DIST_MODEL_END as i32 {
                let probs = self
                    .coder
                    .get_dist_special((dist_slot - DIST_MODEL_START as i32) as usize);
                self.coder.reps[0] |= rc.decode_reverse_bit_tree(probs) as i32;
            } else {
                let r0 = rc.decode_direct_bits(limit as u32 - ALIGN_BITS as u32) << ALIGN_BITS;
                self.coder.reps[0] |= r0;
                let align: &mut [u16; ALIGN_SIZE] = &mut self.coder.dist_align;
                self.coder.reps[0] |= rc.decode_reverse_bit_tree_fixed(align) as i32;
            }
        }

        len
    }

    #[inline(always)]
    fn decode_rep_match<R: RangeReader>(
        &mut self,
        state: usize,
        pos_state: usize,
        rc: &mut RangeDecoder<R>,
    ) -> u32 {
        if rc.decode_bit(&mut self.coder.is_rep0[state]) == 0 {
            if rc.decode_bit(&mut self.coder.is_rep0_long[state][pos_state]) == 0 {
                self.coder.state.update_short_rep();
                return 1;
            }
        } else {
            let tmp;
            if rc.decode_bit(&mut self.coder.is_rep1[state]) == 0 {
                tmp = self.coder.reps[1];
            } else {
                if rc.decode_bit(&mut self.coder.is_rep2[state]) == 0 {
                    tmp = self.coder.reps[2];
                } else {
                    tmp = self.coder.reps[3];
                    self.coder.reps[3] = self.coder.reps[2];
                }
                self.coder.reps[2] = self.coder.reps[1];
            }
            self.coder.reps[1] = self.coder.reps[0];
            self.coder.reps[0] = tmp;
        }

        self.coder.state.update_long_rep();
        self.rep_len_decoder.decode(pos_state, rc)
    }
}

pub(crate) struct LiteralDecoder {
    coder: LiteralCoder,
    sub_decoders: Vec<LiteralSubDecoder>,
}

impl LiteralDecoder {
    fn new(lc: u32, lp: u32) -> Self {
        let coder = LiteralCoder::new(lc, lp);
        let sub_decoders = vec![LiteralSubDecoder::new(); (1 << (lc + lp)) as _];

        Self {
            coder,
            sub_decoders,
        }
    }

    fn reset(&mut self) {
        for ele in self.sub_decoders.iter_mut() {
            ele.coder.reset()
        }
    }

    #[inline(always)]
    fn decode<R: RangeReader>(
        &mut self,
        coder: &mut LzmaCoder,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) {
        let i = self
            .coder
            .get_sub_coder_index(lz.get_byte(0) as _, lz.get_pos() as _);
        let d = &mut self.sub_decoders[i as usize];
        d.decode(coder, lz, rc)
    }
}

#[derive(Clone)]
struct LiteralSubDecoder {
    coder: LiteralSubCoder,
}

impl LiteralSubDecoder {
    fn new() -> Self {
        Self {
            coder: LiteralSubCoder::new(),
        }
    }

    /// Decode one literal byte.
    ///
    /// nzbfast: **deliberately NOT unrolled, and not unchecked.** 7-Zip's
    /// `LzmaDec.c` writes these two chains out eight times
    /// (`NORMAL_LITER_DEC` / `MATCHED_LITER_DEC`) and that is the obvious
    /// thing to copy, so here is the measurement that says not to. Unrolling
    /// both arms to a fixed eight steps with `get_unchecked_mut` removes 6.1%
    /// of the instructions a 1 GiB LZMA2 decode retires - and it is SLOWER on
    /// both architectures we ship: 9.87-10.04 s/GiB against 9.52-9.62 for the
    /// loop below on an 8-vCPU EPYC, and +2.4% of user CPU on an M1-class
    /// core. Instructions are not the binding constraint in this decoder; the
    /// range coder's per-bit dependency chain is, and eight inlined copies of
    /// the normalisation branch cost more front end than they save. Numbers,
    /// arms and the isolation in `research/RAR-PERF-AUDIT-2026-09-02.md`,
    /// round 20. Do not "finish the port" here without re-measuring.
    #[inline(always)]
    fn decode<R: RangeReader>(
        &mut self,
        coder: &mut LzmaCoder,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) {
        let probs = &mut self.coder.probs;
        let symbol = if coder.state.is_literal() {
            let mut symbol = 1usize;
            loop {
                let bit = rc.decode_bit(&mut probs[symbol]) as usize;
                symbol = (symbol << 1) | bit;
                if symbol >= 0x100 {
                    break;
                }
            }
            symbol
        } else {
            let mut match_byte = lz.get_byte(coder.reps[0] as usize) as usize;
            let mut offset = 0x100usize;
            let mut symbol = 1usize;
            loop {
                match_byte <<= 1;
                let match_bit = match_byte & offset;
                let index = offset + match_bit + symbol;
                let bit = rc.decode_bit(&mut probs[index]) as usize;
                symbol = (symbol << 1) | bit;
                offset &= (0usize.wrapping_sub(bit)) ^ !match_bit;
                if symbol >= 0x100 {
                    break;
                }
            }
            symbol
        };
        lz.put_byte(symbol as u8);
        coder.state.update_literal();
    }
}

impl LengthCoder {
    #[inline(always)]
    fn decode<R: RangeReader>(&mut self, pos_state: usize, rc: &mut RangeDecoder<R>) -> u32 {
        if rc.decode_bit(&mut self.choice[0]) == 0 {
            let low: &mut [u16; LOW_SYMBOLS] = &mut self.low[pos_state];
            return rc.decode_bit_tree_fixed(low) + MATCH_LEN_MIN as u32;
        }

        if rc.decode_bit(&mut self.choice[1]) == 0 {
            let mid: &mut [u16; MID_SYMBOLS] = &mut self.mid[pos_state];
            return rc.decode_bit_tree_fixed(mid) + (MATCH_LEN_MIN + LOW_SYMBOLS) as u32;
        }

        let high: &mut [u16; HIGH_SYMBOLS] = &mut self.high;
        rc.decode_bit_tree_fixed(high) + (MATCH_LEN_MIN + LOW_SYMBOLS + MID_SYMBOLS) as u32
    }
}

// ---------------------------------------------------------------------------
// The pre-fastpath decoder, kept verbatim as the differential test's oracle.
// ---------------------------------------------------------------------------

#[cfg(test)]
impl LzmaDecoder {
    fn decode_reference<R: RangeReader>(
        &mut self,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) -> crate::Result<()> {
        lz.repeat_pending()?;
        while lz.has_space() && rc.can_start_symbol() {
            let pos_state = lz.get_pos() as u32 & self.coder.pos_mask;
            let i = self.coder.state.get() as usize;
            let probs = &mut self.coder.is_match[i];
            let bit = rc.decode_bit(&mut probs[pos_state as usize]);
            if bit == 0 {
                self.literal_decoder.decode_reference(&mut self.coder, lz, rc);
            } else {
                let index = self.coder.state.get() as usize;
                let len = if rc.decode_bit(&mut self.coder.is_rep[index]) == 0 {
                    self.decode_match_reference(pos_state, rc)
                } else {
                    self.decode_rep_match_reference(pos_state, rc)
                };
                lz.repeat(self.coder.reps[0] as _, len as _)?;
            }
        }
        if !lz.has_space() && rc.can_normalize() {
            rc.normalize();
        }
        Ok(())
    }

    fn decode_match_reference<R: RangeReader>(
        &mut self,
        pos_state: u32,
        rc: &mut RangeDecoder<R>,
    ) -> u32 {
        self.coder.state.update_match();
        self.coder.reps[3] = self.coder.reps[2];
        self.coder.reps[2] = self.coder.reps[1];
        self.coder.reps[1] = self.coder.reps[0];

        let len = self.match_len_decoder.decode_reference(pos_state as _, rc);
        let dist_slot =
            rc.decode_bit_tree_reference(&mut self.coder.dist_slots[coder_get_dict_size(len as _)]);

        if dist_slot < DIST_MODEL_START as i32 {
            self.coder.reps[0] = dist_slot as _;
        } else {
            let limit = (dist_slot >> 1) - 1;
            self.coder.reps[0] = (2 | (dist_slot & 1)) << limit;
            if dist_slot < DIST_MODEL_END as i32 {
                let probs = self
                    .coder
                    .get_dist_special((dist_slot - DIST_MODEL_START as i32) as usize);
                self.coder.reps[0] |= rc.decode_reverse_bit_tree_reference(probs);
            } else {
                let r0 = rc.decode_direct_bits(limit as u32 - ALIGN_BITS as u32) << ALIGN_BITS;
                self.coder.reps[0] |= r0;
                self.coder.reps[0] |=
                    rc.decode_reverse_bit_tree_reference(&mut self.coder.dist_align);
            }
        }

        len as _
    }

    fn decode_rep_match_reference<R: RangeReader>(
        &mut self,
        pos_state: u32,
        rc: &mut RangeDecoder<R>,
    ) -> u32 {
        let index = self.coder.state.get() as usize;
        if rc.decode_bit(&mut self.coder.is_rep0[index]) == 0 {
            let index: usize = self.coder.state.get() as usize;
            if rc.decode_bit(&mut self.coder.is_rep0_long[index][pos_state as usize]) == 0 {
                self.coder.state.update_short_rep();
                return 1;
            }
        } else {
            let tmp;
            let s = self.coder.state.get() as usize;
            if rc.decode_bit(&mut self.coder.is_rep1[s]) == 0 {
                tmp = self.coder.reps[1];
            } else {
                if rc.decode_bit(&mut self.coder.is_rep2[s]) == 0 {
                    tmp = self.coder.reps[2];
                } else {
                    tmp = self.coder.reps[3];
                    self.coder.reps[3] = self.coder.reps[2];
                }
                self.coder.reps[2] = self.coder.reps[1];
            }
            self.coder.reps[1] = self.coder.reps[0];
            self.coder.reps[0] = tmp;
        }

        self.coder.state.update_long_rep();
        self.rep_len_decoder.decode_reference(pos_state as _, rc) as u32
    }
}

#[cfg(test)]
impl LiteralDecoder {
    fn decode_reference<R: RangeReader>(
        &mut self,
        coder: &mut LzmaCoder,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) {
        let i = self
            .coder
            .get_sub_coder_index(lz.get_byte(0) as _, lz.get_pos() as _);
        let d = &mut self.sub_decoders[i as usize];
        d.decode_reference(coder, lz, rc)
    }
}

#[cfg(test)]
impl LiteralSubDecoder {
    fn decode_reference<R: RangeReader>(
        &mut self,
        coder: &mut LzmaCoder,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) {
        let mut symbol: u32 = 1;
        let liter = coder.state.is_literal();
        if liter {
            loop {
                let b = rc.decode_bit(&mut self.coder.probs[symbol as usize]) as u32;
                symbol = (symbol << 1) | b;
                if symbol >= 0x100 {
                    break;
                }
            }
        } else {
            let r = coder.reps[0];
            let mut match_byte = lz.get_byte(r as usize) as u32;
            let mut offset = 0x100;
            let mut match_bit;
            let mut bit;

            loop {
                match_byte <<= 1;
                match_bit = match_byte & offset;
                bit = rc.decode_bit(&mut self.coder.probs[(offset + match_bit + symbol) as usize])
                    as u32;
                symbol = (symbol << 1) | bit;
                offset &= (0u32.wrapping_sub(bit)) ^ !match_bit;
                if symbol >= 0x100 {
                    break;
                }
            }
        }
        lz.put_byte(symbol as u8);
        coder.state.update_literal();
    }
}

#[cfg(test)]
impl LengthCoder {
    fn decode_reference<R: RangeReader>(
        &mut self,
        pos_state: usize,
        rc: &mut RangeDecoder<R>,
    ) -> i32 {
        if rc.decode_bit(&mut self.choice[0]) == 0 {
            return rc
                .decode_bit_tree_reference(&mut self.low[pos_state])
                .wrapping_add(MATCH_LEN_MIN as _);
        }

        if rc.decode_bit(&mut self.choice[1]) == 0 {
            return rc
                .decode_bit_tree_reference(&mut self.mid[pos_state])
                .wrapping_add(MATCH_LEN_MIN as _)
                .wrapping_add(LOW_SYMBOLS as _);
        }

        rc.decode_bit_tree_reference(&mut self.high)
            .wrapping_add(MATCH_LEN_MIN as _)
            .wrapping_add(LOW_SYMBOLS as _)
            .wrapping_add(MID_SYMBOLS as _)
    }
}

// ---------------------------------------------------------------------------
// nzbfast: the differential test. Every stream is decoded twice - once through
// the fast decoder above, once through the reference kept below it - and the
// two outputs must be identical, byte for byte. The fixtures are raw LZMA2
// pack streams lifted out of one-folder .7z archives made by 7-Zip itself, so
// they carry the real encoder's symbol mix (its rep matches, its distance
// slots, its literal/matched-literal ratio), which no stream produced by this
// crate's own encoder would.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod differential {
    use alloc::vec::Vec;

    use super::with_reference_decoder;
    use crate::{Lzma2Reader, Read, crc::Crc32};

    /// Every plaintext here is under 2 MiB, so a 2 MiB window is always at
    /// least as large as the window the encoder used.
    const DICT: u32 = 1 << 21;

    /// name, raw LZMA2 pack stream, decoded length, CRC-32 of the decoded
    /// bytes. Built by the recipe in the fixture header below; the CRC comes
    /// from liblzma, not from this crate, so it is an independent anchor and
    /// not just a record of what we happen to produce.
    ///
    /// The `_bcj` arm's LZMA2 layer decodes to the BCJ-filtered intermediate
    /// rather than to the original code image, which is exactly the point: it
    /// is a different byte distribution through the same decoder.
    #[allow(clippy::type_complexity)]
    const FIXTURES: &[(&str, &[u8], usize, u32)] = &[
        (
            "mx1_text",
            include_bytes!("../testdata/mx1_text.lzma2"),
            103_290,
            0x6228_5c6b,
        ),
        (
            "mx5_text",
            include_bytes!("../testdata/mx5_text.lzma2"),
            103_290,
            0x6228_5c6b,
        ),
        (
            "mx9_text",
            include_bytes!("../testdata/mx9_text.lzma2"),
            103_290,
            0x6228_5c6b,
        ),
        (
            "mx1_code",
            include_bytes!("../testdata/mx1_code.lzma2"),
            98_304,
            0xa93e_b77a,
        ),
        (
            "mx9_code",
            include_bytes!("../testdata/mx9_code.lzma2"),
            98_304,
            0xa93e_b77a,
        ),
        (
            "mx9_code_bcj",
            include_bytes!("../testdata/mx9_code_bcj.lzma2"),
            98_304,
            0x1264_a1e4,
        ),
    ];

    fn decode(stream: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut reader = Lzma2Reader::new(stream, DICT, None);
        reader.read_to_end(&mut out).expect("LZMA2 decode failed");
        out
    }

    #[test]
    fn fastpath_matches_the_reference_on_7zip_streams() {
        for (name, stream, len, crc) in FIXTURES {
            let fast = decode(stream);
            let reference = with_reference_decoder(|| decode(stream));

            assert_eq!(
                fast.len(),
                *len,
                "{name}: fast decode produced {} bytes, expected {len}",
                fast.len()
            );
            assert_eq!(
                Crc32::checksum(&fast),
                *crc,
                "{name}: fast decode has the wrong CRC-32"
            );
            assert!(
                fast == reference,
                "{name}: fast and reference decoders disagree"
            );
        }
    }

    /// The fixtures are all 7-Zip's `lc=3 lp=0 pb=2`. This arm sweeps the rest
    /// of the parameter space with this crate's own encoder, because `lc` and
    /// `lp` change how many literal sub-coders exist and `pb` changes the
    /// position-state index - all three feed the indexing the fastpath
    /// tightened.
    #[test]
    fn fastpath_matches_the_reference_across_lc_lp_pb() {
        use crate::{Lzma2Options, Lzma2Writer, Write};

        // A mix of runs, near-repeats and incompressible bytes, so a stream
        // carries literals, short matches, long matches and rep matches.
        let mut plain = Vec::with_capacity(96 * 1024);
        let mut x: u32 = 0x1234_5678;
        while plain.len() < 96 * 1024 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            match x >> 29 {
                0..=2 => plain.extend_from_slice(b"the quick brown fox jumps over"),
                3..=4 => {
                    let n = (x >> 8) as usize % 200;
                    plain.extend(core::iter::repeat_n(b'=', n));
                }
                5 => {
                    let from = plain.len().saturating_sub(4096);
                    let take = ((x >> 4) as usize % 300).min(plain.len() - from);
                    let slice = plain[from..from + take].to_vec();
                    plain.extend_from_slice(&slice);
                }
                _ => plain.extend_from_slice(&x.to_le_bytes()),
            }
        }

        for (lc, lp, pb) in [
            (0u32, 0u32, 0u32),
            (0, 2, 0),
            (1, 0, 1),
            (2, 2, 2),
            (3, 0, 2),
            (3, 1, 4),
            (4, 0, 3),
        ] {
            let mut options = Lzma2Options::with_preset(6);
            options.lzma_options.lc = lc;
            options.lzma_options.lp = lp;
            options.lzma_options.pb = pb;
            options.lzma_options.dict_size = DICT;

            let mut packed = Vec::new();
            let mut writer = Lzma2Writer::new(&mut packed, options);
            writer.write_all(&plain).unwrap();
            writer.finish().unwrap();

            let fast = decode(&packed);
            let reference = with_reference_decoder(|| decode(&packed));
            assert!(
                fast == plain,
                "lc={lc} lp={lp} pb={pb}: fast decode does not round-trip"
            );
            assert!(
                fast == reference,
                "lc={lc} lp={lp} pb={pb}: fast and reference decoders disagree"
            );
        }
    }

    /// Corrupted streams must reach the same outcome through both decoders.
    ///
    /// This is the arm that matters most for the lifted bounds checks: a
    /// mangled stream drives `symbol`, the distance slots and the literal
    /// offsets down paths a well-formed one never takes, and the fastpath's
    /// indexing has to stay inside its arrays on all of them. Deterministic,
    /// so a failure is reproducible from the seed printed in the message.
    #[test]
    fn corrupted_streams_decode_the_same_way() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for (name, stream, ..) in FIXTURES {
            for round in 0..24 {
                let mut bad = stream.to_vec();
                // Leave the first chunk header alone often enough that the
                // corruption lands in coded symbols rather than in the framing.
                let flips = 1 + (next() % 8) as usize;
                for _ in 0..flips {
                    let at = (next() as usize) % bad.len();
                    bad[at] ^= 1u8 << (next() % 8);
                }
                let mut fast_out = Vec::new();
                let fast = Lzma2Reader::new(&bad[..], DICT, None)
                    .read_to_end(&mut fast_out)
                    .is_ok();
                let mut ref_out = Vec::new();
                let reference = with_reference_decoder(|| {
                    Lzma2Reader::new(&bad[..], DICT, None)
                        .read_to_end(&mut ref_out)
                        .is_ok()
                });
                assert_eq!(fast, reference, "{name} round {round}: outcome differs");
                assert!(
                    fast_out == ref_out,
                    "{name} round {round}: output differs ({} vs {} bytes)",
                    fast_out.len(),
                    ref_out.len()
                );
            }
        }
    }

    /// A truncated stream must still stop the same way through both decoders:
    /// the fastpath lifted bounds checks out of the per-bit path, so a
    /// malformed stream is the case where a lifted check would show as a wrong
    /// answer rather than a panic.
    #[test]
    fn truncated_streams_fail_the_same_way() {
        for (name, stream, ..) in FIXTURES {
            for cut in [1usize, 7, 64, 1024, stream.len() / 3, stream.len() - 1] {
                if cut >= stream.len() {
                    continue;
                }
                let short = &stream[..cut];
                let mut fast_out = Vec::new();
                let fast = Lzma2Reader::new(short, DICT, None)
                    .read_to_end(&mut fast_out)
                    .is_ok();
                let mut ref_out = Vec::new();
                let reference = with_reference_decoder(|| {
                    Lzma2Reader::new(short, DICT, None)
                        .read_to_end(&mut ref_out)
                        .is_ok()
                });
                assert_eq!(fast, reference, "{name} cut at {cut}: outcome differs");
                assert!(
                    fast_out == ref_out,
                    "{name} cut at {cut}: partial output differs"
                );
            }
        }
    }
}
