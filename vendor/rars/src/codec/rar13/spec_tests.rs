//! Rule-level tests: hand-built bit strings whose output is worked out by
//! hand from the specification at the initial state, and scripted item
//! sequences written through the model and decoded back. Until the oracle
//! was removed these also decoded every stream with the old implementation
//! and required the two to agree; they did.

use super::bits::{BitCounter, BitSink, BitWriter};
use super::codes::{PrefixCode, LENA, LENB, RK0, RK1, RK2};
use super::model::{Model, NONE};
use super::Rar15Decoder;
use crate::codec::Error;

/// Assembles a bit string from codewords and literal bit runs.
#[derive(Default)]
struct Asm(BitWriter);

impl Asm {
    fn code(mut self, code: &PrefixCode, value: u32) -> Self {
        let (word, length) = code.encode(value).expect("value has a codeword");
        self.0.write_bits(word, length);
        self
    }

    fn bits(mut self, text: &str) -> Self {
        for bit in text.bytes() {
            self.0.write_bits(u32::from(bit == b'1'), 1);
        }
        self
    }

    fn finish(self) -> Vec<u8> {
        self.0.finish()
    }
}

fn decode(packed: &[u8], target: usize) -> Result<Vec<u8>, Error> {
    Rar15Decoder::new().decode_member(packed, target, false)
}

/// FLG slot i holds symbol (256 - i) mod 256 at the start.
fn initial_flag_slot(flags: u8) -> u32 {
    u32::from(0u8.wrapping_sub(flags))
}

#[test]
fn d1_target_zero_reads_nothing() {
    struct Refuses;
    impl std::io::Read for Refuses {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("a zero-byte member must not read its input");
        }
    }
    let mut out = Vec::new();
    Rar15Decoder::new()
        .decode_member_from_reader(&mut Refuses, 0, false, &mut out)
        .unwrap();
    assert!(out.is_empty());
    assert_eq!(
        Rar15Decoder::new()
            .decode_member(&[0xff; 8], 0, true)
            .unwrap(),
        b""
    );
}

#[test]
fn d4_literals_and_value_256_as_slot_0() {
    // Flag byte 0xff (eight literal bits; the preference counters start
    // equal, so a single 1 bit is a literal). AVG_LIT 13568 selects RK1.
    // Literal 1: value 256 is slot 0, byte 0; slot 0 gains weight in place.
    // Literal 2: slot 65, byte 'A'; it trades with slot 1 (the weight-0
    // cursor), so literal 3 at slot 1 is 'A' again.
    for first in [256, 0] {
        let packed = Asm::default()
            .code(&RK2, initial_flag_slot(0xff))
            .code(&RK1, first)
            .code(&RK1, 65)
            .code(&RK1, 1)
            .finish();
        assert_eq!(decode(&packed, 3).unwrap(), [0, b'A', b'A']);
    }
}

#[test]
fn d6_near_match_repeats_escape_and_flag_byte_promotion() {
    // Flags 0xc0: literal, literal, then three short-family steps.
    // 'a' (slot 97, moves to slot 0), 'b' (slot 98).
    // Near index 1 (SHA "101"): length 3, RK2 value 1 -> NEAR entry 1 -> D 2,
    // an overlapping copy: "ab" + "aba". NEAR entries 0 and 1 swap.
    // Index 9 ("1100") twice: repeats of (2, 3), REPEATS reaches 2.
    // A new flag byte 0: symbol 0 now sits in slot 64, where the first flag
    // byte's promotion put it. Escape bit 1: a third repeat.
    // Escape bit 0: REPEATS 0, then near index 0 with rank 0 -> NEAR entry 0,
    // which is 1 after the swap -> D 2, length 2.
    let packed = Asm::default()
        .code(&RK2, initial_flag_slot(0xc0))
        .code(&RK1, 97)
        .code(&RK1, 98)
        .bits("101")
        .code(&RK2, 1)
        .bits("1100")
        .bits("1100")
        .code(&RK2, 64)
        .bits("1")
        .bits("0")
        .bits("0")
        .code(&RK2, 0)
        .finish();
    assert_eq!(decode(&packed, 16).unwrap(), b"abababababababab");
}

#[test]
fn d7_long_match_in_unary_and_16_bit_forms() {
    // Flags 0xfa: five literals, then "01" = long match. "hello": the second
    // 'l' is at slot 2 after the first one's promotion.
    // Long: AVG_LONG 0 -> unary, "1" is c = 0. AVG_FAR 0 -> RK0, value 256 is
    // slot 0 = high part 0. Seven bits 5 -> D 5. L = 0 + 3 + 8 (D <= 256).
    let hello = |length_bits: &str, rank: u32| {
        Asm::default()
            .code(&RK2, initial_flag_slot(0xfa))
            .code(&RK1, 104)
            .code(&RK1, 101)
            .code(&RK1, 108)
            .code(&RK1, 2)
            .code(&RK1, 111)
            .bits(length_bits)
            .code(&RK0, rank)
            .bits("0000101")
            .finish()
    };
    assert_eq!(decode(&hello("1", 256), 16).unwrap(), b"hellohellohelloh");
    // The decoder also accepts c <= 7 as a 16-bit value.
    assert_eq!(
        decode(&hello("0000000000000000", 256), 16).unwrap(),
        b"hellohellohelloh"
    );
    // c = 3 in unary is "0001": L = 14.
    assert_eq!(
        decode(&hello("0001", 0), 19).unwrap(),
        b"hellohellohellohell"
    );
}

// ---- D7 steps 10 and 12: the hit counter and the threshold it feeds ------
//
// These assert the RULES rather than a decoded byte string, because output
// cannot see them. `HITS` is written by step 10 and read in exactly one
// place, step 12's `H3 > 176`; a member whose counter never reaches 177
// decodes identically however step 10 is written. Measured on the eight-case
// corpus of RARFAST-BENCH section 33: seven cases reach the decrement's floor
// (`text16m_level5` 21,501 times) but peak at `HITS` 44, far below the read;
// the one case that does reach the read, `audio_win_names`, saturates at 255
// and never takes the decrement's floor arm at all. No case does both, which
// is why a wrong step 10 was byte-identical on all eight and passed the whole
// suite. A round trip cannot see it either: the encoder and the decoder share
// this model, so a broken rule re-encodes and re-decodes consistently.

/// Lowers `AVG_LIT` under 10752 so step 12's second disjunct is disarmed and
/// the threshold depends on `HITS` alone. `run_literal` is used rather than
/// `literal` because it writes the literal without touching `RUN`, so the
/// drive cannot trip run-mode entry.
fn quiet_literals(model: &mut Model) {
    for _ in 0..200 {
        model.run_literal(1);
    }
    assert_eq!(
        model.threshold(),
        8193,
        "the drive left the threshold alone"
    );
}

/// A long match that takes step 10's INCREMENT arm: c = 0 and D = 1, which is
/// under either threshold. Slot 0 of `FAR` holds symbol 0 and a promotion of
/// slot 0 trades it with itself, so D is 1 on every call.
fn hit(model: &mut Model) {
    assert_eq!(model.long_match(0, 0, 1).0, 1, "D is the 7 raw bits");
}

/// A long match that takes step 10's DECREMENT arm: c is neither 0, 1 nor 4.
/// c = 5 also keeps `AVG_LONG` clear of step 12's `A2 < 64` boundary.
fn miss(model: &mut Model) {
    model.long_match(5, 0, 1);
}

#[test]
fn d7_hit_counter_decrement_floors_at_zero() {
    // NEGATIVE CONTROL: with step 10's `HITS > 0` written `HITS > 1` the
    // counter sticks at 1 here and this test reads 1. That is the arm the
    // whole corpus and the whole suite passed.
    let mut model = Model::new();
    quiet_literals(&mut model);
    for expected in 1..=5 {
        hit(&mut model);
        assert_eq!(model.hits(), expected, "the increment is +1 under 255");
    }
    for expected in (0..=4).rev() {
        miss(&mut model);
        assert_eq!(model.hits(), expected, "the decrement is -1");
    }
    for _ in 0..8 {
        miss(&mut model);
        assert_eq!(
            model.hits(),
            0,
            "the floor is 0 and the counter stays on it"
        );
    }
    // And the floor is a floor, not a latch: the counter climbs off it.
    hit(&mut model);
    assert_eq!(model.hits(), 1);
}

#[test]
fn d7_threshold_reads_the_hit_counter_from_before_step_10() {
    // NEGATIVE CONTROL: `HITS > 1` in step 10 reaches 177 one call earlier
    // and the first assertion below reads 32512. Reading `self.hits` instead
    // of the saved H3 in step 12 fails the same assertion, for the other
    // reason - so this pins the order constraint as well as the boundary.
    let mut model = Model::new();
    quiet_literals(&mut model);
    // Up, through the floor, and up again: 176 increments off a floor the
    // counter actually reached. Nothing here reads `hits` - this is what a
    // caller outside the model can see, and it is the whole of what the
    // decoded bytes can depend on.
    for _ in 0..5 {
        hit(&mut model);
    }
    for _ in 0..20 {
        miss(&mut model);
    }
    for _ in 0..176 {
        hit(&mut model);
    }

    // H3 = 176 is NOT above 176, though `HITS` is 177 when step 12 runs.
    hit(&mut model);
    assert_eq!(
        model.threshold(),
        8193,
        "step 12 uses H3, and 176 is not > 176"
    );

    // H3 = 177 is.
    hit(&mut model);
    assert_eq!(model.threshold(), 32512);
}

#[test]
fn d7_threshold_second_disjunct_uses_the_saved_avg_long() {
    // `AVG_LIT` starts at 13568, above 10752, and `AVG_LONG` at 0, below 64,
    // so a first long match with a large c arms the second disjunct on the
    // values from BEFORE step 5 - and disarms it on the values after.
    // NEGATIVE CONTROL: step 12 reading `self.avg_long` rather than the saved
    // A2 reads 97 here, and the first assertion below gives 8193.
    let mut model = Model::new();
    model.long_match(100, 0, 1);
    assert_eq!(model.threshold(), 32512, "A2 is 0, not the 97 step 5 left");

    // Both halves are needed. Same A2 = 0, but a quiet `AVG_LIT`.
    let mut model = Model::new();
    quiet_literals(&mut model);
    model.long_match(100, 0, 1);
    assert_eq!(model.threshold(), 8193, "AVG_LIT is under 10752");

    // And the first half alone is not enough either: `AVG_LIT` is still
    // 13568 here, but A2 is 97 by the second call.
    let mut model = Model::new();
    model.long_match(100, 0, 1);
    model.long_match(100, 0, 1);
    assert_eq!(model.threshold(), 8193, "A2 is 97, which is not under 64");
}

/// Decays `AVG_LIT` from its initial 13568 with `n` zero-slot literals, then
/// lands it on exactly `target` with one literal of slot `q`. Rule L is
/// `AVG_LIT += q; AVG_LIT -= AVG_LIT/256`, whose fixed points are sparse, so
/// the boundaries below are reached rather than set.
fn avg_literal_at(model: &mut Model, n: usize, q: u8) {
    for _ in 0..n {
        model.run_literal(1);
    }
    model.run_literal(u16::from(q) + 1);
}

#[test]
fn d7_hit_counter_ignores_length_codes_1_and_4() {
    // Step 10 runs only when c is neither 1 nor 4, and its increment arm
    // needs BOTH c = 0 and D <= THRESH. Neither condition is pinned by
    // anything else in the repository: dropping `c != 4` from the guard, or
    // dropping `D <= THRESH` from the increment, passes the rest of the suite
    // and is byte-identical on the whole eight-case corpus.
    // NEGATIVE CONTROL: the guard written `c != 1` makes the c = 4 assertion
    // read 4; the increment arm written `c == 0` alone makes the last
    // assertion read 6.
    let mut model = Model::new();
    quiet_literals(&mut model);
    for _ in 0..5 {
        hit(&mut model);
    }
    assert_eq!(model.hits(), 5);

    // D = 1 is under THRESH, so a c of 0 here would have raised the counter
    // and a c of 5 would have lowered it. c = 1 and c = 4 do neither.
    model.long_match(1, 0, 1);
    assert_eq!(model.hits(), 5, "c = 1 does not reach step 10");
    model.long_match(4, 0, 1);
    assert_eq!(model.hits(), 5, "c = 4 does not reach step 10");

    // c = 0 alone is not enough to increment. Slot 65 of `FAR` holds symbol
    // 65, so D is 8320, over the 8193 THRESH sits at here, and this takes the
    // DECREMENT arm.
    assert_eq!(model.threshold(), 8193);
    assert_eq!(model.long_match(0, 65, 0).0, 8320, "D is over THRESH");
    assert_eq!(model.hits(), 4, "c = 0 with a far D decrements");
}

#[test]
fn d7_threshold_avg_literal_boundary_is_10752() {
    // Step 12's second disjunct is `AVG_LIT >= 10752 and A2 < 64`. With H3 at
    // 0 and `AVG_LONG` never leaving 0 (c = 0 adds nothing), the threshold is
    // that comparison alone. 60 zero-slot literals leave `AVG_LIT` at 10754;
    // one more of slot 40 lands it on exactly 10752, and slot 39 on 10751.
    // NEGATIVE CONTROL: the constant written 10753 makes the first assertion
    // read 8193.
    let mut model = Model::new();
    avg_literal_at(&mut model, 60, 40);
    model.long_match(0, 0, 1);
    assert_eq!(model.threshold(), 32512, "10752 is not under 10752");

    let mut model = Model::new();
    avg_literal_at(&mut model, 60, 39);
    model.long_match(0, 0, 1);
    assert_eq!(model.threshold(), 8193, "10751 is");
}

#[test]
fn d7_distance_rank_code_boundaries_are_1791_and_10495() {
    // Step 6 picks RK0 up to 1791, RK1 to 10495, RK2 above. `AVG_FAR` starts
    // at 0 and step 7 is `AVG_FAR += v; AVG_FAR -= AVG_FAR/256` with v up to
    // 256, so the two boundaries are reached by seven then thirty-seven
    // maximal steps and one measured one (the second run continues from
    // 1792, which is why its last value is 166 and not the 185 a run from
    // zero would need). c = 1 is used throughout so step 10
    // never runs and nothing here depends on the hit counter.
    // NEGATIVE CONTROL: 1791 written 1790 fails the first assertion; 10495
    // written 10494 fails the third.
    let mut model = Model::new();
    for _ in 0..7 {
        model.long_match(1, 256, 0);
    }
    model.long_match(1, 28, 0);
    assert!(
        std::ptr::eq(model.far_rank_code(), &RK0),
        "AVG_FAR 1791 is RK0"
    );

    let mut model = Model::new();
    for _ in 0..7 {
        model.long_match(1, 256, 0);
    }
    model.long_match(1, 29, 0);
    assert!(
        std::ptr::eq(model.far_rank_code(), &RK1),
        "AVG_FAR 1792 is RK1"
    );

    for _ in 0..37 {
        model.long_match(1, 256, 0);
    }
    model.long_match(1, 166, 0);
    assert!(
        std::ptr::eq(model.far_rank_code(), &RK1),
        "AVG_FAR 10495 is RK1"
    );
    model.long_match(1, 167, 0);
    assert!(
        std::ptr::eq(model.far_rank_code(), &RK2),
        "AVG_FAR 10496 is RK2"
    );
}

#[test]
fn d4_literal_code_boundary_is_3583() {
    // Rule 4.5's lowest boundary, and the one edge of that ladder nothing
    // else reaches: `AVG_LIT` starts at 13568 inside RK1's band and every
    // fixture keeps it there. 346 zero-slot literals leave it at 3597; one
    // more of slot 1 lands on 3584 and slot 0 on 3583.
    // NEGATIVE CONTROL: the constant written 3582 fails the second assertion.
    let mut model = Model::new();
    avg_literal_at(&mut model, 346, 1);
    assert!(std::ptr::eq(model.literal_code(), &RK1), "3584 is RK1");

    let mut model = Model::new();
    avg_literal_at(&mut model, 346, 0);
    assert!(std::ptr::eq(model.literal_code(), &RK0), "3583 is RK0");
}

#[test]
fn d8_zero_fill_for_distance_0_none_and_unwritten() {
    // Long at distance 0: flags 0x40 ("01" first), c = 0, rank 0, t = 0.
    let packed = Asm::default()
        .code(&RK2, initial_flag_slot(0x40))
        .bits("1")
        .code(&RK0, 0)
        .bits("0000000")
        .finish();
    assert_eq!(decode(&packed, 11).unwrap(), [0; 11]);

    // Ring match at the newest recent distance while it is none: index 10,
    // LENA 0 -> L = 0 + 2 + 1 + 1 = 4 zeros; then a repeat, 4 more.
    let packed = Asm::default()
        .code(&RK2, initial_flag_slot(0))
        .bits("1000")
        .code(&LENA, 0)
        .bits("1100")
        .finish();
    assert_eq!(decode(&packed, 8).unwrap(), [0; 8]);

    // A repeat right after a full reset copies length 0: no output, and the
    // member still ends at its target on the zero bits that follow.
    let packed = Asm::default()
        .code(&RK2, initial_flag_slot(0))
        .bits("1100")
        .finish();
    assert_eq!(decode(&packed, 2).unwrap(), [0; 2]);

    // Near match at distance 3 with two bytes written: zeros.
    let packed = Asm::default()
        .code(&RK2, initial_flag_slot(0xc0))
        .code(&RK1, 97)
        .code(&RK1, 98)
        .bits("101")
        .code(&RK2, 2)
        .finish();
    assert_eq!(decode(&packed, 5).unwrap(), b"ab\0\0\0");
}

#[test]
fn d8_a_match_past_the_target_is_invalid_data() {
    let packed = Asm::default()
        .code(&RK2, initial_flag_slot(0xc0))
        .code(&RK1, 97)
        .code(&RK1, 98)
        .bits("101")
        .code(&RK2, 1)
        .finish();
    assert!(matches!(decode(&packed, 4), Err(Error::InvalidData(_))));
    let mut out = Vec::new();
    let result = Rar15Decoder::new().decode_member_to(&packed, 4, false, &mut out);
    assert!(matches!(result, Err(Error::InvalidData(_))));
    assert!(out.len() <= 2, "no byte of the failing match is delivered");
}

#[test]
fn d6_toggle_enables_index_14() {
    // Flags 0: index 10 with LENA 255 flips TOGGLE (no output). Then the
    // toggled SHA code: "1011" is index 14, LENB 0 -> L 5, 15 bits 3 ->
    // D 32771, unwritten, so zeros. Then "1010" is index 1 (length 3).
    let packed = Asm::default()
        .code(&RK2, initial_flag_slot(0))
        .bits("1000")
        .code(&LENA, 255)
        .bits("1011")
        .code(&LENB, 0)
        .bits("000000000000011")
        .bits("1010")
        .code(&RK2, 0)
        .finish();
    assert_eq!(decode(&packed, 8).unwrap(), [0; 8]);
}

#[test]
fn d3_flag_byte_value_256_is_eight_zero_bits() {
    // RK2 value 256: flag byte 0. Short-family steps: near index 0 with rank
    // 0, two zeros each (nothing written yet).
    let packed = Asm::default()
        .code(&RK2, 256)
        .bits("0")
        .code(&RK2, 0)
        .bits("0")
        .code(&RK2, 0)
        .finish();
    assert_eq!(decode(&packed, 4).unwrap(), [0; 4]);
}

#[test]
fn d5_run_mode_entry_needs_run_16_and_the_last_flag_bit() {
    // Drive the model with literals, filling flag bytes exactly, and
    // occasionally a near match to shift the literals against byte ends.
    let mut model = Model::new();
    let mut sink = BitCounter::default();
    let (mut entries, mut non_entries) = (0, 0);
    for step in 0..2000u32 {
        if model.flag_left() == 0 {
            model.open_planning_group();
        }
        if model.run_mode() {
            model.put_run_exit(&mut sink).unwrap();
            continue;
        }
        if step % 29 == 3 && model.flag_left() >= 2 {
            model.put_near(&mut sink, 3, 1).unwrap();
            continue;
        }
        if model.flag_bits_for(true) > model.flag_left() {
            // One bit left and literals take two: a long match takes one.
            model.put_long(&mut sink, 11, 5).unwrap();
            continue;
        }
        let run_before = model.run_length();
        model.put_literal(&mut sink, (step % 251) as u8).unwrap();
        let expected = run_before >= 16 && model.flag_left() == 0;
        assert_eq!(model.run_mode(), expected, "step {step}, RUN {run_before}");
        if expected {
            entries += 1;
        } else if run_before >= 16 && model.flag_left() == 1 {
            non_entries += 1;
        }
    }
    assert!(
        entries > 0 && non_entries > 0,
        "{entries} entries, {non_entries} non-entries"
    );
}

/// One item of a scripted member.
#[derive(Clone, Copy, Debug)]
enum Item {
    Literal(u8),
    Near(u32, u32),
    Ring(usize, u32),
    Repeat,
    Toggle,
    FarShort(u32, u32),
    Long(u32, u32),
    RunLiteral(u8),
    RunMatch(u32, u32),
}

/// Writes `items` through the model's commits, grouping flag bits into
/// whole flag bytes and leaving run mode before any normal item, and returns
/// the packed bytes and the expected output. Run-mode items are skipped when
/// the model is not in run mode.
fn script(items: &[Item]) -> (Vec<u8>, Vec<u8>) {
    let mut model = Model::new();
    let mut bits = BitWriter::default();
    let mut output = Vec::new();
    let mut index = 0;
    while index < items.len() {
        let run_item = matches!(items[index], Item::RunLiteral(_) | Item::RunMatch(..));
        if run_item {
            if model.run_mode() {
                apply(&mut model, &mut bits, &mut output, items[index]);
            }
            index += 1;
            continue;
        }
        if model.run_mode() {
            model.put_run_exit(&mut bits).unwrap();
        }
        let mut plan = model;
        plan.open_planning_group();
        let mut flags = 0u8;
        let mut used = 0usize;
        let mut group = Vec::new();
        while index < items.len() && used < 8 && !plan.run_mode() {
            let mut item = items[index];
            if matches!(item, Item::RunLiteral(_) | Item::RunMatch(..)) {
                break;
            }
            let pattern = |plan: &Model, item: Item| -> &'static [bool] {
                match item {
                    Item::Literal(_) if plan.prefers_long() => &[false, true],
                    Item::Literal(_) => &[true],
                    Item::Long(..) if plan.prefers_long() => &[true],
                    Item::Long(..) => &[false, true],
                    _ => &[false, false],
                }
            };
            let filler = used + pattern(&plan, item).len() > 8;
            if filler {
                // One flag bit left for a two-bit item: fill it with a
                // one-bit item instead (a literal, or a long match when long
                // matches take the single bit).
                item = if plan.prefers_long() {
                    Item::Long(11, 5)
                } else {
                    Item::Literal(b'#')
                };
            }
            for &bit in pattern(&plan, item) {
                if bit {
                    flags |= 0x80 >> used;
                }
                used += 1;
            }
            apply(&mut plan, &mut BitCounter::default(), &mut Vec::new(), item);
            group.push(item);
            if !filler {
                index += 1;
            }
        }
        let at_end = index == items.len()
            || matches!(items[index], Item::RunLiteral(_) | Item::RunMatch(..));
        assert!(
            used == 8 || at_end,
            "flag byte left partly used before item {index}"
        );
        model.put_flag_byte(&mut bits, flags).unwrap();
        for item in group {
            apply(&mut model, &mut bits, &mut output, item);
        }
    }
    (bits.finish(), output)
}

/// D8 over a flat vector, independent of the ring arithmetic. The zero fill
/// is settled ONCE, from the state before the copy, exactly as D8 step 3
/// says ("not wrapped and D > FILLED", with wrapped read before the copy).
///
/// Re-reading `d <= output.len()` per byte is NOT the same rule, and the two
/// part company for a copy that STRADDLES the history boundary: it begins
/// while the distance reaches back further than the bytes produced so far,
/// and produces enough bytes for the distance to become valid part-way
/// through. Reference `rar` 7.23 decodes such a member to all zeros - the
/// reading below - and not to zeros followed by real bytes; see
/// `zero_fill_is_settled_once_for_a_copy_that_straddles_the_history_boundary`.
fn copy_expected(output: &mut Vec<u8>, distance: u32, length: u32) {
    let d = distance as usize;
    let zero_fill = distance == NONE || d == 0 || d > 0x10000 || d > output.len();
    for _ in 0..length {
        let byte = if zero_fill {
            0
        } else {
            output[output.len() - d]
        };
        output.push(byte);
    }
}

fn apply(model: &mut Model, sink: &mut impl BitSink, output: &mut Vec<u8>, item: Item) {
    match item {
        Item::Literal(byte) => {
            model.put_literal(sink, byte).unwrap();
            output.push(byte);
        }
        Item::Near(length, distance) => {
            model.put_near(sink, length, distance).unwrap();
            copy_expected(output, distance, length);
        }
        Item::Ring(k, length) => {
            let distance = model.recent()[k - 1];
            model.put_ring(sink, k, length).unwrap();
            copy_expected(output, distance, length);
        }
        Item::Repeat => {
            let (distance, length) = model.last_match();
            model.put_repeat(sink, length, distance).unwrap();
            copy_expected(output, distance, length);
        }
        Item::Toggle => model.put_toggle(sink).unwrap(),
        Item::FarShort(length, distance) => {
            model.put_far_short(sink, length, distance).unwrap();
            copy_expected(output, distance, length);
        }
        Item::Long(length, distance) => {
            model.put_long(sink, length, distance).unwrap();
            copy_expected(output, distance, length);
        }
        Item::RunLiteral(byte) => {
            model.put_run_literal(sink, byte).unwrap();
            output.push(byte);
        }
        Item::RunMatch(length, distance) => {
            model.put_run_match(sink, length, distance).unwrap();
            copy_expected(output, distance, length);
        }
    }
}

#[test]
fn scripted_run_mode_items_decode_the_same_in_both_decoders() {
    // 24 one-bit literals: the 24th has RUN 23 and uses the last flag bit of
    // the third flag byte, so run mode starts. A run match at 8200 needs
    // rank value 256 (8200 / 32 = 256); at 24 bytes written it is zeros.
    let mut items: Vec<Item> = (0..24u8).map(|i| Item::Literal(b'a' + i % 5)).collect();
    items.extend([
        Item::RunLiteral(b'z'),
        Item::RunMatch(4, 8200),
        Item::RunMatch(3, 3),
        Item::RunLiteral(0xff),
        Item::Literal(b'q'),
    ]);
    let (packed, expected) = script(&items);
    assert_eq!(
        expected.len(),
        24 + 1 + 4 + 3 + 1 + 1,
        "every run item was written"
    );
    assert_eq!(decode(&packed, expected.len()).unwrap(), expected);
}

#[test]
fn scripted_items_cover_toggle_far_short_ring_and_repeats() {
    let mut items = Vec::new();
    for index in 0..300u32 {
        items.push(Item::Literal((index * 7 % 251) as u8));
    }
    // Leave run mode and realign: the script exits before the next normal
    // item. Short-family items take two flag bits each, four per byte.
    items.extend([
        Item::Near(4, 17),
        Item::Repeat,
        Item::Repeat,
        Item::Repeat,
        Item::Ring(2, 5),
        Item::Toggle,
        Item::FarShort(9, 40000),
        Item::Ring(1, 6),
        Item::Toggle,
        Item::Near(10, 256),
        Item::Ring(4, 3),
        Item::Near(2, 1),
    ]);
    let (packed, expected) = script(&items);
    assert_eq!(decode(&packed, expected.len()).unwrap(), expected);
}

/// D8's block copy overshoots the end of a match, and on a 64 KiB ring the
/// bytes it overshoots into are LIVE: `far_short` (D6d) reaches distance
/// 65,535, which is the byte one position ahead of the write cursor. This
/// scripts exactly that read - a wrapped window, a match wide enough to take
/// the block path, then a far-short match at distance 65,535 whose source is
/// the first byte past the previous match's end - so a copy that leaves its
/// overshoot in place returns the wrong bytes here.
///
/// Verified to FAIL against the unsound 32-byte arm of
/// `research/rarbench-2026-09-16/rar15roof-variant-wild32.patch` (it reads
/// back the overshoot) and to pass against the byte loop and the block copy
/// that restores what it clobbered.
#[test]
fn d8_far_short_reads_the_bytes_a_block_copy_overshoots() {
    // A 256-byte literal alphabet, then that pattern replicated past the
    // window's end so the ring has wrapped and every distance is live.
    let mut items: Vec<Item> = (0..256u32)
        .map(|i| Item::Literal((i * 7 % 251) as u8))
        .collect();
    items.extend(std::iter::repeat_n(Item::Near(10, 256), 6604));
    // The probe. `Near(4, 100)` is wide enough for the block path and short
    // enough to leave an overshoot; the far-short match that follows reads
    // from one byte past the write cursor, which is inside it.
    items.extend([
        Item::Toggle,
        Item::Near(4, 100),
        Item::FarShort(20, 65535),
        Item::Near(2, 1),
    ]);
    let (packed, expected) = script(&items);
    assert!(
        expected.len() > 65_536 + 256,
        "the window must have wrapped: {} bytes",
        expected.len()
    );
    let decoded = decode(&packed, expected.len()).unwrap();
    // Point at the far-short match's own 20 bytes when it differs, not at the
    // first of 66,000.
    let probe = expected.len() - 22;
    assert_eq!(
        &decoded[probe..],
        &expected[probe..],
        "the far-short match at distance 65,535 read the overshoot"
    );
    assert_eq!(decoded, expected);
}

/// The same boundary as the test above, taken randomly rather than at one
/// hand-placed position: many wrapped windows, short matches at every distance
/// class, and far-short matches all the way out to 65,535. `script`'s expected
/// output is built by `copy_expected` over a FLAT vector, so it is an oracle
/// independent of the window's ring arithmetic and of any block copy over it.
///
/// This is the arm that gates the match copy's overshoot generally: a copy
/// that leaves clobbered bytes behind fails it within the first seed.
#[test]
fn far_distance_matches_agree_with_a_flat_oracle_over_many_wraps() {
    for seed in 0..8u64 {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // A varied literal prefix, in whole flag bytes.
        let mut items: Vec<Item> = (0..512u32)
            .map(|i| Item::Literal((i.wrapping_mul(97) % 251) as u8))
            .collect();
        // Fill past the window's end before any far match, so every distance
        // below is inside the history. A copy that STRADDLES that boundary is
        // a different question - the decoder settles zero-fill once for the
        // whole copy where `copy_expected` re-reads it per byte - and it is
        // not the one this test asks.
        items.extend(std::iter::repeat_n(Item::Near(10, 256), 6604));
        // Then short-family items only, four to a flag byte. The leading
        // toggle turns index 14 on and nothing here turns it off again.
        items.push(Item::Toggle);
        for _ in 0..(4 * 12_000 - 1) {
            let draw = next();
            items.push(if draw & 3 == 0 {
                // Far: 32,768 to 65,535, the class that reaches the bytes
                // AHEAD of the write cursor.
                let distance = 32_768 + (draw >> 8) as u32 % 32_768;
                let length = 5 + (draw >> 32) as u32 % 36;
                Item::FarShort(length, distance)
            } else {
                // Near: 1 to 256, which straddles the block path's minimum
                // separation and the overlapping-pattern fallback.
                let distance = 1 + (draw >> 8) as u32 % 256;
                let length = 2 + (draw >> 32) as u32 % 9;
                Item::Near(length, distance)
            });
        }
        let (packed, expected) = script(&items);
        assert!(
            expected.len() > 4 * 65_536,
            "seed {seed}: the window must wrap several times, got {} bytes",
            expected.len()
        );
        let decoded = decode(&packed, expected.len()).unwrap();
        if decoded != expected {
            let at = decoded
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            panic!(
                "seed {seed}: first divergence at byte {at} of {} (window position {}): \
                 decoded {:?} expected {:?}",
                expected.len(),
                at % 65_536,
                &decoded[at..(at + 8).min(decoded.len())],
                &expected[at..(at + 8).min(expected.len())]
            );
        }
    }
}

#[test]
fn a_refused_commit_writes_nothing_and_changes_nothing() {
    let mut model = Model::new();
    let mut sink = BitWriter::default();
    model.open_planning_group();
    // Run-mode items outside run mode, a near match out of range, a ring
    // match whose length code would be negative, a far short match with the
    // toggle off.
    assert!(model.put_run_match(&mut sink, 3, 8200).is_err());
    assert!(model.put_run_literal(&mut sink, 1).is_err());
    assert!(model.put_near(&mut sink, 11, 1).is_err());
    assert!(model.put_ring(&mut sink, 1, 2).is_err());
    assert!(model.put_far_short(&mut sink, 5, 40000).is_err());
    assert_eq!(model.flag_left(), 8);
    assert!(sink.finish().is_empty());
}

#[test]
fn decoder_and_model_values_stay_small() {
    let model = std::mem::size_of::<Model>();
    let decoder = std::mem::size_of::<Rar15Decoder>();
    assert!(
        decoder <= model + 32,
        "decoder {decoder} bytes, model {model}"
    );
    assert!(model <= 3 * 1024 + 512 + 128, "model {model} bytes");
}

#[test]
fn zero_fill_is_settled_once_for_a_copy_that_straddles_the_history_boundary() {
    // Five literals, then a near match at distance 10 and length 10: the
    // distance reaches back further than the five bytes produced, and the
    // copy itself produces enough bytes for distance 10 to become valid
    // part-way through. D8 settles the zero fill once, before the copy, so
    // every byte of the match is zero.
    //
    // The expected bytes are not this crate's: reference `rar` 7.23 extracts
    // a hand-built RAR 1.5 member carrying exactly this item stream to them,
    // and refuses the other reading (`ABCDE`, five zeros, `ABCDE`) on its
    // checksum. A control member in the same rig - twenty literals and a
    // self-overlapping match at distance 5 - extracts to the same bytes in
    // both readings, which is what says the rig can tell them apart.
    let mut items: Vec<Item> = (0..5u8).map(|index| Item::Literal(b'A' + index)).collect();
    items.push(Item::Near(10, 10));
    let (packed, expected) = script(&items);
    let reference: &[u8] = b"ABCDE\0\0\0\0\0\0\0\0\0\0";
    // Both arms matter: the first is the decoder, the second is the flat
    // oracle every scripted test here is checked against, which read the
    // rule per byte until 16 Sep 2026 and disagreed on this member.
    assert_eq!(decode(&packed, reference.len()).unwrap(), reference);
    assert_eq!(expected, reference);

    // A wider gap, so the boundary is crossed at a different offset.
    let mut items: Vec<Item> = (0..3u8).map(|index| Item::Literal(b'A' + index)).collect();
    items.push(Item::Near(10, 12));
    let (packed, expected) = script(&items);
    let reference: &[u8] = b"ABC\0\0\0\0\0\0\0\0\0\0";
    assert_eq!(decode(&packed, reference.len()).unwrap(), reference);
    assert_eq!(expected, reference);
}

// ---------------------------------------------------------------------------
// The second mutation census (claim `rar15-codec-mutation-census-rest`,
// 16 Sep 2026) ran 89 single-rule mutations over `bits.rs`, `codes.rs`,
// `decoder.rs` and `model.rs`'s section 5 encoder half, each a whole
// `cargo test -p rars --lib --features parallel` leg. Ten rules were
// unconstrained by anything in the repository. The tests below pin those ten,
// each against hand-derived constants and each shown red against its own
// deliberate break - the break is named in the test's own comment and is
// never a second code path.
//
// The six other uncaught mutations are semantically INERT on every reachable
// input (a free choice of constant, a redundant statement, or a cost-only
// query that cannot make output wrong), and are argued rather than tested;
// see nzbfast's 16 Sep 2026 note on the rest of the RAR 1.5 codec mutation
// census.
// ---------------------------------------------------------------------------

/// 48 distinct literals, which is exactly two run-mode entries' worth: a
/// literal enters run mode when `RUN` >= 16 and it used the last flag bit of
/// its flag byte (D4 step 2), and 24 one-bit literals fill three flag bytes
/// exactly. The bytes are all different, so a copy at the wrong distance
/// cannot land on the same byte by chance.
fn forty_eight_distinct_literals() -> Vec<Item> {
    (0..48u8).map(Item::Literal).collect()
}

#[test]
fn d5_run_match_distance_is_the_rank_value_times_32_plus_five_bits() {
    // NEGATIVE CONTROL: with D5's `u * 32 + f` written `u * 16 + f` the
    // distance below is 24 rather than 40 and this test reads output[24..27].
    // The whole suite and the whole corpus pass that arm: the only two run
    // matches anywhere in the repository are at D = 3 (where 0 * 32 and
    // 0 * 16 agree) and at D = 8200 with 25 bytes written (where both
    // distances are past the history and zero-fill).
    let mut items = forty_eight_distinct_literals();
    items.push(Item::RunMatch(3, 40));
    let (packed, expected) = script(&items);
    assert_eq!(expected.len(), 48 + 3, "the run match was written");
    // 40 back from position 48 is output[8], and the literals are their own
    // index, so the three copied bytes are 8, 9, 10 - worked out from the
    // rule, not read off a decode.
    assert_eq!(&expected[48..], &[8, 9, 10], "u = 1, f = 8, so D = 40");
    assert_eq!(decode(&packed, expected.len()).unwrap(), expected);
}

#[test]
fn d8_a_long_overlapping_match_repeats_its_pattern() {
    // NEGATIVE CONTROL: the block copy declines a `copy_within` unless the
    // match does not overlap (`back >= span`). Written `back >= 1` this test
    // reads a flat 100-byte copy of output[80..180] instead of the 40-byte
    // pattern repeated, because `copy_within` is a memmove and has no
    // repeating-pattern semantics. Nothing else in the repository has a match
    // that is longer than `LONG` (64) at a distance that is at least `WILD`
    // (32) and under its own length, which is the only shape that reaches it.
    let mut items: Vec<Item> = (0..120u8).map(Item::Literal).collect();
    items.push(Item::Long(100, 40));
    let (packed, expected) = script(&items);
    assert_eq!(expected.len(), 120 + 100);
    // D8 step 4: each byte is written before the next is read, so a match at
    // distance 40 repeats output[80..120] until it has 100 bytes.
    let pattern: Vec<u8> = (80..120u8).collect();
    let repeated: Vec<u8> = pattern.iter().cycle().take(100).copied().collect();
    assert_eq!(&expected[120..], &repeated[..], "the pattern repeats");
    assert_eq!(decode(&packed, expected.len()).unwrap(), expected);
}

#[test]
fn d1_a_non_solid_member_resets_the_output_side() {
    // NEGATIVE CONTROL: with D1's `if !solid` written `if solid` the second
    // member below keeps the first member's write position and the match
    // reads the FIRST member's bytes instead of zero-filling. No test in the
    // repository decodes two non-solid members on one decoder where the
    // second reaches back past its own start, so the whole suite passes it.
    let (first_packed, first) = script(&forty_eight_distinct_literals());
    // Twelve literals, then a near match 50 back: at 12 bytes produced and a
    // fresh window, D8 step 3's "not wrapped and D > FILLED" is true, so the
    // ten bytes are zeros.
    let mut items: Vec<Item> = (0..12u8).map(|i| Item::Literal(200 + i)).collect();
    items.push(Item::Near(10, 50));
    let (second_packed, second) = script(&items);
    assert_eq!(&second[12..], &[0u8; 10], "the match is past this member");

    let mut decoder = Rar15Decoder::new();
    assert_eq!(
        decoder
            .decode_member(&first_packed, first.len(), false)
            .unwrap(),
        first
    );
    assert_eq!(
        decoder
            .decode_member(&second_packed, second.len(), false)
            .unwrap(),
        second,
        "the second member starts from an empty history"
    );
}

#[test]
fn d1_the_reader_entry_point_decodes_a_one_byte_member() {
    // NEGATIVE CONTROL: the reader entry point's `if target == 0` fast path
    // written `if target == 1` returns success with NO output here, and every
    // other test passes: no fixture member and no generated case is one byte
    // long on the reader path.
    let (packed, expected) = script(&[Item::Literal(b'Z')]);
    assert_eq!(expected, b"Z");
    let mut out = Vec::new();
    Rar15Decoder::new()
        .decode_member_from_reader(&mut packed.as_slice(), 1, false, &mut out)
        .unwrap();
    assert_eq!(out, b"Z");
}

#[test]
fn a_reader_that_reports_interrupted_is_retried_not_refused() {
    // NEGATIVE CONTROL: the reader source retries `ErrorKind::Interrupted`;
    // written as any other kind, this decode is `Err(InvalidData)`. Nothing
    // else in the repository hands the decoder an interrupted read.
    struct Interrupts<'a> {
        data: &'a [u8],
        left: usize,
    }
    impl std::io::Read for Interrupts<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.left > 0 {
                self.left -= 1;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            let len = self.data.len().min(out.len());
            out[..len].copy_from_slice(&self.data[..len]);
            self.data = &self.data[len..];
            Ok(len)
        }
    }
    let (packed, expected) = script(&forty_eight_distinct_literals());
    let mut source = Interrupts {
        data: &packed,
        left: 3,
    };
    let mut out = Vec::new();
    Rar15Decoder::new()
        .decode_member_from_reader(&mut source, expected.len(), false, &mut out)
        .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn a_ring_match_at_the_newest_distance_cannot_spell_the_toggle() {
    // NEGATIVE CONTROL: the guard is `k == 1 && x == 255`; written `k == 2`
    // both assertions below flip. D6e step 3 makes index 10 with `LENA` value
    // 255 the TOGGLE and not a match, so an encoder that spelled it would
    // desynchronise; indexes 11 to 13 with 255 are ordinary matches. Nothing
    // else in the repository reaches this arm - the planner's own ring finder
    // refuses the shape a step earlier, which is a different guard.
    let mut model = Model::new();
    model.set_recent_for_test([100, 200, 300, 400]);
    // D = 100 is at most 256 and under the threshold, so x = L - 2 exactly:
    // L = 257 is the length whose code value is 255.
    assert_eq!(
        model.ring_bits(1, 257),
        None,
        "k = 1, x = 255 is the toggle"
    );
    assert!(
        model.ring_bits(2, 257).is_some(),
        "k = 2 with x = 255 is an ordinary match"
    );
    assert!(
        model.ring_bits(1, 256).is_some(),
        "x = 254 is fine at k = 1"
    );
}

#[test]
fn a_long_match_is_refused_past_32767() {
    // NEGATIVE CONTROL: `distance > 0x7fff` written `> 0xffff` makes both
    // assertions below `Some`, and the emitted stream desynchronises, because
    // D7 step 8 takes the FAR slot of `floor(D / 128)` as a u8 and 65,535
    // truncates to the same slot as 32,767. Nothing else covers it: the
    // planner's long finder caps its own search, so this guard is never the
    // one that fires.
    let model = Model::new();
    // D = 0x7fff is at or above the initial threshold, so c = L - 3 - 1.
    assert!(
        model.long_bits(20, 0x7fff).is_some(),
        "32,767 is expressible"
    );
    assert_eq!(model.long_bits(20, 0x8000), None, "32,768 is not");
    let mut model = model;
    let mut sink = BitCounter::default();
    model.open_planning_group();
    assert!(model.put_long(&mut sink, 20, 0x8000).is_err());
    assert_eq!(sink.bits, 0, "a refused commit writes nothing");
}

#[test]
fn a_long_match_inside_256_bytes_carries_the_eight_byte_length_bonus() {
    // NEGATIVE CONTROL: D7 step 11's `+ 8 if D <= 256`, written `+ 7` on the
    // ENCODER'S side (`long_fields`), makes the decoder read a match one byte
    // longer than the encoder meant and this test fails on the length. The
    // whole suite passes it because the planner's long finder,
    // `find_long_match_bucketed`, skips every candidate nearer than 257, so
    // no long match at 256 or less is ever planned. (This comment named
    // `find_long_match` until 17 Sep 2026. The conclusion was right and the
    // pointer was not: `find_long_match` is the test-only oracle and is not on
    // the planner's path at all.) The one hand-written `put_long(11, 5)` in
    // this file is a
    // filler that the current scripts never reach.
    let mut items: Vec<Item> = (0..24u8).map(Item::Literal).collect();
    items.push(Item::Long(11, 5));
    let (packed, expected) = script(&items);
    assert_eq!(expected.len(), 24 + 11, "L = c + 3 + 8 with c = 0");
    // 5 back from position 24 is output[19], and the match is longer than its
    // own distance, so it repeats 19, 20, 21, 22, 23 twice and then 19.
    assert_eq!(
        &expected[24..],
        &[19, 20, 21, 22, 23, 19, 20, 21, 22, 23, 19]
    );
    assert_eq!(decode(&packed, expected.len()).unwrap(), expected);
}

#[test]
fn a_far_short_match_reaches_length_260() {
    // NEGATIVE CONTROL: the range `5..=260` written `5..=259` fails the first
    // assertion. D6d gives L = x + 5 with x a `LENB` value 0..=255, so 260 is
    // the longest far-short match there is; nothing else in the repository
    // writes one longer than a few bytes.
    let mut model = Model::new();
    let mut sink = BitCounter::default();
    model.open_planning_group();
    model.put_toggle(&mut sink).unwrap();
    let mut at_260 = model;
    at_260.open_planning_group();
    assert!(at_260
        .put_far_short(&mut BitCounter::default(), 260, 0x8000)
        .is_ok());
    let mut at_261 = model;
    at_261.open_planning_group();
    assert!(at_261
        .put_far_short(&mut BitCounter::default(), 261, 0x8000)
        .is_err());
    let mut at_4 = model;
    at_4.open_planning_group();
    assert!(at_4
        .put_far_short(&mut BitCounter::default(), 4, 0x8000)
        .is_err());
}

#[test]
fn a_flag_byte_may_carry_one_unused_bit_and_never_two() {
    // NEGATIVE CONTROL: `carried > 1` written `carried > 2` makes the last
    // assertion `Ok`. 5.3.1 allows exactly one bit to straddle two flag bytes
    // - a one-bit flag always fits, so only a two-bit flag can be left with
    // its first bit in the old byte - and a planner that left two would write
    // the new byte's codeword at the wrong bit position. Nothing else reaches
    // it: the planner fills every group.
    let mut sink = BitCounter::default();
    let mut one_left = Model::new();
    one_left.put_flag_byte(&mut sink, 0).unwrap();
    // A literal is one flag bit here (PREF_LONG is not above PREF_LIT at the
    // initial state), then three short items at two bits each: 7 of 8 used.
    one_left.put_literal(&mut sink, b'a').unwrap();
    for _ in 0..3 {
        one_left.put_near(&mut sink, 3, 1).unwrap();
    }
    assert_eq!(one_left.flag_left(), 1);
    assert!(
        one_left.put_flag_byte(&mut sink, 0).is_ok(),
        "one bit may straddle"
    );

    let mut two_left = Model::new();
    two_left.put_flag_byte(&mut sink, 0).unwrap();
    for _ in 0..3 {
        two_left.put_near(&mut sink, 3, 1).unwrap();
    }
    assert_eq!(two_left.flag_left(), 2);
    assert!(
        two_left.put_flag_byte(&mut sink, 0).is_err(),
        "two bits may not"
    );
}
