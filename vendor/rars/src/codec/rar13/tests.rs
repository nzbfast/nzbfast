//! Encoder and planner round trips.

use super::{
    choose_token, decode_rar15, encode_rar15, find_long_match, find_long_match_bucketed,
    find_ring_match, find_token, find_tokens, should_lazy_emit_literal, EncodeOptions,
    EncodedToken, LongMatch, MatchIndex, MatchingWriter, NearMatch, PlanState, Rar15CheckedEncoder,
    Rar15Decoder, Rar15Encoder, RingMatch, MAX_LONG_DISTANCE, MAX_LONG_MATCH_CANDIDATES, NONE,
};

/// A deterministic byte source: the census's own LCG, kept out of the tests
/// below so each states only what it is pinning.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

#[test]
fn find_tokens_never_offers_a_literal_candidate() {
    // NEGATIVE CONTROL: pushing `EncodedToken::Literal(input[pos])` onto
    // `find_tokens`'s vector fails this at the first position it reaches, and
    // the rest of the suite stays green - a literal candidate is a legal
    // thing to offer, it only moves packed size. That is exactly the point.
    // This is the gate on the reachability argument that keeps
    // `EncodedToken::flag_bits`'s and `token_bit_cost`'s `Literal` arms dead
    // (census leg A3, 16 Sep 2026), and an argument by inspection is the kind
    // that goes stale the day a call site is added.
    let mut input = noise(2048, 0x2545_f491);
    input.extend_from_within(1..65);
    input.extend_from_within(900..1200);
    input.extend_from_within(2048..2100);

    let states = [
        PlanState {
            previous_distance: NONE,
            previous_length: 0,
            recent: [NONE; 4],
            threshold: 0x2001,
            pref_long: 0,
            pref_literal: 0,
        },
        PlanState {
            previous_distance: 300,
            previous_length: 8,
            recent: [300, 64, 1, 1024],
            threshold: 0x7f00,
            pref_long: 0x40,
            pref_literal: 0x20,
        },
    ];

    let mut offered = 0usize;
    for ring_matches in [false, true] {
        let options = EncodeOptions::new().with_old_distance_tokens(ring_matches);
        let mut index = MatchIndex::new(input.len());
        for pos in 0..input.len() {
            for state in states {
                for token in find_tokens(&input, pos, &mut index, state, options) {
                    assert!(
                        !matches!(token, EncodedToken::Literal(_)),
                        "find_tokens offered a literal at {pos}: {token:?}"
                    );
                    offered += 1;
                }
            }
        }
    }
    // Failing to find is failing: a fixture that offered nothing would pass
    // the loop above and pin nothing at all.
    assert!(
        offered > 1000,
        "the fixture offered only {offered} candidates"
    );
}

/// `find_long_match` has no production caller, so nothing in the suite
/// constrains it - and two other tests lean on it as an oracle, inheriting
/// whatever it says. Pins legs I2, I4 and I5 of the 16 Sep 2026 census. I1,
/// the `pos < 257` guard, is not pinnable and says so at the site.
#[test]
fn find_long_match_holds_the_bounds_its_dependants_assume() {
    // I2, the search starts at distance 257. NEGATIVE CONTROL: writing the
    // loop as `256..=max_distance` finds the 64-byte repeat 256 back here and
    // fails this assertion; nothing else in the suite notices.
    let mut input = noise(1024, 0x1357_9bdf);
    let block = input[256..320].to_vec();
    input[512..576].copy_from_slice(&block);
    assert_eq!(
        find_long_match(&input, 512, 0x8000),
        None,
        "a repeat 256 back is a near match's business, not a long match's"
    );

    // I4, a long match is at most 258 bytes however much matches. NEGATIVE
    // CONTROL: `length < 259` returns a 259-byte match and fails this.
    let mut input = noise(300, 0x9e37_79b9);
    input.extend_from_within(..300);
    input.extend_from_within(..300);
    assert_eq!(
        find_long_match(&input, 300, 0x8000),
        Some(LongMatch {
            distance: 300,
            length: 258
        })
    );

    // I5, a long match is at least 3 bytes. NEGATIVE CONTROL: this needs BOTH
    // the loop's `length >= 3` and the final `best.length >= 3` relaxed to 2
    // before it fails - each alone is masked by the other, which is why the
    // census reported I5 uncaught, and why this pins the pair rather than
    // either half.
    let mut input = noise(600, 0x85eb_ca6b);
    let block = input[..2].to_vec();
    input[500..502].copy_from_slice(&block);
    input[502] = input[2] ^ 1;
    assert_eq!(
        find_long_match(&input, 500, 0x8000),
        None,
        "a two-byte repeat is not a match"
    );
}

/// `MATCH_WINDOW`'s doc comment read as a correctness invariant until 17 Sep
/// 2026. It is not one, and this is the half of the re-worded claim a machine
/// can check. The walk is driven over an index whose ring is far smaller
/// than its own distance bound, which is the state a shrunken `MATCH_WINDOW`
/// would leave it in and where most links it reads have been overwritten by
/// a newer position. It still returns, and still returns only matches whose
/// bytes are real.
#[test]
fn the_candidate_walk_returns_on_a_ring_smaller_than_its_distance_bound() {
    // NEGATIVE CONTROL: swapping `MatchIndex::insert_below`'s two lines makes
    // every position link to ITSELF, and this test then HANGS rather than
    // failing - which is census leg K3, and the reason
    // `find_long_match_bucketed` carries a written termination argument and
    // not a cycle guard. A hang is a detection, but a weak one: under
    // nextest's retry it can report flaky rather than red, so read this test
    // by name if the suite ever wedges.
    let mut state = 0x0bad_c0deu32;
    // Six-bit bytes, so the 4,096 hash buckets collide hard and the chains
    // the walk follows are long.
    let input: Vec<u8> = (0..40_000)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 26) as u8
        })
        .collect();

    // A ring of 4,096 links against a 32,767-byte distance bound.
    let mut index = MatchIndex::new(1 << 12);
    let mut found = 0usize;
    for pos in (300..input.len() - 3).step_by(11) {
        let Some(long) = find_long_match_bucketed(
            &input,
            pos,
            MAX_LONG_DISTANCE,
            &mut index,
            MAX_LONG_MATCH_CANDIDATES,
        ) else {
            continue;
        };
        found += 1;
        let distance = long.distance as usize;
        assert!(
            (257..=MAX_LONG_DISTANCE).contains(&distance) && distance <= pos,
            "distance {distance} out of range at {pos}"
        );
        assert!(
            long.length >= 3 && long.length <= 258,
            "length {}",
            long.length
        );
        for offset in 0..long.length as usize {
            assert_eq!(
                input[pos + offset],
                input[pos + offset - distance],
                "byte {offset} of the match at {pos} is not real"
            );
        }
    }
    assert!(found > 50, "the fixture found only {found} matches");
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
            let len = self.input.len().min(out.len()).min(2);
            out[..len].copy_from_slice(&self.input[..len]);
            self.input = &self.input[len..];
            Ok(len)
        }
    }

    let expected = b"RAR 1.4 incremental input fixture\n".repeat(32);
    let packed = encode_rar15(&expected).unwrap();
    assert_eq!(decode_rar15(&packed, expected.len()).unwrap(), expected);

    let mut reader = TinyReader { input: &packed };
    let mut decoder = Rar15Decoder::new();
    let mut output = Vec::new();
    decoder
        .decode_member_from_reader(&mut reader, expected.len(), false, &mut output)
        .unwrap();

    assert_eq!(output, expected);
}

#[test]
fn encoder_emits_rar15_very_long_matches() {
    let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
    input.extend_from_within(..258);

    assert_eq!(
        find_long_match(&input, 300, 0x8000),
        Some(LongMatch {
            distance: 300,
            length: 258
        })
    );
    let packed = encode_rar15(&input).unwrap();

    assert!(
        packed.len() < 330,
        "a very long match should encode a 258-byte repeat compactly, got {} bytes",
        packed.len()
    );
    assert_eq!(decode_rar15(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_adjusts_rar15_long_match_length_for_far_distance_bonus() {
    let mut input: Vec<_> = (0..9000).map(|index| (index * 73 + 19) as u8).collect();
    input.extend_from_within(..10);

    let packed = encode_rar15(&input).unwrap();

    assert_eq!(decode_rar15(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_reuses_rar15_repeat_token() {
    let input = b"abcdefghijklmnop".repeat(64);
    let packed = encode_rar15(&input).unwrap();

    assert!(
        packed.len() < 100,
        "repeat tokens should keep a simple repeated pattern compact, got {} bytes",
        packed.len()
    );
    assert_eq!(decode_rar15(&packed, input.len()).unwrap(), input);
}

#[test]
fn ring_finder_maps_recent_distances_to_short_indexes() {
    let mut input: Vec<_> = (0..80).map(|index| (index * 37 + 11) as u8).collect();
    let pos = input.len();
    input.extend_from_within(pos - 33..pos - 13);

    assert_eq!(
        find_ring_match(&input, pos, [44, 33, 22, 11]),
        Some(RingMatch {
            distance: 33,
            length: 20,
            index: 11,
        })
    );
}

#[test]
fn ring_finder_rejects_the_toggle_encoding() {
    let mut input = b"abcd".repeat(128);
    let pos = input.len();
    input.extend((0..257).map(|index| b"abcd"[index % 4]));

    assert_eq!(
        find_ring_match(&input, pos, [4, NONE, NONE, NONE]),
        None,
        "index 10 with length code 255 is the toggle, not a match"
    );
}

#[test]
fn planner_emits_safe_ring_token() {
    let mut input: Vec<_> = (0..80).map(|index| (index * 37 + 11) as u8).collect();
    let pos = input.len();
    input.extend_from_within(pos - 33..pos - 13);

    let mut encoder = Rar15Encoder::new();
    encoder.model.set_recent_for_test([44, 33, 22, 11]);
    let mut index = MatchIndex::new(input.len());
    let token = choose_token(
        &encoder.model,
        encoder.options,
        &input,
        pos,
        &mut index,
        PlanState {
            previous_distance: NONE,
            previous_length: 0,
            recent: [44, 33, 22, 11],
            threshold: 0x2001,
            pref_long: encoder.model.pref_long(),
            pref_literal: encoder.model.pref_literal(),
        },
    )
    .expect("ring candidate should be selected");

    assert_eq!(
        token,
        EncodedToken::Ring(RingMatch {
            distance: 33,
            length: 20,
            index: 11,
        })
    );
}

#[test]
fn encoder_exits_run_mode_when_literal_runs_trigger_it() {
    let input: Vec<_> = (0..96).map(|index| (index * 73 + 19) as u8).collect();
    let packed = encode_rar15(&input).unwrap();

    assert_eq!(decode_rar15(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_run_mode_literals_for_long_literal_runs() {
    let input: Vec<_> = (0..128).map(|index| (index * 73 + 19) as u8).collect();
    let mut encoder = Rar15Encoder::new();
    let packed = encoder.encode_member(&input).unwrap();

    assert!(
        encoder.run_literal_count > 0,
        "long literal runs should use run-mode literals before leaving run mode"
    );
    assert_eq!(decode_rar15(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_options_can_disable_run_mode_literals() {
    let input: Vec<_> = (0..128).map(|index| (index * 73 + 19) as u8).collect();
    let mut encoder =
        Rar15Encoder::with_options(EncodeOptions::new().with_stmode_literal_runs(false));
    let packed = encoder.encode_member(&input).unwrap();

    assert_eq!(encoder.run_literal_count, 0);
    assert_eq!(decode_rar15(&packed, input.len()).unwrap(), input);
}

/// `find_long_match` is the exhaustive oracle two other tests lean on; it has
/// no production caller, so this pins the oracle's own distance bound and
/// says NOTHING about `EncodeOptions::with_max_long_match_distance`. The
/// option's effect is pinned by
/// `long_match_distance_option_bounds_the_distance_a_token_may_carry`
/// below, which is the planner path.
#[test]
fn find_long_match_bounds_its_distance_argument() {
    let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
    input.extend_from_within(..64);

    assert_eq!(find_long_match(&input, 300, 256), None);
    assert_eq!(
        find_long_match(&input, 300, 0x8000),
        Some(LongMatch {
            distance: 300,
            length: 64
        })
    );
}

/// `with_max_long_match_distance` caps the distance the planner's long-match
/// search will look back, and the cap must reach the TOKEN: a round trip
/// cannot see it, because a search that looks further still emits a stream
/// that decodes. So this asserts the token `find_tokens` yields, against
/// values derived from the fixture by hand.
///
/// The fixture plants two copies of a 48-byte needle behind position 4,000:
/// a full one at distance 3,000 and a 32-byte prefix at distance 1,000,
/// each terminated by a byte that cannot extend it. Every other byte is
/// under 0x80 and every needle byte is at or above it, so no filler
/// position can match even three bytes forward from 4,000 - the candidate
/// set is exactly those two, by construction rather than by luck. The
/// finder prefers the longer match and breaks its walk at the first
/// candidate past the cap, so the three rungs are:
///
/// - a cap at or above 3,000 reaches both: distance 3,000, length 48;
/// - a cap of 1,500 reaches only the nearer one: distance 1,000, length 32;
/// - a cap of 500 reaches neither: no long token at all.
///
/// Verified to FAIL on both CAPPED rungs, each on its own, against a setter
/// that drops its argument (`self.max_long_match_distance =
/// MAX_LONG_DISTANCE;`) - the mutation
/// `research/RAR15-PLANNER-CENSUS-2026-09-16.md` gap 3 found the whole
/// suite passing. Each reads back `distance: 3,000, length: 48`, the
/// uncapped answer. The uncapped rung passes under that mutation and must:
/// the mutation makes every rung uncapped, so that rung is the control
/// showing the fixture has a needle at 3,000 to be excluded at all.
#[test]
fn long_match_distance_option_bounds_the_distance_a_token_may_carry() {
    const POS: usize = 4_000;
    let needle: Vec<u8> = (0..48u8)
        .map(|k| 0x80 | (k.wrapping_mul(13) & 0x3f))
        .collect();

    let mut input = Vec::with_capacity(5_000);
    let mut state = 0x1234_5678u32;
    for _ in 0..5_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push(((state >> 24) & 0x7f) as u8);
    }
    // Distance 3,000: the whole needle, then a byte that stops it at 48.
    input[1_000..1_048].copy_from_slice(&needle);
    input[1_048] = 0x01;
    // Distance 1,000: 32 bytes of it, then a byte that stops it at 32.
    input[3_000..3_032].copy_from_slice(&needle[..32]);
    input[3_032] = 0x00;
    input[POS..POS + 48].copy_from_slice(&needle);
    input[POS + 48] = 0x02;

    let long_token = |cap: usize| {
        let mut index = MatchIndex::new(input.len());
        find_tokens(
            &input,
            POS,
            &mut index,
            PlanState {
                previous_distance: NONE,
                previous_length: 0,
                recent: [NONE; 4],
                threshold: 0x1000,
                pref_long: 0,
                pref_literal: 0,
            },
            EncodeOptions::new().with_max_long_match_distance(cap),
        )
        .into_iter()
        .find_map(|token| match token {
            EncodedToken::Long(long) => Some(long),
            _ => None,
        })
    };

    assert_eq!(
        long_token(0x7fff),
        Some(LongMatch {
            distance: 3_000,
            length: 48
        }),
        "an uncapped search takes the longer, further needle"
    );
    assert_eq!(
        long_token(1_500),
        Some(LongMatch {
            distance: 1_000,
            length: 32
        }),
        "a cap of 1,500 must not reach the needle at 3,000"
    );
    assert_eq!(
        long_token(500),
        None,
        "a cap of 500 must not reach either needle"
    );
}

#[test]
fn long_match_search_rejects_unencodable_32k_distance() {
    let mut input = Vec::with_capacity(0x8000 + 64);
    let mut state = 0x1234_5678u32;
    for _ in 0..0x8000 + 64 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 24) as u8);
    }
    let repeated = input[..64].to_vec();
    input[0x8000..0x8000 + 64].copy_from_slice(&repeated);

    let token = find_long_match(&input, 0x8000, 0x8000);

    assert_ne!(token.map(|token| token.distance), Some(0x8000));
}

#[test]
fn lazy_match_prefers_longer_next_position_match() {
    let input = b"abcXbcQRSTabcQRSTUV";
    let mut index = MatchIndex::new(input.len());
    let token = find_token(
        input,
        10,
        &mut index,
        PlanState {
            previous_distance: NONE,
            previous_length: 0,
            recent: [NONE; 4],
            threshold: 0x2001,
            pref_long: 0,
            pref_literal: 0,
        },
        EncodeOptions::default(),
    )
    .unwrap();

    assert!(matches!(
        token,
        EncodedToken::Near(NearMatch { length: 3, .. })
    ));
    assert!(should_lazy_emit_literal(
        input,
        10,
        &mut index,
        token,
        0x2001,
        EncodeOptions::default()
    ));

    let packed = encode_rar15(input).unwrap();
    assert_eq!(decode_rar15(&packed, input.len()).unwrap(), input);
}

#[test]
fn cost_aware_selection_prefers_better_bits_per_byte_token() {
    let mut input = vec![b'Z'; 40];
    input[7] = b'A';
    input[8] = b'A';
    input[9] = b'A';
    input[10] = b'B';
    input[39] = b'A';
    let pos = input.len();
    input.extend_from_slice(b"AAAAAAAAAA");

    let mut encoder = Rar15Encoder::new();
    encoder.model.set_recent_for_test([33, NONE, NONE, NONE]);
    let mut index = MatchIndex::new(input.len());
    let token = choose_token(
        &encoder.model,
        encoder.options,
        &input,
        pos,
        &mut index,
        PlanState {
            previous_distance: NONE,
            previous_length: 0,
            recent: encoder.model.recent(),
            threshold: encoder.model.threshold(),
            pref_long: encoder.model.pref_long(),
            pref_literal: encoder.model.pref_literal(),
        },
    )
    .unwrap();

    assert_eq!(
        token,
        EncodedToken::Near(NearMatch {
            distance: 1,
            length: 10,
        })
    );
}

#[test]
fn planner_uses_the_planned_threshold_for_ring_candidates() {
    let mut state = 0x1234_5678u32;
    let mut input = Vec::with_capacity(9004);
    for _ in 0..9004 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        input.push(state as u8);
    }
    let pos = 9000;
    let prefix = [input[0], input[1], input[2]];
    input[pos..pos + 3].copy_from_slice(&prefix);
    input[pos + 3] = input[3].wrapping_add(1);

    let mut encoder = Rar15Encoder::new();
    encoder.model.set_threshold_for_test(0x7f00);
    encoder.model.set_recent_for_test([9000, NONE, NONE, NONE]);
    let mut index = MatchIndex::new(input.len());
    let token = choose_token(
        &encoder.model,
        encoder.options,
        &input,
        pos,
        &mut index,
        PlanState {
            previous_distance: NONE,
            previous_length: 0,
            recent: [9000, NONE, NONE, NONE],
            threshold: 0x2001,
            pref_long: encoder.model.pref_long(),
            pref_literal: encoder.model.pref_literal(),
        },
    );

    assert_eq!(token, None);
}

#[test]
fn encoder_round_trips_source_shaped_payload() {
    let source = include_bytes!("model.rs");
    let input = &source[..source.len().min(50_902)];

    let packed = encode_rar15(input).unwrap();
    let decoded = decode_rar15(&packed, input.len()).unwrap();

    let first_diff = decoded
        .iter()
        .zip(input)
        .position(|(actual, expected)| actual != expected);
    assert_eq!(first_diff, None, "first differing byte in decoded payload");
    assert_eq!(decoded, input);
}

/// The decoded bytes of `member` in a RAR 1.5-4.x fixture, through the
/// crate's container and the (differentially verified) decoder.
fn rar15_fixture_member(path: &str, member: &str) -> Vec<u8> {
    let full = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    let bytes = std::fs::read(&full).unwrap();
    let archive = crate::rar15_40::Archive::parse(&bytes).unwrap();
    let mut decoder = Rar15Decoder::new();
    for file in archive.files() {
        if file.is_directory() || file.is_stored() || file.unp_ver != 15 {
            continue;
        }
        let packed = file.packed_data(&archive).unwrap();
        let data = decoder
            .decode_member(&packed, file.unp_size as usize, file.is_solid())
            .unwrap();
        if file.name == member.as_bytes() {
            return data;
        }
    }
    panic!("{path}: no member {member}");
}

/// The RAR 1.3 writer's level 3 once packed this member into a stream that
/// decoded to different bytes from 33,379 on: one flag group ended with bit
/// 7 unused.
#[test]
fn level_three_options_round_trip_doc_154_member() {
    let input = rar15_fixture_member("rar15_40/rar154/doc_154_best.rar", "RAR1~FHU.MD");
    let options = EncodeOptions::new()
        .with_old_distance_tokens(false)
        .with_lazy_matching(false)
        .with_max_long_match_distance(16 * 1024);
    assert!(round_trips(&input, options));
}

/// Deterministic text-like input: words from a small vocabulary with
/// back-references, so every item kind and both flag widths appear.
pub(super) fn generated_text(seed: u64, len: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 12] = [
        b"the ",
        b"archive ",
        b"member ",
        b"flag ",
        b"\n",
        b"decoder ",
        b"0123456789",
        b"rank ",
        b"window ",
        b"=",
        b"  ",
        b"RAR 1.5 ",
    ];
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    // Every `%` below is taken in u64 and narrowed afterwards, NEVER
    // `as usize` first. `u64 as usize` KEEPS all 64 bits on a 64-bit
    // target and TRUNCATES to the low 32 on a 32-bit one, so the
    // truncating spelling makes this generator emit a different corpus
    // under `armv7-unknown-linux-musleabihf` - and every expectation
    // baked off it, `literals_only_output_decodes_back_to_its_input`'s
    // (176, 226) counter pair among them, is then asserting about bytes
    // that target never produced. That is what reddened nightly
    // `armv7-cross` on a6b911c35 (run 35501647947): 8784 of 8785 passed
    // and the one failure was this corpus, not the codec. The narrowed
    // form is byte-identical on 64-bit, which is what keeps every other
    // baked figure in this file valid.
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        let r = next();
        if r % 5 == 0 && out.len() > 64 {
            let distance = 1 + (next() % out.len().min(20_000) as u64) as usize;
            let start = out.len() - distance;
            let length = 3 + (next() % 40) as usize;
            for i in 0..length {
                out.push(out[start + i % distance]);
            }
        } else if r % 11 == 1 {
            out.push((next() >> 24) as u8);
        } else {
            out.extend_from_slice(WORDS[((r >> 8) % WORDS.len() as u64) as usize]);
        }
    }
    out.truncate(len);
    out
}

/// `generated_text` is the corpus almost every baked figure in this file
/// hangs off - `literals_only_output_decodes_back_to_its_input`'s (176, 226)
/// counter pair among them - so it must produce the SAME BYTES on every
/// target. It did not until 20 Sep 2026: three `u64 as usize` narrowings
/// kept all 64 bits on a 64-bit target and truncated to the low 32 on a
/// 32-bit one, which moved the corpus under
/// `armv7-unknown-linux-musleabihf` and reddened nightly `armv7-cross`
/// (a6b911c35, run 35501647947) with the counter pair reading (192, 200).
///
/// This test exists so the NEXT such divergence names the corpus instead.
/// A pointer-width break reads as a codec failure otherwise: the run that
/// found it reported one failing test out of 8785, in the RAR 1.3 decoder,
/// with nothing pointing at the generator. Two arms, because the
/// narrowings sit on two paths - the first corpus is short enough that
/// only the WORDS index is reached, and the second is long enough to run
/// the match path's `distance` and `length`.
///
/// To repair after a DELIBERATE generator change: recompute both figures
/// and say in the commit why the corpus moved, because every baked
/// expectation in this file moved with it. Never relax an arm to match a
/// corpus you have not accounted for.
#[test]
fn the_generated_corpus_does_not_depend_on_pointer_width() {
    // Arm 1: 24 bytes, the WORDS-index narrowing only.
    assert_eq!(
        generated_text(7, 24),
        b"  \n\nrank rank   Bflag th".to_vec(),
        "the short corpus moved - suspect a `u64 as usize` narrowing in \
         generated_text, which truncates on a 32-bit target"
    );

    // Arm 2: the match path too, folded rather than spelled out.
    fn fold(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in bytes {
            h = (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
        h
    }
    assert_eq!(
        fold(&generated_text(7, 300)),
        0x9f5e_49b0_aa26_6a5d,
        "the long corpus moved - the match path's `distance`/`length` \
         narrowings are the ones a 32-bit target sees differently"
    );
    assert_eq!(
        fold(&generated_text(100, 160)),
        0x46bf_580d_fdb4_29f1,
        "the 160-byte block corpus moved - long_match_heavy_member() is \
         built out of eight of these, so case 2's counter pair follows it"
    );
}

fn search_option_sets() -> Vec<EncodeOptions> {
    let base = EncodeOptions::new();
    vec![
        base,
        base.with_lazy_matching(false),
        base.with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_max_long_match_distance(16 * 1024),
        base.with_max_long_match_distance(8 * 1024),
        base.with_old_distance_tokens(false),
    ]
}

fn round_trips(input: &[u8], options: EncodeOptions) -> bool {
    let packed = super::encode_rar15_with_options(input, options).unwrap();
    decode_rar15(&packed, input.len()).ok().as_deref() == Some(input)
}

/// The smallest of 4,000 generated inputs that once failed to decode back:
/// a flag group ended with bit 7 unused because a literal flagged `01` did
/// not fit, and the decoder read that unused bit as the next item's first
/// flag bit.
#[test]
fn literal_flag_straddling_two_flag_bytes_round_trips() {
    let input = generated_text(1890, 2926);
    assert!(round_trips(
        &input,
        EncodeOptions::new().with_lazy_matching(false)
    ));
}

/// Every stream decodes back, one-shot and across solid chains, over
/// generated inputs and the option sets the writers use.
#[test]
fn generated_inputs_round_trip_one_shot_and_solid() {
    for seed in 0..120u64 {
        let len = 16 + (seed as usize * 7919) % 6000;
        let input = generated_text(seed, len);
        for options in search_option_sets() {
            assert!(round_trips(&input, options), "seed {seed} {options:?}");
            let mut encoder = Rar15Encoder::with_options(options);
            let mut decoder = Rar15Decoder::new();
            for part in 0..3u64 {
                let member = generated_text(seed * 3 + part + 100_000, 200 + len / 3);
                let packed = encoder.encode_member(&member).unwrap();
                let decoded = decoder.decode_member(&packed, member.len(), part != 0);
                assert_eq!(
                    decoded.ok(),
                    Some(member),
                    "seed {seed} part {part} {options:?}"
                );
            }
        }
    }
}

/// The input `rar15_encode_roundtrip` found from an empty corpus with the
/// flag-straddle fix reverted: one 1,087-byte member, every planner knob off
/// and the long-match distance capped at 9,984. It did not decode back then
/// ("match runs past the member's unpacked size"); the fuzz seed of the same
/// name carries the 3-byte option header in front of these bytes.
#[test]
fn fuzz_found_rar15_encoder_input_round_trips() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40/codec_inputs/encoder_fuzz_found_1087.bin");
    let input = std::fs::read(path).unwrap();
    assert_eq!(input.len(), 1087);
    let options = EncodeOptions::new()
        .with_old_distance_tokens(false)
        .with_lazy_matching(false)
        .with_stmode_literal_runs(false)
        .with_max_long_match_distance(9984);
    assert!(round_trips(&input, options));
}

/// Eight blocks of generated text, then nine of them again in an order that
/// never repeats a distance twice running: every repeat is a long match at a
/// fresh distance, which is what drives `PREF_LONG` up and (through D4's
/// halving) `PREF_LIT` down. The shape is not arbitrary - see
/// [`literals_only_output_decodes_back_to_its_input`], which asserts the exact
/// counter pair it leaves behind.
fn long_match_heavy_member() -> Vec<u8> {
    let blocks: Vec<Vec<u8>> = (0..8u64).map(|k| generated_text(100 + k, 160)).collect();
    let mut data: Vec<u8> = blocks.concat();
    for j in 0..9usize {
        data.extend_from_slice(&blocks[(j * 3 + 1) % 8]);
    }
    data
}

/// `encode_literals_only` emits a real RAR 1.5 stream, not merely a plausible
/// size: it decodes back to its input, on a fresh encoder and as the solid
/// continuation of a member that left the preference counters lopsided.
///
/// NEGATIVE CONTROL. Nothing else in the repository decodes this path's
/// output - its only other caller,
/// `crate::rar13::tests::compressed_writer_emits_long_matches`, reads
/// `.len()` and nothing else, as a size baseline - so each rule below is
/// unconstrained without this test. Each was re-broken and the suite run: in
/// every case the only test to fail was this one, except where noted.
///
/// * The path emitting the input's own bytes. `EncodedToken::Literal(
///   input[pos] ^ 1)` decodes to entirely different bytes; case 1 catches it.
/// * 5.3.3's member reset, `begin_member(true)` written `begin_member(false)`.
///   Invisible on a fresh encoder, whose model is already new, so only case 2
///   catches it: the encoder would start the member from a full reset while
///   the decoder continues solid.
/// * D4's literal-preference rule, `model::literal_preference`, which the
///   planner and `Model::literal_at` now share. Its four constants decide,
///   per literal, whether `PREF_LONG <= PREF_LIT` and so whether the flag is
///   the one-bit or the two-bit form; a planner that chose differently from
///   the decoder would desynchronise the stream. The step written `+= 17`
///   (first wrong flag at literal 3), the ceiling `> 0x7f` (literal 1), the
///   reset `= 0` (literal 5, and this one also reddens
///   `compressed_writer_emits_long_matches`, whose size baseline moves) and
///   the halving deleted (literal 5) were all caught by case 2 when the
///   planner carried its own copy (`plan_literal_preference`, merged away
///   17 Sep 2026) and only that copy could be broken on its own. Breaking the
///   shared function now moves planner and decoder together, so the net is
///   wider: `+= 17` and `> 0x7f` were each re-broken at the merged site and
///   each failed these five, this test among them -
///   `fixture_tests::a_solid_member_on_a_fresh_decoder_decodes_as_non_solid`,
///   `fixture_tests::every_fixture_member_decodes_the_same_through_all_entry_points`,
///   `tests::level_three_options_round_trip_doc_154_member`, this test, and
///   `crate::rar13::tests::solid_writer_packs_member_that_once_did_not_decode_back`.
///   Read the verdict off the failing test NAMES, not off a pass count.
///
/// Case 2's counter pair is load-bearing and is asserted below rather than
/// assumed. A fresh encoder never reaches the flip at all - `PREF_LIT` only
/// ever climbs away from an untouched `PREF_LONG` - so case 1 pins none of the
/// four; and most lopsided pairs pin only three. At `PREF_LIT` 144 /
/// `PREF_LONG` 185, which is what six 200-byte blocks leave, the step written
/// `+= 17` produces the same flag sequence as `+= 16` for 300 literals and the
/// whole suite passes.
#[test]
fn literals_only_output_decodes_back_to_its_input() {
    let literals = generated_text(7, 300);

    // Case 1: a fresh encoder. 300 literals cross D4's 0xff ceiling many
    // times over, run mode included.
    let packed = Rar15Encoder::new().encode_literals_only(&literals).unwrap();
    assert_eq!(
        Rar15Decoder::new()
            .decode_member(&packed, literals.len(), false)
            .ok(),
        Some(literals.clone()),
        "the literals-only stream must decode back to its input"
    );

    // Case 2: the same payload as the solid continuation of a long-match
    // member, so the member opens with PREF_LONG above PREF_LIT and the
    // one-bit/two-bit flip happens inside it.
    let first = long_match_heavy_member();
    let mut encoder = Rar15Encoder::new();
    let packed_first = encoder.encode_member(&first).unwrap();
    assert_eq!(
        (encoder.model.pref_literal(), encoder.model.pref_long()),
        (176, 226),
        "the first member must leave this exact counter pair, or case 2 stops \
         pinning model::literal_preference's constants. To repair: find a first \
         member whose pair makes all four of the mutations in this test's \
         comment change the flag sequence, rather than relaxing this assertion"
    );
    let packed_literals = encoder.encode_literals_only(&literals).unwrap();

    let mut decoder = Rar15Decoder::new();
    assert_eq!(
        decoder
            .decode_member(&packed_first, first.len(), false)
            .ok(),
        Some(first),
        "the long-match member decodes back"
    );
    assert_eq!(
        decoder
            .decode_member(&packed_literals, literals.len(), true)
            .ok(),
        Some(literals),
        "the literals-only stream decodes back as a solid continuation"
    );
}

/// `MatchingWriter` accepts only the bytes it is holding, in order. A
/// writer that took anything would make `Rar15CheckedEncoder`'s decode-back
/// vacuous: the decoder's output would never be compared with the input at
/// all. Negative control: make `write` return `Ok(buf.len())` without the
/// `strip_prefix` check and this test fails on the `unwrap_err` below.
#[test]
fn matching_writer_refuses_bytes_it_is_not_expecting() {
    use std::io::Write;

    let mut writer = MatchingWriter::new(b"RAR 1.5 decodes back");
    writer.write_all(b"RAR 1.5 ").unwrap();
    // A byte that is not next is refused, and refused without consuming it.
    writer.write_all(b"decides").unwrap_err();
    writer.write_all(b"decodes back").unwrap();
    assert!(writer.is_complete());

    // Longer than what is left is a mismatch too, not a short write.
    let mut writer = MatchingWriter::new(b"abc");
    writer.write_all(b"abcd").unwrap_err();
}

/// `is_complete` is the other half of the check: the decoder can write a
/// correct prefix and stop, and only this reports that it did. Negative
/// control: make `is_complete` return `true` unconditionally and the two
/// `assert!(!...)` lines below fail.
#[test]
fn matching_writer_is_complete_only_once_every_byte_is_written() {
    use std::io::Write;

    let mut writer = MatchingWriter::new(b"RAR 1.5 decodes back");
    assert!(!writer.is_complete());
    writer.write_all(b"RAR 1.5 decodes ").unwrap();
    assert!(!writer.is_complete());
    writer.write_all(b"back").unwrap();
    assert!(writer.is_complete());

    // Nothing expected is complete from the start - the empty-member path.
    assert!(MatchingWriter::new(b"").is_complete());
}

/// The refusal path of the safety net itself, on the state its doc comment
/// names: an encoder and a decoder that are out of step. The encoder here
/// has a member behind it and the decoder does not, so the encoder's
/// matches back into that member decode to something else, and the member
/// must not be handed out. Nothing else in the suite ever takes this
/// branch - every other writer test hands the encoder a member that does
/// decode back, so the `None` arm is only reached here.
///
/// Negative control: replace the `then_some` condition with `true` (hand
/// every member out unchecked) and both halves of this test fail - the
/// `is_none` assert, and the `unwrap_err` on the solid form.
#[test]
fn checked_encoder_refuses_a_member_its_decoder_does_not_reproduce() {
    let first = b"RAR 1.5 solid window contents, distinctive enough to match.\n".repeat(16);

    let mut primed = Rar15Encoder::with_options(EncodeOptions::new());
    primed.encode_member(&first).unwrap();

    // The encoder carries `first` in its window; the decoder carries
    // nothing, and `started` will be true because the decoder is present.
    let mut checked = Rar15CheckedEncoder {
        encoder: primed,
        decoder: Some(Rar15Decoder::new()),
    };
    assert!(checked
        .encode_member_with_progress(&first, &mut |_| true)
        .unwrap()
        .is_none());

    let mut primed = Rar15Encoder::with_options(EncodeOptions::new());
    primed.encode_member(&first).unwrap();
    let mut checked = Rar15CheckedEncoder {
        encoder: primed,
        decoder: Some(Rar15Decoder::new()),
    };
    let err = checked
        .encode_solid_member_with_progress(&first, &mut |_| true)
        .unwrap_err();
    assert!(
        matches!(err, crate::codec::Error::InvalidData(_)),
        "{err:?}"
    );
}
