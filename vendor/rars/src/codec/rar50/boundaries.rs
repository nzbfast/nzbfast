//! Where one tokenizer block's token stream is cut into entropy blocks.
//!
//! nzbfast-local change, 7 Sep 2026; see VENDORING.md.
//!
//! [`super::entropy_block_token_ranges`] cuts every `ENTROPY_BLOCK_BYTES` of
//! input, which is a guess: the right place for a table boundary is where the
//! symbol distribution actually changes, and a fixed cut lands there only by
//! accident. This module picks the cuts by EXACT encoded cost instead.
//!
//! Token decisions and the rep-distance state are fixed by the tokenizer
//! before this runs, so an entropy block's encoded size depends only on its
//! own tokens - it does not depend on where the boundaries around it fall.
//! That makes the partition a shortest path: prefix histograms of the emitted
//! symbols at every candidate boundary give any block's exact size from two
//! snapshots (`Statistics::difference` then `Statistics::encoded_size`, which
//! count the same symbols, extra bits, table description and block framing the
//! emitter writes), and a shortest path over the candidates picks the cheapest
//! partition. Each boundary is then moved within [`REFINE_WINDOW_BYTES`] on
//! the fine grid by coordinate descent over its two adjacent blocks' exact
//! costs.
//!
//! The fixed layout is priced by the same model and kept as the fallback, so
//! the output is never larger than the fixed cut would have been.
//!
//! [`super::ENTROPY_BLOCK_MIN_TOKENS`], the floor that stops the FIXED cutter
//! spending a table set on a handful of symbols, is deliberately NOT a
//! constraint here, and that is measured rather than assumed. The floor
//! exists because a cutter that counts only input bytes cannot know what a
//! table costs; this search's objective IS the encoded size with the table
//! description in it, so it never buys a table that does not pay for itself.
//! Imposing the floor on top cost real bytes and bought nothing (1 GiB
//! corpora, `rar5cli -m3`, 7 Sep 2026): mixed at a 32 MiB dictionary
//! -0.27% with the floor against -0.76% without, mixed at 128 KiB -0.58%
//! against -1.34%, and the repeated-payload corpus - the very case the floor
//! was added for - came out 919 bytes SMALLER without it, never larger. The
//! reader pays nothing for that: 3,101 blocks become 6,026 on the 1 GiB
//! mixed archive (rar 7.23 writes about 20,600 for the same input) and
//! decode CPU moved 7.93 s to 8.02 s over five passes.
//!
//! Measured on the 1 GiB mixed corpus and the 400-file member sets; the
//! numbers, and the research lane that produced this, are in
//! `research/CODEX-RAR-RATIO-LAB-REVIEW-2026-09-07.md`. The feature-gated
//! `codec::rar50::ratio` lab is where the arms that did NOT ship were tried.

use super::*;
use std::ops::Range;

/// The grid the shortest path runs on. Finer costs O(n^2) edges for
/// boundaries the refinement pass reaches anyway.
const COARSE_GRID_BYTES: usize = 64 << 10;
/// The grid the refinement pass may move a boundary onto.
const FINE_GRID_BYTES: usize = 4 << 10;
/// No entropy block chosen by the shortest path spans more than this. It
/// bounds the edge count, and it keeps one table set from covering a
/// stretch without limit.
const MAX_ENTROPY_SPAN_BYTES: usize = 512 << 10;
/// How far the refinement pass may move one boundary. Wider costs
/// proportionally more and measured no smaller.
const REFINE_WINDOW_BYTES: usize = 32 << 10;
/// Coordinate descent passes. A third measured no smaller on any corpus.
const REFINE_PASSES: usize = 2;

/// One candidate boundary: the token index it cuts at (a match is never
/// split) and the input byte offset there.
#[derive(Clone, Copy)]
struct Point {
    token: usize,
    byte: usize,
}

/// The buffers this search reuses from one block to the next. A 4 KiB grid
/// over a 4 MiB tokenizer block is about a thousand snapshots of ~3.5 KB
/// each, so allocating them per call would be ~3.5 MB of fresh pages per
/// block on every pool worker - the trap [`super::EncoderScratch`] itself
/// exists for.
#[derive(Default)]
pub(super) struct BoundaryScratch {
    prefix: Vec<Statistics>,
    points: Vec<Point>,
    /// Indices into `points`: the coarse grid, which is what the shortest
    /// path searches over.
    coarse: Vec<usize>,
    /// Indices into `points`: the fixed layout's own cuts.
    fixed: Vec<usize>,
}

/// Symbol counts and raw extra bits for a stretch of tokens: the same
/// symbols [`super::encode_token_block`] writes, counted rather than
/// emitted, so a candidate partition can be priced without being encoded.
/// `distance` is sized for the RAR 7 table; a RAR 5 stream leaves the top
/// slots at zero and only `distance_size` of them are ever read.
#[derive(Clone)]
struct Statistics {
    main: [usize; MAIN_TABLE_SIZE],
    distance: [usize; DISTANCE_TABLE_SIZE_70],
    align: [usize; ALIGN_TABLE_SIZE],
    length: [usize; LENGTH_TABLE_SIZE],
    extra: usize,
}

impl Statistics {
    fn empty() -> Self {
        Self {
            main: [0; MAIN_TABLE_SIZE],
            distance: [0; DISTANCE_TABLE_SIZE_70],
            align: [0; ALIGN_TABLE_SIZE],
            length: [0; LENGTH_TABLE_SIZE],
            extra: 0,
        }
    }

    fn add(
        &mut self,
        token: EncodeToken,
        data: &[u8],
        state: &mut EncoderMatchState,
        distance_size: usize,
    ) -> Result<()> {
        if token.distance == 0 {
            for &byte in data {
                self.main[usize::from(byte)] += 1;
            }
        } else {
            match state.encode_match(token.length, token.distance, distance_size)? {
                EncodedMatch::LastLengthRepeat => self.main[257] += 1,
                EncodedMatch::RepeatDistance {
                    index, length_slot, ..
                } => {
                    self.main[258 + index] += 1;
                    self.length[length_slot] += 1;
                    self.extra += usize::from(length_slot_extra_bits(length_slot)?);
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
                    self.extra += usize::from(length_slot_extra_bits(length_slot)?);
                    if distance_bit_count >= 4 {
                        self.align[distance_extra & 0x0f] += 1;
                        self.extra += distance_bit_count - 4;
                    } else {
                        self.extra += distance_bit_count;
                    }
                }
            }
            state.remember(token.length, token.distance);
        }
        Ok(())
    }

    fn difference(&self, earlier: &Self) -> Self {
        Self {
            main: std::array::from_fn(|i| self.main[i] - earlier.main[i]),
            distance: std::array::from_fn(|i| self.distance[i] - earlier.distance[i]),
            align: std::array::from_fn(|i| self.align[i] - earlier.align[i]),
            length: std::array::from_fn(|i| self.length[i] - earlier.length[i]),
            extra: self.extra - earlier.extra,
        }
    }

    /// Exactly the length [`super::encode_token_block`] would return for
    /// these tokens. `filter_symbols` and `filter_bits` are the leading
    /// filter records the FIRST entropy block of a member carries - one
    /// symbol 256 each plus their raw payload - and they go in before the
    /// code lengths are built, because they change the table they are
    /// priced against. The ratio lab's
    /// `statistical_cost_matches_actual_emission` pins this to the emitter,
    /// filters and both distance tables included.
    fn encoded_size(
        &self,
        distance_size: usize,
        algorithm_version: u8,
        filter_symbols: usize,
        filter_bits: usize,
    ) -> Result<usize> {
        let mut main = self.main;
        main[256] += filter_symbols;
        let lengths = TableLengths {
            main: huffman::complete_lengths_for_frequencies(&main, 15),
            distance: huffman::complete_lengths_for_frequencies(
                &self.distance[..distance_size],
                15,
            ),
            align: huffman::complete_lengths_for_frequencies(&self.align, 15),
            length: huffman::complete_lengths_for_frequencies(&self.length, 15),
        };
        let (_, table_bits) = encode_table_lengths_with_bit_count(&lengths, algorithm_version)?;
        let mut bits = table_bits + self.extra + filter_bits;
        for (frequencies, code_lengths) in [
            (&main[..], &lengths.main),
            (&self.distance[..distance_size], &lengths.distance),
            (&self.align[..], &lengths.align),
            (&self.length[..], &lengths.length),
        ] {
            bits += frequencies
                .iter()
                .zip(code_lengths)
                .map(|(count, len)| count * usize::from(*len))
                .sum::<usize>();
        }
        let payload = bits.div_ceil(8);
        if payload > 0x00ff_ffff {
            return Err(Error::InvalidData("RAR 5 block payload is too large"));
        }
        // Flags, checksum and the 1-3 byte size field the framing writes.
        Ok(payload
            + 2
            + if payload <= 0xff {
                1
            } else if payload <= 0xffff {
                2
            } else {
                3
            })
    }
}

/// The bits `write_filter` will spend on these records, measured by writing
/// them rather than by a second copy of the field widths - the two would
/// drift.
/// The payload bits of one record as the emitter writes it: an offset
/// from `position`, the start of the token it is written before.
fn filter_record_bits(filter: EncodeFilter, position: usize) -> Result<usize> {
    let mut writer = BitWriter::new();
    write_filter(
        &mut writer,
        EncodeFilter {
            offset: filter.offset.saturating_sub(position),
            ..filter
        },
    )?;
    Ok(writer.bit_pos)
}

/// The payload bits of `filters` as `tokens` will carry them.
fn filter_payload_bits(tokens: &[EncodeToken], filters: &[EncodeFilter]) -> Result<usize> {
    filter_token_indices(tokens, filters)
        .iter()
        .zip(filters)
        .map(|(&(_, position), &filter)| filter_record_bits(filter, position))
        .sum()
}

/// One tokenizer block's tokens as a run of RAR 5 compressed blocks, cut
/// where the exact encoded cost says to cut. Never larger than the fixed
/// cut: that layout is priced by the same model and emitted instead when
/// the search does not beat it.
#[allow(clippy::too_many_arguments)]
pub(super) fn encode_token_blocks_adaptive(
    data: &[u8],
    tokens: &[EncodeToken],
    initial_filters: &[EncodeFilter],
    algorithm_version: u8,
    distance_size: usize,
    is_last: bool,
    target_bytes: usize,
    scratch: &mut BoundaryScratch,
) -> Result<Vec<u8>> {
    let fixed_ranges = entropy_block_token_ranges(tokens, target_bytes);
    let emit = |ranges: &[Range<usize>]| {
        emit_entropy_blocks(
            data,
            tokens,
            ranges,
            initial_filters,
            algorithm_version,
            distance_size,
            is_last,
        )
    };
    if tokens.len() < 2 {
        return emit(&fixed_ranges);
    }

    build_points(tokens, &fixed_ranges, scratch);
    build_prefix(data, tokens, distance_size, scratch)?;

    // Each record is charged to the block whose tokens reach it (the last
    // block takes any past the final token), as the emitter writes them.
    let at_token = filter_token_indices(tokens, initial_filters);
    let filter_bits: Vec<usize> = initial_filters
        .iter()
        .zip(&at_token)
        .map(|(&filter, &(_, position))| filter_record_bits(filter, position))
        .collect::<Result<_>>()?;
    let prefix = &scratch.prefix;
    let points = &scratch.points;
    // `a` and `b` index the candidate points; the records are placed by
    // token, as the emitter places them.
    let cost = |a: usize, b: usize| -> Result<usize> {
        let (first, end) = (points[a].token, points[b].token);
        let mut symbols = 0usize;
        let mut bits = 0usize;
        for (&(token, _), &record_bits) in at_token.iter().zip(&filter_bits) {
            if token >= first && (token < end || (end == tokens.len() && token >= end)) {
                symbols += 1;
                bits += record_bits;
            }
        }
        prefix[b].difference(&prefix[a]).encoded_size(
            distance_size,
            algorithm_version,
            symbols,
            bits,
        )
    };

    // The fixed layout, priced rather than encoded: it is the fallback and
    // the number every candidate has to beat, and encoding it to find out
    // would double the emit work on every block.
    let mut fixed_size = 0usize;
    for pair in scratch.fixed.windows(2) {
        fixed_size += cost(pair[0], pair[1])?;
    }

    let (mut boundaries, mut best_size) = match shortest_path(&scratch.coarse, points, &cost)? {
        Some(found) if found.1 < fixed_size => found,
        // The fixed layout is the starting point when it wins outright; the
        // refinement pass still gets to move its boundaries.
        _ => (scratch.fixed.clone(), fixed_size),
    };

    refine(&mut boundaries, &mut best_size, points, &cost)?;

    if best_size >= fixed_size {
        return emit(&fixed_ranges);
    }
    let out = emit(&boundary_ranges(&boundaries, points))?;
    debug_assert_eq!(out.len(), best_size);
    if out.len() > fixed_size {
        // Unreachable while the cost model matches the emitter, which the
        // ratio lab's `statistical_cost_matches_actual_emission` pins. The
        // fallback is here so that a model which ever stopped matching
        // would cost time nobody measures rather than bytes the fixed cut
        // would not have spent.
        return emit(&fixed_ranges);
    }
    Ok(out)
}

/// The candidate boundaries: the fine grid, the coarse grid, and every cut
/// the fixed layout makes (so that layout is always expressible here). One
/// pass over the tokens builds all three.
fn build_points(
    tokens: &[EncodeToken],
    fixed_ranges: &[Range<usize>],
    scratch: &mut BoundaryScratch,
) {
    scratch.points.clear();
    scratch.coarse.clear();
    scratch.fixed.clear();
    scratch.points.push(Point { token: 0, byte: 0 });
    scratch.coarse.push(0);
    scratch.fixed.push(0);

    let mut next_coarse = COARSE_GRID_BYTES;
    let mut next_fine = FINE_GRID_BYTES;
    let mut next_fixed = 0usize;
    let mut byte = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        byte += token.length;
        let token_index = index + 1;
        let on_coarse = byte >= next_coarse;
        if on_coarse {
            next_coarse = byte + COARSE_GRID_BYTES;
        }
        let on_fine = byte >= next_fine;
        if on_fine {
            next_fine = byte + FINE_GRID_BYTES;
        }
        let on_fixed =
            next_fixed < fixed_ranges.len() && fixed_ranges[next_fixed].end == token_index;
        // The final boundary is pushed once, below, whichever grids reach it.
        if token_index == tokens.len() || !(on_coarse || on_fine || on_fixed) {
            continue;
        }
        scratch.points.push(Point {
            token: token_index,
            byte,
        });
        if on_coarse || on_fixed {
            scratch.coarse.push(scratch.points.len() - 1);
        }
        if on_fixed {
            scratch.fixed.push(scratch.points.len() - 1);
            next_fixed += 1;
        }
    }
    scratch.points.push(Point {
        token: tokens.len(),
        byte,
    });
    scratch.coarse.push(scratch.points.len() - 1);
    scratch.fixed.push(scratch.points.len() - 1);
}

/// Symbol counts for `tokens[..points[i].token]` at every candidate.
/// `clear` keeps the allocation, so the snapshots are written over the
/// previous block's.
fn build_prefix(
    data: &[u8],
    tokens: &[EncodeToken],
    distance_size: usize,
    scratch: &mut BoundaryScratch,
) -> Result<()> {
    scratch.prefix.clear();
    scratch.prefix.push(Statistics::empty());
    let mut running = Statistics::empty();
    let mut state = EncoderMatchState::default();
    let mut next = 1usize;
    let mut byte = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        running.add(
            *token,
            &data[byte..byte + token.length],
            &mut state,
            distance_size,
        )?;
        byte += token.length;
        if next < scratch.points.len() && index + 1 == scratch.points[next].token {
            scratch.prefix.push(running.clone());
            next += 1;
        }
    }
    Ok(())
}

/// Cheapest partition over the coarse candidates. `None` only if some
/// future constraint leaves no path; the caller then keeps the fixed cut.
fn shortest_path(
    coarse: &[usize],
    points: &[Point],
    cost: &impl Fn(usize, usize) -> Result<usize>,
) -> Result<Option<(Vec<usize>, usize)>> {
    let mut costs = vec![usize::MAX; coarse.len()];
    let mut previous = vec![0usize; coarse.len()];
    costs[0] = 0;
    for end in 1..coarse.len() {
        for begin in (0..end).rev() {
            if begin + 1 < end
                && points[coarse[end]].byte - points[coarse[begin]].byte > MAX_ENTROPY_SPAN_BYTES
            {
                break;
            }
            if costs[begin] == usize::MAX {
                continue;
            }
            let size = cost(coarse[begin], coarse[end])?;
            if let Some(value) = costs[begin].checked_add(size) {
                if value < costs[end] {
                    costs[end] = value;
                    previous[end] = begin;
                }
            }
        }
    }
    let total = costs[coarse.len() - 1];
    if total == usize::MAX {
        return Ok(None);
    }
    let mut boundaries = vec![*coarse.last().unwrap()];
    let mut end = coarse.len() - 1;
    while end != 0 {
        end = previous[end];
        boundaries.push(coarse[end]);
    }
    boundaries.reverse();
    Ok(Some((boundaries, total)))
}

/// Coordinate descent: one boundary at a time, on the fine grid, within
/// [`REFINE_WINDOW_BYTES`] of where it is, scored by the exact sum of its
/// two adjacent blocks. The rep state a block starts from does not depend
/// on the boundaries around it, so these comparisons compose.
fn refine(
    boundaries: &mut [usize],
    best_size: &mut usize,
    points: &[Point],
    cost: &impl Fn(usize, usize) -> Result<usize>,
) -> Result<()> {
    if boundaries.len() < 3 {
        return Ok(());
    }
    for _pass in 0..REFINE_PASSES {
        let mut changed = false;
        for i in 1..boundaries.len() - 1 {
            let left = boundaries[i - 1];
            let right = boundaries[i + 1];
            let old = boundaries[i];
            let center = points[old].byte;
            let prior = cost(left, old)? + cost(old, right)?;
            let mut smallest = prior;
            let mut best = old;
            for candidate in left + 1..right {
                if points[candidate].byte.abs_diff(center) > REFINE_WINDOW_BYTES {
                    continue;
                }
                let value = cost(left, candidate)? + cost(candidate, right)?;
                if value < smallest {
                    smallest = value;
                    best = candidate;
                }
            }
            if best != old {
                boundaries[i] = best;
                *best_size -= prior - smallest;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

fn boundary_ranges(boundaries: &[usize], points: &[Point]) -> Vec<Range<usize>> {
    boundaries
        .windows(2)
        .map(|pair| points[pair[0]].token..points[pair[1]].token)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text, a repeat, and an incompressible stretch: three distributions
    /// in one payload, which is what a boundary search is for.
    fn payload(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        while out.len() < len {
            let phase = (out.len() / 4096) % 3;
            match phase {
                0 => out.extend_from_slice(b"the quick brown fox jumps over the lazy dog. "),
                1 => out.extend_from_slice(&[0x41u8; 64]),
                _ => {
                    for _ in 0..64 {
                        seed = seed
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        out.push((seed >> 33) as u8);
                    }
                }
            }
        }
        out.truncate(len);
        out
    }

    /// Short matches from a small vocabulary: many tokens per input byte,
    /// which is where the boundary search has cuts to choose between (the
    /// long-match payload above has a few hundred tokens per megabyte and
    /// the token floor leaves it one block, on purpose).
    fn token_dense(len: usize) -> Vec<u8> {
        let vocabulary: Vec<[u8; 24]> = (0..64u8)
            .map(|i| std::array::from_fn(|j| b'a' + ((i as usize * 7 + j * 5) % 26) as u8))
            .collect();
        let mut out = Vec::with_capacity(len + 24);
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        while out.len() < len {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(&vocabulary[(seed >> 40) as usize % vocabulary.len()]);
        }
        out.truncate(len);
        out
    }

    fn statistics_for(
        data: &[u8],
        tokens: &[EncodeToken],
        distance_size: usize,
    ) -> Result<Statistics> {
        let mut stats = Statistics::empty();
        let mut state = EncoderMatchState::default();
        let mut pos = 0usize;
        for token in tokens {
            stats.add(
                *token,
                &data[pos..pos + token.length],
                &mut state,
                distance_size,
            )?;
            pos += token.length;
        }
        Ok(stats)
    }

    /// The one property everything here rests on: the price the search puts
    /// on a stretch of tokens is the length the emitter actually writes for
    /// it, filters and both distance tables included. The lab's own copy of
    /// this test pins the lab's cost model; this one pins production's.
    #[test]
    fn statistical_cost_matches_actual_emission() {
        let filter_sets: [Vec<EncodeFilter>; 3] = [
            Vec::new(),
            vec![EncodeFilter {
                offset: 0,
                length: 4096,
                filter_type: FilterType::E8E9,
                channels: 0,
            }],
            vec![
                EncodeFilter {
                    offset: 17,
                    length: 300_000,
                    filter_type: FilterType::Delta,
                    channels: 3,
                },
                EncodeFilter {
                    offset: 70_000,
                    length: 64,
                    filter_type: FilterType::Arm,
                    channels: 0,
                },
            ],
        ];
        for (algorithm_version, distance_size) in
            [(0u8, DISTANCE_TABLE_SIZE_50), (1u8, DISTANCE_TABLE_SIZE_70)]
        {
            for n in [0usize, 1, 2, 100, 65536, 300_000] {
                let data = payload(n);
                let options = EncodeOptions::default();
                let tokens = encode_tokens(&data, &[], options, distance_size);
                let stats = statistics_for(&data, &tokens, distance_size).unwrap();
                for filters in &filter_sets {
                    let (actual, _) = encode_token_block(
                        &data,
                        &tokens,
                        0,
                        filters,
                        algorithm_version,
                        distance_size,
                        &mut EncoderMatchState::default(),
                        true,
                    )
                    .unwrap();
                    let priced = stats
                        .encoded_size(
                            distance_size,
                            algorithm_version,
                            filters.len(),
                            filter_payload_bits(&tokens, filters).unwrap(),
                        )
                        .unwrap();
                    assert_eq!(priced, actual.len(), "n={n} v={algorithm_version}");
                }
            }
        }
    }

    /// The search never spends more than the fixed cut would have, and what
    /// it writes still decodes to the input.
    #[test]
    fn adaptive_boundaries_never_grow_and_round_trip() {
        for (dense, n) in [
            (false, 0usize),
            (false, 1),
            (false, 4096),
            (false, 300_000),
            (false, 1_100_000),
            (true, 300_000),
            (true, 1_100_000),
        ] {
            let data = if dense { token_dense(n) } else { payload(n) };
            let adaptive = EncodeOptions::default();
            let fixed = EncodeOptions::default().with_adaptive_entropy_blocks(false);
            for algorithm_version in [0u8, 1u8] {
                let small =
                    encode_lz_member_with_options(&data, algorithm_version, adaptive).unwrap();
                let plain = encode_lz_member_with_options(&data, algorithm_version, fixed).unwrap();
                assert!(
                    small.len() <= plain.len(),
                    "n={n} v={algorithm_version}: {} > {}",
                    small.len(),
                    plain.len()
                );
                assert_eq!(
                    decode_lz(&small, algorithm_version, data.len()).unwrap(),
                    data,
                    "n={n} v={algorithm_version}"
                );
            }
        }
    }

    /// The switch off is the fixed cut, byte for byte - the property the
    /// fixtures that pin archive bytes rely on.
    #[test]
    fn switch_off_is_the_fixed_cut() {
        let data = payload(900_000);
        let options = EncodeOptions::default().with_adaptive_entropy_blocks(false);
        let tokens = encode_tokens(&data, &[], options, DISTANCE_TABLE_SIZE_50);
        let mut scratch = BoundaryScratch::default();
        let dispatched = encode_token_blocks(
            &data,
            &tokens,
            &[],
            0,
            DISTANCE_TABLE_SIZE_50,
            true,
            ENTROPY_BLOCK_BYTES,
            options,
            &mut scratch,
        )
        .unwrap();
        let direct = emit_entropy_blocks(
            &data,
            &tokens,
            &entropy_block_token_ranges(&tokens, ENTROPY_BLOCK_BYTES),
            &[],
            0,
            DISTANCE_TABLE_SIZE_50,
            true,
        )
        .unwrap();
        assert_eq!(dispatched, direct);
    }

    /// The search cuts where the fixed layout does not, the partition it
    /// reports the price of is the partition it emits, and that price is
    /// what the emitter actually writes.
    #[test]
    fn the_chosen_partition_costs_what_the_search_says() {
        let data = token_dense(2_000_000);
        let options = EncodeOptions::default();
        let tokens = encode_tokens(&data, &[], options, DISTANCE_TABLE_SIZE_50);
        let mut scratch = BoundaryScratch::default();
        let fixed_ranges = entropy_block_token_ranges(&tokens, ENTROPY_BLOCK_BYTES);
        build_points(&tokens, &fixed_ranges, &mut scratch);
        build_prefix(&data, &tokens, DISTANCE_TABLE_SIZE_50, &mut scratch).unwrap();
        let prefix = &scratch.prefix;
        let cost = |a: usize, b: usize| -> Result<usize> {
            prefix[b]
                .difference(&prefix[a])
                .encoded_size(DISTANCE_TABLE_SIZE_50, 0, 0, 0)
        };
        let (mut boundaries, mut size) = shortest_path(&scratch.coarse, &scratch.points, &cost)
            .unwrap()
            .expect("a feasible partition on mixed data");
        refine(&mut boundaries, &mut size, &scratch.points, &cost).unwrap();
        assert!(boundaries.len() > 2, "the search found no cuts to make");
        assert_ne!(
            boundaries, scratch.fixed,
            "the search chose the fixed layout, so it is testing nothing"
        );
        let emitted = emit_entropy_blocks(
            &data,
            &tokens,
            &boundary_ranges(&boundaries, &scratch.points),
            &[],
            0,
            DISTANCE_TABLE_SIZE_50,
            true,
        )
        .unwrap();
        assert_eq!(emitted.len(), size);
    }
}
