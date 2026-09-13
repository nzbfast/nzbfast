use super::*;

/// Prefix statistics make candidate pricing independent of span length.
/// This counts the same symbols and extra bits as encode_token_block, but
/// emits only the table description until the winning partition is known.
#[derive(Clone)]
pub(super) struct Statistics {
    main: [usize; MAIN_TABLE_SIZE],
    distance: [usize; DISTANCE_TABLE_SIZE_50],
    align: [usize; ALIGN_TABLE_SIZE],
    length: [usize; LENGTH_TABLE_SIZE],
    extra: usize,
}
impl Statistics {
    pub(super) fn empty() -> Self {
        Self {
            main: [0; MAIN_TABLE_SIZE],
            distance: [0; DISTANCE_TABLE_SIZE_50],
            align: [0; ALIGN_TABLE_SIZE],
            length: [0; LENGTH_TABLE_SIZE],
            extra: 0,
        }
    }
    pub(super) fn add(
        &mut self,
        token: EncodeToken,
        data: &[u8],
        state: &mut EncoderMatchState,
    ) -> Result<()> {
        if token.distance == 0 {
            for &b in data {
                self.main[b as usize] += 1;
            }
        } else {
            match state.encode_match(token.length, token.distance, DISTANCE_TABLE_SIZE_50)? {
                EncodedMatch::LastLengthRepeat => self.main[257] += 1,
                EncodedMatch::RepeatDistance {
                    index, length_slot, ..
                } => {
                    self.main[258 + index] += 1;
                    self.length[length_slot] += 1;
                    self.extra += length_slot_extra_bits(length_slot)? as usize;
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
                    self.extra += length_slot_extra_bits(length_slot)? as usize;
                    if distance_bit_count >= 4 {
                        self.align[distance_extra & 15] += 1;
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
    pub(super) fn encoded_size(&self) -> Result<usize> {
        let lengths = TableLengths {
            main: huffman::complete_lengths_for_frequencies(&self.main, 15),
            distance: huffman::complete_lengths_for_frequencies(&self.distance, 15),
            align: huffman::complete_lengths_for_frequencies(&self.align, 15),
            length: huffman::complete_lengths_for_frequencies(&self.length, 15),
        };
        let (_, table_bits) = encode_table_lengths_with_bit_count(&lengths, 0)?;
        let mut bits = table_bits + self.extra;
        for (frequency, lengths) in [
            (&self.main[..], &lengths.main),
            (&self.distance[..], &lengths.distance),
            (&self.align[..], &lengths.align),
            (&self.length[..], &lengths.length),
        ] {
            bits += frequency
                .iter()
                .zip(lengths)
                .map(|(n, l)| n * usize::from(*l))
                .sum::<usize>();
        }
        let payload = bits.div_ceil(8);
        if payload > 0x00ff_ffff {
            return Err(Error::InvalidData("ratio block too large"));
        }
        Ok(payload
            + 2
            + if payload <= 255 {
                1
            } else if payload <= 65535 {
                2
            } else {
                3
            })
    }
}

/// Exact-cost split search. Token decisions and repeat states are fixed, so
/// the cost of an edge is independent of preceding entropy boundaries.
pub(super) fn emit(
    data: &[u8],
    tokens: &[EncodeToken],
    initial: EncoderMatchState,
    policy: Policy,
    last: bool,
) -> Result<Vec<u8>> {
    let baseline = entropy_block_token_ranges(tokens, ENTROPY_BLOCK_BYTES);
    let mut original = Vec::new();
    let mut state = initial;
    let mut pos = 0;
    for range in &baseline {
        let (bytes, next) = encode_token_block(
            data,
            &tokens[range.clone()],
            pos,
            &[],
            0,
            DISTANCE_TABLE_SIZE_50,
            &mut state,
            last && range.end == tokens.len(),
        )?;
        original.extend(bytes);
        pos = next;
    }
    if !policy.adaptive || tokens.len() < 2 {
        return Ok(original);
    }
    let mut offsets = Vec::with_capacity(tokens.len() + 1);
    offsets.push(0usize);
    for token in tokens {
        offsets.push(offsets.last().unwrap() + token.length);
    }
    let mut coarse = grid_points(&offsets, 64 << 10);
    coarse.extend(baseline.iter().map(|r| r.end));
    coarse.sort_unstable();
    coarse.dedup();
    let mut points = coarse.clone();
    if policy.fine || policy.refine {
        points.extend(grid_points(
            &offsets,
            if policy.refine { 4 << 10 } else { 16 << 10 },
        ));
        points.sort_unstable();
        points.dedup();
    }
    let mut states = vec![initial];
    let mut prefix = vec![Statistics::empty()];
    let mut running = Statistics::empty();
    let mut state = initial;
    let mut next_point = 1;
    for (i, token) in tokens.iter().enumerate() {
        running.add(*token, &data[offsets[i]..offsets[i + 1]], &mut state)?;
        if next_point < points.len() && i + 1 == points[next_point] {
            prefix.push(running.clone());
            states.push(state);
            next_point += 1;
        }
    }
    let coarse_search: Vec<_> = coarse
        .iter()
        .map(|p| points.binary_search(p).unwrap())
        .collect();
    let cost = |a: usize, b: usize| prefix[b].difference(&prefix[a]).encoded_size();
    let (mut boundaries, mut best_size) = partition(&coarse_search, &points, &offsets, &cost)?;
    if policy.fine {
        let dense: Vec<_> = (0..points.len()).collect();
        let (candidate, size) = partition(&dense, &points, &offsets, &cost)?;
        if size < best_size {
            boundaries = candidate;
            best_size = size;
        }
    }
    // Also retain the original layout: it may contain >512 KiB spans.
    if best_size >= original.len() {
        if !policy.refine {
            return Ok(original);
        }
        boundaries = vec![0];
        boundaries.extend(
            baseline
                .iter()
                .map(|r| points.binary_search(&r.end).unwrap()),
        );
        best_size = original.len();
    }
    if policy.refine {
        // Coordinate descent changes one boundary at a time using the exact
        // sum of its two adjacent block sizes. Repeat state is independent
        // of table boundaries, so these comparisons are composable.
        for _pass in 0..2 {
            let mut changed = false;
            for i in 1..boundaries.len() - 1 {
                let left = boundaries[i - 1];
                let right = boundaries[i + 1];
                let old = boundaries[i];
                let center = offsets[points[old]];
                let mut best = old;
                let prior = cost(left, old)? + cost(old, right)?;
                let mut smallest = prior;
                for candidate in left + 1..right {
                    if offsets[points[candidate]].abs_diff(center) > 32 << 10 {
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
                    best_size -= prior - smallest;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
    if best_size >= original.len() {
        return Ok(original);
    }
    let mut out = Vec::with_capacity(best_size);
    for pair in boundaries.windows(2) {
        let a = points[pair[0]];
        let b = points[pair[1]];
        let (bytes, _) = encode_token_block(
            data,
            &tokens[a..b],
            offsets[a],
            &[],
            0,
            DISTANCE_TABLE_SIZE_50,
            &mut states[pair[0]],
            last && b == tokens.len(),
        )?;
        out.extend(bytes);
    }
    debug_assert_eq!(out.len(), best_size);
    Ok(out)
}

fn grid_points(offsets: &[usize], spacing: usize) -> Vec<usize> {
    let mut points = vec![0];
    let mut next = spacing;
    for (i, &offset) in offsets.iter().enumerate().skip(1) {
        if offset >= next {
            points.push(i);
            next = offset + spacing;
        }
    }
    points.push(offsets.len() - 1);
    points.sort_unstable();
    points.dedup();
    points
}

fn partition(
    search: &[usize],
    points: &[usize],
    offsets: &[usize],
    cost: &impl Fn(usize, usize) -> Result<usize>,
) -> Result<(Vec<usize>, usize)> {
    let mut costs = vec![usize::MAX; search.len()];
    let mut previous = vec![0; search.len()];
    costs[0] = 0;
    for end in 1..search.len() {
        for begin in (0..end).rev() {
            if begin + 1 < end
                && offsets[points[search[end]]] - offsets[points[search[begin]]] > 512 << 10
            {
                break;
            }
            let size = cost(search[begin], search[end])?;
            if let Some(value) = costs[begin].checked_add(size) {
                if value < costs[end] {
                    costs[end] = value;
                    previous[end] = begin;
                }
            }
        }
    }
    let mut boundaries = vec![*search.last().unwrap()];
    let mut end = search.len() - 1;
    while end != 0 {
        end = previous[end];
        boundaries.push(search[end]);
    }
    boundaries.reverse();
    Ok((boundaries, costs[search.len() - 1]))
}
