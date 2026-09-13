//! Isolated ratio experiments using the existing RAR5 token emitter.
//! Feature gated; no production defaults or writer paths are changed.
use super::*;
mod adaptive;
mod filtered;
use adaptive::emit;
#[cfg(test)]
use adaptive::Statistics;
pub use filtered::FilteredEncoder;

/// Each switch can be measured independently. This is a research API.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    pub short_repeats: bool,
    pub adaptive: bool,
    pub carry: bool,
    pub exhaustive: bool,
    pub fine: bool,
    pub refine: bool,
}

/// Serial experimental encoder, optionally retaining state across solid members.
#[derive(Clone)]
pub struct Encoder {
    tokenizer_block_size: usize,
    options: EncodeOptions,
    policy: Policy,
    history: Vec<u8>,
    state: EncoderMatchState,
    tree_enabled: bool,
    tree_nice_length: usize,
    tree_distances: Option<std::sync::Arc<Vec<std::sync::atomic::AtomicU32>>>,
    tree_offset: usize,
}
impl Encoder {
    pub fn new(dictionary: usize, policy: Policy) -> Self {
        Self {
            tokenizer_block_size: MAX_COMPRESSED_BLOCK_OUTPUT,
            options: EncodeOptions::new(256)
                .with_lazy_matching(true)
                .with_max_match_distance(dictionary),
            policy,
            history: Vec::new(),
            state: EncoderMatchState::default(),
            tree_enabled: false,
            tree_nice_length: tree::TREE_NICE_LENGTH,
            tree_distances: None,
            tree_offset: 0,
        }
    }
    /// Change the tokenization horizon independently of entropy-block emission.
    /// Experimental only. Existing callers retain the original 4 MiB horizon.
    pub fn with_tokenizer_block_size(mut self, bytes: usize) -> Result<Self> {
        if bytes == 0 || bytes > MAX_COMPRESSED_BLOCK_OUTPUT {
            return Err(Error::InvalidData("invalid ratio-lab tokenizer block size"));
        }
        self.tokenizer_block_size = bytes;
        Ok(self)
    }
    /// Use the production optimal token walker, then the lab's chosen emitter.
    /// Its initial repeat state is empty; carry and lazy-only overrides cannot
    /// be combined with it without changing the parser's contract.
    pub fn with_optimal_parse(mut self, enabled: bool) -> Result<Self> {
        if enabled && (self.policy.carry || self.policy.short_repeats || self.policy.exhaustive) {
            return Err(Error::InvalidData(
                "optimal lab parse rejects lazy-only policies",
            ));
        }
        self.options = self.options.with_optimal_parse(enabled);
        Ok(self)
    }
    /// Build one immutable hint span per member, shared by every horizon trial.
    /// The fixed 4 MiB finder grid is independent of the chosen tokenizer spans.
    pub fn with_tree_search(mut self, enabled: bool) -> Self {
        self.tree_enabled = enabled;
        self
    }

    /// Bound how many matching bytes the tree compares before accepting a hint.
    /// This changes candidate ranking, not the emitted match-length limit.
    pub fn with_tree_nice_length(mut self, bytes: usize) -> Result<Self> {
        if !(4..=256).contains(&bytes) {
            return Err(Error::InvalidData(
                "invalid ratio-lab tree comparison length",
            ));
        }
        self.tree_nice_length = bytes;
        Ok(self)
    }

    fn prepare_tree(&mut self, data: &[u8], solid: bool) {
        self.tree_distances = None;
        self.tree_offset = 0;
        if !self.tree_enabled
            || data.is_empty()
            || self.options.max_match_distance < TREE_MIN_DICTIONARY
            || self.options.max_match_candidates == 0
        {
            return;
        }
        let history = if solid { self.history.as_slice() } else { &[] };
        if !TreeMatchFinder::fits(
            data.len()
                .saturating_add(history.len().min(tree::TREE_MAX_WINDOW)),
        ) {
            return;
        }
        let mut finder = TreeMatchFinder::new(self.options.max_match_distance)
            .with_nice_length(self.tree_nice_length);
        let history = &history[history.len().saturating_sub(finder.window())..];
        let mut span = Vec::with_capacity(history.len() + data.len());
        span.extend_from_slice(history);
        span.extend_from_slice(data);
        for start in (0..history.len()).step_by(MAX_COMPRESSED_BLOCK_OUTPUT) {
            finder.advance_range(
                &span,
                start..(start + MAX_COMPRESSED_BLOCK_OUTPUT).min(history.len()),
                None,
                1,
                1,
            );
        }
        // ONE slot per position, which is the lab's shape and not an
        // oversight: the production parse asks the finder for a frontier
        // of `TREE_CANDIDATE_SLOTS` (7 Sep 2026) and takes it instead of
        // the ring walk, while a stride of one keeps the ring walk with
        // this hint merged into it - so the lab's recorded arms stay
        // comparable with the ones already published. Widening it is the
        // lab's own measurement to make.
        let distances = empty_slots(data.len());
        for start in (0..data.len()).step_by(MAX_COMPRESSED_BLOCK_OUTPUT) {
            let end = (start + MAX_COMPRESSED_BLOCK_OUTPUT).min(data.len());
            finder.advance_range(
                &span,
                history.len() + start..history.len() + end,
                Some(&distances[start..end]),
                1,
                1,
            );
        }
        self.tree_distances = Some(std::sync::Arc::new(distances));
    }

    pub fn encode(&mut self, data: &[u8], solid: bool) -> Result<Vec<u8>> {
        self.prepare_tree(data, solid);
        let result = self.encode_part(data, solid, true);
        self.tree_distances = None;
        result
    }

    /// Compare 4 MiB and 256 KiB tokenizer horizons for each 4 MiB region.
    /// No filters and no carried rep state: both candidates leave identical
    /// raw history for the next region, so local byte improvements compose.
    pub fn encode_adaptive_horizon(&mut self, data: &[u8], solid: bool) -> Result<Vec<u8>> {
        self.encode_horizons(data, solid, &[MAX_COMPRESSED_BLOCK_OUTPUT, 256 * 1024])
    }

    /// Extend the two-horizon comparison with 1 MiB and 512 KiB candidates.
    /// Every horizon divides the region size and preserves the same raw history.
    pub fn encode_wide_horizon(&mut self, data: &[u8], solid: bool) -> Result<Vec<u8>> {
        self.encode_horizons(
            data,
            solid,
            &[
                MAX_COMPRESSED_BLOCK_OUTPUT,
                256 * 1024,
                1024 * 1024,
                512 * 1024,
            ],
        )
    }

    /// Complete the power-of-two horizon experiment from 64 KiB to 4 MiB.
    /// Expensive research option; the existing four choices remain candidates.
    pub fn encode_seven_horizon(&mut self, data: &[u8], solid: bool) -> Result<Vec<u8>> {
        self.encode_horizons(
            data,
            solid,
            &[
                MAX_COMPRESSED_BLOCK_OUTPUT,
                256 * 1024,
                1024 * 1024,
                512 * 1024,
                2048 * 1024,
                128 * 1024,
                64 * 1024,
            ],
        )
    }

    /// Lower-work alternative comparing 4 MiB and 1 MiB tokenizer spans.
    pub fn encode_balanced_horizon(&mut self, data: &[u8], solid: bool) -> Result<Vec<u8>> {
        self.encode_horizons(data, solid, &[MAX_COMPRESSED_BLOCK_OUTPUT, 1024 * 1024])
    }

    fn encode_horizons(&mut self, data: &[u8], solid: bool, sizes: &[usize]) -> Result<Vec<u8>> {
        if self.policy.carry {
            return Err(Error::InvalidData(
                "adaptive horizon requires reset rep state",
            ));
        }
        if data.is_empty() {
            return self.encode(data, solid);
        }
        self.prepare_tree(data, solid);
        let result = (|| {
            let configured_size = self.tokenizer_block_size;
            let mut out = Vec::new();
            let count = data.len().div_ceil(MAX_COMPRESSED_BLOCK_OUTPUT);
            for (i, chunk) in data.chunks(MAX_COMPRESSED_BLOCK_OUTPUT).enumerate() {
                let mut best: Option<(Vec<u8>, Self)> = None;
                for (choice, &size) in sizes.iter().enumerate() {
                    // Spans at least as large as this tail all encode the same
                    // single chunk: same history, index shape, tokens and emit.
                    // Retain the first on ties, just as the exhaustive trials did.
                    if sizes[..choice]
                        .iter()
                        .any(|&prior| prior.min(chunk.len()) == size.min(chunk.len()))
                    {
                        continue;
                    }
                    let mut candidate = self.clone();
                    candidate.tokenizer_block_size = size;
                    let packed = candidate.encode_part(chunk, solid || i != 0, i + 1 == count)?;
                    if best
                        .as_ref()
                        .is_none_or(|(bytes, _)| packed.len() < bytes.len())
                    {
                        best = Some((packed, candidate));
                    }
                }
                let (packed, winner) = best.unwrap();
                out.extend(packed);
                *self = winner;
            }
            self.tokenizer_block_size = configured_size;
            Ok(out)
        })();
        self.tree_distances = None;
        result
    }

    fn encode_part(&mut self, data: &[u8], solid: bool, last: bool) -> Result<Vec<u8>> {
        if !solid {
            self.history.clear();
            self.state = EncoderMatchState::default();
        }
        let mut out = Vec::new();
        // Empty files still need a valid final block.
        let count = data.len().max(1).div_ceil(self.tokenizer_block_size);
        let mut combined = Vec::new();
        for block in 0..count {
            let begin = block * self.tokenizer_block_size;
            let chunk = &data[begin..data.len().min(begin + self.tokenizer_block_size)];
            combined.clear();
            combined.extend_from_slice(&self.history);
            combined.extend_from_slice(chunk);
            let mut index =
                MatchIndex::<usize>::new(combined.len(), self.options.max_match_candidates);
            index.seed_history(&combined, self.history.len(), None);
            let initial = if self.policy.carry {
                self.state
            } else {
                EncoderMatchState::default()
            };
            let hints = self.tree_distances.as_ref().map_or(&[][..], |distances| {
                &distances[self.tree_offset..self.tree_offset + chunk.len()]
            });
            let tree = if hints.is_empty() {
                TreeMatches::none()
            } else {
                TreeMatches {
                    base: self.history.len(),
                    distances: hints,
                    // One slot per position: see `prepare_tree`. This is
                    // the ring walk with the hint merged into it, which is
                    // the shape the lab's published arms were measured on.
                    stride: 1,
                }
            };
            let (tokens, final_state) = if self.options.optimal_parse {
                let (tokens, _) = walk_tokens_optimal(
                    &combined,
                    self.history.len(),
                    combined.len(),
                    self.options,
                    DISTANCE_TABLE_SIZE_50,
                    None,
                    index,
                    Vec::new(),
                    tree,
                )?;
                // Carry is rejected above. Emission and the next parse both
                // use their own empty initial rep model, never this value.
                (tokens, EncoderMatchState::default())
            } else {
                walk_ratio_tokens(
                    &combined,
                    self.history.len(),
                    combined.len(),
                    self.options,
                    DISTANCE_TABLE_SIZE_50,
                    None,
                    index,
                    Vec::new(),
                    initial,
                    self.policy,
                    tree,
                )?
            };
            let bytes = emit(
                chunk,
                &tokens,
                initial,
                self.policy,
                last && block + 1 == count,
            )?;
            out.extend(bytes);
            self.tree_offset += chunk.len();
            self.state = final_state;
            self.history.extend_from_slice(chunk);
            let discard = self
                .history
                .len()
                .saturating_sub(self.options.max_match_distance);
            if discard != 0 {
                self.history.drain(..discard);
            }
        }
        Ok(out)
    }
}

#[allow(clippy::too_many_arguments)]
fn ratio_probe<P: MatchPosition>(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &MatchIndex<P>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    prices: &LiteralPrices,
    policy: Policy,
    tree: TreeMatches<'_>,
) -> (Option<MatchCandidate>, bool) {
    let (mut best, mut saw) = best_match_probe(
        input,
        pos,
        end,
        buckets,
        options,
        state,
        distance_size,
        prices,
        tree,
    );
    if policy.short_repeats && options.max_match_candidates != 0 {
        for distance in state.reps {
            if distance == 0 || distance > pos.min(options.max_match_distance) {
                continue;
            }
            let length = match_length(input, pos, distance, (end - pos).min(3));
            if length < 2 {
                continue;
            }
            saw = true;
            let cost = estimated_match_cost(state, length, distance, distance_size).unwrap();
            let literal = prices.bits(pos, length);
            if cost < literal {
                let candidate = MatchCandidate {
                    length,
                    distance,
                    cost,
                    score: (literal - cost) as isize,
                };
                if best.is_none_or(|b| candidate.score > b.score) {
                    best = Some(candidate);
                }
            }
        }
    }
    (best, saw)
}

#[allow(clippy::too_many_arguments)]
fn walk_ratio_tokens<P: MatchPosition>(
    combined: &[u8],
    start: usize,
    end: usize,
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    mut buckets: MatchIndex<P>,
    mut tokens: Vec<EncodeToken>,
    mut state: EncoderMatchState,
    policy: Policy,
    tree: TreeMatches<'_>,
) -> Result<(Vec<EncodeToken>, EncoderMatchState)> {
    let input = &combined[start..end];

    let mut pos = start;
    let mut next_report = 0usize;
    let mut literal_run = 0usize;
    // The lazy parser's probe at `pos + 1` is the search the next iteration
    // would run from scratch when it defers, so it is kept: `probed` is
    // `Some(best_match(pos))` when the previous iteration already computed
    // it. The position deferred over is inserted BEFORE the probe, so the
    // probe sees exactly what the fresh search would have (the old order
    // inserted it after, and the fresh search saw one candidate more).
    // (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
    let prices = LiteralPrices::new(input, start);
    let mut probed: Option<(Option<MatchCandidate>, bool)> = None;
    while pos < end {
        let (candidate, saw_prefix_match) = match probed.take() {
            Some(probe) => probe,
            None => ratio_probe(
                combined,
                pos,
                end,
                &buckets,
                options,
                &state,
                distance_size,
                &prices,
                policy,
                tree,
            ),
        };
        if saw_prefix_match {
            literal_run = 0;
        }
        if let Some(candidate) = candidate {
            if options.lazy_matching && pos + 1 < end {
                insert_match_position(combined, pos, &mut buckets);
                let next = ratio_probe(
                    combined,
                    pos + 1,
                    end,
                    &buckets,
                    options,
                    &state,
                    distance_size,
                    &prices,
                    policy,
                    tree,
                );
                let deferred = next.0.is_some_and(|next| {
                    next.score > candidate.score + prices.bits(pos, 1) as isize
                }) || should_lazy_emit_literal_beyond_one(
                    combined,
                    pos,
                    &buckets,
                    options,
                    &state,
                    distance_size,
                    candidate,
                    &prices,
                    tree,
                );
                if deferred {
                    EncodeToken::push_literal(&mut tokens);
                    pos += 1;
                    probed = Some(next);
                    continue;
                }
                let MatchCandidate {
                    length, distance, ..
                } = candidate;
                tokens.push(EncodeToken::matched(length, distance));
                state.remember(length, distance);
                insert_match_range(combined, pos + 1..pos + length, &mut buckets);
                pos += length;
                literal_run = 0;
            } else {
                let MatchCandidate {
                    length, distance, ..
                } = candidate;
                tokens.push(EncodeToken::matched(length, distance));
                state.remember(length, distance);
                insert_match_range(combined, pos..pos + length, &mut buckets);
                pos += length;
            }
        } else {
            let step = (if policy.exhaustive {
                1
            } else {
                1 + (literal_run >> LITERAL_SKIP_STRENGTH)
            })
            .min(LITERAL_SKIP_MAX)
            .min(end - pos);
            EncodeToken::push_literals(&mut tokens, step);
            insert_match_range(combined, pos..pos + step, &mut buckets);
            literal_run += step;
            pos += step;
        }
        let consumed = pos.saturating_sub(start);
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
    Ok((tokens, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload(n: usize) -> Vec<u8> {
        let mut x = 0x123456789abcdefu64;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if i % 65536 < 32768 {
                    b"abcabXabcabY12345
"[i % 17]
                } else {
                    x as u8
                }
            })
            .collect()
    }
    #[test]
    fn baseline_matches_existing_encoder() {
        for n in [0, 1, 3, 1000, 300000] {
            let data = payload(n);
            let mut lab = Encoder::new(131072, Policy::default());
            let expected = encode_lz_member_with_options(&data, 0, lab.options).unwrap();
            assert_eq!(lab.encode(&data, false).unwrap(), expected, "size {n}");
        }
    }
    #[test]
    fn all_policies_roundtrip_and_adaptive_never_grows() {
        for n in [0, 2, 3, 100, 300000] {
            let data = payload(n);
            for mask in 0..16 {
                let policy = Policy {
                    short_repeats: mask & 1 != 0,
                    adaptive: mask & 2 != 0,
                    carry: mask & 4 != 0,
                    exhaustive: mask & 8 != 0,
                    ..Policy::default()
                };
                let packed = Encoder::new(131072, policy).encode(&data, false).unwrap();
                assert_eq!(decode_lz(&packed, 0, n).unwrap(), data, "{mask}, {n}");
                if policy.adaptive {
                    let fixed = Encoder::new(
                        131072,
                        Policy {
                            adaptive: false,
                            ..policy
                        },
                    )
                    .encode(&data, false)
                    .unwrap();
                    assert!(packed.len() <= fixed.len());
                }
            }
        }
    }
    #[test]
    fn refined_partitions_preserve_or_improve_coarse_bytes() {
        let mut cases = vec![payload(300000), payload(900000), vec![42; 700000]];
        let mut long_run = payload(17000);
        long_run.extend((0..900000).map(|i| ((i * 73 + i / 7) % 251) as u8));
        cases.push(long_run);
        for data in cases {
            for mask in 0..4 {
                let base = Policy {
                    adaptive: true,
                    short_repeats: mask & 1 != 0,
                    carry: mask & 2 != 0,
                    ..Policy::default()
                };
                let coarse = Encoder::new(131072, base).encode(&data, false).unwrap();
                for (fine, refine) in [(true, false), (false, true), (true, true)] {
                    let encoded = Encoder::new(
                        131072,
                        Policy {
                            fine,
                            refine,
                            ..base
                        },
                    )
                    .encode(&data, false)
                    .unwrap();
                    assert!(encoded.len() <= coarse.len());
                    assert_eq!(decode_lz(&encoded, 0, data.len()).unwrap(), data);
                }
            }
        }
    }
    #[test]
    fn statistical_cost_matches_actual_emission() {
        for n in [0, 1, 2, 100, 65536, 300000] {
            let data = payload(n);
            let options = EncodeOptions::default();
            let tokens = encode_tokens(&data, &[], options, 64);
            let mut stats = Statistics::empty();
            let mut state = EncoderMatchState::default();
            let mut pos = 0;
            for token in &tokens {
                stats
                    .add(*token, &data[pos..pos + token.length], &mut state)
                    .unwrap();
                pos += token.length;
            }
            let (actual, _) = encode_token_block(
                &data,
                &tokens,
                0,
                &[],
                0,
                64,
                &mut EncoderMatchState::default(),
                true,
            )
            .unwrap();
            assert_eq!(stats.encoded_size().unwrap(), actual.len(), "{n}");
        }
    }
    #[test]
    fn carried_state_survives_blocks_members_and_explicit_reset() {
        let first = b"a common phrase and repeated values 123456789\n".repeat(110000);
        let second = b"a common phrase and repeated values 123456789\n".repeat(200);
        let policy = Policy {
            carry: true,
            short_repeats: true,
            adaptive: true,
            exhaustive: true,
            ..Policy::default()
        };
        let mut encoder = Encoder::new(131072, policy);
        let mut decoder = Unpack50Decoder::new();
        for (data, solid) in [(&first, false), (&second, true), (&second, false)] {
            let packed = encoder.encode(data, solid).unwrap();
            let unpacked = decoder
                .decode_member_with_dictionary(
                    &packed,
                    0,
                    data.len(),
                    131072,
                    solid,
                    DecodeMode::Lz,
                )
                .unwrap();
            assert_eq!(&unpacked, data);
        }
    }
    #[test]
    fn adaptive_horizon_matches_or_beats_both_uniform_paths() {
        let data = payload(MAX_COMPRESSED_BLOCK_OUTPUT + 170003);
        let policy = Policy {
            adaptive: true,
            refine: true,
            ..Policy::default()
        };
        let mut adaptive = Encoder::new(131072, policy);
        let mut decoder = Unpack50Decoder::new();
        for (input, solid) in [
            (data.as_slice(), false),
            (&[][..], true),
            (&data[307..400010], true),
            (&data[..777], false),
        ] {
            let mut long = adaptive
                .clone()
                .with_tokenizer_block_size(MAX_COMPRESSED_BLOCK_OUTPUT)
                .unwrap();
            let mut short = adaptive
                .clone()
                .with_tokenizer_block_size(256 * 1024)
                .unwrap();
            let long = long.encode(input, solid).unwrap();
            let short = short.encode(input, solid).unwrap();
            let narrow = adaptive
                .clone()
                .encode_adaptive_horizon(input, solid)
                .unwrap();
            let packed = adaptive.encode_wide_horizon(input, solid).unwrap();
            assert!(packed.len() <= narrow.len());
            assert!(packed.len() <= long.len().min(short.len()));
            let decoded = decoder
                .decode_member_with_dictionary(
                    &packed,
                    0,
                    input.len(),
                    131072,
                    solid,
                    DecodeMode::Lz,
                )
                .unwrap();
            assert_eq!(decoded, input);
        }
        assert!(Encoder::new(
            131072,
            Policy {
                carry: true,
                ..Policy::default()
            }
        )
        .encode_adaptive_horizon(b"abc", false)
        .is_err());
    }
    #[test]
    fn optimal_horizons_refine_and_preserve_solid_state() {
        let data = payload(1200007);
        let policy = Policy {
            adaptive: true,
            refine: true,
            ..Policy::default()
        };
        let mut encoder = Encoder::new(131072, policy)
            .with_optimal_parse(true)
            .unwrap();
        let mut decoder = Unpack50Decoder::new();
        for (input, solid) in [
            (data.as_slice(), false),
            (&[][..], true),
            (&data[13..400003], true),
            (&data[..777], false),
        ] {
            let long = encoder.clone().encode(input, solid).unwrap();
            let short = encoder
                .clone()
                .with_tokenizer_block_size(262144)
                .unwrap()
                .encode(input, solid)
                .unwrap();
            let narrow = encoder
                .clone()
                .encode_adaptive_horizon(input, solid)
                .unwrap();
            for size in [512 * 1024, 1024 * 1024] {
                let uniform = encoder
                    .clone()
                    .with_tokenizer_block_size(size)
                    .unwrap()
                    .encode(input, solid)
                    .unwrap();
                let wide = encoder.clone().encode_wide_horizon(input, solid).unwrap();
                assert!(wide.len() <= uniform.len());
            }
            let balanced = encoder
                .clone()
                .encode_balanced_horizon(input, solid)
                .unwrap();
            let medium = encoder
                .clone()
                .with_tokenizer_block_size(1024 * 1024)
                .unwrap()
                .encode(input, solid)
                .unwrap();
            assert!(balanced.len() <= long.len().min(medium.len()));
            let wide = encoder.clone().encode_wide_horizon(input, solid).unwrap();
            let packed = encoder.encode_seven_horizon(input, solid).unwrap();
            assert!(packed.len() <= wide.len());
            assert!(packed.len() <= balanced.len());
            assert!(packed.len() <= narrow.len());
            assert!(packed.len() <= long.len().min(short.len()));
            assert_eq!(
                decoder
                    .decode_member_with_dictionary(
                        &packed,
                        0,
                        input.len(),
                        131072,
                        solid,
                        DecodeMode::Lz
                    )
                    .unwrap(),
                input
            );
        }
        for policy in [
            Policy {
                carry: true,
                ..Policy::default()
            },
            Policy {
                short_repeats: true,
                ..Policy::default()
            },
            Policy {
                exhaustive: true,
                ..Policy::default()
            },
        ] {
            assert!(Encoder::new(131072, policy)
                .with_optimal_parse(true)
                .is_err());
        }
    }
    #[test]
    fn tree_comparison_caps_roundtrip_solid_reset_and_default_identity() {
        let data = payload(65539);
        let make = || {
            Encoder::new(
                4 << 20,
                Policy {
                    adaptive: true,
                    refine: true,
                    ..Policy::default()
                },
            )
            .with_optimal_parse(true)
            .unwrap()
            .with_tree_search(true)
        };
        assert!(make().with_tree_nice_length(3).is_err());
        assert!(make().with_tree_nice_length(257).is_err());
        assert_eq!(
            make().encode(&data, false).unwrap(),
            make()
                .with_tree_nice_length(64)
                .unwrap()
                .encode(&data, false)
                .unwrap()
        );
        for cap in [32, 64, 128, 256] {
            let mut encoder = make().with_tree_nice_length(cap).unwrap();
            let mut decoder = Unpack50Decoder::new();
            for (input, solid) in [
                (data.as_slice(), false),
                (&[][..], true),
                (&data[37..], true),
                (&data[37..], false),
            ] {
                let packed = encoder.encode(input, solid).unwrap();
                assert!(encoder.tree_distances.is_none());
                assert_eq!(
                    decoder
                        .decode_member_with_dictionary(
                            &packed,
                            0,
                            input.len(),
                            4 << 20,
                            solid,
                            DecodeMode::Lz
                        )
                        .unwrap(),
                    input
                );
            }
        }
    }

    #[test]
    fn tokenizer_horizons_preserve_solid_state_and_tails() {
        let first = payload(300007);
        let second = first[1001..150003].to_vec();
        for size in [65536, 262143, 262144, 524288] {
            for carry in [false, true] {
                let policy = Policy {
                    adaptive: true,
                    refine: true,
                    carry,
                    ..Policy::default()
                };
                let mut encoder = Encoder::new(131072, policy)
                    .with_tokenizer_block_size(size)
                    .unwrap();
                let mut decoder = Unpack50Decoder::new();
                for (data, solid) in [
                    (first.as_slice(), false),
                    (&[][..], true),
                    (second.as_slice(), true),
                    (second.as_slice(), false),
                ] {
                    let packed = encoder.encode(data, solid).unwrap();
                    let unpacked = decoder
                        .decode_member_with_dictionary(
                            &packed,
                            0,
                            data.len(),
                            131072,
                            solid,
                            DecodeMode::Lz,
                        )
                        .unwrap();
                    assert_eq!(unpacked, data);
                }
            }
        }
        assert!(Encoder::new(131072, Policy::default())
            .with_tokenizer_block_size(0)
            .is_err());
        assert!(Encoder::new(131072, Policy::default())
            .with_tokenizer_block_size(MAX_COMPRESSED_BLOCK_OUTPUT + 1)
            .is_err());
    }
    #[test]
    fn shared_tree_horizons_preserve_bounds_history_and_release_hints() {
        let data = payload(MAX_COMPRESSED_BLOCK_OUTPUT + 170003);
        let policy = Policy {
            adaptive: true,
            refine: true,
            ..Policy::default()
        };
        let mut encoder = Encoder::new(4 << 20, policy)
            .with_optimal_parse(true)
            .unwrap()
            .with_tree_search(true);
        let mut decoder = Unpack50Decoder::new();
        for (input, solid) in [
            (data.as_slice(), false),
            (&[][..], true),
            (&data[113..300120], true),
            (&data[..777], false),
        ] {
            let balanced = encoder
                .clone()
                .encode_balanced_horizon(input, solid)
                .unwrap();
            let wide = encoder.clone().encode_wide_horizon(input, solid).unwrap();
            let seven = encoder.encode_seven_horizon(input, solid).unwrap();
            assert!(seven.len() <= wide.len() && wide.len() <= balanced.len());
            assert!(encoder.tree_distances.is_none());
            assert_eq!(
                decoder
                    .decode_member_with_dictionary(
                        &seven,
                        0,
                        input.len(),
                        4 << 20,
                        solid,
                        DecodeMode::Lz,
                    )
                    .unwrap(),
                input
            );
        }
    }

    #[test]
    fn short_repeat_can_encode_tail_below_four_bytes() {
        let input = b"abcdXYabcdXZab";
        let prices = LiteralPrices::new(input, 0);
        let index = MatchIndex::<usize>::new(input.len(), 256);
        let state = EncoderMatchState {
            reps: [6, 0, 0, 0],
            last_length: 2,
        };
        let (candidate, _) = ratio_probe(
            input,
            12,
            14,
            &index,
            EncodeOptions::default(),
            &state,
            64,
            &prices,
            Policy {
                short_repeats: true,
                ..Policy::default()
            },
            TreeMatches::none(),
        );
        assert_eq!(candidate.unwrap().length, 2);
    }
}
