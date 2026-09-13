//! Joint filter/tree experiment. Filter records and block emission stay in the
//! existing codec; only the match hints over transformed bytes are new.
use super::*;

pub struct FilteredEncoder {
    options: EncodeOptions,
    history: Vec<u8>,
    tree_enabled: bool,
}

impl FilteredEncoder {
    pub fn new(dictionary: usize, optimal: bool) -> Self {
        Self {
            options: EncodeOptions::new(256)
                .with_lazy_matching(true)
                .with_max_match_distance(dictionary)
                .with_optimal_parse(optimal),
            history: Vec::new(),
            tree_enabled: true,
        }
    }

    /// A disabled finder is an exact control for the existing filtered path.
    pub fn with_tree_search(mut self, enabled: bool) -> Self {
        self.tree_enabled = enabled;
        self
    }

    pub fn encode(
        &mut self,
        data: &[u8],
        filters: &[Rar50FilterSpec],
        solid: bool,
    ) -> Result<Vec<u8>> {
        let filters = normalized_filter_specs(data.len(), filters)?;
        let dictionary = self.options.max_match_distance;
        let history = if solid { self.history.as_slice() } else { &[] };
        if data.is_empty() {
            let packed = encode_lz_block(&[], history, 0, &[], self.options, true, None)?;
            if !solid {
                self.history.clear();
            }
            return Ok(packed);
        }
        // Exactly the original filter chunking, including absolute offsets for
        // executable filters and separate delta resets at chunk boundaries.
        let mut transformed = data.to_vec();
        let mut records = Vec::new();
        for start in (0..data.len()).step_by(MAX_FILTER_BLOCK_LENGTH) {
            let end = (start + MAX_FILTER_BLOCK_LENGTH).min(data.len());
            let mut chunk_records = Vec::new();
            for filter in &filters {
                let first = filter.range.start.max(start);
                let last = filter.range.end.min(end);
                if first >= last {
                    continue;
                }
                let (filter_type, channels) =
                    encode_filter_data(filter.kind, &mut transformed[first..last], first)?;
                chunk_records.push(EncodeFilter {
                    offset: first - start,
                    length: last - first,
                    filter_type,
                    channels,
                });
            }
            records.push(chunk_records);
        }
        let history_len = history.len();
        let mut span = Vec::with_capacity(history_len + transformed.len());
        span.extend_from_slice(history);
        span.extend_from_slice(&transformed);
        drop(transformed);
        let hints = if self.tree_enabled
            && dictionary >= TREE_MIN_DICTIONARY
            && TreeMatchFinder::fits(span.len())
        {
            let mut finder = TreeMatchFinder::new(dictionary);
            let seed_start = history_len.saturating_sub(finder.window());
            finder.skip_to(seed_start);
            for start in (seed_start..history_len).step_by(MAX_FILTER_BLOCK_LENGTH) {
                finder.advance_range(
                    &span,
                    start..(start + MAX_FILTER_BLOCK_LENGTH).min(history_len),
                    None,
                    1,
                    1,
                );
            }
            let hints = empty_slots(data.len());
            for start in (0..data.len()).step_by(MAX_FILTER_BLOCK_LENGTH) {
                let end = (start + MAX_FILTER_BLOCK_LENGTH).min(data.len());
                finder.advance_range(
                    &span,
                    history_len + start..history_len + end,
                    Some(&hints[start..end]),
                    1,
                    1,
                );
            }
            hints
        } else {
            Vec::new()
        };
        let mut out = Vec::new();
        let mut scratch = EncoderScratch::default();
        for (index, chunk_records) in records.iter().enumerate() {
            let start = history_len + index * MAX_FILTER_BLOCK_LENGTH;
            let end = (start + MAX_FILTER_BLOCK_LENGTH).min(span.len());
            let chunk_hints = if hints.is_empty() {
                &[][..]
            } else {
                &hints[start - history_len..end - history_len]
            };
            out.extend(encode_lz_block_in_span(
                &span[start..end],
                &span[start.saturating_sub(dictionary)..start],
                0,
                chunk_records,
                self.options,
                end == span.len(),
                None,
                &mut scratch,
                None,
                None,
                chunk_hints,
            )?);
        }
        // Keep only dictionary storage between members, not the whole input's
        // capacity. The span and per-position hints are released on return.
        let keep_from = span.len().saturating_sub(dictionary);
        self.history.clear();
        self.history.extend_from_slice(&span[keep_from..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 17 + i / 31) % 251) as u8).collect()
    }

    #[test]
    fn filtered_tree_preserves_filter_boundaries_solid_history_and_ring_controls() {
        let input = data(2 * MAX_FILTER_BLOCK_LENGTH + 19);
        for dictionary in [131072, 4 << 20] {
            for optimal in [false, true] {
                for kind in [
                    Rar50FilterKind::Delta { channels: 2 },
                    Rar50FilterKind::Delta { channels: 32 },
                    Rar50FilterKind::E8,
                    Rar50FilterKind::E8E9,
                    Rar50FilterKind::Arm,
                ] {
                    let mut ring =
                        FilteredEncoder::new(dictionary, optimal).with_tree_search(false);
                    let mut tree = FilteredEncoder::new(dictionary, optimal);
                    let mut reference = Unpack50Encoder::with_options(ring.options);
                    let mut decoder = Unpack50Decoder::new();
                    for (bytes, solid) in [
                        (input.as_slice(), false),
                        (&[][..], true),
                        (&input[7..321], true),
                        (&input[17..], false),
                    ] {
                        if !solid {
                            reference = Unpack50Encoder::with_options(ring.options);
                        }
                        let specs = if bytes.is_empty() {
                            Vec::new()
                        } else {
                            vec![Rar50FilterSpec::new(kind)]
                        };
                        let expected = reference
                            .encode_member_with_filters_chunked(bytes, 0, &specs)
                            .unwrap();
                        assert_eq!(ring.encode(bytes, &specs, solid).unwrap(), expected);
                        assert_eq!(ring.history, reference.history);
                        let packed = tree.encode(bytes, &specs, solid).unwrap();
                        assert_eq!(tree.history, reference.history);
                        assert!(tree.history.capacity() <= dictionary * 2);
                        if dictionary < TREE_MIN_DICTIONARY {
                            assert_eq!(packed, expected);
                        }
                        assert_eq!(
                            decoder
                                .decode_member_with_dictionary(
                                    &packed,
                                    0,
                                    bytes.len(),
                                    dictionary,
                                    solid,
                                    DecodeMode::Lz
                                )
                                .unwrap(),
                            bytes
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn filtered_tree_preserves_partial_ranges_and_error_state() {
        let input = data(2 * MAX_FILTER_BLOCK_LENGTH + 23);
        let filters = [
            Rar50FilterSpec::range(
                Rar50FilterKind::Delta { channels: 4 },
                17..MAX_FILTER_BLOCK_LENGTH + 13,
            ),
            Rar50FilterSpec::range(
                Rar50FilterKind::E8E9,
                MAX_FILTER_BLOCK_LENGTH + 31..input.len() - 3,
            ),
        ];
        let mut tree = FilteredEncoder::new(4 << 20, true);
        let mut reference = Unpack50Encoder::with_options(tree.options);
        let mut ring = FilteredEncoder::new(4 << 20, true).with_tree_search(false);
        let expected = reference
            .encode_member_with_filters_chunked(&input, 0, &filters)
            .unwrap();
        assert_eq!(ring.encode(&input, &filters, false).unwrap(), expected);
        let packed = tree.encode(&input, &filters, false).unwrap();
        assert_eq!(tree.history, reference.history);
        assert_eq!(
            Unpack50Decoder::new()
                .decode_member_with_dictionary(
                    &packed,
                    0,
                    input.len(),
                    4 << 20,
                    false,
                    DecodeMode::Lz
                )
                .unwrap(),
            input
        );
        let saved = tree.history.clone();
        assert!(tree
            .encode(
                &input,
                &[Rar50FilterSpec::range(
                    Rar50FilterKind::E8,
                    1..input.len() + 1
                )],
                true
            )
            .is_err());
        assert_eq!(tree.history, saved);
        assert!(tree
            .encode(
                &input,
                &[Rar50FilterSpec::new(Rar50FilterKind::Delta { channels: 0 })],
                true
            )
            .is_err());
        assert_eq!(tree.history, saved);
    }
}
