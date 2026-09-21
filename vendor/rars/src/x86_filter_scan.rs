use std::ops::Range;

const AUTO_X86_CLUSTER_GAP: usize = 4096;
const AUTO_X86_TIGHT_CLUSTER_GAP: usize = 512;
const AUTO_X86_SPAN_CLUSTER_GAP: usize = 32768;
const AUTO_X86_RANGE_PADDING: usize = 16;
const AUTO_X86_MAX_RANGES: usize = 8;
const AUTO_X86_MAX_SPAN_RANGES: usize = 4;
const AUTO_X86_MIN_SPAN_OPCODES: usize = 4;

/// The chooser, for `benches/x86_filter_scan.rs`. Not an API; `bench-internals`
/// must never be enabled in a shipped build.
#[cfg(feature = "bench-internals")]
pub mod harness {
    use std::ops::Range;

    pub fn auto_x86_filter_ranges(data: &[u8], include_e9: bool) -> Vec<Range<usize>> {
        super::auto_x86_filter_ranges(data, include_e9)
    }
}

pub(crate) fn auto_x86_filter_ranges(data: &[u8], include_e9: bool) -> Vec<Range<usize>> {
    if data.len() <= 5 {
        return Vec::new();
    }

    // ONE walk of the member, feeding both cluster gaps as each trigger
    // arrives. This used to be two calls of a whole-member function, one per
    // gap, which scanned every byte of every member TWICE at write time for
    // two cluster foldings of one opcode stream. Measured 16 Sep 2026: halving
    // the walks is worth about 2x on every corpus a bench has, dense or
    // sparse, which is more than the scan's probe width is worth on any of
    // them (nzbfast research/AUTO-X86-SCAN-PROBE-2026-09-16.md).
    //
    // Collecting the positions once into a `Vec` and folding that twice would
    // read the same and is NOT the same: at real-binary opcode density that
    // vector is about 1.5% of the member in `usize`s - tens of millions of
    // entries on a large member - where two accumulators are O(1).
    let (wide, tight) = if include_e9 {
        collect_clusters::<true>(data)
    } else {
        collect_clusters::<false>(data)
    };
    let mut ranges = ranges_from_clusters(wide, data.len());
    for range in ranges_from_clusters(tight, data.len()) {
        if !ranges.contains(&range) {
            ranges.push(range);
        }
    }
    ranges
}

fn ranges_from_clusters(
    mut clusters: Vec<(usize, usize, usize)>,
    data_len: usize,
) -> Vec<Range<usize>> {
    clusters.retain(|&(_, _, count)| count >= 2);
    let mut ranges = Vec::new();
    let mut span_count = 0;
    let mut span: Option<(usize, usize, usize)> = None;
    for &(start, last, count) in &clusters {
        match span {
            Some((span_start, span_last, span_opcodes))
                if start.saturating_sub(span_last) <= AUTO_X86_SPAN_CLUSTER_GAP =>
            {
                span = Some((span_start, last, span_opcodes + count));
            }
            Some((span_start, span_last, span_opcodes)) => {
                if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES
                    && span_count < AUTO_X86_MAX_SPAN_RANGES
                {
                    push_x86_filter_range(&mut ranges, data_len, span_start, span_last);
                    span_count += 1;
                }
                span = Some((start, last, count));
            }
            None => span = Some((start, last, count)),
        }
    }
    if let Some((span_start, span_last, span_opcodes)) = span {
        if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES && span_count < AUTO_X86_MAX_SPAN_RANGES {
            push_x86_filter_range(&mut ranges, data_len, span_start, span_last);
        }
    }

    clusters.sort_by(|a, b| {
        let a_len = a.1 - a.0 + 5;
        let b_len = b.1 - b.0 + 5;
        b.2.cmp(&a.2).then_with(|| a_len.cmp(&b_len))
    });
    clusters.truncate(AUTO_X86_MAX_RANGES);

    for (start, last, _) in clusters {
        push_x86_filter_range(&mut ranges, data_len, start, last);
    }
    ranges
}

/// Walks every trigger opcode in `data`, left to right, ONCE, folding them
/// into `(start, last, count)` clusters for BOTH cluster gaps as they arrive:
/// the wide gap first, the tight gap second. Both accumulators see the same
/// stream in the same order, which is what makes one walk equivalent to the
/// two this replaced.
///
/// The scan is `codec::address_filters::next_x86_trigger`, which is the crate's
/// only one. This loop asks it for EVERY opcode in the member rather than for
/// the ones a filter will convert, and `auto_x86_filter_ranges` runs it at two
/// cluster gaps, so it pays the per-trigger scan cost about twice over across a
/// whole archive member at write time: it is the scan's heaviest caller, and
/// the one that made the missing word probe worth fixing (nzbfast
/// research/AUTO-X86-SCAN-PROBE-2026-09-16.md).
///
/// `JUMP` is what used to be a runtime `cmp_mask` of `0xff` or `0xfe`. Masking
/// with `0xfe` and comparing to `0xe8` accepts exactly `0xe8` and `0xe9`, which
/// is what `JUMP` selects, so dispatching here monomorphises the scan instead
/// of branching on the mask inside it.
type Clusters = Vec<(usize, usize, usize)>;

fn collect_clusters<const JUMP: bool>(data: &[u8]) -> (Clusters, Clusters) {
    let mut wide: (Clusters, Option<(usize, usize, usize)>) = (Vec::new(), None);
    let mut tight: (Clusters, Option<(usize, usize, usize)>) = (Vec::new(), None);
    let mut scan_pos = 0usize;
    while let Some(pos) = crate::codec::address_filters::next_x86_trigger::<JUMP>(data, scan_pos) {
        for (acc, cluster_gap) in [
            (&mut wide, AUTO_X86_CLUSTER_GAP),
            (&mut tight, AUTO_X86_TIGHT_CLUSTER_GAP),
        ] {
            match acc.1 {
                Some((start, last, count)) if pos - last <= cluster_gap => {
                    acc.1 = Some((start, pos, count + 1));
                }
                Some(cluster) => {
                    acc.0.push(cluster);
                    acc.1 = Some((pos, pos, 1));
                }
                None => acc.1 = Some((pos, pos, 1)),
            }
        }
        scan_pos = pos + 1;
    }
    for acc in [&mut wide, &mut tight] {
        if let Some(cluster) = acc.1 {
            acc.0.push(cluster);
        }
    }
    (wide.0, tight.0)
}

fn push_x86_filter_range(
    ranges: &mut Vec<Range<usize>>,
    data_len: usize,
    start: usize,
    last: usize,
) {
    let range_start = start.saturating_sub(AUTO_X86_RANGE_PADDING);
    let range_end = (last + 5 + AUTO_X86_RANGE_PADDING).min(data_len);
    let range = range_start..range_end;
    if range.start < range.end && !ranges.contains(&range) {
        ranges.push(range);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_auto_x86_filter_ranges(data: &[u8], include_e9: bool) -> Vec<Range<usize>> {
        let mut ranges =
            scalar_auto_x86_filter_ranges_with_cluster_gap(data, include_e9, AUTO_X86_CLUSTER_GAP);
        for range in scalar_auto_x86_filter_ranges_with_cluster_gap(
            data,
            include_e9,
            AUTO_X86_TIGHT_CLUSTER_GAP,
        ) {
            if !ranges.contains(&range) {
                ranges.push(range);
            }
        }
        ranges
    }

    fn scalar_auto_x86_filter_ranges_with_cluster_gap(
        data: &[u8],
        include_e9: bool,
        cluster_gap: usize,
    ) -> Vec<Range<usize>> {
        if data.len() <= 5 {
            return Vec::new();
        }

        let cmp_mask = if include_e9 { 0xfe } else { 0xff };
        let mut clusters = Vec::new();
        let mut current: Option<(usize, usize, usize)> = None;
        for (pos, &byte) in data.iter().take(data.len() - 4).enumerate() {
            if byte & cmp_mask != 0xe8 {
                continue;
            }

            match current {
                Some((start, last, count)) if pos - last <= cluster_gap => {
                    current = Some((start, pos, count + 1));
                }
                Some(cluster) => {
                    clusters.push(cluster);
                    current = Some((pos, pos, 1));
                }
                None => current = Some((pos, pos, 1)),
            }
        }
        if let Some(cluster) = current {
            clusters.push(cluster);
        }

        clusters.retain(|&(_, _, count)| count >= 2);
        let mut ranges = Vec::new();
        let mut span_count = 0;
        let mut span: Option<(usize, usize, usize)> = None;
        for &(start, last, count) in &clusters {
            match span {
                Some((span_start, span_last, span_opcodes))
                    if start.saturating_sub(span_last) <= AUTO_X86_SPAN_CLUSTER_GAP =>
                {
                    span = Some((span_start, last, span_opcodes + count));
                }
                Some((span_start, span_last, span_opcodes)) => {
                    if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES
                        && span_count < AUTO_X86_MAX_SPAN_RANGES
                    {
                        push_x86_filter_range(&mut ranges, data.len(), span_start, span_last);
                        span_count += 1;
                    }
                    span = Some((start, last, count));
                }
                None => span = Some((start, last, count)),
            }
        }
        if let Some((span_start, span_last, span_opcodes)) = span {
            if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES && span_count < AUTO_X86_MAX_SPAN_RANGES {
                push_x86_filter_range(&mut ranges, data.len(), span_start, span_last);
            }
        }

        clusters.sort_by(|a, b| {
            let a_len = a.1 - a.0 + 5;
            let b_len = b.1 - b.0 + 5;
            b.2.cmp(&a.2).then_with(|| a_len.cmp(&b_len))
        });
        clusters.truncate(AUTO_X86_MAX_RANGES);

        for (start, last, _) in clusters {
            push_x86_filter_range(&mut ranges, data.len(), start, last);
        }
        ranges
    }

    /// Carried over from `src/fast.rs` when that second trigger scan was
    /// deleted on 16 Sep 2026: the cluster walk must find EXACTLY the opcodes a
    /// plain byte scan finds, in the same order. The range set is built from
    /// that stream by clustering constants sensitive to both, so this is the
    /// property the range assertions below rest on, asserted directly.
    ///
    /// The shapes put opcodes on the probe seams the scan has - every multiple
    /// of eight up to its probe width, and the handover to the vector search.
    #[test]
    fn the_cluster_walk_finds_exactly_the_byte_scans_opcodes() {
        let mut wide = vec![0x90u8; 128];
        for pos in [0, 1, 8, 16, 24, 31, 32, 33, 40, 63, 64, 95, 123] {
            wide[pos] = 0xe8;
        }
        wide[47] = 0xe9;
        let mut narrow = vec![0x41u8; 96];
        for pos in [0, 7, 8, 9, 23, 24, 25, 31, 32, 33, 63, 64, 91] {
            narrow[pos] = 0xe8;
        }
        narrow[47] = 0xe9;

        for data in [wide, narrow] {
            for include_e9 in [false, true] {
                let cmp_mask = if include_e9 { 0xfe } else { 0xff };
                // Both shapes are shorter than AUTO_X86_TIGHT_CLUSTER_GAP, so
                // every opcode lands in one cluster in BOTH accumulators and
                // each one's `(start, last, count)` describes the whole stream.
                let (wide, tight) = if include_e9 {
                    collect_clusters::<true>(&data)
                } else {
                    collect_clusters::<false>(&data)
                };
                assert_eq!(wide, tight, "include_e9 {include_e9}");
                let clusters = wide;

                let expected: Vec<_> = data
                    .iter()
                    .take(data.len() - 4)
                    .enumerate()
                    .filter_map(|(pos, &byte)| (byte & cmp_mask == 0xe8).then_some(pos))
                    .collect();
                assert_eq!(clusters.len(), 1, "include_e9 {include_e9}");
                let (start, last, count) = clusters[0];
                assert_eq!(start, expected[0], "include_e9 {include_e9}");
                assert_eq!(last, *expected.last().unwrap(), "include_e9 {include_e9}");
                assert_eq!(count, expected.len(), "include_e9 {include_e9}");
            }
        }
    }

    #[test]
    fn returns_no_ranges_for_inputs_too_short_to_contain_a_call() {
        for len in 0..=5 {
            let data = vec![0xe8; len];
            assert!(auto_x86_filter_ranges(&data, false).is_empty());
            assert!(auto_x86_filter_ranges(&data, true).is_empty());
        }
    }

    #[test]
    fn auto_x86_filter_ranges_match_scalar_scanner_at_lane_boundaries() {
        let mut data = vec![0x41u8; 150_000];
        for pos in [
            31usize, 32, 33, 1024, 1088, 4096, 4160, 80_000, 80_032, 80_064,
        ] {
            data[pos] = 0xe8;
        }
        data[80_096] = 0xe9;

        assert_eq!(
            auto_x86_filter_ranges(&data, false),
            scalar_auto_x86_filter_ranges(&data, false)
        );
        assert_eq!(
            auto_x86_filter_ranges(&data, true),
            scalar_auto_x86_filter_ranges(&data, true)
        );
    }

    /// `auto_x86_filter_ranges` walks the member ONCE and folds both cluster
    /// gaps as each trigger arrives; it used to call a whole-member function
    /// twice, once per gap. That is equivalent only if both accumulators see
    /// the same stream in the same order, and the range set is sensitive to
    /// both, so this checks it against the byte-scanning oracle over shapes
    /// chosen to land ON the boundaries the folding turns on:
    /// AUTO_X86_TIGHT_CLUSTER_GAP (512), AUTO_X86_CLUSTER_GAP (4096) and
    /// AUTO_X86_SPAN_CLUSTER_GAP (32768), each exactly, one under and one
    /// over - which is where a one-pass fold would diverge from a two-pass one
    /// if it were going to - plus randomised shapes that reach the
    /// count >= 2 retain, the span-opcode floor and both range caps.
    #[test]
    fn one_walk_of_both_cluster_gaps_matches_the_byte_scanner() {
        let mut rng = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };

        let mut shapes: Vec<Vec<u8>> = Vec::new();

        // Exact strides at and either side of every gap the folding uses.
        for stride in [
            1usize, 2, 4, 5, 6, 511, 512, 513, 4095, 4096, 4097, 32767, 32768, 32769,
        ] {
            let mut data = vec![0x41u8; 120_000];
            let mut at = 64usize;
            while at < data.len() - 5 {
                data[at] = if at.is_multiple_of(3) { 0xe9 } else { 0xe8 };
                at += stride;
            }
            shapes.push(data);
        }

        // Pairs of clusters separated by exactly a gap boundary, which is what
        // decides whether two clusters become one and whether a span closes.
        for separation in [511usize, 512, 513, 4095, 4096, 4097, 32767, 32768, 32769] {
            let mut data = vec![0x41u8; 200_000];
            for base in [1000usize, 1000 + separation, 60_000, 60_000 + separation] {
                for index in 0..5 {
                    if let Some(byte) = data.get_mut(base + index * 8) {
                        *byte = 0xe8;
                    }
                }
            }
            shapes.push(data);
        }

        // Randomised: varying density, with occasional long trigger-free runs
        // so clusters and spans open and close irregularly.
        for round in 0..40 {
            let len = 8_000 + (next() % 150_000) as usize;
            let mut data = vec![0x41u8; len];
            let density = 1 + (round % 7) * 40;
            let mut at = 0usize;
            while at < len.saturating_sub(5) {
                if next() % 1000 < density as u64 {
                    data[at] = if next() % 4 == 0 { 0xe9 } else { 0xe8 };
                }
                at += 1;
                if next() % 20_000 == 0 {
                    at += (next() % 40_000) as usize;
                }
            }
            shapes.push(data);
        }

        for (index, data) in shapes.iter().enumerate() {
            for include_e9 in [false, true] {
                assert_eq!(
                    auto_x86_filter_ranges(data, include_e9),
                    scalar_auto_x86_filter_ranges(data, include_e9),
                    "shape {index} (len {}) include_e9 {include_e9}",
                    data.len()
                );
            }
        }
    }

    #[test]
    fn drops_isolated_opcodes_that_never_form_a_cluster() {
        let mut data = vec![0x41; 20_000];
        data[100] = 0xe8;
        data[10_000] = 0xe8;
        assert!(auto_x86_filter_ranges(&data, false).is_empty());
    }

    #[test]
    fn clamps_padded_range_to_buffer_bounds_at_both_ends() {
        let mut data = vec![0x41u8; 30];
        for pos in [0, 4, 8, 12] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert_eq!(ranges, vec![0..30]);
    }

    #[test]
    fn does_not_duplicate_a_span_range_already_emitted_for_a_cluster() {
        let mut data = vec![0x41u8; 20_000];
        for pos in [1024, 1050, 1090, 1130] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 1008..1151);
    }

    #[test]
    fn includes_tighter_ranges_inside_sparse_code_spans() {
        let mut data = vec![0x41u8; 8_000];
        for pos in [1024, 1088, 3600, 3664] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert!(
            ranges
                .iter()
                .any(|range| range.start <= 1024 && range.end > 3664 && range.len() > 2000),
            "missing broad sparse-code span: {ranges:?}"
        );
        assert!(
            ranges.iter().any(|range| range.contains(&1024)
                && range.contains(&1088)
                && !range.contains(&3600)),
            "missing first tight code cluster: {ranges:?}"
        );
        assert!(
            ranges.iter().any(|range| range.contains(&3600)
                && range.contains(&3664)
                && !range.contains(&1088)),
            "missing second tight code cluster: {ranges:?}"
        );
    }

    #[test]
    fn keeps_more_disjoint_code_section_candidates() {
        let mut data = vec![0x41u8; 700_000];
        for section in 0..8 {
            let start = 16_384 + section * 80_000;
            for index in 0..6 {
                data[start + index * 64] = 0xe8;
            }
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        for section in 0..8 {
            let start = 16_384 + section * 80_000;
            assert!(
                ranges.iter().any(|range| range.contains(&start)),
                "missing x86 section at {start}"
            );
        }
    }
}
