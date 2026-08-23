#[cfg(feature = "fast")]
use std::simd::{cmp::SimdPartialEq, Simd};

#[cfg(feature = "fast")]
const LANES: usize = 32;

pub(crate) fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    if distance == 0 || distance > pos {
        return 0;
    }

    let max_length = max_length.min(input.len().saturating_sub(pos));
    match_length_impl(input, pos, distance, max_length)
}

#[cfg(feature = "fast")]
fn match_length_impl(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    let mut length = 0usize;
    while length + LANES <= max_length {
        let current = Simd::<u8, LANES>::from_slice(&input[pos + length..pos + length + LANES]);
        let previous = Simd::<u8, LANES>::from_slice(
            &input[pos + length - distance..pos + length - distance + LANES],
        );
        if let Some(mismatch) = current.simd_ne(previous).first_set() {
            return length + mismatch;
        }
        length += LANES;
    }

    match_length_scalar(input, pos, distance, max_length, length)
}

#[cfg(not(feature = "fast"))]
fn match_length_impl(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    match_length_scalar(input, pos, distance, max_length, 0)
}

fn match_length_scalar(
    input: &[u8],
    pos: usize,
    distance: usize,
    max_length: usize,
    mut length: usize,
) -> usize {
    while length < max_length && input[pos + length] == input[pos + length - distance] {
        length += 1;
    }
    length
}

// The x86 E8/E8E9 opcode scan has ONE definition, in `crate::fast`, and
// every caller in this module tree reaches it through here. It lived as a
// byte-identical second copy in this file until the two were collapsed;
// `match_length` below is what actually belongs to `codec::fast`.
// (nzbfast-local change, 23 Aug 2026 - re-apply on the next rars re-sync,
// see vendor/rars/VENDORING.md.)
pub(crate) use crate::fast::next_x86_opcode;

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_match_length(
        input: &[u8],
        pos: usize,
        distance: usize,
        max_length: usize,
    ) -> usize {
        let mut length = 0usize;
        while length < max_length && input[pos + length] == input[pos + length - distance] {
            length += 1;
        }
        length
    }

    #[test]
    fn match_length_matches_scalar_around_lane_boundaries() {
        let mut input = Vec::new();
        input.extend((0..192).map(|index| (index % 251) as u8));
        input.extend_from_within(64..192);

        for distance in 1..=64 {
            let pos = 192usize;
            let max = (input.len() - pos).min(96);
            let expected = reference_match_length(&input, pos, distance, max);
            assert_eq!(match_length(&input, pos, distance, max), expected);
        }
    }

    #[test]
    fn match_length_stops_at_first_mismatch_in_vector_tail() {
        let mut input = b"abcdefghijklmnopqrstuvwxyz012345".repeat(4);
        let pos = 64;
        input[pos + 37] ^= 0x55;

        assert_eq!(
            match_length(&input, pos, 32, 64),
            reference_match_length(&input, pos, 32, 64)
        );
    }
}
