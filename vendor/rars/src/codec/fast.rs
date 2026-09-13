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
    // Compare full words before the byte tail. Both ranges are immutable,
    // so overlapping repeats need no special handling. Little-endian words
    // make trailing_zeros locate the first mismatching byte on any host.
    // (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
    while max_length - length >= 8 {
        let at = pos + length;
        let current = u64::from_le_bytes(input[at..at + 8].try_into().unwrap());
        let previous =
            u64::from_le_bytes(input[at - distance..at - distance + 8].try_into().unwrap());
        let difference = current ^ previous;
        if difference != 0 {
            return length + difference.trailing_zeros() as usize / 8;
        }
        length += 8;
    }
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
    #[test]
    fn match_length_matches_byte_oracle_at_every_word_boundary() {
        for alignment in 0..16 {
            let pos = 64 + alignment;
            for distance in 1..=64 {
                let input: Vec<u8> = (0..pos + 160)
                    .map(|i| ((i % distance) * 37) as u8)
                    .collect();
                for mismatch in 0..=129 {
                    let mut changed = input.clone();
                    changed[pos + mismatch] ^= 0x80;
                    for limit in [
                        0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 160, 200,
                    ] {
                        let expected = reference_match_length(
                            &changed,
                            pos,
                            distance,
                            limit.min(changed.len() - pos),
                        );
                        assert_eq!(match_length(&changed, pos, distance, limit), expected,
                            "alignment={alignment} distance={distance} mismatch={mismatch} limit={limit}");
                    }
                }
            }
        }
        assert_eq!(match_length(b"abc", 1, 0, 2), 0);
        assert_eq!(match_length(b"abc", 1, 2, 2), 0);
    }
}
