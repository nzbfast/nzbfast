#[cfg(feature = "fast")]
use std::simd::{cmp::SimdPartialEq, Simd};

#[cfg(feature = "fast")]
const LANES: usize = 32;

/// The crate's ONE x86 E8/E8E9 opcode scan. `codec::fast` carried a
/// byte-identical second copy of this function and its two helpers until the
/// two were collapsed here; that module re-exports this one, so
/// `super::fast::next_x86_opcode` in `codec/filters.rs` and `codec/rar50.rs`
/// still resolves. (nzbfast-local change, 23 Aug 2026 - re-apply on the next
/// rars re-sync, see vendor/rars/VENDORING.md.)
pub(crate) fn next_x86_opcode(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    let end = end_exclusive.min(data.len());
    if start >= end {
        return None;
    }

    next_x86_opcode_impl(data, start, end, cmp_mask)
}

#[cfg(feature = "fast")]
fn next_x86_opcode_impl(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    let mask = Simd::<u8, LANES>::splat(cmp_mask);
    let needle = Simd::<u8, LANES>::splat(0xe8);
    let mut pos = start;
    while pos + LANES <= end_exclusive {
        let bytes = Simd::<u8, LANES>::from_slice(&data[pos..pos + LANES]);
        if let Some(lane) = (bytes & mask).simd_eq(needle).first_set() {
            return Some(pos + lane);
        }
        pos += LANES;
    }

    next_x86_opcode_scalar(data, pos, end_exclusive, cmp_mask)
}

#[cfg(not(feature = "fast"))]
fn next_x86_opcode_impl(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    next_x86_opcode_scalar(data, start, end_exclusive, cmp_mask)
}

/// `cmp_mask` is `0xff` for the E8 filter and `0xfe` for E8E9, and those
/// are the only two values any caller passes - masking with `0xfe` and
/// comparing to `0xe8` accepts exactly `0xe8` and `0xe9`. So the scan is a
/// one- or two-byte search, which `memchr` does with a runtime-dispatched
/// vector kernel instead of a byte at a time. Measured on a 64 MiB stream
/// at ~1.5% opcode density: 2481 -> 7237 MiB/s for E8, 2282 -> 4009 MiB/s
/// for E8E9. Any other mask keeps the byte loop, so the semantics are the
/// same whatever the caller passes. (nzbfast-local change, 22 Aug 2026 -
/// re-apply on the next rars re-sync, see vendor/rars/VENDORING.md.)
fn next_x86_opcode_scalar(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    let haystack = &data[start..end_exclusive];
    let found = match cmp_mask {
        0xff => memchr::memchr(0xe8, haystack),
        0xfe => memchr::memchr2(0xe8, 0xe9, haystack),
        _ => haystack.iter().position(|&byte| byte & cmp_mask == 0xe8),
    };
    found.map(|offset| start + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_opcode_scan_matches_scalar_at_lane_boundaries() {
        let mut data = vec![0x90u8; 128];
        for pos in [0, 1, 31, 32, 33, 63, 64, 95, 123] {
            data[pos] = 0xe8;
        }
        data[47] = 0xe9;

        for &include_e9 in &[false, true] {
            let cmp_mask = if include_e9 { 0xfe } else { 0xff };
            let mut pos = 0usize;
            let mut found = Vec::new();
            while let Some(next) = next_x86_opcode(&data, pos, data.len() - 4, cmp_mask) {
                found.push(next);
                pos = next + 1;
            }
            let expected: Vec<_> = data
                .iter()
                .take(data.len() - 4)
                .enumerate()
                .filter_map(|(pos, &byte)| (byte & cmp_mask == 0xe8).then_some(pos))
                .collect();
            assert_eq!(found, expected);
        }
    }

    #[test]
    fn x86_opcode_scan_matches_scalar_for_e8_and_e8e9() {
        let mut data = vec![0x41u8; 96];
        for pos in [0, 31, 32, 33, 63, 64, 91] {
            data[pos] = 0xe8;
        }
        data[47] = 0xe9;

        for &include_e9 in &[false, true] {
            let cmp_mask = if include_e9 { 0xfe } else { 0xff };
            let mut pos = 0usize;
            let mut found = Vec::new();
            while let Some(next) = next_x86_opcode(&data, pos, data.len() - 4, cmp_mask) {
                found.push(next);
                pos = next + 1;
            }

            let expected: Vec<_> = data
                .iter()
                .take(data.len() - 4)
                .enumerate()
                .filter_map(|(pos, &byte)| (byte & cmp_mask == 0xe8).then_some(pos))
                .collect();
            assert_eq!(found, expected);
        }
    }

    #[test]
    fn x86_opcode_scan_falls_back_for_a_mask_no_caller_uses() {
        // The two-byte search covers 0xff and 0xfe; every other mask keeps
        // the byte loop, and nothing else in the crate exercises that arm.
        let mut data = vec![0x00u8; 96];
        for pos in [3, 31, 32, 64, 89] {
            data[pos] = 0xe8;
        }
        data[40] = 0xea;
        data[41] = 0xf8;

        for &cmp_mask in &[0xfcu8, 0xf8, 0xe8] {
            let mut pos = 0usize;
            let mut found = Vec::new();
            while let Some(next) = next_x86_opcode(&data, pos, data.len() - 4, cmp_mask) {
                found.push(next);
                pos = next + 1;
            }
            let expected: Vec<_> = data
                .iter()
                .take(data.len() - 4)
                .enumerate()
                .filter_map(|(pos, &byte)| (byte & cmp_mask == 0xe8).then_some(pos))
                .collect();
            assert_eq!(found, expected, "cmp_mask {cmp_mask:#04x}");
        }
    }
}
