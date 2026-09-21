//! The fixed prefix codes of the RAR 1.5 algorithm.
//!
//! Seven canonical codes (two length codes and five rank codes) and the two
//! short-match index codes, each in two variants. Every table is built at
//! compile time from the codeword counts or codewords, and each code is at
//! most 12 bits long, so one 12-bit peek decodes any of them.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

/// Bits a decoder peeks to resolve any codeword.
pub(crate) const PEEK_BITS: u32 = 12;

/// A prefix code as two lookup tables.
pub(crate) struct PrefixCode {
    /// Indexed by the next 12 bits: `value | length << 12` (value up to 256).
    decode: [u16; 1 << PEEK_BITS],
    /// Indexed by value: `codeword | length << 16`; length 0 marks a value
    /// the code cannot express.
    encode: [u32; 257],
}

impl PrefixCode {
    /// Decodes the codeword at the front of `peek`, the next 12 bits of the
    /// stream (first bit most significant). Returns (value, length).
    #[inline(always)]
    pub(crate) fn decode(&self, peek: u32) -> (u16, u32) {
        // A 12-bit mask proves the index is inside the 4,096-entry table.
        #[allow(clippy::indexing_slicing)]
        let entry = self.decode[(peek & 0xfff) as usize];
        (entry & 0x1ff, u32::from(entry >> 12))
    }

    /// The codeword and its length for `value`, or `None` when the code has
    /// no codeword for it.
    #[inline(always)]
    pub(crate) fn encode(&self, value: u32) -> Option<(u32, u32)> {
        let entry = *self.encode.get(value as usize)?;
        let length = entry >> 16;
        (length != 0).then_some((entry & 0xffff, length))
    }
}

/// Builds a canonical code from the number of codewords of each length
/// (index = length, 1..=12). Codewords are handed out in order of increasing
/// length, consecutive within a length, values ascending.
// Evaluated only at compile time for the statics below: an index out of
// range fails the build, it cannot panic at run time.
#[allow(clippy::indexing_slicing)]
const fn canonical(counts: [u16; 13]) -> PrefixCode {
    let mut decode = [0u16; 1 << PEEK_BITS];
    let mut encode = [0u32; 257];
    let mut code = 0u32;
    let mut value = 0usize;
    let mut length = 1usize;
    while length <= PEEK_BITS as usize {
        let mut emitted = 0u16;
        while emitted < counts[length] {
            encode[value] = code | (length as u32) << 16;
            let shift = PEEK_BITS as usize - length;
            let mut index = (code as usize) << shift;
            let end = ((code as usize) + 1) << shift;
            while index < end {
                decode[index] = value as u16 | (length as u16) << 12;
                index += 1;
            }
            code += 1;
            value += 1;
            emitted += 1;
        }
        code <<= 1;
        length += 1;
    }
    PrefixCode { decode, encode }
}

/// Builds a code from explicit codewords, `(bits, length)` per index; a
/// length of 0 marks an index the variant does not have.
// Compile-time only, like `canonical`.
#[allow(clippy::indexing_slicing)]
const fn explicit(words: [(u16, u8); 15]) -> PrefixCode {
    let mut decode = [0u16; 1 << PEEK_BITS];
    let mut encode = [0u32; 257];
    let mut value = 0usize;
    while value < words.len() {
        let (bits, length) = words[value];
        if length != 0 {
            encode[value] = bits as u32 | (length as u32) << 16;
            let shift = PEEK_BITS as usize - length as usize;
            let mut index = (bits as usize) << shift;
            let end = ((bits as usize) + 1) << shift;
            while index < end {
                decode[index] = value as u16 | (length as u16) << 12;
                index += 1;
            }
        }
        value += 1;
    }
    PrefixCode { decode, encode }
}

/// Length code `LENA`: values 0..=255.
pub(crate) static LENA: PrefixCode = canonical([0, 0, 2, 1, 2, 2, 4, 5, 4, 4, 8, 0, 224]);
/// Length code `LENB`: values 0..=255.
pub(crate) static LENB: PrefixCode = canonical([0, 0, 0, 5, 2, 2, 4, 5, 4, 4, 8, 2, 220]);
/// Rank code `RK0`: values 0..=256.
pub(crate) static RK0: PrefixCode = canonical([0, 0, 0, 0, 8, 8, 8, 9, 0, 0, 0, 0, 224]);
/// Rank code `RK1`: values 0..=256.
pub(crate) static RK1: PrefixCode = canonical([0, 0, 0, 0, 0, 4, 40, 16, 16, 4, 0, 47, 130]);
/// Rank code `RK2`: values 0..=256.
pub(crate) static RK2: PrefixCode = canonical([0, 0, 0, 0, 0, 2, 5, 46, 64, 116, 24, 0, 0]);
/// Rank code `RK3`: values 0..=256.
pub(crate) static RK3: PrefixCode = canonical([0, 0, 0, 0, 0, 0, 2, 14, 202, 33, 6, 0, 0]);
/// Rank code `RK4`: values 0..=256.
pub(crate) static RK4: PrefixCode = canonical([0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0]);

/// Short-match index code `SHA`, alternate variant off (indexes 0..=13).
pub(crate) static SHA: PrefixCode = explicit([
    (0b0, 1),
    (0b101, 3),
    (0b1101, 4),
    (0b1110, 4),
    (0b11110, 5),
    (0b111110, 6),
    (0b1111110, 7),
    (0b11111110, 8),
    (0b11111111, 8),
    (0b1100, 4),
    (0b1000, 4),
    (0b10010, 5),
    (0b100110, 6),
    (0b100111, 6),
    (0, 0),
]);
/// Short-match index code `SHA`, alternate variant on (indexes 0..=14).
pub(crate) static SHA_TOGGLED: PrefixCode = explicit([
    (0b0, 1),
    (0b1010, 4),
    (0b1101, 4),
    (0b1110, 4),
    (0b11110, 5),
    (0b111110, 6),
    (0b1111110, 7),
    (0b11111110, 8),
    (0b11111111, 8),
    (0b1100, 4),
    (0b1000, 4),
    (0b10010, 5),
    (0b100110, 6),
    (0b100111, 6),
    (0b1011, 4),
]);
/// Short-match index code `SHB`, alternate variant off (indexes 0..=13).
pub(crate) static SHB: PrefixCode = explicit([
    (0b00, 2),
    (0b010, 3),
    (0b011, 3),
    (0b101, 3),
    (0b1101, 4),
    (0b1110, 4),
    (0b11110, 5),
    (0b111110, 6),
    (0b111111, 6),
    (0b1100, 4),
    (0b1000, 4),
    (0b10010, 5),
    (0b100110, 6),
    (0b100111, 6),
    (0, 0),
]);
/// Short-match index code `SHB`, alternate variant on (indexes 0..=14).
pub(crate) static SHB_TOGGLED: PrefixCode = explicit([
    (0b00, 2),
    (0b010, 3),
    (0b011, 3),
    (0b1010, 4),
    (0b1101, 4),
    (0b1110, 4),
    (0b11110, 5),
    (0b111110, 6),
    (0b111111, 6),
    (0b1100, 4),
    (0b1000, 4),
    (0b10010, 5),
    (0b100110, 6),
    (0b100111, 6),
    (0b1011, 4),
]);

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    fn parse(bits: &str) -> (u32, u32) {
        (u32::from_str_radix(bits, 2).unwrap(), bits.len() as u32)
    }

    fn check(code: &PrefixCode, vectors: &[(&str, u16)]) {
        for &(bits, value) in vectors {
            let (word, length) = parse(bits);
            assert_eq!(
                code.decode(word << (PEEK_BITS - length)),
                (value, length),
                "decode {bits}"
            );
            assert_eq!(
                code.encode(u32::from(value)),
                Some((word, length)),
                "encode {value}"
            );
        }
    }

    /// Every 12-bit pattern starts with exactly one codeword, and every
    /// codeword the encoder hands out decodes back to its value.
    fn assert_complete(code: &PrefixCode, values: u32) {
        for value in 0..values {
            let (word, length) = code.encode(value).expect("value has a codeword");
            for tail in 0..(1u32 << (PEEK_BITS - length)) {
                assert_eq!(
                    code.decode(word << (PEEK_BITS - length) | tail),
                    (value as u16, length)
                );
            }
        }
        let covered: u32 = (0..values)
            .map(|value| 1u32 << (PEEK_BITS - code.encode(value).unwrap().1))
            .sum();
        assert_eq!(covered, 1 << PEEK_BITS, "code is complete");
    }

    #[test]
    fn canonical_codes_match_the_check_vectors() {
        check(
            &LENA,
            &[
                ("00", 0),
                ("01", 1),
                ("100", 2),
                ("1010", 3),
                ("11000", 5),
                ("110100", 7),
                ("1110000", 11),
                ("11101010", 16),
                ("111011100", 20),
                ("1111000000", 24),
                ("111100100000", 32),
                ("111111111111", 255),
            ],
        );
        check(
            &LENB,
            &[
                ("000", 0),
                ("100", 4),
                ("1010", 5),
                ("11000", 7),
                ("110100", 9),
                ("1110000", 13),
                ("11101010", 18),
                ("111011100", 22),
                ("1111000000", 26),
                ("11110010000", 34),
                ("111100100100", 36),
                ("111111111111", 255),
            ],
        );
        check(
            &RK0,
            &[
                ("0000", 0),
                ("0111", 7),
                ("10000", 8),
                ("110000", 16),
                ("1110000", 24),
                ("1111000", 32),
                ("111100100000", 33),
                ("111111111111", 256),
            ],
        );
        check(
            &RK1,
            &[
                ("00000", 0),
                ("001000", 4),
                ("101111", 43),
                ("1100000", 44),
                ("11100000", 60),
                ("111100000", 76),
                ("11110010000", 80),
                ("11110111110", 126),
                ("111101111110", 127),
                ("111111111111", 256),
            ],
        );
        check(
            &RK2,
            &[
                ("00000", 0),
                ("000100", 2),
                ("0010010", 7),
                ("10000000", 53),
                ("110000000", 117),
                ("111110011", 232),
                ("1111101000", 233),
                ("1111111111", 256),
            ],
        );
        check(
            &RK3,
            &[
                ("000000", 0),
                ("0000100", 2),
                ("00100100", 16),
                ("111011100", 218),
                ("111111100", 250),
                ("1111111010", 251),
                ("1111111111", 256),
            ],
        );
        check(
            &RK4,
            &[
                ("00000000", 0),
                ("11111110", 254),
                ("111111110", 255),
                ("111111111", 256),
            ],
        );
    }

    #[test]
    fn every_code_is_complete() {
        assert_complete(&LENA, 256);
        assert_complete(&LENB, 256);
        for code in [&RK0, &RK1, &RK2, &RK3, &RK4] {
            assert_complete(code, 257);
        }
        assert_complete(&SHA, 14);
        assert_complete(&SHB, 14);
        assert_complete(&SHA_TOGGLED, 15);
        assert_complete(&SHB_TOGGLED, 15);
    }

    #[test]
    fn short_codes_without_the_toggle_cannot_express_index_14() {
        assert_eq!(SHA.encode(14), None);
        assert_eq!(SHB.encode(14), None);
        // `1011...` is index 1 in SHA and index 3 in SHB.
        assert_eq!(SHA.decode(0b1011 << 8), (1, 3));
        assert_eq!(SHB.decode(0b1011 << 8), (3, 3));
        assert_eq!(SHA_TOGGLED.decode(0b1011 << 8), (14, 4));
        assert_eq!(SHB_TOGGLED.decode(0b1011 << 8), (14, 4));
    }
}
