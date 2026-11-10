//! Human size and rate strings, in the one direction this crate needs
//! them: `"500M"` / `"10G"` / `"1.5T"` / `"900Mb"` -> bytes.
//!
//! One function, at the crate root rather than under `serve/`, because
//! `gates`, `rss` and `smart` all parse the same strings and reaching
//! for `crate::serve::parse_size` to do it made three modules depend on
//! the daemon (TODO 276 item 3). `serve` re-exports it, so its own ~29
//! call sites are unchanged.

/// Parse "500M"/"10G"/"1.5T" (SAB-style size strings) to bytes.
///
/// A lowercase `b` here is BITS (`900Mb` is a line speed), which is
/// right for a rate and wrong for the size of a file: see
/// [`parse_byte_size`] for the rules that measure files.
pub fn parse_size(s: &str) -> Option<u64> {
    parse(s, true)
}

/// [`parse_size`] for a quantity that is a FILE SIZE, never a rate: a
/// lowercase `b` is BYTES.
///
/// The bit reading exists for the Line speed box, where every ISP
/// quotes megaBITS. A file-size rule shares the parser but not the
/// convention: indexers, newsreaders and file managers all print a
/// release as `1.4 GB`, and people type that back in lowercase, so
/// `size<100mb` in an RSS filter or an index gate filtered at 12.5 MB.
/// Nobody bounds a release's size in megabits, so reading every saved
/// `mb`/`gb` rule as bytes gives each one the meaning its author
/// evidently had. The spelled-out `bit`/`bits`/`bps` forms keep their
/// bit meaning: those say so in words, and only the one-letter suffix
/// was ambiguous.
pub fn parse_byte_size(s: &str) -> Option<u64> {
    parse(s, false)
}

fn parse(s: &str, lower_b_is_bits: bool) -> Option<u64> {
    let s = s.trim();
    // BITS when the user says bits, and this is not a nicety: every ISP
    // on earth advertises a line in megaBITS, so "900M" in the Line
    // speed box is what a person with a 900 Mbps connection types - and
    // it was read as 900 MB/s, eight times their actual line. The tuner
    // then scored a perfectly good 37 MB/s as "4% of your line" (field
    // report, 4 Aug).
    //
    // Nothing existing changes meaning: every suffixed form below is
    // REJECTED by this function today (only a bare 900M or 1G parses at
    // all), so this can only turn a refusal into a number. A bare
    // magnitude stays BYTES, because that is what it has always meant
    // here and 29 call sites depend on it - the disk and cache settings
    // are not secretly about bits.
    let s = s
        .strip_suffix("/s")
        .or_else(|| s.strip_suffix("/S"))
        .unwrap_or(s)
        .trim_end();
    // Case matters exactly where the convention says it does: `b` is
    // bits, `B` is bytes. The spelled-out forms are case-insensitive
    // because nobody typing "Mbps" means anything else.
    let lower = s.to_ascii_lowercase();
    let (s, bits) = if let Some(rest) = lower
        .strip_suffix("bits")
        .or_else(|| lower.strip_suffix("bit"))
        .or_else(|| lower.strip_suffix("bps"))
    {
        (&s[..rest.len()], true)
    } else if let Some(rest) = s.strip_suffix('b') {
        (rest, lower_b_is_bits)
    } else if let Some(rest) = s.strip_suffix('B') {
        (rest, false)
    } else {
        (s, false)
    };
    let s = s.trim_end();
    let (num, mult) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1e3),
        'm' | 'M' => (&s[..s.len() - 1], 1e6),
        'g' | 'G' => (&s[..s.len() - 1], 1e9),
        't' | 'T' => (&s[..s.len() - 1], 1e12),
        _ => (s, 1.0),
    };
    let v: f64 = num.trim().parse().ok()?;
    let bytes = if bits { v * mult / 8.0 } else { v * mult };
    (v >= 0.0).then_some(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::{parse_byte_size, parse_size};

    /// A file-size rule's lowercase `mb` is megaBYTES; a line speed's is
    /// still megabits. NEGATIVE CONTROL, run: with `parse_byte_size`
    /// passing `true`, `100mb` reads 12,500,000 and the first assert
    /// fails.
    #[test]
    fn a_file_size_reads_lowercase_b_as_bytes_and_a_rate_as_bits() {
        assert_eq!(parse_byte_size("100mb"), Some(100_000_000));
        assert_eq!(parse_byte_size("1.5gb"), Some(1_500_000_000));
        assert_eq!(parse_byte_size("100MB"), Some(100_000_000));
        assert_eq!(parse_byte_size("100M"), Some(100_000_000));
        assert_eq!(parse_byte_size("4096"), Some(4096));
        // Spelled-out bits say so in words and keep that meaning.
        assert_eq!(parse_byte_size("800Mbit"), Some(100_000_000));
        assert_eq!(parse_byte_size("-1mb"), None);
        assert_eq!(parse_byte_size("nope"), None);
        // The rate parser is unchanged.
        assert_eq!(parse_size("100mb"), Some(12_500_000));
        assert_eq!(parse_size("900Mb"), Some(112_500_000));
        assert_eq!(parse_size("100MB"), Some(100_000_000));
    }
}
