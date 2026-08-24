//! Human size and rate strings, in the one direction this crate needs
//! them: `"500M"` / `"10G"` / `"1.5T"` / `"900Mb"` -> bytes.
//!
//! One function, at the crate root rather than under `serve/`, because
//! `gates`, `rss` and `smart` all parse the same strings and reaching
//! for `crate::serve::parse_size` to do it made three modules depend on
//! the daemon (TODO 276 item 3). `serve` re-exports it, so its own ~29
//! call sites are unchanged.

/// Parse "500M"/"10G"/"1.5T" (SAB-style size strings) to bytes.
pub fn parse_size(s: &str) -> Option<u64> {
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
        (rest, true)
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
