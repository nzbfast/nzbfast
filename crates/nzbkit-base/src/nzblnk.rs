//! NZBLNK links (spec: <https://nzblnk.info/>) - the German/Dutch board
//! convention for handing out an obfuscated post without an NZB file.
//!
//! ```text
//! nzblnk:?t=Our+Sommervacation&h=fbzzreinpngvba&g=a.b.documentaries&p=v4c4t10n4tw1n
//! ```
//!
//! The link carries no article ids at all. `h` is a HEADER: a string
//! distinctive enough to find the posting in a raw-header index, which
//! the client then rebuilds an NZB from. That is why the format exists
//! on boards that post obfuscated releases - there is nothing to link to
//! until someone has scanned the group.
//!
//! Per the spec `h` and `t` are both mandatory, but real links in the
//! wild routinely omit `t` (the board's own thread title is the label),
//! so only `h` is required here and a missing title falls back to the
//! header. Everything else is optional: `p` is the archive password and
//! `g` names a group to search, and MAY repeat.
//!
//! This module is pure text: parsing only, no I/O and no lookups. What
//! to do with the header afterwards - our own index first, then the
//! user's configured indexers - is the daemon's ladder.

/// A parsed NZBLNK link.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NzbLnk {
    /// The `h` parameter: what to search the header pool for. Required,
    /// never empty.
    pub header: String,
    /// The `t` parameter, or the header when the link carried no title.
    /// Becomes the job (and output folder) name.
    pub title: String,
    /// The `p` parameter; empty when absent. Feeds the job password, so
    /// an encrypted archive unlocks without the user typing anything.
    pub password: String,
    /// The `g` parameters, in link order, deduped. Empty when absent -
    /// a hint about where to look, never a requirement.
    pub groups: Vec<String>,
}

/// Why a string is not a usable NZBLNK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NzbLnkError {
    /// Not an `nzblnk:` link at all.
    NotALink,
    /// An `nzblnk:` link with no `h`, or an `h` that decoded to nothing.
    NoHeader,
}

impl std::fmt::Display for NzbLnkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NzbLnkError::NotALink => "that is not an nzblnk link",
            NzbLnkError::NoHeader => "the nzblnk link has no header to search for",
        })
    }
}

impl std::error::Error for NzbLnkError {}

/// Defensive caps. A link is pasted text from a web page, so every field
/// is attacker-shaped; none of these should ever bind on a real link.
const MAX_HEADER: usize = 1024;
const MAX_TITLE: usize = 512;
const MAX_PASSWORD: usize = 512;
const MAX_GROUPS: usize = 32;

/// Cheap scheme test, for deciding whether a pasted string is ours
/// before paying for a parse. Case-insensitive: links arrive from HTML
/// where the scheme may be spelled `NZBLNK:`.
pub fn looks_like(s: &str) -> bool {
    // Bytes, not `&t[..7]`: the slice would panic on a paste whose 8th
    // byte lands inside a multi-byte character, and everything reaching
    // here is attacker-shaped text.
    let t = trim_wrapping(s).as_bytes();
    t.len() >= 7 && t[..7].eq_ignore_ascii_case(b"nzblnk:")
}

/// Peel the punctuation a paste drags along: surrounding whitespace,
/// angle brackets (mail/forum auto-linking), and quotes.
///
/// Matched pairs come off first, then a LEADING-only bracket or quote -
/// a half-selected copy is common, and nothing legal can precede the
/// scheme anyway. A trailing-only one is deliberately left alone: the
/// last character of a link is part of a value, and a password is
/// allowed to end in a quote.
fn trim_wrapping(s: &str) -> &str {
    let mut t = s.trim();
    loop {
        let before = t;
        t = t.trim();
        if let Some(inner) = t.strip_prefix('<').and_then(|r| r.strip_suffix('>')) {
            t = inner;
        }
        for q in ['"', '\''] {
            if t.len() >= 2 && t.starts_with(q) && t.ends_with(q) {
                t = &t[1..t.len() - 1];
            }
        }
        t = t.trim_start_matches(['<', '"', '\'']);
        if t == before {
            return t;
        }
    }
}

/// Percent-decode one query component. `+` is a space (the spec's own
/// example encodes "Our Sommervacation" that way), and a `%` that is not
/// followed by two hex digits stays literal rather than eating the next
/// characters - passwords are full of stray punctuation and a strict
/// reader would mangle them.
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                };
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push(h << 4 | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A group name as usenet spells one. Anything else in a `g` is dropped
/// rather than failing the link: the groups are only a search hint, and
/// a board that mistypes one must not cost the user the download.
fn is_group(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b'+'))
        && s.contains('.')
}

/// Keep the first `n` characters (not bytes) of `s`.
fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

/// Parse one NZBLNK.
///
/// Accepts `nzblnk:?…` and the `nzblnk://?…` spelling some board
/// software emits, with or without the `?`. Unknown parameters are
/// ignored (the format is meant to grow), a repeated single-valued
/// parameter keeps its FIRST value, and `g` accumulates.
pub fn parse(s: &str) -> Result<NzbLnk, NzbLnkError> {
    let t = trim_wrapping(s);
    if !looks_like(t) {
        return Err(NzbLnkError::NotALink);
    }
    let rest = &t[7..];
    // `//` authority (nzblnk://?h=…) and a bare leading `/` both appear
    // in the wild; the query may or may not be introduced by `?`.
    let rest = rest.trim_start_matches('/');
    let rest = rest.strip_prefix('?').unwrap_or(rest);
    // A fragment is not part of the query - a link pasted out of a page
    // anchor can carry one.
    let query = rest.split('#').next().unwrap_or("");

    let mut out = NzbLnk::default();
    let mut header: Option<String> = None;
    let mut title: Option<String> = None;
    let mut password: Option<String> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(k.trim()).trim().to_ascii_lowercase();
        let val = decode(v);
        match key.as_str() {
            "h" if header.is_none() => header = Some(val.trim().to_string()),
            "t" if title.is_none() => title = Some(val.trim().to_string()),
            // A password is taken verbatim: leading and trailing spaces
            // are legal in one, and trimming would lock the user out of
            // their own archive.
            "p" if password.is_none() => password = Some(val),
            "g" => {
                let g = val.trim().to_ascii_lowercase();
                if is_group(&g) && !out.groups.contains(&g) && out.groups.len() < MAX_GROUPS {
                    out.groups.push(g);
                }
            }
            _ => {}
        }
    }

    let header = header
        .filter(|h| !h.is_empty())
        .ok_or(NzbLnkError::NoHeader)?;
    out.header = clip(&header, MAX_HEADER);
    out.title = match title {
        Some(t) if !t.is_empty() => clip(&t, MAX_TITLE),
        // Clipped to MAX_TITLE too. The header's own cap is MAX_HEADER
        // (1024), so a link with a long header and no `t` - the common
        // shape, since boards label the link with their thread title -
        // handed back a 1024-char title, twice the documented cap the
        // resolution ladder and the UI rely on. It reaches a filesystem
        // stem, and nothing in the naming path caps length. Found by
        // `nzblnk_parse` fuzzing, 30 Jul.
        _ => clip(&out.header, MAX_TITLE),
    };
    out.password = clip(&password.unwrap_or_default(), MAX_PASSWORD);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example() {
        let l = parse(
            "nzblnk:?t=Our+Sommervacation&h=fbzzreinpngvba&g=a.b.documentaries&p=v4c4t10n4tw1n",
        )
        .unwrap();
        assert_eq!(l.header, "fbzzreinpngvba");
        assert_eq!(l.title, "Our Sommervacation");
        assert_eq!(l.password, "v4c4t10n4tw1n");
        assert_eq!(l.groups, vec!["a.b.documentaries"]);
    }

    #[test]
    fn order_is_not_significant() {
        let a = parse("nzblnk:?h=abc&t=Title").unwrap();
        let b = parse("nzblnk:?t=Title&h=abc").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn header_only_falls_back_to_the_header_as_title() {
        let l = parse("nzblnk:?h=8f3ac91e").unwrap();
        assert_eq!(l.header, "8f3ac91e");
        assert_eq!(l.title, "8f3ac91e");
        assert!(l.password.is_empty());
        assert!(l.groups.is_empty());
    }

    #[test]
    fn percent_and_plus_decoding() {
        let l = parse("nzblnk:?h=a%20b%2Bc&t=Gr%C3%BC%C3%9Fe+aus+K%C3%B6ln&p=p%25w%2Bd").unwrap();
        // %20 is a space, %2B is a literal plus.
        assert_eq!(l.header, "a b+c");
        assert_eq!(l.title, "Grüße aus Köln");
        assert_eq!(l.password, "p%w+d");
    }

    #[test]
    fn a_stray_percent_stays_literal() {
        // A password of "100%sure" pasted unencoded must survive.
        let l = parse("nzblnk:?h=x.y&p=100%sure").unwrap();
        assert_eq!(l.password, "100%sure");
        // ...and a truncated escape at the very end too.
        assert_eq!(parse("nzblnk:?h=x.y&p=ab%2").unwrap().password, "ab%2");
    }

    #[test]
    fn password_keeps_its_spaces() {
        let l = parse("nzblnk:?h=abc&p=%20hunter2%20").unwrap();
        assert_eq!(l.password, " hunter2 ");
    }

    #[test]
    fn repeated_groups_accumulate_and_dedupe() {
        let l = parse(
            "nzblnk:?h=abc&g=alt.binaries.boneless&g=ALT.BINARIES.Boneless&g=alt.binaries.misc",
        )
        .unwrap();
        assert_eq!(l.groups, vec!["alt.binaries.boneless", "alt.binaries.misc"]);
    }

    #[test]
    fn a_repeated_single_valued_param_keeps_the_first() {
        let l = parse("nzblnk:?h=first&h=second&t=A&t=B&p=one&p=two").unwrap();
        assert_eq!(l.header, "first");
        assert_eq!(l.title, "A");
        assert_eq!(l.password, "one");
    }

    #[test]
    fn junk_groups_are_dropped_not_fatal() {
        let l = parse("nzblnk:?h=abc&g=not a group&g=nodot&g=alt.binaries.ok").unwrap();
        assert_eq!(l.groups, vec!["alt.binaries.ok"]);
    }

    #[test]
    fn scheme_spellings() {
        for s in [
            "nzblnk:?h=abc",
            "NZBLNK:?h=abc",
            "nzblnk://?h=abc",
            "nzblnk:h=abc",
            "  nzblnk:?h=abc  ",
            "<nzblnk:?h=abc>",
            "\"nzblnk:?h=abc\"",
            // Half-selected copies out of a page: the leading bracket or
            // quote has no partner. `looks_like` and `parse` must agree,
            // or the UI accepts what the daemon then refuses.
            "\"nzblnk:?h=abc",
            "<nzblnk:?h=abc",
        ] {
            assert_eq!(parse(s).unwrap().header, "abc", "{s}");
            assert!(looks_like(s), "{s}");
        }
    }

    /// Everything here is pasted text, so no input may panic - and the
    /// prefix test used to slice at byte 7, which is inside a character
    /// for plenty of real strings.
    #[test]
    fn hostile_input_never_panics() {
        let cases = [
            "nzblnké",
            "aaaaaaé",
            "«nzblnk:?h=abc»",
            "nzblnk:?h=é",
            "\u{feff}nzblnk:?h=abc",
            "nzblnk:?h=%FF%FE%00",
            "nzblnk:?%=%&&&==&h=ok.value",
            "nzblnk:?h=a&g=\u{202e}reversed.group",
        ];
        for s in cases {
            let _ = looks_like(s);
            let _ = parse(s);
        }
        // Every byte pattern of a short link, as UTF-8 as we can make it.
        for b in 0u8..=255 {
            let s = format!("nzblnk:?h=ab{}cd", b as char);
            let _ = parse(&s);
            let _ = looks_like(&s);
            let _ = parse(&format!("{}nzblnk:?h=abcd", b as char));
        }
    }

    #[test]
    fn fragments_and_unknown_params_are_ignored() {
        let l = parse("nzblnk:?h=abc&x=1&nzb=whatever#post-42").unwrap();
        assert_eq!(l.header, "abc");
        assert_eq!(l.title, "abc");
    }

    #[test]
    fn junk_is_rejected() {
        for s in [
            "",
            "   ",
            "hello",
            "http://example.invalid/x.nzb",
            "nzb:?h=abc",
            "nzblnk",
        ] {
            assert_eq!(parse(s), Err(NzbLnkError::NotALink), "{s}");
            assert!(!looks_like(s), "{s}");
        }
        for s in [
            "nzblnk:",
            "nzblnk:?",
            "nzblnk:?t=Title&p=pw",
            "nzblnk:?h=",
            "nzblnk:?h=%20%20",
        ] {
            assert_eq!(parse(s), Err(NzbLnkError::NoHeader), "{s}");
        }
    }

    #[test]
    fn oversized_fields_are_clipped() {
        let long = "a".repeat(4000);
        let l = parse(&format!("nzblnk:?h={long}&t={long}&p={long}")).unwrap();
        assert_eq!(l.header.len(), MAX_HEADER);
        assert_eq!(l.title.len(), MAX_TITLE);
        assert_eq!(l.password.len(), MAX_PASSWORD);
        let many: String = (0..80)
            .map(|i| format!("&g=alt.binaries.g{i}"))
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(
            parse(&format!("nzblnk:?h=abc{many}")).unwrap().groups.len(),
            MAX_GROUPS
        );
        // The title FALLBACK is capped too, not just an explicit `t`. A long
        // header with no title used to hand back MAX_HEADER (1024) chars of
        // title - twice the cap - which reaches the UI and a filesystem stem.
        // Both fuzz artifacts on 30 Jul were this. Multi-byte chars because
        // the cap counts chars, not bytes.
        let l = parse(&format!("nzblnk:?h={long}")).unwrap();
        assert_eq!(l.title.chars().count(), MAX_TITLE);
        let wide = "ü".repeat(4000);
        let l = parse(&format!("nzblnk:?h={wide}")).unwrap();
        assert_eq!(l.title.chars().count(), MAX_TITLE);
        assert_eq!(l.header.chars().count(), MAX_HEADER);
    }

    #[test]
    fn a_header_may_be_a_whole_subject_line() {
        // Some boards paste the article subject verbatim.
        let l = parse("nzblnk:?h=%5B01%2F42%5D+-+%22xyz.part01.rar%22+yEnc&t=Film").unwrap();
        assert_eq!(l.header, "[01/42] - \"xyz.part01.rar\" yEnc");
    }
}
