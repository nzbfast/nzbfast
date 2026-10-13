//! The one XML lexer this crate reads wire documents with - RSS and Atom
//! feeds (`rss`), Newznab caps, results and error documents (`newznab`)
//! and both Plex watchlist shapes (`plex`).
//!
//! It is a TOLERANT LEXER, not a validating parser, and that is a
//! decision rather than a shortcut. Feeds in the wild are messy - junk
//! elements, mismatched close tags, half-formed items - and every reader
//! here is required to take what it can out of one rather than refuse
//! the document (`rss::parse_feed_checked` refuses only a body that is
//! not a feed at all). An event reader such as quick-xml stops at the
//! first well-formedness error, so it would turn "one bad item" into
//! "zero items", which is the healthy-and-empty failure every one of
//! these readers was written to avoid. The helpers also hand out `&str`
//! slices of the document, which all three consumers are written around.
//!
//! What it DOES know is the part of the grammar that decides where markup
//! is, which is what the substring scans it replaced did not (13 Oct 2026
//! read-only sweep, F7; and the document-layer half of the 26 Aug sweep's
//! P2-2, which was left open for exactly this):
//!
//! - COMMENTS, CDATA SECTIONS, PROCESSING INSTRUCTIONS AND DECLARATIONS
//!   are opaque. An `<enclosure url=...>` written as example text inside
//!   `<description><![CDATA[...]]></description>` is text, and so is a
//!   commented-out one. A first-match scan used to pick it over the real
//!   enclosure that followed, and its URL became the download target.
//! - QUOTED ATTRIBUTE VALUES are opaque. `url='...'` inside a `title="..."`
//!   value is not a `url` attribute, and a `>` inside a value does not end
//!   the tag.
//! - CDATA IS LITERAL. [`unescape`] decodes entities in ordinary text and
//!   leaves a CDATA section's content exactly as written:
//!   `<![CDATA[Show &amp; Tell]]>` is the eleven characters `Show &amp;
//!   Tell`, not `Show & Tell`.
//!
//! Element names are matched on their LOCAL part, after any `prefix:`:
//! `<atom:entry>` is as good an entry as `<entry>`, and literal-substring
//! scans made every fully-prefixed Atom feed parse to healthy-and-empty
//! (review sweep 5 Aug M9).
//!
//! ONE RULE, ONE COPY: a reader that wants an element, its body or an
//! attribute asks this module. A `find("<item")` beside it reintroduces
//! F7 in that reader alone, which is how newznab came to carry its own
//! copy of the defect after rss's helpers had been fixed once already.

/// Index just past the markup starting at `at` when it is one the scanner
/// steps over whole - a comment, a CDATA section, a processing
/// instruction or a `<!...>` declaration - else `None`.
///
/// An unterminated one swallows the rest of the document, which is what
/// the grammar says: nothing after an unclosed comment is markup.
fn skip_opaque(xml: &str, at: usize) -> Option<usize> {
    let rest = &xml.as_bytes()[at..];
    let past = |open: usize, close: &str| {
        xml[at + open..]
            .find(close)
            .map_or(xml.len(), |e| at + open + e + close.len())
    };
    if rest.starts_with(b"<!--") {
        return Some(past(4, "-->"));
    }
    // Case-blind: `rss::wrong_document` scans a LOWERCASED head.
    if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case(b"<![CDATA[") {
        let close = xml[at + 9..].find("]]>");
        return Some(close.map_or(xml.len(), |e| at + 9 + e + 3));
    }
    if rest.starts_with(b"<?") {
        return Some(past(2, "?>"));
    }
    if rest.starts_with(b"<!") {
        // `<!DOCTYPE rss [ <!ENTITY x "y"> ]>`: the internal subset may
        // hold `>`s of its own, inside brackets and quotes.
        let mut depth = 0usize;
        let mut quote = None;
        for (i, &c) in rest.iter().enumerate().skip(2) {
            match (quote, c) {
                (Some(q), _) if c == q => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(c),
                (None, b'[') => depth += 1,
                (None, b']') => depth = depth.saturating_sub(1),
                (None, b'>') if depth == 0 => return Some(at + i + 1),
                _ => {}
            }
        }
        return Some(xml.len());
    }
    None
}

/// Index of the `>` that closes the tag opened at `open`, stepping over
/// quoted attribute values - `title="a > b"` does not end the tag.
///
/// A quote opens a value only straight after `=` (whitespace allowed),
/// so a stray quote character elsewhere in a malformed tag is just a
/// character. A value that never closes, or that runs into a `<` (which
/// XML forbids in an attribute value, so the quote was broken), falls
/// back to the first raw `>`: the tag a malformed feed most plausibly
/// meant, and what this scanner answered before it knew about quotes.
fn tag_end(xml: &str, open: usize) -> Option<usize> {
    let b = xml.as_bytes();
    let mut quote: Option<u8> = None;
    let mut after_eq = false;
    for (i, &c) in b.iter().enumerate().skip(open + 1) {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) if c == b'<' => break,
            Some(_) => {}
            None => match c {
                b'>' => return Some(i),
                b'<' => break,
                b'"' | b'\'' if after_eq => quote = Some(c),
                b'=' => {
                    after_eq = true;
                    continue;
                }
                c if c.is_ascii_whitespace() => continue,
                _ => {}
            },
        }
        after_eq = false;
    }
    xml[open..].find('>').map(|e| open + e)
}

/// One tag the scanner found: where its `<` is, where its `>` is (the
/// document's end for an unterminated one), and its name as written. An
/// END tag's name carries its leading `/`, so it never equals a start
/// tag's.
#[derive(Clone, Copy)]
struct Tag<'a> {
    at: usize,
    end: usize,
    name: &'a str,
}

/// Every start and end tag in `xml` from byte `from` on, in order, with
/// comments, CDATA, PIs and declarations stepped over whole and each tag
/// stepped over to its quote-aware end.
///
/// A `<` that cannot open a tag (`a < b`, which is malformed but turns up
/// in feeds) is passed over as text rather than taken to the next `>`,
/// which could swallow a real tag after it.
fn tags_from(xml: &str, from: usize) -> impl Iterator<Item = Tag<'_>> {
    let mut i = from;
    std::iter::from_fn(move || {
        loop {
            let lt = i + xml.get(i..)?.find('<')?;
            if let Some(past) = skip_opaque(xml, lt) {
                i = past;
                continue;
            }
            let after = &xml[lt + 1..];
            let body = after.strip_prefix('/').unwrap_or(after);
            let len = body
                .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .unwrap_or(body.len());
            let opens_name = body
                .chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_' || c == ':');
            if len == 0 || !opens_name {
                i = lt + 1;
                continue;
            }
            let name = &after[..len + (after.len() - body.len())];
            let end = tag_end(xml, lt).unwrap_or(xml.len());
            i = end + 1;
            return Some(Tag { at: lt, end, name });
        }
    })
}

/// The local part of an element name: everything after the last `:`.
fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// The names of the start tags in `xml`, in document order - for a
/// caller that only wants to know what elements are there.
pub(crate) fn start_tag_names(xml: &str) -> impl Iterator<Item = &str> {
    tags_from(xml, 0)
        .map(|t| t.name)
        .filter(|n| !n.starts_with('/'))
}

fn start_tags<'a>(xml: &'a str, local: &'a str) -> impl Iterator<Item = Tag<'a>> {
    tags_from(xml, 0).filter(move |t| !t.name.starts_with('/') && local_name(t.name) == local)
}

/// The document's root element as (local name, raw tag text), when
/// nothing but whitespace and opaque markup - an `<?xml?>` declaration, a
/// DOCTYPE, comments, PIs - comes before it. Text ahead of the first tag
/// means this is not an XML document's root at all, and answers `None`.
pub(crate) fn root_tag(xml: &str) -> Option<(&str, &str)> {
    let mut i = 0;
    loop {
        i += xml[i..].len() - xml[i..].trim_start().len();
        match skip_opaque(xml, i) {
            Some(past) if xml[i..].starts_with('<') => i = past,
            _ => break,
        }
    }
    let t = tags_from(xml, i).next().filter(|t| t.at == i)?;
    (!t.name.starts_with('/')).then(|| (local_name(t.name), &xml[t.at..t.end]))
}

/// Raw tag text (`<` up to but excluding `>`) of every start tag in `xml`
/// whose local name is `local`, self-closing included.
pub(crate) fn elem_tags<'a>(xml: &'a str, local: &'a str) -> Vec<&'a str> {
    start_tags(xml, local).map(|t| &xml[t.at..t.end]).collect()
}

/// Every element in `xml` whose local name is `local`, as its raw tag
/// text and its inner XML. The body is `None` for a self-closing element
/// and for one with no closing tag; scanning carries on past either.
///
/// The close is the first `</name>` after the start tag spelled with the
/// SAME prefix, found by the same scanner - so a `</item>` written inside
/// a CDATA description does not end the item early. Scanning resumes
/// after the close, so an element nested inside a match is part of its
/// body rather than a match of its own.
pub(crate) fn elements<'a>(xml: &'a str, local: &'a str) -> Vec<(&'a str, Option<&'a str>)> {
    let mut out = Vec::new();
    let mut from = 0;
    // A name whose close search has failed once fails from every later
    // position too, so it is not searched for again: a body of ten
    // thousand unclosed `<item>`s costs one pass, not ten thousand.
    let mut unclosed: Vec<&str> = Vec::new();
    while let Some(t) =
        tags_from(xml, from).find(|t| !t.name.starts_with('/') && local_name(t.name) == local)
    {
        let tag = &xml[t.at..t.end];
        from = t.end + 1;
        if tag.ends_with('/') || unclosed.contains(&t.name) {
            out.push((tag, None));
            continue;
        }
        let close = tags_from(xml, from).find(|c| c.name.strip_prefix('/') == Some(t.name));
        match close {
            Some(c) => {
                out.push((tag, Some(&xml[from..c.at])));
                from = c.end + 1;
            }
            None => {
                unclosed.push(t.name);
                out.push((tag, None));
            }
        }
    }
    out
}

/// The trimmed inner XML of the first element named `tag` that has a
/// closing tag. Self-closing and unclosed matches are passed over: an RSS
/// item can carry a self-closing `<atom:link rel="self"/>` ahead of the
/// `<link>` whose text is wanted.
pub(crate) fn tag_text<'a>(xml: &'a str, tag: &'a str) -> Option<&'a str> {
    elements(xml, tag)
        .into_iter()
        .find_map(|(_, body)| body)
        .map(str::trim)
}

/// The value of attribute `name` in a start tag, read to the XML
/// attribute grammar: attributes are walked in order, so a name that
/// appears inside ANOTHER attribute's quoted value is never matched -
/// `<enclosure title="see url='decoy'" url="real">` answers `real`.
///
/// Single and double quotes are both legal, whitespace either side of `=`
/// is legal, and the name is matched whole (asking for `url` never finds
/// the tail of `xmlUrl=`). An unquoted or unterminated value is not XML
/// and is never returned. The value is returned RAW; entity decoding is
/// the caller's, through [`unescape`].
///
/// `tag` is the raw text [`elem_tags`] hands out (`<name attr=...`); a
/// fragment that does not start with `<` is read as attributes from its
/// first byte.
pub(crate) fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let b = tag.as_bytes();
    let is_sep = |c: u8| c.is_ascii_whitespace() || c == b'/';
    let skip_ws = |mut j: usize| {
        while b.get(j).is_some_and(u8::is_ascii_whitespace) {
            j += 1;
        }
        j
    };
    let mut i = 0;
    if b.first() == Some(&b'<') {
        i = 1;
        while b.get(i).is_some_and(|&c| !is_sep(c) && c != b'>') {
            i += 1;
        }
    }
    loop {
        while b.get(i).is_some_and(|&c| is_sep(c)) {
            i += 1;
        }
        if b.get(i).is_none_or(|&c| c == b'>') {
            return None;
        }
        let key_at = i;
        while b
            .get(i)
            .is_some_and(|&c| !is_sep(c) && !matches!(c, b'=' | b'>' | b'"' | b'\''))
        {
            i += 1;
        }
        let key = &tag[key_at..i];
        let eq = skip_ws(i);
        if b.get(eq) != Some(&b'=') {
            // A valueless name, or a stray quote with no name before it.
            if key.is_empty() {
                i += 1;
            }
            continue;
        }
        let v = skip_ws(eq + 1);
        match b.get(v) {
            Some(&q @ (b'"' | b'\'')) => {
                let end = v + 1 + tag[v + 1..].find(q as char)?;
                if key == name {
                    return Some(&tag[v + 1..end]);
                }
                i = end + 1;
            }
            // Unquoted: step over it as one token, never answer it.
            _ => {
                i = v;
                while b
                    .get(i)
                    .is_some_and(|&c| !c.is_ascii_whitespace() && c != b'>')
                {
                    i += 1;
                }
            }
        }
    }
}

/// Character data as the document means it: entities decoded in ordinary
/// text, CDATA sections kept LITERAL with their markers removed, and
/// comments dropped (a comment is not character data).
///
/// ONE LEFT-TO-RIGHT PASS, which is what makes `&amp;` safe rather than
/// an ordering rule to remember. The chain of `replace` calls this used
/// to be had to decode `&amp;` LAST - doing it first turns `&amp;lt;` (an
/// escaped literal "&lt;") into `&lt;`, which the next pass then wrongly
/// decodes to "<". A single scan never revisits what it has already
/// emitted, so the hazard cannot arise.
///
/// NUMERIC CHARACTER REFERENCES are decoded too, decimal and hex. In a
/// feed's `<link>` that is not cosmetic: `&#35;` left as four characters
/// handed an indexer URL on with a fragment marker the server never sees,
/// silently truncating the query.
pub(crate) fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(['&', '<']) {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        if let Some(body) = rest.strip_prefix("<![CDATA[") {
            let end = body.find("]]>").unwrap_or(body.len());
            out.push_str(&body[..end]);
            rest = body.get(end + 3..).unwrap_or("");
            continue;
        }
        if let Some(body) = rest.strip_prefix("<!--") {
            rest = body.find("-->").map_or("", |e| &body[e + 3..]);
            continue;
        }
        if rest.starts_with('<') {
            out.push('<');
            rest = &rest[1..];
            continue;
        }
        // Bounded: an unterminated `&` must not scan to the end of a
        // megabyte of feed, and anything that reaches whitespace or a
        // second `&` was never an entity to begin with.
        let semi = rest
            .char_indices()
            .skip(1)
            .take(12)
            .find(|(_, c)| *c == ';' || *c == '&' || c.is_whitespace())
            .filter(|(_, c)| *c == ';')
            .map(|(i, _)| i);
        let decoded = semi.and_then(|semi| match &rest[1..semi] {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "amp" => Some('&'),
            n => n.strip_prefix('#').and_then(|n| {
                match n.strip_prefix(['x', 'X']) {
                    Some(h) => u32::from_str_radix(h, 16).ok(),
                    None => n.parse::<u32>().ok(),
                }
                .and_then(char::from_u32)
            }),
        });
        match (decoded, semi) {
            (Some(c), Some(semi)) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            // Not an entity: the `&` is a literal.
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_cdata_pis_and_declarations_hide_their_markup() {
        let xml = r#"<?xml version="1.0"?><!DOCTYPE rss [ <!ENTITY e "<item>"> ]>
<!-- <item>commented</item> --><x><![CDATA[<item>cdata</item>]]></x>
<?pi <item>pi</item> ?><item>real</item>"#;
        let names: Vec<&str> = start_tag_names(xml).collect();
        assert_eq!(names, ["x", "item"]);
        assert_eq!(tag_text(xml, "item"), Some("real"));
    }

    #[test]
    fn the_root_is_the_first_tag_after_prolog_markup_only() {
        let doc = "<?xml version=\"1.0\"?>\n<!-- c --><!DOCTYPE x><n:error code=\"1\"/>";
        assert_eq!(root_tag(doc), Some(("error", r#"<n:error code="1"/"#)));
        assert_eq!(root_tag("junk <error/>"), None);
        assert_eq!(root_tag("</error>"), None);
        assert_eq!(root_tag(""), None);
    }

    #[test]
    fn a_quoted_gt_does_not_end_the_tag() {
        let xml = r#"<enclosure title="a > b" url="u"/><next/>"#;
        assert_eq!(
            elem_tags(xml, "enclosure"),
            [r#"<enclosure title="a > b" url="u"/"#]
        );
        assert_eq!(
            start_tag_names(xml).collect::<Vec<_>>(),
            ["enclosure", "next"]
        );
    }

    #[test]
    fn a_broken_quote_falls_back_to_the_first_gt() {
        // Unterminated, and running into a `<`: both read as the tag the
        // malformed feed most plausibly meant.
        assert_eq!(elem_tags(r#"<a x="oops><b/>"#, "a"), [r#"<a x="oops"#]);
        assert_eq!(
            start_tag_names(r#"<a x="oops><b/>"#).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn a_stray_lt_in_text_does_not_swallow_the_next_tag() {
        let xml = "<t>a < b</t><u>x</u>";
        assert_eq!(tag_text(xml, "t"), Some("a < b"));
        assert_eq!(tag_text(xml, "u"), Some("x"));
    }

    #[test]
    fn an_attribute_name_inside_another_value_is_not_an_attribute() {
        let tag =
            r#"<enclosure title="Example url='https://x/decoy.nzb'" url="https://x/real.nzb""#;
        assert_eq!(attr(tag, "url"), Some("https://x/real.nzb"));
        let tag = r#"<e a='b="decoy"' b="real""#;
        assert_eq!(attr(tag, "b"), Some("real"));
        // A valueless (HTML-ish) attribute ahead of the wanted one.
        assert_eq!(attr(r#"<e hidden url="u""#, "url"), Some("u"));
        // An unquoted value is stepped over, not mistaken for names.
        assert_eq!(attr(r#"<e a=url="x" url="y""#, "url"), Some("y"));
    }

    #[test]
    fn cdata_is_literal_and_comments_are_not_text() {
        assert_eq!(unescape("<![CDATA[Show &amp; Tell]]>"), "Show &amp; Tell");
        assert_eq!(unescape("a &amp; <![CDATA[&lt;]]> &lt;"), "a & &lt; <");
        assert_eq!(unescape("a<!-- &amp; -->b"), "ab");
        assert_eq!(
            unescape("<![CDATA[unterminated &amp;"),
            "unterminated &amp;"
        );
    }

    #[test]
    fn elements_close_on_the_same_prefix_and_skip_cdata_closes() {
        let xml = "<a:i><d><![CDATA[</a:i>]]></d>1</a:i><a:i/><a:i>2</a:i>";
        let got: Vec<_> = elements(xml, "i").into_iter().map(|(_, b)| b).collect();
        assert_eq!(got, [Some("<d><![CDATA[</a:i>]]></d>1"), None, Some("2")]);
    }

    #[test]
    fn an_unclosed_element_does_not_hide_a_differently_prefixed_one() {
        // The give-up-on-this-name shortcut is per spelling: `<a:i>`
        // never closing says nothing about `<b:i>`.
        let xml = "<a:i>x<a:i>y<b:i>z</b:i>";
        let got: Vec<_> = elements(xml, "i").into_iter().map(|(_, b)| b).collect();
        assert_eq!(got, [None, None, Some("z")]);
    }

    /// Every entry point over deterministic token soup, multibyte text
    /// included: the lexer slices `&str` by byte offset, and an offset
    /// off a char boundary is a panic in a reader fed untrusted bodies.
    #[test]
    fn token_soup_never_panics() {
        const TOKS: [&str; 24] = [
            "<",
            ">",
            "/",
            "=",
            "\"",
            "'",
            " ",
            "<item",
            "</item>",
            "<![CDATA[",
            "]]>",
            "<!--",
            "-->",
            "<?",
            "?>",
            "<!DOCTYPE",
            "[",
            "]",
            "url",
            "&amp;",
            "&#x",
            "é",
            "\u{1F600}",
            "a:",
        ];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut bytes = 0usize;
        for _ in 0..20_000 {
            let mut doc = String::new();
            for _ in 0..(next() % 40) {
                doc.push_str(TOKS[(next() % TOKS.len() as u64) as usize]);
            }
            bytes += doc.len();
            for (tag, body) in elements(&doc, "item") {
                let _ = (attr(tag, "url"), body.map(unescape));
            }
            let _ = (root_tag(&doc), tag_text(&doc, "item"), unescape(&doc));
            let _ = start_tag_names(&doc).count();
            for tag in elem_tags(&doc, "item") {
                let _ = attr(tag, "a");
            }
        }
        // The soup is soup: a generator stuck on empty documents proves
        // nothing (this test's first draft was one).
        assert!(bytes > 20_000 * 40, "{bytes}");
    }
}
