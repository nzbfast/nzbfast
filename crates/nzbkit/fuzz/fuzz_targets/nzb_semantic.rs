#![no_main]
//! Semantic/differential fuzz over the NZB MANIFEST (addendum row N6-14).
//!
//! `nzb_parse` feeds arbitrary bytes to `Nzb::parse` and asks one
//! question: did it panic, hang or read out of bounds? Every row in the
//! 30 Aug 2026 parser/front-door addendum that matters most is exit-0 to
//! that question - the file PARSES, successfully, into a manifest that
//! is missing a payload or has reclassified one, and the reduced
//! manifest then completes green because every later count agrees with
//! it. A self-closing `<file/>` disappearing (N6-01), a nested `<file>`
//! clobbering its parent (N6-03), a namespaced `x:subject` overwriting
//! the core one (N6-02): all three are a clean `Ok(Nzb { .. })`.
//!
//! So this target does not fuzz BYTES, it fuzzes a MODEL. The fuzzer's
//! input is read as a stream of small choices that build a manifest -
//! files, segments, groups, meta - which is then RENDERED to XML three
//! times under independently chosen but semantically EQUIVALENT styles
//! (attribute order, named versus numeric character references, CDATA
//! versus text, a comment splitting a text node, formatting whitespace,
//! namespace prefix versus default `xmlns`, apostrophe versus quote
//! delimiters, `<groups>` before or after `<segments>`). Two things are
//! then asserted:
//!
//! * **differential** - all three renderings must parse to the SAME
//!   `Nzb`. Whatever policy the parser settles on, it has to settle on
//!   the same one for every legal spelling of one document. This is the
//!   arm that covers N6-02 (attribute order deciding which value wins)
//!   and the representation half of N6-06/N6-12 (entity versus literal).
//! * **accounting** - a well-formed document parses; the parsed file
//!   count equals the DECLARED `<file>` count; and for each file
//!   `segments.len() + dropped_segments` equals the declared segment
//!   count. Nothing declared may leave without being charged. That is
//!   the arm that covers N6-01 and N6-03, and it is the property the
//!   addendum names as the completion rule for the whole section.
//!
//! Everything asserted here is deliberately POLICY-FREE. It never says
//! what a malformed `bytes=` should mean, whether `trim()` may eat a
//! non-breaking space, or which of two quoted names is the filename -
//! those are the sibling rows N6-04..N6-08, owned by other lanes, and a
//! fuzz target that pinned today's answer to them would go red on their
//! fix rather than on a regression. What it does assert about numbers is
//! the one half no policy can move: a WELL-FORMED in-range decimal must
//! survive as its own value (N6-08's "must not become a valid zero" seen
//! from the safe side).
//!
//! ## Hostile shapes, and the `EMIT_*` flags that used to gate them
//!
//! This target shipped with three shapes behind `EMIT_*` flags, off,
//! because they were LIVE BUGS with a fix owned by claim
//! `nzb-manifest-integrity`. All three flags are retired, and the way
//! each one retired is worth reading before adding a fourth.
//!
//! * N6-01, `<file .../>` self-closing - FIXED in `dd479f9b4`, and the
//!   shape is now ordinary legal input: an empty element is charged one
//!   `dropped_segments` like a `<segment/>`. Generated unconditionally.
//! * N6-02, a foreign-namespace attribute whose local name is core
//!   vocabulary - FIXED in the same commit by `core_attr`, which reads a
//!   PREFIXED attribute as somebody else's. Also ordinary legal input
//!   now: `x:subject` is ignored in either attribute order, and the
//!   differential arm is what says so. Generated unconditionally.
//! * N6-03, a `<file>` nested in a `<file>` and two concatenated `<nzb>`
//!   roots - FIXED in the same commit by the context stack, and these
//!   two did NOT become legal: they are `Schema` REFUSALS. So the flag
//!   did not flip, the shape MOVED, into the hostile arm below. That is
//!   the retirement this file's original instruction ("flip the flag to
//!   `true`") did not anticipate, and it is the likelier one: a fix for
//!   a silent-loss row usually turns the input into an honest refusal
//!   rather than into something accepted.
//!
//! ## The hostile arm (T6 and F7, 31 Aug 2026)
//!
//! Everything above fuzzes documents that PARSE. Two whole classes of
//! answer could not be reached at all:
//!
//! * a `Schema` refusal (T6). `Nzb::parse` refuses a wrong root, a
//!   second root, and a core element in a place the NZB grammar has no
//!   slot for. WHICH documents those are is policy; that the ANSWER does
//!   not depend on how the document is SPELLED is not. So the hostile
//!   arm renders one violation under three styles and asserts all three
//!   are refused with the same error class - the row's own oracle 3
//!   (namespace extensions) and oracle 4 (attribute order), asked of a
//!   refusal instead of of a manifest.
//! * the N6-09 ceilings and the `Over` latch (F7). `nzb_parse` feeds
//!   arbitrary BYTES, so it would have to mutate its way to a 4097-byte
//!   attribute or a 1,000,001-segment manifest, and at the README's
//!   1 MiB `max_len` it cannot get near either. Nothing in either fuzz
//!   target had ever executed a line of the ceiling code.
//!
//! The ceiling half is not a second copy of
//! `nzb_tests::structural_ceilings_refuse_a_dense_manifest`, and the
//! difference is where the state space is. A COUNT ceiling has one
//! shape - there is exactly one way to declare too many segments - and
//! that test already pins it in both segment spellings. The FIELD
//! ceilings do not: `push_capped` is applied per TEXT FRAGMENT, so a
//! value crosses `MAX_FIELD` differently depending on how many
//! fragments it arrives in, how big the crossing one is, and whether it
//! came as literal text, as character references (one event each), as
//! CDATA, or split by a comment. That is the arithmetic this arm exists
//! for, and its invariant is exact rather than approximate: a value is
//! kept if and only if the whole accumulation fits, and one that does
//! not fit is DROPPED - never retained as a prefix, because half a
//! password is a wrong password and half a message-id is an article
//! nobody posted.
//!
//! Do NOT satisfy a failure here by weakening a style so two renderings
//! stop differing, and do NOT delete an assertion so the survivors
//! agree: both are the same edit as deleting the target.

use libfuzzer_sys::fuzz_target;
use nzbkit::nzb::{limits, Nzb, NzbError};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The namespace every real NZB declares. Both rendering styles put the
/// core vocabulary IN it - one as the default `xmlns`, one behind a
/// prefix - which is load-bearing rather than decorative since
/// `dd479f9b4`: dispatch is by RESOLVED namespace now, not by local name,
/// so a document whose core elements were not in it would take the
/// extension path wholesale and parse as an empty manifest.
const NZB_NS: &str = "http://www.newzbin.com/DTD/2003/nzb";

/// Names chosen to reach the classification and split-archive rules as
/// well as the escaping ones: PAR2 index and both recovery-volume
/// spellings, the unquoted `.NNN` split shapes of N6-07, a name whose
/// `.par2` is followed by more text (N6-05), and one of each character
/// that has to be escaped in an attribute.
const NAMES: &[&str] = &[
    "Movie.2026.1080p.mkv",
    "release.part01.rar",
    "release.vol000+10.par2",
    "release.vol-01.par2",
    "release.par2",
    "release.zip.001",
    "archive.7z.001",
    "payload.001",
    "Show.S01E01",
    "ordinary.par2 notes.txt",
    "a&b.mkv",
    "quote\"name.mkv",
    "apos'name.mkv",
    "angle<gt>.mkv",
    "Uenicode-\u{fc}\u{e4}\u{f6}.mkv",
    "spaced name.part1.rar",
    "8c63a701",
];

/// Posters carry the same escaping surface as subjects and nothing else.
const POSTERS: &[&str] = &[
    "poster@news.example",
    "A. Poster <poster@news.example>",
    "p&w@news.example",
    "",
];

/// `date` is parsed with `unwrap_or(0)`, so malformed values are here for
/// the DIFFERENTIAL only - no absolute assertion reads them.
const DATES: &[&str] = &["1690000000", "0", "-5", "abc", "", "99999999999999999999"];

/// Group names, including ones the parser must refuse (interior
/// whitespace is not wire-safe) and ones only formatting whitespace
/// separates from a legal name.
const GROUPS: &[&str] = &[
    "alt.binaries.test",
    "alt.binaries.multimedia",
    "alt.bin&ary",
    "  alt.binaries.padded  ",
    "has space",
    "",
    "\u{a0}alt.binaries.nbsp\u{a0}",
];

/// Message-ids: legal, refused (empty, interior whitespace, angle
/// brackets - N6-13's bracketed shape), and boundary-whitespace ones that
/// N6-06 is about.
const IDS: &[&str] = &[
    "part1@news.example",
    "abc.def.123@news.example",
    "a&b@news.example",
    "<bracketed@news.example>",
    "has space@news.example",
    "",
    "   ",
    "\u{a0}nbsp@news.example",
    "\u{2003}emsp@news.example\u{2003}",
];

/// `bytes` / `number` attribute text. The first four are well formed and
/// in range, which is what the one numeric assertion below reads; the
/// rest are N6-08's shapes and are differential-only.
const NUMS: &[&str] = &[
    "1",
    "42",
    "100000",
    "4294967295",
    "0",
    "-1",
    "abc",
    "",
    "99999999999999999999999",
    " 7 ",
    "+3",
];

const META_TYPES: &[&str] = &["password", "PASSWORD", " category ", "title", "", "x&y"];
const META_VALUES: &[&str] = &[
    "secret",
    "secret & more",
    "  padded  ",
    "",
    "\u{a0}nbsp\u{a0}",
    "movies > hd",
];

/// The fuzzer's bytes, read as a stream of small choices - the same
/// shape `par2_verify_diff` uses, and for the same reason: a derive on
/// `arbitrary` would put a dependency between the corpus format and a
/// crate version, and this needs only "give me a number under n".
struct Src<'a> {
    d: &'a [u8],
    i: usize,
}

impl<'a> Src<'a> {
    fn new(d: &'a [u8]) -> Self {
        Src { d, i: 0 }
    }
    fn byte(&mut self) -> u8 {
        let b = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        b
    }
    fn upto(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            self.byte() as usize % n
        }
    }
    fn pick<'t>(&mut self, xs: &[&'t str]) -> &'t str {
        xs[self.upto(xs.len())]
    }
    fn flag(&mut self) -> bool {
        self.byte() & 1 == 1
    }
}

/// One declared segment, held as the ATTRIBUTE TEXT rather than as
/// numbers: a malformed `bytes=` is a case this target must be able to
/// spell, and it can only be spelled before parsing.
struct MSeg {
    number: &'static str,
    bytes: &'static str,
    id: &'static str,
    /// Written `<segment .../>`: no message-id by construction, and the
    /// parser owes it a `dropped_segments` charge.
    self_closing: bool,
}

struct MFile {
    subject: String,
    poster: &'static str,
    date: &'static str,
    groups: Vec<&'static str>,
    segs: Vec<MSeg>,
    /// N6-01's shape: a self-closing file, which carries no groups and
    /// no segments and is owed exactly one `dropped_segments`.
    self_closing: bool,
}

struct Model {
    meta: Vec<(&'static str, &'static str)>,
    files: Vec<MFile>,
}

/// A subject built the way posters build them, so `quoted_filename` /
/// `unquoted_filename` / `kind` are all reachable.
fn subject(src: &mut Src) -> String {
    let name = src.pick(NAMES);
    let n = 1 + src.upto(30);
    match src.upto(6) {
        0 => format!("\"{name}\" yEnc (1/{n})"),
        1 => format!("[01/{n}] - \"{name}\" yEnc (1/{n})"),
        2 => format!("{name} yEnc (1/{n})"),
        3 => format!("\"{}\" - \"{name}\" yEnc", src.pick(NAMES)),
        4 => name.to_string(),
        _ => format!("Some prose subject yEnc (1/{n})"),
    }
}

fn model(src: &mut Src) -> Model {
    let nfiles = 1 + src.upto(4);
    let mut files = Vec::with_capacity(nfiles);
    for _ in 0..nfiles {
        let self_closing = src.flag();
        let (groups, segs) = if self_closing {
            (Vec::new(), Vec::new())
        } else {
            let ng = src.upto(3);
            let groups = (0..ng).map(|_| src.pick(GROUPS)).collect();
            let ns = src.upto(5);
            let segs = (0..ns)
                .map(|_| MSeg {
                    number: src.pick(NUMS),
                    bytes: src.pick(NUMS),
                    id: src.pick(IDS),
                    self_closing: src.flag(),
                })
                .collect();
            (groups, segs)
        };
        files.push(MFile {
            subject: subject(src),
            poster: src.pick(POSTERS),
            date: src.pick(DATES),
            groups,
            segs,
            self_closing,
        });
    }
    let nmeta = src.upto(3);
    let meta = (0..nmeta)
        .map(|_| (src.pick(META_TYPES), src.pick(META_VALUES)))
        .collect();
    Model { meta, files }
}

/// How a value is spelled. Every variant has to mean the SAME string
/// once the XML layer is done with it - that is the whole contract this
/// target rests on, so nothing here may touch whitespace: `&#10;` in an
/// attribute survives as a newline where a literal one normalises to a
/// space, and escaping whitespace would make two renderings genuinely
/// different documents rather than two spellings of one.
#[derive(Clone, Copy, PartialEq)]
enum Esc {
    Named,
    Numeric,
}

struct Style {
    esc: Esc,
    /// `'` instead of `"` around attribute values.
    apos: bool,
    /// `subject poster date` reversed.
    rev_attrs: bool,
    /// Formatting whitespace and newlines around element content. The
    /// parser trims group/meta/segment values as a whole, so this is
    /// equivalence-preserving for any content.
    pad: bool,
    /// Wrap element content in `<![CDATA[...]]>` where it holds no
    /// `]]>`. CDATA is literal, so it must mean what the escaped text
    /// spelling means.
    cdata: bool,
    /// Split element content with an XML comment. Comments are their own
    /// event, so the two text fragments have to re-join.
    comment_split: bool,
    /// `<n:nzb xmlns:n="...">` instead of `<nzb xmlns="...">`.
    prefix: bool,
    /// `<segments>` before `<groups>`.
    segs_first: bool,
    /// Emit the XML declaration and a DOCTYPE.
    prologue: bool,
}

fn style(src: &mut Src) -> Style {
    Style {
        esc: if src.flag() { Esc::Numeric } else { Esc::Named },
        apos: src.flag(),
        rev_attrs: src.flag(),
        pad: src.flag(),
        cdata: src.flag(),
        comment_split: src.flag(),
        prefix: src.flag(),
        segs_first: src.flag(),
        prologue: src.flag(),
    }
}

fn esc_into(s: &str, delim: Option<char>, esc: Esc, out: &mut String) {
    for c in s.chars() {
        let named = match c {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '"' if delim == Some('"') => Some("&quot;"),
            '\'' if delim == Some('\'') => Some("&apos;"),
            _ => None,
        };
        match named {
            None => out.push(c),
            Some(n) if esc == Esc::Named => out.push_str(n),
            Some(_) => {
                out.push_str("&#");
                out.push_str(&(c as u32).to_string());
                out.push(';');
            }
        }
    }
}

fn attr(out: &mut String, st: &Style, name: &str, value: &str) {
    let q = if st.apos { '\'' } else { '"' };
    out.push(' ');
    out.push_str(name);
    out.push('=');
    out.push(q);
    esc_into(value, Some(q), st.esc, out);
    out.push(q);
}

/// Element CONTENT, in whichever of the equivalent spellings this style
/// asked for.
fn content(out: &mut String, st: &Style, value: &str) {
    if st.pad {
        out.push_str("\n      ");
    }
    if st.cdata && !value.contains("]]>") {
        out.push_str("<![CDATA[");
        out.push_str(value);
        out.push_str("]]>");
    } else if st.comment_split && value.len() > 1 {
        // Split on a char boundary, never a byte one.
        let mut cut = value.len() / 2;
        while cut > 0 && !value.is_char_boundary(cut) {
            cut -= 1;
        }
        esc_into(&value[..cut], None, st.esc, out);
        out.push_str("<!-- split -->");
        esc_into(&value[cut..], None, st.esc, out);
    } else {
        esc_into(value, None, st.esc, out);
    }
    if st.pad {
        out.push_str("\n    ");
    }
}

fn render(m: &Model, st: &Style) -> String {
    let p = if st.prefix { "n:" } else { "" };
    let mut out = String::new();
    if st.prologue {
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(
            "<!DOCTYPE nzb PUBLIC \"-//newzBin//DTD NZB 1.1//EN\" \
                      \"http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd\">\n",
        );
    }
    let open_root = |out: &mut String| {
        out.push('<');
        out.push_str(p);
        out.push_str("nzb");
        if st.prefix {
            out.push_str(" xmlns:n=\"");
        } else {
            out.push_str(" xmlns=\"");
        }
        out.push_str(NZB_NS);
        out.push_str("\">\n");
    };
    let close_root = |out: &mut String| {
        out.push_str("</");
        out.push_str(p);
        out.push_str("nzb>\n");
    };
    open_root(&mut out);

    if !m.meta.is_empty() {
        out.push_str("  <");
        out.push_str(p);
        out.push_str("head>\n");
        for (ty, val) in &m.meta {
            out.push_str("    <");
            out.push_str(p);
            out.push_str("meta");
            attr(&mut out, st, "type", ty);
            out.push('>');
            content(&mut out, st, val);
            out.push_str("</");
            out.push_str(p);
            out.push_str("meta>\n");
        }
        out.push_str("  </");
        out.push_str(p);
        out.push_str("head>\n");
    }

    for f in &m.files {
        out.push_str("  <");
        out.push_str(p);
        out.push_str("file");
        if st.rev_attrs {
            attr(&mut out, st, "date", f.date);
            attr(&mut out, st, "poster", f.poster);
            attr(&mut out, st, "x:subject", "decoy.vol000+10.par2");
            attr(&mut out, st, "subject", &f.subject);
        } else {
            attr(&mut out, st, "subject", &f.subject);
            attr(&mut out, st, "x:subject", "decoy.vol000+10.par2");
            attr(&mut out, st, "poster", f.poster);
            attr(&mut out, st, "date", f.date);
        }
        out.push_str(" xmlns:x=\"urn:example:extension\"");
        if f.self_closing {
            out.push_str("/>\n");
            continue;
        }
        out.push_str(">\n");

        let groups = |out: &mut String| {
            if f.groups.is_empty() {
                return;
            }
            out.push_str("    <");
            out.push_str(p);
            out.push_str("groups>\n");
            for g in &f.groups {
                out.push_str("      <");
                out.push_str(p);
                out.push_str("group>");
                content(out, st, g);
                out.push_str("</");
                out.push_str(p);
                out.push_str("group>\n");
            }
            out.push_str("    </");
            out.push_str(p);
            out.push_str("groups>\n");
        };
        let segments = |out: &mut String| {
            if f.segs.is_empty() {
                return;
            }
            out.push_str("    <");
            out.push_str(p);
            out.push_str("segments>\n");
            for s in &f.segs {
                out.push_str("      <");
                out.push_str(p);
                out.push_str("segment");
                if st.rev_attrs {
                    out.push_str(" xmlns:x=\"urn:example:extension\"");
                    attr(out, st, "x:bytes", "999999");
                }
                attr(out, st, "bytes", s.bytes);
                attr(out, st, "number", s.number);
                if !st.rev_attrs {
                    out.push_str(" xmlns:x=\"urn:example:extension\"");
                    attr(out, st, "x:bytes", "999999");
                }
                if s.self_closing {
                    out.push_str("/>\n");
                    continue;
                }
                out.push('>');
                content(out, st, s.id);
                out.push_str("</");
                out.push_str(p);
                out.push_str("segment>\n");
            }
            out.push_str("    </");
            out.push_str(p);
            out.push_str("segments>\n");
        };
        if st.segs_first {
            segments(&mut out);
            groups(&mut out);
        } else {
            groups(&mut out);
            segments(&mut out);
        }
        out.push_str("  </");
        out.push_str(p);
        out.push_str("file>\n");
    }
    close_root(&mut out);
    out
}

/// XML 1.0 production 3 `S` - space, tab, CR, LF, and nothing else -
/// written out here for the same reason `wire_safe` below is: the
/// parser's `trim_xml_space` is private, and an oracle that asks the
/// code under test what the answer is has stopped being an oracle.
///
/// It is NOT `str::trim`, and that difference is this target's own
/// N6-06 exposure rather than a nicety. Rust trims the Unicode
/// `White_Space` set, so `\u{2003}emsp@news.example\u{2003}` comes out
/// of `trim()` wire-safe and keeps its EM SPACE under XML `S`. The
/// parser used the wide trim until `97e4dea88` (30 Aug 2026 19:20) -
/// 110 minutes AFTER this target landed in `ec0fdeb27` - and this file
/// went on asserting the old contract in two places, so `nzb_semantic`
/// was red on origin/main from a cold corpus in under a second and
/// nothing had run it. Do NOT put `trim()` back at either site.
fn trim_xml_space(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// The parser's own wire-safety rule, written out again here rather than
/// imported: it is `pub(crate)`, and an oracle that asks the code under
/// test what the answer is has stopped being an oracle.
fn wire_safe(s: &str) -> bool {
    !s.chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>'))
}

/// A `bytes=`/`number=` token whose meaning no policy decision can move:
/// a plain in-range decimal has to survive as its own value.
fn settled_u64(t: &str) -> Option<u64> {
    (!t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()))
        .then(|| t.parse().ok())
        .flatten()
}

fn check_accounting(m: &Model, nzb: &Nzb, xml: &str) {
    assert_eq!(
        nzb.files.len(),
        m.files.len(),
        "declared {} <file> elements, parsed {} - a declared file left \
         without being charged (N6-01/N6-03)\n{xml}",
        m.files.len(),
        nzb.files.len()
    );
    for (f, mf) in nzb.files.iter().zip(m.files.iter()) {
        let declared = mf.segs.len().max(1);
        assert_eq!(
            f.segments.len() + f.dropped_segments,
            declared,
            "declared {declared} segments, parsed {} + dropped {} - a \
             declared segment left without being charged\n{xml}",
            f.segments.len(),
            f.dropped_segments
        );
        assert!(
            f.segments.windows(2).all(|w| w[0].number <= w[1].number),
            "segments are not in part order\n{xml}"
        );
        for s in &f.segments {
            assert!(
                !s.message_id.is_empty()
                    && wire_safe(&s.message_id)
                    && trim_xml_space(&s.message_id) == s.message_id,
                "a kept segment carries an id the parser's own contract \
                 refuses: {:?}\n{xml}",
                s.message_id
            );
        }
        for g in &f.groups {
            assert!(
                !g.is_empty() && wire_safe(g) && trim_xml_space(g) == g,
                "a kept group is not a wire-safe trimmed name: {g:?}\n{xml}"
            );
        }
        assert_eq!(
            f.bytes(),
            f.segments
                .iter()
                .map(|s| s.bytes)
                .fold(0u64, u64::saturating_add),
            "a file's byte total is not the sum of its segments\n{xml}"
        );
        // N6-08 from the safe side: a well-formed in-range decimal is
        // the one reading no policy choice can take away. Compared as a
        // MULTISET, because the parse sorts by part number and two
        // segments may legitimately declare the same pair.
        let mut got: Vec<(u64, u64)> = f
            .segments
            .iter()
            .map(|s| (u64::from(s.number), s.bytes))
            .collect();
        for ms in &mf.segs {
            if ms.self_closing {
                continue;
            }
            let id = trim_xml_space(ms.id);
            if id.is_empty() || !wire_safe(id) {
                continue;
            }
            let (Some(n), Some(b)) = (settled_u64(ms.number), settled_u64(ms.bytes)) else {
                continue;
            };
            if u32::try_from(n).is_err() {
                continue;
            }
            match got.iter().position(|g| *g == (n, b)) {
                Some(at) => {
                    got.swap_remove(at);
                }
                None => panic!(
                    "a well-formed number={n} bytes={b} did not survive \
                     the parse (N6-08)\n{xml}"
                ),
            }
        }
    }
    for (ty, val) in &nzb.meta {
        assert!(
            !ty.is_empty() && ty.trim() == ty && ty.to_lowercase() == *ty,
            "a meta type is not trimmed and lowercased: {ty:?}\n{xml}"
        );
        assert!(
            !val.is_empty() && trim_xml_space(val) == val,
            "a meta value is not trimmed and non-empty: {val:?}\n{xml}"
        );
    }
    assert_eq!(
        nzb.total_bytes(),
        nzb.files
            .iter()
            .map(|f| f.bytes())
            .fold(0u64, u64::saturating_add),
        "the manifest total is not the sum of its files\n{xml}"
    );
}

// ---------------------------------------------------------------------
// The hostile arm (T6, F7) - documents built to be REFUSED, or to cross
// a ceiling neither NZB fuzz target has ever reached.
// ---------------------------------------------------------------------

/// An [`NzbError`] compared by CLASS. The match is exhaustive on
/// purpose: a parser that grows a refusal variant is a COMPILE ERROR
/// here, which is the only way this target finds out there is an answer
/// it has never generated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Xml,
    Attr,
    Empty,
    Truncated,
    UnknownEntity,
    Schema,
    /// Carries `what` rather than collapsing to one variant. A document
    /// refused by the WRONG ceiling is a defect a bare "it was refused"
    /// arm cannot see - and the ceilings are close enough together
    /// (`MAX_WIRE_TOKEN` 512 inside `MAX_FIELD` 4096 inside
    /// `MAX_TEXT_BYTES` 64 MiB) that confusing two is a live way to get
    /// this wrong.
    TooLarge(&'static str),
}

fn kind(e: &NzbError) -> Kind {
    match e {
        NzbError::Xml(_) => Kind::Xml,
        NzbError::Attr(_) => Kind::Attr,
        NzbError::Empty => Kind::Empty,
        NzbError::Truncated => Kind::Truncated,
        NzbError::UnknownEntity(_) => Kind::UnknownEntity,
        NzbError::Schema(_) => Kind::Schema,
        NzbError::TooLarge(what, _) => Kind::TooLarge(what),
    }
}

/// A minimal element writer over the same [`Style`] the legal renderer
/// uses. The escaping primitives are SHARED (`attr`, `esc_into`) -
/// only the element scaffolding is written twice, because a hostile
/// document is shaped by what it BREAKS rather than by a `Model`, and
/// threading that through `render` would put the legal arm's assertions
/// at the mercy of a hostile branch.
///
/// Nothing here emits a newline except [`W::block`], and that is
/// load-bearing rather than tidy: element text is ACCUMULATED, so a
/// newline after `<meta type="password">` is a fragment that counts
/// against `MAX_FIELD` like any other. Whitespace inside a container
/// (`<nzb>`, `<head>`, `<file>`, `<groups>`, `<segments>`) reaches no
/// accumulator at all, which is why `block` may have it and `open` may
/// not.
struct W<'a> {
    out: String,
    st: &'a Style,
    /// The style's element prefix, applied to EVERY core element. A bare
    /// `<file>` inside a prefix-style document is in no namespace at
    /// all, which the parser reads as somebody's extension and ignores -
    /// so a break spelled without this is not a break under half the
    /// styles, and the differential below would be asserting a
    /// difference this target invented.
    p: &'static str,
}

impl<'a> W<'a> {
    fn new(st: &'a Style) -> Self {
        let mut w = W {
            out: String::new(),
            st,
            p: if st.prefix { "n:" } else { "" },
        };
        if st.prologue {
            w.out
                .push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        }
        w
    }

    /// The root. Its local name is a parameter so `Break::WrongRoot` can
    /// hand it something that is not `nzb`.
    fn root(&mut self, local: &str) {
        self.out.push('<');
        self.out.push_str(self.p);
        self.out.push_str(local);
        self.out.push_str(if self.st.prefix {
            " xmlns:n=\""
        } else {
            " xmlns=\""
        });
        self.out.push_str(NZB_NS);
        self.out.push_str("\">\n");
    }

    fn tag(&mut self, local: &str, attrs: &[(&str, &str)], tail: &str) {
        self.out.push('<');
        self.out.push_str(self.p);
        self.out.push_str(local);
        if self.st.rev_attrs {
            for (k, v) in attrs.iter().rev() {
                attr(&mut self.out, self.st, k, v);
            }
        } else {
            for (k, v) in attrs {
                attr(&mut self.out, self.st, k, v);
            }
        }
        self.out.push_str(tail);
    }

    /// A container element - newline allowed, see the type's own note.
    fn block(&mut self, local: &str, attrs: &[(&str, &str)]) {
        self.tag(local, attrs, ">\n");
    }
    /// A text-bearing element - no newline, ever.
    fn open(&mut self, local: &str, attrs: &[(&str, &str)]) {
        self.tag(local, attrs, ">");
    }
    fn empty(&mut self, local: &str, attrs: &[(&str, &str)]) {
        self.tag(local, attrs, "/>");
    }
    fn close(&mut self, local: &str) {
        self.out.push_str("</");
        self.out.push_str(self.p);
        self.out.push_str(local);
        self.out.push('>');
    }
    fn nl(&mut self) {
        self.out.push('\n');
    }
    fn text(&mut self, s: &str) {
        esc_into(s, None, self.st.esc, &mut self.out);
    }
    /// An element in somebody ELSE'S vocabulary. Unprefixed core names
    /// are refused wherever they appear, so this is what says an
    /// extension wrapper is not a way to smuggle one in.
    fn ext_open(&mut self) {
        self.out
            .push_str("<x:ext xmlns:x=\"urn:example:extension\">\n");
    }
    fn ext_close(&mut self) {
        self.out.push_str("</x:ext>\n");
    }
}

/// One ordinary legal `<file>`: the minimum a hostile document needs so
/// it is refused for the reason it was BUILT for and not for
/// `NzbError::Empty`, which most of these would otherwise reach first.
fn legal_file(w: &mut W) {
    w.block(
        "file",
        &[
            ("subject", "\"ok.mkv\" yEnc (1/1)"),
            ("poster", "p@news.example"),
            ("date", "1690000000"),
        ],
    );
    w.block("segments", &[]);
    w.open("segment", &[("bytes", "1"), ("number", "1")]);
    w.text("ok@news.example");
    w.close("segment");
    w.nl();
    w.close("segments");
    w.nl();
    w.close("file");
    w.nl();
}

/// Which structural rule the document breaks. Every one of these has to
/// be a violation under EVERY style, or the differential is asserting a
/// property of this file rather than one of the parser.
#[derive(Clone, Copy)]
enum Break {
    /// The root is not `<nzb>`.
    WrongRoot,
    /// Two complete documents concatenated. N6-03's second half, which
    /// used to merge into one manifest.
    SecondRoot,
    /// `<file>` inside `<file>`. N6-03's first half, which used to
    /// replace the outer file and lose it with nothing charged.
    FileInFile,
    /// `<segment>` straight under the root.
    SegmentAtRoot,
    /// `<group>` straight under `<file>`, with no `<groups>`.
    GroupOutsideGroups,
    /// `<meta>` outside `<head>`.
    MetaOutsideHead,
    /// `<file>` inside `<head>`.
    FileInHead,
    /// A core `<file>` inside a namespace-extension element.
    CoreInsideExtension,
}

const BREAKS: &[Break] = &[
    Break::WrongRoot,
    Break::SecondRoot,
    Break::FileInFile,
    Break::SegmentAtRoot,
    Break::GroupOutsideGroups,
    Break::MetaOutsideHead,
    Break::FileInHead,
    Break::CoreInsideExtension,
];

fn render_break(b: Break, st: &Style) -> String {
    let mut w = W::new(st);
    match b {
        Break::WrongRoot => {
            w.root("nzbx");
            legal_file(&mut w);
            w.close("nzbx");
        }
        Break::SecondRoot => {
            w.root("nzb");
            legal_file(&mut w);
            w.close("nzb");
            w.nl();
            w.root("nzb");
            legal_file(&mut w);
            w.close("nzb");
        }
        Break::FileInFile => {
            w.root("nzb");
            w.block("file", &[("subject", "\"outer.mkv\" yEnc (1/1)")]);
            w.block("file", &[("subject", "\"inner.mkv\" yEnc (1/1)")]);
            w.close("file");
            w.nl();
            w.close("file");
            w.nl();
            w.close("nzb");
        }
        Break::SegmentAtRoot => {
            w.root("nzb");
            w.open("segment", &[("bytes", "1"), ("number", "1")]);
            w.text("loose@news.example");
            w.close("segment");
            w.nl();
            legal_file(&mut w);
            w.close("nzb");
        }
        Break::GroupOutsideGroups => {
            w.root("nzb");
            w.block("file", &[("subject", "\"ok.mkv\" yEnc (1/1)")]);
            w.open("group", &[]);
            w.text("alt.binaries.test");
            w.close("group");
            w.nl();
            w.close("file");
            w.nl();
            w.close("nzb");
        }
        Break::MetaOutsideHead => {
            w.root("nzb");
            w.open("meta", &[("type", "password")]);
            w.text("secret");
            w.close("meta");
            w.nl();
            legal_file(&mut w);
            w.close("nzb");
        }
        Break::FileInHead => {
            w.root("nzb");
            w.block("head", &[]);
            w.block("file", &[("subject", "\"ok.mkv\" yEnc (1/1)")]);
            w.close("file");
            w.nl();
            w.close("head");
            w.nl();
            legal_file(&mut w);
            w.close("nzb");
        }
        Break::CoreInsideExtension => {
            w.root("nzb");
            w.ext_open();
            w.block("file", &[("subject", "\"smuggled.mkv\" yEnc (1/1)")]);
            w.close("file");
            w.nl();
            w.ext_close();
            legal_file(&mut w);
            w.close("nzb");
        }
    }
    w.out
}

/// Which capped field is grown past its ceiling.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LongField {
    /// An ATTRIBUTE, length-checked whole at the read: refused, never
    /// truncated, because a shortened subject is a different filename.
    Subject,
    Poster,
    MetaType,
    /// Element TEXT, accumulated per fragment and latched in `Over`.
    MetaValue,
    Group,
    SegmentId,
}

const LONG_FIELDS: &[LongField] = &[
    LongField::Subject,
    LongField::Poster,
    LongField::MetaType,
    LongField::MetaValue,
    LongField::Group,
    LongField::SegmentId,
];

/// What the value is made of. All three spell a value whose BYTE length
/// is exactly the one asked for, because every cap in `nzb::limits` is
/// on bytes.
#[derive(Clone, Copy)]
enum Filler {
    /// Plain ASCII: one text run, so the whole value arrives in as few
    /// fragments as the style allows.
    Ascii,
    /// `&`, which every style has to escape - so the value arrives as
    /// one `GeneralRef` event PER BYTE, which is the hardest case a
    /// per-fragment cap has and the only one that puts `push_capped`
    /// under four thousand consecutive calls.
    Amp,
    /// U+00FC, two UTF-8 bytes. A cap that had drifted to counting CHARS
    /// would pass every ASCII case above and fail here.
    Multibyte,
}

/// Lengths that straddle both token caps from either side, plus a couple
/// far past. `MAX_WIRE_TOKEN` (512) sits INSIDE `MAX_FIELD` (4096), so a
/// group or a message-id has two ceilings and the sample has to cross
/// both to say which one answered.
const LONG_LENS: &[usize] = &[
    1,
    2,
    limits::MAX_WIRE_TOKEN - 1,
    limits::MAX_WIRE_TOKEN,
    limits::MAX_WIRE_TOKEN + 1,
    limits::MAX_WIRE_TOKEN + 2,
    limits::MAX_FIELD - 2,
    limits::MAX_FIELD - 1,
    limits::MAX_FIELD,
    limits::MAX_FIELD + 1,
    limits::MAX_FIELD + 2,
    limits::MAX_FIELD * 2,
];

struct Long {
    field: LongField,
    /// Decoded BYTE length of the value.
    len: usize,
    /// How many fragments the value arrives in, where the style permits
    /// fragmenting at all. Adjacent literal runs MERGE into one text
    /// event, so this is a ceiling on the fragment count rather than a
    /// promise of it - which is the point: the three styles fragment one
    /// value three ways and must still agree.
    frags: usize,
    filler: Filler,
}

fn long(src: &mut Src) -> Long {
    Long {
        field: LONG_FIELDS[src.upto(LONG_FIELDS.len())],
        len: LONG_LENS[src.upto(LONG_LENS.len())],
        frags: 1 + src.upto(8),
        filler: match src.upto(3) {
            0 => Filler::Ascii,
            1 => Filler::Amp,
            _ => Filler::Multibyte,
        },
    }
}

fn long_value(l: &Long) -> String {
    match l.filler {
        Filler::Ascii => "x".repeat(l.len),
        Filler::Amp => "&".repeat(l.len),
        Filler::Multibyte => {
            let mut s = "\u{fc}".repeat(l.len / 2);
            if l.len % 2 == 1 {
                s.push('x');
            }
            s
        }
    }
}

/// The long value as element CONTENT, in up to `frags` pieces.
///
/// No `pad`, deliberately, and this is the one place the legal
/// renderer's formatting whitespace is switched off. Element text is
/// accumulated BEFORE it is trimmed, so indentation counts against
/// `MAX_FIELD` like any other fragment: twelve bytes of it would decide
/// a value placed exactly on the boundary, and two spellings of one
/// value would then genuinely disagree. That is a real property of the
/// parser and worth knowing - a pretty-printed 4090-byte meta value is
/// dropped where the same value on one line is kept - but it is a
/// question about whether whitespace should COUNT, not about spelling,
/// so it is stated here rather than asserted. Do not "fix" a failure by
/// switching padding back on.
fn long_content(out: &mut String, st: &Style, value: &str, frags: usize) {
    let n = frags.max(1);
    let mut start = 0usize;
    for i in 0..n {
        let mut end = value.len() * (i + 1) / n;
        if end > value.len() {
            end = value.len();
        }
        while end < value.len() && !value.is_char_boundary(end) {
            end += 1;
        }
        if end <= start {
            continue;
        }
        let piece = &value[start..end];
        start = end;
        if st.cdata {
            out.push_str("<![CDATA[");
            out.push_str(piece);
            out.push_str("]]>");
        } else {
            if i > 0 && st.comment_split {
                out.push_str("<!-- f -->");
            }
            esc_into(piece, None, st.esc, out);
        }
    }
}

/// What the parser owes this field, computed from the MODEL and never
/// from the parse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Owed {
    /// The whole document is refused, by this ceiling.
    Refused(&'static str),
    /// It parses and the value survives WHOLE.
    Kept,
    /// It parses and the value is DROPPED - never retained as a prefix.
    Dropped,
}

fn owed(l: &Long) -> Owed {
    match l.field {
        LongField::Subject | LongField::Poster => {
            if l.len > limits::MAX_FIELD {
                Owed::Refused("subject/poster length")
            } else {
                Owed::Kept
            }
        }
        LongField::MetaType => {
            if l.len > limits::MAX_FIELD {
                Owed::Refused("meta type length")
            } else {
                Owed::Kept
            }
        }
        // The `Over` latch's own half. A meta VALUE has no token cap, so
        // this is the ONLY field where crossing `MAX_FIELD` is what
        // decides the answer - and it is the field the parser's own
        // comment is about, because it is the archive password.
        LongField::MetaValue => {
            if l.len > limits::MAX_FIELD {
                Owed::Dropped
            } else {
                Owed::Kept
            }
        }
        // Two ceilings, and the WIRE one binds first: `MAX_WIRE_TOKEN`
        // (512) sits inside `MAX_FIELD` (4096), so a group or an id that
        // reaches the latch has already failed the token cap. Both
        // verdicts are the same - dropped at the field, document intact
        // - so the arm is exact either way, and the note is here so
        // nobody reads a green run as evidence the latch was reached
        // through a group.
        LongField::Group | LongField::SegmentId => {
            if l.len > limits::MAX_WIRE_TOKEN {
                Owed::Dropped
            } else {
                Owed::Kept
            }
        }
    }
}

fn render_long(l: &Long, v: &str, st: &Style) -> String {
    let mut w = W::new(st);
    w.root("nzb");
    match l.field {
        LongField::MetaType | LongField::MetaValue => {
            w.block("head", &[]);
            let ty = if l.field == LongField::MetaType {
                v
            } else {
                "password"
            };
            w.open("meta", &[("type", ty)]);
            if l.field == LongField::MetaValue {
                long_content(&mut w.out, st, v, l.frags);
            } else {
                w.text("v");
            }
            w.close("meta");
            w.nl();
            w.close("head");
            w.nl();
            legal_file(&mut w);
        }
        LongField::Subject | LongField::Poster => {
            let subject = if l.field == LongField::Subject {
                v
            } else {
                "\"ok.mkv\" yEnc (1/1)"
            };
            let poster = if l.field == LongField::Poster {
                v
            } else {
                "p@news.example"
            };
            w.block(
                "file",
                &[
                    ("subject", subject),
                    ("poster", poster),
                    ("date", "1690000000"),
                ],
            );
            w.block("segments", &[]);
            w.open("segment", &[("bytes", "1"), ("number", "1")]);
            w.text("ok@news.example");
            w.close("segment");
            w.nl();
            w.close("segments");
            w.nl();
            w.close("file");
            w.nl();
        }
        LongField::Group => {
            w.block("file", &[("subject", "\"ok.mkv\" yEnc (1/1)")]);
            w.block("groups", &[]);
            w.open("group", &[]);
            long_content(&mut w.out, st, v, l.frags);
            w.close("group");
            w.nl();
            w.open("group", &[]);
            w.text("alt.binaries.test");
            w.close("group");
            w.nl();
            w.close("groups");
            w.nl();
            w.block("segments", &[]);
            w.open("segment", &[("bytes", "1"), ("number", "1")]);
            w.text("ok@news.example");
            w.close("segment");
            w.nl();
            w.close("segments");
            w.nl();
            w.close("file");
            w.nl();
        }
        LongField::SegmentId => {
            w.block("file", &[("subject", "\"ok.mkv\" yEnc (1/1)")]);
            w.block("segments", &[]);
            w.open("segment", &[("bytes", "1"), ("number", "1")]);
            long_content(&mut w.out, st, v, l.frags);
            w.close("segment");
            w.nl();
            w.open("segment", &[("bytes", "2"), ("number", "2")]);
            w.text("ok@news.example");
            w.close("segment");
            w.nl();
            w.close("segments");
            w.nl();
            w.close("file");
            w.nl();
        }
    }
    w.close("nzb");
    w.out
}

/// The half no "was it refused?" check can make: what a DROPPED value
/// must not leave behind. The parser's own comment is the assertion -
/// half a password is a wrong password, and half a message-id is an
/// article nobody posted - so absence is not enough, nothing kept may be
/// a PREFIX of what was declared.
fn no_prefix_survived(kept: &[&str], v: &str, what: &str, xml: &str) {
    for k in kept {
        assert!(
            !v.starts_with(*k),
            "an over-length {what} was retained as a {}-byte PREFIX of the \
             {}-byte value declared - dropped is the contract, truncated is \
             a fabricated value\n{xml}",
            k.len(),
            v.len()
        );
    }
}

fn check_long(l: &Long, v: &str, got: &Result<Nzb, NzbError>, xml: &str) {
    let want = owed(l);
    let nzb = match (want, got) {
        (Owed::Refused(what), Err(e)) => {
            assert_eq!(
                kind(e),
                Kind::TooLarge(what),
                "a {}-byte field was refused by the wrong ceiling\n{xml}",
                v.len()
            );
            return;
        }
        (Owed::Refused(what), Ok(_)) => panic!(
            "a {}-byte field should have been refused by the {what} ceiling \
             and was accepted\n{xml}",
            v.len()
        ),
        (_, Err(e)) => panic!(
            "a legal document carrying a {}-byte field was refused: {e}\n{xml}",
            v.len()
        ),
        (_, Ok(n)) => n,
    };
    let kept_meta: Vec<&str> = nzb.meta.iter().map(|(_, val)| val.as_str()).collect();
    let f = nzb.files.first().expect("the document declares a file");
    let kept_groups: Vec<&str> = f.groups.iter().map(String::as_str).collect();
    let kept_ids: Vec<&str> = f.segments.iter().map(|s| s.message_id.as_str()).collect();
    match (l.field, want) {
        (LongField::Subject, _) => assert_eq!(f.subject, v, "the subject did not survive\n{xml}"),
        (LongField::Poster, _) => assert_eq!(f.poster, v, "the poster did not survive\n{xml}"),
        (LongField::MetaType, _) => assert_eq!(
            nzb.meta,
            vec![(v.to_lowercase(), "v".to_string())],
            "the meta type did not survive\n{xml}"
        ),
        (LongField::MetaValue, Owed::Kept) => assert_eq!(
            nzb.meta,
            vec![("password".to_string(), v.to_string())],
            "a meta value inside the cap did not survive whole\n{xml}"
        ),
        (LongField::MetaValue, _) => {
            assert!(
                nzb.meta.is_empty(),
                "an over-length meta value was kept: {:?}\n{xml}",
                nzb.meta
            );
            no_prefix_survived(&kept_meta, v, "meta value", xml);
        }
        (LongField::Group, Owed::Kept) => assert_eq!(
            kept_groups,
            vec![v, "alt.binaries.test"],
            "a group inside the cap did not survive whole\n{xml}"
        ),
        (LongField::Group, _) => {
            assert_eq!(
                kept_groups,
                vec!["alt.binaries.test"],
                "an over-length group was kept, or took its healthy sibling \
                 with it\n{xml}"
            );
            no_prefix_survived(&kept_groups, v, "group name", xml);
        }
        (LongField::SegmentId, Owed::Kept) => {
            assert_eq!(
                kept_ids,
                vec![v, "ok@news.example"],
                "a message-id inside the cap did not survive whole\n{xml}"
            );
            assert_eq!(f.dropped_segments, 0, "nothing was owed here\n{xml}");
        }
        (LongField::SegmentId, _) => {
            assert_eq!(
                kept_ids,
                vec!["ok@news.example"],
                "an over-length message-id was kept, or took its healthy \
                 sibling with it\n{xml}"
            );
            assert_eq!(
                f.dropped_segments, 1,
                "a refused segment left without being charged\n{xml}"
            );
            no_prefix_survived(&kept_ids, v, "message-id", xml);
        }
    }
}

/// The two COUNT ceilings. Their state space is ONE - there is exactly
/// one way to declare too many segments - and
/// `nzb_tests::structural_ceilings_refuse_a_dense_manifest` already pins
/// both in both segment spellings. What is here is REACH, which is
/// F7's actual ask: no fuzz target had ever executed the counter, and a
/// ceiling nothing exercises is one a refactor can drop in silence.
#[derive(Clone, Copy)]
enum Count {
    Files,
    Segments,
}

/// The smallest legal segment is ten bytes and there have to be
/// 1,000,001 of them, so ONE of these documents is a double-digit
/// megabyte string. Far too expensive to reach through an ordinary
/// choice byte, and mutating around it buys nothing on a state space of
/// one - so it is behind a four-byte magic, and the corpus carries a
/// seed for each spelling. `seeds/nzb_semantic/nzbc-*` and
/// `fuzz_seed_corpus.rs::the_nzb_semantic_count_seeds_still_carry_their_magic`
/// are the other half; change this constant and both move with it.
const COUNT_MAGIC: &[u8; 4] = b"NZBC";

/// How many of those documents ONE PROCESS will build, and the magic
/// above is not enough without it. Measured 31 Aug 2026 on the dev Mac,
/// 60 s bursts: the four seeds alone take the burst from **1,557 exec/s
/// to 287** - a 5.4x collapse for +28 edges - because libFuzzer keeps
/// them (they expand coverage enormously) and then mutates AROUND them,
/// and a mutant that leaves the first four bytes alone rebuilds the
/// whole nineteen-megabyte document. Per document, under the sanitizer:
/// 101 ms for `<file/>` x100,001, 169 ms for the paired prefixed
/// spelling, 792 ms for `<segment/>` x1,000,001 and 1,546 ms for its
/// paired spelling - the last is the one to watch against fuzz-smoke's
/// `-timeout=10`, and it is the reason the committed segment seeds take
/// the cheap default-namespace style.
///
/// So reach here is a fixed BUDGET, not a rate, and that is the right
/// shape rather than a concession: there is exactly ONE way to declare
/// too many segments, libFuzzer runs the whole corpus at INITED, and the
/// committed seeds cover all four shapes (two ceilings x two spellings).
/// A ceiling that regressed therefore fails in the first seconds of
/// every run, deterministically, rather than at some point in a
/// campaign, which is a stronger guarantee than a rate for about three
/// seconds of runner time.
/// What it deliberately does NOT buy is exploration; the FIELD ceilings
/// are where the state space is, and they are on the cheap path.
const COUNT_BUDGET: usize = 8;
static COUNT_SPENT: AtomicUsize = AtomicUsize::new(0);

fn render_count(c: Count, st: &Style, self_closing: bool) -> String {
    let mut w = W::new(st);
    w.root("nzb");
    match c {
        Count::Files => {
            for _ in 0..=limits::MAX_FILES {
                if self_closing {
                    w.empty("file", &[]);
                } else {
                    w.open("file", &[]);
                    w.close("file");
                }
            }
        }
        Count::Segments => {
            w.block("file", &[("subject", "\"ok.mkv\" yEnc (1/1)")]);
            w.block("segments", &[]);
            for _ in 0..=limits::MAX_SEGMENTS {
                if self_closing {
                    w.empty("segment", &[]);
                } else {
                    w.open("segment", &[]);
                    w.close("segment");
                }
            }
            w.close("segments");
            w.close("file");
        }
    }
    w.close("nzb");
    w.out
}

fn run_count(src: &mut Src) {
    let c = if src.flag() {
        Count::Files
    } else {
        Count::Segments
    };
    let self_closing = src.flag();
    let st = style(src);
    // ONE rendering, not three. The document is megabytes; the
    // differential's question - do two spellings of one document agree -
    // is answered across EXECS here instead of within one, because the
    // style is drawn from the choice stream like everything else.
    let xml = render_count(c, &st, self_closing);
    let want = match c {
        Count::Files => "file count",
        Count::Segments => "segment count",
    };
    let got = Nzb::parse(xml.as_bytes());
    match got {
        Err(ref e) => assert_eq!(
            kind(e),
            Kind::TooLarge(want),
            "a manifest past the {want} ceiling was refused by something else"
        ),
        Ok(n) => panic!(
            "a manifest past the {want} ceiling parsed into {} files",
            n.files.len()
        ),
    }
}

/// A hostile document that is cheap enough to render three times: the
/// `Schema` breaks (T6) and the field ceilings (F7).
enum Hostile {
    Break(Break),
    Long(Long),
}

fn run_hostile(h: &Hostile, src: &mut Src) {
    let styles = [style(src), style(src), style(src)];
    let mut seen: Vec<(String, Result<Nzb, NzbError>)> = Vec::with_capacity(styles.len());
    for st in &styles {
        let (xml, v) = match h {
            Hostile::Break(b) => (render_break(*b, st), None),
            Hostile::Long(l) => {
                let v = long_value(l);
                (render_long(l, &v, st), Some(v))
            }
        };
        let got = Nzb::parse(xml.as_bytes());
        match h {
            Hostile::Break(_) => {
                // Which documents are schema violations is policy, and
                // this target does not litigate it - only that the
                // answer is a refusal and that it is the SCHEMA one, so
                // a break that stopped being a break shows up as an
                // accept rather than as a quieter error.
                match got {
                    Err(ref e) => assert_eq!(
                        kind(e),
                        Kind::Schema,
                        "a schema violation was refused by something other \
                         than the schema\n{xml}"
                    ),
                    Ok(ref n) => panic!(
                        "a document that is not a well-formed NZB parsed into \
                         {} files\n{xml}",
                        n.files.len()
                    ),
                }
            }
            Hostile::Long(l) => check_long(l, v.as_deref().unwrap_or(""), &got, &xml),
        }
        seen.push((xml, got));
    }
    // T6's own invariant, and the half no per-rendering assertion above
    // can make: whatever the answer is, three equivalent spellings of
    // one document have to reach it. Attribute order and a namespace
    // PREFIX are two of the styles, which is the row's oracle 4 and
    // oracle 3 asked of a refusal instead of of a manifest.
    for i in 1..seen.len() {
        match (&seen[0].1, &seen[i].1) {
            (Ok(a), Ok(b)) => assert!(
                a == b,
                "two equivalent spellings of one document parsed \
                 differently\n--- A ---\n{}\n--- B ---\n{}",
                seen[0].0,
                seen[i].0
            ),
            (Err(a), Err(b)) => assert_eq!(
                kind(a),
                kind(b),
                "two equivalent spellings of one document were refused for \
                 different reasons: {a} against {b}\n--- A ---\n{}\n--- B ---\n{}",
                seen[0].0,
                seen[i].0
            ),
            (a, b) => panic!(
                "one spelling of this document was accepted and another \
                 refused ({a:?} against {b:?})\n--- A ---\n{}\n--- B ---\n{}",
                seen[0].0, seen[i].0
            ),
        }
    }
}

/// The legal arm this target shipped as: a manifest that must PARSE, and
/// must parse to the same thing however it is spelled.
fn run_legal(src: &mut Src) {
    let m = model(src);
    let styles = [style(src), style(src), style(src)];

    let mut parsed = Vec::with_capacity(styles.len());
    for st in &styles {
        let xml = render(&m, st);
        let nzb = match Nzb::parse(xml.as_bytes()) {
            Ok(n) => n,
            Err(e) => panic!("a well-formed generated NZB was refused: {e}\n{xml}"),
        };
        // Determinism: nothing in the parse may depend on state left by
        // an earlier one.
        assert!(
            Nzb::parse(xml.as_bytes()).is_ok_and(|again| again == nzb),
            "parsing the same bytes twice disagreed\n{xml}"
        );
        check_accounting(&m, &nzb, &xml);
        parsed.push((xml, nzb));
    }
    for i in 1..parsed.len() {
        assert!(
            parsed[i].1 == parsed[0].1,
            "two equivalent spellings of one manifest parsed \
             differently\n--- A ---\n{}\n--- B ---\n{}",
            parsed[0].0,
            parsed[i].0
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // A choice stream this short cannot build a manifest worth three
    // renderings; leave the byte-level work to `nzb_parse`.
    if data.len() < 8 {
        return;
    }
    // The count ceilings are behind a magic prefix rather than a choice
    // byte - see `COUNT_MAGIC` for why a rate worth having is too
    // expensive for a double-digit-megabyte document.
    if data.starts_with(COUNT_MAGIC) {
        if COUNT_SPENT.fetch_add(1, Ordering::Relaxed) < COUNT_BUDGET {
            run_count(&mut Src::new(&data[COUNT_MAGIC.len()..]));
        }
        return;
    }
    let mut src = Src::new(data);
    // Half the stream stays on the legal arm: that is where the state
    // space is, and the hostile shapes below are a small enumerable set
    // that the fuzzer reaches in milliseconds.
    match src.upto(4) {
        0 | 1 => run_legal(&mut src),
        2 => run_hostile(&Hostile::Break(BREAKS[src.upto(BREAKS.len())]), &mut src),
        _ => run_hostile(&Hostile::Long(long(&mut src)), &mut src),
    }
});
