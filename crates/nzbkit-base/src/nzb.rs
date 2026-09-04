//! NZB file parsing.
//!
//! An NZB is XML: `<nzb><file ...><groups><group>…</groups>
//! <segments><segment bytes number>message-id</segment></segments></file></nzb>`.
//! We keep the model deliberately close to the wire format; scheduling
//! concepts (server tiers, block accounting) live elsewhere.

use quick_xml::NsReader;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;

#[derive(Debug, thiserror::Error)]
pub enum NzbError {
    // Carries the encoding failures too, since quick-xml 0.42. There was a
    // separate `Encoding(#[from] quick_xml::encoding::EncodingError)` variant
    // until then, fed by the decode step every content accessor used to
    // perform; 0.42 validates UTF-8 when it BUILDS the event instead, so the
    // failure now arrives as `quick_xml::Error::Encoding` and nothing in this
    // crate could construct the old variant any more. Do NOT put it back
    // without a call that can actually produce one.
    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("XML attribute error: {0}")]
    Attr(#[from] quick_xml::events::attributes::AttrError),
    #[error("NZB contains no files")]
    Empty,
    #[error("NZB truncated: document ends inside an open element")]
    Truncated,
    /// An entity in element text that is neither predefined, a character
    /// reference, nor one of the HTML latin-1 names indexers write.
    /// Refused rather than dropped: see the `GeneralRef` arm in
    /// [`Nzb::parse`].
    #[error("NZB uses an undefined entity: &{0};")]
    UnknownEntity(String),
    /// The document is well-formed XML but is not a well-formed NZB: a
    /// wrong root, a second root, or a core element somewhere the NZB
    /// grammar has no place for it. Refused rather than salvaged - see
    /// the context stack in [`Nzb::parse`], and TODO N6-03.
    #[error("NZB schema violation: {0}")]
    Schema(String),
    /// A structural ceiling in [`limits`] was reached. Carries what was
    /// exceeded and the ceiling, never the offending value: the point of
    /// refusing is to stop building, so there is nothing to report.
    ///
    /// N6-09: the HTTP body cap is on request BYTES and says nothing
    /// about manifest STRUCTURE, so a legal 256 MiB upload can declare
    /// ~13.4 million segments (measured: 20 wire bytes is the smallest
    /// legal `<segment>a</segment>`) and the parser alone retains ~48
    /// bytes per segment (measured on this tree, release profile, over
    /// 100k/500k/1m/2m). That is ~640 MB of parser residency from ONE
    /// in-cap request, before the plan adds its own slots, request
    /// vectors and bracketed ids.
    #[error("NZB exceeds the {0} limit ({1})")]
    TooLarge(&'static str, usize),
}

/// Structural ceilings applied while parsing, so a hostile manifest is
/// refused rather than built. See [`NzbError::TooLarge`] for the
/// measurement these are sized against; each one is stated here with
/// the real-world figure it clears, because a limit nobody can justify
/// is a limit the next reader raises to make a report go away.
pub mod limits {
    /// Most `<file>` entries. MEASURED over a 270-document field
    /// corpus on 2026-08-30 - the census written up at `child_ctx`:
    /// median 11, p99 202, largest 574 - a UHD remux.
    /// The three fixtures in this repo top out at 89, which is why
    /// this comment used to name that number and why it was three
    /// orders of magnitude out. 100k is 174x the largest real one and
    /// bounds the file vector at ~11 MB of `NzbFile` structs.
    pub const MAX_FILES: usize = 100_000;
    /// Most `<segment>` entries in the whole document, counting the
    /// refused ones - the refusal path allocates nothing but must not
    /// become the way past this.
    ///
    /// A 1m-segment post is ~750 GB at a realistic 768 KB article, or
    /// 16 TB at the 16 MB ceiling `Nzb::geometry_bytes` already
    /// assumes; the body cap permits 13.4m, so this binds 13x below
    /// the wire.
    ///
    /// The other half of that sentence used to read "90x above
    /// anything real", off the 11,060 the largest fixture in this repo
    /// declares. MEASURED over the same 270-document field corpus:
    /// median 1,391, p90 25,113, p99 108,348, largest **157,639**, and
    /// 44 of the 270 are over 11,060. So the real headroom is 6.3x,
    /// not 90x. Still ample, and left where it is - but a reader
    /// sizing anything else off "anything real" must use 157,639.
    pub const MAX_SEGMENTS: usize = 1_000_000;
    /// Longest `subject`, `poster` or `<meta>` value. A document
    /// carrying a longer one is refused rather than truncated, because
    /// truncating a subject silently renames the file it describes.
    ///
    /// "Four times any real subject" is what this used to say, and the
    /// same 270-document field corpus measured under [`MAX_SEGMENTS`]
    /// says 12.6x: longest subject 326 bytes (median 103, p99 218),
    /// longest poster 148, longest `<meta>` value 260.
    pub const MAX_FIELD: usize = 4096;
    /// Longest message-id or group name, and NOT an arbitrary number:
    /// RFC 3977 3.1 caps an NNTP command line at 512 octets, so a
    /// longer one can never be spelled as `BODY <id>` or `GROUP name`.
    /// Over-length is therefore unfetchable rather than malformed, and
    /// takes the same route as a wire-unsafe one - `dropped_segments`
    /// for an id, silently dropped for a group.
    pub const MAX_WIRE_TOKEN: usize = 512;
    /// Total retained text across every subject, poster, group,
    /// message-id and meta value. `MAX_FILES` x `MAX_FIELD` alone is
    /// 410 MB, so the per-field caps do not bound the document on their
    /// own. 64 MiB is 54x the largest real fixture's whole file.
    pub const MAX_TEXT_BYTES: usize = 64 << 20;
}

/// XML 1.0 production 3 `S`: space, tab, CR, LF - and nothing else.
///
/// N6-06: Rust's [`str::trim`] uses the Unicode `White_Space` property,
/// which is far wider than the four characters XML calls formatting
/// whitespace. That difference is invisible on ordinary input and
/// silently REWRITES explicit data on hostile input: a message-id
/// written `&#xa0;real@news.example` was trimmed to `real@news.example`
/// and the wrong article was fetched, a `<meta type="password">` of
/// `&#xa0;secret&#x2003;` became `secret` and extraction used the wrong
/// password, and a group name was rewritten the same way. A producer
/// writing a character reference at a field boundary MEANT that
/// character; only element-formatting space is ours to remove.
///
/// What survives the trim is then judged, not accepted: a U+00A0 left
/// on a message-id or group name fails [`is_wire_safe`] (NBSP is
/// `char::is_whitespace`), so the segment is charged to
/// `dropped_segments` and the group is dropped - refused honestly
/// rather than fetched under a fabricated key.
fn trim_xml_space(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// Append `piece` to an accumulating field, refusing to grow it past
/// `cap`. `false` means the field has overflowed and `dst` was left
/// alone - the caller latches that in [`Over`] and refuses the field at
/// its close.
///
/// N6-09: element TEXT is where a manifest's memory is unbounded even
/// with the segment and file ceilings in place, because one
/// `<segment>` body can be the whole request. Stopping at the cap is
/// what makes the refusal cheap: nothing past it is ever held.
fn push_capped(dst: &mut String, piece: &str, cap: usize) -> bool {
    if piece.len() > cap.saturating_sub(dst.len()) {
        return false;
    }
    dst.push_str(piece);
    true
}

/// Which of the three accumulating text fields has hit
/// [`limits::MAX_FIELD`] and stopped growing. Latched rather than acted
/// on immediately because the value is then a PREFIX by construction,
/// and a prefix is refused at the field's close rather than retained -
/// half a password is a wrong password, and half a message-id is an
/// article nobody posted.
#[derive(Default)]
struct Over {
    meta: bool,
    group: bool,
    segment: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nzb {
    pub files: Vec<NzbFile>,
    /// `<head><meta type="…">value</meta></head>` pairs (type lowercased).
    /// Indexers use these for password/category/title hints.
    pub meta: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NzbFile {
    pub subject: String,
    pub poster: String,
    /// Unix timestamp from the `date` attribute (0 if absent/unparseable).
    pub date: i64,
    pub groups: Vec<String>,
    pub segments: Vec<Segment>,
    /// Declared segments the parser refused (empty or wire-unsafe
    /// message-id). The file's byte range still includes them, so a
    /// downloader must treat each as a segment it can never fetch -
    /// silently shrinking the manifest turns a hostile NZB into a
    /// zero-filled file that finishes green.
    pub dropped_segments: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// 1-based part number within the file.
    pub number: u32,
    /// Encoded article size in bytes, per the NZB (approximate; trust yEnc headers).
    pub bytes: u64,
    /// Message-ID without angle brackets.
    pub message_id: String,
}

/// Coarse role of a file within the download, used by the minimality logic:
/// PAR2 volumes are never fetched speculatively, and only the main .par2
/// packet is needed up front for filenames + block hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// The small main `.par2` (index) file - fetch eagerly.
    Par2Main,
    /// A `.volNN+MM.par2` recovery volume - fetch only when repairing.
    Par2Volume,
    /// Actual payload.
    Data,
}

/// Is this NZB-supplied token safe to interpolate into an NNTP command line?
///
/// Message-ids and group names go straight into `BODY <{id}>` / `GROUP {name}`,
/// and NNTP is a CRLF-delimited protocol, so a CR or LF inside one ENDS our
/// command and starts an attacker's. A hostile NZB carrying
/// `a@b&#13;&#10;POST&#13;&#10;c@d` (the char-ref path resolves those to real
/// control characters, and a CDATA body can hold the raw bytes) would run
/// arbitrary commands - POST/IHAVE among them - on the user's authenticated,
/// paid provider session, and desync every pipelined reply after it.
///
/// A real message-id contains none of these (RFC 5536 forbids whitespace and
/// the delimiters), so rejecting is free on legitimate input.
pub fn is_wire_safe(s: &str) -> bool {
    !s.chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>'))
}

/// HTML's ISO-8859-1 named entities (U+00A0..U+00FF), which are NOT
/// defined in XML. NZBIndex-era generators emitted subjects like
/// `gesch&auml;ndeten` straight from HTML-escaped listings, so real
/// NZBs in the wild carry them (nzbget hit the same files: its issue
/// #699 is exactly this, and SABnzbd accepts them). Resolving just this
/// closed set keeps everything else strict - an entity outside the
/// table still fails the parse.
fn html_latin1_entity(name: &str) -> Option<&'static str> {
    Some(match name {
        // The XML predefined five: quick-xml's `*_with` normalizer uses
        // the supplied resolver INSTEAD of its predefined table (the
        // fallback documented on `unescape_with` does not apply on the
        // attribute-normalization path), so they must be listed here or
        // `&quot;` stops resolving.
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        "iexcl" => "¡",
        "cent" => "¢",
        "pound" => "£",
        "curren" => "¤",
        "yen" => "¥",
        "brvbar" => "¦",
        "sect" => "§",
        "uml" => "¨",
        "copy" => "©",
        "ordf" => "ª",
        "laquo" => "«",
        "not" => "¬",
        "shy" => "\u{ad}",
        "reg" => "®",
        "macr" => "¯",
        "deg" => "°",
        "plusmn" => "±",
        "sup2" => "²",
        "sup3" => "³",
        "acute" => "´",
        "micro" => "µ",
        "para" => "¶",
        "middot" => "·",
        "cedil" => "¸",
        "sup1" => "¹",
        "ordm" => "º",
        "raquo" => "»",
        "frac14" => "¼",
        "frac12" => "½",
        "frac34" => "¾",
        "iquest" => "¿",
        "Agrave" => "À",
        "Aacute" => "Á",
        "Acirc" => "Â",
        "Atilde" => "Ã",
        "Auml" => "Ä",
        "Aring" => "Å",
        "AElig" => "Æ",
        "Ccedil" => "Ç",
        "Egrave" => "È",
        "Eacute" => "É",
        "Ecirc" => "Ê",
        "Euml" => "Ë",
        "Igrave" => "Ì",
        "Iacute" => "Í",
        "Icirc" => "Î",
        "Iuml" => "Ï",
        "ETH" => "Ð",
        "Ntilde" => "Ñ",
        "Ograve" => "Ò",
        "Oacute" => "Ó",
        "Ocirc" => "Ô",
        "Otilde" => "Õ",
        "Ouml" => "Ö",
        "times" => "×",
        "Oslash" => "Ø",
        "Ugrave" => "Ù",
        "Uacute" => "Ú",
        "Ucirc" => "Û",
        "Uuml" => "Ü",
        "Yacute" => "Ý",
        "THORN" => "Þ",
        "szlig" => "ß",
        "agrave" => "à",
        "aacute" => "á",
        "acirc" => "â",
        "atilde" => "ã",
        "auml" => "ä",
        "aring" => "å",
        "aelig" => "æ",
        "ccedil" => "ç",
        "egrave" => "è",
        "eacute" => "é",
        "ecirc" => "ê",
        "euml" => "ë",
        "igrave" => "ì",
        "iacute" => "í",
        "icirc" => "î",
        "iuml" => "ï",
        "eth" => "ð",
        "ntilde" => "ñ",
        "ograve" => "ò",
        "oacute" => "ó",
        "ocirc" => "ô",
        "otilde" => "õ",
        "ouml" => "ö",
        "divide" => "÷",
        "oslash" => "ø",
        "ugrave" => "ù",
        "uacute" => "ú",
        "ucirc" => "û",
        "uuml" => "ü",
        "yacute" => "ý",
        "thorn" => "þ",
        "yuml" => "ÿ",
        _ => return None,
    })
}

/// The namespace an element resolved into, in a form that outlives the
/// event that carried it: `ResolveResult` borrows the reader, and the
/// ROOT's namespace has to survive every later comparison.
#[derive(Clone, Debug)]
enum Ns {
    /// No default namespace in scope - what most field NZBs are, and
    /// what every unprefixed attribute is by XML rule.
    Nothing,
    Uri(String),
    /// A prefix with no declaration in scope. Deliberately equal to
    /// NOTHING, itself included: an undeclared prefix names no
    /// vocabulary, so it can never be the core one.
    Unknown,
}

impl Ns {
    fn of(r: &ResolveResult) -> Ns {
        match r {
            ResolveResult::Unbound => Ns::Nothing,
            ResolveResult::Bound(n) => Ns::Uri(n.as_ref().to_string()),
            ResolveResult::Unknown(_) => Ns::Unknown,
        }
    }
}

// NOT derived, and not `Eq` either: `Unknown != Unknown` is the point,
// which is not a reflexive relation. See the variant's own note.
impl PartialEq for Ns {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Ns::Nothing, Ns::Nothing) => true,
            (Ns::Uri(a), Ns::Uri(b)) => a == b,
            _ => false,
        }
    }
}

/// One open element on the parse stack. The NZB grammar is small enough
/// to name in full, and naming it in full is what makes "a core tag in
/// the wrong place" answerable at all: the old parser kept a bare depth
/// counter plus one `cur_file`/`cur_segment`, so nesting silently
/// OVERWROTE the outer entry (N6-03).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctx {
    Nzb,
    Head,
    Meta,
    File,
    Groups,
    Group,
    Segments,
    Segment,
    /// Somebody else's vocabulary - an extension element. Ignored
    /// wholesale, itself and every descendant.
    Foreign,
}

impl Ctx {
    fn name(self) -> &'static str {
        match self {
            Ctx::Nzb => "nzb",
            Ctx::Head => "head",
            Ctx::Meta => "meta",
            Ctx::File => "file",
            Ctx::Groups => "groups",
            Ctx::Group => "group",
            Ctx::Segments => "segments",
            Ctx::Segment => "segment",
            Ctx::Foreign => "a namespace extension",
        }
    }
}

/// Element names the NZB grammar reserves. A core-namespace element
/// wearing one of these somewhere the grammar has no place for it is
/// REFUSED rather than ignored, because ignoring is how a declared file
/// disappears: `<x:file><segments><segment>…` has core-namespace
/// segments (an unprefixed name takes the DEFAULT namespace, which the
/// root declared) hanging off an element that is not a file, and there
/// is no honest reading of that. Refusing is the completion rule's
/// other half - accepted accurately or refused honestly.
const RESERVED: [&str; 8] = [
    "nzb", "head", "meta", "file", "groups", "group", "segments", "segment",
];

/// The context a child element opens, or `None` to refuse the document.
///
/// THE EXACT-PARENT RULE IS MEASURED, NOT ASSUMED. N6-03 landed this
/// table against synthetic inputs and the three `.nzb` fixtures this
/// repo owns, and the shapes most likely to be a real DIALECT rather
/// than a hostile document are the two where an exact parent is
/// demanded: `<group>` written straight under `<file>` with no
/// `<groups>`, and `<segment>` under `<file>` with no `<segments>`.
/// Both are refused here, and refusing a dialect refuses a download
/// the user can see is fine.
///
/// So they were counted. 270 unique documents on 2026-08-30 - 253 real
/// manifests off the indexers in use, byte-for-byte as fetched, plus
/// the 17 NZB fixtures the SABnzbd and NZBGet projects publish - 224.6
/// MB of XML, 118 distinct structural signatures, at least nine
/// generator families (newznab, nZEDb, NZBgeek, Binsearch, NZBIndex,
/// NewsbinPro, yEncBin Poster, JBinUp, and 91 documents carrying no
/// generator stamp at all). EVERY ONE PARSES. The full core edge set
/// the corpus writes is exactly the eight this table allows, and the
/// count of `<file>`-to-`<group>`, `<file>`-to-`<segment>`, foreign
/// wrappers of core children, second roots and non-`<nzb>` roots is
/// ZERO in all 270. Nothing here was loosened, on evidence.
///
/// The sample's own weakness, stated because a census that implies
/// coverage it lacks is worse than none: 253 of the 270 are one
/// household's download history, so they are the mainstream
/// Newznab-family sites that household subscribes to and not the long
/// tail of small, regional or single-topic ones. A wrapper-less
/// `<group>` turning up in the field later is answered by relaxing
/// THESE TWO EDGES ONLY to a parent-chain test ("is a `File` anywhere
/// below me on the stack"). It is never answered by relaxing the root,
/// second-root or nesting arms: those four are the ones that were
/// silently losing files, so a hit there is a broken or hostile
/// manifest and not a dialect.
fn child_ctx(parent: Ctx, local: &str, is_core: bool) -> Option<Ctx> {
    if !is_core {
        return Some(Ctx::Foreign);
    }
    let allowed = match (parent, local) {
        (Ctx::Nzb, "head") => Some(Ctx::Head),
        (Ctx::Nzb, "file") => Some(Ctx::File),
        (Ctx::Head, "meta") => Some(Ctx::Meta),
        (Ctx::File, "groups") => Some(Ctx::Groups),
        (Ctx::File, "segments") => Some(Ctx::Segments),
        (Ctx::Groups, "group") => Some(Ctx::Group),
        (Ctx::Segments, "segment") => Some(Ctx::Segment),
        _ => None,
    };
    if allowed.is_some() {
        return allowed;
    }
    if RESERVED.contains(&local) {
        return None;
    }
    Some(Ctx::Foreign)
}

/// Is this attribute part of the core NZB vocabulary?
///
/// Core NZB attributes are UNPREFIXED, always: an unprefixed attribute
/// takes NO namespace in XML (the default `xmlns` does not reach
/// attributes), so "no prefix" is the whole test and no resolver call is
/// needed. A prefixed one belongs to whoever declared that prefix and is
/// ignored - including the vanishingly rare case of a prefix bound to
/// the core namespace itself, which costs nothing because it can only
/// ever be a second spelling of a value the unprefixed attribute already
/// carries. What it BUYS is N6-02: `x:subject="decoy.vol000+10.par2"`
/// no longer overwrites `subject="movie.mkv"`, in either attribute
/// order, so one manifest has one reading.
fn core_attr<'a>(a: &'a quick_xml::events::attributes::Attribute<'a>) -> Option<&'a str> {
    // Split by hand rather than through `key.local_name()`: that returns
    // a `LocalName` BY VALUE and its `AsRef<str>` borrows the temporary,
    // so the local name cannot outlive the call.
    let qname: &'a str = a.key.as_ref();
    match qname.split_once(':') {
        Some(_) => None,
        None => Some(qname),
    }
}

fn attr_value(a: &quick_xml::events::attributes::Attribute) -> Result<String, NzbError> {
    Ok(
        a.normalized_value_with(XmlVersion::Implicit1_0, 128, html_latin1_entity)?
            .into_owned(),
    )
}

fn file_attrs(e: &BytesStart) -> Result<NzbFile, NzbError> {
    let mut f = NzbFile::default();
    for attr in e.attributes() {
        let attr = attr?;
        let Some(name) = core_attr(&attr) else {
            continue;
        };
        match name {
            // N6-09: refused, never truncated - a shortened subject is a
            // different filename, and every namer downstream would
            // believe it.
            "subject" | "poster" => {
                let v = attr_value(&attr)?;
                if v.len() > limits::MAX_FIELD {
                    return Err(NzbError::TooLarge(
                        "subject/poster length",
                        limits::MAX_FIELD,
                    ));
                }
                if name == "subject" {
                    f.subject = v;
                } else {
                    f.poster = v;
                }
            }
            "date" => f.date = trim_xml_space(&attr_value(&attr)?).parse().unwrap_or(0),
            _ => {}
        }
    }
    Ok(f)
}

/// The `<segment …>` attribute read. Returns the segment, and whether a
/// numeric attribute was PRESENT and would not parse - the caller
/// charges that one to `dropped_segments` at `</segment>`.
fn segment_attrs(e: &BytesStart) -> Result<(Segment, bool), NzbError> {
    // N6-08: `bytes` and `number` are REQUIRED by the NZB DTD, and both used
    // to be `parse().unwrap_or(0)` - so `bytes="abc"`, `bytes="-5"`, a value
    // one past `u64::MAX` and an absent attribute all became a perfectly
    // ordinary declared ZERO. Nothing downstream can tell that apart from a
    // producer saying the article is empty: `total_bytes()` under-reports the
    // job, every plan offset and seek estimate derives from these bytes, and a
    // file whose `enc_total` collapses to 0 has its whole byte-range mapping
    // SKIPPED (`streamhub`'s `enc_total > 0` guard).
    //
    // So an attribute that is PRESENT and does not parse is refused rather
    // than zeroed. The segment is still DECLARED: it goes to
    // `dropped_segments` at `</segment>`, which is precisely that field's
    // contract (a segment the parser refused, whose bytes the file still
    // owes), so the job repairs or fails instead of finishing green over a
    // hole.
    //
    // AN ABSENT ATTRIBUTE IS NOT REFUSED, and that is the line this rule
    // turns on rather than a softening of it. This repo already has an
    // explicit, tested position on the no-`bytes=` post: "0 posted bytes
    // means unknown, not zero", with `Nzb::geometry_bytes` as the ceiling
    // that replaces the byte claim (`repair::sidefetch::volume_prealloc_cap`
    // and its `an_nzb_without_byte_attributes_is_bounded_by_its_geometry`).
    // Refusing that shape would break a posting convention the codebase
    // supports on purpose. Silence is an honest unknown the product already
    // models; a NONSENSE value is a claim, and turning a claim into a valid
    // zero is the defect.
    //
    // An EXPLICIT `0` is accepted for the same reason. `bytes` is documented
    // as approximate - the yEnc header is the authority - and `number` 0 is
    // the pool's own spelling of "part unknown" (`ArticleReq::part`), where
    // the part-mismatch gate stands down.
    let mut seg = Segment {
        number: 0,
        bytes: 0,
        message_id: String::new(),
    };
    let mut bad_attr = false;
    for attr in e.attributes() {
        let attr = attr?;
        let Some(name) = core_attr(&attr) else {
            continue;
        };
        match name {
            "bytes" => match trim_xml_space(&attr_value(&attr)?).parse::<u64>() {
                Ok(v) => seg.bytes = v,
                Err(_) => bad_attr = true,
            },
            "number" => match trim_xml_space(&attr_value(&attr)?).parse::<u32>() {
                Ok(v) => seg.number = v,
                Err(_) => bad_attr = true,
            },
            _ => {}
        }
    }
    Ok((seg, bad_attr))
}

fn meta_type(e: &BytesStart) -> Result<String, NzbError> {
    for attr in e.attributes() {
        let attr = attr?;
        if core_attr(&attr) == Some("type") {
            let raw = attr_value(&attr)?;
            if raw.len() > limits::MAX_FIELD {
                return Err(NzbError::TooLarge("meta type length", limits::MAX_FIELD));
            }
            // Still a generic `trim()`, and deliberately so: a meta TYPE
            // is a vocabulary token this parser matches against
            // ("password"), not data it hands anybody. Trimming it
            // widely cannot rewrite a secret - the VALUE is what N6-06
            // is about, and that one takes `trim_xml_space`.
            return Ok(raw.trim().to_lowercase());
        }
    }
    Ok(String::new())
}

/// Append a text fragment to whichever field the INNERMOST open element
/// is, and to nothing otherwise. Shared by the Text, CData and
/// GeneralRef arms so the three cannot drift on which field they feed.
fn accumulate(
    ctx: Option<&Ctx>,
    text: &str,
    cur_meta: &mut Option<(String, String)>,
    cur_group: &mut Option<String>,
    cur_segment: &mut Option<Segment>,
    over: &mut Over,
) {
    // N6-09: every append is capped at `limits::MAX_FIELD` and the
    // overflow is latched, because ONE element's text can be the whole
    // request - the segment and file ceilings say nothing about it.
    match ctx {
        Some(Ctx::Meta) => {
            if let Some((_, v)) = cur_meta.as_mut() {
                over.meta |= !push_capped(v, text, limits::MAX_FIELD);
            }
        }
        Some(Ctx::Group) => {
            if let Some(g) = cur_group.as_mut() {
                over.group |= !push_capped(g, text, limits::MAX_FIELD);
            }
        }
        Some(Ctx::Segment) => {
            if let Some(seg) = cur_segment.as_mut() {
                over.segment |= !push_capped(&mut seg.message_id, text, limits::MAX_FIELD);
            }
        }
        _ => {}
    }
}

impl Nzb {
    // Attribute values go through XML attribute-value normalization, on
    // purpose. A comment here used to claim the opposite - that the
    // deprecated `unescape_value_with` skipped it - and that was never
    // true: in quick-xml 0.41 that name is a thin alias for exactly the
    // `normalized_value_with(Implicit1_0, 128, ..)` call below, so a
    // LITERAL tab/CR/LF inside a `subject=` has always arrived as a
    // space and no downstream matcher has ever seen one. That is what
    // the XML spec requires and what every other NZB reader does, so
    // the call is now spelled honestly rather than the behaviour
    // changed. A producer that really means a tab writes `&#9;`, which
    // normalization leaves alone - both halves are pinned by
    // `subject_whitespace_is_normalized_per_xml_spec`.
    pub fn parse(xml: &[u8]) -> Result<Nzb, NzbError> {
        // An NsReader, not a plain Reader, and that is the whole of
        // N6-02. Dispatch used to be on `local_name()` alone, so an
        // unrelated namespace extension was indistinguishable from core
        // vocabulary: `<x:file>` parsed as a file, and
        // `subject="movie.mkv" x:subject="decoy.vol000+10.par2"` ended
        // with the decoy - reversing the attribute order reversed the
        // parsed name AND the FileKind, so one manifest had two
        // readings and the payload was the one that lost.
        let mut reader = NsReader::from_reader(xml);
        // NOT trim_text(true): quick-xml would trim each text EVENT, and
        // entities split one value into several events - the spaces
        // around `&amp;` in a password vanished. Every consuming arm
        // below trims for itself instead (meta as a whole at </meta>).
        reader.config_mut().trim_text(false);

        let mut files: Vec<NzbFile> = Vec::new();
        let mut meta: Vec<(String, String)> = Vec::new();
        let mut cur_file: Option<NzbFile> = None;
        let mut cur_segment: Option<Segment> = None;
        let mut cur_meta: Option<(String, String)> = None;
        // Group names accumulate like meta values rather than being
        // pushed per text EVENT: an entity splits one name into
        // Text/GeneralRef/Text, and pushing each fragment invented two
        // groups out of one ("alt.bin&amp;ary" became `alt.bin` + `ary`,
        // neither of which exists).
        let mut cur_group: Option<String> = None;
        // The document's core namespace, taken from the ROOT rather than
        // pinned to the newzbin URI: a field NZB that declares a variant
        // xmlns (or none at all - most hand-written ones) must keep
        // parsing, and "core vocabulary is whatever the root is in" is
        // the rule that still gives an extension prefix somewhere else
        // to be. `None` until the root is read.
        let mut core_ns: Option<Ns> = None;
        // The open element chain. Replaces the bare `depth` counter,
        // which could only answer "are we inside something" - so a
        // `<file>` nested in a `<file>` REPLACED the outer one and lost
        // it, a `<segment>` nested in a `<segment>` did the same with no
        // `dropped_segments` charge, a lone `<file>` under a non-NZB
        // wrapper was accepted, and two concatenated `<nzb>` roots
        // merged into one manifest (N6-03). It also still answers the
        // question `depth` was there for: quick-xml reports Eof, not an
        // error, when the input ends with elements still open, and a
        // truncated NZB would otherwise "parse" as whatever files
        // happened to close before the cut - the shrunken manifest
        // finishes green with data missing.
        let mut stack: Vec<Ctx> = Vec::new();
        let mut root_done = false;
        // N6-09: structural budget, counted as the document is READ so a
        // hostile manifest is refused while it is being built rather
        // than after. `declared_segments` counts REFUSED segments too,
        // since a refusal allocates nothing and must not be the way
        // past the ceiling.
        let mut declared_segments: usize = 0;
        let mut text_bytes: usize = 0;
        let mut over = Over::default();
        let mut buf = Vec::new();

        loop {
            let (ns, ev) = reader.read_resolved_event_into(&mut buf)?;
            match ev {
                // `Event::Empty` used to reach ONLY the `<segment/>`
                // arm, so a self-closing `<file subject="x.rar"/>`
                // beside a healthy file parsed as ONE file: the declared
                // name charged no `dropped_segments`, the plan built no
                // slot, and every later count was self-consistent
                // without it - a payload named in the manifest, never
                // mentioned again, job green (N6-01). Both shapes take
                // the same path now; an empty element simply pushes no
                // context and closes immediately.
                Event::Start(ref e) | Event::Empty(ref e) => {
                    let empty = matches!(ev, Event::Empty(_));
                    let ns = Ns::of(&ns);
                    let local_owned = e.local_name();
                    let local = local_owned.as_ref();
                    let ctx = if stack.is_empty() {
                        if root_done {
                            return Err(NzbError::Schema(
                                "document has more than one root element".into(),
                            ));
                        }
                        if local != "nzb" {
                            return Err(NzbError::Schema(format!(
                                "root element is <{local}>, not <nzb>"
                            )));
                        }
                        core_ns = Some(ns);
                        Ctx::Nzb
                    } else {
                        let is_core = core_ns.as_ref() == Some(&ns);
                        let parent = *stack.last().expect("stack is non-empty here");
                        match child_ctx(parent, local, is_core) {
                            Some(c) => c,
                            None => {
                                return Err(NzbError::Schema(format!(
                                    "<{local}> is not allowed inside <{}>",
                                    parent.name(),
                                )));
                            }
                        }
                    };
                    match ctx {
                        Ctx::File => {
                            if files.len() >= limits::MAX_FILES {
                                return Err(NzbError::TooLarge("file count", limits::MAX_FILES));
                            }
                            let mut f = file_attrs(e)?;
                            text_bytes = text_bytes
                                .saturating_add(f.subject.len())
                                .saturating_add(f.poster.len());
                            if text_bytes > limits::MAX_TEXT_BYTES {
                                return Err(NzbError::TooLarge(
                                    "total text",
                                    limits::MAX_TEXT_BYTES,
                                ));
                            }
                            if empty {
                                // Exactly `<file …></file>` with no
                                // segments, which the `</file>` arm
                                // below already charges one missing
                                // segment for.
                                f.dropped_segments = 1;
                                files.push(f);
                            } else {
                                cur_file = Some(f);
                            }
                        }
                        Ctx::Group if !empty => {
                            cur_group = Some(String::new());
                            over.group = false;
                        }
                        Ctx::Meta if !empty => {
                            cur_meta = Some((meta_type(e)?, String::new()));
                            over.meta = false;
                        }
                        Ctx::Segment => {
                            // N6-09: counted in BOTH spellings, and the
                            // self-closing one allocates nothing - which
                            // is exactly why it must be counted, or the
                            // cheapest legal segment is the one that
                            // walks past the ceiling.
                            declared_segments += 1;
                            if declared_segments > limits::MAX_SEGMENTS {
                                return Err(NzbError::TooLarge(
                                    "segment count",
                                    limits::MAX_SEGMENTS,
                                ));
                            }
                            if empty {
                                // Self-closing elements never pair with
                                // an End, and `expand_empty_elements` is
                                // off, so `<segment ... />` reached
                                // neither the Start nor the End arm: a
                                // declared segment vanished with nothing
                                // counted, which is exactly what
                                // `dropped_segments` exists to prevent
                                // (the same segment written `<segment
                                // …></segment>` does count). It carries
                                // no message-id by construction, so
                                // there is nothing to fetch - only
                                // something to declare.
                                if let Some(f) = cur_file.as_mut() {
                                    f.dropped_segments += 1;
                                }
                            } else {
                                let (seg, bad) = segment_attrs(e)?;
                                over.segment = bad;
                                cur_segment = Some(seg);
                            }
                        }
                        _ => {}
                    }
                    if empty {
                        if ctx == Ctx::Nzb {
                            root_done = true;
                        }
                    } else {
                        stack.push(ctx);
                    }
                }
                Event::Text(t) => {
                    let text = t.xml10_content();
                    // Meta values keep their fragments UNTRIMMED and are
                    // trimmed once as a whole at </meta>: entities split
                    // the text into separate events, and per-fragment
                    // trimming ate the spaces around them - a password
                    // of `secret &amp; more` decoded to `secret&more`
                    // and extraction used the wrong password.
                    //
                    // Gated on the INNERMOST context rather than on
                    // "some accumulator is open", so text inside a
                    // namespace extension nested in a core element -
                    // `<segment>id<x:note>junk</x:note></segment>` -
                    // cannot append to the core field (N6-02).
                    //
                    // Message-ids accumulate UNTRIMMED like meta values,
                    // trimmed once at </segment>: per-fragment trimming ate
                    // the spaces around entities, so an id declared with
                    // interior whitespace (wire-unsafe, owed to
                    // dropped_segments) was silently rewritten into a
                    // fabricated id that passed is_wire_safe and was
                    // fetched as something never posted.
                    accumulate(
                        stack.last(),
                        &text,
                        &mut cur_meta,
                        &mut cur_group,
                        &mut cur_segment,
                        &mut over,
                    );
                }
                Event::CData(c) => {
                    // quick-xml emits `<![CDATA[...]]>` as its own event,
                    // distinct from Text/GeneralRef. Without this arm a
                    // CDATA-wrapped message-id (or meta value / group name)
                    // is silently dropped and the article never fetched.
                    // CDATA content is literal - no entity unescaping.
                    // NOT `String::from_utf8_lossy` any more, and that is a
                    // behaviour change rather than a spelling one: quick-xml
                    // 0.42 validates UTF-8 when it BUILDS the event, so a
                    // latin-1 byte inside a CDATA body now fails the whole
                    // parse where it used to arrive as U+FFFD. Measured 28 Aug
                    // 2026 across both versions - a subject or a text node
                    // already hard-failed under 0.41, so CDATA was the one
                    // place a bad byte was silently swallowed, and swallowing
                    // it produced a WRONG meta password or a message-id that
                    // was never posted. Pinned by
                    // `cdata_with_a_latin1_byte_is_refused_not_corrupted`.
                    //
                    // Same accumulation rules as Text above.
                    let raw = c.into_inner();
                    accumulate(
                        stack.last(),
                        &raw,
                        &mut cur_meta,
                        &mut cur_group,
                        &mut cur_segment,
                        &mut over,
                    );
                }
                Event::GeneralRef(r) => {
                    // Entities inside text arrive as their own event
                    // ("p&amp;w" = Text/GeneralRef/Text): resolve the
                    // predefined five + char refs and append wherever the
                    // surrounding text is accumulating.
                    let resolved = if let Some(c) = r.resolve_char_ref()? {
                        c.to_string()
                    } else {
                        let name = r.xml10_content();
                        match name.as_ref() {
                            "amp" => "&".to_string(),
                            "lt" => "<".to_string(),
                            "gt" => ">".to_string(),
                            "quot" => "\"".to_string(),
                            "apos" => "'".to_string(),
                            // REJECT, never drop. An entity this parser
                            // cannot resolve used to vanish, so
                            // `abc&bogus;def@news` silently became
                            // `abcdef@news` - a message-id that does not
                            // exist, fetched, 430'd and counted missing,
                            // with no parse error anywhere. The
                            // attribute path has always errored on the
                            // same input (quick-xml's own resolver
                            // call); text now matches it.
                            _ => match html_latin1_entity(name.as_ref()) {
                                Some(c) => c.to_string(),
                                None => return Err(NzbError::UnknownEntity(name.into_owned())),
                            },
                        }
                    };
                    accumulate(
                        stack.last(),
                        &resolved,
                        &mut cur_meta,
                        &mut cur_group,
                        &mut cur_segment,
                        &mut over,
                    );
                }
                Event::End(_) => {
                    // The name is not consulted: quick-xml has already
                    // proven this End matches the open Start (it errors
                    // on a mismatch), so the STACK says what closed -
                    // and the stack is what knows whether that `<file>`
                    // was a core file or an extension's.
                    let Some(ctx) = stack.pop() else {
                        return Err(NzbError::Schema("stray closing tag".into()));
                    };
                    match ctx {
                        Ctx::Nzb => root_done = true,
                        Ctx::File => {
                            if let Some(mut f) = cur_file.take() {
                                // Segments arrive in document order which is not
                                // guaranteed to be part order.
                                f.segments.sort_by_key(|s| s.number);
                                // A `<file>` that declares NO segment at all -
                                // none fetchable, none dropped - planned as a
                                // slot with nothing owed: `total_segments` 0,
                                // `remaining` 0, `missing` 0 (see `get::plan`).
                                // The census only counts a file incomplete when
                                // something is missing or unresolved, so the job
                                // finished GREEN having written nothing for that
                                // name, and repair never ran because nothing was
                                // missing. Same reasoning as the self-closing
                                // `<segment/>` arm above: there is nothing to
                                // fetch, only something to DECLARE - so declare
                                // it, and the file either repairs through PAR2
                                // or fails the job.
                                if f.segments.is_empty() && f.dropped_segments == 0 {
                                    f.dropped_segments = 1;
                                }
                                files.push(f);
                            }
                        }
                        Ctx::Group => {
                            let over = std::mem::take(&mut over.group);
                            if let Some(g) = cur_group.take()
                                && let Some(f) = cur_file.as_mut()
                            {
                                // N6-06: `trim_xml_space`, not `trim()`.
                                // A boundary `&#xa0;` used to vanish and
                                // the rewritten name was sent as
                                // `GROUP <name>`; now it survives, fails
                                // `is_wire_safe`, and the group is
                                // dropped the way every other unusable
                                // group name is. N6-09: over-length is
                                // the same verdict - RFC 3977 3.1 caps
                                // the command line, so a longer name can
                                // never be spelled on the wire.
                                let g = trim_xml_space(g.as_str());
                                if !over
                                    && !g.is_empty()
                                    && g.len() <= limits::MAX_WIRE_TOKEN
                                    && is_wire_safe(g)
                                {
                                    text_bytes = text_bytes.saturating_add(g.len());
                                    if text_bytes > limits::MAX_TEXT_BYTES {
                                        return Err(NzbError::TooLarge(
                                            "total text",
                                            limits::MAX_TEXT_BYTES,
                                        ));
                                    }
                                    f.groups.push(g.to_string());
                                }
                            }
                        }
                        Ctx::Meta => {
                            let over = std::mem::take(&mut over.meta);
                            if let Some((ty, val)) = cur_meta.take() {
                                // One whole-value trim, replacing the old
                                // per-fragment trims: element-formatting
                                // whitespace goes, interior spaces stay.
                                //
                                // N6-06: XML `S` only. This value is the
                                // archive PASSWORD on the convention
                                // every newznab site uses, and a generic
                                // Unicode trim rewrote
                                // `&#xa0;secret&#x2003;` to `secret` -
                                // a correct password turned into a wrong
                                // one, silently, with extraction then
                                // failing for a reason nothing reports.
                                // A producer who writes a character
                                // reference at the boundary meant it.
                                let val = trim_xml_space(val.as_str()).to_string();
                                // N6-09: an over-length value stopped
                                // accumulating, so what is held is a
                                // PREFIX. Dropped rather than retained:
                                // half a password is a wrong password.
                                if !over && !ty.is_empty() && !val.is_empty() {
                                    text_bytes = text_bytes.saturating_add(ty.len() + val.len());
                                    if text_bytes > limits::MAX_TEXT_BYTES {
                                        return Err(NzbError::TooLarge(
                                            "total text",
                                            limits::MAX_TEXT_BYTES,
                                        ));
                                    }
                                    meta.push((ty, val));
                                }
                            }
                        }
                        Ctx::Segment => {
                            let bad = std::mem::take(&mut over.segment);
                            if let (Some(f), Some(mut seg)) =
                                (cur_file.as_mut(), cur_segment.take())
                            {
                                // One whole-value trim, like </meta>:
                                // element-formatting whitespace goes,
                                // interior whitespace stays and fails
                                // is_wire_safe into dropped_segments.
                                //
                                // N6-06: `trim_xml_space`, not `trim()`.
                                // `&#xa0;real@news.example` used to be
                                // rewritten to `real@news.example` and
                                // FETCHED under that key - a different
                                // article from the one declared. The
                                // NBSP now survives, `is_wire_safe`
                                // refuses it, and the segment is charged
                                // as one that can never be fetched.
                                let id = trim_xml_space(seg.message_id.as_str());
                                // N6-09: RFC 3977 3.1 caps an NNTP
                                // command line at 512 octets, so a
                                // longer id can never be spelled as
                                // `BODY <id>`. Unfetchable takes the
                                // same route as wire-unsafe.
                                // N6-08: `bad` is a required numeric
                                // attribute that was present and would
                                // not parse.
                                if !bad
                                    && !id.is_empty()
                                    && id.len() <= limits::MAX_WIRE_TOKEN
                                    && is_wire_safe(id)
                                {
                                    if id.len() != seg.message_id.len() {
                                        seg.message_id = id.to_string();
                                    }
                                    text_bytes = text_bytes.saturating_add(seg.message_id.len());
                                    if text_bytes > limits::MAX_TEXT_BYTES {
                                        return Err(NzbError::TooLarge(
                                            "total text",
                                            limits::MAX_TEXT_BYTES,
                                        ));
                                    }
                                    f.segments.push(seg);
                                } else {
                                    f.dropped_segments += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Event::Eof => {
                    if !stack.is_empty() {
                        return Err(NzbError::Truncated);
                    }
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        if files.is_empty() {
            return Err(NzbError::Empty);
        }
        Ok(Nzb { files, meta })
    }

    /// Archive password embedded by the indexer, if any: a
    /// `<meta type="password">` entry (the x264/scene convention used by
    /// most newznab sites).
    pub fn password(&self) -> Option<&str> {
        self.meta
            .iter()
            .find(|(t, v)| t == "password" && !v.is_empty())
            .map(|(_, v)| v.as_str())
    }

    /// Total encoded bytes across all files (what a naive client downloads).
    pub fn total_bytes(&self) -> u64 {
        // Saturating: the per-segment `bytes` come from an untrusted NZB
        // attribute (up to u64::MAX); a plain sum panics in debug and wraps
        // in release, corrupting size-based routing/display.
        self.files
            .iter()
            .map(NzbFile::bytes)
            .fold(0u64, u64::saturating_add)
    }

    /// A preallocation ceiling justified by the post's GEOMETRY rather
    /// than its byte claims: declared articles times a generous
    /// per-article maximum. Both the NZB's `bytes=` attributes and the
    /// yEnc `size=` header are poster-controlled, so `min(size, posted
    /// bytes)` is an attacker choosing both sides - one tiny article
    /// carrying two 100 GB claims turned into a real Linux `fallocate`
    /// of the victim's free space. Articles are different: reserving
    /// more space means DECLARING more articles, every one of which the
    /// downloader fetches and holds the job accountable for. No real
    /// article approaches 16 MB (providers cap them far lower), so this
    /// never binds on a legitimate post.
    pub fn geometry_bytes(&self) -> u64 {
        const MAX_ARTICLE_BYTES: u64 = 16 << 20;
        self.files
            .iter()
            .map(|f| (f.segments.len() + f.dropped_segments) as u64)
            .fold(0u64, u64::saturating_add)
            .saturating_mul(MAX_ARTICLE_BYTES)
    }

    /// Encoded bytes excluding PAR2 recovery volumes (what we download
    /// up front - layer 1 of the minimality plan).
    pub fn eager_bytes(&self) -> u64 {
        self.files
            .iter()
            .filter(|f| f.kind() != FileKind::Par2Volume)
            .map(NzbFile::bytes)
            .fold(0u64, u64::saturating_add)
    }

    /// The cheapest file in this NZB whose head carries the recovery
    /// set's critical packets: the smallest `.par2` index if the post
    /// ships one, else the smallest recovery volume.
    ///
    /// Two callers, one question. The download path asks it because an
    /// obfuscated post often ships volumes and no plain index, and the
    /// critical packets (Main/FileDesc/IFSC) are duplicated into every
    /// volume, so the smallest volume bootstraps the set for a few tens
    /// of KB (`get::plan`). Pre-flight asks it because the Main packet
    /// is the only place the set's BLOCK SIZE is written down, and
    /// without that figure a `.vol-NN.par2` budget cannot be sized at
    /// all (`nzbfast check`). Answering it twice is how the two paths
    /// would drift.
    ///
    /// Smallest by encoded bytes on purpose: for an index that is the
    /// whole file, and for a volume it is the one with the fewest
    /// recovery slices in front of the packets we came for.
    pub fn par2_seed_file(&self) -> Option<usize> {
        let pick = |kind: FileKind| {
            self.files
                .iter()
                .enumerate()
                .filter(|(_, f)| f.kind() == kind && !f.segments.is_empty())
                .min_by_key(|(_, f)| f.bytes())
                .map(|(i, _)| i)
        };
        pick(FileKind::Par2Main).or_else(|| pick(FileKind::Par2Volume))
    }
}

impl NzbFile {
    pub fn bytes(&self) -> u64 {
        self.segments
            .iter()
            .map(|s| s.bytes)
            .fold(0u64, u64::saturating_add)
    }

    /// The filename quoted in the subject, per the near-universal posting
    /// convention `… "filename.ext" yEnc …`. Obfuscated posts may lie;
    /// the PAR2 main packet is the authority once we have it.
    pub fn filename_hint(&self) -> Option<&str> {
        quoted_filename(&self.subject)
    }

    /// [`Self::filename_hint`], falling back to an UNQUOTED filename
    /// read out of the subject (issue #55): some posters write
    /// `subject="10-Track Name-8c63a701.flac (1/0)"`, no quotes at all,
    /// and the quoted-only read left those slots named `fileNNN` with
    /// the real name discarded. The fallback is deliberately strict
    /// (see [`unquoted_filename`]) and this is deliberately a SECOND
    /// method rather than a change to `filename_hint`: the quoted read
    /// feeds classification and import paths whose behavior on prose
    /// subjects is settled, so only callers that would otherwise invent
    /// an anonymous name opt into the wider parse.
    pub fn filename_hint_lenient(&self) -> Option<&str> {
        self.filename_hint()
            .or_else(|| unquoted_filename(&self.subject))
    }

    pub fn kind(&self) -> FileKind {
        self.classify().kind()
    }

    /// [`Self::kind`], keeping the name and the rule it was decided
    /// under. Take this rather than `kind()` whenever the answer to
    /// "which file is this" is followed by a question about the same
    /// name's SHAPE - the set stem, the volume suffix - so the two
    /// cannot be asked under different rules. See [`SubjectClass`].
    pub fn classify(&self) -> SubjectClass<'_> {
        classify_subject_detail(&self.subject)
    }
}

/// The quoted filename in a subject: the first `"…"` run that looks like
/// a filename (contains a dot) AND whose own kind is the one
/// [`classify_subject`] reached for the subject as a whole, else the
/// first dotted run, else the first non-empty quoted run.
/// Posts like `"S01E01" - "Show.part01.rar" yEnc (1/2)` put a decoy
/// first - taking quote #1 unconditionally misclassified the file.
///
/// T5: the agreeing-run clause is what the first-dotted-run rule could
/// not do. On the N6-04 ambiguity class - two or more dotted runs whose
/// own kinds DISAGREE, so the subject answers `Data` - the first dotted
/// run can be the recovery-volume name while the file is payload:
/// `"label.vol000+50.par2" - "Movie.mkv"` named the slot, the per-file
/// API row, the donor key and the FileDesc length lookup after a volume
/// that the classifier had already refused to treat as one. Preferring a
/// run that agrees with the final kind names `Movie.mkv` instead. It is
/// inert everywhere else BY CONSTRUCTION: with no disagreement the first
/// dotted run agrees by definition and is picked exactly as before, and
/// where nothing agrees (`"a.par2" - "b.vol000+50.par2"`, Par2Main
/// against Par2Volume) the old rule is the fallback. It cannot help the
/// mirror shape `"Show.S01E01" - "Show.vol000+50.par2"`, where both runs
/// are plausible names and the label agrees with `Data` first - no
/// par2-awareness in a PICK can separate those two.
///
/// The rule lives HERE and not in [`NzbFile::filename_hint`] because two
/// callers reach the pick without it - `index::ingest::quoted_name` and
/// `faultplan::vol_first_block` - and a rule spelled twice is the
/// hand-copied-twin class `role_of` was found in.
///
/// N6-10: a candidate the OUTPUT-NAME policy cannot carry is skipped,
/// not returned. `unquoted_filename` has capped its candidate at 255
/// bytes since it was written; this one had no cap at all, so a
/// 5,000-byte quoted name parsed, planned, and downloaded, and failed
/// only when the leaf was created - after the network work, at the
/// filesystem, with a message about a name nobody can read. The rule is
/// [`crate::disk::name_within_limits`] rather than a second number
/// invented here: ONE policy, the one `sanitize_relpath_for` already
/// enforces (255 bytes per component, 511 in all), asked at the front
/// door instead of at materialization.
///
/// Skipped, not fatal: the scan continues, so a subject whose first
/// dotted quote is unusable can still be named by a later one, and a
/// subject with nothing usable falls to `unquoted_filename` and then to
/// the plan's `fileNNN` placeholder - which is unique per slot, so the
/// refusal is collision-safe by construction.
pub fn quoted_filename(s: &str) -> Option<&str> {
    let runs = quoted_runs(s);
    let usable = || {
        runs.iter()
            .copied()
            .filter(|n| crate::disk::name_within_limits(n))
    };
    let kind = classify_runs(&runs, s).kind();
    usable()
        .find(|n| n.contains('.') && classify_one(&n.to_ascii_lowercase(), true) == kind)
        .or_else(|| usable().find(|n| n.contains('.')))
        .or_else(|| usable().next())
}

/// Every quoted run in a subject, trimmed, in order, empties dropped.
///
/// Split out of [`quoted_filename`] because classification needs the
/// WHOLE list and the name pick needs one entry: one run has to be
/// chosen for the NAME, and no single run may decide the KIND, which is
/// what [`classify_subject`] exists to say. Since T5 the pick asks that
/// rule too, so both readers start from this list.
///
/// F2, a KNOWN divergence, deliberately left standing: the trim here is
/// Rust's Unicode `White_Space` trim, where N6-06 moved the message-id,
/// group and password fields onto [`trim_xml_space`] (XML production 3
/// `S` only) because a character reference written at a field boundary
/// was MEANT. A quoted `"&#xa0;movie.mkv"` therefore loses its NBSP
/// here. It stays because the divergence is contained - on-disk names
/// and every identity key fold through `sanitize_out_name`, which strips
/// the boundary space on both sides of every compare, and the only
/// observable difference is a raw-name compare (`described_length`, the
/// name ladder) that fails CLOSED either way, unlike N6-06's fields
/// which fetched a wrong article under a fabricated key. A bare
/// `trim_xml_space` swap also has a degenerate case: a run of only
/// Unicode whitespace stops being empty, so it becomes a candidate and
/// hands the slot a name that sanitizes to `unnamed`, strictly worse
/// than today's unique `fileNNN`. See
/// `research/FILENAME-HINT-CENSUS-2026-08-31.md` section 5 for the full
/// read and for what evidence would change the answer - do not "fix"
/// this by reflex in the next N6-06-style sweep.
fn quoted_runs(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(a) = rest.find('"') {
        let after = &rest[a + 1..];
        let Some(b) = after.find('"') else { break };
        let name = after[..b].trim();
        if !name.is_empty() {
            out.push(name);
        }
        rest = &after[b + 1..];
    }
    out
}

/// Where does this lowercased name END at `.par2`, if it does? The byte
/// offset of the terminating occurrence, or `None`.
///
/// `isolated` says whether the name has already been cut out of its
/// subject by quotes. It has NOT when `kind()` falls back to the whole
/// raw subject, where `.par2` is legitimately followed by ` yEnc (1/2)`
/// - so whitespace ends the name there. It HAS when the name came from
/// between a pair of quotes, and there `.par2` must be terminal: a
/// quoted `"ordinary.par2 notes.txt"` is one filename that merely
/// CONTAINS `.par2`, and reading the raw-subject rule onto it classified
/// a payload as the recovery index (N6-05).
///
/// THE ONE HOME OF THE TERMINAL RULE, and `pub` for that reason rather
/// than for a caller's convenience. `check::multiple_par2_sets` wrote
/// the same two-clause test out a second time to recover a Main's stem,
/// with a comment saying the two had to agree - which is how
/// `faultplan::role_of` began, and it was still a hand-copied twin of
/// `NzbFile::kind` months later when N6-04 and N6-05 turned out to be
/// live in both. An OFFSET rather than a bool because that is what the
/// second copy actually wanted: the stem is everything in front of it.
/// `tools/par2-rule-gate.py` refuses the third copy.
pub fn par2_name_end(lower: &str, isolated: bool) -> Option<usize> {
    lower
        .match_indices(".par2")
        .find(|(i, _)| {
            let rest = &lower[i + ".par2".len()..];
            rest.is_empty() || (!isolated && rest.starts_with(char::is_whitespace))
        })
        .map(|(i, _)| i)
}

fn classify_one(lower: &str, isolated: bool) -> FileKind {
    // The name must END at ".par2" to be a PAR2 file at all - either
    // there and then, or with the raw subject carrying on after
    // whitespace. A mere `contains` also caught payload whose name
    // continues past the extension, so "extras.vol-10.par2-sample.mkv"
    // was classified PAR2 rather than data (14 Aug sweep).
    if par2_name_end(lower, isolated).is_none() {
        return FileKind::Data;
    }
    // Anything with .par2 that doesn't wear a recovery-volume suffix is
    // the index. The suffix rule lives in `vol_suffix`, shared with
    // `extract::release_stem` through `par2_vol_suffix`.
    if vol_suffix(lower, isolated).is_some() {
        FileKind::Par2Volume
    } else {
        FileKind::Par2Main
    }
}

/// THE classification rule: what role does this subject claim?
///
/// One function, called by [`NzbFile::kind`] and by
/// `faultplan::role_of`, which used to be a hand-copied twin of it.
///
/// A subject may quote more than one filename-looking name, and the old
/// rule took the first dotted one as authority for the KIND as well as
/// the name. That is the wrong direction of wrong (N6-04): a
/// `"label.vol000+50.par2" - "Movie.mkv"` post classified as a recovery
/// volume, and `build_fetch_plan` gives a non-bootstrap volume NO SLOT
/// - so the payload named right there in the manifest was never
/// fetched, nothing was ever missing, and the job finished green.
/// `"label.par2" - "Movie.mkv"` did the same through Par2Main, which
/// excludes the file from normal payload verification.
///
/// So candidates must AGREE. Every dotted quoted run is classified on
/// its own, and a disagreement answers `Data` - the only answer that
/// cannot lose a file, since the cost of calling a recovery volume
/// payload is bandwidth and the cost of the reverse is the download.
/// One candidate still decides alone, which is what keeps a decoy-first
/// post like `"S01E01" - "Show.vol000+50.par2"` a volume: an undotted
/// run is a label, not a filename, exactly as before.
pub fn classify_subject(subject: &str) -> FileKind {
    classify_subject_detail(subject).kind()
}

/// [`classify_subject`], keeping the NAME it judged and the RULE it
/// judged that name under.
///
/// THE POINT OF THE STRUCT is that `isolated` must not be re-derived
/// downstream. A reader that gates on [`FileKind`] and then asks the
/// public [`par2_vol_suffix`] - the RAW-SUBJECT rule, unconditionally -
/// is asking a looser question than the one that produced the kind it
/// gated on, so the two can disagree about the same string. They did:
/// a quoted `"a.vol-10.par2 x.par2"` is `Par2Main` here (the isolated
/// rule refuses a volume suffix whose tail carries on past `.par2`),
/// while `par2_vol_suffix` answers `Some(1)` and hands the reader the
/// stem `a` - so `check::multiple_par2_sets` folded it into a genuinely
/// separate `a.par2` set, saw one set where there are two, and left the
/// declared-count cap live over a set no probe had sized. Measured on
/// this tree 30 Aug 2026; the regression is
/// `check_tests::a_quoted_par2_with_a_trailing_par2_is_its_own_set`.
///
/// THE T3 GATE AND THIS ARE COMPLEMENTS, and the state of the tree the
/// morning they met is the argument for both. `tools/par2-rule-gate.py`
/// refuses a SECOND WRITING of the terminal test, and found the one in
/// `multiple_par2_sets`; folding that copy onto [`par2_name_end`] fixed
/// the Main arm of this defect and left the VOLUME arm - the branch
/// that actually fires on the name above - still asking
/// `par2_vol_suffix`. A gate against restating the rule cannot see a
/// reader CALLING the right function with the wrong `isolated`, because
/// there is no second copy to find; only carrying the decision closes
/// that.
///
/// So the answers a reader needs are METHODS here rather than a second
/// call to a free function: [`Self::vol_suffix`] and
/// [`Self::par2_stem`] apply this classification's own rule to this
/// classification's own name, and there is nothing left for a reader to
/// get wrong. [`par2_vol_suffix`] stays public for the callers that
/// genuinely hold a real filename off disk or out of the index rather
/// than a subject - `extract::release_stem` and `scan.rs` - where the
/// isolated/raw distinction does not arise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectClass<'a> {
    kind: FileKind,
    name: &'a str,
    isolated: bool,
}

impl<'a> SubjectClass<'a> {
    /// The role the subject claims.
    pub fn kind(&self) -> FileKind {
        self.kind
    }

    /// The name the kind was decided on: the first dotted quoted run,
    /// else the first quoted run, else the whole raw subject. Borrowed
    /// out of the subject in its ORIGINAL case; every offset this type
    /// hands back indexes it, which is sound in either case because
    /// ASCII lowercasing never changes a byte's length.
    ///
    /// This is [`quoted_filename`]'s answer for every name a real post
    /// carries, and deliberately not that call: it applies the
    /// OUTPUT-NAME policy (N6-10, 255 bytes a component) and this does
    /// not, so a subject whose only quoted run is over-length answers
    /// `None` there and sent the reader to the raw subject - under the
    /// RAW rule - for a name the classifier had judged isolated.
    /// Reading the name off the classification closes that seam too.
    /// T5's agreeing-run clause cannot part them either: it picks among
    /// the runs whose own kind EQUALS the subject's answer, and this is
    /// the run that set that answer.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Had the classified name already been cut out of its subject by
    /// quotes? See [`par2_name_end`] for what turns on it.
    pub fn isolated(&self) -> bool {
        self.isolated
    }

    /// Where the recovery-volume suffix starts in [`Self::name`], under
    /// the rule that produced [`Self::kind`]. `Some` exactly when the
    /// kind is [`FileKind::Par2Volume`].
    pub fn vol_suffix(&self) -> Option<usize> {
        if self.kind != FileKind::Par2Volume {
            return None;
        }
        vol_suffix(&self.name.to_ascii_lowercase(), self.isolated)
    }

    /// The PAR2 SET stem this name declares: the text before `.vol…`
    /// for a recovery volume, before `.par2` for an index. `None` for
    /// [`FileKind::Data`], and `Some` - possibly EMPTY, for an
    /// anonymous `.vol-01.par2` with no prefix at all - for either PAR2
    /// kind, by construction: a kind is only ever PAR2 because
    /// [`par2_name_end`] answered `Some` on this same name under this
    /// same rule.
    ///
    /// The private `vol_suffix` rather than [`Self::vol_suffix`], so
    /// the two arms are literally the two branches `classify_one` took:
    /// a `Par2Main` is a name for which that call answered `None`, so
    /// the fallback to the `.par2` offset is not a second opinion, it
    /// is the same one.
    pub fn par2_stem(&self) -> Option<&'a str> {
        if self.kind == FileKind::Data {
            return None;
        }
        let lower = self.name.to_ascii_lowercase();
        let end = par2_name_end(&lower, self.isolated)?;
        Some(&self.name[..vol_suffix(&lower, self.isolated).unwrap_or(end)])
    }
}

/// See [`SubjectClass`].
pub fn classify_subject_detail(subject: &str) -> SubjectClass<'_> {
    classify_runs(&quoted_runs(subject), subject)
}

/// [`classify_subject`] over runs already extracted, so the NAME pick in
/// [`quoted_filename`] can ask this rule without walking the subject a
/// second time. The rule itself lives here and nowhere else: the pick
/// consulting a private copy of the par2-terminal test is the
/// hand-copied-twin class `role_of` was already found in (N6-04).
///
/// It hands back the whole [`SubjectClass`] rather than the bare kind,
/// so the NAME it judged and the `isolated` flag it judged under leave
/// the classifier with the verdict instead of being re-derived by each
/// reader (T2). Callers wanting only the kind take `.kind()`.
fn classify_runs<'a>(runs: &[&'a str], subject: &'a str) -> SubjectClass<'a> {
    let at = |kind, name, isolated| SubjectClass {
        kind,
        name,
        isolated,
    };
    let mut dotted = runs.iter().copied().filter(|n| n.contains('.'));
    if let Some(first) = dotted.next() {
        let kind = classify_one(&first.to_ascii_lowercase(), true);
        for other in dotted {
            if classify_one(&other.to_ascii_lowercase(), true) != kind {
                return at(FileKind::Data, first, true);
            }
        }
        return at(kind, first, true);
    }
    // Quotes but no dot in any of them: `quoted_filename` falls through
    // to its own last arm and answers the first run, so classify exactly
    // that - it is still an isolated name. (Exactly: the first run it
    // finds USABLE, since N6-10; this branch reads `runs` unfiltered, so
    // a first run too long to be an output name is classified here and
    // not named there. T5's agreeing-run clause cannot reach this branch
    // at all - it only ever picks among DOTTED runs, and there are none.)
    if let Some(first) = runs.first() {
        return at(classify_one(&first.to_ascii_lowercase(), true), first, true);
    }
    at(
        classify_one(&subject.to_ascii_lowercase(), false),
        subject,
        false,
    )
}

/// A subject's bare filename CANDIDATE: the decoration - a trailing
/// ` yEnc`, stacked `(n/m)` counters, leading `[01/30]` index tags - taken
/// off, and the output-name policy applied, with no judgement yet about
/// whether the extension makes it a filename.
///
/// Split out of [`unquoted_filename`] for N6-07's set-level reading
/// ([`set_resolved_hints`]), which has to ask the same question of a
/// subject the per-subject rule REFUSED. Spelling the stripping a second
/// time there is how two copies of one rule start; this repo has the
/// scars.
fn unquoted_candidate(s: &str) -> Option<&str> {
    // The yEnc marker ends the name; everything after it is decoration.
    let mut head = match s.find(" yEnc") {
        Some(i) => &s[..i],
        None => s,
    };
    // Trailing `(n/m)` counters (posts sometimes stack two), with any
    // whitespace/dash separators around them.
    fn strip_one_counter(t: &str) -> &str {
        let t = t.trim_end_matches(|c: char| c.is_whitespace() || c == '-');
        if let Some(i) = t.rfind('(')
            && t.ends_with(')')
        {
            let inner = &t[i + 1..t.len() - 1];
            let mut parts = inner.split('/');
            if let (Some(a), Some(b), None) = (parts.next(), parts.next(), parts.next())
                && !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.bytes().all(|c| c.is_ascii_digit())
            {
                return &t[..i];
            }
        }
        t
    }
    let mut prev = usize::MAX;
    while head.len() < prev {
        prev = head.len();
        head = strip_one_counter(head);
    }
    // Leading `[01/30]` / `(01/30)`-style index tags and their ` - `
    // separators. Bounded per tag so a subject that is one long
    // bracketed run is not eaten whole.
    loop {
        let t = head.trim_start_matches(|c: char| c.is_whitespace() || c == '-');
        let stripped = match t.as_bytes().first() {
            Some(b'[') => t.find(']').filter(|&i| i <= 40).map(|i| &t[i + 1..]),
            Some(b'(') => t.find(')').filter(|&i| i <= 40).map(|i| &t[i + 1..]),
            _ => None,
        };
        match stripped {
            Some(rest) => head = rest,
            None => {
                head = t;
                break;
            }
        }
    }
    let name = head.trim();
    if name.is_empty() || name.len() > 255 || name.contains('"') {
        return None;
    }
    Some(name)
}

/// A filename read from a subject that quotes NOTHING - the shape issue
/// #55's album was posted in: `10-Track Name-8c63a701.flac (1/0)`, the
/// real name in the clear with a `(part/total)` counter after it.
///
/// Strict on purpose, because the subjects this must NOT match are the
/// prose ones (`Great Album Name yEnc (1/15)`): after cutting the
/// ` yEnc` marker, stripping trailing `(n/m)` counters and leading
/// `[..]`/`(..)` index tags, the WHOLE remainder must end in a real
/// extension - a dot, then 2 to 5 alphanumerics with at least one
/// letter - or the answer is None. The letter requirement is what keeps
/// a trailing year (`Movie.2026 (1/3)`) from reading as a file.
pub fn unquoted_filename(s: &str) -> Option<&str> {
    let name = unquoted_candidate(s)?;
    let dot = name.rfind('.')?;
    let (stem, ext) = (&name[..dot], &name[dot + 1..]);
    if stem.is_empty() {
        return None;
    }
    if real_extension(ext) {
        return Some(name);
    }
    // N6-07: a SPLIT-PART tail. `release.zip.001`, `movie.7z.001`,
    // `archive.rar.001`, `Movie.mkv.001` and bare `movie.001` all
    // failed the letter test above and came back `None`, so the plan
    // named every part `fileNNN` and threw the grouping name away -
    // while `splitjoin`, `nzbkit::zip` and the top-level e2e all
    // support these shapes downstream. A naming loss, not a capability
    // gap, and one that costs the set the ONE thing that identifies its
    // members as belonging together.
    //
    // Two readings, because a lone subject has no set to lean on the
    // way `splitjoin::numeric_tail` does (that one gets a contiguous
    // run, a width agreement and a magic check before it commits):
    //
    //  * a numeric tail BEHIND a real extension is unambiguous -
    //    nothing writes `Movie.mkv.001` except a splitter - so any
    //    1-4 digit tail is taken, matching `numeric_tail`'s own width
    //    (wider than 4 "is not a split tail, it is a name that happens
    //    to end in digits");
    //
    //  * a BARE numeric tail is taken only when it is ZERO-PADDED
    //    (`.001`, `.01`, `.010`). That is the discriminator the
    //    existing letter rule was standing in for: it keeps a trailing
    //    year out (`Movie.2026`, the case that comment names), and a
    //    bitrate or a resolution with it (`Album.320`, `Show.480`),
    //    while every splitter in the wild pads. `.100` and up in a
    //    3-digit set are what a lone subject cannot settle - and
    //    that is where this function stops rather than where the
    //    job does: a set past part 99 is named by
    //    `set_resolved_hints`, which sees every file at once, and
    //    the measurement that made it necessary is in its doc.
    let digits = (1..=4).contains(&ext.len()) && ext.bytes().all(|c| c.is_ascii_digit());
    if !digits {
        return None;
    }
    let padded = ext.len() >= 2 && ext.starts_with('0');
    let behind_real_ext = stem
        .rfind('.')
        .is_some_and(|d| !stem[..d].is_empty() && real_extension(&stem[d + 1..]));
    (padded || behind_real_ext).then_some(name)
}

/// The BARE numeric split tail of a candidate name: `sunset.100` ->
/// (`sunset`, 100, 3). `None` for everything [`unquoted_filename`]
/// already settles on the subject alone - a tail behind a real
/// extension, a tail wider than any splitter writes, a name with no
/// numeric tail at all - so this answers exactly the question the SET is
/// needed for and nothing else.
fn bare_numeric_tail(name: &str) -> Option<(&str, u32, usize)> {
    let dot = name.rfind('.')?;
    let (stem, ext) = (&name[..dot], &name[dot + 1..]);
    if stem.is_empty() || !(1..=4).contains(&ext.len()) || !ext.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    if stem
        .rfind('.')
        .is_some_and(|d| !stem[..d].is_empty() && real_extension(&stem[d + 1..]))
    {
        return None;
    }
    Some((stem, ext.parse().ok()?, ext.len()))
}

/// Posted names for a WHOLE file list - [`NzbFile::filename_hint_lenient`]
/// per file, plus the one answer a single subject cannot give.
///
/// N6-07 takes a BARE numeric tail only when it is ZERO-PADDED, because
/// a lone `movie.100` is spelled exactly like a bitrate or a resolution
/// and the subject carries nothing that separates them. In a 3-digit
/// split set that is the whole tail past part 99, so a 101-part
/// `sunset.001`..`.101` came out named for 99 parts and placeholdered
/// for two - and that PARTIAL naming is worse than naming none of them,
/// which is the measurement this function exists for (31 Aug 2026, a
/// bare-numeric 101-part set posted under hash yEnc names):
///
/// * before N6-07 nothing was named, no set was declared, no set was
///   collected on disk, and the job left all 101 parts alone;
/// * after it, parts 1..99 were named, `splitjoin::collect_sets` saw a
///   contiguous run from 1, joined NINETY-NINE parts into a `sunset`
///   nothing can open ("no end-of-central-directory record") and
///   DELETED them, leaving the two placeholders beside it.
///
/// Both outcomes are a broken job; the second also destroys the parts a
/// person would have salvaged by hand, so it is a regression and not
/// merely a miss.
///
/// The SET is what settles it, which is what the row's own follow-up
/// said: a base carrying a ZERO-PADDED tail has been proven a split set
/// by a name no bitrate can wear, and an unpadded tail is admitted when
/// it EXTENDS that run by one - `.100` needs `.099`, and `.101` then
/// needs the `.100` just admitted. A bitrate or a resolution has no such
/// run behind it and is untouched.
///
/// Extending the run, rather than merely sharing the base, is what keeps
/// the rule from costing anything. Matching the base alone would promote
/// an `Album.320` sitting beside a genuine `Album.001`..`.099` set, and
/// BOTH consumers refuse a set with a hole in it (`get::vrig` declares a
/// zip split only on a gapless `1..=n`, `splitjoin::collect_sets` wants
/// a contiguous run from 1) - so one stray file would have taken a
/// 99-part set that joins correctly today and stopped it joining at all.
/// Extension cannot do that: an admitted index is always the one the run
/// was missing.
///
/// STATED LIMIT, because it is a decision and not an oversight: a set
/// written at width 1 (`movie.1`..`movie.9`) has no padded member to
/// anchor on, so none of it is named and every part keeps the
/// placeholder. That is uniform - the partial naming above is the thing
/// that hurts - and it is what the tree did before N6-07, so nothing
/// regresses. Closing it needs evidence a lone subject does not carry:
/// a contiguous run alone would promote `Movie.1` / `Movie.2` sequel
/// numbering, which is the class the padding rule exists to refuse.
pub fn set_resolved_hints(files: &[NzbFile]) -> Vec<Option<&str>> {
    type Key = (String, usize);
    let mut hints: Vec<Option<&str>> = files.iter().map(NzbFile::filename_hint_lenient).collect();
    // Indices a ZERO-PADDED name has already proven, per (base, width).
    let mut runs: std::collections::HashMap<Key, std::collections::BTreeSet<u32>> =
        std::collections::HashMap::new();
    for h in hints.iter().flatten() {
        if let Some((base, idx, width)) = bare_numeric_tail(h)
            && width >= 2
            && h[h.len() - width..].starts_with('0')
        {
            runs.entry((base.to_ascii_lowercase(), width))
                .or_default()
                .insert(idx);
        }
    }
    if runs.is_empty() {
        return hints;
    }
    let mut cands: Vec<(Key, u32, usize)> = Vec::new();
    for (i, h) in hints.iter().enumerate() {
        if h.is_some() {
            continue;
        }
        let Some(cand) = unquoted_candidate(&files[i].subject) else {
            continue;
        };
        if let Some((base, idx, width)) = bare_numeric_tail(cand) {
            let key = (base.to_ascii_lowercase(), width);
            if runs.contains_key(&key) {
                cands.push((key, idx, i));
            }
        }
    }
    // By key, then by INDEX, so a run only ever extends one part at a
    // time: `.100` needs `.099`, and `.101` then needs the `.100` this
    // loop just admitted.
    cands.sort_unstable();
    for (key, idx, i) in cands {
        let seen = runs.get_mut(&key).expect("every key came from `runs`");
        if idx > 0 && seen.contains(&(idx - 1)) {
            seen.insert(idx);
            hints[i] = unquoted_candidate(&files[i].subject);
        }
    }
    hints
}

/// A real filename extension: 2-5 alphanumerics carrying at least one
/// LETTER. Split out of [`unquoted_filename`] so N6-07's split-part
/// reading can ask the same question of the extension BEHIND a numeric
/// tail (`release.zip.001` -> is `zip` real?) rather than spelling the
/// rule a second time.
fn real_extension(ext: &str) -> bool {
    (2..=5).contains(&ext.len())
        && ext.bytes().all(|c| c.is_ascii_alphanumeric())
        && ext.bytes().any(|c| c.is_ascii_alphabetic())
}

/// Byte offset of the recovery-volume suffix in a PAR2 filename, or
/// `None` when the name doesn't carry one. This is THE "is this a
/// recovery volume?" rule: classification (`NzbFile::kind`, which
/// drives deferral) and stem reduction (`extract::release_stem`, which
/// drives index folding) both call it. The rule used to be written
/// twice and drifted the same wrong way - both spellings demanded
/// digits before the separator, so `.vol-01.par2` posts fetched their
/// whole recovery set eagerly (7.5 GB measured on one 42 GiB post) and
/// kept `.vol-01` on the release stem, shattering off their release in
/// the index.
///
/// Accepted, case-insensitive, always directly before `.par2` or the
/// end of the name:
/// - `.vol<digits>+<digits>` - par2cmdline, first slice + count
/// - `.vol<digits>-<digits>` - range convention, end-exclusive
/// - `.vol-<NN>` - bare zero-padded ordinal, nothing before the dash
///   (playWEB/NORViNE/GRACE posts, measured live 13 Aug 2026: always
///   two digits, always straight before `.par2`). Two digits minimum
///   on this shape only: a music compilation's index `VA.Hits.Vol-3.par2`
///   numbers a release, not a volume, and single-digit is that
///   convention's home ground.
pub fn par2_vol_suffix(name: &str) -> Option<usize> {
    vol_suffix(name, false)
}

/// [`par2_vol_suffix`], plus the caller's answer to "has this name
/// already been cut out of its subject?". See [`par2_name_end`] - the
/// whitespace tail below is a RAW-SUBJECT allowance and must not reach
/// an isolated quoted filename.
fn vol_suffix(name: &str, isolated: bool) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    let vol = lower.rfind(".vol")?;
    let rest = &lower[vol + 4..];
    let sep = rest.find(['+', '-'])?;
    let first = &rest[..sep];
    if !first.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let after = &rest[sep + 1..];
    let end = after.find('.').unwrap_or(after.len());
    let ordinal = &after[..end];
    if ordinal.is_empty() || !ordinal.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if first.is_empty() && (rest.as_bytes()[sep] != b'-' || ordinal.len() < 2) {
        return None;
    }
    // The suffix must CLOSE the filename: nothing after the ordinal
    // (a stem already stripped of its .par2), or ".par2" followed by
    // at most a non-name character - kind() falls back to the whole
    // subject when nothing is quoted, so ".par2 yEnc (1/2)" tails are
    // normal there. "Vol-52.2CD-2023-GRP.par2" stays a title: what
    // follows its ordinal is more name, not the extension.
    let tail = &after[end..];
    match tail.strip_prefix(".par2") {
        None if tail.is_empty() => Some(vol),
        // WHITESPACE, not merely "not alphanumeric". The allowance
        // exists because kind() falls back to the raw subject, where
        // ".par2" is followed by " yEnc (1/2)" - and whitespace is
        // exactly what ends a filename inside a subject. Accepting any
        // non-alphanumeric byte also accepted a QUOTED filename that
        // continues past .par2: "x.vol-10.par2.bak" and
        // "extras.vol-10.par2-sample.mkv" classified as recovery
        // volumes, and a volume never gets a download slot
        // (get::plan.rs), so a real payload file listed in the NZB was
        // silently never fetched and the job still reported complete
        // (14 Aug sweep).
        Some("") => Some(vol),
        Some(t) if !isolated && t.starts_with(char::is_whitespace) => Some(vol),
        _ => None,
    }
}

/// Declared recovery-slice count from a PAR2 volume filename:
/// `.vol<first>+<count>` → count; `.vol<start>-<end>` (end-exclusive
/// range) → end − start. `None` when the name declares no count: not a
/// recovery volume at all, the bare-ordinal `.vol-NN` shape, which
/// numbers the volume without sizing it, or a figure too large to be a
/// real slice count (see the cap below). "Is it a volume?" is
/// [`par2_vol_suffix`]'s question - a `None` here does NOT mean the
/// file is safe to fetch eagerly, and every count consumer already
/// copes with `None` the way the obfuscated (nameless) path does:
/// size-based estimates, a conservative 1, or the deferred-article
/// proof in settle.
pub fn par2_vol_count(name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    let vol = par2_vol_suffix(&lower)?;
    let rest = &lower[vol + 4..];
    let sep = rest.find(['+', '-'])?;
    let first: u64 = rest[..sep].parse().ok()?;
    let after = &rest[sep + 1..];
    let end = after.find('.').unwrap_or(after.len());
    let second: u64 = after[..end].parse().ok()?;
    let count = match rest.as_bytes()[sep] {
        b'+' => second,
        _ => second.saturating_sub(first).max(1),
    };
    // A name is not evidence. PAR2's GF(16) Reed-Solomon tops out at
    // 32768 recovery blocks, so a filename claiming a million-odd
    // slices is not sizing a volume - it is feeding an addend into
    // somebody's budget arithmetic. `Rel.vol0+18446744073709551615.par2`
    // parsed as u64 and cast straight to usize, and two such volumes
    // overflowed the `recovery` sum in `nzbfast check` (panic in debug,
    // an attacker-chosen wrapped budget in release, which then picked
    // the REPAIRABLE / IMPOSSIBLE verdict). Cap it and hand back the
    // documented "declares no count" answer, which every consumer
    // already copes with; classification stays `par2_vol_suffix`'s
    // question, so the file is still a recovery volume and still never
    // gets a download slot. `try_from` rather than `as` also stops the
    // silent truncation this had on 32-bit targets, where
    // `.vol0+4294967297.par2` reported a count of 1.
    const MAX_DECLARED_SLICES: u64 = 1 << 20;
    if count > MAX_DECLARED_SLICES {
        return None;
    }
    usize::try_from(count).ok()
}

#[cfg(test)]
#[path = "nzb_tests.rs"]
mod tests;
