//! NZB file parsing.
//!
//! An NZB is XML: `<nzb><file ...><groups><group>…</groups>
//! <segments><segment bytes number>message-id</segment></segments></file></nzb>`.
//! We keep the model deliberately close to the wire format; scheduling
//! concepts (server tiers, block accounting) live elsewhere.

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

#[derive(Debug, thiserror::Error)]
pub enum NzbError {
    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("XML attribute error: {0}")]
    Attr(#[from] quick_xml::events::attributes::AttrError),
    #[error("XML encoding error: {0}")]
    Encoding(#[from] quick_xml::encoding::EncodingError),
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
pub(crate) fn is_wire_safe(s: &str) -> bool {
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
        let mut reader = Reader::from_reader(xml);
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
        // quick-xml reports Eof, not an error, when the input ends with
        // elements still open - a truncated NZB would otherwise "parse"
        // as whatever files happened to close before the cut, and the
        // shrunken manifest finishes green with data missing.
        let mut depth: usize = 0;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Start(e) => {
                    depth += 1;
                    match e.local_name().as_ref() {
                        b"file" => {
                            let mut f = NzbFile::default();
                            for attr in e.attributes() {
                                let attr = attr?;
                                let val = attr.normalized_value_with(
                                    XmlVersion::Implicit1_0,
                                    128,
                                    html_latin1_entity,
                                )?;
                                match attr.key.local_name().as_ref() {
                                    b"subject" => f.subject = val.into_owned(),
                                    b"poster" => f.poster = val.into_owned(),
                                    b"date" => f.date = val.trim().parse().unwrap_or(0),
                                    _ => {}
                                }
                            }
                            cur_file = Some(f);
                        }
                        b"group" => cur_group = Some(String::new()),
                        b"meta" => {
                            let mut ty = String::new();
                            for attr in e.attributes() {
                                let attr = attr?;
                                if attr.key.local_name().as_ref() == b"type" {
                                    ty = attr
                                        .normalized_value_with(
                                            XmlVersion::Implicit1_0,
                                            128,
                                            html_latin1_entity,
                                        )?
                                        .trim()
                                        .to_lowercase();
                                }
                            }
                            cur_meta = Some((ty, String::new()));
                        }
                        b"segment" => {
                            let mut seg = Segment {
                                number: 0,
                                bytes: 0,
                                message_id: String::new(),
                            };
                            for attr in e.attributes() {
                                let attr = attr?;
                                let val = attr.normalized_value_with(
                                    XmlVersion::Implicit1_0,
                                    128,
                                    html_latin1_entity,
                                )?;
                                match attr.key.local_name().as_ref() {
                                    b"bytes" => seg.bytes = val.trim().parse().unwrap_or(0),
                                    b"number" => seg.number = val.trim().parse().unwrap_or(0),
                                    _ => {}
                                }
                            }
                            cur_segment = Some(seg);
                        }
                        _ => {}
                    }
                }
                Event::Text(t) => {
                    let text = t.xml10_content()?;
                    // Meta values keep their fragments UNTRIMMED and are
                    // trimmed once as a whole at </meta>: entities split
                    // the text into separate events, and per-fragment
                    // trimming ate the spaces around them - a password
                    // of `secret &amp; more` decoded to `secret&more`
                    // and extraction used the wrong password.
                    if cur_segment.is_none()
                        && let Some((_, v)) = cur_meta.as_mut()
                    {
                        v.push_str(&text);
                        buf.clear();
                        continue;
                    }
                    if cur_segment.is_none()
                        && let Some(g) = cur_group.as_mut()
                    {
                        g.push_str(&text);
                        buf.clear();
                        continue;
                    }
                    // Message-ids accumulate UNTRIMMED like meta values,
                    // trimmed once at </segment>: per-fragment trimming ate
                    // the spaces around entities, so an id declared with
                    // interior whitespace (wire-unsafe, owed to
                    // dropped_segments) was silently rewritten into a
                    // fabricated id that passed is_wire_safe and was
                    // fetched as something never posted.
                    if let Some(seg) = cur_segment.as_mut() {
                        seg.message_id.push_str(&text);
                    }
                }
                Event::CData(c) => {
                    // quick-xml emits `<![CDATA[...]]>` as its own event,
                    // distinct from Text/GeneralRef. Without this arm a
                    // CDATA-wrapped message-id (or meta value / group name)
                    // is silently dropped and the article never fetched.
                    // CDATA content is literal - no entity unescaping.
                    let raw = String::from_utf8_lossy(&c);
                    // Same rule as Text above: meta fragments stay
                    // untrimmed until </meta>.
                    if cur_segment.is_none()
                        && let Some((_, v)) = cur_meta.as_mut()
                    {
                        v.push_str(&raw);
                        buf.clear();
                        continue;
                    }
                    if cur_segment.is_none()
                        && let Some(g) = cur_group.as_mut()
                    {
                        g.push_str(&raw);
                        buf.clear();
                        continue;
                    }
                    // Same rule as Text above: accumulate untrimmed,
                    // whole-value trim at </segment>.
                    if let Some(seg) = cur_segment.as_mut() {
                        seg.message_id.push_str(&raw);
                    }
                }
                Event::GeneralRef(r) => {
                    // Entities inside text arrive as their own event
                    // ("p&amp;w" = Text/GeneralRef/Text): resolve the
                    // predefined five + char refs and append wherever the
                    // surrounding text is accumulating.
                    let resolved = if let Some(c) = r.resolve_char_ref()? {
                        c.to_string()
                    } else {
                        let name = r.xml10_content()?;
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
                    if let Some(seg) = cur_segment.as_mut() {
                        seg.message_id.push_str(&resolved);
                    } else if let Some((_, v)) = cur_meta.as_mut() {
                        v.push_str(&resolved);
                    } else if let Some(g) = cur_group.as_mut() {
                        // Groups accumulate like meta values - see
                        // `cur_group`.
                        g.push_str(&resolved);
                    }
                }
                Event::End(e) => {
                    depth = depth.saturating_sub(1);
                    match e.local_name().as_ref() {
                        b"file" => {
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
                                // `<segment/>` arm below: there is nothing to
                                // fetch, only something to DECLARE - so declare
                                // it, and the file either repairs through PAR2
                                // or fails the job.
                                if f.segments.is_empty() && f.dropped_segments == 0 {
                                    f.dropped_segments = 1;
                                }
                                files.push(f);
                            }
                        }
                        b"group" => {
                            if let Some(g) = cur_group.take()
                                && let Some(f) = cur_file.as_mut()
                            {
                                let g = g.trim();
                                if !g.is_empty() && is_wire_safe(g) {
                                    f.groups.push(g.to_string());
                                }
                            }
                        }
                        b"meta" => {
                            if let Some((ty, val)) = cur_meta.take() {
                                // One whole-value trim, replacing the old
                                // per-fragment trims: element-formatting
                                // whitespace goes, interior spaces stay.
                                let val = val.trim().to_string();
                                if !ty.is_empty() && !val.is_empty() {
                                    meta.push((ty, val));
                                }
                            }
                        }
                        b"segment" => {
                            if let (Some(f), Some(mut seg)) =
                                (cur_file.as_mut(), cur_segment.take())
                            {
                                // One whole-value trim, like </meta>:
                                // element-formatting whitespace goes,
                                // interior whitespace stays and fails
                                // is_wire_safe into dropped_segments.
                                let id = seg.message_id.trim();
                                if !id.is_empty() && is_wire_safe(id) {
                                    if id.len() != seg.message_id.len() {
                                        seg.message_id = id.to_string();
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
                // Self-closing elements never pair with an End, and
                // `expand_empty_elements` is off, so `<segment ... />`
                // reached neither the Start nor the End arm: a declared
                // segment vanished with nothing counted, which is
                // exactly what `dropped_segments` exists to prevent (the
                // same segment written `<segment …></segment>` does
                // count). It carries no message-id by construction, so
                // there is nothing to fetch - only something to declare.
                Event::Empty(e) => {
                    if e.local_name().as_ref() == b"segment"
                        && let Some(f) = cur_file.as_mut()
                    {
                        f.dropped_segments += 1;
                    }
                }
                Event::Eof => {
                    if depth > 0 {
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
        let name = self
            .filename_hint()
            .unwrap_or(&self.subject)
            .to_ascii_lowercase();
        // The name must END at ".par2" to be a PAR2 file at all - either
        // there and then, or with the raw subject carrying on after
        // whitespace (kind() falls back to the whole subject when
        // nothing is quoted). A mere `contains` also caught payload
        // whose name continues past the extension, so
        // "extras.vol-10.par2-sample.mkv" was classified PAR2 rather
        // than data. Same whitespace rule as `par2_vol_suffix`, for the
        // same reason (14 Aug sweep).
        let is_par2 = name.match_indices(".par2").any(|(i, _)| {
            let rest = &name[i + ".par2".len()..];
            rest.is_empty() || rest.starts_with(char::is_whitespace)
        });
        if !is_par2 {
            return FileKind::Data;
        }
        // Anything with .par2 that doesn't wear a recovery-volume
        // suffix is the index. The suffix rule lives in
        // `par2_vol_suffix`, shared with `extract::release_stem`.
        if par2_vol_suffix(&name).is_some() {
            FileKind::Par2Volume
        } else {
            FileKind::Par2Main
        }
    }
}

/// The quoted filename in a subject: the first `"…"` run that looks like
/// a filename (contains a dot), else the first non-empty quoted run.
/// Posts like `"S01E01" - "Show.part01.rar" yEnc (1/2)` put a decoy
/// first - taking quote #1 unconditionally misclassified the file.
pub fn quoted_filename(s: &str) -> Option<&str> {
    let mut first: Option<&str> = None;
    let mut rest = s;
    while let Some(a) = rest.find('"') {
        let after = &rest[a + 1..];
        let Some(b) = after.find('"') else { break };
        let name = after[..b].trim();
        if !name.is_empty() {
            if name.contains('.') {
                return Some(name);
            }
            first.get_or_insert(name);
        }
        rest = &after[b + 1..];
    }
    first
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
    let dot = name.rfind('.')?;
    let (stem, ext) = (&name[..dot], &name[dot + 1..]);
    let ext_ok = !stem.is_empty()
        && (2..=5).contains(&ext.len())
        && ext.bytes().all(|c| c.is_ascii_alphanumeric())
        && ext.bytes().any(|c| c.is_ascii_alphabetic());
    ext_ok.then_some(name)
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
        Some(t) if t.starts_with(char::is_whitespace) => Some(vol),
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
mod tests {
    use super::*;

    /// Real NZBIndex-generated NZB (nzbget issue #699): subjects carry
    /// `&auml;`, an HTML latin-1 entity undefined in XML. nzbget
    /// rejected it ("Reference to undefined entity"); SABnzbd accepts.
    /// We resolve the latin-1 set so these download.
    #[test]
    fn html_latin1_entities_in_attributes_resolve() {
        let xml = include_bytes!("../testdata/nzb/gh-nzbget699-undefined-entity.nzb");
        let nzb = Nzb::parse(xml).expect("latin-1 entity NZB parses");
        assert!(!nzb.files.is_empty());
        let with_auml: Vec<_> = nzb
            .files
            .iter()
            .filter(|f| f.subject.contains("geschändeten"))
            .collect();
        assert!(
            !with_auml.is_empty(),
            "&auml; should resolve to ä in subjects: {:?}",
            nzb.files[0].subject
        );
        assert!(
            nzb.files.iter().all(|f| !f.subject.contains("&auml;")),
            "no subject may keep the raw entity"
        );
    }

    /// The same entities must resolve in element text (message-ids, meta
    /// values), where they arrive as GeneralRef events - and an entity
    /// outside the latin-1 table must still fail the parse: tolerance is
    /// scoped to the known HTML set, not entities in general.
    #[test]
    fn html_latin1_entities_in_text_resolve_unknown_still_rejected() {
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head><meta type="password">stra&szlig;e</meta></head>
  <file subject="s" poster="p" date="1700000000">
    <groups><group>alt.binaries.test</group></groups>
    <segments><segment bytes="1" number="1">a@example.com</segment></segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).expect("parses");
        assert_eq!(nzb.password(), Some("straße"));

        let unknown = br#"<?xml version="1.0"?>
<nzb><file subject="x&bogus;y" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments><segment bytes="1" number="1">a@b.c</segment></segments>
</file></nzb>"#;
        assert!(
            Nzb::parse(unknown).is_err(),
            "entities outside the latin-1 table must still reject"
        );
    }

    /// A message-id whose declared character content carries interior
    /// whitespace (an entity splits the text, so it arrives as separate
    /// fragments) is wire-unsafe and owed to `dropped_segments`.
    /// Per-fragment trimming used to eat the spaces around the entity
    /// and hand back a FABRICATED id that passed `is_wire_safe` - the
    /// manifest then counted a fetched-and-missing article instead of an
    /// unfetchable declared segment. Ids get the same
    /// accumulate-then-trim-once treatment meta values and groups got.
    #[test]
    fn an_entity_split_id_with_interior_whitespace_drops_instead_of_rewriting() {
        let xml = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments>
    <segment bytes="1" number="1">abc &amp;def@news.example</segment>
    <segment bytes="1" number="2"> ok@news.example </segment>
  </segments>
</file></nzb>"#;
        let nzb = Nzb::parse(xml).expect("parses");
        let f = &nzb.files[0];
        assert_eq!(
            f.dropped_segments, 1,
            "the whitespace-carrying id is declared-but-unfetchable, never rewritten"
        );
        assert_eq!(
            f.segments
                .iter()
                .map(|s| s.message_id.as_str())
                .collect::<Vec<_>>(),
            vec!["ok@news.example"],
            "element-formatting whitespace still trims off a clean id"
        );
    }

    /// Three ways a well-formed NZB used to be quietly rewritten rather
    /// than parsed or refused. All three are silent-data shapes: nothing
    /// logged, nothing counted, a green job with the wrong bytes.
    #[test]
    fn undefined_entities_and_self_closing_segments_do_not_rewrite_the_manifest() {
        // 1. An undefined entity inside a message-id was DROPPED, so the
        // id parsed as a different, non-existent article.
        let in_text = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments><segment bytes="1" number="1">abc&bogus;def@news.example</segment></segments>
</file></nzb>"#;
        let err = Nzb::parse(in_text).expect_err("an undefined entity in text must reject");
        assert!(
            matches!(&err, NzbError::UnknownEntity(name) if name == "bogus"),
            "{err:?}"
        );

        // 2. An entity in a group name split it into two invented names.
        let split_group = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>alt.bin&amp;ary</group></groups>
  <segments><segment bytes="1" number="1">a@b.c</segment></segments>
</file></nzb>"#;
        let nzb = Nzb::parse(split_group).expect("parses");
        assert_eq!(
            nzb.files[0].groups,
            vec!["alt.bin&ary".to_string()],
            "one group element is one group name"
        );

        // 3. A self-closing segment vanished without being counted, so
        // the manifest shrank in silence.
        let empty_seg = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments>
    <segment bytes="700000" number="1">a@b.c</segment>
    <segment bytes="700000" number="2"/>
  </segments>
</file></nzb>"#;
        let nzb = Nzb::parse(empty_seg).expect("parses");
        assert_eq!(nzb.files[0].segments.len(), 1);
        assert_eq!(
            nzb.files[0].dropped_segments, 1,
            "a declared segment we cannot fetch must be counted, not lost"
        );

        // 4. And the same file with NO segment element at all. The plan
        // took that as a slot owing nothing - total 0, remaining 0,
        // missing 0 - so the census never called it incomplete and the
        // job finished GREEN with nothing on disk under that name, and
        // no repair, because nothing was missing.
        let no_segs = br#"<?xml version="1.0"?>
<nzb>
  <file subject="declared but empty" poster="p" date="1">
    <groups><group>a.b</group></groups>
    <segments></segments>
  </file>
  <file subject="the real one" poster="p" date="1">
    <groups><group>a.b</group></groups>
    <segments><segment bytes="700000" number="1">a@b.c</segment></segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(no_segs).expect("parses");
        assert_eq!(nzb.files.len(), 2, "the file is kept, not dropped");
        assert!(nzb.files[0].segments.is_empty());
        assert_eq!(
            nzb.files[0].dropped_segments, 1,
            "a file that declares no segment at all owes ONE unfetchable one"
        );
        assert_eq!(
            nzb.files[1].dropped_segments, 0,
            "and a healthy file beside it is untouched"
        );
    }

    /// Soak corpus strictness guards: entity tolerance must not loosen
    /// the parser elsewhere. An element name starting with a digit
    /// (crashed nzbget, their issue #744 shape) and a document truncated
    /// mid-element both stay rejected.
    #[test]
    fn garbled_and_truncated_nzbs_still_rejected() {
        let garbled = include_bytes!("../testdata/nzb/synth-744-garbled-element.nzb");
        assert!(
            Nzb::parse(garbled).is_err(),
            "element name starting with a digit must reject"
        );
        let truncated = include_bytes!("../testdata/nzb/synth-truncated.nzb");
        assert!(
            Nzb::parse(truncated).is_err(),
            "document truncated mid-element must reject"
        );
    }

    /// A message-id carrying CR/LF would end our `BODY <id>` command and start
    /// the attacker's next command on the user's authenticated, paid provider
    /// session (POST/IHAVE among them), and desync every pipelined reply after
    /// it. Both routes into the id are covered: numeric char refs, which
    /// quick-xml resolves to the real control characters, and a CDATA body,
    /// which can hold the raw bytes. Such segments are dropped at parse.
    #[test]
    fn segments_with_crlf_message_ids_are_dropped() {
        let xml = br#"<?xml version="1.0"?>
<nzb>
  <file subject="x" poster="p" date="1700000000">
    <groups><group>alt.binaries.test&#13;&#10;POST</group></groups>
    <segments>
      <segment bytes="1" number="1">a@b&#13;&#10;POST&#13;&#10;c@d</segment>
      <segment bytes="1" number="2"><![CDATA[e@f
POST]]></segment>
      <segment bytes="1" number="3">clean@example.com</segment>
    </segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).expect("parses");
        let f = &nzb.files[0];
        assert_eq!(
            f.segments.len(),
            1,
            "only the clean segment may survive: {:?}",
            f.segments
        );
        assert_eq!(f.segments[0].message_id, "clean@example.com");
        for seg in &f.segments {
            assert!(
                is_wire_safe(&seg.message_id),
                "unsafe id survived: {:?}",
                seg.message_id
            );
        }
        // The group name takes the same route into `GROUP {name}`.
        assert!(
            f.groups.iter().all(|g| is_wire_safe(g)),
            "unsafe group survived: {:?}",
            f.groups
        );
        // The drop must not silently shrink the manifest: the caller
        // has to learn two declared segments can never be fetched, or a
        // hostile NZB completes green with a zero-filled file.
        assert_eq!(f.dropped_segments, 2);
    }

    /// XML entities split a meta value into separate text events, and
    /// trimming each fragment ate the spaces AROUND the entity: a
    /// password of `secret &amp; more` decoded to `secret&more`, and
    /// extraction then used a password that never existed. Only the
    /// whole assembled value may be trimmed.
    #[test]
    fn entities_in_meta_values_keep_their_neighbouring_spaces() {
        let xml = br#"<?xml version="1.0"?>
<nzb>
  <head>
    <meta type="password">  secret &amp; more </meta>
    <meta type="title">a &lt;b&gt; c</meta>
  </head>
  <file subject="x" poster="p" date="1700000000">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="1" number="1">clean@example.com</segment>
    </segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).expect("parses");
        assert_eq!(nzb.password(), Some("secret & more"));
        let title = nzb
            .meta
            .iter()
            .find(|(t, _)| t == "title")
            .map(|(_, v)| v.as_str());
        assert_eq!(title, Some("a <b> c"));
    }

    /// A file whose EVERY segment is refused still parses (the NZB is
    /// not empty), but it must carry the refusal count: with zero
    /// segments and zero dropped it would enter the downloader with
    /// nothing to fetch, nothing missing, and finish green having
    /// written no bytes at all.
    #[test]
    fn a_file_of_only_unsafe_segments_records_the_drops() {
        let xml = br#"<?xml version="1.0"?>
<nzb>
  <file subject="x" poster="p" date="1700000000">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="1" number="1">a@b&#13;&#10;POST&#13;&#10;c@d</segment>
    </segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).expect("parses");
        let f = &nzb.files[0];
        assert!(f.segments.is_empty());
        assert_eq!(f.dropped_segments, 1);
    }

    fn sample() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="poster@example.com" date="1700000000" subject="Big Release [1/3] - &quot;release.part1.rar&quot; yEnc (1/2)">
    <groups>
      <group>alt.binaries.test</group>
      <group>alt.binaries.misc</group>
    </groups>
    <segments>
      <segment bytes="750000" number="2">seg2@news.example</segment>
      <segment bytes="750000" number="1">seg1@news.example</segment>
    </segments>
  </file>
  <file poster="poster@example.com" date="1700000001" subject="Big Release [2/3] - &quot;release.par2&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="50000" number="1">par2main@news.example</segment>
    </segments>
  </file>
  <file poster="poster@example.com" date="1700000002" subject="Big Release [3/3] - &quot;release.vol000+01.par2&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="100000" number="1">par2vol@news.example</segment>
    </segments>
  </file>
</nzb>"#
    }

    #[test]
    fn meta_password_entities_resolved() {
        // No <head> at all → None.
        assert_eq!(Nzb::parse(sample()).unwrap().password(), None);
        // Entities inside the password ("s3cret&amp;pw") arrive as their
        // own GeneralRef events and must be stitched back in.
        let with_head = String::from_utf8_lossy(sample()).replace(
            "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">",
            "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <head>\n    <meta type=\"title\">Big Release</meta>\n    <meta type=\"PASSWORD\">s3cret&amp;pw</meta>\n  </head>",
        );
        let nzb = Nzb::parse(with_head.as_bytes()).unwrap();
        assert_eq!(nzb.password(), Some("s3cret&pw"));
        assert_eq!(nzb.files.len(), 3, "head must not disturb file parsing");
    }

    #[test]
    fn parses_files_groups_segments() {
        let nzb = Nzb::parse(sample()).unwrap();
        assert_eq!(nzb.files.len(), 3);

        let f = &nzb.files[0];
        assert_eq!(f.poster, "poster@example.com");
        assert_eq!(f.date, 1700000000);
        assert_eq!(f.groups, vec!["alt.binaries.test", "alt.binaries.misc"]);
        assert_eq!(f.segments.len(), 2);
        // Sorted by part number despite reversed document order.
        assert_eq!(f.segments[0].number, 1);
        assert_eq!(f.segments[0].message_id, "seg1@news.example");
        assert_eq!(f.segments[1].number, 2);
        assert_eq!(f.filename_hint(), Some("release.part1.rar"));
    }

    #[test]
    fn cdata_segment_id_and_group_preserved() {
        // A CDATA-wrapped message-id / group must not be silently dropped
        // (quick-xml emits it as Event::CData, a distinct event).
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="x" date="0" subject="&quot;a.rar&quot; yEnc (1/1)">
    <groups><group><![CDATA[alt.binaries.cdata]]></group></groups>
    <segments>
      <segment bytes="750000" number="1"><![CDATA[seg-cdata@news.example]]></segment>
    </segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).unwrap();
        assert_eq!(nzb.files.len(), 1);
        let f = &nzb.files[0];
        assert_eq!(f.segments.len(), 1, "CDATA segment must not be dropped");
        assert_eq!(f.segments[0].message_id, "seg-cdata@news.example");
        assert_eq!(f.groups, vec!["alt.binaries.cdata"]);
    }

    #[test]
    fn classifies_par2_roles() {
        let nzb = Nzb::parse(sample()).unwrap();
        assert_eq!(nzb.files[0].kind(), FileKind::Data);
        assert_eq!(nzb.files[1].kind(), FileKind::Par2Main);
        assert_eq!(nzb.files[2].kind(), FileKind::Par2Volume);
    }

    #[test]
    fn classifies_dash_range_volumes() {
        // Range-style names ("vol000-001" … "vol127-199", end-exclusive)
        // are recovery volumes, not extra copies of the main index - a
        // Par2Main misclassification pulls the whole recovery set (GBs)
        // ahead of the data and buffers it in memory.
        let mut f = NzbFile {
            subject: r#"< Rel > - "Rel.vol127-199.par2" yEnc (01/99)"#.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(f.kind(), FileKind::Par2Volume);
        f.subject = r#"< Rel > - "Rel.vol000-001.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Volume);
        // Bare-ordinal volumes: NOTHING before the dash, zero-padded
        // ("Rel.vol-01.par2" … "Rel.vol-09.par2" - playWEB, NORViNE,
        // GRACE posts, measured live 13 Aug 2026). Both spellings of
        // the old rule demanded digits there, so these classified
        // Par2Main and the whole recovery set (7.5 GB on one measured
        // 42 GiB post) was fetched eagerly.
        f.subject = r#"< Rel > - "Fightland.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-playWEB.vol-01.par2" yEnc (1/13)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Volume);
        // A dash in the release name alone must not demote the index.
        f.subject = r#"< Rel > - "Some.Film.2026.H.265-GRP.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Main);
        f.subject = r#"< Rel > - "Some.Film-GRP.vol.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Main);
        f.subject = r#"< Rel > - "Rel.volume-2.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Main);
        // A compilation numbered "Vol-3" is a release name, not a
        // recovery ordinal - single digit after the dash stays an index.
        f.subject = r#"< Rel > - "VA.Best.Hits.Vol-3.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Main);
    }

    #[test]
    fn filename_hint_skips_decoy_quotes() {
        // A quoted non-filename before the real one ("S01E01" here) made
        // kind() classify a recovery volume as Data - eager-fetching it.
        let f = NzbFile {
            subject: r#""S01E01" - "Show.vol000+50.par2" yEnc (1/60)"#.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(f.filename_hint(), Some("Show.vol000+50.par2"));
        assert_eq!(f.kind(), FileKind::Par2Volume);
        // No dotted quoted run at all → first non-empty run still wins.
        let g = NzbFile {
            subject: r#"post "some label" yEnc (1/2)"#.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(g.filename_hint(), Some("some label"));
    }

    /// Issue #55's exact posting shape: no quotes anywhere, the real
    /// filename in the clear with a `(part/total)` counter after it.
    /// The quoted read answers None and the slot was named `fileNNN`,
    /// the real name discarded - the lenient read is what plan uses.
    #[test]
    fn unquoted_subject_filenames_are_recovered() {
        for (subject, want) in [
            // The reporter's track and its per-track PAR2 set.
            (
                "10-Track Name-8c63a701.flac (1/0)",
                Some("10-Track Name-8c63a701.flac"),
            ),
            (
                "01-Other One-ea8f7cf8.flac.par2 (1/0)",
                Some("01-Other One-ea8f7cf8.flac.par2"),
            ),
            (
                "01-Other One-ea8f7cf8.flac.vol00+01.par2 (1/0)",
                Some("01-Other One-ea8f7cf8.flac.vol00+01.par2"),
            ),
            // The yEnc marker ends the name; index tags strip.
            ("release.part01.rar yEnc (1/2)", Some("release.part01.rar")),
            ("[01/30] - foo.rar (1/5)", Some("foo.rar")),
            // Prose subjects must NOT read as filenames: no extension,
            // or a trailing year where an extension would be.
            ("Great Album Name yEnc (1/15)", None),
            ("Movie Title 2026 (1/3)", None),
            ("Movie.2026 (1/3)", None),
            ("(1/0)", None),
            ("", None),
        ] {
            assert_eq!(unquoted_filename(subject), want, "subject: {subject:?}");
        }
        // A quoted name still wins over anything unquoted beside it,
        // and the lenient method is quoted-first.
        let f = NzbFile {
            subject: r#"decoy.flac - "real.part1.rar" yEnc (1/2)"#.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(f.filename_hint_lenient(), Some("real.part1.rar"));
        let g = NzbFile {
            subject: "10-Track Name-8c63a701.flac (1/0)".to_string(),
            ..NzbFile::default()
        };
        assert_eq!(g.filename_hint(), None, "the quoted read stays narrow");
        assert_eq!(
            g.filename_hint_lenient(),
            Some("10-Track Name-8c63a701.flac")
        );
        // ...and kind() still classifies the unquoted PAR2 subjects off
        // the raw-subject fallback, exactly as before this existed.
        let p = NzbFile {
            subject: "01-Other One-ea8f7cf8.flac.vol00+01.par2 (1/0)".to_string(),
            ..NzbFile::default()
        };
        assert_eq!(p.kind(), FileKind::Par2Volume);
    }

    /// A hostile .nzb can name its volumes anything. `u64::MAX` parses,
    /// and used to be cast straight to `usize` and added into the
    /// pre-flight recovery budget - two such volumes overflowed the sum
    /// (panic in a debug build, a wrapped attacker-chosen budget in
    /// release, which then chose the REPAIRABLE / IMPOSSIBLE verdict).
    /// The file must stay classified as a recovery volume, because a
    /// volume never gets a download slot; only the COUNT goes unknown.
    #[test]
    fn absurd_declared_slice_counts_are_undeclared_not_sizes() {
        assert_eq!(par2_vol_count("Rel.vol0+18446744073709551615.par2"), None);
        assert_eq!(par2_vol_count("Rel.vol0-18446744073709551615.par2"), None);
        // Above u64 entirely: already None via the parse, pinned so the
        // two paths keep agreeing.
        assert_eq!(par2_vol_count("Rel.vol0+184467440737095516150.par2"), None);
        // Truncated to 1 on a 32-bit target before `try_from`.
        assert_eq!(par2_vol_count("Rel.vol0+4294967297.par2"), None);
        // Still a volume: classification is par2_vol_suffix's question.
        assert_eq!(
            par2_vol_suffix("Rel.vol0+18446744073709551615.par2"),
            Some(3)
        );
        // Real shapes, including the largest ones anyone posts, unchanged.
        assert_eq!(par2_vol_count("Rel.vol012+10.par2"), Some(10));
        assert_eq!(par2_vol_count("x.vol10000+12345.par2"), Some(12345));
        assert_eq!(par2_vol_count("x.vol0+32768.par2"), Some(32768));
    }

    #[test]
    fn vol_count_both_conventions() {
        assert_eq!(par2_vol_count("Rel.vol012+10.par2"), Some(10));
        assert_eq!(par2_vol_count("Rel.vol127-199.par2"), Some(72));
        assert_eq!(par2_vol_count("Rel.vol000-001.par2"), Some(1));
        assert_eq!(par2_vol_count("Rel.vol003-007.par2"), Some(4));
        assert_eq!(par2_vol_count("Rel.par2"), None);
        assert_eq!(par2_vol_count("Rel-GRP.par2"), None);
        assert_eq!(par2_vol_count("Rel.volume-2.par2"), None);
        // Bare ordinal: IS a volume (par2_vol_suffix), but its name
        // declares no slice count - callers fall back to estimates,
        // exactly like the nameless obfuscated path.
        assert_eq!(par2_vol_count("Rel.vol-01.par2"), None);
        assert_eq!(par2_vol_suffix("Rel.vol-01.par2"), Some(3));
        assert_eq!(par2_vol_suffix("Rel.vol-09.par2"), Some(3));
        assert_eq!(par2_vol_suffix("Rel.vol012+10.par2"), Some(3));
        assert_eq!(par2_vol_suffix("Rel.vol127-199.par2"), Some(3));
        // Not volumes: non-numeric field before the separator, spelt-out
        // "volume", a bare index, a single-digit compilation number.
        assert_eq!(par2_vol_suffix("Rel.volume-2.par2"), None);
        assert_eq!(par2_vol_suffix("Some.Film-GRP.vol.par2"), None);
        assert_eq!(par2_vol_suffix("Some.Film.2026.H.265-GRP.par2"), None);
        assert_eq!(par2_vol_suffix("VA.Best.Hits.Vol-3.par2"), None);
        // The suffix must sit at the end of the name (or right before
        // .par2) - "Vol-52" mid-name is a title, not a volume.
        assert_eq!(par2_vol_suffix("VA.Hits.Vol-52.2CD-2023-GRP.par2"), None);
        // kind() falls back to the RAW SUBJECT when nothing is quoted,
        // so the rule must see through a " yEnc (n/m)" tail after .par2.
        assert_eq!(par2_vol_suffix("set.vol000+01.par2 yEnc (1/1)"), Some(3));
        assert_eq!(par2_vol_suffix("set.vol-01.par2 yEnc (1/1)"), Some(3));
        assert_eq!(par2_vol_suffix("set.par2 yEnc (1/1)"), None);
        // ...but ONLY whitespace ends the name. A quoted filename that
        // carries on past .par2 is a DATA file: classifying it as a
        // volume costs it its download slot, and the job then completes
        // without the payload it never fetched (14 Aug sweep).
        assert_eq!(par2_vol_suffix("x.vol-10.par2.bak"), None);
        assert_eq!(par2_vol_suffix("extras.vol-10.par2-sample.mkv"), None);
        assert_eq!(par2_vol_suffix("set.vol000+01.par2.txt"), None);
    }

    /// The same rule where it actually decides a download: `kind()`.
    #[test]
    fn a_quoted_name_continuing_past_par2_stays_data() {
        let file = |subject: &str| NzbFile {
            subject: subject.to_string(),
            ..Default::default()
        };
        // The genuine shapes still classify as they did.
        assert_eq!(
            file("Rel [2/3] - \"rel.vol-01.par2\" yEnc (1/1)").kind(),
            FileKind::Par2Volume
        );
        assert_eq!(
            file("Rel [1/3] - \"rel.par2\" yEnc (1/1)").kind(),
            FileKind::Par2Main
        );
        // A quoted payload name that merely CONTAINS the pattern is data
        // and must keep its slot.
        assert_eq!(
            file("Rel [3/3] - \"extras.vol-10.par2-sample.mkv\" yEnc (1/1)").kind(),
            FileKind::Data
        );
        assert_eq!(
            file("Rel [3/3] - \"rel.vol-10.par2.bak\" yEnc (1/1)").kind(),
            FileKind::Data
        );
    }

    /// One answer to "which par2 file do I fetch to get the critical
    /// packets", shared by the download path and pre-flight.
    ///
    /// The download path needs it because an obfuscated post ships
    /// volumes and no index, and it bootstraps the set from the smallest
    /// one. Pre-flight needs it because the Main packet is the only
    /// place the block size is written down, and a `.vol-NN.par2` budget
    /// cannot be sized without it. The 15 Aug post was both cases at
    /// once: seven `.vol-NN` volumes, no index, and the smallest of them
    /// a 41,901-byte file that turned out to hold Main + FileDesc + IFSC
    /// and not one recovery slice.
    #[test]
    fn the_par2_seed_is_the_cheapest_file_carrying_the_critical_packets() {
        let file = |subject: &str, bytes: u64| NzbFile {
            subject: subject.to_string(),
            segments: vec![Segment {
                number: 1,
                bytes,
                message_id: format!("{bytes}@x"),
            }],
            ..Default::default()
        };
        let nzb = |files: Vec<NzbFile>| Nzb {
            files,
            meta: Vec::new(),
        };

        // An index beats every volume, however small the volumes are.
        let with_index = nzb(vec![
            file("\"rel.mkv\" yEnc (1/1)", 3_000_000),
            file("\"rel.vol000+02.par2\" yEnc (1/1)", 900),
            file("\"rel.par2\" yEnc (1/1)", 40_000),
        ]);
        assert_eq!(with_index.par2_seed_file(), Some(2));

        // No index: the smallest volume, which is the 15 Aug shape.
        let obfuscated = nzb(vec![
            file("\"rel.mkv\" yEnc (1/1)", 3_332_350_599),
            file("\"rel.vol-05.par2\" yEnc (1/1)", 26_869_479),
            file("\"rel.vol-01.par2\" yEnc (1/1)", 41_901),
            file("\"rel.vol-02.par2\" yEnc (1/1)", 1_708_175),
        ]);
        assert_eq!(obfuscated.par2_seed_file(), Some(2));

        // A par2 file with no segments cannot be fetched, so it is not
        // the seed however small it looks.
        let mut empty_index = file("\"rel.par2\" yEnc (1/1)", 0);
        empty_index.segments.clear();
        let holed = nzb(vec![
            empty_index,
            file("\"rel.vol-01.par2\" yEnc (1/1)", 41_901),
        ]);
        assert_eq!(holed.par2_seed_file(), Some(1));

        // A post with no par2 at all has no seed and no budget to size.
        assert_eq!(
            nzb(vec![file("\"rel.mkv\" yEnc (1/1)", 3_000_000)]).par2_seed_file(),
            None
        );
    }

    #[test]
    fn minimality_accounting() {
        let nzb = Nzb::parse(sample()).unwrap();
        assert_eq!(nzb.total_bytes(), 1_650_000);
        // Eager set skips the recovery volume.
        assert_eq!(nzb.eager_bytes(), 1_550_000);
    }

    #[test]
    fn parses_head_meta_password() {
        let xml = br#"<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="title">Big Release</meta>
    <meta type="PASSWORD">s3cret pass</meta>
    <meta type="category"></meta>
  </head>
  <file poster="p" date="1" subject="s">
    <groups><group>alt.binaries.test</group></groups>
    <segments><segment bytes="1" number="1">a@b</segment></segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).unwrap();
        // Type is lowercased; empty-valued metas are dropped.
        assert_eq!(
            nzb.meta,
            vec![
                ("title".to_string(), "Big Release".to_string()),
                ("password".to_string(), "s3cret pass".to_string()),
            ]
        );
        assert_eq!(nzb.password(), Some("s3cret pass"));

        let plain = Nzb::parse(sample()).unwrap();
        assert_eq!(plain.password(), None);
    }

    /// The parser applies XML attribute-value normalization, and a
    /// comment claimed for months that it did not. Both halves are
    /// pinned here so the next reader can see the rule rather than the
    /// claim: a LITERAL tab (or CR, or LF) inside an attribute is a
    /// space by the time we see it, and a numeric character reference
    /// survives untouched - that is the escape hatch a producer who
    /// really means a tab has to use. Covers `subject` and `poster`
    /// (one `<file>` attribute route) and `<meta type=>` (the other).
    #[test]
    fn subject_whitespace_is_normalized_per_xml_spec() {
        let xml = b"<?xml version=\"1.0\"?>
<nzb>
  <head><meta type=\"pass\tword\">hunter2</meta></head>
  <file subject=\"a\tb\r\nc\" poster=\"p\tq\" date=\"1700000000\">
    <groups><group>alt.binaries.test</group></groups>
    <segments><segment bytes=\"1\" number=\"1\">a@b</segment></segments>
  </file>
  <file subject=\"a&#9;b\" poster=\"p\" date=\"1700000000\">
    <groups><group>alt.binaries.test</group></groups>
    <segments><segment bytes=\"1\" number=\"1\">c@d</segment></segments>
  </file>
</nzb>";
        let nzb = Nzb::parse(xml).expect("parses");
        // Literal tab -> space; CRLF is one space, not two.
        assert_eq!(nzb.files[0].subject, "a b c");
        assert_eq!(nzb.files[0].poster, "p q");
        // A character reference is NOT normalization input, so it lands
        // as the byte the producer asked for.
        assert_eq!(nzb.files[1].subject, "a\tb");
        // The meta `type=` attribute takes the same route (and is
        // lowercased and trimmed after, which does not touch interior
        // whitespace).
        assert_eq!(nzb.meta[0].0, "pass word");
    }

    #[test]
    fn rejects_empty() {
        let err = Nzb::parse(br#"<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"></nzb>"#);
        assert!(matches!(err, Err(NzbError::Empty)));
    }
}
