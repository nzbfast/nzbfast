//! Spotnet spot ingestion (design: M14j) - the decentralized index where
//! usenet itself carries the metadata. Spots live in `free.pt` headers: the
//! whole record is smuggled into the From address (category, size, RSA
//! modulus + signature - all visible via OVER without fetching bodies), the
//! full spot XML rides in `X-XML` continuation headers, and the NZB payload
//! is posted to `alt.binaries.ftd` as deflated, escape-armored text chunks.
//!
//! Wire format (per the competitor survey / spotweb's
//! `Services_Format_Parsing.php` + `Services_Signing_Base.php`):
//!
//! ```text
//! From: [Nickname] <[modulus].[user-signature]@[cat][keyid][subcats].[size].
//!        [random].[date].[custom-id].[custom-value].[header-signature]>
//! ```
//!
//! - base64 fields use a URL-safe variant: `/`→`-s`, `+`→`-p`, `=` stripped.
//! - The signature that guards the header is the LAST dot-field of the part
//!   after `@` (spotweb's `headersign`), NOT the field before it in the
//!   user-part - that one signs the message-id, and is only used for the
//!   separate full-spot check. It is RSA PKCS#1 v1.5 / SHA-1 over
//!   `title + header-without-that-last-field + poster`, over the raw wire
//!   bytes (the ISO-8859-1 gotcha: never re-encode).
//! - `title` is the subject up to the first `|` for modern keys and the
//!   whole subject on older encodings. Neither rule covers the group on its
//!   own, so both are tried (measured over 21,384 verified `free.pt` spots:
//!   17,114 first-part, 4,270 whole subject).
//! - The key is the modulus embedded in the From for self-signed spots, and
//!   one of the distributed Spotnet master keys otherwise.
//! - Self-signed spots additionally carry the V2 hashcash proof-of-work:
//!   sha1(message-id) starts with hex `0000`. Per spotweb we verify the
//!   signature strictly but treat hashcash failure as a warning flag, not a
//!   rejection - at least one client in the wild posts valid spots with an
//!   unmined message-id.
//! - The NZB payload is raw-deflated then escape-armored: NUL→`=A`,
//!   CR→`=B`, LF→`=C`, `=`→`=D`.
//!
//! Defensive limits (copied from spotweb): From records over 8 KB and spot
//! XML over 50 KB are rejected outright; inflated NZBs cap at 32 MB.

use std::io::Read;

use sha1::{Digest, Sha1};

use crate::index::{Index, Spot};
use crate::nntp::Connection;

/// From-record hard cap: anything bigger is garbage or an attack.
const MAX_FROM_RECORD: usize = 8 * 1024;
/// Spot XML hard cap (spotweb's X-XML limit).
const MAX_SPOT_XML: usize = 50 * 1024;
/// Inflated NZB payload cap.
const MAX_NZB_INFLATED: u64 = 32 * 1024 * 1024;

/// The distributed Spotnet master public keys, verbatim from spotweb's
/// `Services_Upgrade_Settings::createRsaKeys` (base64 modulus; the exponent
/// is 65537 for every one of them). Key-id 1 predates signing and has no
/// key, 5 and 6 were never issued, and 7 means "self-signed" - the modulus
/// travels in the From record instead.
const MASTER_KEYS: [(u8, &str); 3] = [
    (
        2,
        "ys8WSlqonQMWT8ubG0tAA2Q07P36E+CJmb875wSR1XH7IFhEi0CCwlUzNqBFhC+P",
    ),
    (
        3,
        "uiyChPV23eguLAJNttC/o0nAsxXgdjtvUvidV2JL+hjNzc4Tc/PPo2JdYvsqUsat",
    ),
    (
        4,
        "1k6RNDVD6yBYWR6kHmwzmSud7JkNV4SMigBrs+jFgOK5Ldzwl17mKXJhl+su/GR9",
    ),
];

/// Below this a decoded modulus is a random number, not a public key -
/// server-signed spots put a plain integer where the key would go.
const MIN_MODULUS_BYTES: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum SpotError {
    #[error("nntp: {0}")]
    Nntp(#[from] crate::nntp::NntpError),
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Spot(String),
}

fn err(msg: impl Into<String>) -> SpotError {
    SpotError::Spot(msg.into())
}

// ---------------------------------------------------------------------------
// From-header record
// ---------------------------------------------------------------------------

/// A parsed spot From-header record.
#[derive(Debug, Clone)]
pub struct SpotHeader {
    /// Poster nickname, exactly as the signature covers it: everything
    /// before the `<` minus the single separating space, quotes and all.
    /// spotweb signs `substr($from, 0, strpos($from, '<') - 1)`, so this is
    /// deliberately not trimmed.
    pub(crate) poster: String,
    /// Self-signed RSA public-key modulus from the From record, big-endian
    /// (exponent is always 65537). Empty on server-signed spots, which put
    /// a random number there and rely on a master key instead.
    pub(crate) modulus: Vec<u8>,
    /// PKCS#1 v1.5 signature over the header - the LAST dot-field of the
    /// part after `@` (spotweb's `headersign`).
    pub(crate) signature: Vec<u8>,
    /// Signature over `<message-id>` made with `Self::modulus`; the
    /// full-spot check uses it, the header check never does. Optional.
    pub user_signature: Vec<u8>,
    /// Category, 0-based as spotweb stores it (the wire digit minus one).
    pub(crate) category: u8,
    /// Key regime: 1–6 select a distributed Spotnet key, 7 is self-signed.
    pub(crate) key_id: u8,
    /// Subcategory runs, e.g. `["a09", "b04"]`.
    pub(crate) subcats: Vec<String>,
    pub(crate) size: u64,
    /// Unix timestamp from the record.
    pub(crate) date: i64,
    pub custom_id: String,
    pub custom_value: String,
    /// The portion after `@` minus the trailing signature field - the exact
    /// bytes [`Self::signature`] covers.
    pub(crate) signed_part: String,
}

/// Parse a spot From header. Returns `None` on anything malformed or
/// oversized - never panics, tolerates arbitrary garbage.
pub fn parse_spot_from(from_header: &str) -> Option<SpotHeader> {
    if from_header.len() > MAX_FROM_RECORD {
        return None;
    }
    let lt = from_header.find('<')?;
    let gt = from_header.rfind('>')?;
    if gt <= lt {
        return None;
    }
    // The signed poster string drops exactly one byte before the '<' - the
    // space of `Nickname <addr>`. Falling back to a trim keeps a nickname
    // whose last char is multi-byte from being a hard parse failure.
    let poster = from_header
        .get(..lt.saturating_sub(1))
        .unwrap_or_else(|| from_header[..lt].trim_end())
        .to_string();
    let inner = &from_header[lt + 1..gt];
    let (user_part, header) = inner.split_once('@')?;
    // [modulus] or [modulus].[user-signature] - or, on server-signed spots,
    // a plain random number. Both are optional: only the master key regimes
    // can verify without a modulus, and nothing here needs the user
    // signature, so neither absence rejects the record.
    let mut user_fields = user_part.split('.');
    let modulus = user_fields
        .next()
        .and_then(spot_b64_decode)
        .unwrap_or_default();
    let user_signature = user_fields
        .next()
        .and_then(spot_b64_decode)
        .unwrap_or_default();

    // [cat][keyid][subcats].[size].[random].[date].[custom-id].[custom-value]
    // .[header-signature]
    let fields: Vec<&str> = header.split('.').collect();
    if fields.len() < 6 {
        return None;
    }
    // The header signature is the LAST field, and covers everything before
    // it - always, however many fields there are.
    let last = fields[fields.len() - 1];
    let signature = spot_b64_decode(last)?;
    if signature.is_empty() {
        return None;
    }
    let signed_part = &header[..header.len() - last.len() - 1];

    let mut chars = fields[0].chars();
    // spotweb stores `substr($fields[0], 0, 1) - 1`: the wire digit is
    // 1-based, everything downstream of it is 0-based.
    let category = (chars.next()?.to_digit(10)? as u8).saturating_sub(1);
    let key_id = chars.next()?.to_digit(10)? as u8;
    let subcats = parse_subcats(chars.as_str())?;
    let size = fields[1].parse().ok()?;
    let date = fields[3].parse().ok()?;

    Some(SpotHeader {
        poster,
        modulus,
        signature,
        user_signature,
        category,
        key_id,
        subcats,
        size,
        date,
        custom_id: fields[4].to_string(),
        // With the bare six fields spotweb tolerates, field 5 IS the
        // signature, not a custom value.
        custom_value: if fields.len() > 6 {
            fields[5].to_string()
        } else {
            String::new()
        },
        signed_part: signed_part.to_string(),
    })
}

/// Subcats are letter+digit runs concatenated: `a09b04` → `["a09","b04"]`.
fn parse_subcats(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            if !cur.is_empty() {
                if cur.len() < 2 {
                    return None; // a letter with no digits
                }
                out.push(std::mem::take(&mut cur));
            }
            cur.push(c.to_ascii_lowercase());
        } else if c.is_ascii_digit() {
            if cur.is_empty() {
                return None; // digits before any letter
            }
            cur.push(c);
        } else {
            return None;
        }
    }
    if !cur.is_empty() {
        if cur.len() < 2 {
            return None;
        }
        out.push(cur);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Signature + hashcash verification
// ---------------------------------------------------------------------------

/// Which public key a spot's signature verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpotKeySource {
    /// One of the distributed Spotnet keys - the spot was signed by the
    /// central signing server, so the poster identity is vouched for.
    Master,
    /// The modulus the poster put in their own From record. Proves only
    /// that one person posted the whole record; the hashcash is what makes
    /// that cost something.
    SelfSigned,
}

/// Result of [`verify_spot`]: signature strictly, hashcash as a warning.
#[derive(Debug, Clone)]
pub struct SpotVerify {
    pub(crate) signature_ok: bool,
    /// `false` only for self-signed spots whose message-id fails the V2
    /// hashcash proof-of-work - a warning flag, never a rejection.
    pub(crate) hashcash_ok: bool,
    /// Which key verified, `None` when nothing did.
    pub(crate) key_source: Option<SpotKeySource>,
    /// The title the signature actually covered, `None` when nothing
    /// verified. Two conventions are live and the verifier has to try
    /// both, so which one won is the only evidence of where the spotter
    /// meant the title to end - a trailing `| ClubNZB` is part of the
    /// title for one poster and a tag appended after it for another.
    /// Store this rather than the raw subject.
    pub(crate) title: Option<String>,
}

/// PKCS#1 v1.5 signature scheme for SHA-1, written out rather than
/// derived with `Pkcs1v15Sign::new::<Sha1>()`.
///
/// `new::<D>()` uses `D` only to read two constants off it - the digest
/// length and the ASN.1 DigestInfo prefix carrying SHA-1's OID - and
/// never hashes anything (we hash separately, in `signed_digests`). But
/// it demands `D` implement `rsa`'s OWN `digest` traits, which welds
/// this call site to whatever digest major version `rsa` happens to be
/// on. That weld is the entire reason the RustCrypto digest-0.11 wave
/// was held: with it, `sha1` cannot move until `rsa` does.
///
/// The two constants are frozen by RFC 8017 s9.2 note 1, not by a crate
/// version, so naming them here is not a copy of an implementation
/// detail - it is the spec. `pkcs1v15_prefix_matches_rfc8017` pins them.
fn pkcs1v15_sha1() -> rsa::Pkcs1v15Sign {
    /// DigestInfo prefix for SHA-1: RFC 8017 s9.2 note 1.
    const SHA1_DIGESTINFO: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    rsa::Pkcs1v15Sign {
        hash_len: Some(20),
        prefix: Box::new(SHA1_DIGESTINFO),
    }
}

/// Verify a spot header: RSA PKCS#1 v1.5 / SHA-1 over
/// `title + signed_part + poster` (see the module header for the title and
/// key rules), plus the V2 hashcash check when the key was self-signed:
/// sha1(message-id) must start with hex `0000`.
///
/// `subject` is the raw OVER subject, not a pre-split title.
pub fn verify_spot(header: &SpotHeader, subject: &str, message_id: &str) -> SpotVerify {
    let digests = signed_digests(header, subject);
    let scheme = pkcs1v15_sha1();
    let mut key_source = None;
    let mut title = None;
    'search: for (source, key) in candidate_keys(header) {
        for (t, d) in &digests {
            if key.verify(scheme.clone(), d, &header.signature).is_ok() {
                key_source = Some(source);
                title = Some((*t).to_string());
                break 'search;
            }
        }
    }

    let hashcash_ok = if key_source == Some(SpotKeySource::SelfSigned) {
        let d = Sha1::digest(normalize_msgid(message_id).as_bytes());
        d[0] == 0 && d[1] == 0
    } else {
        true
    };

    SpotVerify {
        signature_ok: key_source.is_some(),
        hashcash_ok,
        key_source,
        title,
    }
}

/// The public keys worth trying for a record, best first.
fn candidate_keys(header: &SpotHeader) -> Vec<(SpotKeySource, rsa::RsaPublicKey)> {
    let e = rsa::BigUint::from(65537u32);
    let mut out = Vec::with_capacity(2);
    let master = (header.key_id != 7)
        .then(|| MASTER_KEYS.iter().find(|(id, _)| *id == header.key_id))
        .flatten()
        .and_then(|(_, m)| b64_decode(m))
        .map(|n| rsa::BigUint::from_bytes_be(&n))
        .and_then(|n| rsa::RsaPublicKey::new(n, e.clone()).ok());
    if let Some(key) = master {
        out.push((SpotKeySource::Master, key));
    }
    // Key-id 7 is self-signed by design. Key-id 2 also is when the record
    // carries a real modulus - spotweb's "personal dispose" branch, and not
    // a rarity: 1,246 of the 1,606 key-id 2 spots in a 40,000-line free.pt
    // sample verify this way and only 360 against the master key.
    if header.modulus.len() >= MIN_MODULUS_BYTES {
        let n = rsa::BigUint::from_bytes_be(&header.modulus);
        if let Ok(key) = rsa::RsaPublicKey::new(n, e) {
            out.push((SpotKeySource::SelfSigned, key));
        }
    }
    out
}

/// Every SHA-1 digest the header signature might legitimately cover: two
/// title rules crossed with the two ways a raw header line could have been
/// decoded. Ordered by how often each wins in the wild.
///
/// Each digest is paired with the title it was built from, so the caller
/// can report which rule won; the two decodings of one title share it.
fn signed_digests<'a>(header: &SpotHeader, subject: &'a str) -> Vec<(&'a str, [u8; 20])> {
    let first = subject.split('|').next().unwrap_or(subject).trim();
    let mut titles: Vec<&str> = vec![first];
    if subject != first {
        titles.push(subject);
    }
    let poster_l1 = latin1_bytes(&header.poster);
    let mut out = Vec::with_capacity(titles.len() * 2);
    for title in titles {
        let title_l1 = latin1_bytes(title);
        let mut pairs: Vec<(&[u8], &[u8])> = vec![(title.as_bytes(), header.poster.as_bytes())];
        if title_l1.is_some() || poster_l1.is_some() {
            pairs.push((
                title_l1.as_deref().unwrap_or(title.as_bytes()),
                poster_l1.as_deref().unwrap_or(header.poster.as_bytes()),
            ));
        }
        for (t, p) in pairs {
            let mut h = Sha1::new();
            h.update(t);
            h.update(header.signed_part.as_bytes());
            h.update(p);
            out.push((title, h.finalize().into()));
        }
    }
    out
}

/// The wire bytes behind a latin-1-decoded header field (see
/// [`crate::nntp::decode_header_line`]) - one byte per char. `None` when
/// the field is plain ASCII (its UTF-8 bytes are already the wire bytes)
/// or holds a char that no single byte could have produced.
fn latin1_bytes(s: &str) -> Option<Vec<u8>> {
    if s.is_ascii() {
        return None;
    }
    s.chars()
        .map(|c| (c as u32 <= 0xFF).then_some(c as u8))
        .collect()
}

/// Spotter id: base64 of the big-endian crc32 of the modulus bytes, with
/// `=`, `/` and `+` stripped (spotweb's `calculateSpotterId`).
pub fn spotter_id(modulus_bytes: &[u8]) -> String {
    let crc = crc32fast::hash(modulus_bytes);
    b64_encode(&crc.to_be_bytes())
        .chars()
        .filter(|c| !matches!(c, '=' | '/' | '+'))
        .collect()
}

fn normalize_msgid(id: &str) -> String {
    let id = id.trim();
    if id.starts_with('<') {
        id.to_string()
    } else {
        format!("<{id}>")
    }
}

// ---------------------------------------------------------------------------
// base64 (standard alphabet + the Spotnet URL-safe variant)
// ---------------------------------------------------------------------------

/// Decode Spotnet's URL-safe base64: `-s`→`/`, `-p`→`+`, padding stripped.
pub fn spot_b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut std = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '-' {
            match chars.next() {
                Some('s') => std.push('/'),
                Some('p') => std.push('+'),
                _ => return None,
            }
        } else {
            std.push(c);
        }
    }
    let std = std.trim_end_matches('=').to_string();
    b64_decode(&std)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Standard base64 decode, tolerant of missing padding.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=').as_bytes();
    if s.len() % 4 == 1 {
        return None; // impossible length
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// NZB payload armor: special-zip escaping + raw deflate
// ---------------------------------------------------------------------------

/// Reverse the spot payload armor: un-escape `=A`/`=B`/`=C`/`=D` →
/// NUL/CR/LF/`=`, then inflate (raw deflate first, zlib-wrapped fallback -
/// posters disagree). `None` on corrupt data or output over the 32 MB cap.
pub fn unspecial_zip(data: &[u8]) -> Option<Vec<u8>> {
    let mut raw = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == b'=' && i + 1 < data.len() {
            let mapped = match data[i + 1] {
                b'A' => Some(0),
                b'B' => Some(b'\r'),
                b'C' => Some(b'\n'),
                b'D' => Some(b'='),
                _ => None, // tolerate stray '=' literally
            };
            if let Some(m) = mapped {
                raw.push(m);
                i += 2;
                continue;
            }
        }
        raw.push(b);
        i += 1;
    }
    inflate_capped(&raw)
}

fn inflate_capped(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let ok = flate2::read::DeflateDecoder::new(raw)
        .take(MAX_NZB_INFLATED + 1)
        .read_to_end(&mut out)
        .is_ok();
    if !(ok && !out.is_empty()) {
        out.clear();
        let ok = flate2::read::ZlibDecoder::new(raw)
            .take(MAX_NZB_INFLATED + 1)
            .read_to_end(&mut out)
            .is_ok();
        if !(ok && !out.is_empty()) {
            return None;
        }
    }
    (out.len() as u64 <= MAX_NZB_INFLATED).then_some(out)
}

/// Forward armor (raw deflate + escape) - used by tests and, later, spot
/// posting.
pub fn special_zip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("deflate to memory");
    let deflated = enc.finish().expect("deflate to memory");
    let mut out = Vec::with_capacity(deflated.len() + deflated.len() / 8);
    for &b in &deflated {
        match b {
            0 => out.extend_from_slice(b"=A"),
            b'\r' => out.extend_from_slice(b"=B"),
            b'\n' => out.extend_from_slice(b"=C"),
            b'=' => out.extend_from_slice(b"=D"),
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Spot XML (string-scan; spot XML in the wild is often broken - no XML dep)
// ---------------------------------------------------------------------------

/// The interesting parts of a full spot's XML payload.
#[derive(Debug, Clone, Default)]
pub struct SpotXml {
    pub title: String,
    pub description: String,
    pub poster: String,
    pub category: u32,
    /// Raw `<Sub>` values, e.g. `["01a09", "01b04"]`.
    pub subcats: Vec<String>,
    pub size: u64,
    /// NZB payload segment message-ids (no angle brackets), in order.
    pub nzb_segments: Vec<String>,
}

/// Tolerant string-scan parse of the spot XML. Returns `None` only when the
/// payload is oversized or has no `<Title>` at all.
pub fn parse_spot_xml(xml: &str) -> Option<SpotXml> {
    if xml.len() > MAX_SPOT_XML {
        return None;
    }
    let title = decode_text(tag_text(xml, "Title")?);
    let description = tag_text(xml, "Description")
        .map(decode_text)
        .unwrap_or_default();
    let poster = tag_text(xml, "Poster").map(decode_text).unwrap_or_default();
    let cat_scope = tag_text(xml, "Category").unwrap_or("");
    let category = cat_scope
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    let subcats = all_tag_texts(cat_scope, "Sub")
        .into_iter()
        .map(|s| s.trim().to_string())
        .collect();
    let size = tag_text(xml, "Size")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let nzb_segments = all_tag_texts(tag_text(xml, "NZB").unwrap_or(""), "Segment")
        .into_iter()
        .map(|s| xml_unescape(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();
    Some(SpotXml {
        title,
        description,
        poster,
        category,
        subcats,
        size,
        nzb_segments,
    })
}

/// First `<tag>…</tag>` inner text (attributes on the open tag tolerated).
fn tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let mut search = 0;
    let open = format!("<{tag}");
    loop {
        let p = search + xml[search..].find(&open)?;
        let after = p + open.len();
        // Must be followed by '>' or whitespace+attrs, not a longer tag name.
        match xml[after..].chars().next() {
            Some('>') => {
                let start = after + 1;
                return Some(&xml[start..close_at(xml, start, tag)?]);
            }
            Some(c) if c.is_whitespace() => {
                let gt = after + xml[after..].find('>')?;
                if xml[after..gt].ends_with('/') {
                    return None; // self-closing
                }
                let start = gt + 1;
                return Some(&xml[start..close_at(xml, start, tag)?]);
            }
            _ => search = after, // e.g. <NZBx…> while looking for <NZB>
        }
    }
}

/// Where `</tag>` closes the element that starts at `start`, skipping
/// over any CDATA section on the way.
///
/// A literal `</Title>` inside `<![CDATA[…]]>` is legal XML and means
/// nothing to the parser, but a plain `find` would stop there - which
/// is a free title-truncation primitive for a hostile spot, since the
/// spot XML is attacker-supplied and its title becomes a wall card.
///
/// An UNTERMINATED `<![CDATA[` is not that attack, it is just broken
/// markup, and refusing the element there would throw away a spot whose
/// `<NZB>` segments parse perfectly well. So it degrades to the plain
/// scan: the first close tag after the opener wins, as it did before
/// this function existed.
fn close_at(xml: &str, start: usize, tag: &str) -> Option<usize> {
    let close = format!("</{tag}>");
    let mut i = start;
    loop {
        let rest = &xml[i..];
        let end = rest.find(&close).map(|p| i + p);
        match rest.find(CDATA_OPEN).map(|p| i + p) {
            // A CDATA section opens before the next close tag: jump the
            // whole section, or give up on CDATA if it never closes.
            Some(cd) if end.is_none_or(|e| cd < e) => {
                let body = cd + CDATA_OPEN.len();
                match xml[body..].find(CDATA_CLOSE) {
                    Some(p) => i = body + p + CDATA_CLOSE.len(),
                    None => return end,
                }
            }
            _ => return end,
        }
    }
}

const CDATA_OPEN: &str = "<![CDATA[";
const CDATA_CLOSE: &str = "]]>";

/// One element's text with XML's two ways of writing the same string
/// collapsed into one: `<![CDATA[…]]>` sections are literal, everything
/// outside them is entity-escaped.
///
/// spotweb writes titles both ways depending on its vintage, and the
/// CDATA form used to reach the wall verbatim - live cards named
/// `<![CDATA[Shark Night (2011) R5 LiNE XviD - MiSTERE]]>`, 54 of them
/// on a live index and a larger share the further back the feed is read
/// (the 2011 depth sample is CDATA throughout). The `spots` table was
/// never affected: its title comes from the OVER subject, and only the
/// resolver's full-spot XML title takes this path.
fn decode_text(inner: &str) -> String {
    if !inner.contains(CDATA_OPEN) {
        return xml_unescape(inner).trim().to_string();
    }
    let mut out = String::with_capacity(inner.len());
    let mut rest = inner;
    while let Some(p) = rest.find(CDATA_OPEN) {
        out.push_str(&xml_unescape(&rest[..p]));
        let body = &rest[p + CDATA_OPEN.len()..];
        match body.find(CDATA_CLOSE) {
            Some(e) => {
                out.push_str(&body[..e]);
                rest = &body[e + CDATA_CLOSE.len()..];
            }
            // Unterminated: the remainder is content, not markup.
            None => {
                out.push_str(body);
                rest = "";
                break;
            }
        }
    }
    out.push_str(&xml_unescape(rest));
    out.trim().to_string()
}

/// All `<tag>…</tag>` inner texts within `scope`, in order.
fn all_tag_texts<'a>(scope: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = scope;
    while let Some(inner) = tag_text(rest, tag) {
        out.push(inner);
        // Advance past this close tag.
        let close = format!("</{tag}>");
        let end = inner.as_ptr() as usize - rest.as_ptr() as usize + inner.len() + close.len();
        if end >= rest.len() {
            break;
        }
        rest = &rest[end..];
    }
    out
}

fn xml_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        let tail = &rest[p..];
        let known = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ];
        if let Some((ent, ch)) = known.iter().find(|(e, _)| tail.starts_with(e)) {
            out.push(*ch);
            rest = &tail[ent.len()..];
        } else if let Some(semi) = tail.as_bytes()[..tail.len().min(8)]
            .iter()
            .position(|&b| b == b';')
        {
            // Byte scan, not a &str slice: index 8 of attacker-supplied
            // XML can split a multi-byte char and panic.
            // &#NN; / &#xNN;
            let body = &tail[1..semi];
            let code = body
                .strip_prefix("#x")
                .or_else(|| body.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| body.strip_prefix('#').and_then(|d| d.parse().ok()));
            match code.and_then(char::from_u32) {
                Some(c) => out.push(c),
                None => out.push_str(&tail[..semi + 1]),
            }
            rest = &tail[semi + 1..];
        } else {
            out.push('&');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Scanner: OVER-pass over a spot group (header-only, no bodies)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
pub struct SpotScanSummary {
    /// OVER entries examined.
    pub scanned: u64,
    /// Parsed + signature-verified spots.
    pub valid: u64,
    /// Failed to parse or failed signature verification.
    pub invalid: u64,
    /// The subset of `invalid` that parsed as a spot record but whose
    /// signature did not check out. The rest are ordinary articles: a spot
    /// group carries plenty of traffic that was never a spot, so folding
    /// the two together hides the number that actually measures the
    /// verifier (99.5% of parsed records on `free.pt`).
    pub unverified: u64,
    /// Verified records that are Spotnet moderation traffic rather than
    /// content, and so are not stored. See [`is_moderation`].
    pub moderation: u64,
    /// Valid spots newly inserted (not already in the DB).
    pub new: u64,
    /// Valid key-id-7 spots whose hashcash PoW failed (warning only).
    pub hashcash_warn: u64,
    /// Articles this pass read BELOW the low-water mark, i.e. history
    /// the forward scan would never have reached.
    pub deepened: u64,
    /// Articles still below the low-water mark once this pass finished.
    /// 0 means the group is scanned to its first article.
    pub depth_left: u64,
}

/// Incremental OVER scan of a Spotnet group into the index DB. Resumes from
/// the stored high-water mark (keyed `spots:<group>` so it never collides
/// with a release-index scan of the same group; `server_host` is the host
/// `conn` talks to - article numbers are per server, A8).
/// Is this subject a Spotnet moderation record rather than a spot about
/// a posting? These carry `DISPOSE <message-id> - <the spot's title>`,
/// which is why they read like releases if they are stored.
///
/// We deliberately do not ACT on them either. spotweb checks a dispose
/// against the distributed master keys; the majority here are the
/// self-signed branch, which any poster can mint. Honouring one on that
/// basis would be a free "delete this from someone's index" button.
pub fn is_moderation(subject: &str) -> bool {
    subject.trim_start().starts_with("DISPOSE ")
}

pub async fn scan_spots(
    conn: &mut Connection,
    ix: &mut Index,
    group: &str,
    server_host: &str,
    backfill: u64,
    deepen: u64,
) -> Result<SpotScanSummary, SpotError> {
    let g = conn.group(group).await?;
    let mark_key = format!("spots:{group}");
    let mark = ix.high_water(&mark_key, server_host);
    // Article numbers come from the untrusted GROUP line; saturating math plus a
    // break on the final chunk stop a near-u64::MAX `high` from overflowing
    // (debug panic; in release it wraps to 0, rescans forever, and persists a
    // poisoned high-water mark that re-triggers next run).
    let backfill_floor = g.high.saturating_sub(backfill).max(g.low);
    let mut low = if mark > 0 {
        mark.saturating_add(1)
    } else {
        backfill_floor
    };
    let mut sum = SpotScanSummary::default();
    while low <= g.high {
        let hi = low.saturating_add(OVER_CHUNK - 1).min(g.high);
        let entries = conn.over(low, hi).await?;
        ingest_over(ix, &entries, &mut sum)?;
        ix.set_high_water(&mark_key, server_host, hi)?;
        if hi >= g.high {
            break;
        }
        low = hi + 1;
    }

    // The deepening leg. Without it the spot catalogue is whatever the
    // first backfill happened to reach plus the live trickle - on a live
    // index, 26,552 spots over 141 days against a group holding 4.43 M
    // articles back to 2011, all of it verified and, measured at five
    // depths, all of it still fetchable. That history is the catalogue
    // breadth the header scanner structurally cannot reach: spot NZBs
    // target a.b.misc / boneless / nl / test, which we never scan.
    //
    // Cheap on purpose - OVER only, no bodies. Promotion to wall cards
    // is the expensive half and stays budgeted and newest-first in
    // `spot_resolve_pass`, so a deep backlog never delays a live spot.
    if deepen == 0 {
        return Ok(sum);
    }
    // An install that scanned before this existed has no low-water mark.
    // Seeding it at today's backfill floor re-reads a band we already
    // hold (insert_spot is ON CONFLICT DO NOTHING, so that costs OVER
    // traffic once and nothing else) and, because `g.high` only ever
    // rises, that floor is at or above the one the first backfill used
    // - so the walk down passes through it and no band is skipped.
    let floor = match ix.low_water(&mark_key, server_host) {
        0 => backfill_floor,
        n => n,
    };
    if floor <= g.low {
        return Ok(sum); // the whole group is scanned
    }
    let stop = floor.saturating_sub(deepen).max(g.low);
    for (lo, hi) in deepen_chunks(floor, stop) {
        let entries = conn.over(lo, hi).await?;
        ingest_over(ix, &entries, &mut sum)?;
        sum.deepened += hi - lo + 1;
        // Persist per chunk, not per pass, so an interrupted deepen
        // keeps what it read - and DOWNWARD, so every write is lower
        // than the last and the mark is always the deepest article
        // fully read.
        ix.set_low_water(&mark_key, server_host, lo)?;
    }
    sum.depth_left = stop.saturating_sub(g.low);
    Ok(sum)
}

/// OVER entries per request. Shared by both legs so the deepening walk
/// has the same wire shape as the forward one.
const OVER_CHUNK: u64 = 10_000;

/// The deepening slice `[stop, floor)` cut into OVER-sized inclusive
/// ranges, **deepest last**.
///
/// The direction is the whole point. The low-water mark is persisted
/// after each chunk, so the last write is the one that survives, and it
/// has to be the deepest article actually read. Walking upward writes
/// the HIGHEST chunk start last, which re-reads the tail of the slice
/// every pass: measured live at OVER_CHUNK = 10,000 with deepen =
/// 20,000, the mark landed 10,000 articles above the deepest article
/// read. With `deepen <= OVER_CHUNK` that never advances at all - one
/// slice, re-read forever.
fn deepen_chunks(floor: u64, stop: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut end = floor; // exclusive
    while end > stop {
        let lo = end.saturating_sub(OVER_CHUNK).max(stop);
        out.push((lo, end - 1));
        end = lo;
    }
    out
}

/// Parse, verify and store one OVER batch. Both scan legs run this;
/// only the article range and the mark they move differ.
fn ingest_over(
    ix: &mut Index,
    entries: &[crate::nntp::OverEntry],
    sum: &mut SpotScanSummary,
) -> Result<(), SpotError> {
    // Collected, then stored in ONE transaction below. Row-at-a-time
    // autocommit was a write lock, a WAL commit and an fsync per spot,
    // thousands of times per OVER chunk - see `Index::insert_spots`.
    let mut batch: Vec<Spot> = Vec::new();
    for e in entries {
        sum.scanned += 1;
        let Some(h) = parse_spot_from(&e.from) else {
            sum.invalid += 1;
            continue;
        };
        let v = verify_spot(&h, &e.subject, &e.message_id);
        if !v.signature_ok {
            sum.invalid += 1;
            sum.unverified += 1;
            continue;
        }
        sum.valid += 1;
        if !v.hashcash_ok {
            sum.hashcash_warn += 1;
        }
        // Spotnet's moderation traffic is posted to the same group in
        // the same envelope, and it verifies exactly like content
        // does - it is a takedown request naming another spot, not a
        // description of a posting. There is no NZB behind one, so a
        // stored moderation record is a row that reads like a release
        // and cannot be downloaded. 1,345 of 16,603 verified records
        // in a live 20,000-header pass, so it is 8% of the table.
        //
        // Matched on spotweb's own marker rather than the key regime:
        // most of these are the self-signed "personal dispose" branch
        // (see candidate_keys), so key-id alone does not separate them.
        if is_moderation(&e.subject) {
            sum.moderation += 1;
            continue;
        }
        let spot = Spot {
            id: 0,
            msgid: e.message_id.clone(),
            // The title the signature covered, not the raw subject.
            // Some spotters sign the subject whole, `| ClubNZB` and
            // all; others sign up to the `|` and append a tag after
            // it. Only the verifier knows which, so storing the
            // subject put one poster's tag inside everyone's title.
            title: v.title.clone().unwrap_or_else(|| e.subject.clone()),
            category: h.category,
            subcats: h.subcats.join(","),
            size: h.size,
            date: h.date,
            // Only a self-signed key identifies a spotter; a master-key
            // spot's user-part is a random number, so hashing it would
            // mint a fresh "identity" for every post.
            spotter_id: match v.key_source {
                Some(SpotKeySource::SelfSigned) => spotter_id(&h.modulus),
                _ => String::new(),
            },
            verified: true,
            hashcash_ok: v.hashcash_ok,
            nzb_msgids: Vec::new(),
        };
        batch.push(spot);
    }
    sum.new += ix.insert_spots(&batch)? as u64;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fetch: full spot (X-XML headers) → NZB payload articles → NZB bytes
// ---------------------------------------------------------------------------

/// Fetch a spot's full XML (concatenated `X-XML` continuation headers, body
/// fallback for ancient spots) and its NZB payload (armored deflate chunks
/// posted to alt.binaries.ftd), returning the parsed XML and the inflated
/// NZB bytes.
pub async fn fetch_spot_nzb(
    conn: &mut Connection,
    msgid: &str,
) -> Result<(SpotXml, Vec<u8>), SpotError> {
    let mid = normalize_msgid(msgid);
    let head = conn
        .head(&mid)
        .await?
        .ok_or_else(|| err(format!("spot article {mid} not found")))?;
    let mut xml = xml_from_headers(&head);
    if xml.is_empty() {
        // Pre-X-XML spots carry the XML in the article body.
        let body = conn
            .body(&mid)
            .await?
            .ok_or_else(|| err(format!("spot article {mid} has no body")))?;
        // Check the raw body against the cap BEFORE the lossy conversion: a
        // 256 MiB body of invalid UTF-8 expands to ~768 MiB of U+FFFD on top
        // of the raw copy and the unstuff copy, ~1.3 GB for one spot.
        if body.len() > MAX_SPOT_XML {
            return Err(err(format!("spot XML exceeds the {MAX_SPOT_XML} byte cap")));
        }
        xml = String::from_utf8_lossy(&unstuff(&body, false)).into_owned();
    }
    if xml.len() > MAX_SPOT_XML {
        return Err(err(format!("spot XML exceeds the {MAX_SPOT_XML} byte cap")));
    }
    let sx = parse_spot_xml(&xml).ok_or_else(|| err("unparseable spot XML"))?;
    if sx.nzb_segments.is_empty() {
        return Err(err("spot XML lists no NZB segments"));
    }

    let mut packed = Vec::new();
    for seg in &sx.nzb_segments {
        let sid = normalize_msgid(seg);
        let body = conn
            .body(&sid)
            .await?
            .ok_or_else(|| err(format!("NZB payload segment {sid} missing")))?;
        // The armor escapes every real CR/LF, so any newlines on the wire
        // are transport line-wrapping - strip them all.
        packed.extend_from_slice(&unstuff(&body, true));
        // Cap the COMPRESSED payload too: MAX_NZB_INFLATED only bounds the
        // inflate output (checked after the whole payload is resident), so
        // without this a hostile spot listing thousands of large garbage
        // segments buffers gigabytes in RAM before inflation ever runs.
        if packed.len() as u64 > MAX_NZB_INFLATED {
            return Err(err(format!(
                "spot NZB payload exceeds the {MAX_NZB_INFLATED} byte cap"
            )));
        }
    }
    let nzb = unspecial_zip(&packed).ok_or_else(|| err("could not inflate the NZB payload"))?;
    Ok((sx, nzb))
}

/// The release payload message-ids inside an inflated spot NZB: the
/// first segment of each file, bracketed the way OVER (and the index's
/// `files.segments`) stores them.
///
/// These are the ids the release's own articles carry in the target
/// group, so they can join a header-scanned index. The ids in
/// `SpotXml::nzb_segments` cannot: those name the armored deflate
/// chunks the NZB itself rides on alt.binaries.ftd, which never appear
/// in any content group.
pub fn payload_msgids(nzb: &[u8]) -> Vec<String> {
    let Ok(parsed) = crate::nzb::Nzb::parse(nzb) else {
        return Vec::new();
    };
    parsed
        .files
        .iter()
        .filter_map(|f| f.segments.iter().min_by_key(|s| s.number))
        .map(|s| format!("<{}>", s.message_id))
        .collect()
}

/// Concatenate the values of every `X-XML:` header (in order). Spotweb eats
/// exactly one space after the colon; so do we.
fn xml_from_headers(raw: &[u8]) -> String {
    let mut xml = String::new();
    for line in raw.split_inclusive(|&b| b == b'\n') {
        let line = if line.first() == Some(&b'.') {
            &line[1..]
        } else {
            line
        };
        let text = String::from_utf8_lossy(line);
        let t = text.trim_end_matches(['\r', '\n']);
        // Byte compare: t[..6] on a header whose byte 6 splits a
        // multi-byte char panics (attacker-controlled HEAD line). If the
        // first 6 bytes match the ASCII prefix, 6 is a char boundary.
        if t.len() >= 6 && t.as_bytes()[..6].eq_ignore_ascii_case(b"x-xml:") {
            let v = &t[6..];
            xml.push_str(v.strip_prefix(' ').unwrap_or(v));
            // Enforce the module's stated cap HERE, not after the whole
            // string is built: `head()` returns up to MAX_MULTILINE_BYTES
            // (256 MiB), so a spot whose HEAD is nothing but X-XML lines
            // grew this String to that size before the caller's check could
            // reject it. One byte over is enough for the caller to refuse.
            if xml.len() > MAX_SPOT_XML {
                return xml;
            }
        }
    }
    xml
}

/// Undo NNTP dot-stuffing; optionally strip all line terminators.
fn unstuff(raw: &[u8], strip_newlines: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for line in raw.split_inclusive(|&b| b == b'\n') {
        let line = if line.first() == Some(&b'.') {
            &line[1..]
        } else {
            line
        };
        if strip_newlines {
            let mut end = line.len();
            while end > 0 && (line[end - 1] == b'\r' || line[end - 1] == b'\n') {
                end -= 1;
            }
            out.extend_from_slice(&line[..end]);
        } else {
            out.extend_from_slice(line);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    use crate::mock::{Chaos, MockServer, OverRow};

    /// The DigestInfo prefix `pkcs1v15_sha1` writes out is the one RFC
    /// 8017 s9.2 note 1 fixes for SHA-1, and its length field agrees with
    /// SHA-1's 20-byte output. Decoding it rather than comparing bytes is
    /// the point: a typo in the literal would still match a copy of
    /// itself, but it cannot survive being parsed as the ASN.1 the spec
    /// describes.
    #[test]
    fn pkcs1v15_prefix_matches_rfc8017() {
        let s = pkcs1v15_sha1();
        assert_eq!(s.hash_len, Some(<Sha1 as Digest>::output_size()));
        // SEQUENCE { SEQUENCE { OID 1.3.14.3.2.26, NULL }, OCTET STRING (20) }
        assert_eq!(s.prefix[0], 0x30, "outer SEQUENCE");
        assert_eq!(
            s.prefix[1] as usize,
            s.prefix.len() - 2 + 20,
            "outer length"
        );
        assert_eq!(&s.prefix[2..4], &[0x30, 0x09], "AlgorithmIdentifier");
        assert_eq!(
            &s.prefix[4..11],
            &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a],
            "SHA-1 OID"
        );
        assert_eq!(&s.prefix[11..13], &[0x05, 0x00], "NULL parameters");
        assert_eq!(&s.prefix[13..15], &[0x04, 0x14], "OCTET STRING, 20 bytes");
        assert_eq!(s.prefix.len(), 15);
    }

    /// Fixed small key: 512-bit keygen keeps the suite fast; PKCS#1 v1.5
    /// with SHA-1 needs only 368+ bits.
    fn test_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 512).expect("keygen")
    }

    /// Spotnet-encode base64: strip padding, `/`→`-s`, `+`→`-p`.
    fn spot_b64_encode(data: &[u8]) -> String {
        b64_encode(data)
            .trim_end_matches('=')
            .replace('/', "-s")
            .replace('+', "-p")
    }

    struct TestSpot {
        from: String,
        msgid: String,
        title: String,
        modulus: Vec<u8>,
        header_sig: Vec<u8>,
    }

    /// Build a fully signed spot: header record, PKCS#1 v1.5/SHA-1 header
    /// signature in the LAST header field, and a hashcash-mined message-id
    /// (16 bits - fast).
    fn make_spot(key: &RsaPrivateKey, title: &str, key_id: u8, mine: bool) -> TestSpot {
        let poster = "TestPoster";
        let modulus = RsaPublicKey::from(key).n().to_bytes_be();
        // [cat][keyid][subcats].[size].[random].[date].[custom-id].[custom-value]
        let signed_part = format!("1{key_id}a09b04.1048576.31337.1700000000.0.0");
        let mut h = Sha1::new();
        h.update(title.as_bytes());
        h.update(signed_part.as_bytes());
        h.update(poster.as_bytes());
        let digest = h.finalize();
        let sig = key.sign(pkcs1v15_sha1(), &digest).expect("sign");
        let from = format!(
            "{poster} <{}.{}@{signed_part}.{}>",
            spot_b64_encode(&modulus),
            spot_b64_encode(b"user-signature-signs-the-msgid"),
            spot_b64_encode(&sig),
        );
        let msgid = if mine {
            // Mine the V2 hashcash: sha1("<...>") starts with 0x0000.
            (0u64..)
                .map(|i| format!("<spot{i}@spot.net>"))
                .find(|m| {
                    let d = Sha1::digest(m.as_bytes());
                    d[0] == 0 && d[1] == 0
                })
                .unwrap()
        } else {
            "<unmined@spot.net>".to_string()
        };
        TestSpot {
            from,
            msgid,
            title: title.to_string(),
            modulus,
            header_sig: sig,
        }
    }

    #[test]
    fn parse_verify_spotter_roundtrip() {
        let key = test_key();
        let spot = make_spot(&key, "Test Title", 7, true);

        let h = parse_spot_from(&spot.from).expect("parse");
        assert_eq!(h.poster, "TestPoster");
        // Wire digit 1, stored 0-based (spotweb parity).
        assert_eq!(h.category, 0);
        assert_eq!(h.key_id, 7);
        assert_eq!(h.subcats, vec!["a09", "b04"]);
        assert_eq!(h.size, 1_048_576);
        assert_eq!(h.date, 1_700_000_000);
        assert_eq!(h.modulus, spot.modulus);

        let v = verify_spot(&h, &spot.title, &spot.msgid);
        assert!(v.signature_ok && v.hashcash_ok);
        assert_eq!(v.key_source, Some(SpotKeySource::SelfSigned));

        // Tampered title → signature fails.
        let v = verify_spot(&h, "Evil Title", &spot.msgid);
        assert!(!v.signature_ok);
        assert_eq!(v.key_source, None);

        // The signature the OLD code checked - the user-part field before
        // the '@' - must not be mistaken for the header signature.
        let swapped = spot.from.replace(
            &format!(".{}>", spot_b64_encode(&spot.header_sig)),
            &format!(".{}>", spot_b64_encode(b"not-the-signature")),
        );
        let h_swapped = parse_spot_from(&swapped).unwrap();
        assert!(!verify_spot(&h_swapped, &spot.title, &spot.msgid).signature_ok);

        // A subject that carries a `| tag` suffix verifies on the title
        // rule that keeps only the part before the first '|'.
        let tagged = make_spot(&key, "Tagged Title", 7, true);
        let h_tag = parse_spot_from(&tagged.from).unwrap();
        let v_tag = verify_spot(&h_tag, "Tagged Title | NLsub", &tagged.msgid);
        assert!(v_tag.signature_ok);
        // And the title it reports is the signed one, so the tag does not
        // get stored as part of it (see `stored_title_is_the_signed_one`).
        assert_eq!(v_tag.title.as_deref(), Some("Tagged Title"));

        // Unmined message-id → warning flag only, signature still fine.
        let unmined = make_spot(&key, "Test Title", 7, false);
        let h2 = parse_spot_from(&unmined.from).unwrap();
        let v = verify_spot(&h2, &unmined.title, &unmined.msgid);
        assert!(v.signature_ok && !v.hashcash_ok);

        // A key-id with no master key falls back to the record's own
        // modulus, which makes the hashcash apply just as it does for 7.
        let k1 = make_spot(&key, "Test Title", 1, false);
        let h3 = parse_spot_from(&k1.from).unwrap();
        let v = verify_spot(&h3, &k1.title, &k1.msgid);
        assert!(v.signature_ok && !v.hashcash_ok);
        assert_eq!(v.key_source, Some(SpotKeySource::SelfSigned));

        // Spotter id is deterministic and stripped of /+=.
        let sid = spotter_id(&spot.modulus);
        assert!(!sid.is_empty());
        assert!(sid.chars().all(|c| !matches!(c, '/' | '+' | '=')));
        assert_eq!(sid, spotter_id(&spot.modulus));
    }

    #[test]
    fn spotter_id_known_value() {
        // crc32("abc") = 0x352441c2 → base64(35 24 41 c2) = "NSRBwg==".
        assert_eq!(spotter_id(b"abc"), "NSRBwg");
    }

    #[test]
    fn malformed_from_headers_never_panic() {
        let key = test_key();
        let good = make_spot(&key, "T", 7, false).from;
        // `SIG` stands in for the trailing header signature: decodable
        // base64, so every case below fails on the field it is named for
        // and not on the signature check that guards them all.
        const SIG: &str = "QUJDQUJD";
        let cases: Vec<String> = vec![
            String::new(),
            "no brackets at all".into(),
            "nick <>".into(),
            "nick <mod.sig>".into(),                           // no @
            format!("nick <QUJD.QUJD@x7a09.1.2.3.4.{SIG}>"),   // non-digit category
            format!("nick <QUJD.QUJD@1xa09.1.2.3.4.{SIG}>"),   // non-digit key-id
            format!("nick <QUJD.QUJD@1709x.1.2.3.4.{SIG}>"),   // garbage subcats
            format!("nick <QUJD.QUJD@17a09.NaN.2.3.4.{SIG}>"), // bad size
            format!("nick <QUJD.QUJD@17a09.1.2.NaN.4.{SIG}>"), // bad date
            format!("nick <QUJD.QUJD@17a09.1.{SIG}>"),         // truncated fields
            "nick <QUJD.QUJD@17a09.1.2.3.4.5.6>".into(),       // undecodable signature
            "nick <QUJD.QUJD@17a09.1.2.3.4.5.>".into(),        // empty signature
            good[..good.len() / 2].to_string(),                // truncated record
            format!("nick <{}.QUJD@17a09.1.2.3.4.{SIG}>", "QUJD".repeat(3000)), // >8KB
            format!("nick > reversed < QUJD.QUJD@17a09.1.2.3.4.{SIG}"),
        ];
        for c in &cases {
            assert!(
                parse_spot_from(c).is_none(),
                "should reject: {}",
                &c[..c.len().min(80)]
            );
        }
        // And the good one still parses (guard against over-tightening),
        // including with trailing comment junk after the closing bracket.
        assert!(parse_spot_from(&good).is_some());
        assert!(parse_spot_from(&format!("{good} (comment)")).is_some());

        // A server-signed record puts a random number where the modulus
        // goes and has no user-signature field at all. It must still parse:
        // a master key, not the From, is what verifies it.
        let server_signed = parse_spot_from("nick <10@12a01.1.10.1776489039.c41.mod.QUJDQUJD>")
            .expect("server-signed record parses");
        assert!(server_signed.modulus.len() < MIN_MODULUS_BYTES);
        assert!(server_signed.user_signature.is_empty());
        assert_eq!(server_signed.key_id, 2);
        assert_eq!(server_signed.signed_part, "12a01.1.10.1776489039.c41.mod");
        assert!(
            candidate_keys(&server_signed)
                .iter()
                .all(|(s, _)| *s == SpotKeySource::Master)
        );
    }

    /// Real captured `free.pt` OVER lines, one per way a spot can verify.
    /// Every one of these failed before the header-signature fix (the code
    /// checked the user-part field, which signs the message-id, not the
    /// header), so this is the regression that matters: nothing synthetic
    /// can catch a "verifies the right bytes against the wrong signature"
    /// bug, because a synthetic spot is signed by the same code that
    /// checks it.
    #[test]
    fn live_spot_headers_verify() {
        const FIXTURE: &[u8] = include_bytes!("../testdata/spot/free.pt.over.tsv");
        // (subject fragment, key source, hashcash, category, key-id)
        let want: [(&str, Option<SpotKeySource>, bool, u8, u8); 9] = [
            // Key-id 2 "personal dispose", self-signed, latin-1 subject.
            ("Dansons", Some(SpotKeySource::SelfSigned), true, 0, 2),
            // Key-id 2 "personal dispose", self-signed, plain ASCII.
            (
                "Master of the Universe",
                Some(SpotKeySource::SelfSigned),
                true,
                0,
                2,
            ),
            // Key-id 2 against the distributed master key, latin-1 subject.
            ("pendant la", Some(SpotKeySource::Master), true, 0, 2),
            // Key-id 2 against the distributed master key, plain ASCII.
            ("NCIS", Some(SpotKeySource::Master), true, 0, 2),
            // Self-signed key-id 7, latin-1 subject.
            ("skind (2012)", Some(SpotKeySource::SelfSigned), true, 0, 7),
            // Self-signed key-id 7, non-ASCII subject that really is UTF-8.
            (
                "Oscar Peterson",
                Some(SpotKeySource::SelfSigned),
                true,
                1,
                7,
            ),
            // Self-signed key-id 7, plain ASCII.
            ("Garmin tools", Some(SpotKeySource::SelfSigned), true, 3, 7),
            // Self-signed key-id 7 signed over the WHOLE subject, '|' and
            // all - the rule that splits on '|' misses this one.
            (
                "Testspot 4 | ClubNZB",
                Some(SpotKeySource::SelfSigned),
                true,
                0,
                7,
            ),
            // Server-signed: the From carries a random number, not a key,
            // so there is nothing to verify against. Parses, never valid.
            ("HPI Seizoen.02", None, true, 0, 7),
        ];

        let entries: Vec<_> = FIXTURE
            .split(|&b| b == b'\n')
            .filter(|l| !l.starts_with(b"#"))
            .filter_map(crate::nntp::parse_over_line)
            .collect();
        assert_eq!(entries.len(), want.len(), "fixture/expectation drift");

        for (e, (fragment, source, hashcash, category, key_id)) in entries.iter().zip(want) {
            assert!(
                e.subject.contains(fragment),
                "fixture order changed: {:?} is not {fragment}",
                e.subject
            );
            let h = parse_spot_from(&e.from).unwrap_or_else(|| panic!("parse {fragment}"));
            assert_eq!(h.category, category, "category of {fragment}");
            assert_eq!(h.key_id, key_id, "key-id of {fragment}");
            let v = verify_spot(&h, &e.subject, &e.message_id);
            assert_eq!(v.key_source, source, "key source of {fragment}");
            assert_eq!(v.signature_ok, source.is_some(), "signature of {fragment}");
            assert_eq!(v.hashcash_ok, hashcash, "hashcash of {fragment}");
            // A one-byte change anywhere in the signed bytes must break it.
            let mut tampered = h.clone();
            tampered.signed_part.push('x');
            assert!(!verify_spot(&tampered, &e.subject, &e.message_id).signature_ok);
            assert!(!verify_spot(&h, &format!("x{}", e.subject), &e.message_id).signature_ok);
        }
    }

    /// Moderation records verify exactly like content does - that is the
    /// point of signing them - so verification cannot be what separates
    /// them. Against the same captured fixture: its four `DISPOSE` rows
    /// are moderation (both key-id 2 branches, self-signed AND master
    /// key), and its five real spots are not.
    /// The stored title is the one the signature covered, which is not
    /// always the subject. Both live conventions are in the fixture:
    /// "Testspot 4 | ClubNZB" is signed whole, so the tag IS the title;
    /// every other row is signed up to the `|`, so a trailing tag is not.
    #[test]
    fn stored_title_is_the_signed_one() {
        const FIXTURE: &[u8] = include_bytes!("../testdata/spot/free.pt.over.tsv");
        let entries: Vec<_> = FIXTURE
            .split(|&b| b == b'\n')
            .filter(|l| !l.starts_with(b"#"))
            .filter_map(crate::nntp::parse_over_line)
            .collect();
        let (mut tagged_kept, mut tagged_cut) = (0, 0);
        for e in &entries {
            let h = parse_spot_from(&e.from).unwrap();
            let v = verify_spot(&h, &e.subject, &e.message_id);
            let Some(title) = v.title else {
                assert!(!v.signature_ok, "a verified spot must report its title");
                continue;
            };
            // Whatever it reports came out of the subject, never invented.
            assert!(
                e.subject.contains(title.as_str()),
                "reported title {title:?} is not part of {:?}",
                e.subject
            );
            if !e.subject.contains('|') {
                assert_eq!(title, e.subject.trim(), "an untagged subject IS the title");
            } else if title == e.subject {
                tagged_kept += 1;
            } else {
                tagged_cut += 1;
                assert!(
                    !title.contains('|'),
                    "a cut title keeps nothing after the bar"
                );
            }
        }
        // "Testspot 4 | ClubNZB" is the fixture's one barred subject, and
        // it is signed whole - so the tag IS its title and must survive.
        // The other rule (sign up to the bar, tag appended after) has no
        // live example here; `parse_verify_spotter_roundtrip` covers it
        // with a spot signed on the cut title, and it is the majority
        // rule in the wild (17,114 of 21,384 verified in the sample the
        // verifier was measured on).
        assert_eq!(
            (tagged_kept, tagged_cut),
            (1, 0),
            "the barred row signs whole"
        );
    }

    #[test]
    fn moderation_records_are_not_content() {
        const FIXTURE: &[u8] = include_bytes!("../testdata/spot/free.pt.over.tsv");
        let entries: Vec<_> = FIXTURE
            .split(|&b| b == b'\n')
            .filter(|l| !l.starts_with(b"#"))
            .filter_map(crate::nntp::parse_over_line)
            .collect();
        let flagged: Vec<bool> = entries.iter().map(|e| is_moderation(&e.subject)).collect();
        assert_eq!(
            flagged,
            vec![true, true, true, true, false, false, false, false, false],
            "the four DISPOSE rows are moderation, the five spots are not"
        );
        // And they DO verify - so anything that stored "verified" rows
        // without this check stored them.
        for e in entries.iter().take(4) {
            let h = parse_spot_from(&e.from).unwrap();
            assert!(verify_spot(&h, &e.subject, &e.message_id).signature_ok);
        }
        // Not a substring match: a release whose title merely contains the
        // word must not be swallowed.
        assert!(!is_moderation("How To DISPOSE Of A Body 2026 1080p"));
        assert!(!is_moderation("DISPOSED.2026.1080p"));
    }

    #[test]
    fn special_zip_roundtrip() {
        // Cover every escaped byte class plus plain data.
        let mut data = b"<nzb>\r\n\0 = test</nzb>".to_vec();
        data.extend((0u8..=255).cycle().take(4096));
        let packed = special_zip(&data);
        assert!(
            !packed.iter().any(|&b| matches!(b, 0 | b'\r' | b'\n')),
            "armor must not contain NUL/CR/LF"
        );
        assert_eq!(unspecial_zip(&packed).unwrap(), data);

        // zlib-wrapped variant is accepted too.
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&data).unwrap();
        let zlib = enc.finish().unwrap();
        let escaped: Vec<u8> = zlib
            .iter()
            .flat_map(|&b| match b {
                0 => b"=A".to_vec(),
                b'\r' => b"=B".to_vec(),
                b'\n' => b"=C".to_vec(),
                b'=' => b"=D".to_vec(),
                other => vec![other],
            })
            .collect();
        assert_eq!(unspecial_zip(&escaped).unwrap(), data);

        // Garbage doesn't inflate.
        assert!(unspecial_zip(b"definitely not deflate").is_none());
        assert!(unspecial_zip(b"").is_none());
    }

    /// Char-boundary hardening on attacker-controlled text: neither the
    /// entity scanner (fixed 8-byte lookahead) nor the X-XML header
    /// prefix check (fixed 6-byte slice) may panic on multi-byte chars
    /// straddling those offsets.
    #[test]
    fn non_ascii_never_panics_boundary_slices() {
        // '€' (3 bytes) straddling the 8-byte entity lookahead boundary:
        // tail = "&xxxxx€y;b" puts byte 8 mid-char - the old &str slice
        // panicked here.
        assert_eq!(xml_unescape("a&xxxxx€y;b"), "a&xxxxx€y;b");
        assert_eq!(xml_unescape("&€;"), "&€;");
        // Header line whose byte 6 splits the '€' - and a valid one.
        let raw = b"abcd\xe2\x82\xacf: nope\r\nX-XML: <a/>\r\n";
        assert_eq!(xml_from_headers(raw), "<a/>");
    }

    #[test]
    fn spot_xml_parsing() {
        let xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Spotnet><Posting>\
            <Key>7</Key><Created>1700000000</Created><Poster>Nick</Poster>\
            <Title>Great &amp; Small &#33;</Title>\
            <Description>Multi&lt;br&gt;line</Description>\
            <Image Width=\"10\" Height=\"10\"><Segment>img@ftd</Segment></Image>\
            <Size>12345</Size>\
            <Category>01<Sub>01a09</Sub><Sub>01b04</Sub></Category>\
            <NZB><Segment>seg1@ftd</Segment><Segment>seg2@ftd</Segment></NZB>\
            </Posting></Spotnet>";
        let sx = parse_spot_xml(xml).unwrap();
        assert_eq!(sx.title, "Great & Small !");
        assert_eq!(sx.description, "Multi<br>line");
        assert_eq!(sx.poster, "Nick");
        assert_eq!(sx.category, 1);
        assert_eq!(sx.subcats, vec!["01a09", "01b04"]);
        assert_eq!(sx.size, 12345);
        // The <Image> segment must NOT leak into the NZB segment list.
        assert_eq!(sx.nzb_segments, vec!["seg1@ftd", "seg2@ftd"]);

        // Broken XML tolerated as long as a Title exists.
        let broken = "<Title>Still here</Title><NZB><Segment>a@b</Segment>";
        let sx = parse_spot_xml(broken).unwrap();
        assert_eq!(sx.title, "Still here");
        assert!(sx.nzb_segments.is_empty()); // unclosed NZB scope → none

        // No title → None; oversized → None.
        assert!(parse_spot_xml("<NZB></NZB>").is_none());
        let big = format!("<Title>x</Title>{}", "y".repeat(MAX_SPOT_XML));
        assert!(parse_spot_xml(&big).is_none());
    }

    /// spotweb writes titles either entity-escaped or CDATA-wrapped, and
    /// the CDATA form used to reach the wall as markup: 54 live cards
    /// were literally named `<![CDATA[…]]>`, and the deeper the feed is
    /// read the larger that share gets (the 2011 depth sample is CDATA
    /// throughout). CDATA content is LITERAL - entities inside it are
    /// text, not escapes.
    #[test]
    fn cdata_titles_are_unwrapped_not_stored_as_markup() {
        let sx =
            parse_spot_xml("<Title><![CDATA[Shark Night (2011) R5 LiNE XviD - MiSTERE]]></Title>")
                .unwrap();
        assert_eq!(sx.title, "Shark Night (2011) R5 LiNE XviD - MiSTERE");

        // Literal, so `&amp;` inside CDATA stays five characters, and a
        // `<` needs no escape.
        let sx = parse_spot_xml("<Title><![CDATA[A &amp; B <raw>]]></Title>").unwrap();
        assert_eq!(sx.title, "A &amp; B <raw>");

        // Mixed content: escaped outside, literal inside.
        let sx = parse_spot_xml("<Title>Tom &amp; <![CDATA[Jerry & Co]]> 1080p</Title>").unwrap();
        assert_eq!(sx.title, "Tom & Jerry & Co 1080p");

        // Description and Poster take the same path.
        let sx = parse_spot_xml(
            "<Title>t</Title><Description><![CDATA[line<br>two]]></Description>\
             <Poster><![CDATA[Nick <nick@x>]]></Poster>",
        )
        .unwrap();
        assert_eq!(sx.description, "line<br>two");
        assert_eq!(sx.poster, "Nick <nick@x>");

        // A close tag written INSIDE CDATA is text. Without the
        // CDATA-aware close scan this truncates to "cut here", which is
        // a free title-truncation primitive on attacker-supplied XML.
        let sx = parse_spot_xml("<Title><![CDATA[cut here</Title>and here]]></Title>").unwrap();
        assert_eq!(sx.title, "cut here</Title>and here");

        // Unterminated CDATA is broken markup, not the truncation
        // attack, and refusing the element there would throw away a
        // spot whose NZB segments parse fine. It degrades to the plain
        // close-tag scan and the rest of the document still reads.
        let sx = parse_spot_xml("<Title><![CDATA[no end</Title><Size>7</Size>").unwrap();
        assert_eq!(sx.title, "no end");
        assert_eq!(sx.size, 7);
    }

    /// The chunk walk runs DEEPEST LAST, because the low-water mark is
    /// persisted per chunk and the surviving write must be the deepest
    /// article read.
    ///
    /// Found on the wire, not in review: a live pass with deepen =
    /// 20,000 left the mark 10,000 articles above the floor it had
    /// actually reached, so the next pass would re-read that band - and
    /// with `deepen <= OVER_CHUNK` the walk would never advance at all.
    /// The multi-chunk case is what breaks, and the single-chunk test
    /// below cannot see it.
    #[test]
    fn the_deepening_walk_persists_the_deepest_article_last() {
        // Two and a half chunks below the floor.
        let chunks = deepen_chunks(100_000, 75_000);
        assert_eq!(
            chunks,
            vec![(90_000, 99_999), (80_000, 89_999), (75_000, 79_999),]
        );
        // Every article in the slice, once, and the LAST mark written
        // is the bottom of the slice.
        let covered: u64 = chunks.iter().map(|(lo, hi)| hi - lo + 1).sum();
        assert_eq!(covered, 25_000);
        assert_eq!(chunks.last().unwrap().0, 75_000);
        for w in chunks.windows(2) {
            assert!(w[1].0 < w[0].0, "marks must descend: {w:?}");
            assert_eq!(w[1].1 + 1, w[0].0, "no gap between chunks");
        }
        // Sub-chunk and empty slices.
        assert_eq!(deepen_chunks(1_000, 999), vec![(999, 999)]);
        assert!(deepen_chunks(500, 500).is_empty());
    }

    /// The deepening leg walks BELOW the first backfill's floor, one
    /// bounded slice a pass, and stops at the group's first article.
    ///
    /// Without it the spot catalogue is frozen at whatever the first
    /// backfill reached plus the live trickle: on the live index, 26,552
    /// spots over 141 days against a free.pt holding 4.43 M articles
    /// back to 2011 - all verified, and all still fetchable when probed
    /// at five depths.
    #[tokio::test]
    async fn deepening_walks_below_the_backfill_floor_and_stops_at_the_start() {
        let key = test_key();
        // Six spots at articles 1..=6, so GROUP reports low=1 high=6.
        // Distinct titles keep the signatures distinct; distinct
        // message-ids keep them distinct rows (hashcash is unmined
        // here, which warns but stores - this is testing the walk).
        let overview: Vec<OverRow> = (1..=6u64)
            .map(|n| {
                let title = format!("Deep Release {n}");
                let s = make_spot(&key, &title, 7, false);
                OverRow {
                    number: n,
                    subject: title,
                    from: s.from,
                    message_id: format!("<deep{n}@spot.net>"),
                    bytes: 500,
                }
            })
            .collect();
        let srv =
            MockServer::start_full(HashMap::new(), HashMap::new(), overview, Chaos::default())
                .await;
        let (mut conn, _) = Connection::connect(&srv.server_config()).await.unwrap();
        let dir = std::env::temp_dir().join(format!("nzbfast-spotdeep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Forward only, backfill 2: articles 4..6, and nothing below.
        let sum = scan_spots(&mut conn, &mut ix, "free.pt", "mock", 2, 0)
            .await
            .unwrap();
        assert_eq!((sum.scanned, sum.new, sum.deepened), (3, 3, 0));

        // First deepening pass: 2 articles of history (2..3). The
        // forward mark is untouched, so nothing is re-read at the tip.
        let sum = scan_spots(&mut conn, &mut ix, "free.pt", "mock", 2, 2)
            .await
            .unwrap();
        assert_eq!((sum.scanned, sum.new, sum.deepened), (2, 2, 2));
        assert_eq!(sum.depth_left, 1, "article 1 is still below the floor");

        // Second: the last article, and the walk reports itself done.
        let sum = scan_spots(&mut conn, &mut ix, "free.pt", "mock", 2, 2)
            .await
            .unwrap();
        assert_eq!((sum.new, sum.deepened, sum.depth_left), (1, 1, 0));
        assert_eq!(ix.spot_stats().unwrap(), 6, "the whole group is indexed");

        // Third: exhausted. A deepen pass over a fully scanned group
        // costs one GROUP command and reads nothing, forever.
        let sum = scan_spots(&mut conn, &mut ix, "free.pt", "mock", 2, 2)
            .await
            .unwrap();
        assert_eq!((sum.scanned, sum.deepened), (0, 0));

        conn.quit().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Full pipeline against the mock NNTP server: OVER scan → SQLite →
    /// search → HEAD (X-XML) → payload BODYs → byte-identical NZB.
    #[tokio::test]
    async fn spot_e2e_scan_search_get() {
        let key = test_key();
        let title = "Ubuntu 26.04 LTS amd64 DVD";
        let spot = make_spot(&key, title, 7, true);

        // The NZB payload: armored deflate split across two ftd articles.
        let nzb_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
            <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file \
            poster=\"p@x\" date=\"0\" subject=\"&quot;ubuntu.iso&quot; yEnc \
            (1/1)\">\n    <groups><group>alt.binaries.ftd</group></groups>\n\
            \x20   <segments>\n      <segment bytes=\"1000\" number=\"1\">\
            data1@x</segment>\n    </segments>\n  </file>\n</nzb>\n";
        let packed = special_zip(nzb_xml.as_bytes());
        let cut = packed.len() / 2; // safe: unescape happens after re-concat
        let mut articles = HashMap::new();
        let seg_ids = ["nzbseg1@ftd", "nzbseg2@ftd"];
        for (id, chunk) in seg_ids.iter().zip([&packed[..cut], &packed[cut..]]) {
            let mut body = chunk.to_vec();
            body.extend_from_slice(b"\r\n");
            articles.insert(format!("<{id}>"), body);
        }

        // The spot article: headers only, XML split across X-XML lines.
        let spot_xml = format!(
            "<Spotnet><Posting><Title>{title}</Title><Size>1048576</Size>\
             <Category>01<Sub>01a09</Sub></Category><NZB>\
             <Segment>{}</Segment><Segment>{}</Segment></NZB>\
             </Posting></Spotnet>",
            seg_ids[0], seg_ids[1]
        );
        let mut head = format!("From: {}\r\nSubject: {title}\r\n", spot.from);
        for chunk in spot_xml.as_bytes().chunks(60) {
            head.push_str(&format!(
                "X-XML: {}\r\n",
                std::str::from_utf8(chunk).unwrap()
            ));
        }
        let headers = HashMap::from([(spot.msgid.clone(), head.into_bytes())]);
        let overview = vec![OverRow {
            number: 1,
            subject: title.to_string(),
            from: spot.from.clone(),
            message_id: spot.msgid.clone(),
            bytes: 500,
        }];

        let srv = MockServer::start_full(articles, headers, overview, Chaos::default()).await;
        let (mut conn, _) = Connection::connect(&srv.server_config()).await.unwrap();

        let dir = std::env::temp_dir().join(format!("nzbfast-spot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Scan: one header, one valid spot.
        let sum = scan_spots(&mut conn, &mut ix, "free.pt", "mock", 1000, 0)
            .await
            .unwrap();
        assert_eq!((sum.scanned, sum.valid, sum.invalid, sum.new), (1, 1, 0, 1));
        assert_eq!(sum.hashcash_warn, 0);
        // Re-scan is a no-op (high-water mark).
        let sum2 = scan_spots(&mut conn, &mut ix, "free.pt", "mock", 1000, 0)
            .await
            .unwrap();
        assert_eq!(sum2.scanned, 0);

        // Search.
        let hits = ix.spot_search("ubuntu", 10).unwrap();
        assert_eq!(hits.len(), 1);
        let s = &hits[0];
        assert_eq!(s.title, title);
        assert_eq!(s.category, 0); // wire digit 1, stored 0-based

        assert_eq!(s.subcats, "a09,b04");
        assert_eq!(s.size, 1_048_576);
        assert!(s.verified && s.hashcash_ok);
        assert_eq!(s.spotter_id, spotter_id(&spot.modulus));

        // Get: byte-identical NZB out the other end.
        let (sx, nzb) = fetch_spot_nzb(&mut conn, &s.msgid).await.unwrap();
        assert_eq!(sx.nzb_segments, seg_ids);
        assert_eq!(nzb, nzb_xml.as_bytes());

        // Cache the release payload ids (first segment per file,
        // bracketed) back into the DB - NOT sx.nzb_segments: those are
        // the ftd deflate-chunk ids, which never appear in any content
        // group and so could never join a header-scanned index.
        let payload = payload_msgids(&nzb);
        assert_eq!(payload, vec!["<data1@x>".to_string()]);
        ix.set_spot_nzb(&s.msgid, &payload).unwrap();
        let again = ix.spot_by_msgid(&s.msgid).unwrap().unwrap();
        assert_eq!(again.nzb_msgids, payload);

        conn.quit().await;
        // The index must close before its directory goes: SQLite opens
        // without FILE_SHARE_DELETE, so Windows refuses to remove a
        // directory that still holds an open connection (os error 32) where
        // unix unlinks it quite happily.
        drop(ix);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
