//! §26c A5: the compact on-disk encoding of a file's segment list.
//!
//! `files.segments` was a JSON array of `[number, "<message-id>",
//! bytes]` triples, and on a 26 GB / 13.2 M-release index it was
//! 14.27 GB - 55% of the file. Every byte of it is paid for again by
//! every row read that passes it, and by the page cache that holds it.
//!
//! This module is the replacement: one self-describing byte string per
//! row that every reader accepts BESIDE the JSON it replaces. A value
//! whose first byte is `[` is JSON; one whose first byte is [`MAGIC`]
//! is this format. Nothing ever has to know which a row holds, so the
//! migration from one to the other can run row by row, in slices, for
//! as long as it takes, and a test fixture written as a JSON literal
//! keeps working forever.
//!
//! # What the bytes are
//!
//! Measured on 20,000 rows sampled at random from the real index (22 Aug
//! 2026, 340,533 segments): JSON is 62 bytes per segment. The ids are
//! not the long-common-prefix shape the TODO assumed - the index is
//! dominated by nyuu-style random mixed-case ids (`<pUypfBR_TuNFN...
//! @NrSNlZbb.NvH>`) with ngPost's random hex a minority - so the gain is
//! in packing the random part at its own entropy, not in sharing it:
//!
//! - 2.04x with the per-segment fields folded away (sequential number,
//!   repeated byte count), the per-file prefix and suffix stored once,
//!   and the random middle nibble-packed when hex, 6-bit packed when it
//!   is `[0-9A-Za-z_-]`.
//! - zstd-3 over the JSON is 2.24x and over this format 2.58x; the
//!   extra comes from nyuu's upper/lower case ALTERNATION, which a 6-bit
//!   pack cannot see. It needs a C dependency this tree has already
//!   declined once (the 7z codec census) and a decode on every NZB build
//!   and every claims-replay row, for 1 GB of a 26 GB file. Not taken.
//!
//! A random 32-character base-62 id carries 23.8 bytes of entropy; this
//! format stores it in 24 plus 3 bytes of framing. That is the floor for
//! anything that does not model the generator.
//!
//! Layout:
//!
//! ```text
//! MAGIC (0x01)
//! varint n                      segment count
//! varint plen, plen bytes       longest common prefix of the ids
//! varint slen, slen bytes       longest common suffix (never overlapping the prefix)
//! n times:
//!   u8 flags                    bit0 SAME_BYTES: bytes == previous segment's
//!                               bit1 NEXT_NUM:   number == previous + 1 (previous starts at 0)
//!   [varint zigzag(number - previous - 1)]   when NEXT_NUM is clear
//!   [varint bytes]                           when SAME_BYTES is clear
//!   varint mlen                 byte length of the id between prefix and suffix
//!   tokens, summing to mlen:    u8 tag = kind << 6 | len (1..=63)
//!                               kind 0 raw:  len bytes verbatim
//!                               kind 1 hex:  len even, len/2 bytes
//!                               kind 2 b64:  ceil(len*6/8) bytes, alphabet [0-9A-Za-z-_]
//! ```
//!
//! Lengths are BYTES throughout, never chars. The prefix and suffix are
//! cut at byte level and may split a multi-byte UTF-8 sequence; they are
//! only ever concatenated back together, so the result is the original
//! byte string and `String::from_utf8` on it cannot fail for input that
//! was a `String`. Decoding is lossy only for a value that was never
//! produced by [`encode`]: it returns `None` rather than panicking,
//! and the SQL-side readers treat that as an empty list exactly as the
//! JSON readers treated unparseable JSON.
//!
//! The two SQL functions [`register`] installs (`seg_count`,
//! `seg_first`) are what replaced `json_array_length(segments)` and
//! `json_extract(segments, '$[0][1]')` in the statements that used to
//! reach into the JSON from SQL. They accept both forms too, so a
//! statement reads correctly across a half-migrated table.

use rusqlite::Connection;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};

/// One segment as every index site has always carried it:
/// `(number, message-id, bytes)`.
pub type Seg = (u32, String, u64);

/// First byte of an encoded value. JSON begins with `[` (0x5B), so the
/// two are told apart by one byte and no other value can be mistaken
/// for either - an empty string is neither and decodes as empty.
pub const MAGIC: u8 = 0x01;

const SAME_BYTES: u8 = 1;
const NEXT_NUM: u8 = 2;

const KIND_RAW: u8 = 0;
const KIND_HEX: u8 = 1;
const KIND_B64: u8 = 2;
/// Bound the amount of stale-row decode work between foreground-work checks.
const GUARDED_PARSE_CHUNK: usize = 256;
/// Longest token: the tag keeps its length in six bits.
const TOKEN_MAX: usize = 63;
/// A hex run shorter than this is packed 6-bit with its neighbours
/// rather than starting its own token: the saving on 6 chars (3 bytes
/// against 5) does not pay for the extra tag.
const HEX_MIN: usize = 8;

const B64_ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

fn b64_index(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'Z' => Some(c - b'A' + 10),
        b'a'..=b'z' => Some(c - b'a' + 36),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    fn done(&self) -> bool {
        self.at == self.buf.len()
    }
}

/// Longest common prefix length of `a` and `b`, in bytes.
fn lcp(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// Longest common suffix length of `a` and `b`, in bytes.
fn lcs(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

/// Append the tokens for one id middle.
fn put_middle(out: &mut Vec<u8>, mid: &[u8]) {
    let mut i = 0;
    while i < mid.len() {
        if b64_index(mid[i]).is_some() {
            // A run of packable characters; hex sub-runs of HEX_MIN or
            // more get the denser pack, the rest go 6-bit.
            let mut j = i;
            while j < mid.len() && b64_index(mid[j]).is_some() {
                j += 1;
            }
            let run = &mid[i..j];
            let mut k = 0;
            while k < run.len() {
                let mut h = k;
                while h < run.len() && hex_val(run[h]).is_some() {
                    h += 1;
                }
                if h - k >= HEX_MIN {
                    let mut len = h - k;
                    if len % 2 == 1 {
                        len -= 1;
                    }
                    put_tokens(out, KIND_HEX, &run[k..k + len]);
                    k += len;
                    continue;
                }
                // 6-bit until the next hex run worth its own token.
                let mut l = k;
                while l < run.len() {
                    if hex_val(run[l]).is_some() {
                        let mut m = l;
                        while m < run.len() && hex_val(run[m]).is_some() {
                            m += 1;
                        }
                        if m - l >= HEX_MIN {
                            break;
                        }
                        l = m;
                    } else {
                        l += 1;
                    }
                }
                put_tokens(out, KIND_B64, &run[k..l]);
                k = l;
            }
            i = j;
        } else {
            let mut j = i;
            while j < mid.len() && b64_index(mid[j]).is_none() {
                j += 1;
            }
            put_tokens(out, KIND_RAW, &mid[i..j]);
            i = j;
        }
    }
}

/// One or more tokens of `kind` covering `s`, each at most TOKEN_MAX
/// characters (and an even count for hex).
fn put_tokens(out: &mut Vec<u8>, kind: u8, s: &[u8]) {
    let step = if kind == KIND_HEX {
        TOKEN_MAX - 1
    } else {
        TOKEN_MAX
    };
    for chunk in s.chunks(step) {
        out.push((kind << 6) | chunk.len() as u8);
        match kind {
            KIND_HEX => {
                for pair in chunk.chunks(2) {
                    out.push((hex_val(pair[0]).unwrap_or(0) << 4) | hex_val(pair[1]).unwrap_or(0));
                }
            }
            KIND_B64 => {
                let mut acc: u32 = 0;
                let mut nb = 0;
                for &c in chunk {
                    acc = (acc << 6) | u32::from(b64_index(c).unwrap_or(0));
                    nb += 6;
                    while nb >= 8 {
                        nb -= 8;
                        out.push(((acc >> nb) & 0xff) as u8);
                    }
                }
                if nb > 0 {
                    out.push(((acc << (8 - nb)) & 0xff) as u8);
                }
            }
            _ => out.extend_from_slice(chunk),
        }
    }
}

/// Read one id middle of `mlen` bytes into `into`.
fn get_middle_guarded(
    r: &mut Reader<'_>,
    mlen: usize,
    into: &mut Vec<u8>,
    keep_going: &mut dyn FnMut() -> bool,
) -> Option<()> {
    let mut left = mlen;
    let mut tokens = 0usize;
    while left > 0 {
        if tokens > 0 && tokens.is_multiple_of(GUARDED_PARSE_CHUNK) && !keep_going() {
            return None;
        }
        let tag = r.u8()?;
        let kind = tag >> 6;
        let len = (tag & 0x3f) as usize;
        if len == 0 || len > left {
            return None;
        }
        match kind {
            KIND_RAW => into.extend_from_slice(r.bytes(len)?),
            KIND_HEX => {
                if len % 2 == 1 {
                    return None;
                }
                for &b in r.bytes(len / 2)? {
                    into.push(b"0123456789abcdef"[(b >> 4) as usize]);
                    into.push(b"0123456789abcdef"[(b & 0xf) as usize]);
                }
            }
            KIND_B64 => {
                let nbytes = (len * 6).div_ceil(8);
                let packed = r.bytes(nbytes)?;
                let mut acc: u32 = 0;
                let mut nb = 0;
                let mut emitted = 0;
                for &b in packed {
                    acc = (acc << 8) | u32::from(b);
                    nb += 8;
                    while nb >= 6 && emitted < len {
                        nb -= 6;
                        into.push(B64_ALPHABET[((acc >> nb) & 0x3f) as usize]);
                        emitted += 1;
                    }
                }
                if emitted != len {
                    return None;
                }
            }
            _ => return None,
        }
        left -= len;
        tokens += 1;
    }
    Some(())
}

/// Encode a segment list in the order given. Every list round-trips
/// through [`decode`] exactly, whatever the ids contain.
pub fn encode(segs: &[Seg]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + segs.len() * 28);
    out.push(MAGIC);
    put_varint(&mut out, segs.len() as u64);
    let (prefix, suffix): (&[u8], &[u8]) = match segs.first() {
        None => (&[], &[]),
        Some((_, first, _)) => {
            let first = first.as_bytes();
            let mut p = first.len();
            let mut s = first.len();
            for (_, id, _) in &segs[1..] {
                let id = id.as_bytes();
                p = p.min(lcp(first, id));
                s = s.min(lcs(first, id));
            }
            // The prefix wins the overlap: the shortest id must still
            // hold both without them crossing.
            let shortest = segs.iter().map(|(_, id, _)| id.len()).min().unwrap_or(0);
            if p + s > shortest {
                s = shortest - p;
            }
            (&first[..p], &first[first.len() - s..])
        }
    };
    put_varint(&mut out, prefix.len() as u64);
    out.extend_from_slice(prefix);
    put_varint(&mut out, suffix.len() as u64);
    out.extend_from_slice(suffix);
    let mut prev_num: i64 = 0;
    let mut prev_bytes: Option<u64> = None;
    for (num, id, bytes) in segs {
        let num = i64::from(*num);
        let mut flags = 0;
        if prev_bytes == Some(*bytes) {
            flags |= SAME_BYTES;
        }
        if num == prev_num + 1 {
            flags |= NEXT_NUM;
        }
        out.push(flags);
        if flags & NEXT_NUM == 0 {
            put_varint(&mut out, zigzag(num - prev_num - 1));
        }
        if flags & SAME_BYTES == 0 {
            put_varint(&mut out, *bytes);
        }
        let id = id.as_bytes();
        let mid = &id[prefix.len()..id.len() - suffix.len()];
        put_varint(&mut out, mid.len() as u64);
        put_middle(&mut out, mid);
        prev_num = num;
        prev_bytes = Some(*bytes);
    }
    out
}

/// Decode up to `limit` segments of an encoded value. `None` for
/// anything that is not a well-formed encoding, including JSON.
fn decode_prefix_impl_guarded(
    raw: &[u8],
    limit: usize,
    text_limit: usize,
    strict_utf8: bool,
    keep_going: &mut dyn FnMut() -> bool,
) -> Option<Vec<Seg>> {
    let mut r = Reader { buf: raw, at: 0 };
    if r.u8()? != MAGIC {
        return None;
    }
    let n = r.varint()? as usize;
    let plen = r.varint()? as usize;
    let prefix = r.bytes(plen)?;
    let slen = r.varint()? as usize;
    let suffix = r.bytes(slen)?;
    let want = n.min(limit);
    let mut out = Vec::with_capacity(want.min(1 << 16));
    let mut prev_num: i64 = 0;
    let mut prev_bytes: u64 = 0;
    let mut id = Vec::new();
    let mut text_bytes = 0usize;
    for segment_index in 0..want {
        if segment_index.is_multiple_of(GUARDED_PARSE_CHUNK) && !keep_going() {
            return None;
        }
        let flags = r.u8()?;
        let num = if flags & NEXT_NUM != 0 {
            prev_num + 1
        } else {
            prev_num
                .checked_add(unzigzag(r.varint()?))?
                .checked_add(1)?
        };
        let bytes = if flags & SAME_BYTES != 0 {
            prev_bytes
        } else {
            r.varint()?
        };
        let mlen = r.varint()? as usize;
        let id_len = plen.checked_add(mlen)?.checked_add(slen)?;
        let next_text_bytes = text_bytes.checked_add(id_len)?;
        if next_text_bytes > text_limit {
            return None;
        }
        id.clear();
        id.extend_from_slice(prefix);
        get_middle_guarded(&mut r, mlen, &mut id, keep_going)?;
        id.extend_from_slice(suffix);
        let num32 = u32::try_from(num).ok()?;
        let id = if strict_utf8 {
            std::str::from_utf8(&id).ok()?.to_owned()
        } else {
            String::from_utf8_lossy(&id).into_owned()
        };
        text_bytes = next_text_bytes;
        out.push((num32, id, bytes));
        prev_num = num;
        prev_bytes = bytes;
    }
    if want == n && !r.done() {
        return None;
    }
    Some(out)
}

fn decode_prefix_impl(
    raw: &[u8],
    limit: usize,
    text_limit: usize,
    strict_utf8: bool,
) -> Option<Vec<Seg>> {
    decode_prefix_impl_guarded(raw, limit, text_limit, strict_utf8, &mut || true)
}

fn decode_prefix(raw: &[u8], limit: usize) -> Option<Vec<Seg>> {
    decode_prefix_impl(raw, limit, usize::MAX, false)
}

/// Decode a whole encoded value. `None` for anything that is not a
/// well-formed encoding, including JSON - use [`parse`] for a value
/// that may be either.
pub fn decode(raw: &[u8]) -> Option<Vec<Seg>> {
    decode_prefix(raw, usize::MAX)
}

struct CappedSegments<'a> {
    limit: usize,
    text_limit: usize,
    keep_going: &'a mut dyn FnMut() -> bool,
}

impl<'de> serde::de::DeserializeSeed<'de> for CappedSegments<'_> {
    type Value = Vec<Seg>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(CappedSegmentsVisitor {
            limit: self.limit,
            text_limit: self.text_limit,
            keep_going: self.keep_going,
        })
    }
}

struct CappedSegmentsVisitor<'a> {
    limit: usize,
    text_limit: usize,
    keep_going: &'a mut dyn FnMut() -> bool,
}

impl<'de> serde::de::Visitor<'de> for CappedSegmentsVisitor<'_> {
    type Value = Vec<Seg>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded segment array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.limit));
        let mut text_bytes = 0usize;
        loop {
            if out.len().is_multiple_of(GUARDED_PARSE_CHUNK) && !(self.keep_going)() {
                return Err(serde::de::Error::custom("segment parse deferred"));
            }
            let Some(segment) = sequence.next_element()? else {
                break;
            };
            if out.len() == self.limit {
                return Err(serde::de::Error::custom("segment limit exceeded"));
            }
            let segment: Seg = segment;
            text_bytes = text_bytes
                .checked_add(segment.1.len())
                .ok_or_else(|| serde::de::Error::custom("segment text limit exceeded"))?;
            if text_bytes > self.text_limit {
                return Err(serde::de::Error::custom("segment text limit exceeded"));
            }
            out.push(segment);
        }
        Ok(out)
    }
}

/// Outcome of a bounded candidate-row parse that can yield to foreground work.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum GuardedParse {
    Complete(Vec<Seg>),
    Deferred,
    Invalid,
}

/// Parse either stored representation without ever retaining more than
/// `segment_limit` segments. Compact rows also enforce `text_limit` before
/// allocating each decoded Message-ID and reject invalid UTF-8. JSON rows can
/// materialize one string before the visitor sees it, so callers must also
/// bound the raw input size. An over-limit or malformed value returns `None`.
///
/// The ordinary index readers use [`parse_bytes`] because their row shape is
/// already bounded by ingest. Candidate scans over stale rows need this form:
/// decoding before a compatibility check must not let one unrelated blob
/// allocate an arbitrarily large segment vector.
pub fn parse_capped_bytes(raw: &[u8], segment_limit: usize, text_limit: usize) -> Option<Vec<Seg>> {
    match parse_capped_bytes_guarded(raw, segment_limit, text_limit, &mut || true) {
        GuardedParse::Complete(out) => Some(out),
        GuardedParse::Deferred | GuardedParse::Invalid => None,
    }
}

/// [`parse_capped_bytes`] with bounded cancellation checks while decoding a
/// single stored row. A refused guard never exposes a partially decoded list.
pub(super) fn parse_capped_bytes_guarded(
    raw: &[u8],
    segment_limit: usize,
    text_limit: usize,
    keep_going: &mut impl FnMut() -> bool,
) -> GuardedParse {
    let mut deferred = false;
    let out = {
        let mut guarded = || {
            let allowed = keep_going();
            deferred |= !allowed;
            allowed
        };
        if !guarded() {
            None
        } else {
            let out = if is_encoded(raw) {
                decode_prefix_impl_guarded(
                    raw,
                    segment_limit.saturating_add(1),
                    text_limit,
                    true,
                    &mut guarded,
                )
                .and_then(|out| (out.len() <= segment_limit).then_some(out))
            } else {
                let mut deserializer = serde_json::Deserializer::from_slice(raw);
                serde::de::DeserializeSeed::deserialize(
                    CappedSegments {
                        limit: segment_limit,
                        text_limit,
                        keep_going: &mut guarded,
                    },
                    &mut deserializer,
                )
                .ok()
                .and_then(|out| deserializer.end().ok().map(|()| out))
            };
            if out.is_some() && !guarded() {
                None
            } else {
                out
            }
        }
    };
    if deferred {
        GuardedParse::Deferred
    } else {
        out.map_or(GuardedParse::Invalid, GuardedParse::Complete)
    }
}

/// Is this stored value the compact form (as opposed to JSON)?
pub fn is_encoded(raw: &[u8]) -> bool {
    raw.first() == Some(&MAGIC)
}

/// The list a stored `segments` value holds, in either form. Malformed
/// input is an empty list, which is what every JSON reader did with
/// `serde_json::from_str(..).unwrap_or_default()`.
pub fn parse_bytes(raw: &[u8]) -> Vec<Seg> {
    if is_encoded(raw) {
        decode(raw).unwrap_or_default()
    } else {
        serde_json::from_slice(raw).unwrap_or_default()
    }
}

/// [`parse_bytes`] over a SQLite value: TEXT is JSON, BLOB is either.
pub fn parse(v: ValueRef<'_>) -> Vec<Seg> {
    match v {
        ValueRef::Text(t) | ValueRef::Blob(t) => parse_bytes(t),
        _ => Vec::new(),
    }
}

/// How many segments a stored value holds, without materialising them.
/// JSON is counted by a scan (top-level array elements), not parsed.
pub fn count_bytes(raw: &[u8]) -> i64 {
    if is_encoded(raw) {
        let mut r = Reader { buf: raw, at: 1 };
        return r.varint().map(|n| n as i64).unwrap_or(0);
    }
    json_array_len(raw).unwrap_or(0)
}

/// The first-listed segment's message-id, or None when there is none.
pub fn first_msgid_bytes(raw: &[u8]) -> Option<String> {
    if is_encoded(raw) {
        decode_prefix(raw, 1)?
            .into_iter()
            .next()
            .map(|(_, id, _)| id)
    } else {
        let v: Vec<Seg> = serde_json::from_slice(raw).ok()?;
        v.into_iter().next().map(|(_, id, _)| id)
    }
}

/// Element count of a JSON array, by scanning for the top-level
/// commas. `None` when the text is not an array.
fn json_array_len(raw: &[u8]) -> Option<i64> {
    let mut i = 0;
    while i < raw.len() && raw[i].is_ascii_whitespace() {
        i += 1;
    }
    if raw.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    let mut depth = 1usize;
    let mut count = 0i64;
    let mut saw_element = false;
    let mut in_str = false;
    while i < raw.len() {
        let c = raw[i];
        if in_str {
            match c {
                b'\\' => i += 1,
                b'"' => in_str = false,
                _ => {}
            }
        } else {
            match c {
                b'"' => {
                    in_str = true;
                    saw_element = true;
                }
                b'[' | b'{' => {
                    depth += 1;
                    saw_element = true;
                }
                b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(if saw_element { count + 1 } else { 0 });
                    }
                }
                b',' if depth == 1 => count += 1,
                c if !c.is_ascii_whitespace() => saw_element = true,
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// A `segments` column read straight out of a row, whichever form the
/// row holds: `r.get::<_, SegList>(i)?.0`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SegList(pub Vec<Seg>);

impl FromSql for SegList {
    fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
        match v {
            ValueRef::Text(_) | ValueRef::Blob(_) | ValueRef::Null => Ok(SegList(parse(v))),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

/// The stored bytes of a `segments` column, whichever form, for a
/// caller that wants to decode (and report) for itself. A plain
/// `Vec<u8>` will not do: rusqlite refuses a TEXT value for it, and a
/// pre-migration row IS text.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SegRaw(pub Vec<u8>);

impl FromSql for SegRaw {
    fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
        match v {
            ValueRef::Text(t) | ValueRef::Blob(t) => Ok(SegRaw(t.to_vec())),
            ValueRef::Null => Ok(SegRaw(Vec::new())),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

/// Install `seg_count(x)` and `seg_first(x)` on a connection. Both are
/// deterministic and accept either stored form; `seg_count` of NULL or
/// of anything unreadable is 0 and `seg_first` of those is NULL, which
/// is what the `COALESCE(json_array_length(..), 0)` and
/// `COALESCE(json_extract(..), '')` shapes they replaced produced.
pub fn register(db: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    db.create_scalar_function("seg_count", 1, flags, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Text(t) | ValueRef::Blob(t) => count_bytes(t),
            _ => 0,
        })
    })?;
    db.create_scalar_function("seg_first", 1, flags, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Text(t) | ValueRef::Blob(t) => first_msgid_bytes(t),
            _ => None,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(n: u32, id: &str, b: u64) -> Seg {
        (n, id.to_string(), b)
    }

    fn roundtrip(segs: &[Seg]) -> Vec<u8> {
        let enc = encode(segs);
        assert_eq!(
            decode(&enc).as_deref(),
            Some(segs),
            "round trip of {segs:?}"
        );
        assert_eq!(count_bytes(&enc), segs.len() as i64);
        assert_eq!(first_msgid_bytes(&enc), segs.first().map(|s| s.1.clone()));
        enc
    }

    #[test]
    fn an_empty_list_round_trips_in_two_bytes() {
        let enc = roundtrip(&[]);
        assert_eq!(enc, vec![MAGIC, 0, 0, 0]);
        assert!(is_encoded(&enc));
    }

    #[test]
    fn the_ngpost_shape_packs_its_hex() {
        let segs: Vec<Seg> = (1..=20)
            .map(|n| {
                seg(
                    n,
                    &format!(
                        "<{:032x}@ngPost>",
                        0x1234_5678_9abc_def0u64.wrapping_mul(n as u64)
                    ),
                    716_800,
                )
            })
            .collect();
        let enc = roundtrip(&segs);
        let json = serde_json::to_string(&segs).unwrap();
        // 32 hex chars pack to 16 bytes; framing is a few bytes each.
        assert!(
            enc.len() * 3 < json.len(),
            "{} vs {}",
            enc.len(),
            json.len()
        );
    }

    #[test]
    fn the_nyuu_shape_packs_six_bits_a_char() {
        let segs: Vec<Seg> = (1..=12)
            .map(|n| seg(n, &format!("<JlDqOhBzAtWzIoNpOoWaJdRa-{n}@nyuu>"), 768_000))
            .collect();
        let enc = roundtrip(&segs);
        let json = serde_json::to_string(&segs).unwrap();
        assert!(
            enc.len() * 2 < json.len(),
            "{} vs {}",
            enc.len(),
            json.len()
        );
    }

    #[test]
    fn every_shape_the_index_holds_round_trips() {
        let cases: Vec<Vec<Seg>> = vec![
            vec![seg(
                1,
                "<18ca1e51e75fd25c.8a.e06b3746629533e5@womlhzctlgxqwd.com>",
                1,
            )],
            vec![
                seg(
                    1,
                    "<nhk-bspNk-main.1@mmt-recorder.nhk-archive.invalid>",
                    500_000,
                ),
                seg(
                    2,
                    "<nhk-bspNk-main.2@mmt-recorder.nhk-archive.invalid>",
                    500_000,
                ),
                seg(
                    3,
                    "<nhk-bspNk-main.3@mmt-recorder.nhk-archive.invalid>",
                    120_000,
                ),
            ],
            // Part numbers out of order, with gaps, repeated, and zero.
            vec![
                seg(5, "a", 1),
                seg(2, "b", 2),
                seg(2, "c", 3),
                seg(0, "d", 0),
            ],
            // Empty and whitespace ids, ids without brackets.
            vec![seg(1, "", 7), seg(2, "", 7), seg(3, " ", 7)],
            // An id that is entirely the common prefix of the others.
            vec![
                seg(1, "<ab@x>", 1),
                seg(2, "<ab@x>", 1),
                seg(3, "<ab@x>yy", 1),
            ],
            // Prefix and suffix that would overlap on the shortest id.
            vec![seg(1, "aaaa", 1), seg(2, "aaaaaa", 1), seg(3, "aa", 1)],
            // UTF-8 and control bytes in the middle, prefix and suffix.
            vec![
                seg(1, "<héllo-1.ünï@zürich>", 9),
                seg(2, "<héllo-2.ünï@zürich>", 9),
                seg(3, "<héllo-\u{1F600}\t\u{0}.ünï@zürich>", 9),
            ],
            // A middle longer than one token, in every kind.
            vec![
                seg(1, &"f".repeat(200), 1),
                seg(2, &"Z".repeat(200), 1),
                seg(3, &"@".repeat(200), 1),
                seg(
                    4,
                    &format!("{}{}{}", "f".repeat(71), "Z".repeat(65), "@".repeat(64)),
                    1,
                ),
            ],
            // An odd-length hex run, and one just under HEX_MIN.
            vec![seg(1, "<0123456789abcdef0@x>", 1), seg(2, "<0123456@x>", 1)],
            // Big numbers.
            vec![seg(u32::MAX, "x", u64::MAX), seg(1, "y", 0)],
            // Uppercase hex is not hex (it is b64) and still round-trips.
            vec![
                seg(1, "<ABCDEF0123456789@x>", 1),
                seg(2, "<abcdef0123456789@x>", 2),
            ],
        ];
        for c in cases {
            roundtrip(&c);
        }
    }

    #[test]
    fn a_pseudo_random_corpus_round_trips() {
        // A small LCG so the corpus is deterministic without a dep.
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let alphabet: &[u8] = b"0123456789abcdefABCDEFghXYZ-_@.<>$ \xc3\xa9";
        for _ in 0..500 {
            let n = (next() % 40) as usize;
            let mut segs = Vec::new();
            let mut num = 0u32;
            for _ in 0..n {
                let len = (next() % 60) as usize;
                let id: Vec<u8> = (0..len)
                    .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                    .collect();
                let id = String::from_utf8_lossy(&id).into_owned();
                num = num.wrapping_add((next() % 3) as u32);
                segs.push((num, id, next() % 1_000_000));
            }
            roundtrip(&segs);
        }
    }

    #[test]
    fn garbage_never_panics_and_never_decodes() {
        let enc = encode(&[seg(1, "<abc@x>", 10), seg(2, "<abd@x>", 10)]);
        for cut in 0..enc.len() {
            assert!(decode(&enc[..cut]).is_none(), "truncated at {cut}");
        }
        for i in 0..enc.len() {
            let mut bad = enc.clone();
            bad[i] ^= 0x55;
            let _ = decode(&bad);
            let _ = count_bytes(&bad);
            let _ = first_msgid_bytes(&bad);
        }
        assert!(decode(b"").is_none());
        assert!(decode(b"[]").is_none());
        assert_eq!(parse_bytes(b"\x01\xff\xff\xff\xff"), Vec::<Seg>::new());
    }

    #[test]
    fn json_is_still_read_by_every_entry_point() {
        let json = br#"[[1,"<a@b>",10],[3,"x,y]\"z",20]]"#;
        assert!(!is_encoded(json));
        assert_eq!(
            parse_bytes(json),
            vec![seg(1, "<a@b>", 10), seg(3, "x,y]\"z", 20)]
        );
        assert_eq!(count_bytes(json), 2);
        assert_eq!(first_msgid_bytes(json).as_deref(), Some("<a@b>"));
        assert_eq!(count_bytes(b"[]"), 0);
        assert_eq!(count_bytes(b" [ ] "), 0);
        assert_eq!(count_bytes(b"[[1,\"a\",1]]"), 1);
        assert_eq!(count_bytes(b"not json"), 0);
        assert_eq!(count_bytes(b"[1, 2"), 0);
        assert_eq!(first_msgid_bytes(b"[]"), None);
    }

    #[test]
    fn capped_parse_refuses_both_representations_before_the_extra_segment() {
        let segs = vec![
            seg(1, "one@x", 10),
            seg(2, "two@x", 10),
            seg(3, "three@x", 10),
        ];
        let encoded = encode(&segs);
        let json = serde_json::to_vec(&segs).unwrap();
        assert_eq!(parse_capped_bytes(&encoded, 3, 17), Some(segs.clone()));
        assert_eq!(parse_capped_bytes(&json, 3, 17), Some(segs));
        assert!(parse_capped_bytes(&encoded, 2, 17).is_none());
        assert!(parse_capped_bytes(&json, 2, 17).is_none());
        assert!(parse_capped_bytes(&encoded, 3, 16).is_none());
        assert!(parse_capped_bytes(&json, 3, 16).is_none());

        let mut invalid_utf8 = encode(&[seg(1, "é", 1)]);
        let lead = invalid_utf8.iter().position(|byte| *byte == 0xc3).unwrap();
        invalid_utf8[lead] = 0xff;
        assert!(decode(&invalid_utf8).is_some(), "legacy decode stays lossy");
        assert!(parse_capped_bytes(&invalid_utf8, 1, 2).is_none());
    }

    #[test]
    fn guarded_capped_parse_defers_inside_both_large_representations() {
        let segs: Vec<Seg> = (1..=1_024)
            .map(|number| seg(number, &format!("<guard-{number:04}@x>"), 10))
            .collect();
        let encoded = encode(&segs);
        let json = serde_json::to_vec(&segs).unwrap();
        for raw in [&encoded[..], &json[..]] {
            let calls = std::cell::Cell::new(0usize);
            let parsed = parse_capped_bytes_guarded(raw, segs.len(), usize::MAX, &mut || {
                calls.set(calls.get() + 1);
                calls.get() <= 3
            });
            assert_eq!(parsed, GuardedParse::Deferred);
            assert_eq!(calls.get(), 4, "guard was not checked during row decode");
        }
    }

    #[test]
    fn guarded_capped_parse_checks_again_after_a_small_decode() {
        let segs = vec![seg(1, "<guard@x>", 10)];
        for raw in [encode(&segs), serde_json::to_vec(&segs).unwrap()] {
            let calls = std::cell::Cell::new(0usize);
            let parsed = parse_capped_bytes_guarded(&raw, 1, usize::MAX, &mut || {
                calls.set(calls.get() + 1);
                calls.get() <= 2
            });
            assert_eq!(parsed, GuardedParse::Deferred);
            assert_eq!(calls.get(), 3);
        }
    }

    #[test]
    fn the_sql_functions_answer_for_both_forms() {
        let db = Connection::open_in_memory().unwrap();
        register(&db).unwrap();
        let segs = vec![seg(1, "<first@x>", 5), seg(2, "<second@x>", 6)];
        let enc = encode(&segs);
        let json = serde_json::to_string(&segs).unwrap();
        let (cb, fb): (i64, String) = db
            .query_row("SELECT seg_count(?1), seg_first(?1)", [&enc], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let (cj, fj): (i64, String) = db
            .query_row("SELECT seg_count(?1), seg_first(?1)", [&json], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((cb, fb.as_str()), (2, "<first@x>"));
        assert_eq!((cj, fj.as_str()), (2, "<first@x>"));
        let (cn, fn_): (i64, Option<String>) = db
            .query_row("SELECT seg_count(NULL), seg_first('[]')", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((cn, fn_), (0, None));
        // And the column reader, through a real row of each form.
        db.execute_batch("CREATE TABLE t(s)").unwrap();
        db.execute(
            "INSERT INTO t VALUES(?1), (?2)",
            rusqlite::params![enc, json],
        )
        .unwrap();
        let got: Vec<SegList> = db
            .prepare("SELECT s FROM t")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(got, vec![SegList(segs.clone()), SegList(segs)]);
    }
}
