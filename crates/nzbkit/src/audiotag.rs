//! What a music track calls ITSELF: artist, title and track number read
//! straight out of the bytes that landed.
//!
//! ## Why this exists
//!
//! An obfuscated post arrives with every name replaced by a hash, and
//! the two naming sources the download path already has both run out:
//!
//! 1. The PAR2 recovery set. A FileDesc name is MD5-proven and is
//!    therefore the authority whenever the set covers the file (see
//!    [`crate::live::LiveVerifier`], whose `SlotReport::par2_name` the
//!    daemon renames from). On a fully obfuscated post the set often
//!    names nothing, or names the same hashes.
//! 2. The NZB subject. That is where the on-disk name came from in the
//!    first place, so when it is obfuscated there is nothing further to
//!    extract from it.
//!
//! For video that leaves the container sniff, which can only answer with
//! an EXTENSION - a container carries no filename. Audio is the case
//! where the bytes carry the name: a music file is tagged, and the tag
//! is the poster's own metadata rather than anything inferred. GitHub
//! issue #55 is the report: a whole album landed hash-named because
//! nothing here existed.
//!
//! ## Untrusted input
//!
//! Every byte is attacker-chosen. Nothing allocates from a declared
//! length, every walk is bounded by an entry budget and a byte budget,
//! every offset is checked, and each value has to survive [`clean`]
//! before it can name a file. The fuzz target is `audio_tags`.
//!
//! ## Scope
//!
//! FLAC, MP3 (ID3v2 with an ID3v1 fallback), MP4 audio (`M4A`/`M4B`
//! brands) and Ogg (Vorbis and Opus). Everything else answers `None`,
//! which costs a user an obfuscated filename and never a wrong one.
//! Known gaps, all deliberate: an audio-only `.mp4` wearing a plain
//! `isom`/`mp42` brand, Matroska audio (`.mka`, whose tags are a
//! different grammar), APE, WavPack and WAV.

use std::io::{Read, Seek, SeekFrom};

/// How much of a file's head may be read looking for metadata. Tags sit
/// at the front of every format here except MP4, whose `moov` is walked
/// separately, and 1 MiB is far past any real tag block while still
/// bounding what one hostile head can make this buffer.
pub const HEAD_MAX: usize = 1 << 20;

/// Cap on an MP4 `moov` box read into memory. Metadata only: the audio
/// itself lives in `mdat`, which is skipped.
const MOOV_MAX: u64 = 8 << 20;

/// Longest value kept from a tag, in characters. A real artist or title
/// is far under this; a longer one is a filename nobody wants and a
/// filesystem may refuse.
const VALUE_MAX: usize = 160;

/// Most entries any one tag block may declare before it is refused.
/// Real files carry a dozen; the budget bounds a hostile count field.
const ENTRIES_MAX: usize = 512;

/// How far past an ID3v2 tag a first MPEG audio frame may sit before
/// the file stops being callable an MP3. Padding between the tag and
/// the first frame is legal and small.
const MPEG_SYNC_SEARCH: usize = 8 << 10;

/// What a track says it is. Every field is optional: a tag block may
/// carry any subset, and the caller decides what is enough to name a
/// file with.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AudioTags {
    pub artist: Option<String>,
    pub title: Option<String>,
    pub album: Option<String>,
    pub track: Option<u32>,
}

impl AudioTags {
    /// Nothing was read at all.
    pub fn is_empty(&self) -> bool {
        self.artist.is_none()
            && self.title.is_none()
            && self.album.is_none()
            && self.track.is_none()
    }

    fn set(&mut self, key: Key, value: &str) {
        match key {
            Key::Title if self.title.is_none() => self.title = clean(value),
            Key::Artist if self.artist.is_none() => self.artist = clean(value),
            Key::Album if self.album.is_none() => self.album = clean(value),
            Key::Track if self.track.is_none() => self.track = track_of(value),
            _ => {}
        }
    }
}

/// The four fields worth reading. Everything else in a tag block is
/// skipped rather than stored: a name is built from these and nothing
/// here is a metadata library.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Title,
    Artist,
    Album,
    Track,
}

/// A tag value fit to appear in a filename, or `None`.
///
/// Refuses the empty string, anything carrying a control character (a
/// tag is attacker-chosen and a newline in a filename is somebody's
/// terminal), and anything past [`VALUE_MAX`]. Trailing NULs are
/// stripped first: fixed-width tag fields pad with them.
pub fn clean(s: &str) -> Option<String> {
    let t = s.trim_matches('\0').trim();
    if t.is_empty() || t.chars().count() > VALUE_MAX || t.chars().any(char::is_control) {
        return None;
    }
    Some(t.to_string())
}

/// The track number a tag field declares: a bare number, or the
/// `7/12` and `7 of 12` forms every tagger writes. Zero is not a track
/// and neither is anything past three digits.
pub fn track_of(s: &str) -> Option<u32> {
    let head = s.trim().split([' ', '/']).next()?;
    let n: u32 = head.parse().ok()?;
    (1..=999).contains(&n).then_some(n)
}

/// The extension these bytes should carry, judged on magic alone.
///
/// `None` means "not an audio format this module can name", which is
/// the answer for every video container too - deciding those is
/// `nzbfast`'s `smart::videoext` and its probe, and the two must not
/// both claim a file.
pub fn sniff_ext(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"fLaC") {
        return Some("flac");
    }
    if head.starts_with(b"OggS") {
        // The codec rides in the first packet, a few bytes into the
        // page body. Both markers are unambiguous and neither can
        // appear before its own page header.
        if find(head, b"OpusHead").is_some() {
            return Some("opus");
        }
        if find(head, b"\x01vorbis").is_some() {
            return Some("ogg");
        }
        return None;
    }
    if head.starts_with(b"ID3") {
        // An ID3 tag is not proof of an MP3 - it prefixes AAC and more -
        // so the audio behind it has to sync as an MPEG Layer III frame.
        // A tag running past the head is refused rather than assumed.
        let size = id3v2_len(head)?;
        let from = size.min(head.len());
        let rest = head.get(from..)?;
        let window = rest.len().min(MPEG_SYNC_SEARCH);
        return (0..window)
            .any(|i| is_mpeg_layer3(&rest[i..]))
            .then_some("mp3");
    }
    if is_mpeg_layer3(head) {
        return Some("mp3");
    }
    if head.get(4..8) == Some(b"ftyp") {
        // Major brand, then the compatible-brand list. Only the audio
        // brands: a plain `isom`/`mp42` file is video's to classify.
        let brands = head.get(8..)?;
        for b in brands.chunks_exact(4).take(8) {
            match b {
                b"M4A " => return Some("m4a"),
                b"M4B " => return Some("m4b"),
                _ => {}
            }
        }
        return None;
    }
    None
}

/// The extension these bytes should carry AND what the track calls
/// itself, in one pass over one head read.
///
/// Both halves or nothing: a file that sniffs as audio and carries no
/// tag has nothing to be named after, and the caller has no business
/// touching it. Never blocks and never allocates from a declared
/// length.
pub fn probe<R: Read + Seek>(r: &mut R) -> Option<(&'static str, AudioTags)> {
    let head = read_head(r)?;
    let ext = sniff_ext(&head)?;
    let tags = match ext {
        "flac" => flac_tags(&head),
        "ogg" | "opus" => ogg_tags(&head),
        // ID3v2 sits at the front; a file carrying only the 128-byte
        // ID3v1 trailer is still common enough on old rips to be worth
        // the one extra seek.
        "mp3" => id3v2_tags(&head).or_else(|| id3v1_tags(r)),
        "m4a" | "m4b" => mp4_tags(r),
        _ => None,
    }?;
    (!tags.is_empty()).then_some((ext, tags))
}

/// Everything the tag block says, or `None` when there is no tag this
/// module can read.
pub fn read_tags<R: Read + Seek>(r: &mut R) -> Option<AudioTags> {
    probe(r).map(|(_, t)| t)
}

/// The first [`HEAD_MAX`] bytes, or as many as there are. Grows with
/// what actually arrives rather than with any declared size.
fn read_head<R: Read + Seek>(r: &mut R) -> Option<Vec<u8>> {
    r.seek(SeekFrom::Start(0)).ok()?;
    let mut buf = Vec::new();
    r.take(HEAD_MAX as u64).read_to_end(&mut buf).ok()?;
    (buf.len() >= 12).then_some(buf)
}

/// Byte offset of `needle` in `hay`, searched over a bounded prefix.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let limit = hay.len().min(64 << 10);
    hay.get(..limit)?
        .windows(needle.len())
        .position(|w| w == needle)
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(s))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let s: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(s))
}

/// Does this head sync as an MPEG-1/2 Layer III frame? All of it is
/// required: a bare `0xFF` pair is one and a half bytes of evidence and
/// turns up inside plenty of binaries.
fn is_mpeg_layer3(head: &[u8]) -> bool {
    let Some(b) = head.get(..3) else {
        return false;
    };
    b[0] == 0xFF
        && b[1] & 0xE0 == 0xE0
        && b[1] >> 3 & 0b11 != 0b01 // reserved MPEG version
        && b[1] >> 1 & 0b11 == 0b01 // Layer III
        && b[2] >> 4 != 0 // free-format and bad bitrate indices
        && b[2] >> 4 != 0xF
        && b[2] >> 2 & 0b11 != 0b11 // reserved sample rate
}

// ---------------------------------------------------------------------------
// FLAC and Ogg: the Vorbis comment
// ---------------------------------------------------------------------------

/// FLAC metadata blocks are a header of one flag/type byte and a 24-bit
/// length, walked until the last-block flag. `VORBIS_COMMENT` is type 4.
fn flac_tags(head: &[u8]) -> Option<AudioTags> {
    const VORBIS_COMMENT: u8 = 4;
    let mut off = 4usize;
    // A real file carries a handful of blocks. The budget bounds a
    // header claiming zero-length blocks forever.
    for _ in 0..64 {
        let h = head.get(off..off.checked_add(4)?)?;
        let last = h[0] & 0x80 != 0;
        let kind = h[0] & 0x7F;
        let len = u32::from_be_bytes([0, h[1], h[2], h[3]]) as usize;
        off = off.checked_add(4)?;
        if kind == VORBIS_COMMENT {
            // A comment block reaching past the head - an embedded
            // cover pushed it there - is refused, not guessed at.
            return vorbis_comment(head.get(off..off.checked_add(len)?)?);
        }
        if last {
            return None;
        }
        off = off.checked_add(len)?;
    }
    None
}

/// The comment header of an Ogg stream, found by its own magic.
///
/// Ogg framing is deliberately NOT decoded: the comment packet is
/// identified by the marker the codec puts at its head and parsed from
/// there. A packet long enough to be split across a page boundary
/// therefore has a 27-byte page header injected into the middle of it,
/// and the value that lands on is refused by [`clean`] rather than
/// mis-read - a page header is not printable text.
fn ogg_tags(head: &[u8]) -> Option<AudioTags> {
    if let Some(i) = find(head, b"OpusTags") {
        return vorbis_comment(head.get(i + 8..)?);
    }
    let i = find(head, b"\x03vorbis")?;
    vorbis_comment(head.get(i + 7..)?)
}

/// `vendor`, then a count, then `KEY=value` entries, all little-endian
/// lengths. Shared by FLAC and both Ogg codecs, which is why it is one
/// function: they are the same grammar.
fn vorbis_comment(b: &[u8]) -> Option<AudioTags> {
    let vendor = le32(b, 0)? as usize;
    let mut p = 4usize.checked_add(vendor)?;
    let count = le32(b, p)? as usize;
    if count > ENTRIES_MAX {
        return None;
    }
    p = p.checked_add(4)?;
    let mut tags = AudioTags::default();
    for _ in 0..count {
        let len = le32(b, p)? as usize;
        p = p.checked_add(4)?;
        let item = b.get(p..p.checked_add(len)?)?;
        p = p.checked_add(len)?;
        // One entry that is not text does not condemn the block: skip
        // it and keep reading, the way every player does.
        let Ok(s) = std::str::from_utf8(item) else {
            continue;
        };
        let Some((k, v)) = s.split_once('=') else {
            continue;
        };
        let key = match k.to_ascii_uppercase().as_str() {
            "TITLE" => Key::Title,
            "ARTIST" => Key::Artist,
            "ALBUM" => Key::Album,
            "TRACKNUMBER" => Key::Track,
            _ => continue,
        };
        tags.set(key, v);
    }
    Some(tags)
}

// ---------------------------------------------------------------------------
// ID3
// ---------------------------------------------------------------------------

/// Total bytes an ID3v2 tag occupies, header included, or `None` when
/// the head does not open with one.
fn id3v2_len(head: &[u8]) -> Option<usize> {
    if head.get(..3)? != b"ID3" || !(2..=4).contains(head.get(3)?) {
        return None;
    }
    Some(10 + synchsafe(head.get(6..10)?)? as usize)
}

/// Seven bits per byte, high bit always clear: the ID3 size encoding
/// that keeps a length from ever looking like a frame sync. A byte with
/// its high bit set is not a synchsafe integer and is refused.
fn synchsafe(b: &[u8]) -> Option<u32> {
    let s: [u8; 4] = b.get(..4)?.try_into().ok()?;
    if s.iter().any(|&x| x & 0x80 != 0) {
        return None;
    }
    Some(s.iter().fold(0u32, |a, &x| a << 7 | x as u32))
}

fn id3v2_tags(head: &[u8]) -> Option<AudioTags> {
    let major = *head.get(3)?;
    let flags = *head.get(5)?;
    let end = id3v2_len(head)?.min(head.len());
    let mut p = 10usize;
    if flags & 0x40 != 0 {
        // Extended header: v2.4 declares a synchsafe size INCLUDING
        // itself, v2.3 a plain size EXCLUDING its own four bytes. A
        // wrong guess lands on bytes that are no frame id, and the loop
        // below stops - so this is safe to attempt either way.
        let n = if major == 4 {
            synchsafe(head.get(p..p.checked_add(4)?)?)? as usize
        } else {
            be32(head, p)? as usize + 4
        };
        p = p.checked_add(n)?;
    }
    // v2.2 frames are a 3-byte id and a 3-byte size with no flags;
    // v2.3/v2.4 are 4 and 4 with two flag bytes after.
    let (idlen, hdr) = if major == 2 { (3, 6) } else { (4, 10) };
    let mut tags = AudioTags::default();
    for _ in 0..ENTRIES_MAX {
        let frame = match head.get(p..p.checked_add(hdr)?) {
            Some(f) if p + hdr <= end => f,
            _ => break,
        };
        // A run of NULs is the tag's padding, not a frame.
        if frame[0] == 0 {
            break;
        }
        let size = if major == 2 {
            u32::from_be_bytes([0, frame[3], frame[4], frame[5]]) as usize
        } else if major == 4 {
            // v2.4 sizes are synchsafe. Some writers emit a plain
            // integer anyway; that reads as a wrong size, the next id
            // is not a frame id, and the loop stops with whatever was
            // already read.
            synchsafe(&frame[4..8])? as usize
        } else {
            be32(frame, 4)? as usize
        };
        p = p.checked_add(hdr)?;
        let body = match head.get(p..p.checked_add(size)?) {
            Some(b) if p + size <= end => b,
            _ => break,
        };
        p = p.checked_add(size)?;
        let key = match &frame[..idlen] {
            b"TIT2" | b"TT2" => Key::Title,
            b"TPE1" | b"TP1" => Key::Artist,
            b"TALB" | b"TAL" => Key::Album,
            b"TRCK" | b"TRK" => Key::Track,
            _ => continue,
        };
        if let Some(v) = id3_text(body) {
            tags.set(key, &v);
        }
    }
    Some(tags)
}

/// An ID3 text frame: one encoding byte, then the string in whichever
/// of the four encodings that byte names.
fn id3_text(b: &[u8]) -> Option<String> {
    let (enc, rest) = b.split_first()?;
    let till_nul = |s: &[u8]| s.split(|&c| c == 0).next().unwrap_or(s).to_vec();
    match enc {
        // ISO-8859-1: every byte is its own code point.
        0 => Some(till_nul(rest).iter().map(|&c| c as char).collect()),
        3 => String::from_utf8(till_nul(rest)).ok(),
        // 1 carries a BOM, 2 is big-endian with none.
        1 | 2 => {
            let (body, big) = match (enc, rest.get(..2)) {
                (1, Some([0xFF, 0xFE])) => (rest.get(2..)?, false),
                (1, Some([0xFE, 0xFF])) => (rest.get(2..)?, true),
                (1, _) => return None,
                _ => (rest, true),
            };
            let units: Vec<u16> = body
                .chunks_exact(2)
                .map(|c| {
                    if big {
                        u16::from_be_bytes([c[0], c[1]])
                    } else {
                        u16::from_le_bytes([c[0], c[1]])
                    }
                })
                .take_while(|&u| u != 0)
                .collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

/// The 128-byte ID3v1 trailer: fixed-width Latin-1 fields, and in v1.1
/// a track number in the last two bytes of the comment field.
fn id3v1_tags<R: Read + Seek>(r: &mut R) -> Option<AudioTags> {
    let end = r.seek(SeekFrom::End(0)).ok()?;
    if end < 128 {
        return None;
    }
    r.seek(SeekFrom::Start(end - 128)).ok()?;
    let mut b = [0u8; 128];
    r.read_exact(&mut b).ok()?;
    if &b[..3] != b"TAG" {
        return None;
    }
    let latin1 = |s: &[u8]| -> String {
        s.split(|&c| c == 0)
            .next()
            .unwrap_or(s)
            .iter()
            .map(|&c| c as char)
            .collect()
    };
    let mut tags = AudioTags::default();
    tags.set(Key::Title, &latin1(&b[3..33]));
    tags.set(Key::Artist, &latin1(&b[33..63]));
    tags.set(Key::Album, &latin1(&b[63..93]));
    if b[125] == 0 && b[126] != 0 {
        tags.track = Some(b[126] as u32);
    }
    Some(tags)
}

// ---------------------------------------------------------------------------
// MP4
// ---------------------------------------------------------------------------

/// Walk the top-level boxes for `moov` and read the item list inside it.
///
/// The walk seeks rather than reads: `mdat` is the audio and is jumped,
/// which is what makes a trailing `moov` - the layout most taggers
/// write - reachable at all.
fn mp4_tags<R: Read + Seek>(r: &mut R) -> Option<AudioTags> {
    let end = r.seek(SeekFrom::End(0)).ok()?;
    let mut off = 0u64;
    for _ in 0..64 {
        r.seek(SeekFrom::Start(off)).ok()?;
        let mut hdr = [0u8; 8];
        r.read_exact(&mut hdr).ok()?;
        let mut size = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
        let mut hlen = 8u64;
        if size == 1 {
            let mut ext = [0u8; 8];
            r.read_exact(&mut ext).ok()?;
            size = u64::from_be_bytes(ext);
            hlen = 16;
        }
        if size < hlen || off.checked_add(size)? > end {
            return None;
        }
        if &hdr[4..8] == b"moov" {
            let mut buf = Vec::new();
            r.take((size - hlen).min(MOOV_MAX))
                .read_to_end(&mut buf)
                .ok()?;
            return ilst_tags(&buf);
        }
        off = off.checked_add(size)?;
    }
    None
}

/// The body of the first child box of `buf` with this type.
fn box_body<'a>(buf: &'a [u8], want: &[u8; 4]) -> Option<&'a [u8]> {
    let mut p = 0usize;
    for _ in 0..ENTRIES_MAX {
        let h = buf.get(p..p.checked_add(8)?)?;
        let size = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize;
        if size < 8 {
            return None;
        }
        let body = buf.get(p.checked_add(8)?..p.checked_add(size)?)?;
        if &h[4..8] == want {
            return Some(body);
        }
        p = p.checked_add(size)?;
    }
    None
}

/// `moov/udta/meta/ilst`, and the item list inside it.
fn ilst_tags(moov: &[u8]) -> Option<AudioTags> {
    let udta = box_body(moov, b"udta")?;
    // `meta` is a FULL box: four bytes of version and flags sit before
    // its children, and a walk that misses them finds no `ilst` at all.
    let meta = box_body(udta, b"meta")?.get(4..)?;
    let ilst = box_body(meta, b"ilst")?;
    let mut tags = AudioTags::default();
    let mut p = 0usize;
    for _ in 0..ENTRIES_MAX {
        let Some(h) = ilst.get(p..p + 8) else { break };
        let size = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize;
        if size < 8 {
            break;
        }
        let Some(item) = ilst.get(p + 8..p.checked_add(size)?) else {
            break;
        };
        let kind: [u8; 4] = [h[4], h[5], h[6], h[7]];
        p = p.checked_add(size)?;
        // Every item wraps its value in a `data` box whose first eight
        // bytes are a type and a locale.
        let Some(data) = box_body(item, b"data").and_then(|d| d.get(8..)) else {
            continue;
        };
        match &kind {
            b"\xA9nam" | b"\xA9ART" | b"\xA9alb" => {
                let Ok(s) = std::str::from_utf8(data) else {
                    continue;
                };
                tags.set(
                    match &kind {
                        b"\xA9nam" => Key::Title,
                        b"\xA9ART" => Key::Artist,
                        _ => Key::Album,
                    },
                    s,
                );
            }
            // `trkn` is binary: two pad bytes, the track, then the
            // total.
            b"trkn" => {
                if let Some(n) = data.get(2..4) {
                    let n = u16::from_be_bytes([n[0], n[1]]) as u32;
                    if tags.track.is_none() && (1..=999).contains(&n) {
                        tags.track = Some(n);
                    }
                }
            }
            _ => {}
        }
    }
    Some(tags)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Minimal, valid-enough files for the four supported formats.
///
/// Public for the same reason [`crate::mediaprobe::testmux`] is: the
/// naming pass that consumes these tags lives in the other crate, and
/// its tests need the same bytes rather than a second hand-rolled
/// approximation of them.
pub mod testtag {
    /// One MPEG-1 Layer III frame header: sync, 128 kbit, 44.1 kHz.
    pub const MPEG_FRAME: [u8; 4] = [0xFF, 0xFB, 0x90, 0x00];

    fn vorbis_block(tags: &[(&str, &str)]) -> Vec<u8> {
        let mut v = Vec::new();
        let vendor = b"nzbfast-test";
        v.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
        v.extend_from_slice(vendor);
        v.extend_from_slice(&(tags.len() as u32).to_le_bytes());
        for (k, val) in tags {
            let e = format!("{k}={val}");
            v.extend_from_slice(&(e.len() as u32).to_le_bytes());
            v.extend_from_slice(e.as_bytes());
        }
        v
    }

    /// A FLAC carrying a STREAMINFO block and a Vorbis comment.
    pub fn flac(tags: &[(&str, &str)]) -> Vec<u8> {
        let mut v = b"fLaC".to_vec();
        v.push(0); // STREAMINFO, not last
        v.extend_from_slice(&[0, 0, 34]);
        v.extend_from_slice(&[0u8; 34]);
        let c = vorbis_block(tags);
        v.push(0x84); // VORBIS_COMMENT, last block
        v.extend_from_slice(&[(c.len() >> 16) as u8, (c.len() >> 8) as u8, c.len() as u8]);
        v.extend_from_slice(&c);
        v
    }

    /// An Ogg Opus stream: the identification page, then the comment
    /// page carrying the same grammar FLAC uses.
    pub fn ogg_opus(tags: &[(&str, &str)]) -> Vec<u8> {
        let page = |body: &[u8], seq: u32| {
            let mut p = b"OggS".to_vec();
            p.push(0); // version
            p.push(if seq == 0 { 2 } else { 0 }); // header type
            p.extend_from_slice(&[0u8; 8]); // granule
            p.extend_from_slice(&1u32.to_le_bytes()); // serial
            p.extend_from_slice(&seq.to_le_bytes());
            p.extend_from_slice(&[0u8; 4]); // crc, unchecked here
            let segs: Vec<u8> = std::iter::repeat_n(255u8, body.len() / 255)
                .chain(std::iter::once((body.len() % 255) as u8))
                .collect();
            p.push(segs.len() as u8);
            p.extend_from_slice(&segs);
            p.extend_from_slice(body);
            p
        };
        let mut id = b"OpusHead".to_vec();
        id.extend_from_slice(&[1, 2, 0, 0, 0x80, 0xBB, 0, 0, 0, 0, 0]);
        let mut comment = b"OpusTags".to_vec();
        comment.extend_from_slice(&vorbis_block(tags));
        let mut v = page(&id, 0);
        v.extend_from_slice(&page(&comment, 1));
        v
    }

    /// An MP3 with an ID3v2.3 tag in front of one frame header. `track`
    /// is written verbatim, so "3/12" and "3" are both testable.
    pub fn mp3_id3v2(title: &str, artist: &str, album: &str, track: &str) -> Vec<u8> {
        let mut frames = Vec::new();
        for (id, text) in [
            (b"TIT2", title),
            (b"TPE1", artist),
            (b"TALB", album),
            (b"TRCK", track),
        ] {
            if text.is_empty() {
                continue;
            }
            let mut body = vec![3u8]; // UTF-8
            body.extend_from_slice(text.as_bytes());
            frames.extend_from_slice(id);
            frames.extend_from_slice(&(body.len() as u32).to_be_bytes());
            frames.extend_from_slice(&[0, 0]);
            frames.extend_from_slice(&body);
        }
        let mut v = b"ID3".to_vec();
        v.extend_from_slice(&[3, 0, 0]);
        let n = frames.len() as u32;
        v.extend_from_slice(&[
            (n >> 21 & 0x7F) as u8,
            (n >> 14 & 0x7F) as u8,
            (n >> 7 & 0x7F) as u8,
            (n & 0x7F) as u8,
        ]);
        v.extend_from_slice(&frames);
        v.extend_from_slice(&MPEG_FRAME);
        v.extend_from_slice(&[0u8; 512]);
        v
    }

    /// An MP3 whose only tag is the 128-byte ID3v1 trailer.
    pub fn mp3_id3v1(title: &str, artist: &str, album: &str, track: u8) -> Vec<u8> {
        let mut v = MPEG_FRAME.to_vec();
        v.extend_from_slice(&[0u8; 1024]);
        let mut tag = b"TAG".to_vec();
        let mut field = |s: &str, n: usize| {
            let mut f = s.as_bytes().to_vec();
            f.resize(n, 0);
            tag.extend_from_slice(&f);
        };
        field(title, 30);
        field(artist, 30);
        field(album, 30);
        tag.extend_from_slice(b"2024"); // year
        let mut comment = vec![0u8; 30];
        comment[29] = track; // v1.1: track in the last byte, 28 left NUL
        tag.extend_from_slice(&comment);
        tag.push(0); // genre
        v.extend_from_slice(&tag);
        v
    }

    fn mp4box(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(kind);
        v.extend_from_slice(body);
        v
    }

    fn ilst_item(kind: &[u8; 4], type_flag: u32, payload: &[u8]) -> Vec<u8> {
        let mut data = type_flag.to_be_bytes().to_vec();
        data.extend_from_slice(&[0u8; 4]); // locale
        data.extend_from_slice(payload);
        mp4box(kind, &mp4box(b"data", &data))
    }

    /// An `M4A` whose `moov` sits AFTER the media data, which is the
    /// layout that makes the top-level walk worth having.
    pub fn m4a(title: &str, artist: &str, album: &str, track: u16) -> Vec<u8> {
        let mut ilst = Vec::new();
        ilst.extend_from_slice(&ilst_item(b"\xA9nam", 1, title.as_bytes()));
        ilst.extend_from_slice(&ilst_item(b"\xA9ART", 1, artist.as_bytes()));
        ilst.extend_from_slice(&ilst_item(b"\xA9alb", 1, album.as_bytes()));
        let mut trkn = vec![0, 0];
        trkn.extend_from_slice(&track.to_be_bytes());
        trkn.extend_from_slice(&[0, 0, 0, 0]);
        ilst.extend_from_slice(&ilst_item(b"trkn", 0, &trkn));
        let mut meta = vec![0u8; 4]; // version and flags
        meta.extend_from_slice(&mp4box(b"ilst", &ilst));
        let moov = mp4box(b"udta", &mp4box(b"meta", &meta));

        let mut ftyp = b"M4A \0\0\0\0".to_vec();
        ftyp.extend_from_slice(b"M4A mp42isom");
        let mut v = mp4box(b"ftyp", &ftyp);
        v.extend_from_slice(&mp4box(b"mdat", &[0u8; 256]));
        v.extend_from_slice(&mp4box(b"moov", &moov));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tags(bytes: &[u8]) -> Option<AudioTags> {
        read_tags(&mut Cursor::new(bytes.to_vec()))
    }

    /// The four formats, each carrying the same four facts. One test
    /// rather than four because the interesting thing is that they
    /// AGREE: the naming pass above cannot care which container a track
    /// arrived in.
    #[test]
    fn every_supported_format_reads_the_same_four_facts() {
        let want = AudioTags {
            artist: Some("Some Artist".into()),
            title: Some("A Song Title".into()),
            album: Some("The Album".into()),
            track: Some(7),
        };
        let flac = testtag::flac(&[
            ("TITLE", "A Song Title"),
            ("ARTIST", "Some Artist"),
            ("ALBUM", "The Album"),
            ("TRACKNUMBER", "7/12"),
        ]);
        assert_eq!(sniff_ext(&flac), Some("flac"));
        assert_eq!(tags(&flac).as_ref(), Some(&want));

        let ogg = testtag::ogg_opus(&[
            ("TITLE", "A Song Title"),
            ("ARTIST", "Some Artist"),
            ("ALBUM", "The Album"),
            ("TRACKNUMBER", "07"),
        ]);
        assert_eq!(sniff_ext(&ogg), Some("opus"));
        assert_eq!(tags(&ogg).as_ref(), Some(&want));

        let mp3 = testtag::mp3_id3v2("A Song Title", "Some Artist", "The Album", "7/12");
        assert_eq!(sniff_ext(&mp3), Some("mp3"));
        assert_eq!(tags(&mp3).as_ref(), Some(&want));

        let m4a = testtag::m4a("A Song Title", "Some Artist", "The Album", 7);
        assert_eq!(sniff_ext(&m4a), Some("m4a"));
        assert_eq!(tags(&m4a).as_ref(), Some(&want));
    }

    /// The ID3v1 trailer is the one tag that is not at the front, so it
    /// is the one a head-only read would miss.
    #[test]
    fn an_id3v1_trailer_is_found_at_the_end() {
        let mp3 = testtag::mp3_id3v1("Old Rip", "Some Artist", "The Album", 4);
        assert_eq!(sniff_ext(&mp3), Some("mp3"));
        let t = tags(&mp3).expect("v1 trailer read");
        assert_eq!(t.title.as_deref(), Some("Old Rip"));
        assert_eq!(t.track, Some(4));
    }

    /// ID3 text frames carry their own encoding byte, and UTF-16 with a
    /// BOM is what Windows taggers write.
    #[test]
    fn id3_text_reads_all_four_encodings() {
        assert_eq!(id3_text(&[3, b'h', b'i']).as_deref(), Some("hi"));
        assert_eq!(
            id3_text(&[0, 0xC9, b't', b'e']).as_deref(),
            Some("\u{c9}te")
        );
        let utf16le = [1u8, 0xFF, 0xFE, b'h', 0, b'i', 0];
        assert_eq!(id3_text(&utf16le).as_deref(), Some("hi"));
        let utf16be = [2u8, 0, b'h', 0, b'i'];
        assert_eq!(id3_text(&utf16be).as_deref(), Some("hi"));
        // A declared BOM that is not one: refused rather than read as
        // whichever endianness happened to be assumed.
        assert_eq!(id3_text(&[1, b'h', 0, b'i', 0]), None);
        assert_eq!(id3_text(&[9, b'h', b'i']), None);
    }

    /// A value that cannot be a filename is not one. Every one of these
    /// arrives as somebody's chosen bytes.
    #[test]
    fn a_value_has_to_survive_cleaning() {
        assert_eq!(clean("  Title  ").as_deref(), Some("Title"));
        assert_eq!(clean("Title\0\0").as_deref(), Some("Title"));
        assert_eq!(clean(""), None);
        assert_eq!(clean("   "), None);
        assert_eq!(clean("two\nlines"), None);
        assert_eq!(clean(&"x".repeat(VALUE_MAX + 1)), None);
        assert_eq!(
            clean(&"x".repeat(VALUE_MAX)).map(|s| s.len()),
            Some(VALUE_MAX)
        );

        assert_eq!(track_of("7"), Some(7));
        assert_eq!(track_of("07/12"), Some(7));
        assert_eq!(track_of("7 of 12"), Some(7));
        assert_eq!(track_of("0"), None);
        assert_eq!(track_of("1000"), None);
        assert_eq!(track_of("A"), None);
        assert_eq!(track_of(""), None);
    }

    /// An ID3 tag is not proof of an MP3 - it prefixes AAC too - so the
    /// bytes behind it have to sync as an MPEG Layer III frame.
    #[test]
    fn a_tag_without_a_frame_behind_it_is_not_an_mp3() {
        let mut v = testtag::mp3_id3v2("T", "A", "B", "1");
        assert_eq!(sniff_ext(&v), Some("mp3"));
        // Same tag, ADTS AAC behind it instead of an MPEG frame.
        let cut = v.len() - 516;
        v.truncate(cut);
        v.extend_from_slice(&[0xFF, 0xF1, 0x50, 0x80]);
        v.extend_from_slice(&[0u8; 512]);
        assert_eq!(sniff_ext(&v), None, "layer bits say this is not Layer III");
    }

    /// Nothing here may accept a file it cannot actually read, and
    /// nothing here may panic on one. Every input is a shape a hostile
    /// post can produce.
    #[test]
    fn malformed_input_answers_none_and_never_panics() {
        assert_eq!(tags(b"not audio at all, just some bytes"), None);
        assert_eq!(sniff_ext(b"GIF89a and then some padding"), None);
        assert_eq!(sniff_ext(b"short"), None);

        // A FLAC whose comment block declares more bytes than the file
        // holds: refused, not read past.
        let mut flac = testtag::flac(&[("TITLE", "T")]);
        let n = flac.len();
        flac[n - 4 - 12 - 4 - "TITLE=T".len()] = 0xFF; // corrupt a length
        let _ = tags(&flac);

        let mut lying = b"fLaC".to_vec();
        lying.push(0x84);
        lying.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // 16 MiB of comment
        lying.extend_from_slice(&[0u8; 64]);
        assert_eq!(tags(&lying), None);

        // A vorbis comment declaring more entries than the budget.
        let mut greedy = b"fLaC".to_vec();
        let mut body = 0u32.to_le_bytes().to_vec(); // no vendor
        body.extend_from_slice(&u32::MAX.to_le_bytes()); // entry count
        greedy.push(0x84);
        greedy.extend_from_slice(&[0, 0, body.len() as u8]);
        greedy.extend_from_slice(&body);
        assert_eq!(tags(&greedy), None);

        // An MP4 whose moov box claims to run past the end of the
        // file. The top-level walk refuses it rather than reading
        // whatever follows.
        let mut m4a = testtag::m4a("T", "A", "B", 1);
        let at = m4a
            .windows(4)
            .position(|w| w == b"moov")
            .expect("fixture carries a moov")
            - 4;
        m4a[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(tags(&m4a), None);

        // Every prefix of every fixture, which is what a job that lost
        // its tail actually leaves on disk.
        for f in [
            testtag::flac(&[("TITLE", "T")]),
            testtag::m4a("T", "A", "B", 1),
            testtag::mp3_id3v2("T", "A", "B", "1"),
            testtag::ogg_opus(&[("TITLE", "T")]),
        ] {
            for cut in 0..f.len() {
                let _ = tags(&f[..cut]);
            }
        }
    }

    /// An empty tag block is not a name: a file whose comment carries
    /// only fields this module ignores must read as untagged, or the
    /// caller would rename it to nothing.
    #[test]
    fn a_tag_block_with_nothing_useful_reads_as_none() {
        let flac = testtag::flac(&[("GENRE", "Jazz"), ("DATE", "2024")]);
        assert_eq!(tags(&flac), None);
        let empty = testtag::flac(&[("TITLE", "   ")]);
        assert_eq!(tags(&empty), None);
    }
}
