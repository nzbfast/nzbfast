//! Minimal ISO base media (MP4/M4V/MOV) header probe, the sibling of
//! [`crate::mkv`]: runtime, dimensions, codecs and track languages.
//!
//! MP4 is the second container obfuscated posts actually arrive in, and
//! its facts live in the same three places every time: `mvhd` for the
//! movie duration, each track's `mdhd` for its language, and each
//! track's `stsd` for its codec. That is all this reads. No seeking
//! beyond the one head/tail read the caller already did, no external
//! tools.
//!
//! Untrusted input, same rules as the EBML walk: pure over a slice,
//! every offset checked, depth-capped, box-budgeted, and no allocation
//! that a hostile size field can drive.
//!
//! One asymmetry with Matroska worth knowing: `moov` is not required to
//! be at the front. A file muxed without faststart has `ftyp`, then a
//! multi-gigabyte `mdat`, then `moov` at the very end - so
//! [`crate::media::probe`] falls back to reading the tail and calling
//! [`facts_unanchored`], which walks a window that begins mid-box.

use crate::media::{MediaFacts, normalise_codec, normalise_lang, push_unique};

pub(crate) const MAX_DEPTH: usize = 8;
const MAX_BOXES: usize = 20_000;

/// Containers we descend into. Everything else is skipped by its size,
/// so an unknown or hostile box costs one header read and a bounds
/// check.
const CONTAINERS: [&[u8; 4]; 6] = [b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta"];

/// Handler types, from `hdlr`, that tell us what a track carries.
const HDLR_VIDEO: &[u8; 4] = b"vide";
const HDLR_AUDIO: &[u8; 4] = b"soun";

/// A box header: (type, body start, body end, header length). `end` is
/// clamped to the buffer, so every caller may slice with it directly.
struct BoxHdr {
    kind: [u8; 4],
    body: usize,
    end: usize,
}

/// Read the box header at `at`. `None` for anything that does not
/// describe a box wholly inside `b` - which is also how the walk stops
/// at the end of a truncated head read.
fn read_box(b: &[u8], at: usize, limit: usize) -> Option<BoxHdr> {
    if at + 8 > limit || at + 8 > b.len() {
        return None;
    }
    let size32 = u32::from_be_bytes(b[at..at + 4].try_into().ok()?) as u64;
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&b[at + 4..at + 8]);
    let (size, hdr) = match size32 {
        // 1 means the real size is a 64-bit largesize after the type.
        1 => {
            if at + 16 > limit || at + 16 > b.len() {
                return None;
            }
            (
                u64::from_be_bytes(b[at + 8..at + 16].try_into().ok()?),
                16usize,
            )
        }
        // 0 means "to the end of the enclosing box" - legal only on the
        // last one.
        0 => ((limit - at) as u64, 8usize),
        _ => (size32, 8usize),
    };
    // A box cannot be smaller than its own header, and one that claims
    // to run past its parent is a lie we do not follow.
    if size < hdr as u64 {
        return None;
    }
    let end = at.checked_add(usize::try_from(size).ok()?)?;
    if end > limit {
        return None;
    }
    Some(BoxHdr {
        kind,
        body: at + hdr,
        end: end.min(b.len()),
    })
}

/// Does this look like an ISO base media file? Checked before spending a
/// second read on the tail, so a non-MP4 costs exactly one.
pub fn looks_like_mp4(b: &[u8]) -> bool {
    // `ftyp` is the required first box; `styp`, `moov` and `free`/`skip`
    // lead real files in the wild too.
    read_box(b, 0, b.len()).is_some_and(|h| {
        matches!(
            &h.kind,
            b"ftyp" | b"styp" | b"moov" | b"free" | b"skip" | b"wide"
        )
    })
}

/// Parse an MP4 head. `None` when the buffer does not open with a valid
/// box, or when nothing useful was found.
pub fn facts(b: &[u8]) -> Option<MediaFacts> {
    if !looks_like_mp4(b) {
        return None;
    }
    walk(b, 0)
}

/// Parse a window that begins at an arbitrary offset - the tail read for
/// a file whose `moov` sits at the end. The window almost certainly
/// starts inside `mdat`, so there is no box boundary at offset 0 to walk
/// from: find the `moov` header by scanning for its 4-byte type and
/// stepping back to its size field, then walk from there.
///
/// Scanning for a magic in payload bytes can land on a false positive
/// (an `mdat` full of video happens to contain "moov"), so each
/// candidate must parse as a well-formed box before it is walked, and a
/// candidate that yields nothing lets the scan continue.
pub fn facts_unanchored(b: &[u8]) -> Option<MediaFacts> {
    let mut from = 4usize;
    let mut tried = 0;
    while let Some(rel) = b.get(from..).and_then(|w| find(w, b"moov")) {
        let at = from + rel;
        // The type field sits 4 bytes into the header.
        let start = at - 4;
        if let Some(h) = read_box(b, start, b.len())
            && &h.kind == b"moov"
            && let Some(f) = walk(b, start)
        {
            return Some(f);
        }
        from = at + 4;
        tried += 1;
        if tried > 64 {
            break; // a buffer engineered to be all "moov" is not a file
        }
    }
    None
}

fn find(hay: &[u8], needle: &[u8; 4]) -> Option<usize> {
    hay.windows(4).position(|w| w == needle)
}

/// Per-track state, judged when the `trak` closes: a `hdlr` may arrive
/// after the `stsd` that needs it.
#[derive(Default)]
struct Track {
    handler: Option<[u8; 4]>,
    codec: Option<String>,
    lang: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    /// Track duration in seconds, from `mdhd`. Only used when the movie
    /// header did not give one.
    secs: Option<f64>,
}

fn walk(b: &[u8], start: usize) -> Option<MediaFacts> {
    let mut info = MediaFacts {
        container: "mp4",
        ..MediaFacts::default()
    };
    // (box type, end offset) for every container we are inside. Same
    // shape as the EBML walk, for the same reason: a `trak` is judged
    // when it closes, because its `hdlr` may arrive after its `stsd`.
    let mut stack: Vec<([u8; 4], usize)> = Vec::new();
    let mut track = Track::default();
    let mut longest_track: Option<f64> = None;

    let mut pos = start;
    let top = b.len();
    for _ in 0..MAX_BOXES {
        while let Some(&(kind, end)) = stack.last() {
            if pos < end {
                break;
            }
            if &kind == b"trak" {
                file_track(&mut info, &mut track, &mut longest_track);
            }
            stack.pop();
        }
        let limit = stack.last().map_or(top, |&(_, end)| end);
        if pos >= limit {
            break;
        }
        let Some(h) = read_box(b, pos, limit) else {
            break;
        };
        // A box that does not advance would spin the walk forever;
        // read_box already refuses size < header, so this is belt and
        // braces against a future edit of it.
        if h.end <= pos {
            break;
        }

        if CONTAINERS.contains(&&h.kind) {
            if stack.len() >= MAX_DEPTH {
                break;
            }
            if &h.kind == b"trak" {
                track = Track::default();
            }
            stack.push((h.kind, h.end));
            pos = h.body;
            continue;
        }

        let payload = b.get(h.body..h.end).unwrap_or(&[]);
        match &h.kind {
            b"mvhd" => {
                if let Some(secs) = mvhd_duration(payload) {
                    info.duration_secs = Some(secs);
                }
            }
            b"mdhd" => {
                let (secs, lang) = mdhd(payload);
                track.secs = secs;
                track.lang = lang;
            }
            // version/flags(4) + pre_defined(4) + handler_type(4)
            b"hdlr" => {
                if payload.len() >= 12 {
                    let mut k = [0u8; 4];
                    k.copy_from_slice(&payload[8..12]);
                    track.handler = Some(k);
                }
            }
            b"stsd" => {
                if let Some((codec, dims)) = stsd_first_entry(payload) {
                    track.codec = Some(codec);
                    if let Some((w, h)) = dims {
                        track.width = Some(w);
                        track.height = Some(h);
                    }
                }
            }
            _ => {}
        }
        pos = h.end;
    }
    // Anything still open at the end of the buffer: file the track in
    // hand, which is the common case for a head read that stopped
    // mid-`moov`.
    file_track(&mut info, &mut track, &mut longest_track);

    // A movie header duration of zero (some muxers write it) falls back
    // to the longest media track, which is what a player shows.
    if info.duration_secs.is_none_or(|d| d <= 0.0) {
        info.duration_secs = longest_track;
    }
    let empty = info.duration_secs.is_none()
        && info.width.is_none()
        && info.height.is_none()
        && info.video_codec.is_none()
        && info.audio_codecs.is_empty()
        && info.audio_langs.is_empty()
        && info.sub_langs.is_empty();
    (!empty).then_some(info)
}

/// A finished track joins the facts, classified by its handler.
/// Subtitle handlers are several fourccs (`sbtl`, `text`, `subt`) and
/// muxers disagree, so subtitles are what is left over rather than an
/// explicit list - a handler we do not know contributes no language,
/// which is the safe direction.
fn file_track(info: &mut MediaFacts, track: &mut Track, longest: &mut Option<f64>) {
    let t = std::mem::take(track);
    if t.handler.is_none() && t.codec.is_none() && t.lang.is_none() {
        return;
    }
    if let Some(s) = t.secs
        && s.is_finite()
        && s > 0.0
        && longest.is_none_or(|l| s > l)
    {
        *longest = Some(s);
    }
    let lang = t.lang.as_deref().and_then(normalise_lang);
    match t.handler.as_ref() {
        Some(HDLR_VIDEO) => {
            if info.video_codec.is_none() {
                info.video_codec = t.codec.as_deref().map(normalise_codec);
            }
            if info.width.is_none() {
                info.width = t.width;
                info.height = t.height;
            }
        }
        Some(HDLR_AUDIO) => {
            if let Some(c) = t.codec.as_deref() {
                push_unique(&mut info.audio_codecs, normalise_codec(c));
            }
            if let Some(l) = lang {
                push_unique(&mut info.audio_langs, l);
            }
        }
        Some(b"sbtl" | b"text" | b"subt" | b"clcp") => {
            if let Some(l) = lang {
                push_unique(&mut info.sub_langs, l);
            }
        }
        _ => {}
    }
}

/// `mvhd` duration in seconds. Version 0 writes 32-bit fields, version 1
/// 64-bit ones, and the layout differs by more than the widths - so both
/// are spelled out rather than computed from an offset.
fn mvhd_duration(p: &[u8]) -> Option<f64> {
    let version = *p.first()?;
    let (scale, dur) = match version {
        // version/flags(4) creation(4) modification(4) timescale(4) duration(4)
        0 if p.len() >= 20 => (
            u32::from_be_bytes(p[12..16].try_into().ok()?) as u64,
            u32::from_be_bytes(p[16..20].try_into().ok()?) as u64,
        ),
        // version/flags(4) creation(8) modification(8) timescale(4) duration(8)
        1 if p.len() >= 32 => (
            u32::from_be_bytes(p[20..24].try_into().ok()?) as u64,
            u64::from_be_bytes(p[24..32].try_into().ok()?),
        ),
        _ => return None,
    };
    scale_secs(scale, dur)
}

/// `mdhd` gives a track its own timescale/duration and its language, the
/// latter packed as three 5-bit letters offset by 0x60 ("und" is the
/// no-answer value and normalises away).
fn mdhd(p: &[u8]) -> (Option<f64>, Option<String>) {
    let Some(&version) = p.first() else {
        return (None, None);
    };
    let (scale, dur, lang_at) = match version {
        0 if p.len() >= 22 => (
            u32::from_be_bytes(p[12..16].try_into().unwrap()) as u64,
            u32::from_be_bytes(p[16..20].try_into().unwrap()) as u64,
            20usize,
        ),
        1 if p.len() >= 34 => (
            u32::from_be_bytes(p[20..24].try_into().unwrap()) as u64,
            u64::from_be_bytes(p[24..32].try_into().unwrap()),
            32usize,
        ),
        _ => return (None, None),
    };
    let packed = u16::from_be_bytes(p[lang_at..lang_at + 2].try_into().unwrap());
    let mut code = String::new();
    for shift in [10, 5, 0] {
        let c = ((packed >> shift) & 0x1F) as u8 + 0x60;
        if !c.is_ascii_lowercase() {
            code.clear();
            break;
        }
        code.push(c as char);
    }
    (scale_secs(scale, dur), (!code.is_empty()).then_some(code))
}

fn scale_secs(scale: u64, dur: u64) -> Option<f64> {
    if scale == 0 || dur == 0 {
        return None;
    }
    let secs = dur as f64 / scale as f64;
    secs.is_finite().then_some(secs)
}

/// The first sample entry in a `stsd`: its 4-byte format is the codec,
/// and for a video entry the visual sample entry carries the coded
/// dimensions 24 bytes in.
fn stsd_first_entry(p: &[u8]) -> Option<(String, Option<(u32, u32)>)> {
    // version/flags(4) entry_count(4), then entries.
    if p.len() < 16 {
        return None;
    }
    let entry_size = u32::from_be_bytes(p[8..12].try_into().ok()?) as usize;
    if entry_size < 8 || 8 + entry_size > p.len() {
        return None;
    }
    let entry = &p[8..8 + entry_size];
    let fourcc = std::str::from_utf8(&entry[4..8]).ok()?;
    if !fourcc.is_ascii() {
        return None;
    }
    // VisualSampleEntry: 8 header + 6 reserved + 2 data_ref + 16 pre/
    // reserved = 32, then width u16, height u16.
    let dims = (entry.len() >= 36).then(|| {
        (
            u32::from(u16::from_be_bytes(entry[32..34].try_into().unwrap())),
            u32::from(u16::from_be_bytes(entry[34..36].try_into().unwrap())),
        )
    });
    // A zero-by-zero pair is an audio entry's reserved bytes, not a size.
    let dims = dims.filter(|(w, h)| *w > 0 && *h > 0);
    Some((fourcc.trim().to_string(), dims))
}

/// A minimal, valid MP4 for tests: one video track, one audio track per
/// entry in `audio`, and one subtitle track per entry in `subs`.
#[cfg(test)]
fn test_mp4(
    duration_secs: f64,
    dims: (u32, u32),
    video_codec: &[u8; 4],
    audio: &[(&[u8; 4], &str)],
    subs: &[&str],
) -> Vec<u8> {
    fn bx(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(kind);
        v.extend_from_slice(body);
        v
    }
    fn pack_lang(code: &str) -> [u8; 2] {
        let mut packed: u16 = 0;
        for (i, c) in code.bytes().take(3).enumerate() {
            packed |= u16::from(c - 0x60) << (10 - 5 * i);
        }
        packed.to_be_bytes()
    }
    const SCALE: u32 = 1000;
    let units = (duration_secs * f64::from(SCALE)) as u32;

    let mut mvhd = vec![0u8; 4]; // version 0 + flags
    mvhd.extend([0u8; 8]); // creation, modification
    mvhd.extend(SCALE.to_be_bytes());
    mvhd.extend(units.to_be_bytes());
    mvhd.extend([0u8; 80]); // rate, volume, matrix, next track id

    let trak = |handler: &[u8; 4], fourcc: &[u8; 4], lang: &str, visual: bool| {
        let mut mdhd = vec![0u8; 4];
        mdhd.extend([0u8; 8]);
        mdhd.extend(SCALE.to_be_bytes());
        mdhd.extend(units.to_be_bytes());
        mdhd.extend(pack_lang(lang));
        mdhd.extend([0u8; 2]); // pre_defined

        let mut hdlr = vec![0u8; 8];
        hdlr.extend_from_slice(handler);
        hdlr.extend([0u8; 12]);

        let mut entry = vec![0u8; 8];
        entry[4..8].copy_from_slice(fourcc);
        entry.extend([0u8; 24]); // reserved through pre_defined
        if visual {
            entry.extend(u16::try_from(dims.0).unwrap_or(0).to_be_bytes());
            entry.extend(u16::try_from(dims.1).unwrap_or(0).to_be_bytes());
            entry.extend([0u8; 50]);
        } else {
            entry.extend([0u8; 12]);
        }
        let size = u32::try_from(entry.len()).unwrap();
        entry[0..4].copy_from_slice(&size.to_be_bytes());

        let mut stsd = vec![0u8; 4];
        stsd.extend(1u32.to_be_bytes());
        stsd.extend(entry);

        let stbl = bx(b"stbl", &bx(b"stsd", &stsd));
        let minf = bx(b"minf", &stbl);
        let mut mdia = bx(b"mdhd", &mdhd);
        mdia.extend(bx(b"hdlr", &hdlr));
        mdia.extend(minf);
        bx(b"trak", &bx(b"mdia", &mdia))
    };

    let mut moov = bx(b"mvhd", &mvhd);
    moov.extend(trak(HDLR_VIDEO, video_codec, "und", true));
    for (fourcc, lang) in audio {
        moov.extend(trak(HDLR_AUDIO, fourcc, lang, false));
    }
    for lang in subs {
        moov.extend(trak(b"sbtl", b"tx3g", lang, false));
    }
    let mut out = bx(b"ftyp", b"isom\0\0\x02\0isomiso2avc1mp41");
    out.extend(bx(b"moov", &moov));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_mp4_yields_runtime_codecs_and_languages() {
        let b = test_mp4(6480.0, (1920, 1080), b"avc1", &[(b"ec-3", "eng")], &["fre"]);
        let f = facts(&b).unwrap();
        assert_eq!(f.container, "mp4");
        assert!((f.duration_secs.unwrap() - 6480.0).abs() < 1.0);
        assert_eq!(f.runtime_minutes(), Some(108));
        assert_eq!((f.width, f.height), (Some(1920), Some(1080)));
        assert_eq!(f.video_codec.as_deref(), Some("h264"));
        assert_eq!(f.audio_codecs, vec!["eac3"]);
        assert_eq!(f.audio_langs, vec!["en"]);
        assert_eq!(f.sub_langs, vec!["fr"]);
        assert_eq!(f.original_language(), Some("en"));
    }

    #[test]
    fn a_dual_audio_mp4_offers_no_original_language() {
        let b = test_mp4(
            6000.0,
            (1280, 720),
            b"hvc1",
            &[(b"mp4a", "eng"), (b"ac-3", "jpn")],
            &[],
        );
        let f = facts(&b).unwrap();
        assert_eq!(f.video_codec.as_deref(), Some("h265"));
        assert_eq!(f.audio_codecs, vec!["aac", "ac3"]);
        assert_eq!(f.audio_langs, vec!["en", "ja"]);
        assert_eq!(f.original_language(), None);
    }

    #[test]
    fn an_untagged_audio_track_asserts_nothing() {
        // "und" is the mdhd no-answer value. Treating it as a language
        // would hand the catalogue filter a fact nobody wrote down.
        let b = test_mp4(5400.0, (1920, 800), b"av01", &[(b"mp4a", "und")], &[]);
        let f = facts(&b).unwrap();
        assert_eq!(f.video_codec.as_deref(), Some("av1"));
        assert!(f.audio_langs.is_empty());
        assert_eq!(f.original_language(), None);
    }

    #[test]
    fn a_tail_placed_moov_parses_from_an_arbitrary_offset() {
        // No faststart: ftyp, a big mdat, then moov. The tail window the
        // caller reads begins inside mdat, at no box boundary at all.
        let b = test_mp4(6480.0, (1920, 1080), b"avc1", &[(b"ec-3", "eng")], &[]);
        let moov_at = find(&b, b"moov").unwrap() - 4;
        let mut file = b[..find(&b, b"moov").unwrap() - 4].to_vec();
        // 64 KiB of payload that happens to contain the magic, to prove
        // the scan does not stop at the first false positive.
        let mut mdat_body = vec![0x11u8; 65536];
        mdat_body[1000..1004].copy_from_slice(b"moov");
        let mut mdat = ((mdat_body.len() + 8) as u32).to_be_bytes().to_vec();
        mdat.extend_from_slice(b"mdat");
        mdat.extend_from_slice(&mdat_body);
        file.extend(mdat);
        file.extend_from_slice(&b[moov_at..]);

        // The head walk finds nothing beyond ftyp/mdat...
        assert_eq!(facts(&file[..2048]), None);
        // ...and the unanchored tail walk recovers everything.
        let f = facts_unanchored(&file[512..]).unwrap();
        assert_eq!(f.runtime_minutes(), Some(108));
        assert_eq!(f.video_codec.as_deref(), Some("h264"));
        assert_eq!(f.audio_langs, vec!["en"]);
    }

    #[test]
    fn a_zero_mvhd_duration_falls_back_to_the_longest_track() {
        let mut b = test_mp4(6480.0, (1920, 1080), b"avc1", &[(b"mp4a", "eng")], &[]);
        // Zero the mvhd duration the way some muxers do, leaving the
        // per-track mdhd durations intact.
        let at = find(&b, b"mvhd").unwrap() + 4 + 16;
        b[at..at + 4].copy_from_slice(&0u32.to_be_bytes());
        let f = facts(&b).unwrap();
        assert_eq!(f.runtime_minutes(), Some(108));
    }

    #[test]
    fn hostile_shapes_return_none_not_panic() {
        assert_eq!(facts(b""), None);
        assert_eq!(facts(b"\x00\x00\x00\x08ftyp"), None);
        assert_eq!(facts(b"not an mp4 at all....."), None);
        // A box claiming a gigantic size, and one claiming zero.
        assert_eq!(facts(b"\xff\xff\xff\xffftypisom"), None);
        assert_eq!(facts(b"\x00\x00\x00\x00ftypisom"), None);
        // Truncation at every offset must not panic.
        let b = test_mp4(6480.0, (1920, 1080), b"avc1", &[(b"ec-3", "eng")], &["eng"]);
        for cut in 0..b.len() {
            let _ = facts(&b[..cut]);
            let _ = facts_unanchored(&b[..cut]);
        }
        // Nor must a buffer built entirely out of the magic we scan for.
        let all_magic = b"moov".repeat(4096);
        assert_eq!(facts_unanchored(&all_magic), None);
    }
}
