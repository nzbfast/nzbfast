//! Minimal Matroska/WebM header probe: duration, pixel dimensions, the
//! container's own Title, and the track layout (codecs and languages).
//!
//! The renamer's resolution tag comes from whatever the POSTER wrote in
//! the subject, and posters lie - a "1080p" name over a 720p stream gets
//! stamped onto the final filename. The container itself knows. This is
//! a deliberately tiny EBML walk that reads only what a name can be
//! checked, recovered or synthesised from: no external tools (the
//! no-bundled-ffmpeg rule), no seeking, no allocation beyond the head
//! read.
//!
//! The Title is here because it survives obfuscation. A muxer writes
//! Segment>Info>Title once, at encode time, and the reposter who
//! scrambles the subject line and the filenames almost never reaches
//! inside the container to clear it - so an unnameable post frequently
//! carries its own real release name a few KB into the payload.
//!
//! Two entry points over ONE walk. [`parse`] answers what the renamer
//! and the identity oracles ask (how long, how wide, what it calls
//! itself); [`facts`] returns the same walk's full result, adding the
//! track layout that synthesised naming searches a film catalogue by
//! when the Title is absent too. See [`crate::media`].
//!
//! Untrusted input: completed downloads are attacker-shaped bytes, so
//! both are pure over a slice, every offset is checked, containers are
//! depth-capped, and the walk is bounded by an element budget. The fuzz
//! harness drives `parse` directly (fuzz_targets/mkv_parse.rs).

/// What the head of the file said. Fields are independent - a muxer that
/// wrote no Duration still yields dimensions, and vice versa.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MkvInfo {
    pub duration_secs: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Segment>Info>Title, verbatim apart from trimming and the length
    /// cap. Judging whether it reads as a release name is the caller's
    /// job (`release::looks_like_release_name`) - the parser reports
    /// what the container said, not what it means.
    pub title: Option<String>,
}

/// How much of the file `probe` reads. Info and Tracks sit in the first
/// few KB of every ordinary mux; the slack is for muxers that front-load
/// SeekHead padding, attachments or chapter furniture before them.
const HEAD: u64 = 4 << 20;

/// Containers we descend into. Everything else is skipped by size, so an
/// unknown or hostile element costs one size read and a bounds check.
const SEGMENT: u32 = 0x1853_8067;
const INFO: u32 = 0x1549_A966;
const TRACKS: u32 = 0x1654_AE6B;
const TRACK_ENTRY: u32 = 0xAE;
const VIDEO: u32 = 0xE0;
// Leaves.
const EBML_HEAD: u32 = 0x1A45_DFA3;
/// The first payload container. Never descended into - it is here only
/// because RFC 9559 §5.1.3 permits it to carry an UNKNOWN size (a
/// live/pipe mux cannot backfill the length), and reaching it means the
/// header furniture we came for is behind us.
const CLUSTER: u32 = 0x1F43_B675;
const TIMESTAMP_SCALE: u32 = 0x2A_D7B1;
const DURATION: u32 = 0x4489;
const TITLE: u32 = 0x7BA9;
const TRACK_TYPE: u32 = 0x83;
const PIXEL_WIDTH: u32 = 0xB0;
const PIXEL_HEIGHT: u32 = 0xBA;
const CODEC_ID: u32 = 0x86;
const LANGUAGE: u32 = 0x22_B59C;
/// Matroska 4 replaced `Language` with a BCP 47 tag. When a mux writes
/// both they can disagree, and the newer element is the one the muxer
/// meant - see the TrackEntry flush.
const LANGUAGE_BCP47: u32 = 0x22_B59D;

/// TrackType values we care about. 1 video, 2 audio, 0x11 subtitle;
/// everything else (buttons, logos, control tracks) is skipped.
const TRACK_VIDEO: u64 = 1;
const TRACK_AUDIO: u64 = 2;
const TRACK_SUBTITLE: u64 = 0x11;

const MAX_DEPTH: usize = 8;
const MAX_ELEMENTS: usize = 10_000;

/// Longest CodecID or Language payload we will copy out of a leaf.
/// Both are short spec-defined strings; a megabyte-long "language" is a
/// hostile file trying to make us allocate, not a mux.
const MAX_TAG: usize = 64;

/// Longest Title we will carry out of a container. Real ones are a
/// release name (under 120 characters); the element is a length-prefixed
/// UTF-8 string with no other bound, so a hostile mux could declare a
/// megabyte of it and we would allocate all of it for a field whose only
/// consumer is a filename.
const MAX_TITLE: usize = 200;

/// Read the head of `path` and parse it. `None` means "not a Matroska
/// file we could read", never an error worth reporting - the caller's
/// fallback is the filename claim it already had.
pub fn probe(path: &std::path::Path) -> Option<MkvInfo> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut head = Vec::new();
    f.take(HEAD).read_to_end(&mut head).ok()?;
    parse(&head)
}

/// One TrackEntry's fields as they are read. A muxer orders them freely,
/// so the entry is judged when it CLOSES, not as the leaves arrive.
#[derive(Default)]
struct Track {
    kind: Option<u64>,
    width: Option<u32>,
    height: Option<u32>,
    codec: Option<String>,
    lang: Option<String>,
    lang_bcp47: Option<String>,
}

/// EBML id: length from the leading-zero count of the first byte, value
/// kept WITH its marker bits, the way ids are written in the spec.
fn read_id(b: &[u8], at: usize) -> Option<(u32, usize)> {
    let first = *b.get(at)?;
    let len = (first.leading_zeros() as usize) + 1;
    if len > 4 || at + len > b.len() {
        return None;
    }
    let mut id: u32 = 0;
    for i in 0..len {
        id = (id << 8) | u32::from(b[at + i]);
    }
    Some((id, len))
}

/// EBML size vint: marker bit stripped. `None` in the value slot means
/// the all-ones "unknown size" - legal only on Segment, where it means
/// "to end of file".
fn read_size(b: &[u8], at: usize) -> Option<(Option<u64>, usize)> {
    let first = *b.get(at)?;
    let len = (first.leading_zeros() as usize) + 1;
    if len > 8 || at + len > b.len() {
        return None;
    }
    let mut v: u64 = u64::from(first) & (0xFF >> len);
    for i in 1..len {
        v = (v << 8) | u64::from(b[at + i]);
    }
    let all_ones = (1u64 << (7 * len)) - 1;
    Some(((v != all_ones).then_some(v), len))
}

fn read_uint(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 8 {
        return None;
    }
    Some(b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x)))
}

/// Segment>Info>Title: a UTF-8 string, null-padded in some muxes.
///
/// Lossy on purpose. The bytes come off the wire, and a Title that is
/// half-valid UTF-8 is still worth reading - the caller decides whether
/// what came out looks like a release name, and a replacement character
/// is exactly the kind of thing that makes it decide no.
fn read_title(b: &[u8]) -> Option<String> {
    let b = &b[..b.len().min(MAX_TITLE)];
    let end = b.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
    // Control characters are not part of any real title and would go
    // straight into a filename; drop them rather than sanitising later.
    let s: String = String::from_utf8_lossy(&b[..end])
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let s = strip_muxer_credit(s.trim());
    (!s.is_empty()).then(|| s.to_string())
}

/// Drop a repacker's signature from the end of a Title.
///
/// The known shape is `", RMZ.cr"` - a comma, a space, and the site the
/// repack came from - appended to an otherwise untouched release name.
/// Matched structurally rather than by name so the sibling sites behave
/// the same: the tail after the last comma must be a single bare
/// domain-ish token, which no release name ends with.
pub fn strip_muxer_credit(title: &str) -> &str {
    let Some((head, tail)) = title.rsplit_once(',') else {
        return title;
    };
    let tail = tail.trim();
    let domainish = tail.len() <= 20
        && tail.contains('.')
        && !tail.starts_with('.')
        && !tail.ends_with('.')
        && tail
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    let head = head.trim_end();
    if domainish && !head.is_empty() {
        head
    } else {
        title
    }
}

fn read_float(b: &[u8]) -> Option<f64> {
    match b.len() {
        0 => Some(0.0),
        4 => Some(f64::from(f32::from_be_bytes(b.try_into().ok()?))),
        8 => Some(f64::from_be_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

pub fn parse(b: &[u8]) -> Option<MkvInfo> {
    let f = facts(b)?;
    let info = MkvInfo {
        duration_secs: f.duration_secs,
        width: f.width,
        height: f.height,
        title: f.title,
    };
    // `facts` answers Some for a head that yielded ANY fact, including
    // one that carried only codecs. This entry point's contract is
    // narrower and predates them: None means "nothing I was asked for".
    (info != MkvInfo::default()).then_some(info)
}

/// The full walk: runtime, dimensions, codecs and track languages.
/// `None` on anything that is not a Matroska head we could read, and on
/// a head that yielded no fact at all.
pub fn facts(b: &[u8]) -> Option<crate::media::MediaFacts> {
    use crate::media::{MediaFacts, normalise_codec, normalise_lang, push_unique};

    // The file must open with the EBML header; anything else is not
    // Matroska and not worth walking.
    let (first_id, _) = read_id(b, 0)?;
    if first_id != EBML_HEAD {
        return None;
    }

    let mut info = MediaFacts {
        container: "mkv",
        ..MediaFacts::default()
    };
    let mut scale: f64 = 1_000_000.0; // TimestampScale default, ns
    let mut raw_duration: Option<f64> = None;

    // (container id, end offset) for every container we are inside.
    let mut stack: Vec<(u32, usize)> = Vec::new();
    let mut track = Track::default();

    // A TrackEntry has finished: file what it turned out to be. Split
    // out because the walk closes entries in two places - as it passes
    // their extent, and when the head runs out mid-Tracks.
    fn flush(info: &mut crate::media::MediaFacts, track: &mut Track) {
        let t = std::mem::take(track);
        // Matroska defaults an untagged track to English. We do NOT
        // honour that: an untagged track means the muxer said nothing,
        // and treating silence as "eng" would hand the language filter
        // a fact nobody asserted.
        let lang = t
            .lang_bcp47
            .as_deref()
            .and_then(normalise_lang)
            .or_else(|| t.lang.as_deref().and_then(normalise_lang));
        match t.kind {
            // Only the FIRST video track wins: a second one is cover art
            // or a hostile duplicate.
            Some(TRACK_VIDEO) => {
                if info.width.is_none() && info.height.is_none() {
                    info.width = t.width;
                    info.height = t.height;
                }
                if info.video_codec.is_none() {
                    info.video_codec = t.codec.as_deref().map(normalise_codec);
                }
            }
            Some(TRACK_AUDIO) => {
                if let Some(c) = t.codec.as_deref() {
                    push_unique(&mut info.audio_codecs, normalise_codec(c));
                }
                if let Some(l) = lang {
                    push_unique(&mut info.audio_langs, l);
                }
            }
            Some(TRACK_SUBTITLE) => {
                if let Some(l) = lang {
                    push_unique(&mut info.sub_langs, l);
                }
            }
            _ => {}
        }
    }

    let mut pos = 0usize;
    for _ in 0..MAX_ELEMENTS {
        // Close every container whose extent we have walked past.
        while let Some(&(id, end)) = stack.last() {
            if pos < end {
                break;
            }
            if id == TRACK_ENTRY {
                flush(&mut info, &mut track);
            }
            stack.pop();
        }
        if pos >= b.len() {
            break;
        }

        // A head read that stops inside an element's id/size vint is the
        // same truncation the leaf arm below already handles by breaking
        // and KEEPING what the walk collected - Duration, dimensions,
        // title, track layout. Returning None here threw all of it away
        // purely because the 4 MiB cut landed in a 5-12 byte header
        // rather than in a payload. Downstream, a missing duration reads
        // as "no veto" in the sample sweeper, so a real episode with
        // "sample" in its name could be deleted. The `return None` arms
        // are kept for a structurally invalid vint, which is a different
        // claim from "the buffer ended here".
        let (id, id_len) = match read_id(b, pos) {
            Some(v) => v,
            None if b.len() - pos < 4 => break,
            None => return None,
        };
        let (size, size_len) = match read_size(b, pos + id_len) {
            Some(v) => v,
            None if b.len() - (pos + id_len) < 8 => break,
            None => return None,
        };
        let body = pos + id_len + size_len;
        let end = match size {
            Some(s) => body.checked_add(usize::try_from(s).ok()?)?,
            // Unknown size: tolerated on the Segment alone, running to
            // the end of what we read.
            None if id == SEGMENT => b.len(),
            // An unknown-sized Cluster is legal (RFC 9559 §5.1.3) and a
            // live/pipe mux writes them as a matter of course. It has no
            // parseable end, so the walk STOPS - but it stops with what
            // Info and Tracks already gave us, because the payload
            // starting is not a reason to disbelieve the header.
            // Returning None here threw the duration away, and cleanup
            // reads a missing duration as "no veto": a genuine 45-minute
            // episode with "sample"/"proof" in its name was deleted for
            // being small beside the pack's feature.
            None if id == CLUSTER => break,
            None => return None,
        };

        let descend = matches!(id, SEGMENT | INFO | TRACKS | TRACK_ENTRY | VIDEO);
        if descend {
            if stack.len() >= MAX_DEPTH {
                return None;
            }
            if id == TRACK_ENTRY {
                track = Track::default();
            }
            stack.push((id, end.min(b.len())));
            pos = body;
            continue;
        }

        // Leaf: the payload must be inside what we read to be believed.
        if end <= b.len() {
            let payload = &b[body..end];
            match id {
                TIMESTAMP_SCALE => {
                    if let Some(v) = read_uint(payload)
                        && v > 0
                    {
                        scale = v as f64;
                    }
                }
                DURATION => raw_duration = read_float(payload),
                // First Title wins. A Segment carries exactly one Info
                // in any legal mux, so a second is a duplicate or a
                // hostile override of what we already believed.
                TITLE if info.title.is_none() => info.title = read_title(payload),
                TRACK_TYPE => track.kind = read_uint(payload),
                PIXEL_WIDTH => track.width = read_uint(payload).and_then(|v| u32::try_from(v).ok()),
                PIXEL_HEIGHT => {
                    track.height = read_uint(payload).and_then(|v| u32::try_from(v).ok())
                }
                CODEC_ID => track.codec = read_tag(payload),
                LANGUAGE => track.lang = read_tag(payload),
                LANGUAGE_BCP47 => track.lang_bcp47 = read_tag(payload),
                _ => {}
            }
            pos = end;
        } else {
            // Truncated leaf (the head read stopped mid-file): keep what
            // we have.
            break;
        }
    }

    // Flush containers still open at the end of the head.
    while let Some((id, _)) = stack.pop() {
        if id == TRACK_ENTRY {
            flush(&mut info, &mut track);
        }
    }

    if let Some(d) = raw_duration
        && d.is_finite()
        && d >= 0.0
    {
        let secs = d * scale / 1e9;
        if secs.is_finite() {
            info.duration_secs = Some(secs);
        }
    }
    let empty = info.duration_secs.is_none()
        && info.width.is_none()
        && info.height.is_none()
        && info.title.is_none()
        && info.video_codec.is_none()
        && info.audio_codecs.is_empty()
        && info.audio_langs.is_empty()
        && info.sub_langs.is_empty();
    (!empty).then_some(info)
}

/// A short ASCII spec string out of a leaf payload. Length-capped (see
/// [`MAX_TAG`]) and refused outright if it is not ASCII: CodecID and
/// Language are both defined as ASCII, so anything else is a corrupt or
/// hostile mux and passing it on would put arbitrary bytes into a
/// filename.
fn read_tag(payload: &[u8]) -> Option<String> {
    if payload.is_empty() || payload.len() > MAX_TAG {
        return None;
    }
    // Some muxers zero-pad these to a fixed width.
    let trimmed: &[u8] = payload.split(|&b| b == 0).next().unwrap_or(payload);
    if trimmed.is_empty() || !trimmed.is_ascii() {
        return None;
    }
    Some(String::from_utf8_lossy(trimmed).into_owned())
}

/// The resolution tag the measured dimensions deserve, in the same
/// spelling `release::res_of` produces. Buckets are Sonarr's, chosen off
/// real-world encodes: a 1912x800 scope crop is 1080p, not 800p.
pub fn res_bucket(width: u32, height: u32) -> &'static str {
    if width >= 3200 || height >= 2100 {
        "2160p"
    } else if width >= 1800 || height >= 1000 {
        "1080p"
    } else if width >= 1200 || height >= 700 {
        "720p"
    } else if width >= 1000 || height >= 560 {
        "576p"
    } else {
        "480p"
    }
}

/// id bytes as written, payload appended under a 1-or-2-byte size.
#[doc(hidden)]
pub fn el(id: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = id.to_vec();
    if payload.len() < 0x7F {
        v.push(0x80 | payload.len() as u8);
    } else {
        assert!(payload.len() < 0x3FFF);
        v.push(0x40 | (payload.len() >> 8) as u8);
        v.push((payload.len() & 0xFF) as u8);
    }
    v.extend_from_slice(payload);
    v
}

/// A minimal, valid mux for tests and fuzz seeds - ours and the callers'
/// (`smart` exercises the probe against real files on disk).
#[doc(hidden)]
pub fn test_mux(duration: Option<f64>, dims: Option<(u32, u32)>) -> Vec<u8> {
    test_mux_titled(duration, dims, None)
}

/// `test_mux` with a Segment>Info>Title.
#[doc(hidden)]
pub fn test_mux_titled(
    duration: Option<f64>,
    dims: Option<(u32, u32)>,
    title: Option<&str>,
) -> Vec<u8> {
    let mut infos = el(&[0x2A, 0xD7, 0xB1], &1_000_000u32.to_be_bytes()); // scale 1ms
    if let Some(t) = title {
        infos.extend(el(&[0x7B, 0xA9], t.as_bytes()));
    }
    if let Some(d) = duration {
        // Duration in scale units: d seconds = d * 1000 ms.
        infos.extend(el(&[0x44, 0x89], &((d * 1000.0) as f32).to_be_bytes()));
    }
    let mut entry = el(&[0x83], &[1]); // TrackType video
    if let Some((w, h)) = dims {
        let mut video = el(&[0xB0], &w.to_be_bytes()[2..]);
        video.extend(el(&[0xBA], &h.to_be_bytes()[2..]));
        entry.extend(el(&[0xE0], &video));
    }
    let mut seg = el(&[0x15, 0x49, 0xA9, 0x66], &infos);
    seg.extend(el(&[0x16, 0x54, 0xAE, 0x6B], &el(&[0xAE], &entry)));
    let mut out = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]); // EBML header, empty
    out.extend(el(&[0x18, 0x53, 0x80, 0x67], &seg));
    out
}

/// One TrackEntry for [`test_mux_tracks`]: (TrackType, CodecID,
/// Language). `None` for a language writes no element at all, which is
/// the untagged case the flush deliberately does not default to English.
#[doc(hidden)]
pub type TestTrack<'a> = (u64, &'a str, Option<&'a str>);

/// A mux with an arbitrary track list, for the fact-extraction tests and
/// the callers that need more than one track. `test_mux` stays as it was
/// - it seeds the fuzz corpus, and its shape is pinned by a checked-in
/// fixture.
#[doc(hidden)]
pub fn test_mux_tracks(
    duration: Option<f64>,
    dims: Option<(u32, u32)>,
    tracks: &[TestTrack<'_>],
) -> Vec<u8> {
    let mut infos = el(&[0x2A, 0xD7, 0xB1], &1_000_000u32.to_be_bytes());
    if let Some(d) = duration {
        infos.extend(el(&[0x44, 0x89], &((d * 1000.0) as f32).to_be_bytes()));
    }
    let mut entries = Vec::new();
    for (kind, codec, lang) in tracks {
        let mut entry = el(&[0x83], &[*kind as u8]);
        entry.extend(el(&[0x86], codec.as_bytes()));
        if let Some(l) = lang {
            entry.extend(el(&[0x22, 0xB5, 0x9C], l.as_bytes()));
        }
        if *kind == TRACK_VIDEO
            && let Some((w, h)) = dims
        {
            let mut video = el(&[0xB0], &w.to_be_bytes()[2..]);
            video.extend(el(&[0xBA], &h.to_be_bytes()[2..]));
            entry.extend(el(&[0xE0], &video));
        }
        entries.extend(el(&[0xAE], &entry));
    }
    let mut seg = el(&[0x15, 0x49, 0xA9, 0x66], &infos);
    seg.extend(el(&[0x16, 0x54, 0xAE, 0x6B], &entries));
    let mut out = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
    out.extend(el(&[0x18, 0x53, 0x80, 0x67], &seg));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mkv(duration: Option<f64>, dims: Option<(u32, u32)>) -> Vec<u8> {
        test_mux(duration, dims)
    }

    #[test]
    fn a_plain_mux_yields_duration_and_dimensions() {
        let b = sample_mkv(Some(5400.0), Some((1920, 1080)));
        let i = parse(&b).unwrap();
        assert!((i.duration_secs.unwrap() - 5400.0).abs() < 1.0);
        assert_eq!((i.width, i.height), (Some(1920), Some(1080)));
    }

    #[test]
    fn fields_are_independent() {
        let i = parse(&sample_mkv(None, Some((1280, 720)))).unwrap();
        assert_eq!(i.duration_secs, None);
        assert_eq!((i.width, i.height), (Some(1280), Some(720)));
        let i = parse(&sample_mkv(Some(90.0), None)).unwrap();
        assert!((i.duration_secs.unwrap() - 90.0).abs() < 1.0);
        assert_eq!((i.width, i.height), (None, None));
    }

    #[test]
    fn an_unknown_size_segment_still_parses() {
        // Streamed muxes write Segment with the unknown-size vint.
        let b = sample_mkv(Some(60.0), Some((1920, 800)));
        // Rebuild with Segment size FF (unknown, 1-byte vint all ones).
        let ebml = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
        let seg_body_at = {
            // sample_mkv wrote: ebml, then segment id(4) + size + body.
            let at = ebml.len() + 4;
            let (sz, sl) = super::read_size(&b, at).unwrap();
            (at + sl, sz.unwrap() as usize)
        };
        let mut out = ebml.clone();
        out.extend_from_slice(&[0x18, 0x53, 0x80, 0x67, 0xFF]);
        out.extend_from_slice(&b[seg_body_at.0..seg_body_at.0 + seg_body_at.1]);
        let i = parse(&out).unwrap();
        assert_eq!((i.width, i.height), (Some(1920), Some(800)));
    }

    /// The live/pipe-mux shape: an unknown-sized Segment whose Info and
    /// Tracks are followed by `trailer` (an element the walk meets after
    /// the header furniture it came for).
    fn streamed_mkv(duration: Option<f64>, dims: Option<(u32, u32)>, trailer: &[u8]) -> Vec<u8> {
        let b = sample_mkv(duration, dims);
        let ebml = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
        let at = ebml.len() + 4;
        let (sz, sl) = super::read_size(&b, at).unwrap();
        let (body, len) = (at + sl, sz.unwrap() as usize);
        let mut out = ebml;
        out.extend_from_slice(&[0x18, 0x53, 0x80, 0x67, 0xFF]); // Segment, unknown size
        out.extend_from_slice(&b[body..body + len]);
        out.extend_from_slice(trailer);
        out
    }

    #[test]
    fn an_unknown_size_cluster_keeps_the_header_we_already_read() {
        // RFC 9559 §5.1.3: Cluster may omit its length, and anything
        // muxed through a pipe does. The walk has to stop there - but
        // stopping is not disbelieving: Info and Tracks are behind us
        // and already parsed. Throwing them away cost a real episode its
        // duration, and a missing duration is what cleanup reads as "no
        // veto" before deleting a "sample"/"proof"-named file that sits
        // small beside the pack's feature.
        let mut trailer = vec![0x1F, 0x43, 0xB6, 0x75, 0xFF]; // Cluster, unknown size
        trailer.extend_from_slice(&[0xE7, 0x81, 0x00]); // Timestamp 0, inside it
        let i = parse(&streamed_mkv(Some(2700.0), Some((1920, 1080)), &trailer))
            .expect("the header before the cluster still counts");
        assert!((i.duration_secs.unwrap() - 2700.0).abs() < 1.0);
        assert_eq!((i.width, i.height), (Some(1920), Some(1080)));
    }

    #[test]
    fn other_unknown_size_elements_still_fail_safely() {
        // Only Segment and Cluster may omit their length. An unknown-
        // sized anything-else has no parseable extent, so the walk
        // cannot know where the next element begins - refuse rather than
        // resynchronise on whatever follows.
        let trailer = [0x1C, 0x53, 0xBB, 0x6B, 0xFF]; // Cues, unknown size
        assert_eq!(
            parse(&streamed_mkv(Some(2700.0), Some((1920, 1080)), &trailer)),
            None
        );
    }

    #[test]
    fn a_non_video_track_contributes_no_dimensions() {
        // TrackType 2 (audio) carrying a Video element anyway: hostile
        // or broken, either way its numbers must not be believed.
        let mut entry = el(&[0x83], &[2]);
        let mut video = el(&[0xB0], &1920u32.to_be_bytes()[2..]);
        video.extend(el(&[0xBA], &1080u32.to_be_bytes()[2..]));
        entry.extend(el(&[0xE0], &video));
        let seg = el(&[0x16, 0x54, 0xAE, 0x6B], &el(&[0xAE], &entry));
        let mut out = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
        out.extend(el(&[0x18, 0x53, 0x80, 0x67], &seg));
        assert_eq!(parse(&out), None);
    }

    #[test]
    fn hostile_shapes_return_none_not_panic() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"\x00"), None);
        assert_eq!(parse(b"not matroska at all"), None);
        // EBML magic then garbage sizes.
        assert_eq!(parse(&[0x1A, 0x45, 0xDF, 0xA3, 0xFF, 0xFF, 0xFF]), None);
        // Truncated mid-element.
        let b = sample_mkv(Some(60.0), Some((1920, 1080)));
        for cut in 0..b.len() {
            let _ = parse(&b[..cut]); // must not panic; value is free
        }
    }

    #[test]
    fn the_checked_in_fixture_parses() {
        // The same file seeds the fuzz corpus (fixtures/mkv/head.mkv);
        // this pins fixture and parser to each other.
        let b = include_bytes!("../tests/fixtures/mkv/head.mkv");
        let i = parse(b).unwrap();
        assert_eq!((i.width, i.height), (Some(1920), Some(1080)));
        assert!((i.duration_secs.unwrap() - 5400.0).abs() < 1.0);
    }

    /// The RMZ.cr pattern: a repacker leaves the real release name in
    /// the container Title and signs it. Both halves matter - reading
    /// the Title at all, and handing the caller a name that is not
    /// carrying a website on the end of it.
    #[test]
    fn a_title_is_read_and_its_muxer_credit_stripped() {
        let name = "Example.Movie.2019.1080p.BluRay.x264-GRP";
        let b = test_mux_titled(
            Some(60.0),
            Some((1920, 1080)),
            Some(&format!("{name}, RMZ.cr")),
        );
        assert_eq!(parse(&b).unwrap().title.as_deref(), Some(name));
        // A Title-only mux still parses: the fields are independent, and
        // an obfuscated post's container is exactly where this pays.
        let b = test_mux_titled(None, None, Some(name));
        assert_eq!(parse(&b).unwrap().title.as_deref(), Some(name));
        // No Title element at all.
        assert_eq!(
            parse(&test_mux(Some(60.0), Some((1920, 1080))))
                .unwrap()
                .title,
            None
        );
    }

    #[test]
    fn muxer_credits_are_stripped_structurally_not_by_name() {
        // The known signature, and its siblings.
        assert_eq!(
            strip_muxer_credit("A.Film.2019.1080p-GRP, RMZ.cr"),
            "A.Film.2019.1080p-GRP"
        );
        assert_eq!(
            strip_muxer_credit("A.Film.2019-GRP,rarbg.to"),
            "A.Film.2019-GRP"
        );
        // A comma inside a real title is not a credit: the tail has to
        // read as a bare domain.
        assert_eq!(strip_muxer_credit("Hello, World 2019"), "Hello, World 2019");
        assert_eq!(
            strip_muxer_credit("Fire, Walk With Me"),
            "Fire, Walk With Me"
        );
        // Nothing left over after stripping is not a strip at all.
        assert_eq!(strip_muxer_credit(", RMZ.cr"), ", RMZ.cr");
        assert_eq!(strip_muxer_credit("A Film"), "A Film");
    }

    /// Titles come off the wire. A declared length far past anything a
    /// real muxer writes must not be carried into a filename, and
    /// invalid UTF-8 or control bytes must not panic or escape.
    #[test]
    fn hostile_titles_are_bounded_and_sanitised() {
        let long = "x".repeat(5_000);
        let got = parse(&test_mux_titled(None, None, Some(&long)))
            .unwrap()
            .title
            .unwrap();
        assert!(
            got.len() <= MAX_TITLE,
            "a {}-byte title escaped the cap",
            got.len()
        );
        // Control characters (a newline injected into a name) are gone.
        let got = parse(&test_mux_titled(None, None, Some("Film.2019\n\u{7}-GRP")))
            .unwrap()
            .title
            .unwrap();
        assert_eq!(got, "Film.2019-GRP");
        // A whitespace-only Title is no Title.
        assert_eq!(
            parse(&test_mux_titled(Some(60.0), None, Some("   ")))
                .unwrap()
                .title,
            None
        );
    }

    #[test]
    fn a_mux_yields_codecs_and_track_languages() {
        let b = test_mux_tracks(
            Some(6480.0),
            Some((1920, 1080)),
            &[
                (1, "V_MPEG4/ISO/AVC", None),
                (2, "A_EAC3", Some("eng")),
                (0x11, "S_TEXT/UTF8", Some("fre")),
                (0x11, "S_TEXT/UTF8", Some("ger")),
            ],
        );
        let f = facts(&b).unwrap();
        assert_eq!(f.container, "mkv");
        assert_eq!(f.runtime_minutes(), Some(108));
        assert_eq!((f.width, f.height), (Some(1920), Some(1080)));
        assert_eq!(f.video_codec.as_deref(), Some("h264"));
        assert_eq!(f.audio_codecs, vec!["eac3"]);
        assert_eq!(f.audio_langs, vec!["en"]);
        assert_eq!(f.sub_langs, vec!["fr", "de"]);
        assert_eq!(f.original_language(), Some("en"));
    }

    #[test]
    fn an_untagged_audio_track_is_not_defaulted_to_english() {
        // Matroska's spec default for a missing Language IS "eng", and
        // we deliberately do not honour it: silence from the muxer must
        // not become an assertion the language filter acts on.
        let b = test_mux_tracks(
            Some(6000.0),
            Some((1280, 720)),
            &[(1, "V_MPEGH/ISO/HEVC", None), (2, "A_AAC", None)],
        );
        let f = facts(&b).unwrap();
        assert_eq!(f.video_codec.as_deref(), Some("h265"));
        assert_eq!(f.audio_codecs, vec!["aac"]);
        assert!(f.audio_langs.is_empty());
        assert_eq!(f.original_language(), None);
    }

    #[test]
    fn a_dual_audio_mux_offers_no_original_language() {
        let b = test_mux_tracks(
            Some(7000.0),
            Some((1920, 1080)),
            &[
                (1, "V_AV1", None),
                (2, "A_DTS", Some("jpn")),
                (2, "A_AC3", Some("eng")),
            ],
        );
        let f = facts(&b).unwrap();
        assert_eq!(f.video_codec.as_deref(), Some("av1"));
        assert_eq!(f.audio_codecs, vec!["dts", "ac3"]);
        assert_eq!(f.audio_langs, vec!["ja", "en"]);
        assert_eq!(f.original_language(), None);
    }

    #[test]
    fn a_codec_only_head_answers_facts_but_not_parse() {
        // `facts` reports whatever the head yielded; `parse` keeps its
        // older, narrower contract of "duration or dimensions or None".
        let b = test_mux_tracks(None, None, &[(2, "A_FLAC", Some("ita"))]);
        let f = facts(&b).unwrap();
        assert_eq!(f.audio_codecs, vec!["flac"]);
        assert_eq!(f.audio_langs, vec!["it"]);
        assert_eq!(parse(&b), None);
    }

    #[test]
    fn a_hostile_language_payload_is_refused_not_carried() {
        // CodecID and Language are ASCII by spec. Non-ASCII bytes are a
        // corrupt or hostile mux, and passing them on would put
        // arbitrary bytes in front of a filename.
        let mut entry = el(&[0x83], &[2]);
        entry.extend(el(&[0x86], &[0xFF, 0xFE, 0x00, 0x41]));
        entry.extend(el(&[0x22, 0xB5, 0x9C], &[0xC3, 0xA9, 0xC3, 0xA9]));
        let mut seg = el(
            &[0x15, 0x49, 0xA9, 0x66],
            &el(&[0x44, 0x89], &6000f32.to_be_bytes()),
        );
        seg.extend(el(&[0x16, 0x54, 0xAE, 0x6B], &el(&[0xAE], &entry)));
        let mut out = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
        out.extend(el(&[0x18, 0x53, 0x80, 0x67], &seg));
        let f = facts(&out).unwrap();
        assert!(f.audio_codecs.is_empty());
        assert!(f.audio_langs.is_empty());
    }

    #[test]
    fn facts_never_panic_on_truncated_or_hostile_input() {
        assert_eq!(facts(b""), None);
        assert_eq!(facts(b"not matroska at all"), None);
        let b = test_mux_tracks(
            Some(6480.0),
            Some((1920, 1080)),
            &[(1, "V_MPEG4/ISO/AVC", None), (2, "A_EAC3", Some("eng"))],
        );
        for cut in 0..b.len() {
            let _ = facts(&b[..cut]); // must not panic; value is free
        }
    }

    #[test]
    fn buckets_match_real_encode_shapes() {
        assert_eq!(res_bucket(3840, 2160), "2160p");
        assert_eq!(res_bucket(1920, 1080), "1080p");
        assert_eq!(res_bucket(1912, 800), "1080p"); // scope crop
        assert_eq!(res_bucket(1280, 720), "720p");
        assert_eq!(res_bucket(1280, 536), "720p"); // scope crop
        assert_eq!(res_bucket(1024, 576), "576p");
        assert_eq!(res_bucket(720, 480), "480p");
        assert_eq!(res_bucket(640, 352), "480p");
    }
}
