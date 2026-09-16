//! Matroska / WebM: the EBML walk.
//!
//! Everything a verification panel needs sits before the first Cluster
//! in any sane mux, so the walk stops there. What a muxer legitimately
//! writes AFTER the clusters - Chapters and Tags, sometimes Tracks -
//! is reached by the SeekHead, which is the container's own index of
//! where it put things. That is the Matroska twin of MP4's
//! moov-at-the-end case, and on a live download it resolves as soon as
//! the tail lands (the daemon keeps the last 8 MB hot for exactly this).

use super::{
    AudioTrack, Chapter, Container, Hdr, MAX_CHAPTERS, MAX_DEPTH, MAX_STRING, MAX_TRACKS,
    MediaInfo, ProbeError, Rd, SubTrack, VideoTrack, be_uint, codec, normalize_lang, ratio, round3,
};
use std::collections::HashSet;
use std::io::{Read, Seek};

// Masters we descend into. Everything else is skipped by its declared
// size, so an unknown or hostile element costs one header read.
const EBML_HEAD: u32 = 0x1A45_DFA3;
const SEGMENT: u32 = 0x1853_8067;
const SEEK_HEAD: u32 = 0x114D_9B74;
const SEEK: u32 = 0x4DBB;
const INFO: u32 = 0x1549_A966;
const TRACKS: u32 = 0x1654_AE6B;
const TRACK_ENTRY: u32 = 0xAE;
const VIDEO: u32 = 0xE0;
const AUDIO: u32 = 0xE1;
const COLOUR: u32 = 0x55B0;
const CHAPTERS: u32 = 0x1043_A770;
const EDITION: u32 = 0x45B9;
const CHAPTER_ATOM: u32 = 0xB6;
const CHAPTER_DISPLAY: u32 = 0x80;
const TAGS: u32 = 0x1254_C367;
const TAG: u32 = 0x7373;
const TARGETS: u32 = 0x63C0;
const SIMPLE_TAG: u32 = 0x67C8;
const CLUSTER: u32 = 0x1F43_B675;

// Leaves.
const DOC_TYPE: u32 = 0x4282;
const SEEK_ID: u32 = 0x53AB;
const SEEK_POSITION: u32 = 0x53AC;
const TIMESTAMP_SCALE: u32 = 0x002A_D7B1;
const DURATION: u32 = 0x4489;
const TITLE: u32 = 0x7BA9;
const TRACK_NUMBER: u32 = 0xD7;
const TRACK_UID: u32 = 0x73C5;
const TRACK_TYPE: u32 = 0x83;
const FLAG_ENABLED: u32 = 0xB9;
const FLAG_DEFAULT: u32 = 0x88;
const FLAG_FORCED: u32 = 0x55AA;
const DEFAULT_DURATION: u32 = 0x0023_E383;
const NAME: u32 = 0x536E;
const LANGUAGE: u32 = 0x0022_B59C;
const LANGUAGE_BCP47: u32 = 0x0022_B59D;
const CODEC_ID: u32 = 0x86;
const CODEC_PRIVATE: u32 = 0x63A2;
const PIXEL_WIDTH: u32 = 0xB0;
const PIXEL_HEIGHT: u32 = 0xBA;
const DISPLAY_WIDTH: u32 = 0x54B0;
const DISPLAY_HEIGHT: u32 = 0x54BA;
const DISPLAY_UNIT: u32 = 0x54B2;
const MATRIX_COEFFICIENTS: u32 = 0x55B1;
const BITS_PER_CHANNEL: u32 = 0x55B2;
const TRANSFER_CHARACTERISTICS: u32 = 0x55BA;
const PRIMARIES: u32 = 0x55BB;
const MAX_CLL: u32 = 0x55BC;
const MAX_FALL: u32 = 0x55BD;
const SAMPLING_FREQUENCY: u32 = 0xB5;
const OUTPUT_SAMPLING_FREQUENCY: u32 = 0x78B5;
const CHANNELS: u32 = 0x9F;
const CHAPTER_TIME_START: u32 = 0x91;
const CHAP_STRING: u32 = 0x85;
const TAG_TRACK_UID: u32 = 0x63C5;
const TAG_NAME: u32 = 0x45A3;
const TAG_STRING: u32 = 0x4487;

const TRACK_VIDEO: u64 = 1;
const TRACK_AUDIO: u64 = 2;
const TRACK_SUBTITLE: u64 = 0x11;

/// Longest CodecPrivate we will read. avcC/hvcC/av1C all fit in a few
/// dozen bytes; the cap is for the mux that declares a megabyte.
const MAX_CODEC_PRIVATE: usize = 64 << 10;

fn is_master(id: u32) -> bool {
    matches!(
        id,
        EBML_HEAD
            | SEGMENT
            | SEEK_HEAD
            | SEEK
            | INFO
            | TRACKS
            | TRACK_ENTRY
            | VIDEO
            | AUDIO
            | COLOUR
            | CHAPTERS
            | EDITION
            | CHAPTER_ATOM
            | CHAPTER_DISPLAY
            | TAGS
            | TAG
            | TARGETS
            | SIMPLE_TAG
    )
}

/// One TrackEntry as its leaves arrive. A muxer orders them freely, so
/// the entry is judged when it CLOSES.
#[derive(Default)]
struct TrackBuf {
    number: Option<u64>,
    uid: Option<u64>,
    kind: Option<u64>,
    enabled: bool,
    default: bool,
    forced: bool,
    codec_id: Option<String>,
    codec_private: Option<Vec<u8>>,
    lang: Option<String>,
    lang_bcp47: Option<String>,
    name: Option<String>,
    default_duration: Option<u64>,
    width: Option<u64>,
    height: Option<u64>,
    disp_w: Option<u64>,
    disp_h: Option<u64>,
    disp_unit: u64,
    bit_depth: Option<u8>,
    matrix: Option<String>,
    transfer: Option<String>,
    primaries: Option<String>,
    max_cll: Option<u32>,
    max_fall: Option<u32>,
    channels: Option<u64>,
    sample_rate: Option<f64>,
    out_sample_rate: Option<f64>,
}

impl TrackBuf {
    fn fresh() -> Self {
        TrackBuf {
            // Matroska's defaults for the two flags that have one.
            enabled: true,
            default: true,
            disp_unit: 0,
            ..TrackBuf::default()
        }
    }
}

#[derive(Default)]
struct State {
    scale: f64,
    raw_duration: Option<f64>,
    track: TrackBuf,
    seg_data_start: u64,
    seg_end: u64,
    /// SeekHead targets: (element id, offset RELATIVE to the segment's
    /// data start, which is what a SeekPosition carries).
    seek: Vec<(u32, u64)>,
    cur_seek_id: Option<u32>,
    cur_seek_pos: Option<u64>,
    chap_start: Option<u64>,
    chap_title: Option<String>,
    /// Tags: (track UID or None for "the file"), bits per second.
    bps: Vec<(Option<u64>, u64)>,
    tag_uid: Option<u64>,
    tag_name: Option<String>,
    tag_value: Option<String>,
    seen_tracks: bool,
    seen_chapters: bool,
    seen_tags: bool,
    /// UID and number of every track filed, so a Tags BPS can find it.
    filed: Vec<(Option<u64>, Option<u64>, bool)>,
}

pub(super) fn parse<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
) -> Result<(), ProbeError> {
    let mut st = State {
        scale: 1_000_000.0,
        track: TrackBuf::fresh(),
        ..State::default()
    };
    st.seg_end = rd.end;
    let file_end = rd.end;
    walk(rd, info, &mut st, 0, file_end)?;

    // Chapters and Tags are legitimately written after the clusters.
    // The SeekHead is the container's own index of where; chase only
    // what we have not already seen, and only backwards-safe targets.
    //
    // These three are read ONCE, here, and must NOT become a per-target
    // re-check inside the loop below. They answer "did the PRE-CLUSTER
    // walk already cover this kind" - and a chase walk of a Chapters
    // element sets `st.seen_chapters` itself, through `close()`, so
    // re-reading them would drop every target after the first of its
    // kind. Two distinct Chapters elements at two offsets are two
    // elements and both belong in the answer; the offset set below is
    // the dedupe, not this.
    let (want_chapters, want_tags, want_tracks) =
        (!st.seen_chapters, !st.seen_tags, !st.seen_tracks);
    let chaseable = |id: u32| match id {
        CHAPTERS => want_chapters,
        TAGS => want_tags,
        TRACKS => want_tracks,
        // A SeekHead naming ANOTHER SeekHead is ordinary, specified
        // Matroska rather than an exotic shape: it is how a muxer
        // writes a small fixed-size index at the front of the Segment
        // and defers the real one to the tail, which is exactly the
        // case this chase exists for. Always chaseable - there is no
        // `seen_` for it, because a second index is not redundant with
        // the first. Handoff 16 Sep 2026.
        SEEK_HEAD => true,
        _ => false,
    };
    // The dedupe key is the RESOLVED ABSOLUTE OFFSET of the target
    // element, and deliberately not its element ID: a SeekHead may
    // legitimately list the same target twice (and a hostile one from
    // Usenet certainly may), while two entries at two DIFFERENT offsets
    // are two different elements whose contents both belong in the
    // answer - keying on the ID would silently drop the second. It is
    // not the offset of the Seek ENTRY either; two entries that resolve
    // to one element are one walk.
    //
    // It IS the cycle guard, now that the chase is a WORKLIST rather
    // than a snapshot: `st.seek` is drained by index and grows under
    // the loop, because a walk of a second SeekHead appends its entries
    // through `close(SEEK)`. A SeekHead naming itself, or two naming
    // each other, is a trivial hostile file from Usenet; the resolved
    // offset is what terminates it, on the second visit, with no cap on
    // the number of entries chased - a cap would turn this correctness
    // fix into a silent truncation.
    //
    // Termination does not rest on that set alone. Entries reach
    // `st.seek` only from `close(SEEK)`, and every SEEK master opened
    // has already paid `charge_element()` against the probe's global
    // element budget, so the worklist cannot exceed MAX_ELEMENTS
    // entries however the file is shaped; `next` advances on every
    // iteration whatever happens to the entry. The offset set is what
    // makes a cycle cost ONE extra walk rather than a burned budget and
    // a "too complex to inspect fully" warning on a file that is fine.
    let mut walked: HashSet<u64> = HashSet::new();
    let mut next = 0usize;
    while next < st.seek.len() {
        let (id, rel) = st.seek[next];
        next += 1;
        if !chaseable(id) {
            continue;
        }
        let at = match st.seg_data_start.checked_add(rel) {
            Some(a) if a < file_end => a,
            _ => continue,
        };
        if !walked.insert(at) {
            continue;
        }
        let label = match id {
            CHAPTERS => "chapters",
            TAGS => "tags",
            SEEK_HEAD => "index",
            _ => "track list",
        };
        // The element at the target must be the one the index promised;
        // a SeekPosition pointing into the middle of a cluster is a
        // corrupt or hostile index, and walking it would be walking
        // payload as structure.
        //
        // Its declared END is read here too, and it is what the chase
        // walk is bounded by. Walking to `file_end` instead let a walk
        // run off the end of its own target into the NEXT top-level
        // element, so a tail of [Tags][Chapters] parsed the Chapters
        // twice - once by falling out of Tags and once as its own
        // target - and `close(CHAPTER_ATOM)` pushed every chapter
        // again. Bug sweep 16 Sep 2026, item 26.
        rd.seek_to(at);
        let id_len = match read_id(rd) {
            Ok((found, n)) if found == id => n,
            Ok(_) => {
                info.incomplete(format!("{label} index points at the wrong element"));
                continue;
            }
            Err(e) if e.is_gap() => {
                info.incomplete(format!("{label} not downloaded yet"));
                continue;
            }
            Err(_) => {
                info.incomplete(format!("{label} index is unreadable"));
                continue;
            }
        };
        let elem_end = match read_size(rd) {
            Ok((Some(s), size_len)) => at
                .saturating_add(id_len as u64)
                .saturating_add(size_len as u64)
                .saturating_add(s)
                .min(file_end),
            // An unknown size is legal only on Segment and Cluster.
            // A chase target with one has no end to walk to, and the
            // walk would refuse it at its first element anyway.
            Ok((None, _)) => {
                info.incomplete(format!("{label} index points at an unsized element"));
                continue;
            }
            Err(e) if e.is_gap() => {
                info.incomplete(format!("{label} not downloaded yet"));
                continue;
            }
            Err(_) => {
                info.incomplete(format!("{label} index is unreadable"));
                continue;
            }
        };
        if walk(rd, info, &mut st, at, elem_end).is_err() {
            info.incomplete(format!("{label} not downloaded yet"));
        }
    }

    // A Tags BPS attaches to the track with that UID, or - when the tag
    // named no target - to the single video track.
    for (uid, bps) in &st.bps {
        match uid {
            Some(u) => {
                if let Some(idx) = st
                    .filed
                    .iter()
                    .position(|(tuid, tnum, _)| tuid == &Some(*u) || tnum == &Some(*u))
                {
                    let (_, _, is_video) = st.filed[idx];
                    let nth = st.filed[..idx].iter().filter(|f| f.2 == is_video).count();
                    if is_video {
                        if let Some(t) = info.video.get_mut(nth) {
                            t.bitrate = Some(*bps);
                        }
                    } else if let Some(t) = info.audio.get_mut(nth) {
                        t.bitrate = Some(*bps);
                    }
                }
            }
            None => {
                if let [only] = info.video.as_mut_slice() {
                    only.bitrate = Some(*bps);
                }
            }
        }
    }

    if let Some(d) = st.raw_duration
        && d.is_finite()
        && d > 0.0
    {
        let ms = d * st.scale / 1e6;
        if ms.is_finite() && ms >= 0.0 && ms < u64::MAX as f64 {
            info.duration_ms = Some(ms as u64);
        }
    }
    Ok(())
}

/// One pass over `[start, end)`, descending into masters. Returns `Err`
/// only for a structurally impossible header at the very first element;
/// everything else stops the walk and keeps what was parsed.
fn walk<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
    st: &mut State,
    start: u64,
    end: u64,
) -> Result<(), ProbeError> {
    let mut stack: Vec<(u32, u64)> = Vec::new();
    let mut pos = start;
    let mut first = true;
    loop {
        while let Some(&(id, fend)) = stack.last() {
            if pos < fend {
                break;
            }
            close(info, st, id);
            stack.pop();
        }
        let limit = stack.last().map_or(end, |&(_, e)| e);
        if pos >= limit {
            break;
        }
        if rd.budget.charge_element().is_err() {
            info.incomplete("file is too complex to inspect fully");
            break;
        }
        rd.seek_to(pos);
        let (id, id_len) = match read_id(rd) {
            Ok(v) => v,
            Err(e) if first => return Err(e),
            Err(e) if e.is_gap() => {
                info.incomplete("the rest of the header has not downloaded yet");
                break;
            }
            Err(_) => {
                info.incomplete("the container's structure ends here");
                break;
            }
        };
        let (size, size_len) = match read_size(rd) {
            Ok(v) => v,
            Err(e) if first => return Err(e),
            Err(e) if e.is_gap() => {
                info.incomplete("the rest of the header has not downloaded yet");
                break;
            }
            Err(_) => {
                info.incomplete("the container's structure ends here");
                break;
            }
        };
        first = false;
        let body = pos + id_len as u64 + size_len as u64;
        let elem_end = match size {
            Some(s) => body.saturating_add(s).min(limit),
            // Unknown size is legal in practice on Segment (a mux that
            // could not backfill the length) and on Cluster. Anywhere
            // else there is no way to find the next sibling, so the
            // walk stops with what it already has.
            None if id == SEGMENT => limit,
            None if id == CLUSTER => break,
            None => {
                info.incomplete("the container's structure ends here");
                break;
            }
        };
        // `elem_end <= pos` catches a walk that would not advance. The second
        // arm catches a DIFFERENT shape: `elem_end` is clamped to `limit`
        // above (both on the sized arm's `.min(limit)` and on the unknown-size
        // SEGMENT arm), and `body` is past the ID and size fields, so an
        // element whose own header runs beyond its parent's declared end
        // lands with `body > elem_end`. That still satisfies `elem_end > pos`,
        // because `pos < limit` is guaranteed at the top of the loop - so the
        // first arm waves it through and the `elem_end - body` below
        // underflows. Found by the mediaprobe fuzz target, 4 Aug.
        if elem_end <= pos || elem_end < body {
            info.incomplete("the container's structure ends here");
            break;
        }
        // Metadata precedes the first cluster in every ordinary mux;
        // anything after it is reached through the SeekHead instead.
        if id == CLUSTER {
            break;
        }
        if id == SEGMENT {
            st.seg_data_start = body;
            st.seg_end = elem_end;
        }
        if is_master(id) {
            if stack.len() >= MAX_DEPTH {
                info.incomplete("the container nests too deeply to inspect");
                break;
            }
            open(st, id);
            stack.push((id, elem_end));
            pos = body;
            continue;
        }
        rd.seek_to(body);
        let payload_len = elem_end - body;
        match leaf(rd, info, st, id, payload_len) {
            Ok(()) => {}
            Err(e) if e.is_gap() => {
                // Seeking past it is free, so a hole in one leaf costs
                // only that leaf.
                info.incomplete("part of the header has not downloaded yet");
            }
            Err(ProbeError::BudgetExceeded) => {
                info.incomplete("file is too complex to inspect fully");
                break;
            }
            Err(_) => info.incomplete("part of the header could not be read"),
        }
        pos = elem_end;
    }
    while let Some((id, _)) = stack.pop() {
        close(info, st, id);
    }
    Ok(())
}

fn open(st: &mut State, id: u32) {
    match id {
        TRACK_ENTRY => st.track = TrackBuf::fresh(),
        SEEK => {
            st.cur_seek_id = None;
            st.cur_seek_pos = None;
        }
        CHAPTER_ATOM => {
            st.chap_start = None;
            st.chap_title = None;
        }
        TAG => st.tag_uid = None,
        SIMPLE_TAG => {
            st.tag_name = None;
            st.tag_value = None;
        }
        _ => {}
    }
}

fn close(info: &mut MediaInfo, st: &mut State, id: u32) {
    match id {
        TRACKS => st.seen_tracks = true,
        CHAPTERS => st.seen_chapters = true,
        TAGS => st.seen_tags = true,
        TRACK_ENTRY => flush_track(info, st),
        SEEK => {
            if let (Some(id), Some(pos)) = (st.cur_seek_id, st.cur_seek_pos) {
                st.seek.push((id, pos));
            }
        }
        CHAPTER_ATOM => {
            if let Some(start) = st.chap_start
                && info.chapters.len() < MAX_CHAPTERS
            {
                info.chapters.push(Chapter {
                    start_ms: start / 1_000_000,
                    title: st.chap_title.take().unwrap_or_default(),
                });
            }
        }
        SIMPLE_TAG => {
            if st.tag_name.as_deref() == Some("BPS")
                && let Some(v) = st.tag_value.as_deref().and_then(|v| v.parse::<u64>().ok())
            {
                st.bps.push((st.tag_uid, v));
            }
        }
        _ => {}
    }
}

fn flush_track(info: &mut MediaInfo, st: &mut State) {
    let t = std::mem::replace(&mut st.track, TrackBuf::fresh());
    if info.video.len() + info.audio.len() + info.subtitles.len() >= MAX_TRACKS {
        info.incomplete("this file has more tracks than we will list");
        return;
    }
    let raw = t.codec_id.clone().unwrap_or_default();
    // Matroska's spec default for an absent Language IS "eng". The
    // naming path deliberately does not honour it (silence must not
    // become a fact a filter acts on); here it is honoured, because the
    // panel is showing a viewer what a player will pick, and a player
    // follows the spec.
    let lang = normalize_lang(
        t.lang_bcp47
            .as_deref()
            .or(t.lang.as_deref())
            .unwrap_or("eng"),
    );
    match t.kind {
        Some(TRACK_VIDEO) => {
            // V_MS/VFW/FOURCC says nothing by itself: it is a wrapper
            // whose real codec is the biCompression fourcc inside the
            // BITMAPINFOHEADER it carries as CodecPrivate. Guessing a
            // codec from the wrapper alone is how the two tables in
            // this tree ended up disagreeing about it.
            let canon = match vfw_fourcc(&raw, t.codec_private.as_deref()) {
                Some(cc) => codec::lookup(Container::Avi, &cc, true).0,
                None => codec::lookup(info.container, &raw, true).0,
            };
            let (profile, level, cp_depth) =
                codec_private_video(&canon, t.codec_private.as_deref());
            // Matroska's CodecPrivate IS the configuration record the
            // codec string is spelled from - avcC bytes for H.264,
            // hvcC for HEVC - so the browser question is answerable
            // for an MKV without an MP4 sample entry anywhere in sight.
            let codec_rfc6381 = codec::rfc6381_video(&canon, t.codec_private.as_deref());
            let hdr = (t.matrix.is_some()
                || t.transfer.is_some()
                || t.primaries.is_some()
                || t.max_cll.is_some())
            .then(|| Hdr {
                format: codec::hdr_format(t.transfer.as_deref(), t.primaries.as_deref()),
                matrix: t.matrix.clone(),
                transfer: t.transfer.clone(),
                primaries: t.primaries.clone(),
                max_cll: t.max_cll,
                max_fall: t.max_fall,
            });
            let (w, h) = (t.width.unwrap_or(0), t.height.unwrap_or(0));
            // DisplayUnit 0 is pixels and 3 is a bare aspect ratio; the
            // other units (cm, inches) describe a physical screen and
            // say nothing about the pixels.
            let display_ar = match (t.disp_w, t.disp_h, t.disp_unit) {
                (Some(dw), Some(dh), 0 | 3) if ratio(dw, dh) != ratio(w, h) => ratio(dw, dh),
                _ => None,
            };
            st.filed.push((t.uid, t.number, true));
            info.video.push(VideoTrack {
                codec: canon,
                codec_id: raw,
                width: u32::try_from(w).unwrap_or(0),
                height: u32::try_from(h).unwrap_or(0),
                display_ar,
                fps: t
                    .default_duration
                    .filter(|d| *d > 0)
                    .and_then(|d| round3(1e9 / d as f64)),
                bit_depth: t.bit_depth.or(cp_depth),
                hdr,
                profile,
                level,
                bitrate: None,
                codec_rfc6381,
                enabled: t.enabled,
                default: t.default,
            });
        }
        Some(TRACK_AUDIO) => {
            let (canon, _) = codec::lookup(info.container, &raw, false);
            let codec_rfc6381 = codec::rfc6381_audio(&canon);
            let ch = t.channels.unwrap_or(0);
            st.filed.push((t.uid, t.number, false));
            info.audio.push(AudioTrack {
                codec: canon,
                codec_id: raw,
                lang,
                channels: u32::try_from(ch).unwrap_or(0),
                channel_layout: codec::channel_layout(u32::try_from(ch).unwrap_or(0)),
                // OutputSamplingFrequency wins when present: an SBR
                // track's real output rate is double the core rate.
                sample_rate: t
                    .out_sample_rate
                    .or(t.sample_rate)
                    .filter(|f| f.is_finite() && *f > 0.0 && *f < 1e9)
                    .map(|f| f.round() as u32),
                title: t.name,
                default: t.default,
                forced: t.forced,
                bitrate: None,
                codec_rfc6381,
                enabled: t.enabled,
            });
        }
        Some(TRACK_SUBTITLE) => {
            let (canon, kind) = codec::lookup_sub(info.container, &raw);
            info.subtitles.push(SubTrack {
                codec: canon,
                codec_id: raw,
                lang,
                title: t.name,
                default: t.default,
                forced: t.forced,
                kind,
            });
        }
        // Buttons, logos, control tracks: not something a viewer is
        // checking for, and not worth a warning.
        _ => {}
    }
}

/// The BITMAPINFOHEADER fourcc a VFW-wrapped track really is. `None`
/// for any other CodecID, and for a wrapper whose private data is too
/// short to hold the header it claims.
fn vfw_fourcc(codec_id: &str, cp: Option<&[u8]>) -> Option<String> {
    if !codec_id.to_ascii_lowercase().starts_with("v_ms/vfw/fourcc") {
        return None;
    }
    let cc = cp?.get(16..20)?;
    let s = String::from_utf8_lossy(cc)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string();
    (!s.is_empty()).then_some(s)
}

/// avcC / hvcC / av1C, the only CodecPrivate layouts worth reading: they
/// carry the profile and level a viewer compares against "will my TV
/// play this".
fn codec_private_video(
    canon: &str,
    cp: Option<&[u8]>,
) -> (Option<String>, Option<String>, Option<u8>) {
    let Some(cp) = cp else {
        return (None, None, None);
    };
    match canon {
        "h264" if cp.len() >= 4 => {
            let profile = match cp[1] {
                66 => "Baseline",
                77 => "Main",
                88 => "Extended",
                100 => "High",
                110 => "High 10",
                122 => "High 4:2:2",
                244 => "High 4:4:4",
                _ => "",
            };
            let depth = if matches!(cp[1], 110 | 122 | 244) {
                10
            } else {
                8
            };
            (
                (!profile.is_empty()).then(|| profile.to_string()),
                Some(format!("{}.{}", cp[3] / 10, cp[3] % 10)),
                Some(depth),
            )
        }
        "hevc" if cp.len() >= 13 => {
            let prof = cp[1] & 0x1F;
            let name = match prof {
                1 => "Main",
                2 => "Main 10",
                3 => "Main Still Picture",
                4 => "Rext",
                _ => "",
            };
            let idc = cp[12];
            (
                (!name.is_empty()).then(|| name.to_string()),
                Some(format!("{}.{}", idc / 30, (idc % 30) / 3)),
                Some(if prof == 2 { 10 } else { 8 }),
            )
        }
        "av1" if cp.len() >= 3 => {
            let seq_profile = (cp[1] >> 5) & 0x07;
            let level_idx = cp[1] & 0x1F;
            let high_bitdepth = (cp[2] >> 6) & 1;
            (
                Some(format!("Profile {seq_profile}")),
                Some(format!("{}.{}", 2 + level_idx / 4, level_idx % 4)),
                Some(if high_bitdepth == 1 { 10 } else { 8 }),
            )
        }
        _ => (None, None, None),
    }
}

fn leaf<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
    st: &mut State,
    id: u32,
    len: u64,
) -> Result<(), ProbeError> {
    // Everything below is a small scalar or a short string; a leaf that
    // declares more than its cap is read up to the cap and no further.
    match id {
        DOC_TYPE => {
            if let Some(s) = rd.read_string(len)? {
                info.container = match s.as_str() {
                    "webm" => Container::Webm,
                    "matroska" => Container::Mkv,
                    other => {
                        info.warn(format!("unusual EBML doctype {other}"));
                        info.container
                    }
                };
            }
        }
        SEEK_ID => {
            let b = rd.read_leaf(len, 4)?;
            let mut v: u32 = 0;
            for x in &b {
                v = (v << 8) | u32::from(*x);
            }
            st.cur_seek_id = Some(v);
        }
        SEEK_POSITION => st.cur_seek_pos = uint(rd, len)?,
        TIMESTAMP_SCALE => {
            if let Some(v) = uint(rd, len)?
                && v > 0
            {
                st.scale = v as f64;
            }
        }
        DURATION => st.raw_duration = float(rd, len)?,
        TITLE => {
            if info.title.is_none() {
                info.title = rd
                    .read_string(len)?
                    .map(|t| crate::mkv::strip_muxer_credit(&t).to_string())
                    .filter(|t| !t.is_empty());
            }
        }
        TRACK_NUMBER => st.track.number = uint(rd, len)?,
        TRACK_UID => st.track.uid = uint(rd, len)?,
        TRACK_TYPE => st.track.kind = uint(rd, len)?,
        FLAG_ENABLED => st.track.enabled = uint(rd, len)?.unwrap_or(1) != 0,
        FLAG_DEFAULT => st.track.default = uint(rd, len)?.unwrap_or(1) != 0,
        FLAG_FORCED => st.track.forced = uint(rd, len)?.unwrap_or(0) != 0,
        DEFAULT_DURATION => st.track.default_duration = uint(rd, len)?,
        NAME => st.track.name = rd.read_string(len)?,
        LANGUAGE => st.track.lang = rd.read_string(len)?,
        LANGUAGE_BCP47 => st.track.lang_bcp47 = rd.read_string(len)?,
        CODEC_ID => st.track.codec_id = rd.read_string(len)?,
        CODEC_PRIVATE => st.track.codec_private = Some(rd.read_leaf(len, MAX_CODEC_PRIVATE)?),
        PIXEL_WIDTH => st.track.width = uint(rd, len)?,
        PIXEL_HEIGHT => st.track.height = uint(rd, len)?,
        DISPLAY_WIDTH => st.track.disp_w = uint(rd, len)?,
        DISPLAY_HEIGHT => st.track.disp_h = uint(rd, len)?,
        DISPLAY_UNIT => st.track.disp_unit = uint(rd, len)?.unwrap_or(0),
        MATRIX_COEFFICIENTS => {
            st.track.matrix = uint(rd, len)?
                .and_then(codec::matrix_name)
                .map(str::to_string)
        }
        BITS_PER_CHANNEL => st.track.bit_depth = uint(rd, len)?.and_then(|v| u8::try_from(v).ok()),
        TRANSFER_CHARACTERISTICS => {
            st.track.transfer = uint(rd, len)?
                .and_then(codec::transfer_name)
                .map(str::to_string)
        }
        PRIMARIES => {
            st.track.primaries = uint(rd, len)?
                .and_then(codec::primaries_name)
                .map(str::to_string)
        }
        MAX_CLL => st.track.max_cll = uint(rd, len)?.and_then(|v| u32::try_from(v).ok()),
        MAX_FALL => st.track.max_fall = uint(rd, len)?.and_then(|v| u32::try_from(v).ok()),
        SAMPLING_FREQUENCY => st.track.sample_rate = float(rd, len)?,
        OUTPUT_SAMPLING_FREQUENCY => st.track.out_sample_rate = float(rd, len)?,
        CHANNELS => st.track.channels = uint(rd, len)?,
        CHAPTER_TIME_START => st.chap_start = uint(rd, len)?,
        CHAP_STRING => {
            if st.chap_title.is_none() {
                st.chap_title = rd.read_string(len)?;
            }
        }
        TAG_TRACK_UID => st.tag_uid = uint(rd, len)?,
        TAG_NAME => st.tag_name = rd.read_string(len.min(MAX_STRING as u64))?,
        TAG_STRING => st.tag_value = rd.read_string(len)?,
        _ => {}
    }
    Ok(())
}

fn uint<R: Read + Seek>(rd: &mut Rd<R>, len: u64) -> Result<Option<u64>, ProbeError> {
    // Size 0 is a legal encoding of zero; longer than 8 bytes is not an
    // integer any Matroska element uses.
    if len > 8 {
        return Ok(None);
    }
    let b = rd.read_leaf(len, 8)?;
    Ok(be_uint(&b))
}

fn float<R: Read + Seek>(rd: &mut Rd<R>, len: u64) -> Result<Option<f64>, ProbeError> {
    if !matches!(len, 0 | 4 | 8) {
        return Ok(None);
    }
    let b = rd.read_leaf(len, 8)?;
    Ok(match b.len() {
        0 => Some(0.0),
        4 => b[..4]
            .try_into()
            .ok()
            .map(|a| f64::from(f32::from_be_bytes(a))),
        _ => b[..8].try_into().ok().map(f64::from_be_bytes),
    })
}

/// An element id, marker bits KEPT - that is how the spec writes ids, so
/// `TrackEntry` compares equal to `0xAE`.
fn read_id<R: Read + Seek>(rd: &mut Rd<R>) -> Result<(u32, usize), ProbeError> {
    let mut b = [0u8; 4];
    rd.read_exact(&mut b[..1])?;
    // A leading zero byte would mean a 9+ byte id, which does not
    // exist - and treating it as one would let a run of zeros advance
    // the walk by nothing at all.
    if b[0] == 0 {
        return Err(ProbeError::Malformed {
            container: "mkv",
            what: "element id",
        });
    }
    let len = (b[0].leading_zeros() as usize) + 1;
    if len > 4 {
        return Err(ProbeError::Malformed {
            container: "mkv",
            what: "element id",
        });
    }
    if len > 1 {
        rd.read_exact(&mut b[1..len])?;
    }
    let mut id: u32 = 0;
    for x in &b[..len] {
        id = (id << 8) | u32::from(*x);
    }
    Ok((id, len))
}

/// A data size, marker bit STRIPPED. `None` is the all-ones "unknown
/// size" form.
fn read_size<R: Read + Seek>(rd: &mut Rd<R>) -> Result<(Option<u64>, usize), ProbeError> {
    let mut b = [0u8; 8];
    rd.read_exact(&mut b[..1])?;
    if b[0] == 0 {
        return Err(ProbeError::Malformed {
            container: "mkv",
            what: "size vint",
        });
    }
    let len = (b[0].leading_zeros() as usize) + 1;
    if len > 8 {
        return Err(ProbeError::Malformed {
            container: "mkv",
            what: "size vint",
        });
    }
    if len > 1 {
        rd.read_exact(&mut b[1..len])?;
    }
    let mut v = u64::from(b[0]) & (0xFF >> len);
    for x in &b[1..len] {
        v = (v << 8) | u64::from(*x);
    }
    let all_ones = (1u64 << (7 * len)) - 1;
    Ok(((v != all_ones).then_some(v), len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn probe(b: &[u8]) -> MediaInfo {
        super::super::probe(
            &mut Cursor::new(b),
            super::super::ProbeHint {
                filename: None,
                known_size: Some(b.len() as u64),
            },
        )
        .expect("a well-formed mux probes")
    }

    #[test]
    fn vints_decode_by_their_leading_zeros() {
        let mut c = Cursor::new(vec![0x81u8]);
        let mut rd = Rd::new(&mut c, None).unwrap();
        assert_eq!(read_size(&mut rd).unwrap(), (Some(1), 1));

        let mut c = Cursor::new(vec![0x40u8, 0x02]);
        let mut rd = Rd::new(&mut c, None).unwrap();
        assert_eq!(read_size(&mut rd).unwrap(), (Some(2), 2));

        // All-ones is the unknown-size form, not a 127-byte element.
        let mut c = Cursor::new(vec![0xFFu8]);
        let mut rd = Rd::new(&mut c, None).unwrap();
        assert_eq!(read_size(&mut rd).unwrap(), (None, 1));

        // A leading zero byte has no valid width; accepting it would
        // let a run of zeros advance the walk by nothing.
        let mut c = Cursor::new(vec![0x00u8, 0x00]);
        let mut rd = Rd::new(&mut c, None).unwrap();
        assert!(read_size(&mut rd).is_err());

        let mut c = Cursor::new(vec![0xAEu8]);
        let mut rd = Rd::new(&mut c, None).unwrap();
        assert_eq!(read_id(&mut rd).unwrap(), (0xAE, 1));
    }

    #[test]
    fn an_element_header_running_past_its_parent_does_not_underflow() {
        // Found by the mediaprobe fuzz target, 4 Aug. `elem_end` is clamped
        // to the parent's `limit`, but `body` sits past the ID and size
        // fields, so an element whose own header crosses that limit leaves
        // `body > elem_end` - and `elem_end - body` underflowed. The loop
        // guard only checked `elem_end <= pos`, which this shape satisfies.
        //
        // Debug builds panicked outright. Release has no overflow-checks, so
        // there it wrapped to a near-u64::MAX payload length instead; every
        // leaf reader caps its own read, so that degraded to a misparse
        // rather than a huge allocation. The probe runs on files still
        // arriving off Usenet, before PAR2 has verified anything.
        let crash = [
            0x1a, 0x45, 0xdf, 0xa3, 0x81, 0xd7, 0x81, 0x81, 0xff, 0x6d, 0x81, 0x81, 0x76, 0x6d,
            0xff, 0x6d, 0xff,
        ];
        let out = super::super::probe(
            &mut Cursor::new(&crash[..]),
            super::super::ProbeHint {
                filename: None,
                known_size: Some(crash.len() as u64),
            },
        );
        // The only requirement is that it terminates without panicking; a
        // container this broken is free to probe to Err or to a partial Ok.
        if let Ok(i) = out {
            assert!(i.video.len() + i.audio.len() + i.subtitles.len() <= 64);
        }
    }

    #[test]
    fn a_full_mux_yields_every_track() {
        let b = super::super::testmux::mkv_full();
        let i = probe(&b);
        assert_eq!(i.container, Container::Mkv);
        assert_eq!(i.duration_ms, Some(60_000));
        assert_eq!(i.title.as_deref(), Some("Example.Movie.2019.1080p-GRP"));
        assert_eq!(i.video.len(), 1);
        let v = &i.video[0];
        assert_eq!(v.codec, "h264");
        assert_eq!(v.codec_id, "V_MPEG4/ISO/AVC");
        assert_eq!((v.width, v.height), (1920, 1080));
        assert_eq!(v.fps, Some(23.976));
        assert_eq!(v.profile.as_deref(), Some("High"));
        assert_eq!(v.level.as_deref(), Some("4.1"));
        // §73 phase 2: the string the panel asks the browser about,
        // spelled out of the same CodecPrivate the profile came from.
        assert_eq!(v.codec_rfc6381.as_deref(), Some("avc1.640029"));
        assert_eq!(i.audio.len(), 2);
        assert_eq!(i.audio[0].codec, "aac");
        assert_eq!(i.audio[0].codec_rfc6381.as_deref(), Some("mp4a.40.2"));
        assert_eq!(i.audio[0].lang, "en");
        assert_eq!(i.audio[0].channels, 2);
        assert_eq!(i.audio[0].channel_layout, "stereo");
        assert_eq!(i.audio[0].sample_rate, Some(48_000));
        // The /B spelling mkvmerge writes must land on the same code as
        // the /T one.
        assert_eq!(i.audio[1].codec, "ac3");
        // The one that decides "plays" from "plays, silently".
        assert_eq!(i.audio[1].codec_rfc6381.as_deref(), Some("ac-3"));
        assert_eq!(i.audio[1].lang, "de");
        assert_eq!(i.audio[1].channels, 6);
        assert_eq!(i.audio[1].channel_layout, "5.1");
        assert_eq!(i.subtitles.len(), 2);
        assert_eq!(
            (i.subtitles[0].codec.as_str(), i.subtitles[0].lang.as_str()),
            ("srt", "en")
        );
        assert!(i.subtitles[0].forced);
        assert_eq!(i.subtitles[1].codec, "pgs");
        assert_eq!(i.subtitles[1].kind, super::super::SubKind::Bitmap);
        assert_eq!(i.playback, super::super::PlaybackPath::Transcode);
        assert!(i.complete, "warnings: {:?}", i.warnings);
    }

    #[test]
    fn hdr_signalling_is_read_off_the_colour_element() {
        let b = super::super::testmux::mkv_hdr();
        let i = probe(&b);
        let v = &i.video[0];
        assert_eq!(v.codec, "hevc");
        assert_eq!(v.bit_depth, Some(10));
        let hdr = v.hdr.as_ref().expect("colour element parsed");
        assert_eq!(hdr.format, "HDR10");
        assert_eq!(hdr.transfer.as_deref(), Some("pq"));
        assert_eq!(hdr.primaries.as_deref(), Some("bt2020"));
        assert_eq!(hdr.matrix.as_deref(), Some("bt2020nc"));
        assert_eq!(hdr.max_cll, Some(1000));
        assert_eq!(hdr.max_fall, Some(400));
        assert!(
            i.warnings
                .iter()
                .any(|w| w.contains("hevc video needs transcoding"))
        );
    }

    #[test]
    fn chapters_come_out_in_order_with_their_titles() {
        let b = super::super::testmux::mkv_chapters();
        let i = probe(&b);
        assert_eq!(
            i.chapters,
            vec![
                Chapter {
                    start_ms: 0,
                    title: "One".into()
                },
                Chapter {
                    start_ms: 250,
                    title: "Two".into()
                },
            ]
        );
    }

    /// A muxer that wrote Chapters after the clusters is the normal
    /// case, not an exotic one - and it is the shape that proves the
    /// SeekHead chase works, because the pre-cluster walk cannot reach
    /// them.
    #[test]
    fn chapters_behind_the_clusters_are_found_through_the_seekhead() {
        let b = super::super::testmux::mkv_seekhead_chapters();
        let i = probe(&b);
        assert_eq!(i.chapters.len(), 2);
        assert_eq!(i.chapters[1].title, "Two");
        assert!(i.complete, "warnings: {:?}", i.warnings);
    }

    /// A SeekHead that lists one target twice is one element, and one
    /// walk. Before the offset dedupe both entries survived the filter
    /// (it is evaluated once, before the loop) and both were walked, so
    /// every chapter was pushed twice.
    #[test]
    fn a_target_listed_twice_is_walked_once() {
        let b = super::super::testmux::mkv_seekhead_same_target_twice();
        let i = probe(&b);
        assert_eq!(
            i.chapters,
            vec![
                Chapter {
                    start_ms: 0,
                    title: "One".into()
                },
                Chapter {
                    start_ms: 250,
                    title: "Two".into()
                },
            ]
        );
        assert!(i.complete, "warnings: {:?}", i.warnings);
    }

    /// The honest-mux doubling: a tail of [Tags][Chapters] with both
    /// indexed. The walk from Tags used to run past the end of its own
    /// target into the Chapters behind it, and the Chapters target then
    /// parsed the same element again.
    #[test]
    fn a_chase_walk_stops_at_the_end_of_its_own_target() {
        let b = super::super::testmux::mkv_seekhead_tags_before_chapters();
        let i = probe(&b);
        assert_eq!(
            i.chapters,
            vec![
                Chapter {
                    start_ms: 0,
                    title: "One".into()
                },
                Chapter {
                    start_ms: 250,
                    title: "Two".into()
                },
            ]
        );
        assert!(i.complete, "warnings: {:?}", i.warnings);
    }

    /// The negative control for that dedupe. Two Chapters elements at
    /// two offsets are two elements: the key is the resolved offset, so
    /// both are walked and both contribute. A key of "the element ID"
    /// or a re-check of `seen_chapters` inside the loop would pass the
    /// two tests above and silently lose "Three"/"Four" here.
    #[test]
    fn two_distinct_chapters_elements_both_survive_the_dedupe() {
        let b = super::super::testmux::mkv_seekhead_two_chapter_elements();
        let i = probe(&b);
        assert_eq!(
            i.chapters
                .iter()
                .map(|c| c.title.as_str())
                .collect::<Vec<_>>(),
            vec!["One", "Two", "Three", "Four"]
        );
        assert_eq!(
            i.chapters.iter().map(|c| c.start_ms).collect::<Vec<_>>(),
            vec![0, 250, 500, 750]
        );
    }

    /// A front SeekHead that names only a SECOND SeekHead, which names
    /// the Chapters. That is the deferred-index mux - a small
    /// fixed-size index up front, the real one in the tail - and it is
    /// ordinary, specified Matroska. Before the chase became a
    /// worklist this returned ZERO chapters with `complete` still true,
    /// by two independent mechanisms: the target filter refused
    /// SEEK_HEAD, and the target list was a snapshot taken before the
    /// loop, so the second index's entries arrived too late to be read.
    #[test]
    fn chapters_behind_a_second_chained_seekhead_are_found() {
        let b = super::super::testmux::mkv_seekhead_chained();
        let i = probe(&b);
        assert_eq!(
            i.chapters,
            vec![
                Chapter {
                    start_ms: 0,
                    title: "One".into()
                },
                Chapter {
                    start_ms: 250,
                    title: "Two".into()
                },
            ]
        );
        assert!(i.complete, "warnings: {:?}", i.warnings);
    }

    /// The cycle control, RUN rather than argued: two SeekHeads naming
    /// each other, with the Chapters reachable only through the second.
    /// A worklist over offsets a hostile file chose has to terminate on
    /// its own - the resolved-offset set is what does it, on the second
    /// visit - and it has to terminate with the file's real contents
    /// rather than a budget warning or a doubled chapter list.
    #[test]
    fn a_seekhead_cycle_terminates_and_still_reads_what_is_there() {
        for (what, b) in [
            ("mutual", super::super::testmux::mkv_seekhead_cycle()),
            ("self", super::super::testmux::mkv_seekhead_self_loop()),
        ] {
            let i = probe(&b);
            assert_eq!(
                i.chapters
                    .iter()
                    .map(|c| c.title.as_str())
                    .collect::<Vec<_>>(),
                vec!["One", "Two"],
                "{what} cycle"
            );
            assert!(i.complete, "{what} cycle warnings: {:?}", i.warnings);
        }
    }

    /// V_MS/VFW/FOURCC is a wrapper, not a codec. The real id is the
    /// BITMAPINFOHEADER fourcc inside CodecPrivate - reading it is what
    /// keeps this table and the naming path's from disagreeing about
    /// what the wrapper "means".
    #[test]
    fn a_vfw_wrapped_track_is_resolved_from_its_codec_private() {
        let b = super::super::testmux::mkv_vfw_xvid();
        let i = probe(&b);
        assert_eq!(i.video[0].codec, "mpeg4");
        assert_eq!(i.video[0].codec_id, "V_MS/VFW/FOURCC");
        assert_eq!(i.playback, super::super::PlaybackPath::Transcode);
        // Without the private data there is nothing to resolve, and
        // guessing would be worse than saying so.
        assert_eq!(vfw_fourcc("V_MS/VFW/FOURCC", None), None);
        assert_eq!(vfw_fourcc("V_MPEG4/ISO/AVC", Some(&[0u8; 40])), None);
    }

    #[test]
    fn a_webm_doctype_is_reported_as_webm() {
        let b = super::super::testmux::webm();
        let i = probe(&b);
        assert_eq!(i.container, Container::Webm);
        assert_eq!(i.video[0].codec, "vp9");
        assert_eq!(i.audio[0].codec, "opus");
        assert_eq!(i.playback, super::super::PlaybackPath::Remux);
    }

    #[test]
    fn a_disabled_track_is_listed_but_flagged() {
        let b = super::super::testmux::mkv_disabled_track();
        let i = probe(&b);
        assert_eq!(i.audio.len(), 2);
        assert!(i.audio[0].enabled);
        assert!(!i.audio[1].enabled);
        // The disabled DTS track does not drag the file onto the
        // transcode path.
        assert_eq!(i.playback, super::super::PlaybackPath::Remux);
    }
}
