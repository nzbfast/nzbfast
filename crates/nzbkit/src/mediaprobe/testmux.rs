//! Synthetic containers: the fixtures this parser is tested against.
//!
//! The spec called for ffmpeg-generated files committed as binaries.
//! They are built in Rust instead, for three reasons that all point the
//! same way: the build box has no ffmpeg, a committed binary fixture
//! cannot be diffed when a test starts failing, and a generator lets a
//! test ask for the exact shape it is about (a moov at the end, a
//! Chapters element behind the clusters, a disabled track) instead of
//! whatever an encoder happened to write. Real-file coverage comes from
//! the fuzz corpus and from the daemon-side live probe.
//!
//! Public and `#[doc(hidden)]` on the same footing as
//! [`crate::mkv::test_mux`]: the integration suite and the fuzz seed
//! corpus both build against it.
#![doc(hidden)]

// ---------------------------------------------------------------------------
// EBML
// ---------------------------------------------------------------------------

/// One EBML element. The size is always written as a 4-byte vint so
/// that a builder can compute a later element's offset without having
/// to know how big the length field turned out to be - which is what
/// the SeekHead fixture needs.
pub fn el(id: &[u8], payload: &[u8]) -> Vec<u8> {
    let n = payload.len() as u32;
    assert!(n < 1 << 28, "test element too large");
    let mut v = id.to_vec();
    v.extend_from_slice(&[
        0x10 | (n >> 24) as u8,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
    ]);
    v.extend_from_slice(payload);
    v
}

/// An unsigned integer leaf, in the shortest big-endian form.
pub fn uint(id: &[u8], v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    el(id, &bytes[first..])
}

pub fn f64el(id: &[u8], v: f64) -> Vec<u8> {
    el(id, &v.to_be_bytes())
}

pub fn str_el(id: &[u8], v: &str) -> Vec<u8> {
    el(id, v.as_bytes())
}

const EBML_HEADER: &[u8] = &[0x1A, 0x45, 0xDF, 0xA3];
const SEGMENT: &[u8] = &[0x18, 0x53, 0x80, 0x67];

fn ebml_head(doctype: &str) -> Vec<u8> {
    el(EBML_HEADER, &str_el(&[0x42, 0x82], doctype))
}

/// Segment>Info with a millisecond timestamp scale.
fn info(duration_ms: f64, title: Option<&str>) -> Vec<u8> {
    let mut body = uint(&[0x2A, 0xD7, 0xB1], 1_000_000);
    if let Some(t) = title {
        body.extend(str_el(&[0x7B, 0xA9], t));
    }
    body.extend(f64el(&[0x44, 0x89], duration_ms));
    el(&[0x15, 0x49, 0xA9, 0x66], &body)
}

/// A video TrackEntry: h264 unless `codec` says otherwise.
fn video_track(codec: &str, private: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut e = uint(&[0x83], 1); // TrackType video
    e.extend(uint(&[0xD7], 1)); // TrackNumber
    e.extend(uint(&[0x73, 0xC5], 0x1111)); // TrackUID
    e.extend(str_el(&[0x86], codec));
    if !private.is_empty() {
        e.extend(el(&[0x63, 0xA2], private));
    }
    e.extend(uint(&[0x23, 0xE3, 0x83], 41_708_333)); // DefaultDuration
    let mut v = uint(&[0xB0], 1920);
    v.extend(uint(&[0xBA], 1080));
    v.extend_from_slice(extra);
    e.extend(el(&[0xE0], &v));
    el(&[0xAE], &e)
}

fn audio_track(
    number: u64,
    codec: &str,
    lang: &str,
    channels: u64,
    rate: f64,
    enabled: bool,
) -> Vec<u8> {
    let mut e = uint(&[0x83], 2);
    e.extend(uint(&[0xD7], number));
    e.extend(uint(&[0x73, 0xC5], 0x2000 + number));
    e.extend(str_el(&[0x86], codec));
    e.extend(str_el(&[0x22, 0xB5, 0x9C], lang));
    if !enabled {
        e.extend(uint(&[0xB9], 0)); // FlagEnabled
    }
    let mut a = uint(&[0x9F], channels);
    a.extend(f64el(&[0xB5], rate));
    e.extend(el(&[0xE1], &a));
    el(&[0xAE], &e)
}

fn sub_track(number: u64, codec: &str, lang: &str, forced: bool) -> Vec<u8> {
    let mut e = uint(&[0x83], 0x11);
    e.extend(uint(&[0xD7], number));
    e.extend(str_el(&[0x86], codec));
    e.extend(str_el(&[0x22, 0xB5, 0x9C], lang));
    if forced {
        e.extend(uint(&[0x55, 0xAA], 1));
    }
    el(&[0xAE], &e)
}

fn tracks(entries: &[Vec<u8>]) -> Vec<u8> {
    el(&[0x16, 0x54, 0xAE, 0x6B], &entries.concat())
}

fn chapters(list: &[(u64, &str)]) -> Vec<u8> {
    let mut edition = uint(&[0x45, 0xBC], 1); // EditionUID
    for (start_ms, title) in list {
        let mut atom = uint(&[0x91], start_ms * 1_000_000); // ChapterTimeStart
        atom.extend(el(&[0x80], &str_el(&[0x85], title))); // ChapterDisplay
        edition.extend(el(&[0xB6], &atom));
    }
    el(&[0x10, 0x43, 0xA7, 0x70], &el(&[0x45, 0xB9], &edition))
}

/// avcC: High profile, level 4.1.
const AVCC: &[u8] = &[1, 100, 0, 41, 0xFF, 0xE1, 0, 0];
/// hvcC: Main 10, level 5.1 (general_level_idc 153).
const HVCC: &[u8] = &[1, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 153, 0];

pub fn mkv_full() -> Vec<u8> {
    let mut seg = info(60_000.0, Some("Example.Movie.2019.1080p-GRP, RMZ.cr"));
    seg.extend(tracks(&[
        video_track("V_MPEG4/ISO/AVC", AVCC, &[]),
        audio_track(2, "A_AAC", "eng", 2, 48_000.0, true),
        audio_track(3, "A_AC3", "ger", 6, 48_000.0, true),
        sub_track(4, "S_TEXT/UTF8", "eng", true),
        sub_track(5, "S_HDMV/PGS", "fre", false),
    ]));
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

/// Matroska carrying ONLY audio - what a `.mka` external track is.
///
/// Its DocType is "matroska" and its magic is the same four bytes as any
/// `.mkv`, which is the whole point: no amount of head-sniffing can tell
/// this from a feature, so anything deciding "is this a video" has to
/// read the track types. Used by nzbfast's `video_ext` to prove a
/// nameless audio payload is not offered as a rename candidate.
pub fn mka() -> Vec<u8> {
    let mut seg = info(60_000.0, None);
    seg.extend(tracks(&[audio_track(1, "A_AAC", "eng", 2, 48_000.0, true)]));
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

pub fn mkv_hdr() -> Vec<u8> {
    let mut colour = uint(&[0x55, 0xB1], 9); // bt2020nc
    colour.extend(uint(&[0x55, 0xB2], 10)); // BitsPerChannel
    colour.extend(uint(&[0x55, 0xBA], 16)); // pq
    colour.extend(uint(&[0x55, 0xBB], 9)); // bt2020
    colour.extend(uint(&[0x55, 0xBC], 1000)); // MaxCLL
    colour.extend(uint(&[0x55, 0xBD], 400)); // MaxFALL
    let mut seg = info(60_000.0, None);
    seg.extend(tracks(&[
        video_track("V_MPEGH/ISO/HEVC", HVCC, &el(&[0x55, 0xB0], &colour)),
        audio_track(2, "A_EAC3", "eng", 6, 48_000.0, true),
    ]));
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

pub fn mkv_chapters() -> Vec<u8> {
    let mut seg = info(60_000.0, None);
    seg.extend(tracks(&[video_track("V_MPEG4/ISO/AVC", AVCC, &[])]));
    seg.extend(chapters(&[(0, "One"), (250, "Two")]));
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

/// Chapters written AFTER the clusters, reachable only through the
/// SeekHead - the Matroska twin of a trailing moov.
pub fn mkv_seekhead_chapters() -> Vec<u8> {
    let info_el = info(60_000.0, None);
    let tracks_el = tracks(&[video_track("V_MPEG4/ISO/AVC", AVCC, &[])]);
    // A cluster the walk must stop at, so the Chapters behind it can
    // only be found through the index.
    let cluster = el(&[0x1F, 0x43, 0xB6, 0x75], &uint(&[0xE7], 0));
    let chapters_el = chapters(&[(0, "One"), (250, "Two")]);

    // SeekPosition is written as a fixed 8-byte integer so the index's
    // own size does not depend on the offset it is about to carry.
    let seek_entry = |id: &[u8], pos: u64| {
        let mut s = el(&[0x53, 0xAB], id);
        s.extend(el(&[0x53, 0xAC], &pos.to_be_bytes()));
        el(&[0x4D, 0xBB], &s)
    };
    let head_len = el(
        &[0x11, 0x4D, 0x9B, 0x74],
        &seek_entry(&[0x10, 0x43, 0xA7, 0x70], 0),
    )
    .len();
    let chapters_at = (head_len + info_el.len() + tracks_el.len() + cluster.len()) as u64;
    let seek_head = el(
        &[0x11, 0x4D, 0x9B, 0x74],
        &seek_entry(&[0x10, 0x43, 0xA7, 0x70], chapters_at),
    );
    assert_eq!(seek_head.len(), head_len, "seek head size must be stable");

    let mut seg = seek_head;
    seg.extend(info_el);
    seg.extend(tracks_el);
    seg.extend(cluster);
    seg.extend(chapters_el);
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

/// [`mkv_full`] with a payload cluster of `bytes` junk after the
/// header, so a test has a file of a realistic SIZE without a realistic
/// encode. The walk stops at the cluster exactly as it does on a real
/// mux, so the parse stays complete.
pub fn mkv_padded(bytes: usize) -> Vec<u8> {
    let mut seg = info(60_000.0, Some("Example.Movie.2019.1080p-GRP"));
    seg.extend(tracks(&[
        video_track("V_MPEG4/ISO/AVC", AVCC, &[]),
        audio_track(2, "A_AAC", "eng", 2, 48_000.0, true),
        sub_track(3, "S_TEXT/UTF8", "eng", false),
    ]));
    seg.extend(el(&[0x1F, 0x43, 0xB6, 0x75], &vec![0x5Au8; bytes]));
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

/// A track wrapped in VFW: the CodecID says nothing, the
/// BITMAPINFOHEADER inside CodecPrivate says XviD.
pub fn mkv_vfw_xvid() -> Vec<u8> {
    let mut bih = vec![0u8; 40];
    bih[0..4].copy_from_slice(&40u32.to_le_bytes());
    bih[4..8].copy_from_slice(&640u32.to_le_bytes());
    bih[8..12].copy_from_slice(&352u32.to_le_bytes());
    bih[16..20].copy_from_slice(b"XVID");
    let mut seg = info(60_000.0, None);
    seg.extend(tracks(&[
        video_track("V_MS/VFW/FOURCC", &bih, &[]),
        audio_track(2, "A_AAC", "eng", 2, 48_000.0, true),
    ]));
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

pub fn webm() -> Vec<u8> {
    let mut seg = info(30_000.0, None);
    seg.extend(tracks(&[
        video_track("V_VP9", &[], &[]),
        audio_track(2, "A_OPUS", "und", 2, 48_000.0, true),
    ]));
    let mut out = ebml_head("webm");
    out.extend(el(SEGMENT, &seg));
    out
}

pub fn mkv_disabled_track() -> Vec<u8> {
    let mut seg = info(60_000.0, None);
    seg.extend(tracks(&[
        video_track("V_MPEG4/ISO/AVC", AVCC, &[]),
        audio_track(2, "A_AAC", "eng", 2, 48_000.0, true),
        audio_track(3, "A_DTS", "eng", 6, 48_000.0, false),
    ]));
    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

// ---------------------------------------------------------------------------
// ISO base media
// ---------------------------------------------------------------------------

pub fn mp4box(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    v.extend_from_slice(kind);
    v.extend_from_slice(payload);
    v
}

fn full(version: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![version, 0, 0, 0];
    v.extend_from_slice(body);
    v
}

fn mvhd(timescale: u32, duration: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0u32.to_be_bytes()); // creation
    b.extend(0u32.to_be_bytes()); // modification
    b.extend(timescale.to_be_bytes());
    b.extend(duration.to_be_bytes());
    b.extend([0u8; 80]); // rate, volume, matrix, predefined, next track id
    mp4box(b"mvhd", &full(0, &b))
}

fn tkhd(track_id: u32, width: u32, height: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0u32.to_be_bytes());
    b.extend(0u32.to_be_bytes());
    b.extend(track_id.to_be_bytes());
    b.extend(0u32.to_be_bytes());
    b.extend(0u32.to_be_bytes()); // duration
    b.extend([0u8; 8]);
    b.extend([0u8; 8]); // layer, alt group, volume, reserved
    b.extend([0u8; 36]); // matrix
    b.extend((width << 16).to_be_bytes());
    b.extend((height << 16).to_be_bytes());
    // Track_enabled is flag bit 0.
    let mut v = vec![0u8, 0, 0, 1];
    v.extend(b);
    mp4box(b"tkhd", &v)
}

fn mdhd(timescale: u32, duration: u32, lang: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0u32.to_be_bytes());
    b.extend(0u32.to_be_bytes());
    b.extend(timescale.to_be_bytes());
    b.extend(duration.to_be_bytes());
    b.extend(lang.to_be_bytes());
    b.extend(0u16.to_be_bytes());
    mp4box(b"mdhd", &full(0, &b))
}

fn hdlr(kind: &[u8; 4]) -> Vec<u8> {
    let mut b = 0u32.to_be_bytes().to_vec();
    b.extend_from_slice(kind);
    b.extend([0u8; 12]);
    b.push(0);
    mp4box(b"hdlr", &full(0, &b))
}

fn visual_entry(fourcc: &[u8; 4], width: u16, height: u16, children: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 78];
    b[24..26].copy_from_slice(&width.to_be_bytes());
    b[26..28].copy_from_slice(&height.to_be_bytes());
    b.extend_from_slice(children);
    mp4box(fourcc, &b)
}

fn audio_entry(fourcc: &[u8; 4], channels: u16, rate: u32, children: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 28];
    b[16..18].copy_from_slice(&channels.to_be_bytes());
    b[24..28].copy_from_slice(&(rate << 16).to_be_bytes());
    b.extend_from_slice(children);
    mp4box(fourcc, &b)
}

/// A minimal `esds` whose DecoderConfigDescriptor says AAC at 128 kbps.
fn esds_aac() -> Vec<u8> {
    let mut dec = vec![0x40, 0x15]; // objectTypeIndication, streamType
    dec.extend([0, 0, 0]); // bufferSizeDB
    dec.extend(192_000u32.to_be_bytes()); // maxBitrate
    dec.extend(128_000u32.to_be_bytes()); // avgBitrate
    let mut dec_desc = vec![0x04, dec.len() as u8];
    dec_desc.extend(dec);

    let mut es = vec![0x00, 0x01, 0x00]; // ES_ID, flags
    es.extend(dec_desc);
    let mut es_desc = vec![0x03, es.len() as u8];
    es_desc.extend(es);
    mp4box(b"esds", &full(0, &es_desc))
}

fn stts(count: u32, delta: u32) -> Vec<u8> {
    let mut b = 1u32.to_be_bytes().to_vec(); // one entry
    b.extend(count.to_be_bytes());
    b.extend(delta.to_be_bytes());
    mp4box(b"stts", &full(0, &b))
}

fn stbl(entry: &[u8], samples: u32, delta: u32) -> Vec<u8> {
    let mut b = 1u32.to_be_bytes().to_vec(); // one stsd entry
    b.extend_from_slice(entry);
    let mut out = mp4box(b"stsd", &full(0, &b));
    out.extend(stts(samples, delta));
    mp4box(b"stbl", &out)
}

fn video_trak() -> Vec<u8> {
    let avcc = mp4box(b"avcC", &[1, 100, 0, 40, 0xFF, 0xE1]);
    let entry = visual_entry(b"avc1", 1920, 1080, &avcc);
    let mut mdia = mdhd(24_000, 1_440_000, 0x55C4); // "und"
    mdia.extend(hdlr(b"vide"));
    mdia.extend(mp4box(b"minf", &stbl(&entry, 1_440, 1_000)));
    let mut trak = tkhd(1, 1920, 1080);
    trak.extend(mp4box(b"mdia", &mdia));
    mp4box(b"trak", &trak)
}

fn audio_trak() -> Vec<u8> {
    let entry = audio_entry(b"mp4a", 2, 48_000, &esds_aac());
    let mut mdia = mdhd(48_000, 2_880_000, 0x15C7); // "eng"
    mdia.extend(hdlr(b"soun"));
    mdia.extend(mp4box(b"minf", &stbl(&entry, 2_812, 1_024)));
    let mut trak = tkhd(2, 0, 0);
    trak.extend(mp4box(b"mdia", &mdia));
    mp4box(b"trak", &trak)
}

fn moov() -> Vec<u8> {
    let mut b = mvhd(1_000, 60_000);
    b.extend(video_trak());
    b.extend(audio_trak());
    mp4box(b"moov", &b)
}

fn ftyp() -> Vec<u8> {
    let mut b = b"isom".to_vec();
    b.extend(512u32.to_be_bytes());
    b.extend_from_slice(b"isomavc1mp41");
    mp4box(b"ftyp", &b)
}

pub fn mp4_faststart() -> Vec<u8> {
    let mut out = ftyp();
    out.extend(moov());
    out.extend(mp4box(b"mdat", &vec![0u8; 4096]));
    out
}

/// The shape that matters on a live download: the index is at the end,
/// behind a payload nobody has fetched.
pub fn mp4_moov_at_end() -> Vec<u8> {
    let mut out = ftyp();
    out.extend(mp4box(b"mdat", &vec![0u8; 65_536]));
    out.extend(moov());
    out
}

/// Where the `mdat` payload sits in [`mp4_moov_at_end`], for the test
/// that punches a hole over it.
pub fn mp4_moov_at_end_mdat() -> (u64, u64) {
    let start = ftyp().len() as u64 + 8;
    (start, start + 65_536)
}

// ---------------------------------------------------------------------------
// RIFF / AVI
// ---------------------------------------------------------------------------

fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = kind.to_vec();
    v.extend((payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        v.push(0);
    }
    v
}

fn list(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut body = kind.to_vec();
    body.extend_from_slice(payload);
    chunk(b"LIST", &body)
}

pub fn avi() -> Vec<u8> {
    let mut avih = vec![0u8; 56];
    avih[0..4].copy_from_slice(&41_667u32.to_le_bytes()); // us per frame
    avih[16..20].copy_from_slice(&12u32.to_le_bytes()); // total frames
    avih[32..36].copy_from_slice(&640u32.to_le_bytes());
    avih[36..40].copy_from_slice(&352u32.to_le_bytes());

    let mut vstrh = vec![0u8; 40];
    vstrh[0..4].copy_from_slice(b"vids");
    vstrh[4..8].copy_from_slice(b"XVID");
    vstrh[20..24].copy_from_slice(&1u32.to_le_bytes()); // scale
    vstrh[24..28].copy_from_slice(&24u32.to_le_bytes()); // rate
    let mut vstrf = vec![0u8; 40];
    vstrf[0..4].copy_from_slice(&40u32.to_le_bytes());
    vstrf[4..8].copy_from_slice(&640u32.to_le_bytes());
    vstrf[8..12].copy_from_slice(&352u32.to_le_bytes());
    vstrf[16..20].copy_from_slice(b"XVID");

    let mut astrh = vec![0u8; 40];
    astrh[0..4].copy_from_slice(b"auds");
    astrh[20..24].copy_from_slice(&1u32.to_le_bytes());
    astrh[24..28].copy_from_slice(&48_000u32.to_le_bytes());
    let mut astrf = vec![0u8; 18];
    astrf[0..2].copy_from_slice(&0x0055u16.to_le_bytes()); // mp3
    astrf[2..4].copy_from_slice(&2u16.to_le_bytes());
    astrf[4..8].copy_from_slice(&48_000u32.to_le_bytes());
    astrf[8..12].copy_from_slice(&16_000u32.to_le_bytes());

    let mut hdrl = chunk(b"avih", &avih);
    let mut vstrl = chunk(b"strh", &vstrh);
    vstrl.extend(chunk(b"strf", &vstrf));
    hdrl.extend(list(b"strl", &vstrl));
    let mut astrl = chunk(b"strh", &astrh);
    astrl.extend(chunk(b"strf", &astrf));
    hdrl.extend(list(b"strl", &astrl));

    let mut body = b"AVI ".to_vec();
    body.extend(list(b"hdrl", &hdrl));
    body.extend(list(b"movi", &vec![0u8; 256]));
    chunk(b"RIFF", &body)
}

// ---------------------------------------------------------------------------
// Remux fixtures: containers with actual payload in them
// ---------------------------------------------------------------------------
//
// Everything above describes a file; the remuxer needs one that also
// CONTAINS something. These two build a couple of seconds of synthetic
// elementary stream and wrap it in the shapes the sample walk has to
// survive: mixed SimpleBlock and BlockGroup, all three lacing modes,
// Cues reachable only through the SeekHead, and on the MP4 side a moov
// at the end with composition offsets and a sparse sync-sample table.
//
// The payloads are not real video - the remuxer never looks inside a
// sample, so a deterministic byte pattern proves exactly as much and
// can be regenerated rather than committed.

/// Deterministic sample payload: distinguishable per frame, so a
/// byte-identity assertion cannot pass by accident.
///
/// "Distinguishable" is not "unique as a substring", and a test that
/// SEARCHES a file for one frame has to know the difference. The filler
/// cycles every 256 bytes, and XOR by 0x80 is exactly a 128-byte shift
/// of that cycle - so `frame(t, n)` and `frame(t ^ 0x80, m)` are the
/// same bytes offset by 128, and whichever is longer contains the
/// shorter one whole. Since the tags here are `BASE ^ index`, that
/// pairs frame `i` with frame `i ^ 128`. Assert on the shorter-partner
/// side of such a pair, or assert on an offset rather than a search
/// (`nzbfast`'s `tests/integration/stream_repair.rs` does the former,
/// and checks it at runtime).
fn frame(tag: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| tag ^ (i as u8).wrapping_mul(31)).collect()
}

/// An unsigned EBML variable-size integer, shortest form.
fn vint(v: u64) -> Vec<u8> {
    for len in 1..=8u32 {
        let max = (1u64 << (7 * len)) - 1;
        if v < max {
            let mut out = Vec::with_capacity(len as usize);
            let marker = 1u64 << (7 * len);
            let x = v | marker;
            for i in (0..len).rev() {
                out.push((x >> (8 * i)) as u8);
            }
            return out;
        }
    }
    panic!("value too large for a vint");
}

/// A SIGNED EBML lace delta: biased by the midpoint of its width.
fn svint(v: i64) -> Vec<u8> {
    for len in 1..=8u32 {
        let bias = (1i64 << (7 * len - 1)) - 1;
        let max = (1i64 << (7 * len)) - 1;
        let biased = v + bias;
        if biased >= 0 && biased < max {
            return vint(biased as u64);
        }
    }
    panic!("delta too large for a signed vint");
}

/// A signed integer leaf, two's complement in the shortest form that
/// keeps the sign.
fn sint(id: &[u8], v: i64) -> Vec<u8> {
    let mut n = 1;
    while n < 8 && !(-(1i64 << (8 * n - 1))..1i64 << (8 * n - 1)).contains(&v) {
        n += 1;
    }
    el(id, &v.to_be_bytes()[8 - n..])
}

/// A SimpleBlock with an optional lacing mode.
///
/// `lacing`: 0 none, 1 Xiph, 2 fixed, 3 EBML - the wire encoding is
/// those two bits shifted into the flags byte.
fn simple_block(track: u64, rel: i16, key: bool, lacing: u8, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vint(track);
    b.extend(rel.to_be_bytes());
    let flags = if key { 0x80 } else { 0 } | (lacing << 1);
    b.push(flags);
    b.extend(lace_body(lacing, frames));
    el(&[0xA3], &b)
}

/// The lacing header plus the concatenated frames.
fn lace_body(lacing: u8, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    if lacing == 0 {
        assert_eq!(frames.len(), 1, "an unlaced block holds one frame");
        b.extend_from_slice(&frames[0]);
        return b;
    }
    b.push((frames.len() - 1) as u8);
    match lacing {
        // Xiph: 255-terminated runs for all but the last frame.
        1 => {
            for f in &frames[..frames.len() - 1] {
                let mut n = f.len();
                while n >= 255 {
                    b.push(255);
                    n -= 255;
                }
                b.push(n as u8);
            }
        }
        // Fixed: nothing written, the sizes must divide evenly.
        2 => {
            let first = frames[0].len();
            assert!(
                frames.iter().all(|f| f.len() == first),
                "fixed lacing needs equal frames"
            );
        }
        // EBML: an absolute first size then signed deltas.
        _ => {
            b.extend(vint(frames[0].len() as u64));
            for w in frames.windows(2).take(frames.len().saturating_sub(2)) {
                b.extend(svint(w[1].len() as i64 - w[0].len() as i64));
            }
        }
    }
    for f in frames {
        b.extend_from_slice(f);
    }
    b
}

/// A BlockGroup: the older framing, whose keyframe-ness is stated by the
/// ABSENCE of a ReferenceBlock.
fn block_group(track: u64, rel: i16, payload: &[u8], duration: Option<u64>, refs: bool) -> Vec<u8> {
    let mut blk = vint(track);
    blk.extend(rel.to_be_bytes());
    blk.push(0); // Block carries no keyframe bit at all
    blk.extend_from_slice(payload);
    let mut g = el(&[0xA1], &blk);
    if let Some(d) = duration {
        g.extend(uint(&[0x9B], d));
    }
    if refs {
        g.extend(sint(&[0xFB], -40));
    }
    el(&[0xA0], &g)
}

const CUES_ID: &[u8] = &[0x1C, 0x53, 0xBB, 0x6B];
const CLUSTER_ID: &[u8] = &[0x1F, 0x43, 0xB6, 0x75];

fn remux_video_track() -> Vec<u8> {
    let mut e = uint(&[0x83], 1); // TrackType video
    e.extend(uint(&[0xD7], 1)); // TrackNumber
    e.extend(uint(&[0x73, 0xC5], 0x1111));
    e.extend(str_el(&[0x86], "V_MPEG4/ISO/AVC"));
    e.extend(el(&[0x63, 0xA2], AVCC));
    e.extend(uint(&[0x23, 0xE3, 0x83], 40_000_000)); // 40 ms
    let mut v = uint(&[0xB0], 1280);
    v.extend(uint(&[0xBA], 720));
    e.extend(el(&[0xE0], &v));
    el(&[0xAE], &e)
}

/// AAC-LC, 48 kHz, stereo: the two-byte AudioSpecificConfig.
const ASC_AAC_LC_48_2: &[u8] = &[0x11, 0x90];

fn remux_audio_track() -> Vec<u8> {
    let mut e = uint(&[0x83], 2);
    e.extend(uint(&[0xD7], 2));
    e.extend(uint(&[0x73, 0xC5], 0x2222));
    e.extend(str_el(&[0x86], "A_AAC"));
    e.extend(str_el(&[0x22, 0xB5, 0x9C], "eng"));
    e.extend(el(&[0x63, 0xA2], ASC_AAC_LC_48_2));
    e.extend(uint(&[0x23, 0xE3, 0x83], 20_000_000)); // 20 ms
    let mut a = uint(&[0x9F], 2);
    a.extend(f64el(&[0xB5], 48_000.0));
    e.extend(el(&[0xE1], &a));
    el(&[0xAE], &e)
}

/// Frames per cluster and the timing they run at, stated once so the
/// fixture and its expected-output twin cannot drift apart.
///
/// Twenty-four clusters is eleven and a half seconds, which is the
/// smallest fixture that is honestly exercising: it spans several
/// two-second fragments (so the boundary rule runs more than once), and
/// a thirty-percent prefix of it still contains whole fragments, which
/// is what the arrival-pattern test needs in order to mean anything.
const CLUSTERS: usize = 24;
const V_PER_CLUSTER: usize = 12;
const V_STEP_MS: i64 = 40;
const A_PER_CLUSTER: usize = 24;
const A_STEP_MS: i64 = 20;

/// The video and audio payloads this fixture contains, in decode order.
/// The byte-identity test compares the remuxed `mdat` against these.
pub fn mkv_remux_streams() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    mkv_remux_streams_scaled(1)
}

/// The same streams with every frame `scale` times as long.
///
/// The frame COUNT, the timing and the block framing are untouched, so
/// a scaled fixture is the same walk over the same structure - only
/// heavier. That is what a test needs when the thing under test is not
/// the walk at all but the FILE: a posting whose articles take seconds
/// to arrive, whose damaged span sits megabytes past a player's
/// playhead, or whose remuxed output cannot fit in a socket buffer (see
/// `nzbfast`'s `tests/integration/stream_repair.rs`).
pub fn mkv_remux_streams_scaled(scale: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    assert!(scale >= 1, "a fixture cannot be scaled below its own size");
    let mut video = Vec::new();
    let mut audio = Vec::new();
    for k in 0..CLUSTERS {
        for j in 0..V_PER_CLUSTER {
            let n = k * V_PER_CLUSTER + j;
            // Sizes vary but do not grow without bound: a fixture that
            // is mostly one enormous frame stops testing the walk.
            video.push(frame(0xA0 ^ n as u8, (300 + (n % 40) * 7) * scale));
        }
        for j in 0..A_PER_CLUSTER {
            let n = k * A_PER_CLUSTER + j;
            // Every fourth cluster laces at a fixed size, which needs
            // equal frames.
            let size = if k % 4 == 2 { 160 } else { 140 + (n % 11) * 3 };
            audio.push(frame(0x50 ^ n as u8, size * scale));
        }
    }
    (video, audio)
}

/// A Matroska file with two seconds of payload, Cues behind the
/// clusters, and every block framing the walk has to handle.
pub fn mkv_remux_fixture() -> Vec<u8> {
    mkv_remux_fixture_scaled(1)
}

/// The same file built from [`mkv_remux_streams_scaled`] - identical in
/// structure, `scale` times the bytes.
pub fn mkv_remux_fixture_scaled(scale: usize) -> Vec<u8> {
    let (video, audio) = mkv_remux_streams_scaled(scale);
    let info_el = info(1_920.0, None);
    let tracks_el = tracks(&[remux_video_track(), remux_audio_track()]);

    let mut clusters: Vec<(u64, Vec<u8>)> = Vec::new();
    for k in 0..CLUSTERS {
        let cluster_ms = (k * V_PER_CLUSTER) as i64 * V_STEP_MS;
        let mut body = uint(&[0xE7], cluster_ms as u64);
        for j in 0..V_PER_CLUSTER {
            let n = k * V_PER_CLUSTER + j;
            let rel = (j as i64 * V_STEP_MS) as i16;
            let key = j == 0;
            if j == 5 {
                // One frame per cluster through the older framing, with
                // an explicit duration and a reference that makes it a
                // delta frame.
                body.extend(block_group(1, rel, &video[n], Some(40), true));
            } else {
                body.extend(simple_block(1, rel, key, 0, &video[n..n + 1]));
            }
        }
        // A different lacing mode every four clusters, so all three
        // encodings and the unlaced case are all walked repeatedly.
        let lacing = match k % 4 {
            0 => 3u8, // EBML
            1 => 1,   // Xiph
            2 => 2,   // fixed
            _ => 0,
        };
        let group = if lacing == 0 { 1 } else { 6 };
        let mut j = 0;
        while j < A_PER_CLUSTER {
            let n = k * A_PER_CLUSTER + j;
            let rel = (j as i64 * A_STEP_MS) as i16;
            let frames = &audio[n..n + group];
            body.extend(simple_block(2, rel, true, lacing, frames));
            j += group;
        }
        clusters.push((cluster_ms as u64, el(CLUSTER_ID, &body)));
    }

    // SeekPosition is written as a fixed 8-byte integer so the index's
    // own size does not move when the offset it carries does.
    let seek_entry = |id: &[u8], pos: u64| {
        let mut s = el(&[0x53, 0xAB], id);
        s.extend(el(&[0x53, 0xAC], &pos.to_be_bytes()));
        el(&[0x4D, 0xBB], &s)
    };
    let head_len = el(&[0x11, 0x4D, 0x9B, 0x74], &seek_entry(CUES_ID, 0)).len();

    let mut off = (head_len + info_el.len() + tracks_el.len()) as u64;
    let mut cue_body = Vec::new();
    for (ts, c) in &clusters {
        let mut pt = uint(&[0xB3], *ts);
        let mut pos = uint(&[0xF7], 1); // CueTrack
        pos.extend(uint(&[0xF1], off)); // CueClusterPosition
        pt.extend(el(&[0xB7], &pos));
        cue_body.extend(el(&[0xBB], &pt));
        off += c.len() as u64;
    }
    let cues_at = off;
    let seek_head = el(&[0x11, 0x4D, 0x9B, 0x74], &seek_entry(CUES_ID, cues_at));
    assert_eq!(seek_head.len(), head_len, "seek head size must be stable");

    let mut seg = seek_head;
    seg.extend(info_el);
    seg.extend(tracks_el);
    for (_, c) in &clusters {
        seg.extend_from_slice(c);
    }
    seg.extend(el(CUES_ID, &cue_body));

    let mut out = ebml_head("matroska");
    out.extend(el(SEGMENT, &seg));
    out
}

// --- MP4 ---

const MP4_V_SAMPLES: usize = 30;
const MP4_A_SAMPLES: usize = 60;
/// Samples per chunk, so the fixture exercises the stsc walk rather
/// than one chunk holding everything.
const MP4_V_PER_CHUNK: usize = 10;
const MP4_A_PER_CHUNK: usize = 20;
const MP4_V_TIMESCALE: u32 = 90_000;
const MP4_A_TIMESCALE: u32 = 48_000;
/// 30 fps in a 90 kHz timescale, and 1024 AAC samples at 48 kHz.
const MP4_V_DELTA: u32 = 3_000;
const MP4_A_DELTA: u32 = 1_024;

pub fn mp4_remux_streams() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let video = (0..MP4_V_SAMPLES)
        .map(|i| frame(0xC0 ^ i as u8, 200 + i * 3))
        .collect();
    let audio = (0..MP4_A_SAMPLES)
        .map(|i| frame(0x30 ^ i as u8, 100 + (i % 7)))
        .collect();
    (video, audio)
}

/// The composition offsets the fixture writes: every third frame is
/// displayed later than it decodes, which is what a B-frame stream looks
/// like and what `trun` version 1 exists to carry.
fn mp4_ctts_runs() -> Vec<(u32, i32)> {
    (0..MP4_V_SAMPLES / 3)
        .flat_map(|_| [(1u32, 6_000i32), (2, 0)])
        .collect()
}

fn table_u32(fourcc: &[u8; 4], values: &[u32]) -> Vec<u8> {
    let mut b = (values.len() as u32).to_be_bytes().to_vec();
    for v in values {
        b.extend(v.to_be_bytes());
    }
    mp4box(fourcc, &full(0, &b))
}

fn table_pairs(fourcc: &[u8; 4], pairs: &[(u32, u32)]) -> Vec<u8> {
    let mut b = (pairs.len() as u32).to_be_bytes().to_vec();
    for (a, c) in pairs {
        b.extend(a.to_be_bytes());
        b.extend(c.to_be_bytes());
    }
    mp4box(fourcc, &full(0, &b))
}

fn table_stsc(runs: &[(u32, u32)]) -> Vec<u8> {
    let mut b = (runs.len() as u32).to_be_bytes().to_vec();
    for (first, spc) in runs {
        b.extend(first.to_be_bytes());
        b.extend(spc.to_be_bytes());
        b.extend(1u32.to_be_bytes()); // sample_description_index
    }
    mp4box(b"stsc", &full(0, &b))
}

fn table_stsz(sizes: &[u32]) -> Vec<u8> {
    let mut b = 0u32.to_be_bytes().to_vec(); // per-sample sizes follow
    b.extend((sizes.len() as u32).to_be_bytes());
    for s in sizes {
        b.extend(s.to_be_bytes());
    }
    mp4box(b"stsz", &full(0, &b))
}

/// The interleave the fixture writes, as `(is_video, sample_range)` in
/// mdat order. Chunks alternate, which is what a real muxer does and
/// what makes the stsc/stco walk load-bearing.
fn mp4_chunk_plan() -> Vec<(bool, std::ops::Range<usize>)> {
    let mut plan = Vec::new();
    let chunks = MP4_V_SAMPLES / MP4_V_PER_CHUNK;
    for c in 0..chunks {
        plan.push((true, c * MP4_V_PER_CHUNK..(c + 1) * MP4_V_PER_CHUNK));
        plan.push((false, c * MP4_A_PER_CHUNK..(c + 1) * MP4_A_PER_CHUNK));
    }
    plan
}

/// An MP4 whose index is at the END, with composition offsets and a
/// sparse sync-sample table: the shape a download hands us, and the one
/// a seek has to work on.
pub fn mp4_remux_fixture() -> Vec<u8> {
    let (video, audio) = mp4_remux_streams();
    let plan = mp4_chunk_plan();

    // mdat first, so the chunk offsets can be computed against the real
    // file layout rather than guessed.
    let mut mdat_body = Vec::new();
    let mut chunk_at: Vec<(bool, usize)> = Vec::new();
    for (is_video, range) in &plan {
        chunk_at.push((*is_video, mdat_body.len()));
        for i in range.clone() {
            mdat_body.extend_from_slice(if *is_video { &video[i] } else { &audio[i] });
        }
    }
    let ftyp_el = ftyp();
    let mdat_payload_at = (ftyp_el.len() + 8) as u32;
    let v_chunks: Vec<u32> = chunk_at
        .iter()
        .filter(|(v, _)| *v)
        .map(|(_, o)| mdat_payload_at + *o as u32)
        .collect();
    let a_chunks: Vec<u32> = chunk_at
        .iter()
        .filter(|(v, _)| !*v)
        .map(|(_, o)| mdat_payload_at + *o as u32)
        .collect();

    let avcc = mp4box(b"avcC", &[1, 100, 0, 40, 0xFF, 0xE1, 0, 0]);
    let mut vstbl = {
        let mut b = 1u32.to_be_bytes().to_vec();
        b.extend(visual_entry(b"avc1", 1280, 720, &avcc));
        mp4box(b"stsd", &full(0, &b))
    };
    vstbl.extend(table_pairs(b"stts", &[(MP4_V_SAMPLES as u32, MP4_V_DELTA)]));
    vstbl.extend(table_pairs(
        b"ctts",
        &mp4_ctts_runs()
            .iter()
            .map(|(c, v)| (*c, *v as u32))
            .collect::<Vec<_>>(),
    ));
    vstbl.extend(table_stsz(
        &video.iter().map(|f| f.len() as u32).collect::<Vec<_>>(),
    ));
    vstbl.extend(table_stsc(&[(1, MP4_V_PER_CHUNK as u32)]));
    vstbl.extend(table_u32(b"stco", &v_chunks));
    // A sync sample every ten frames: three keyframes in the file.
    vstbl.extend(table_u32(b"stss", &[1, 11, 21]));

    let mut vmdia = mdhd(MP4_V_TIMESCALE, MP4_V_SAMPLES as u32 * MP4_V_DELTA, 0x55C4);
    vmdia.extend(hdlr(b"vide"));
    vmdia.extend(mp4box(b"minf", &mp4box(b"stbl", &vstbl)));
    let mut vtrak = tkhd(1, 1280, 720);
    vtrak.extend(mp4box(b"mdia", &vmdia));

    let mut astbl = {
        let mut b = 1u32.to_be_bytes().to_vec();
        b.extend(audio_entry(b"mp4a", 2, 48_000, &esds_aac()));
        mp4box(b"stsd", &full(0, &b))
    };
    astbl.extend(table_pairs(b"stts", &[(MP4_A_SAMPLES as u32, MP4_A_DELTA)]));
    astbl.extend(table_stsz(
        &audio.iter().map(|f| f.len() as u32).collect::<Vec<_>>(),
    ));
    astbl.extend(table_stsc(&[(1, MP4_A_PER_CHUNK as u32)]));
    astbl.extend(table_u32(b"stco", &a_chunks));

    let mut amdia = mdhd(MP4_A_TIMESCALE, MP4_A_SAMPLES as u32 * MP4_A_DELTA, 0x15C7);
    amdia.extend(hdlr(b"soun"));
    amdia.extend(mp4box(b"minf", &mp4box(b"stbl", &astbl)));
    let mut atrak = tkhd(2, 0, 0);
    atrak.extend(mp4box(b"mdia", &amdia));

    let mut moov_body = mvhd(1_000, 1_000);
    moov_body.extend(mp4box(b"trak", &vtrak));
    moov_body.extend(mp4box(b"trak", &atrak));

    let mut out = ftyp_el;
    out.extend(mp4box(b"mdat", &mdat_body));
    out.extend(mp4box(b"moov", &moov_body));
    out
}

/// Every fixture, named - the fuzz seed corpus and the truncation
/// matrix both walk this list rather than repeating it.
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("mkv_full", mkv_full()),
        ("mkv_hdr", mkv_hdr()),
        ("mkv_chapters", mkv_chapters()),
        ("mkv_seekhead_chapters", mkv_seekhead_chapters()),
        ("mkv_disabled_track", mkv_disabled_track()),
        ("mkv_vfw_xvid", mkv_vfw_xvid()),
        ("webm", webm()),
        ("mp4_faststart", mp4_faststart()),
        ("mp4_moov_at_end", mp4_moov_at_end()),
        ("avi", avi()),
        ("mkv_remux", mkv_remux_fixture()),
        ("mp4_remux", mp4_remux_fixture()),
    ]
}
