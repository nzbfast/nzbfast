//! Elementary samples out of Matroska and MP4, in decode order.
//!
//! This is the read half of the remuxer: it turns a container into a
//! stream of [`Sample`]s, each one a byte span in the SOURCE file plus
//! the timing the muxer needs to describe it. Nothing here copies a
//! payload - a `Sample` is an offset and a length, and the session
//! decides when the bytes under it are worth waiting for.
//!
//! ## Why this is a second walk, not the probe's
//!
//! [`super::probe`] answers "what is this file" and deliberately stops
//! at the first Cluster: it never reads a sample table, and its output
//! is a JSON document that goes to a browser. Sample tables are the
//! wrong thing to put on that wire - an hour of video is hundreds of
//! thousands of entries - so the remuxer runs its own walk, gathering
//! exactly the structures it will index, and the probe's contract stays
//! the size it is. What the two share is the codec table
//! ([`super::codec`]), so a container id that means H.264 to one means
//! it to the other.
//!
//! ## Ticks, not nanoseconds
//!
//! Every [`Sample`] carries its timing in ITS OWN track timescale as
//! well as in nanoseconds. The nanoseconds exist to interleave two
//! tracks and to cut fragments on a wall-clock rule; the ticks are what
//! reach `tfdt` and `trun`. This is deliberate and it is the difference
//! between a bit-exact remux and a drifting one: a 90 kHz MP4 track
//! round-tripped through nanoseconds loses a tick per sample, and half
//! an hour later the audio is visibly late. The source's own timescale
//! is copied and its own tick values are passed through unchanged.
//!
//! ## Untrusted input
//!
//! Same posture as the probe. Every declared length is checked against
//! the file size before it is allocated, every walk carries an element
//! budget, and a structure that does not make sense ends the walk with
//! an error rather than an index into nowhere. The budgets carry no
//! wall clock, so the same bytes always produce the same samples - the
//! property the fuzz target asserts.

use super::source::{Source, is_pending, read_vec};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

// ---------------------------------------------------------------------------
// What a walk produces
// ---------------------------------------------------------------------------

/// One elementary-stream sample: where its bytes are and when it plays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// OUR fMP4 track id, 1-based, assigned by [`select_mkv`] /
    /// [`select_mp4`].
    pub(crate) track: u32,
    /// Decode timestamp in this track's timescale.
    pub(crate) dts: u64,
    /// Composition offset (pts - dts) in ticks. Always 0 for Matroska;
    /// see [`MkvSampleIter`].
    pub(crate) cts_offset: i32,
    /// Duration in ticks when the container stated one. `None` means
    /// "infer it from the next sample", which is the muxer's job.
    pub(crate) dur: Option<u32>,
    pub(crate) keyframe: bool,
    /// Byte offset of the payload in the SOURCE file.
    pub(crate) src_off: u64,
    pub(crate) size: u32,
    /// The same decode time in nanoseconds. Interleaving and the
    /// fragment-boundary rule use this; nothing written into a box does.
    pub(crate) dts_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackKind {
    Video,
    Audio,
}

/// The decoder configuration, in the form the fMP4 SampleEntry needs.
///
/// Matroska stores these records raw in `CodecPrivate` and MP4 stores
/// them inside the `stsd` entry, so the two arms differ: from an MP4 we
/// copy the entry verbatim (exact, and it carries fields we would
/// otherwise have to guess), and from Matroska we rebuild it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackConfig {
    /// AVCDecoderConfigurationRecord, the `avcC` payload.
    Avc(Vec<u8>),
    /// HEVCDecoderConfigurationRecord, the `hvcC` payload. Written into
    /// an `hvc1` entry: the parameter sets live in the record, not
    /// in-band, which is what Matroska's CodecPrivate always holds.
    Hevc(Vec<u8>),
    /// AV1CodecConfigurationRecord, the `av1C` payload.
    Av1(Vec<u8>),
    /// VPCodecConfigurationRecord, the `vpcC` payload. Matroska usually
    /// carries no CodecPrivate for VP9, so this may be synthesised.
    Vp9(Vec<u8>),
    /// AudioSpecificConfig, wrapped in an `esds` descriptor chain.
    Aac(Vec<u8>),
    /// An `OpusHead` blob, byte-swapped into `dOps`.
    Opus(Vec<u8>),
    /// FLAC `STREAMINFO` (and any following metadata blocks), written
    /// into `dfLa`.
    Flac(Vec<u8>),
    /// An MP4 source: the whole `stsd` entry, copied through unchanged.
    Mp4Entry { fourcc: [u8; 4], entry: Vec<u8> },
}

/// A track the session will carry into the output file.
#[derive(Debug, Clone)]
pub struct SelectedTrack {
    /// Our fMP4 `track_ID`, 1-based. Video is always 1.
    pub(crate) id: u32,
    pub(crate) kind: TrackKind,
    /// The source's own id: Matroska `TrackNumber`, MP4 `track_ID`.
    pub(crate) src_id: u64,
    /// Ticks per second for this track in the OUTPUT file. Copied from
    /// an MP4 source; derived from `TimestampScale` for Matroska.
    pub(crate) timescale: u32,
    pub(crate) config: TrackConfig,
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) channels: u16,
    pub(crate) sample_rate: u32,
    /// Matroska `DefaultDuration`, already in output ticks.
    pub(crate) default_dur: Option<u32>,
    /// Canonical codec name, for warnings and for the panel.
    pub codec: String,
}

/// Why a file cannot be remuxed. Distinct from
/// [`super::ProbeError`]: the probe answering "I do not know" is a
/// normal outcome, and this one is always the end of an attempt.
#[derive(Debug, thiserror::Error)]
pub enum RemuxError {
    #[error("no track this remuxer can carry")]
    NoUsableTrack,
    /// The container has no keyframe index, so an arbitrary seek cannot
    /// be answered. Forward playback from the start still works.
    #[error("no seek index in this file")]
    NoIndex,
    #[error("{0} is not remuxable: {1}")]
    Unsupported(&'static str, String),
    #[error("malformed {0}: {1}")]
    Malformed(&'static str, String),
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
}

impl RemuxError {
    /// True when this is "the bytes have not arrived", which the caller
    /// answers by waiting rather than by giving up.
    pub fn is_pending(&self) -> bool {
        matches!(self, RemuxError::Io(e) if is_pending(e))
    }
}

fn bad(container: &'static str, what: impl Into<String>) -> RemuxError {
    RemuxError::Malformed(container, what.into())
}

/// Walks are bounded by element count, never by wall clock, so the same
/// bytes always produce the same answer.
const MAX_ELEMENTS: u32 = 500_000;
/// Entries in any one sample table. An hour of 24 fps video is ~86k and
/// its AAC track ~170k; this is two orders above a feature film and far
/// below anything that could exhaust memory.
const MAX_TABLE_ENTRIES: u64 = 16_000_000;
/// Frames in one laced Matroska block. The field is a `u8`, so this is
/// the format's own ceiling stated as code.
const MAX_LACE: usize = 256;
/// Longest configuration record carried out of a container.
const MAX_CODEC_PRIVATE: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// A growable window over one element's head
// ---------------------------------------------------------------------------

/// Reads a structure's header in stages instead of in one gulp.
///
/// A block header is eleven bytes and a laced one can be a few hundred,
/// but the payload behind it is megabytes. Reading a fixed generous
/// window would routinely reach past the download frontier and turn a
/// perfectly readable header into a wait - so this grows only as far as
/// the parse actually walks.
struct Peek<'a> {
    src: &'a dyn Source,
    base: u64,
    /// Never read past this (the element's own end).
    limit: u64,
    buf: Vec<u8>,
    wait: Duration,
}

impl<'a> Peek<'a> {
    fn new(src: &'a dyn Source, base: u64, limit: u64, wait: Duration) -> Self {
        Peek {
            src,
            base,
            limit: limit.max(base),
            buf: Vec::new(),
            wait,
        }
    }

    /// Guarantee `self.buf.len() >= n`, or fail.
    fn ensure(&mut self, n: usize) -> Result<(), RemuxError> {
        if self.buf.len() >= n {
            return Ok(());
        }
        let avail = self.limit - self.base;
        if n as u64 > avail {
            return Err(bad("mkv", "element header runs past the element"));
        }
        // Grow in chunks so a lacing table costs a handful of reads, not
        // one per byte, but never past the element.
        let want = (n.max(32).next_power_of_two() as u64).min(avail) as usize;
        let from = self.base + self.buf.len() as u64;
        let more = want - self.buf.len();
        let mut ext = vec![0u8; more];
        self.src.read_at_wait(from, &mut ext, self.wait)?;
        self.buf.extend_from_slice(&ext);
        Ok(())
    }

    fn byte(&mut self, i: usize) -> Result<u8, RemuxError> {
        self.ensure(i + 1)?;
        Ok(self.buf[i])
    }
}

// ---------------------------------------------------------------------------
// EBML primitives
// ---------------------------------------------------------------------------

/// Bytes an EBML variable-size integer occupies, from its first byte.
/// A zero first byte has no marker bit at all and is not a vint.
fn vint_len(first: u8) -> Result<usize, RemuxError> {
    match first {
        0 => Err(bad("mkv", "variable-size integer with no length marker")),
        _ => Ok(first.leading_zeros() as usize + 1),
    }
}

/// An element ID, marker bit KEPT: ids are compared as they are written.
fn read_id(src: &dyn Source, off: u64, wait: Duration) -> Result<(u32, u64), RemuxError> {
    let mut b = [0u8; 4];
    src.read_at_wait(off, &mut b[..1], wait)?;
    let len = vint_len(b[0])?;
    if len > 4 {
        return Err(bad("mkv", "element id longer than four bytes"));
    }
    if len > 1 {
        src.read_at_wait(off + 1, &mut b[1..len], wait)?;
    }
    let v = b[..len].iter().fold(0u32, |a, &x| (a << 8) | u32::from(x));
    Ok((v, len as u64))
}

/// An element size, marker bit STRIPPED. The `bool` is "unknown size"
/// (all value bits set), legal on Segment and Cluster only.
fn read_size(src: &dyn Source, off: u64, wait: Duration) -> Result<(u64, u64, bool), RemuxError> {
    let mut b = [0u8; 8];
    src.read_at_wait(off, &mut b[..1], wait)?;
    let len = vint_len(b[0])?;
    if len > 8 {
        return Err(bad("mkv", "element size longer than eight bytes"));
    }
    if len > 1 {
        src.read_at_wait(off + 1, &mut b[1..len], wait)?;
    }
    let mut v = u64::from(b[0] & value_mask(len));
    for &x in &b[1..len] {
        v = (v << 8) | u64::from(x);
    }
    let unknown = v == (1u64 << (7 * len)) - 1;
    Ok((v, len as u64, unknown))
}

/// The value bits of a variable-size integer's FIRST byte, once the
/// length marker is taken out. At the maximum width the marker is the
/// whole byte and nothing is left - a case that reads as an eight-bit
/// shift, which is undefined for a `u8` and used to be a panic here.
fn value_mask(len: usize) -> u8 {
    if len >= 8 { 0 } else { 0xFFu8 >> len }
}

/// A vint read out of an already-buffered block header (track numbers
/// and lacing sizes). Returns the value with the marker stripped.
fn buf_vint(p: &mut Peek, at: usize) -> Result<(u64, usize), RemuxError> {
    let first = p.byte(at)?;
    let len = vint_len(first)?;
    if len > 8 {
        return Err(bad("mkv", "lacing integer longer than eight bytes"));
    }
    p.ensure(at + len)?;
    let mut v = u64::from(first & value_mask(len));
    for i in 1..len {
        v = (v << 8) | u64::from(p.buf[at + i]);
    }
    Ok((v, len))
}

/// A SIGNED EBML lace delta: the unsigned value minus the midpoint of
/// its width.
fn buf_svint(p: &mut Peek, at: usize) -> Result<(i64, usize), RemuxError> {
    let (v, len) = buf_vint(p, at)?;
    let bias = (1i64 << (7 * len as i64 - 1)) - 1;
    Ok((v as i64 - bias, len))
}

fn be_uint(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0u64, |a, &x| (a << 8) | u64::from(x))
}

// Matroska element ids the remuxer cares about.
const SEGMENT: u32 = 0x1853_8067;
const SEEK_HEAD: u32 = 0x114D_9B74;
const SEEK: u32 = 0x4DBB;
const SEEK_ID: u32 = 0x53AB;
const SEEK_POSITION: u32 = 0x53AC;
const INFO: u32 = 0x1549_A966;
const TIMESTAMP_SCALE: u32 = 0x002A_D7B1;
const DURATION: u32 = 0x4489;
const TRACKS: u32 = 0x1654_AE6B;
const TRACK_ENTRY: u32 = 0xAE;
const TRACK_NUMBER: u32 = 0xD7;
const TRACK_TYPE: u32 = 0x83;
const FLAG_ENABLED: u32 = 0xB9;
const FLAG_DEFAULT: u32 = 0x88;
const CODEC_ID: u32 = 0x86;
const CODEC_PRIVATE: u32 = 0x63A2;
const DEFAULT_DURATION: u32 = 0x0023_E383;
const VIDEO: u32 = 0xE0;
const AUDIO: u32 = 0xE1;
const PIXEL_WIDTH: u32 = 0xB0;
const PIXEL_HEIGHT: u32 = 0xBA;
const CHANNELS: u32 = 0x9F;
const SAMPLING_FREQUENCY: u32 = 0xB5;
const CLUSTER: u32 = 0x1F43_B675;
const TIMESTAMP: u32 = 0xE7;
const SIMPLE_BLOCK: u32 = 0xA3;
const BLOCK_GROUP: u32 = 0xA0;
const BLOCK: u32 = 0xA1;
const BLOCK_DURATION: u32 = 0x9B;
const REFERENCE_BLOCK: u32 = 0xFB;
const CUES: u32 = 0x1C53_BB6B;
const CUE_POINT: u32 = 0xBB;
const CUE_TIME: u32 = 0xB3;
const CUE_TRACK_POSITIONS: u32 = 0xB7;
const CUE_TRACK: u32 = 0xF7;
const CUE_CLUSTER_POSITION: u32 = 0xF1;
const TAGS: u32 = 0x1254_C367;
const CHAPTERS: u32 = 0x1043_A770;
const ATTACHMENTS: u32 = 0x1941_A469;

/// Elements that can only appear at the top of a Segment. Reaching one
/// ends an unknown-size Cluster, which is how those are terminated.
fn is_segment_level(id: u32) -> bool {
    matches!(
        id,
        CLUSTER | CUES | TAGS | CHAPTERS | ATTACHMENTS | SEEK_HEAD | INFO | TRACKS
    )
}

// ---------------------------------------------------------------------------
// Matroska layout
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MkvTrack {
    pub(crate) number: u64,
    /// 1 video, 2 audio, others ignored.
    pub(crate) kind: u64,
    pub(crate) codec_id: String,
    pub(crate) codec_private: Vec<u8>,
    pub(crate) default_duration_ns: Option<u64>,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) channels: u32,
    pub(crate) sample_rate: u32,
    pub(crate) enabled: bool,
    pub(crate) default: bool,
}

#[derive(Debug, Clone)]
pub struct MkvLayout {
    /// First byte AFTER the Segment's own header - every SeekHead and
    /// Cues offset in the file is relative to this.
    pub(crate) segment_data_start: u64,
    pub(crate) segment_end: u64,
    pub(crate) timestamp_scale_ns: u64,
    pub(crate) first_cluster_off: Option<u64>,
    pub cues_off: Option<u64>,
    pub(crate) duration_ns: Option<u64>,
    pub(crate) tracks: Vec<MkvTrack>,
}

/// Read everything the remuxer needs out of a Matroska header.
///
/// Follows the SeekHead for Tracks and Cues when they are not where the
/// linear walk found them, which is the normal shape: Cues are written
/// after the clusters, so on a live download they arrive with the tail.
pub fn mkv_layout(src: &dyn Source, wait: Duration) -> Result<MkvLayout, RemuxError> {
    let end = src.size();
    let mut pos = 0u64;
    let mut budget = MAX_ELEMENTS;

    // Step over the EBML header to the Segment.
    let (mut seg_start, mut seg_end) = (0u64, end);
    let mut found_segment = false;
    while pos < end {
        charge(&mut budget)?;
        let (id, idl) = read_id(src, pos, wait)?;
        let (size, szl, unknown) = read_size(src, pos + idl, wait)?;
        let body = pos + idl + szl;
        if id == SEGMENT {
            seg_start = body;
            seg_end = if unknown {
                end
            } else {
                body.saturating_add(size).min(end)
            };
            found_segment = true;
            break;
        }
        if unknown {
            return Err(bad("mkv", "unknown size on a top-level element"));
        }
        pos = body.saturating_add(size);
    }
    if !found_segment {
        return Err(bad("mkv", "no Segment element"));
    }

    let mut lay = MkvLayout {
        segment_data_start: seg_start,
        segment_end: seg_end,
        timestamp_scale_ns: 1_000_000,
        first_cluster_off: None,
        cues_off: None,
        duration_ns: None,
        tracks: Vec::new(),
    };
    let mut seek: Vec<(u32, u64)> = Vec::new();
    let mut raw_duration: Option<f64> = None;

    // One linear pass over the Segment's children, stopping at the
    // first Cluster: everything before it is header, everything after
    // is payload the SeekHead indexes.
    pos = seg_start;
    while pos < seg_end {
        charge(&mut budget)?;
        let (id, idl) = read_id(src, pos, wait)?;
        let (size, szl, unknown) = read_size(src, pos + idl, wait)?;
        let body = pos + idl + szl;
        let bend = if unknown {
            seg_end
        } else {
            body.saturating_add(size).min(seg_end)
        };
        match id {
            CLUSTER => {
                lay.first_cluster_off = Some(pos);
                break;
            }
            SEEK_HEAD => read_seek_head(src, body, bend, wait, &mut budget, &mut seek)?,
            INFO => {
                let (scale, dur) = read_info(src, body, bend, wait, &mut budget)?;
                if let Some(s) = scale {
                    lay.timestamp_scale_ns = s;
                }
                raw_duration = dur.or(raw_duration);
            }
            TRACKS => lay.tracks = read_tracks(src, body, bend, wait, &mut budget)?,
            CUES => lay.cues_off = Some(pos),
            _ => {}
        }
        if unknown {
            return Err(bad("mkv", "unknown size outside Segment and Cluster"));
        }
        pos = body.saturating_add(size);
    }

    // Whatever the linear pass did not reach, the container's own index
    // knows where to find. Verify the id at the target before walking
    // it: a SeekPosition landing in the middle of a cluster is a corrupt
    // index, and following it would read payload as structure.
    for (id, rel) in seek {
        let want_tracks = id == TRACKS && lay.tracks.is_empty();
        let want_cues = id == CUES && lay.cues_off.is_none();
        if !(want_tracks || want_cues) {
            continue;
        }
        let Some(at) = seg_start.checked_add(rel).filter(|a| *a < seg_end) else {
            continue;
        };
        match read_id(src, at, wait) {
            Ok((found, idl)) if found == id => {
                if want_cues {
                    lay.cues_off = Some(at);
                } else {
                    let (size, szl, _) = read_size(src, at + idl, wait)?;
                    let body = at + idl + szl;
                    let bend = body.saturating_add(size).min(seg_end);
                    lay.tracks = read_tracks(src, body, bend, wait, &mut budget)?;
                }
            }
            // A gap over the index is not corruption: the tail has not
            // landed. The caller retries; the file is unchanged.
            Ok(_) => {}
            Err(e) if e.is_pending() => return Err(e),
            Err(_) => {}
        }
    }

    if let Some(d) = raw_duration
        && d.is_finite()
        && d > 0.0
    {
        let ns = d * lay.timestamp_scale_ns as f64;
        if ns.is_finite() && ns < u64::MAX as f64 {
            lay.duration_ns = Some(ns as u64);
        }
    }
    Ok(lay)
}

fn charge(budget: &mut u32) -> Result<(), RemuxError> {
    *budget = budget.saturating_sub(1);
    (*budget > 0)
        .then_some(())
        .ok_or_else(|| bad("mkv", "too many elements"))
}

fn read_seek_head(
    src: &dyn Source,
    start: u64,
    end: u64,
    wait: Duration,
    budget: &mut u32,
    out: &mut Vec<(u32, u64)>,
) -> Result<(), RemuxError> {
    let mut pos = start;
    while pos < end {
        charge(budget)?;
        let (id, idl) = read_id(src, pos, wait)?;
        let (size, szl, _) = read_size(src, pos + idl, wait)?;
        let body = pos + idl + szl;
        let bend = body.saturating_add(size).min(end);
        if id == SEEK {
            let (mut sid, mut spos) = (None, None);
            let mut p = body;
            while p < bend {
                charge(budget)?;
                let (cid, cidl) = read_id(src, p, wait)?;
                let (csz, cszl, _) = read_size(src, p + cidl, wait)?;
                let cbody = p + cidl + cszl;
                match cid {
                    SEEK_ID if csz <= 4 => {
                        let b = read_vec(src, cbody, csz, wait)?;
                        sid = Some(b.iter().fold(0u32, |a, &x| (a << 8) | u32::from(x)));
                    }
                    SEEK_POSITION if csz <= 8 => {
                        spos = Some(be_uint(&read_vec(src, cbody, csz, wait)?));
                    }
                    _ => {}
                }
                p = cbody.saturating_add(csz);
            }
            if let (Some(a), Some(b)) = (sid, spos) {
                out.push((a, b));
            }
        }
        pos = body.saturating_add(size);
    }
    Ok(())
}

fn read_info(
    src: &dyn Source,
    start: u64,
    end: u64,
    wait: Duration,
    budget: &mut u32,
) -> Result<(Option<u64>, Option<f64>), RemuxError> {
    let (mut scale, mut dur) = (None, None);
    let mut pos = start;
    while pos < end {
        charge(budget)?;
        let (id, idl) = read_id(src, pos, wait)?;
        let (size, szl, _) = read_size(src, pos + idl, wait)?;
        let body = pos + idl + szl;
        match id {
            TIMESTAMP_SCALE if (1..=8).contains(&size) => {
                let v = be_uint(&read_vec(src, body, size, wait)?);
                if v > 0 {
                    scale = Some(v);
                }
            }
            DURATION if size == 4 || size == 8 => {
                let b = read_vec(src, body, size, wait)?;
                dur = Some(if size == 4 {
                    f64::from(f32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                } else {
                    f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                });
            }
            _ => {}
        }
        pos = body.saturating_add(size);
    }
    Ok((scale, dur))
}

fn read_tracks(
    src: &dyn Source,
    start: u64,
    end: u64,
    wait: Duration,
    budget: &mut u32,
) -> Result<Vec<MkvTrack>, RemuxError> {
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end && out.len() < 64 {
        charge(budget)?;
        let (id, idl) = read_id(src, pos, wait)?;
        let (size, szl, _) = read_size(src, pos + idl, wait)?;
        let body = pos + idl + szl;
        let bend = body.saturating_add(size).min(end);
        if id == TRACK_ENTRY {
            out.push(read_track_entry(src, body, bend, wait, budget)?);
        }
        pos = body.saturating_add(size);
    }
    Ok(out)
}

fn read_track_entry(
    src: &dyn Source,
    start: u64,
    end: u64,
    wait: Duration,
    budget: &mut u32,
) -> Result<MkvTrack, RemuxError> {
    let mut t = MkvTrack {
        number: 0,
        kind: 0,
        codec_id: String::new(),
        codec_private: Vec::new(),
        default_duration_ns: None,
        width: 0,
        height: 0,
        channels: 0,
        sample_rate: 0,
        // Matroska's own defaults for the two flags that have one.
        enabled: true,
        default: true,
    };
    let mut pos = start;
    while pos < end {
        charge(budget)?;
        let (id, idl) = read_id(src, pos, wait)?;
        let (size, szl, _) = read_size(src, pos + idl, wait)?;
        let body = pos + idl + szl;
        let bend = body.saturating_add(size).min(end);
        let uint = |src: &dyn Source| -> Result<u64, RemuxError> {
            Ok(be_uint(&read_vec(src, body, size.min(8), wait)?))
        };
        match id {
            TRACK_NUMBER if size <= 8 => t.number = uint(src)?,
            TRACK_TYPE if size <= 8 => t.kind = uint(src)?,
            FLAG_ENABLED if size <= 8 => t.enabled = uint(src)? != 0,
            FLAG_DEFAULT if size <= 8 => t.default = uint(src)? != 0,
            DEFAULT_DURATION if size <= 8 => {
                let v = uint(src)?;
                t.default_duration_ns = (v > 0).then_some(v);
            }
            CODEC_ID => {
                let b = read_vec(src, body, size.min(256), wait)?;
                let n = b.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
                t.codec_id = String::from_utf8_lossy(&b[..n]).trim().to_string();
            }
            CODEC_PRIVATE if size <= MAX_CODEC_PRIVATE => {
                t.codec_private = read_vec(src, body, size, wait)?;
            }
            VIDEO | AUDIO => {
                let mut p = body;
                while p < bend {
                    charge(budget)?;
                    let (cid, cidl) = read_id(src, p, wait)?;
                    let (csz, cszl, _) = read_size(src, p + cidl, wait)?;
                    let cbody = p + cidl + cszl;
                    match cid {
                        PIXEL_WIDTH if csz <= 8 => {
                            t.width = be_uint(&read_vec(src, cbody, csz, wait)?) as u32
                        }
                        PIXEL_HEIGHT if csz <= 8 => {
                            t.height = be_uint(&read_vec(src, cbody, csz, wait)?) as u32
                        }
                        CHANNELS if csz <= 8 => {
                            t.channels = be_uint(&read_vec(src, cbody, csz, wait)?) as u32
                        }
                        SAMPLING_FREQUENCY if csz == 4 || csz == 8 => {
                            let b = read_vec(src, cbody, csz, wait)?;
                            let f = if csz == 4 {
                                f64::from(f32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                            } else {
                                f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                            };
                            if f.is_finite() && f > 0.0 && f < 1e7 {
                                t.sample_rate = f.round() as u32;
                            }
                        }
                        _ => {}
                    }
                    p = cbody.saturating_add(csz);
                }
            }
            _ => {}
        }
        pos = body.saturating_add(size);
    }
    Ok(t)
}

/// A parsed Cues element: presentation time to cluster offset.
#[derive(Debug, Clone, Default)]
pub struct Cues {
    /// `(time in ticks, absolute cluster offset)`, sorted by time.
    pub(crate) points: Vec<(u64, u64)>,
}

/// Parse Cues for one track. Cue points naming a different track are
/// kept only when the wanted track has none of its own - a video-only
/// index is still a usable index for an audio seek.
pub fn read_cues(
    src: &dyn Source,
    lay: &MkvLayout,
    track: u64,
    wait: Duration,
) -> Result<Cues, RemuxError> {
    let Some(at) = lay.cues_off else {
        return Err(RemuxError::NoIndex);
    };
    let mut budget = MAX_ELEMENTS;
    let (id, idl) = read_id(src, at, wait)?;
    if id != CUES {
        return Err(RemuxError::NoIndex);
    }
    let (size, szl, _) = read_size(src, at + idl, wait)?;
    let body = at + idl + szl;
    let end = body.saturating_add(size).min(lay.segment_end);

    let mut mine: Vec<(u64, u64)> = Vec::new();
    let mut any: Vec<(u64, u64)> = Vec::new();
    let mut pos = body;
    while pos < end {
        charge(&mut budget)?;
        let (cid, cidl) = read_id(src, pos, wait)?;
        let (csz, cszl, _) = read_size(src, pos + cidl, wait)?;
        let cbody = pos + cidl + cszl;
        let cend = cbody.saturating_add(csz).min(end);
        if cid == CUE_POINT {
            let mut time = None;
            let mut p = cbody;
            while p < cend {
                charge(&mut budget)?;
                let (gid, gidl) = read_id(src, p, wait)?;
                let (gsz, gszl, _) = read_size(src, p + gidl, wait)?;
                let gbody = p + gidl + gszl;
                let gend = gbody.saturating_add(gsz).min(cend);
                match gid {
                    CUE_TIME if gsz <= 8 => {
                        time = Some(be_uint(&read_vec(src, gbody, gsz, wait)?));
                    }
                    CUE_TRACK_POSITIONS => {
                        let (mut ct, mut cp) = (None, None);
                        let mut q = gbody;
                        while q < gend {
                            charge(&mut budget)?;
                            let (tid, tidl) = read_id(src, q, wait)?;
                            let (tsz, tszl, _) = read_size(src, q + tidl, wait)?;
                            let tbody = q + tidl + tszl;
                            match tid {
                                CUE_TRACK if tsz <= 8 => {
                                    ct = Some(be_uint(&read_vec(src, tbody, tsz, wait)?))
                                }
                                CUE_CLUSTER_POSITION if tsz <= 8 => {
                                    cp = Some(be_uint(&read_vec(src, tbody, tsz, wait)?))
                                }
                                _ => {}
                            }
                            q = tbody.saturating_add(tsz);
                        }
                        if let (Some(t), Some(rel)) = (time, cp)
                            && let Some(abs) = lay
                                .segment_data_start
                                .checked_add(rel)
                                .filter(|a| *a < lay.segment_end)
                        {
                            any.push((t, abs));
                            if ct == Some(track) {
                                mine.push((t, abs));
                            }
                        }
                    }
                    _ => {}
                }
                p = gbody.saturating_add(gsz);
            }
        }
        pos = cbody.saturating_add(csz);
    }
    let mut points = if mine.is_empty() { any } else { mine };
    points.sort_unstable();
    points.dedup();
    if points.is_empty() {
        return Err(RemuxError::NoIndex);
    }
    Ok(Cues { points })
}

// ---------------------------------------------------------------------------
// The Matroska sample walk
// ---------------------------------------------------------------------------

/// Cluster / SimpleBlock / BlockGroup walk, in storage order.
///
/// ## Composition offsets are always zero
///
/// Matroska block timestamps are PRESENTATION times, and the reordering
/// a `ctts` table would describe is not written down anywhere: storage
/// order is decode order and the timestamp field is the pts. Every
/// Matroska-to-fMP4 remuxer resolves this the same way, by emitting the
/// presentation time as the decode time and leaving `cts_offset` at
/// zero. Browsers decode correctly because the frames still arrive in
/// decode order; the only artifact is that composition time equals
/// decode time, which no player can observe. Inventing offsets from the
/// ReferenceBlock graph would be a guess, and a wrong guess here shows
/// up as stutter rather than as an error.
pub struct MkvSampleIter {
    /// Ticks the source counts in.
    scale_ns: u64,
    /// Multiplier from a source tick to an output tick.
    tick_mul: u64,
    seg_end: u64,
    pos: u64,
    /// End of the cluster being walked; `u64::MAX` for an unknown-size
    /// one, which ends at the next segment-level element.
    cluster_end: u64,
    cluster_ts: u64,
    /// Source track number to (our id, default duration in output ticks).
    map: Vec<(u64, u32, Option<u32>)>,
    queue: VecDeque<Sample>,
    /// Set once the walk has passed the end of the segment.
    done: bool,
    /// Warnings the session hands to the panel.
    pub warnings: Vec<String>,
}

impl MkvSampleIter {
    pub fn new(lay: &MkvLayout, tracks: &[SelectedTrack]) -> Result<Self, RemuxError> {
        let (_, tick_mul) = mkv_timescale(lay.timestamp_scale_ns);
        let map = tracks
            .iter()
            .map(|t| (t.src_id, t.id, t.default_dur))
            .collect();
        Ok(MkvSampleIter {
            scale_ns: lay.timestamp_scale_ns,
            tick_mul,
            seg_end: lay.segment_end,
            pos: lay.first_cluster_off.unwrap_or(lay.segment_end),
            cluster_end: 0,
            cluster_ts: 0,
            map,
            queue: VecDeque::new(),
            done: lay.first_cluster_off.is_none(),
            warnings: Vec::new(),
        })
    }

    fn our_track(&self, num: u64) -> Option<(u32, Option<u32>)> {
        self.map
            .iter()
            .find(|(n, _, _)| *n == num)
            .map(|(_, id, d)| (*id, *d))
    }

    fn warn(&mut self, m: impl Into<String>) {
        let m = m.into();
        if !self.warnings.contains(&m) {
            self.warnings.push(m);
        }
    }

    /// Decode one Block or SimpleBlock payload into `queue`.
    ///
    /// `simple` distinguishes the two framings: a SimpleBlock states
    /// keyframe-ness in its flags, a Block infers it from the absence of
    /// a ReferenceBlock sibling.
    fn read_block(
        &mut self,
        src: &dyn Source,
        body: u64,
        end: u64,
        simple: bool,
        group_key: bool,
        group_dur: Option<u64>,
        wait: Duration,
    ) -> Result<(), RemuxError> {
        let mut p = Peek::new(src, body, end, wait);
        let (num, nlen) = buf_vint(&mut p, 0)?;
        p.ensure(nlen + 3)?;
        let rel = i16::from_be_bytes([p.buf[nlen], p.buf[nlen + 1]]);
        let flags = p.buf[nlen + 2];
        let mut at = nlen + 3;

        let Some((track, def_dur)) = self.our_track(num) else {
            return Ok(()); // a track we did not select
        };
        let keyframe = if simple { flags & 0x80 != 0 } else { group_key };

        let ticks = i64::from(rel).saturating_add(self.cluster_ts as i64).max(0) as u64;
        let base_dts = ticks.saturating_mul(self.tick_mul);
        let base_ns = ticks.saturating_mul(self.scale_ns);

        let payload_start = body + at as u64;
        let payload_len = end.saturating_sub(payload_start);
        let lacing = (flags & 0x06) >> 1;

        // Sizes of the frames concatenated in this block's payload.
        let sizes: Vec<u64> = if lacing == 0 {
            vec![payload_len]
        } else {
            let n = usize::from(p.byte(at)?) + 1;
            at += 1;
            if n > MAX_LACE {
                return Err(bad("mkv", "laced block claims too many frames"));
            }
            let avail = end.saturating_sub(body + at as u64);
            let mut sizes = Vec::with_capacity(n);
            match lacing {
                // Fixed: the remainder split evenly, and it must divide.
                0b10 => {
                    if n == 0 || !avail.is_multiple_of(n as u64) {
                        return Err(bad("mkv", "fixed lacing does not divide the payload"));
                    }
                    sizes.resize(n, avail / n as u64);
                }
                // Xiph: 255-terminated runs for the first n-1 frames.
                0b01 => {
                    let mut used = 0u64;
                    for _ in 0..n - 1 {
                        let mut s = 0u64;
                        loop {
                            let b = p.byte(at)?;
                            at += 1;
                            s = s.saturating_add(u64::from(b));
                            if b != 255 {
                                break;
                            }
                            if s > avail {
                                return Err(bad("mkv", "Xiph lace size runs past the payload"));
                            }
                        }
                        used = used.saturating_add(s);
                        sizes.push(s);
                    }
                    let rest = end.saturating_sub(body + at as u64);
                    let last = rest
                        .checked_sub(used)
                        .ok_or_else(|| bad("mkv", "Xiph lace sizes exceed the payload"))?;
                    sizes.push(last);
                }
                // EBML: an absolute first size then signed deltas. A
                // single-frame lace writes no sizes at all, so reading
                // one would consume a byte of payload.
                _ if n == 1 => sizes.push(avail),
                _ => {
                    let (first, l) = buf_vint(&mut p, at)?;
                    at += l;
                    let mut cur = first;
                    let mut used = first;
                    sizes.push(first);
                    for _ in 0..n.saturating_sub(2) {
                        let (d, l) = buf_svint(&mut p, at)?;
                        at += l;
                        cur = cur
                            .checked_add_signed(d)
                            .ok_or_else(|| bad("mkv", "EBML lace delta underflows"))?;
                        used = used.saturating_add(cur);
                        sizes.push(cur);
                    }
                    if n >= 2 {
                        let rest = end.saturating_sub(body + at as u64);
                        let last = rest
                            .checked_sub(used)
                            .ok_or_else(|| bad("mkv", "EBML lace sizes exceed the payload"))?;
                        sizes.push(last);
                    }
                }
            }
            sizes
        };

        // Per-frame duration: the group's BlockDuration split across the
        // lace, else the track's DefaultDuration.
        let n = sizes.len().max(1) as u64;
        let per_dur = match (group_dur, def_dur) {
            (Some(d), _) => u32::try_from(d.saturating_mul(self.tick_mul) / n).ok(),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        if sizes.len() > 1 && per_dur.is_none() {
            self.warn("laced audio without a frame duration");
        }

        let mut off = body + at as u64;
        for (i, s) in sizes.iter().copied().enumerate() {
            if off.saturating_add(s) > end {
                return Err(bad("mkv", "lace sizes exceed the block"));
            }
            let step = u64::from(per_dur.unwrap_or(0)) * i as u64;
            let step_ns = per_dur.map_or(0, |d| {
                u64::from(d) * i as u64 * 1_000_000_000 / mkv_out_timescale(self.scale_ns).max(1)
            });
            self.queue.push_back(Sample {
                track,
                dts: base_dts.saturating_add(step),
                cts_offset: 0,
                dur: per_dur,
                // Only the first frame of a lace can be the block's
                // keyframe; the rest depend on it by construction.
                keyframe: keyframe && i == 0,
                src_off: off,
                size: u32::try_from(s).map_err(|_| bad("mkv", "frame larger than 4 GiB"))?,
                dts_ns: base_ns.saturating_add(step_ns),
            });
            off += s;
        }
        Ok(())
    }

    /// Walk a BlockGroup, which states keyframe-ness by omission.
    fn read_block_group(
        &mut self,
        src: &dyn Source,
        start: u64,
        end: u64,
        wait: Duration,
    ) -> Result<(), RemuxError> {
        let (mut block, mut dur, mut referenced) = (None, None, false);
        let mut pos = start;
        let mut budget = 4096u32;
        while pos < end {
            charge(&mut budget)?;
            let (id, idl) = read_id(src, pos, wait)?;
            let (size, szl, _) = read_size(src, pos + idl, wait)?;
            let body = pos + idl + szl;
            let bend = body.saturating_add(size).min(end);
            match id {
                BLOCK => block = Some((body, bend)),
                BLOCK_DURATION if size <= 8 => {
                    dur = Some(be_uint(&read_vec(src, body, size, wait)?));
                }
                REFERENCE_BLOCK => referenced = true,
                _ => {}
            }
            pos = body.saturating_add(size);
        }
        if let Some((b, e)) = block {
            self.read_block(src, b, e, false, !referenced, dur, wait)?;
        }
        Ok(())
    }
}

/// Output timescale for a Matroska file, and the multiplier from a
/// source tick to an output tick.
///
/// The usual `TimestampScale` of a million nanoseconds gives a timescale
/// of 1000 and a multiplier of 1: source ticks pass through untouched.
/// A scale that does not divide a second exactly cannot be expressed
/// that way, so those files count in whole nanoseconds instead - which
/// is still integer-exact, just with a larger timescale field.
fn mkv_timescale(scale_ns: u64) -> (u32, u64) {
    let s = scale_ns.max(1);
    if s <= 1_000_000_000 && 1_000_000_000u64.is_multiple_of(s) {
        ((1_000_000_000 / s) as u32, 1)
    } else {
        (1_000_000_000, s)
    }
}

fn mkv_out_timescale(scale_ns: u64) -> u64 {
    u64::from(mkv_timescale(scale_ns).0)
}

impl SampleIter for MkvSampleIter {
    fn next(&mut self, src: &dyn Source, wait: Duration) -> Result<Option<Sample>, RemuxError> {
        loop {
            if let Some(s) = self.queue.pop_front() {
                return Ok(Some(s));
            }
            if self.done || self.pos >= self.seg_end {
                return Ok(None);
            }
            let (id, idl) = match read_id(src, self.pos, wait) {
                Ok(v) => v,
                Err(e) if e.is_pending() => return Err(e),
                // A structurally impossible id at the walk cursor is the
                // end of what this file can be read as. Everything
                // emitted so far stands.
                Err(_) => {
                    self.done = true;
                    return Ok(None);
                }
            };
            // An unknown-size cluster ends where the next segment-level
            // element begins; that is the format's only terminator.
            if is_segment_level(id) && self.pos >= self.cluster_end {
                self.cluster_end = 0;
            }
            let inside_cluster = self.pos < self.cluster_end;
            let (size, szl, unknown) = match read_size(src, self.pos + idl, wait) {
                Ok(v) => v,
                Err(e) if e.is_pending() => return Err(e),
                Err(_) => {
                    self.done = true;
                    return Ok(None);
                }
            };
            let body = self.pos + idl + szl;
            let bend = if unknown {
                self.seg_end
            } else {
                body.saturating_add(size).min(self.seg_end)
            };
            match id {
                CLUSTER => {
                    self.cluster_end = bend;
                    self.cluster_ts = 0;
                    self.pos = body;
                    continue;
                }
                TIMESTAMP if inside_cluster && size <= 8 => {
                    self.cluster_ts = be_uint(&read_vec(src, body, size, wait)?);
                }
                SIMPLE_BLOCK if inside_cluster => {
                    self.read_block(src, body, bend, true, false, None, wait)?;
                }
                BLOCK_GROUP if inside_cluster => {
                    self.read_block_group(src, body, bend, wait)?;
                }
                _ => {}
            }
            if unknown {
                // Only Segment and Cluster may carry one, and both are
                // handled above.
                self.done = true;
                return Ok(None);
            }
            self.pos = body.saturating_add(size);
        }
    }

    fn seek(&mut self, src: &dyn Source, at: u64, t_ticks: u64) -> Result<(), RemuxError> {
        let _ = src;
        self.queue.clear();
        self.pos = at;
        self.cluster_end = 0;
        self.cluster_ts = t_ticks;
        self.done = false;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MP4 layout
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Stsz {
    Uniform(u32),
    Table(Vec<u32>),
}

impl Stsz {
    pub fn get(&self, i: u64) -> Option<u32> {
        match self {
            Stsz::Uniform(n) => Some(*n),
            Stsz::Table(v) => v.get(usize::try_from(i).ok()?).copied(),
        }
    }
    pub fn count(&self, total: u64) -> u64 {
        match self {
            Stsz::Uniform(_) => total,
            Stsz::Table(v) => v.len() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Mp4Track {
    pub(crate) track_id: u64,
    /// 'vide' or 'soun'.
    pub(crate) handler: [u8; 4],
    pub(crate) timescale: u32,
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) channels: u16,
    pub(crate) sample_rate: u32,
    pub(crate) stsd_fourcc: [u8; 4],
    /// The whole sample entry box, copied through unchanged.
    pub(crate) stsd_entry: Vec<u8>,
    pub(crate) stts: Vec<(u32, u32)>,
    pub(crate) ctts: Vec<(u32, i32)>,
    pub(crate) stsz: Stsz,
    /// `(first_chunk 1-based, samples_per_chunk)`.
    pub(crate) stsc: Vec<(u32, u32)>,
    pub(crate) chunk_offsets: Vec<u64>,
    /// 1-based sync sample numbers; `None` means every sample is a sync
    /// sample, which is what an audio track and an all-intra video track
    /// both leave out.
    pub(crate) stss: Option<Vec<u32>>,
    /// `tkhd` flag bit 0. Carried for the same reason Matroska's
    /// `FlagEnabled` is: it is what `select_mp4` filters on, so that
    /// `a=` counts the same tracks in both containers.
    pub enabled: bool,
}

impl Mp4Track {
    /// Total samples, from whichever table states it.
    ///
    /// Capped at [`MAX_TABLE_ENTRIES`], which is the one bound every
    /// cursor walk in this file inherits (`step` stops at `total`). A
    /// physical stts entry count is already clipped to what its box can
    /// hold, but each entry's RUN count is an untrusted u32: two entries
    /// declaring `count = u32::MAX` describe 8.6 billion samples in
    /// sixteen bytes, and with a `Uniform` stsz nothing else contradicts
    /// them. 16M samples is ~194 hours of 24 fps video, so the cap costs
    /// no real file anything (Codex sweep 12 Aug F5).
    pub fn sample_count(&self) -> u64 {
        let by_stts: u64 = self
            .stts
            .iter()
            .map(|(c, _)| u64::from(*c))
            .fold(0u64, u64::saturating_add);
        match &self.stsz {
            Stsz::Table(v) => (v.len() as u64).min(by_stts.max(v.len() as u64)),
            Stsz::Uniform(_) => by_stts,
        }
        .min(MAX_TABLE_ENTRIES)
    }
}

#[derive(Debug, Clone)]
pub struct Mp4Layout {
    pub(crate) timescale: u32,
    pub(crate) duration: u64,
    pub tracks: Vec<Mp4Track>,
}

impl Mp4Layout {
    pub fn duration_ns(&self) -> Option<u64> {
        (self.timescale > 0 && self.duration > 0).then(|| {
            (u128::from(self.duration) * 1_000_000_000 / u128::from(self.timescale)) as u64
        })
    }
}

fn read_box(src: &dyn Source, off: u64, end: u64, wait: Duration) -> Result<BoxHdr, RemuxError> {
    if off.saturating_add(8) > end {
        return Err(bad("mp4", "box header runs past its parent"));
    }
    let mut h = [0u8; 16];
    src.read_at_wait(off, &mut h[..8], wait)?;
    let mut size = u64::from(u32::from_be_bytes([h[0], h[1], h[2], h[3]]));
    let fourcc = [h[4], h[5], h[6], h[7]];
    let mut hdr = 8u64;
    if size == 1 {
        if off + 16 > end {
            return Err(bad("mp4", "64-bit box header runs past its parent"));
        }
        src.read_at_wait(off + 8, &mut h[8..16], wait)?;
        size = u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);
        hdr = 16;
    } else if size == 0 {
        // "To the end of the enclosing container" - legal for the last
        // top-level box, and the shape a still-writing muxer leaves.
        size = end - off;
    }
    if size < hdr || off.saturating_add(size) > end {
        return Err(bad("mp4", "box size runs past its parent"));
    }
    Ok(BoxHdr {
        fourcc,
        body: off + hdr,
        end: off + size,
        next: off + size,
    })
}

struct BoxHdr {
    fourcc: [u8; 4],
    body: u64,
    end: u64,
    next: u64,
}

/// Read the sample tables and track configuration out of an MP4 `moov`.
///
/// The `moov` may be at either end of the file: a muxer that wrote it
/// last is the common case for anything not prepared for the web, and on
/// a live download that box arrives with the tail the playhead promotion
/// already keeps hot.
pub fn mp4_layout(src: &dyn Source, wait: Duration) -> Result<Mp4Layout, RemuxError> {
    let end = src.size();
    let mut pos = 0u64;
    let mut budget = MAX_ELEMENTS;
    let mut moov = None;
    while pos < end {
        charge_mp4(&mut budget)?;
        let b = read_box(src, pos, end, wait)?;
        if &b.fourcc == b"moov" {
            moov = Some((b.body, b.end));
            break;
        }
        if b.next <= pos {
            return Err(bad("mp4", "zero-length box"));
        }
        pos = b.next;
    }
    let Some((mbody, mend)) = moov else {
        return Err(bad("mp4", "no moov box"));
    };

    let mut lay = Mp4Layout {
        timescale: 1000,
        duration: 0,
        tracks: Vec::new(),
    };
    let mut pos = mbody;
    while pos < mend {
        charge_mp4(&mut budget)?;
        let b = read_box(src, pos, mend, wait)?;
        match &b.fourcc {
            b"mvhd" => {
                let v = read_vec(src, b.body, (b.end - b.body).min(32), wait)?;
                if v.len() >= 20 {
                    let (ts, dur) = if v[0] == 1 && v.len() >= 32 {
                        (
                            u32::from_be_bytes([v[20], v[21], v[22], v[23]]),
                            u64::from_be_bytes([
                                v[24], v[25], v[26], v[27], v[28], v[29], v[30], v[31],
                            ]),
                        )
                    } else {
                        (
                            u32::from_be_bytes([v[12], v[13], v[14], v[15]]),
                            u64::from(u32::from_be_bytes([v[16], v[17], v[18], v[19]])),
                        )
                    };
                    lay.timescale = ts.max(1);
                    lay.duration = dur;
                }
            }
            b"trak" => {
                if let Some(t) = read_trak(src, b.body, b.end, wait, &mut budget)? {
                    lay.tracks.push(t);
                }
            }
            _ => {}
        }
        if b.next <= pos {
            return Err(bad("mp4", "zero-length box"));
        }
        pos = b.next;
    }
    Ok(lay)
}

fn charge_mp4(budget: &mut u32) -> Result<(), RemuxError> {
    *budget = budget.saturating_sub(1);
    (*budget > 0)
        .then_some(())
        .ok_or_else(|| bad("mp4", "too many boxes"))
}

fn read_trak(
    src: &dyn Source,
    start: u64,
    end: u64,
    wait: Duration,
    budget: &mut u32,
) -> Result<Option<Mp4Track>, RemuxError> {
    let mut t = Mp4Track {
        track_id: 0,
        handler: *b"    ",
        timescale: 0,
        width: 0,
        height: 0,
        channels: 0,
        sample_rate: 0,
        stsd_fourcc: *b"    ",
        stsd_entry: Vec::new(),
        stts: Vec::new(),
        ctts: Vec::new(),
        stsz: Stsz::Uniform(0),
        stsc: Vec::new(),
        chunk_offsets: Vec::new(),
        stss: None,
        // A track with no tkhd at all is enabled, the same way a
        // Matroska track with no FlagEnabled is.
        enabled: true,
    };
    // An explicit stack keeps the descent structural: every child is
    // clipped to its parent's extent and the depth is bounded by the
    // container list itself.
    let containers: &[&[u8; 4]] = &[b"trak", b"mdia", b"minf", b"stbl"];
    let mut stack: Vec<(u64, u64)> = vec![(start, end)];
    while let Some((pos, pend)) = stack.pop() {
        if pos >= pend {
            continue;
        }
        charge_mp4(budget)?;
        let b = read_box(src, pos, pend, wait)?;
        if b.next <= pos {
            return Err(bad("mp4", "zero-length box"));
        }
        stack.push((b.next, pend));
        if containers.contains(&&b.fourcc) {
            stack.push((b.body, b.end));
            continue;
        }
        let len = b.end - b.body;
        match &b.fourcc {
            b"tkhd" => {
                let v = read_vec(src, b.body, len.min(96), wait)?;
                // version is v[0]; the 24-bit flags follow it, and bit 0
                // is track_enabled. A disabled track is one the file
                // itself says is not for playing, so it must not be
                // reachable by `a=` or picked as the default.
                if v.len() >= 4 {
                    t.enabled = u32::from_be_bytes([0, v[1], v[2], v[3]]) & 1 != 0;
                }
                if v.len() >= 24 {
                    t.track_id = u64::from(if v[0] == 1 && v.len() >= 32 {
                        u32::from_be_bytes([v[20], v[21], v[22], v[23]])
                    } else {
                        u32::from_be_bytes([v[12], v[13], v[14], v[15]])
                    });
                }
                // width/height are 16.16 fixed at the end of the box.
                if v.len() >= 84 {
                    let n = v.len();
                    t.width = u16::from_be_bytes([v[n - 8], v[n - 7]]);
                    t.height = u16::from_be_bytes([v[n - 4], v[n - 3]]);
                }
            }
            b"mdhd" => {
                let v = read_vec(src, b.body, len.min(36), wait)?;
                if v.len() >= 20 {
                    t.timescale = if v[0] == 1 && v.len() >= 28 {
                        u32::from_be_bytes([v[20], v[21], v[22], v[23]])
                    } else {
                        u32::from_be_bytes([v[12], v[13], v[14], v[15]])
                    };
                }
            }
            b"hdlr" => {
                let v = read_vec(src, b.body, len.min(16), wait)?;
                if v.len() >= 12 {
                    t.handler = [v[8], v[9], v[10], v[11]];
                }
            }
            b"stsd" => read_stsd(src, &mut t, b.body, b.end, wait, budget)?,
            b"stts" => t.stts = read_pairs(src, b.body, b.end, wait)?,
            b"ctts" => {
                // Version 0 declares the offset unsigned and version 1
                // signed, but the field is the same 32 bits either way
                // and muxers have written version-0 tables holding
                // values that only make sense read as signed. Both are
                // reinterpreted rather than clamped: clamping a large
                // "unsigned" offset to i32::MAX would put a frame hours
                // into the future, where reading it as the negative it
                // was meant to be puts it where the muxer intended.
                t.ctts = read_pairs(src, b.body, b.end, wait)?
                    .into_iter()
                    .map(|(c, v)| (c, v as i32))
                    .collect();
            }
            b"stsz" => read_stsz(src, &mut t, b.body, b.end, wait)?,
            // NOT read_stsz: stz2 is a different box with a different
            // layout, and sharing the reader silently mis-decoded every
            // one of them - see [`read_stz2`].
            b"stz2" => read_stz2(src, &mut t, b.body, b.end, wait)?,
            b"stsc" => {
                t.stsc = read_pairs3(src, b.body, b.end, wait)?;
            }
            b"stco" => {
                t.chunk_offsets = read_u32s(src, b.body, b.end, wait)?
                    .into_iter()
                    .map(u64::from)
                    .collect();
            }
            b"co64" => {
                t.chunk_offsets = read_u64s(src, b.body, b.end, wait)?;
            }
            b"stss" => {
                t.stss = Some(read_u32s(src, b.body, b.end, wait)?);
            }
            _ => {}
        }
    }
    if t.timescale == 0 || t.stsd_entry.is_empty() {
        return Ok(None);
    }
    Ok(Some(t))
}

/// A full box's entry count, and the offset of the first entry.
fn entry_count(
    src: &dyn Source,
    body: u64,
    end: u64,
    entry_len: u64,
    wait: Duration,
) -> Result<(u64, u64), RemuxError> {
    if body + 8 > end {
        return Err(bad("mp4", "table box is shorter than its header"));
    }
    let v = read_vec(src, body, 8, wait)?;
    let n = u64::from(u32::from_be_bytes([v[4], v[5], v[6], v[7]]));
    // The declared count never sizes the allocation on its own: it is
    // clipped to what the box can physically hold first.
    let can_hold = (end - body - 8) / entry_len.max(1);
    let n = n.min(can_hold).min(MAX_TABLE_ENTRIES);
    Ok((n, body + 8))
}

fn read_u32s(
    src: &dyn Source,
    body: u64,
    end: u64,
    wait: Duration,
) -> Result<Vec<u32>, RemuxError> {
    let (n, at) = entry_count(src, body, end, 4, wait)?;
    let raw = read_vec(src, at, n * 4, wait)?;
    Ok(raw
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

fn read_u64s(
    src: &dyn Source,
    body: u64,
    end: u64,
    wait: Duration,
) -> Result<Vec<u64>, RemuxError> {
    let (n, at) = entry_count(src, body, end, 8, wait)?;
    let raw = read_vec(src, at, n * 8, wait)?;
    Ok(raw
        .chunks_exact(8)
        .map(|c| u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
        .collect())
}

fn read_pairs(
    src: &dyn Source,
    body: u64,
    end: u64,
    wait: Duration,
) -> Result<Vec<(u32, u32)>, RemuxError> {
    let (n, at) = entry_count(src, body, end, 8, wait)?;
    let raw = read_vec(src, at, n * 8, wait)?;
    Ok(raw
        .chunks_exact(8)
        .map(|c| {
            (
                u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
            )
        })
        .collect())
}

/// `stsc` entries, keeping only `(first_chunk, samples_per_chunk)`.
fn read_pairs3(
    src: &dyn Source,
    body: u64,
    end: u64,
    wait: Duration,
) -> Result<Vec<(u32, u32)>, RemuxError> {
    let (n, at) = entry_count(src, body, end, 12, wait)?;
    let raw = read_vec(src, at, n * 12, wait)?;
    Ok(raw
        .chunks_exact(12)
        .map(|c| {
            (
                u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
            )
        })
        .collect())
}

fn read_stsz(
    src: &dyn Source,
    t: &mut Mp4Track,
    body: u64,
    end: u64,
    wait: Duration,
) -> Result<(), RemuxError> {
    if body + 12 > end {
        return Err(bad("mp4", "stsz is shorter than its header"));
    }
    let h = read_vec(src, body, 12, wait)?;
    let uniform = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
    let count = u64::from(u32::from_be_bytes([h[8], h[9], h[10], h[11]]));
    if uniform != 0 {
        t.stsz = Stsz::Uniform(uniform);
        return Ok(());
    }
    let can_hold = (end - body - 12) / 4;
    let n = count.min(can_hold).min(MAX_TABLE_ENTRIES);
    let raw = read_vec(src, body + 12, n * 4, wait)?;
    t.stsz = Stsz::Table(
        raw.chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    );
    Ok(())
}

/// `stz2` - the COMPACT sample size table. Same job as `stsz`, different
/// bytes: after the version/flags come three reserved bytes, then a
/// one-byte `field_size` of 4, 8 or 16, then the sample count, then the
/// sizes packed at that width (two per byte at 4 bits, high nibble
/// first).
///
/// This was dispatched to [`read_stsz`], which reads bytes 4..8 as a
/// uniform sample size - for an stz2 that is `[0, 0, 0, field_size]`,
/// i.e. the non-zero value 4, 8 or 16. So EVERY valid stz2 file was
/// decoded as "every sample is exactly 4/8/16 bytes long": offsets walked
/// into earlier samples within the first chunk and the remux output was
/// truncated and overlapping (Codex sweep 12 Aug F9).
fn read_stz2(
    src: &dyn Source,
    t: &mut Mp4Track,
    body: u64,
    end: u64,
    wait: Duration,
) -> Result<(), RemuxError> {
    if body + 12 > end {
        return Err(bad("mp4", "stz2 is shorter than its header"));
    }
    let h = read_vec(src, body, 12, wait)?;
    let field_size = h[7];
    let count = u64::from(u32::from_be_bytes([h[8], h[9], h[10], h[11]]));
    // Only the three widths the spec defines. Anything else is a file we
    // would have to guess at, and a guess here is silent corruption.
    if !matches!(field_size, 4 | 8 | 16) {
        return Err(bad("mp4", "stz2 declares an unsupported field size"));
    }
    let bits = u64::from(field_size);
    // Same discipline as every other table here: the declared count never
    // sizes the read on its own, it is clipped to what the box holds.
    let can_hold = (end - body - 12).saturating_mul(8) / bits;
    let n = count.min(can_hold).min(MAX_TABLE_ENTRIES);
    // Round UP: at 4 bits an odd count's last size lives in the high
    // nibble of a byte whose low nibble is padding.
    let raw = read_vec(src, body + 12, (n * bits).div_ceil(8), wait)?;
    let sizes: Vec<u32> = (0..n)
        .map(|i| match field_size {
            4 => {
                let b = raw[(i / 2) as usize];
                u32::from(if i % 2 == 0 { b >> 4 } else { b & 0x0f })
            }
            8 => u32::from(raw[i as usize]),
            _ => {
                let o = (i * 2) as usize;
                u32::from(u16::from_be_bytes([raw[o], raw[o + 1]]))
            }
        })
        .collect();
    t.stsz = Stsz::Table(sizes);
    Ok(())
}

fn read_stsd(
    src: &dyn Source,
    t: &mut Mp4Track,
    body: u64,
    end: u64,
    wait: Duration,
    budget: &mut u32,
) -> Result<(), RemuxError> {
    if body + 8 > end {
        return Err(bad("mp4", "stsd is shorter than its header"));
    }
    charge_mp4(budget)?;
    let b = read_box(src, body + 8, end, wait)?;
    let len = b.end - (body + 8);
    if len > MAX_CODEC_PRIVATE {
        return Err(bad("mp4", "sample entry is implausibly large"));
    }
    t.stsd_fourcc = b.fourcc;
    t.stsd_entry = read_vec(src, body + 8, len, wait)?;
    // The fixed part of the entry: 8 bytes of box header, then 6
    // reserved + data_reference_index, then the visual or audio shape.
    let e = &t.stsd_entry;
    if e.len() >= 8 + 8 + 16 + 4 && &t.handler == b"vide" {
        let o = 8 + 8 + 16;
        t.width = u16::from_be_bytes([e[o], e[o + 1]]);
        t.height = u16::from_be_bytes([e[o + 2], e[o + 3]]);
    }
    if e.len() >= 8 + 8 + 8 + 8 && &t.handler == b"soun" {
        let o = 8 + 8 + 8;
        t.channels = u16::from_be_bytes([e[o], e[o + 1]]);
        // samplerate is 16.16 fixed; the integer half is what we need.
        t.sample_rate = u32::from(u16::from_be_bytes([e[o + 6], e[o + 7]]));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The MP4 sample walk
// ---------------------------------------------------------------------------

/// A running position in one track's sample tables.
///
/// Nothing here materialises a per-sample vector: a two-hour film has
/// half a million samples per track, and the tables that describe them
/// are run-length coded for exactly that reason. The cursor decodes the
/// runs as it walks and only ever re-derives from the start on a seek.
#[derive(Debug, Clone)]
struct Mp4Cursor {
    our_id: u32,
    timescale: u32,
    total: u64,
    /// Sample index, 0-based.
    i: u64,
    dts: u64,
    stts_run: usize,
    stts_left: u32,
    ctts_run: usize,
    ctts_left: u32,
    /// 0-based chunk index and where we are inside it.
    chunk: u64,
    in_chunk: u32,
    chunk_spc: u32,
    off: u64,
    done: bool,
}

pub struct Mp4SampleIter {
    tracks: Vec<Mp4Track>,
    cursors: Vec<Mp4Cursor>,
    pub warnings: Vec<String>,
}

/// `samples_per_chunk` for a 0-based chunk index.
fn spc_for(stsc: &[(u32, u32)], chunk0: u64) -> u32 {
    let c1 = chunk0.saturating_add(1);
    let mut spc = 0;
    for &(first, n) in stsc {
        if u64::from(first) <= c1 {
            spc = n;
        } else {
            break;
        }
    }
    spc
}

impl Mp4Cursor {
    fn new(t: &Mp4Track, our_id: u32) -> Self {
        let mut c = Mp4Cursor {
            our_id,
            timescale: t.timescale.max(1),
            total: t.sample_count(),
            i: 0,
            dts: 0,
            stts_run: 0,
            stts_left: t.stts.first().map_or(0, |(c, _)| *c),
            ctts_run: 0,
            ctts_left: t.ctts.first().map_or(0, |(c, _)| *c),
            chunk: 0,
            in_chunk: 0,
            chunk_spc: spc_for(&t.stsc, 0),
            off: t.chunk_offsets.first().copied().unwrap_or(0),
            done: false,
        };
        // An stsc that puts no samples in the first chunk describes no
        // samples at all; walking it would step a chunk per sample.
        c.done = c.total == 0 || t.chunk_offsets.is_empty() || c.chunk_spc == 0;
        c
    }

    fn dts_ns(&self) -> u64 {
        (u128::from(self.dts) * 1_000_000_000 / u128::from(self.timescale.max(1))) as u64
    }

    /// Reposition to sample `target`, re-deriving every run cursor from
    /// the start of the tables. Only a seek pays for this.
    fn reset_to(&mut self, t: &Mp4Track, target: u64) -> Result<(), RemuxError> {
        *self = Mp4Cursor::new(t, self.our_id);
        while self.i < target && !self.done {
            self.step(t)?;
        }
        Ok(())
    }

    /// The sample under the cursor, without advancing.
    fn peek(&self, t: &Mp4Track) -> Option<(u64, u32, u32, i32, bool)> {
        if self.done || self.i >= self.total {
            return None;
        }
        let size = t.stsz.get(self.i)?;
        let dur = t.stts.get(self.stts_run).map_or(0, |(_, d)| *d);
        let cts = t.ctts.get(self.ctts_run).map_or(0, |(_, v)| *v);
        let key = match &t.stss {
            None => true,
            Some(v) => v
                .binary_search(&(u32::try_from(self.i + 1).unwrap_or(u32::MAX)))
                .is_ok(),
        };
        Some((self.off, size, dur, cts, key))
    }

    /// Advance one sample, moving every run cursor with it.
    fn step(&mut self, t: &Mp4Track) -> Result<(), RemuxError> {
        let Some(size) = t.stsz.get(self.i) else {
            self.done = true;
            return Ok(());
        };
        let dur = t.stts.get(self.stts_run).map_or(0, |(_, d)| *d);
        self.dts = self.dts.saturating_add(u64::from(dur));
        self.i += 1;
        if self.i >= self.total {
            self.done = true;
            return Ok(());
        }
        // stts / ctts run cursors.
        if self.stts_left > 0 {
            self.stts_left -= 1;
        }
        while self.stts_left == 0 && self.stts_run + 1 < t.stts.len() {
            self.stts_run += 1;
            self.stts_left = t.stts[self.stts_run].0;
        }
        if !t.ctts.is_empty() {
            if self.ctts_left > 0 {
                self.ctts_left -= 1;
            }
            while self.ctts_left == 0 && self.ctts_run + 1 < t.ctts.len() {
                self.ctts_run += 1;
                self.ctts_left = t.ctts[self.ctts_run].0;
            }
        }
        // Chunk cursor: inside a chunk the samples are contiguous, so
        // the offset just advances by the size we just consumed.
        self.in_chunk += 1;
        if self.in_chunk >= self.chunk_spc {
            self.chunk += 1;
            self.in_chunk = 0;
            self.chunk_spc = spc_for(&t.stsc, self.chunk);
            match t
                .chunk_offsets
                .get(usize::try_from(self.chunk).unwrap_or(usize::MAX))
            {
                Some(o) => self.off = *o,
                None => {
                    self.done = true;
                    return Ok(());
                }
            }
            if self.chunk_spc == 0 {
                return Err(bad("mp4", "stsc declares a chunk with no samples"));
            }
        } else {
            self.off = self.off.saturating_add(u64::from(size));
        }
        Ok(())
    }
}

impl Mp4SampleIter {
    pub fn new(lay: &Mp4Layout, tracks: &[SelectedTrack]) -> Result<Self, RemuxError> {
        let mut picked = Vec::new();
        let mut cursors = Vec::new();
        for sel in tracks {
            let Some(t) = lay.tracks.iter().find(|t| t.track_id == sel.src_id) else {
                continue;
            };
            cursors.push(Mp4Cursor::new(t, sel.id));
            picked.push(t.clone());
        }
        if picked.is_empty() {
            return Err(RemuxError::NoUsableTrack);
        }
        Ok(Mp4SampleIter {
            tracks: picked,
            cursors,
            warnings: Vec::new(),
        })
    }

    /// The cursor to pop next: whichever track's next sample decodes
    /// first, video winning a tie so a fragment always opens on it.
    fn pick(&self) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        for (i, c) in self.cursors.iter().enumerate() {
            if c.done || c.i >= c.total {
                continue;
            }
            let key = c.dts_ns();
            match best {
                Some((_, b)) if b <= key => {}
                _ => best = Some((i, key)),
            }
        }
        best.map(|(i, _)| i)
    }
}

impl SampleIter for Mp4SampleIter {
    fn next(&mut self, src: &dyn Source, wait: Duration) -> Result<Option<Sample>, RemuxError> {
        // Sample tables were read up front, so nothing here touches the
        // source; the payload wait belongs to the session.
        let _ = (src, wait);
        let Some(k) = self.pick() else {
            return Ok(None);
        };
        let t = &self.tracks[k];
        let c = &mut self.cursors[k];
        let Some((off, size, dur, cts, key)) = c.peek(t) else {
            c.done = true;
            return Ok(None);
        };
        // An offset table pointing past the file is corruption, not a
        // gap: the value cannot become right by waiting.
        if off.saturating_add(u64::from(size)) > src.size() {
            return Err(bad("mp4", "sample offset runs past the end of the file"));
        }
        let s = Sample {
            track: c.our_id,
            dts: c.dts,
            cts_offset: cts,
            dur: Some(dur),
            keyframe: key,
            src_off: off,
            size,
            dts_ns: c.dts_ns(),
        };
        c.step(t)?;
        Ok(Some(s))
    }

    fn seek(&mut self, _src: &dyn Source, at: u64, _t_ticks: u64) -> Result<(), RemuxError> {
        // For MP4 the "position" is a sample index on the video track,
        // and the audio cursor follows it by decode time.
        let vk = 0usize;
        let t = self.tracks[vk].clone();
        self.cursors[vk].reset_to(&t, at)?;
        let target_ns = self.cursors[vk].dts_ns();
        for (k, c) in self.cursors.iter_mut().enumerate() {
            if k == vk {
                continue;
            }
            let t = &self.tracks[k];
            // Walk forward to the first sample at or after the video's
            // decode time. Audio ahead of the video would be trimmed by
            // the browser anyway; audio behind it is a gap in sound.
            let mut probe = Mp4Cursor::new(t, c.our_id);
            while !probe.done && probe.dts_ns() < target_ns {
                let before = probe.i;
                probe.step(t)?;
                if probe.i == before {
                    break;
                }
            }
            *c = probe;
        }
        Ok(())
    }
}

/// The video sample index of the last sync sample at or before `t_ticks`.
pub fn mp4_sync_before(t: &Mp4Track, t_ticks: u64) -> Option<u64> {
    // Walk the stts RUNS - by arithmetic, never sample by sample. Every
    // run is `count` samples of equal duration starting at `dts`, so the
    // number of them at or before `t_ticks` is one division. Expanding
    // instead made a 16-byte table a CPU bomb: `count = u32::MAX` with
    // `dur = 0` never advances dts, so any seek past zero span 4.29
    // billion iterations, and sixteen authenticated preview requests
    // could hold every remux worker (Codex sweep 12 Aug F5).
    let total = t.sample_count();
    let mut idx = 0u64;
    let mut dts = 0u64;
    let mut found = 0u64;
    for &(count, dur) in &t.stts {
        if dts > t_ticks || idx >= total {
            break;
        }
        // Samples remaining under the cap `sample_count` already applied,
        // so `found` cannot name a sample the cursor will refuse to reach.
        let count = u64::from(count).min(total - idx);
        if count == 0 {
            continue;
        }
        // A zero-duration run leaves dts where it is, so the whole run is
        // at or before t_ticks - and the `dts > t_ticks` guard above is
        // what stops the NEXT run.
        let fit = match u64::from(dur) {
            0 => count,
            d => count.min((t_ticks - dts) / d + 1),
        };
        found = idx + fit - 1;
        idx += fit;
        dts = dts.saturating_add(fit.saturating_mul(u64::from(dur)));
        if fit < count {
            break;
        }
    }
    match &t.stss {
        // Every sample is a sync sample.
        None => Some(found),
        Some(v) => {
            // stss numbers samples from ONE, so the table's entry minus
            // one is the index. A file is free to write a zero there,
            // and nothing upstream rejects it: the table is read
            // straight off the wire before PAR2 has verified a byte.
            // Saturating is what keeps that a sample index instead of
            // u64::MAX - which panics where overflow checks are on and,
            // where they are not, seeks the walk past the end of the
            // file and answers a legitimate seek with nothing.
            let idx0 = |n: u32| u64::from(n).saturating_sub(1);
            let want = u32::try_from(found + 1).unwrap_or(u32::MAX);
            match v.binary_search(&want) {
                Ok(i) => Some(idx0(v[i])),
                Err(0) => v.first().map(|n| idx0(*n)),
                Err(i) => Some(idx0(v[i - 1])),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The iterator contract
// ---------------------------------------------------------------------------

pub trait SampleIter: Send {
    /// Next sample in decode order across the selected tracks.
    /// `Ok(None)` is the end of the stream; a `WouldBlock` inside the
    /// error is "the structure bytes have not landed", never the end.
    fn next(&mut self, src: &dyn Source, wait: Duration) -> Result<Option<Sample>, RemuxError>;

    /// Reposition. `at` is a byte offset for Matroska and a video sample
    /// index for MP4; `t_ticks` seeds the Matroska cluster timestamp so
    /// a walk resuming mid-file still knows what time it is.
    fn seek(&mut self, src: &dyn Source, at: u64, t_ticks: u64) -> Result<(), RemuxError>;
}

// ---------------------------------------------------------------------------
// Track selection
// ---------------------------------------------------------------------------

/// Turn a Matroska CodecID plus its CodecPrivate into a configuration
/// record the fMP4 SampleEntry can carry.
fn mkv_config(t: &MkvTrack) -> Option<(TrackConfig, &'static str)> {
    let id = t.codec_id.to_ascii_uppercase();
    let priv_ok = |min: usize| (t.codec_private.len() >= min).then(|| t.codec_private.clone());
    match id.as_str() {
        // CodecPrivate IS the configuration record for these three.
        "V_MPEG4/ISO/AVC" => priv_ok(7)
            .filter(|p| p[0] == 1)
            .map(|p| (TrackConfig::Avc(p), "h264")),
        "V_MPEGH/ISO/HEVC" => priv_ok(23).map(|p| (TrackConfig::Hevc(p), "hevc")),
        "V_AV1" => priv_ok(4).map(|p| (TrackConfig::Av1(p), "av1")),
        // VP9 in Matroska normally carries nothing; a default vpcC is
        // what every other remuxer writes and browsers ignore most of.
        "V_VP9" => Some((TrackConfig::Vp9(t.codec_private.clone()), "vp9")),
        "A_AAC" | "A_AAC/MPEG4/LC" | "A_AAC/MPEG4/LC/SBR" | "A_AAC/MPEG2/LC" => {
            Some((TrackConfig::Aac(t.codec_private.clone()), "aac"))
        }
        "A_OPUS" => priv_ok(19).map(|p| (TrackConfig::Opus(p), "opus")),
        "A_FLAC" => priv_ok(4).map(|p| (TrackConfig::Flac(p), "flac")),
        _ => None,
    }
}

/// The fourcc families an MP4 sample entry can be copied through as.
fn mp4_config(t: &Mp4Track) -> Option<(TrackConfig, &'static str)> {
    let name = match &t.stsd_fourcc {
        b"avc1" | b"avc3" => "h264",
        b"hvc1" | b"hev1" => "hevc",
        b"av01" => "av1",
        b"vp09" => "vp9",
        b"mp4a" => "aac",
        b"Opus" => "opus",
        b"fLaC" => "flac",
        _ => return None,
    };
    Some((
        TrackConfig::Mp4Entry {
            fourcc: t.stsd_fourcc,
            entry: t.stsd_entry.clone(),
        },
        name,
    ))
}

/// Which tracks the output file will carry: one video track, and at most
/// one audio track.
///
/// A browser plays one of each and a remuxer that offers more only
/// widens the surface a MediaSource can reject on. The audio choice is
/// the caller's: `want_audio` indexes the ENABLED audio tracks in
/// container order, which is what the endpoint's `a=` parameter selects.
/// `select_mp4` counts the same way, so a client can compute one index
/// from the probe without knowing which container it came from.
pub fn select_mkv(
    lay: &MkvLayout,
    want_audio: Option<usize>,
) -> Result<Vec<SelectedTrack>, RemuxError> {
    let (timescale, tick_mul) = mkv_timescale(lay.timestamp_scale_ns);
    let dur_ticks = |ns: Option<u64>| -> Option<u32> {
        let ns = ns?;
        let ticks = ns / lay.timestamp_scale_ns.max(1) * tick_mul;
        u32::try_from(ticks).ok().filter(|t| *t > 0)
    };
    let mut out = Vec::new();
    let video: Vec<&MkvTrack> = lay
        .tracks
        .iter()
        .filter(|t| t.kind == 1 && t.enabled)
        .collect();
    let audio: Vec<&MkvTrack> = lay
        .tracks
        .iter()
        .filter(|t| t.kind == 2 && t.enabled)
        .collect();

    let v = video.iter().find(|t| t.default).or(video.first());
    if let Some(t) = v
        && let Some((config, codec)) = mkv_config(t)
    {
        out.push(SelectedTrack {
            id: 1,
            kind: TrackKind::Video,
            src_id: t.number,
            timescale,
            config,
            width: u16::try_from(t.width).unwrap_or(0),
            height: u16::try_from(t.height).unwrap_or(0),
            channels: 0,
            sample_rate: 0,
            default_dur: dur_ticks(t.default_duration_ns),
            codec: codec.to_string(),
        });
    }
    let a = match want_audio {
        Some(i) => audio.get(i).copied(),
        None => audio.iter().find(|t| t.default).or(audio.first()).copied(),
    };
    if let Some(t) = a
        && let Some((config, codec)) = mkv_config(t)
    {
        out.push(SelectedTrack {
            id: out.len() as u32 + 1,
            kind: TrackKind::Audio,
            src_id: t.number,
            timescale,
            config,
            width: 0,
            height: 0,
            channels: u16::try_from(t.channels).unwrap_or(2).max(1),
            sample_rate: if t.sample_rate > 0 {
                t.sample_rate
            } else {
                48_000
            },
            default_dur: dur_ticks(t.default_duration_ns),
            codec: codec.to_string(),
        });
    }
    if out.is_empty() {
        return Err(RemuxError::NoUsableTrack);
    }
    Ok(out)
}

/// The ISO-BMFF twin of `select_mkv`, and it counts tracks the same way:
/// disabled tracks are filtered out FIRST, then `want_audio` indexes what
/// is left. See that function's note - the two must agree, or `a=N` means
/// a different track depending on the container it was computed for.
pub fn select_mp4(
    lay: &Mp4Layout,
    want_audio: Option<usize>,
) -> Result<Vec<SelectedTrack>, RemuxError> {
    let mut out = Vec::new();
    let video: Vec<&Mp4Track> = lay
        .tracks
        .iter()
        .filter(|t| &t.handler == b"vide" && t.enabled)
        .collect();
    let audio: Vec<&Mp4Track> = lay
        .tracks
        .iter()
        .filter(|t| &t.handler == b"soun" && t.enabled)
        .collect();
    if let Some(t) = video.first()
        && let Some((config, codec)) = mp4_config(t)
    {
        out.push(SelectedTrack {
            id: 1,
            kind: TrackKind::Video,
            src_id: t.track_id,
            timescale: t.timescale,
            config,
            width: t.width,
            height: t.height,
            channels: 0,
            sample_rate: 0,
            default_dur: None,
            codec: codec.to_string(),
        });
    }
    let a = match want_audio {
        Some(i) => audio.get(i).copied(),
        None => audio.first().copied(),
    };
    if let Some(t) = a
        && let Some((config, codec)) = mp4_config(t)
    {
        out.push(SelectedTrack {
            id: out.len() as u32 + 1,
            kind: TrackKind::Audio,
            src_id: t.track_id,
            timescale: t.timescale,
            config,
            width: 0,
            height: 0,
            channels: t.channels.max(1),
            sample_rate: if t.sample_rate > 0 {
                t.sample_rate
            } else {
                48_000
            },
            default_dur: None,
            codec: codec.to_string(),
        });
    }
    if out.is_empty() {
        return Err(RemuxError::NoUsableTrack);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediaprobe::source::MemSource;

    const NOW: Duration = Duration::ZERO;

    #[test]
    fn vint_lengths_follow_the_leading_zero_count() {
        assert_eq!(vint_len(0x80).unwrap(), 1);
        assert_eq!(vint_len(0x40).unwrap(), 2);
        assert_eq!(vint_len(0x01).unwrap(), 8);
        assert!(vint_len(0).is_err());
    }

    #[test]
    fn an_unknown_size_is_all_value_bits_set() {
        let s = MemSource(vec![0xFF, 0x01]);
        let (v, len, unknown) = read_size(&s, 0, NOW).unwrap();
        assert_eq!((v, len, unknown), (127, 1, true));
        let s = MemSource(vec![0x81]);
        let (v, _, unknown) = read_size(&s, 0, NOW).unwrap();
        assert_eq!((v, unknown), (1, false));
    }

    /// A timescale that divides a second passes ticks straight through;
    /// one that does not counts in nanoseconds instead. Both are exact.
    #[test]
    fn mkv_timescales_stay_integer_exact() {
        assert_eq!(mkv_timescale(1_000_000), (1000, 1));
        assert_eq!(mkv_timescale(1), (1_000_000_000, 1));
        let (ts, mul) = mkv_timescale(3);
        assert_eq!((ts, mul), (1_000_000_000, 3));
        // 100 source ticks of 3 ns = 300 ns, exactly.
        assert_eq!(100 * mul * 1_000_000_000 / u64::from(ts), 300);
    }

    // ---------------------------------------------------------------
    // Track selection, and the one index the client has to agree with
    // ---------------------------------------------------------------

    fn mkv_track(number: u64, kind: u64, codec: &str, enabled: bool) -> MkvTrack {
        MkvTrack {
            number,
            kind,
            codec_id: codec.to_string(),
            // Enough of an avcC for mkv_config to accept the video one;
            // A_AAC takes whatever it is given.
            codec_private: vec![1, 100, 0, 40, 0xFF, 0xE1, 0],
            default_duration_ns: None,
            width: 1920,
            height: 1080,
            channels: 2,
            sample_rate: 48_000,
            enabled,
            default: false,
        }
    }

    fn mkv_lay(tracks: Vec<MkvTrack>) -> MkvLayout {
        MkvLayout {
            segment_data_start: 0,
            segment_end: 0,
            timestamp_scale_ns: 1_000_000,
            first_cluster_off: None,
            cues_off: None,
            duration_ns: None,
            tracks,
        }
    }

    fn mp4_track(track_id: u64, handler: &[u8; 4], fourcc: &[u8; 4], enabled: bool) -> Mp4Track {
        Mp4Track {
            track_id,
            handler: *handler,
            timescale: 1000,
            width: 1920,
            height: 1080,
            channels: 2,
            sample_rate: 48_000,
            stsd_fourcc: *fourcc,
            stsd_entry: vec![0; 16],
            stts: vec![(1, 100)],
            ctts: vec![],
            stsz: Stsz::Uniform(10),
            stsc: vec![(1, 1)],
            chunk_offsets: vec![0],
            stss: None,
            enabled,
        }
    }

    fn audio_src_id(sel: &[SelectedTrack]) -> Option<u64> {
        sel.iter()
            .find(|t| t.kind == TrackKind::Audio)
            .map(|t| t.src_id)
    }

    /// `a=` counts ENABLED audio tracks. A file whose second audio track
    /// is disabled must answer `a=1` with the THIRD track, because that
    /// is the second one a viewer can be offered - and it is the index
    /// the dashboard computes from the probe, which filters the same way.
    #[test]
    fn audio_selection_indexes_enabled_tracks_only() {
        let lay = mkv_lay(vec![
            mkv_track(1, 1, "V_MPEG4/ISO/AVC", true),
            mkv_track(2, 2, "A_AAC", true),
            mkv_track(3, 2, "A_AAC", false),
            mkv_track(4, 2, "A_AAC", true),
        ]);
        assert_eq!(audio_src_id(&select_mkv(&lay, Some(0)).unwrap()), Some(2));
        // The disabled track 3 is not addressable at all; index 1 is the
        // next ENABLED one. Counting raw tracks would answer 3 here.
        assert_eq!(audio_src_id(&select_mkv(&lay, Some(1)).unwrap()), Some(4));
        // Default with no request: the first enabled track.
        assert_eq!(audio_src_id(&select_mkv(&lay, None).unwrap()), Some(2));
    }

    /// The same count in the other container, so one client-side index is
    /// correct for both. Before this, `select_mp4` ignored tkhd's enabled
    /// flag and `a=1` meant a different track than it did in Matroska.
    #[test]
    fn mp4_audio_selection_counts_the_same_way() {
        let lay = Mp4Layout {
            timescale: 1000,
            duration: 1000,
            tracks: vec![
                mp4_track(1, b"vide", b"avc1", true),
                mp4_track(2, b"soun", b"mp4a", true),
                mp4_track(3, b"soun", b"mp4a", false),
                mp4_track(4, b"soun", b"mp4a", true),
            ],
        };
        assert_eq!(audio_src_id(&select_mp4(&lay, Some(0)).unwrap()), Some(2));
        assert_eq!(audio_src_id(&select_mp4(&lay, Some(1)).unwrap()), Some(4));
        assert_eq!(audio_src_id(&select_mp4(&lay, None).unwrap()), Some(2));
    }

    /// An index past the end drops the audio track rather than wrapping,
    /// clamping or panicking. The video still plays: a bad `a=` must not
    /// cost the viewer the picture too.
    #[test]
    fn an_out_of_range_audio_index_yields_no_audio_track() {
        let lay = mkv_lay(vec![
            mkv_track(1, 1, "V_MPEG4/ISO/AVC", true),
            mkv_track(2, 2, "A_AAC", true),
        ]);
        let sel = select_mkv(&lay, Some(9)).unwrap();
        assert_eq!(audio_src_id(&sel), None);
        assert!(sel.iter().any(|t| t.kind == TrackKind::Video));

        let mp4 = Mp4Layout {
            timescale: 1000,
            duration: 1000,
            tracks: vec![
                mp4_track(1, b"vide", b"avc1", true),
                mp4_track(2, b"soun", b"mp4a", true),
            ],
        };
        let sel = select_mp4(&mp4, Some(9)).unwrap();
        assert_eq!(audio_src_id(&sel), None);
        assert!(sel.iter().any(|t| t.kind == TrackKind::Video));
    }

    /// A disabled VIDEO track is not the one that plays either. Matroska
    /// already worked this way; ISO-BMFF now agrees.
    #[test]
    fn a_disabled_video_track_is_skipped() {
        let lay = Mp4Layout {
            timescale: 1000,
            duration: 1000,
            tracks: vec![
                mp4_track(1, b"vide", b"avc1", false),
                mp4_track(2, b"vide", b"avc1", true),
            ],
        };
        let sel = select_mp4(&lay, None).unwrap();
        let v = sel.iter().find(|t| t.kind == TrackKind::Video).unwrap();
        assert_eq!(v.src_id, 2);
    }

    #[test]
    fn stsc_runs_resolve_samples_per_chunk() {
        let stsc = vec![(1u32, 4u32), (5, 2), (9, 7)];
        assert_eq!(spc_for(&stsc, 0), 4);
        assert_eq!(spc_for(&stsc, 3), 4);
        assert_eq!(spc_for(&stsc, 4), 2);
        assert_eq!(spc_for(&stsc, 7), 2);
        assert_eq!(spc_for(&stsc, 8), 7);
        assert_eq!(spc_for(&stsc, 100), 7);
    }

    #[test]
    fn sync_search_lands_at_or_before_the_target() {
        let t = Mp4Track {
            track_id: 1,
            handler: *b"vide",
            timescale: 1000,
            width: 0,
            height: 0,
            channels: 0,
            sample_rate: 0,
            stsd_fourcc: *b"avc1",
            stsd_entry: vec![0; 16],
            stts: vec![(10, 100)],
            ctts: vec![],
            stsz: Stsz::Uniform(10),
            stsc: vec![(1, 10)],
            chunk_offsets: vec![0],
            stss: Some(vec![1, 5, 9]),
            enabled: true,
        };
        // t=0 -> sample 0 (index of stss entry 1).
        assert_eq!(mp4_sync_before(&t, 0), Some(0));
        // t=650 -> sample 6, last sync at or before is stss 5 -> index 4.
        assert_eq!(mp4_sync_before(&t, 650), Some(4));
        // Past the end clamps to the last sync sample.
        assert_eq!(mp4_sync_before(&t, 100_000), Some(8));
    }

    /// A sync-sample table numbers from one. A file that writes a ZERO
    /// there is malformed, and the subtraction that turns an entry into
    /// an index used to underflow on it: a panic where overflow checks
    /// are on, and u64::MAX where they are not, which seeks the walk
    /// past the end of the file. Found by the `remux` fuzz target on its
    /// first campaign (603k execs).
    #[test]
    fn a_zero_sync_sample_entry_does_not_underflow() {
        let mut t = mp4_track(1, b"vide", b"avc1", true);
        t.stts = vec![(10, 100)];
        t.stsz = Stsz::Uniform(10);
        t.stsc = vec![(1, 10)];
        // Every arm of the binary search has to survive it.
        t.stss = Some(vec![0]);
        assert_eq!(mp4_sync_before(&t, 0), Some(0)); // Ok arm is unreachable at 0
        assert_eq!(mp4_sync_before(&t, 100_000), Some(0)); // Err(i), reads v[i-1]
        t.stss = Some(vec![0, 5]);
        assert_eq!(mp4_sync_before(&t, 0), Some(0)); // Err(0), reads v.first()
        assert_eq!(mp4_sync_before(&t, 650), Some(4));
        // A zero beside real entries still never reports a wrapped index.
        t.stss = Some(vec![0, 0, 9]);
        for ticks in [0u64, 250, 650, 100_000] {
            let got = mp4_sync_before(&t, ticks).unwrap();
            assert!(got < 100, "index {got} wrapped");
        }
    }

    /// The seek walks stts by RUN, not by sample. A sixteen-byte table
    /// declaring `count = u32::MAX, duration = 0` never advances DTS, so
    /// the old per-sample expansion span 4.29 billion iterations for any
    /// seek past zero - and sixteen authenticated preview requests could
    /// hold every remux worker (Codex sweep 12 Aug F5).
    ///
    /// The assertion that matters is that this returns AT ALL: a test
    /// that hangs is the regression.
    #[test]
    fn a_pathological_stts_run_cannot_spin() {
        let mut t = mp4_track(1, b"vide", b"avc1", true);
        t.stsz = Stsz::Uniform(10);
        t.stsc = vec![(1, 10)];
        t.stss = None;
        // Zero duration: DTS is stuck at 0, so every sample in the run is
        // "at or before" any target. The answer is the last sample the
        // cursor could ever reach, not 4.29 billion.
        t.stts = vec![(u32::MAX, 0)];
        assert_eq!(t.sample_count(), MAX_TABLE_ENTRIES);
        assert_eq!(mp4_sync_before(&t, 5_000_000), Some(MAX_TABLE_ENTRIES - 1));
        // Two such runs cannot sum past the cap either.
        t.stts = vec![(u32::MAX, 0), (u32::MAX, 0)];
        assert_eq!(t.sample_count(), MAX_TABLE_ENTRIES);
        assert_eq!(mp4_sync_before(&t, 1), Some(MAX_TABLE_ENTRIES - 1));
    }

    /// Run arithmetic has to give the same answers the sample-by-sample
    /// walk did, including across a run boundary and inside a run.
    #[test]
    fn sync_search_matches_a_sample_by_sample_walk() {
        let mut t = mp4_track(1, b"vide", b"avc1", true);
        t.stsz = Stsz::Table(vec![10; 30]);
        t.stsc = vec![(1, 30)];
        t.stss = None;
        // 10 samples of 100 ticks (0..900), then 10 of 250 (1000..3250),
        // then 10 of 1 (3500..3509).
        t.stts = vec![(10, 100), (10, 250), (10, 1)];
        let walk = |target: u64| -> u64 {
            let mut idx = 0u64;
            let mut dts = 0u64;
            let mut found = 0u64;
            'outer: for &(count, dur) in &t.stts {
                for _ in 0..count {
                    if dts > target {
                        break 'outer;
                    }
                    found = idx;
                    dts += u64::from(dur);
                    idx += 1;
                }
            }
            found
        };
        for target in [
            0u64, 1, 99, 100, 899, 900, 999, 1000, 1249, 3250, 3509, 99_999,
        ] {
            assert_eq!(
                mp4_sync_before(&t, target),
                Some(walk(target)),
                "target {target}"
            );
        }
    }

    /// `stz2` is the COMPACT table and shared `read_stsz` for its whole
    /// life, which read its `field_size` byte as a UNIFORM sample size -
    /// so every valid stz2 file decoded as "4, 8 or 16 bytes per sample",
    /// and the remux output overlapped and truncated (Codex sweep 12 Aug
    /// F9).
    #[test]
    fn compact_sample_sizes_are_decoded_at_all_three_widths() {
        // (field_size, packed body, expected sizes) - an ODD count at 4
        // bits, so the padded final nibble is covered too.
        let cases: [(u8, Vec<u8>, Vec<u32>); 3] = [
            (4, vec![0x39, 0xF0], vec![3, 9, 15]),
            (8, vec![7, 255, 1], vec![7, 255, 1]),
            (
                16,
                vec![0x00, 0x07, 0xFF, 0xFF, 0x01, 0x00],
                vec![7, 65_535, 256],
            ),
        ];
        for (field_size, body, want) in cases {
            let mut buf = vec![0u8; 8]; // box header room; body starts at 8
            buf.extend([0, 0, 0, 0]); // version + flags
            buf.extend([0, 0, 0]); // reserved
            buf.push(field_size);
            buf.extend(3u32.to_be_bytes()); // sample_count
            buf.extend(&body);
            let end = buf.len() as u64;
            let src = MemSource(buf);
            let mut t = mp4_track(1, b"vide", b"avc1", true);
            read_stz2(&src, &mut t, 8, end, NOW).unwrap();
            let got: Vec<u32> = (0..want.len() as u64)
                .map(|i| t.stsz.get(i).unwrap())
                .collect();
            assert_eq!(got, want, "field_size {field_size}");
            assert_eq!(t.stsz.count(0), want.len() as u64);
        }
    }

    /// A width the spec does not define is refused rather than guessed
    /// at: a guess here is silent output corruption.
    #[test]
    fn an_unsupported_compact_field_size_is_refused() {
        let mut buf = vec![0u8; 8];
        buf.extend([0, 0, 0, 0, 0, 0, 0, 12]); // version/flags + field_size 12
        buf.extend(1u32.to_be_bytes());
        buf.extend([0, 0, 0, 0]);
        let end = buf.len() as u64;
        let src = MemSource(buf);
        let mut t = mp4_track(1, b"vide", b"avc1", true);
        assert!(read_stz2(&src, &mut t, 8, end, NOW).is_err());
    }

    /// A declared table count larger than the box that holds it is
    /// clipped to what the box can physically contain, so a hostile
    /// count cannot reserve memory.
    #[test]
    fn a_table_count_is_clipped_to_the_box() {
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0, 0, 0]); // version + flags
        b.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // count: a lie
        b.extend_from_slice(&7u32.to_be_bytes());
        b.extend_from_slice(&9u32.to_be_bytes());
        let s = MemSource(b);
        let v = read_u32s(&s, 0, s.size(), NOW).unwrap();
        assert_eq!(v, vec![7, 9]);
    }
}
