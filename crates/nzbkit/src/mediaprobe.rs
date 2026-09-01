//! What a downloading video actually is: container, tracks, codecs,
//! languages, HDR - read straight out of the bytes that have landed.
//!
//! This is the backend of the preview-and-verify panel (TODO §73 phase
//! 1). A user who can see, forty seconds into a download, that the file
//! is HEVC when they wanted h264, or that the only audio track is
//! German, has saved themselves the rest of the download and a failed
//! import. Everything here is byte-layout parsing - no codec decode, no
//! external tools, no new dependencies.
//!
//! ## Why this is not [`crate::mkv`] / [`crate::mp4`]
//!
//! Those two answer a different question over a different reader. They
//! are pure functions over ONE bounded head slice, and they exist to
//! check or synthesise a FILENAME: how long, how wide, what the muxer
//! titled it. They deliberately drop what a name cannot use - an
//! untagged track's language stays untagged rather than defaulting to
//! English, a track that is not the first video track is discarded.
//!
//! This module reads a `Read + Seek` (so it can jump a multi-gigabyte
//! `mdat` to reach a trailing `moov`, and chase a SeekHead into the
//! tail), tolerates HOLES in the middle of the file, and reports every
//! track with the flags a viewer needs. The two answer to different
//! callers and neither is a superset of the other, so they stay
//! separate walks over shared tables: codec spellings and the ISO 639
//! mapping live in [`crate::media`] and are called from here, never
//! copied.
//!
//! ## The gap convention
//!
//! Probe NEVER blocks and never sleeps. A reader sitting over a
//! half-downloaded file reports a byte range that has not arrived as
//! [`std::io::ErrorKind::WouldBlock`] (see [`LiveProbeReader`]); a
//! plain [`std::fs::File`] never does, so a finished file is the
//! degenerate case of the same code. Hitting a gap ends that subtree
//! cleanly: keep what was parsed, push a warning, clear
//! [`MediaInfo::complete`], and carry on with the siblings whose
//! offsets are known. Waiting is the endpoint layer's job (the client
//! polls), never the parser's.
//!
//! ## Untrusted input
//!
//! These bytes come off Usenet. Every walk is bounded by an element
//! budget and a byte budget, is depth-capped, clips every child to its
//! parent's extent, and never allocates from a declared length. The
//! budgets are deliberately free of wall-clock time so that probing the
//! same bytes twice gives the same answer - which is what the fuzz
//! target asserts (fuzz_targets/mediaprobe.rs).

use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};

mod codec;
mod ebml;
pub mod facts;
pub mod fmp4;
mod isobmff;
mod riff;
pub mod samples;
pub mod session;
pub mod source;
pub mod testmux;

pub use samples::{RemuxError, Sample, SelectedTrack, TrackConfig, TrackKind};
pub use session::{Emit, FragRef, RemuxSession};
pub use source::Source;

pub use codec::{CodecSupport, channel_layout, lookup};
pub use facts::MediaFacts;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Everything the probe could read. `Option` fields serialize as `null`
/// rather than vanishing, and every `Vec` is always present: the
/// dashboard panel codes against a stable shape.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MediaInfo {
    pub container: Container,
    pub(crate) duration_ms: Option<u64>,
    pub playback: PlaybackPath,
    pub video: Vec<VideoTrack>,
    pub audio: Vec<AudioTrack>,
    pub subtitles: Vec<SubTrack>,
    pub chapters: Vec<Chapter>,
    /// The container's own title, when it wrote one (Matroska
    /// Segment>Info>Title, MP4 `udta/©nam`). Not in the original
    /// contract and added deliberately: this feature exists to answer
    /// "is this the right file", and a muxer's own name for the content
    /// survives every layer of subject-line obfuscation around it.
    pub(crate) title: Option<String>,
    /// True when every metadata region the container needed was read to
    /// its end without hitting a gap or a truncation. NOT "the file is
    /// fully downloaded".
    pub complete: bool,
    /// English wire strings; the UI translates at the edge.
    pub warnings: Vec<String>,
}

impl MediaInfo {
    /// Does this file actually carry picture?
    ///
    /// Counts ENABLED video tracks only, the same rule [`classify`] uses
    /// - a container may list a track it has marked off, and a track the
    /// muxer disabled does not make the file a video.
    ///
    /// Exists because `enabled` is crate-private while the question is
    /// not: nzbfast asks it when a payload arrived with no extension at
    /// all, where the container magic cannot answer. `.mka` is Matroska
    /// and `.m4a` is MP4, so magic alone calls audio-only files video;
    /// track types are the only honest discriminator.
    pub fn has_video(&self) -> bool {
        self.video.iter().any(|v| v.enabled)
    }

    fn new(container: Container) -> Self {
        MediaInfo {
            container,
            duration_ms: None,
            playback: PlaybackPath::Unknown,
            video: Vec::new(),
            audio: Vec::new(),
            subtitles: Vec::new(),
            chapters: Vec::new(),
            title: None,
            complete: true,
            warnings: Vec::new(),
        }
    }

    /// One warning, once. A truncated file hits the same gap on every
    /// sibling element, and a panel listing "chapters not yet
    /// downloaded" forty times says nothing extra.
    fn warn(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if !self.warnings.contains(&msg) {
            self.warnings.push(msg);
        }
    }

    /// A gap or truncation: keep what we have, say what is missing.
    fn incomplete(&mut self, msg: impl Into<String>) {
        self.complete = false;
        self.warn(msg);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Container {
    Mkv,
    Webm,
    Mp4,
    Avi,
    Unknown,
}

/// How this file can reach a browser. Serializes PascalCase on purpose:
/// the wire JSON and the dashboard's `switch (j.playback)` both spell it
/// that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PlaybackPath {
    /// Raw bytes straight to a `<video>` element.
    Native,
    /// Needs the fMP4 remux (phase 2); the codecs themselves are fine.
    Remux,
    /// A real transcoder would be needed - detected on PATH only, never
    /// bundled. Until then the panel still verifies and hands off.
    Transcode,
    /// Not enough parsed yet, or nothing we recognise.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VideoTrack {
    /// Canonical short name ("h264", "hevc", "av1", ...), or the raw id
    /// lowercased when we do not recognise it.
    pub codec: String,
    /// Raw container identifier: MKV CodecID, MP4 sample-entry fourcc,
    /// AVI biCompression fourcc.
    pub(crate) codec_id: String,
    pub width: u32,
    pub height: u32,
    /// Display aspect as "W:H" reduced by gcd, when the container says
    /// the pixels are not square. `None` means "as coded".
    pub(crate) display_ar: Option<String>,
    pub(crate) fps: Option<f64>,
    pub(crate) bit_depth: Option<u8>,
    pub(crate) hdr: Option<Hdr>,
    pub(crate) profile: Option<String>,
    pub(crate) level: Option<String>,
    pub(crate) bitrate: Option<u64>,
    /// The RFC 6381 codec parameter ("avc1.640029"), built from the
    /// container's own configuration record - what a browser is asked
    /// about with `canPlayType` / `MediaSource.isTypeSupported`. `null`
    /// when the container carried no configuration record to build it
    /// from; the client then falls back to a coarse family test.
    pub(crate) codec_rfc6381: Option<String>,
    /// False when the container marked the track disabled. Disabled
    /// tracks are still listed (the panel shows everything) but do not
    /// vote on [`PlaybackPath`].
    pub(crate) enabled: bool,
    pub(crate) default: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AudioTrack {
    pub codec: String,
    pub(crate) codec_id: String,
    /// Normalised BCP 47; "und" when the muxer said nothing.
    pub(crate) lang: String,
    pub(crate) channels: u32,
    /// "mono", "stereo", "5.1", "7.1", or "N ch".
    pub(crate) channel_layout: String,
    pub(crate) sample_rate: Option<u32>,
    pub(crate) title: Option<String>,
    pub(crate) default: bool,
    pub(crate) forced: bool,
    pub(crate) bitrate: Option<u64>,
    /// The RFC 6381 codec parameter ("mp4a.40.2", "ec-3"). Same purpose
    /// as [`VideoTrack::codec_rfc6381`]: it is how the panel finds out
    /// whether this browser has the decoder, which is what stands
    /// between "plays" and "plays, silently".
    pub(crate) codec_rfc6381: Option<String>,
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SubTrack {
    pub(crate) codec: String,
    pub(crate) codec_id: String,
    pub(crate) lang: String,
    pub(crate) title: Option<String>,
    pub(crate) default: bool,
    pub(crate) forced: bool,
    pub(crate) kind: SubKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SubKind {
    /// Renderable as timed text.
    Text,
    /// A picture per subtitle (PGS, VobSub) - nothing but a real
    /// renderer can show these.
    Bitmap,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Chapter {
    pub(crate) start_ms: u64,
    /// "" when the container gave a chapter no name.
    pub(crate) title: String,
}

/// Colour signalling, resolved from the H.273 code points both
/// containers write.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Hdr {
    pub(crate) matrix: Option<String>,
    pub(crate) transfer: Option<String>,
    pub(crate) primaries: Option<String>,
    pub(crate) max_cll: Option<u32>,
    pub(crate) max_fall: Option<u32>,
    /// The panel's badge: "HDR10", "HLG", "HDR" (wide primaries but an
    /// unknown transfer), or "SDR".
    pub format: String,
}

/// What the caller already knows about the file. Both fields are hints
/// only - the magic bytes decide the container, never the name.
#[derive(Debug, Clone, Default)]
pub struct ProbeHint {
    /// Output filename, used to label warnings.
    pub filename: Option<String>,
    /// Final on-disk size when known ([`crate::disk::FileWriter::size`]).
    /// Needed for the unknown-size Matroska Segment and for the
    /// moov-at-end scan, neither of which can ask a half-written file
    /// how long it will be.
    pub known_size: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("unrecognized container")]
    UnknownContainer,
    /// The first bytes needed to identify the container are not on disk
    /// yet. The caller answers "pending", not "error".
    #[error("header bytes not yet available")]
    NotYet,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed {container}: {what}")]
    Malformed {
        container: &'static str,
        what: &'static str,
    },
    #[error("probe budget exceeded")]
    BudgetExceeded,
}

impl ProbeError {
    /// A missing byte range, not a broken file: the two arrive as the
    /// same `Err` and mean "stop this subtree, keep the rest".
    fn is_gap(&self) -> bool {
        matches!(
            self,
            ProbeError::Io(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::UnexpectedEof
        )
    }
}

// ---------------------------------------------------------------------------
// Budgets (deliberately time-free - see the module doc)
// ---------------------------------------------------------------------------

/// Total bytes the probe will actually read. Headers and parsed leaves
/// only: `mdat` and clusters are skipped by arithmetic, so a 60 GB file
/// costs a few hundred KB.
const MAX_PROBE_BYTES: u64 = 64 << 20;
/// Elements/boxes visited across every walk.
const MAX_ELEMENTS: u32 = 100_000;
/// Nesting depth. Both walks use an explicit stack, so this is a
/// structural bound rather than a convention about recursion.
const MAX_DEPTH: usize = 16;
const MAX_TRACKS: usize = 64;
const MAX_CHAPTERS: usize = 512;
/// Longest string leaf carried out of a container.
const MAX_STRING: usize = 1024;

#[derive(Debug)]
struct Budget {
    bytes: u64,
    elements: u32,
}

impl Budget {
    fn new() -> Self {
        Budget {
            bytes: 0,
            elements: 0,
        }
    }

    fn charge_bytes(&mut self, n: u64) -> Result<(), ProbeError> {
        self.bytes = self.bytes.saturating_add(n);
        (self.bytes <= MAX_PROBE_BYTES)
            .then_some(())
            .ok_or(ProbeError::BudgetExceeded)
    }

    /// Charged once per element/box header, so no walk can spin without
    /// paying for it.
    fn charge_element(&mut self) -> Result<(), ProbeError> {
        self.elements += 1;
        (self.elements <= MAX_ELEMENTS)
            .then_some(())
            .ok_or(ProbeError::BudgetExceeded)
    }
}

// ---------------------------------------------------------------------------
// The bounded reader every walk goes through
// ---------------------------------------------------------------------------

/// A cursor with a budget. Seeking is pure arithmetic (nothing is read
/// until a read is asked for), which is what lets the MP4 walk step over
/// a multi-gigabyte `mdat` that has not been downloaded at all.
pub(crate) struct Rd<'a, R: Read + Seek> {
    r: &'a mut R,
    pos: u64,
    /// End of the file, from the hint or from a seek to the end.
    end: u64,
    budget: Budget,
}

impl<'a, R: Read + Seek> Rd<'a, R> {
    fn new(r: &'a mut R, known_size: Option<u64>) -> Result<Self, ProbeError> {
        let end = match known_size {
            Some(n) => n,
            None => r.seek(SeekFrom::End(0))?,
        };
        Ok(Rd {
            r,
            pos: 0,
            end,
            budget: Budget::new(),
        })
    }

    fn seek_to(&mut self, pos: u64) {
        self.pos = pos;
    }

    fn read_exact_at(&mut self, pos: u64, buf: &mut [u8]) -> Result<(), ProbeError> {
        self.budget.charge_bytes(buf.len() as u64)?;
        self.r.seek(SeekFrom::Start(pos))?;
        self.r.read_exact(buf)?;
        self.pos = pos + buf.len() as u64;
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ProbeError> {
        let at = self.pos;
        self.read_exact_at(at, buf)
    }

    /// A leaf payload, capped. Allocation follows `min(declared, cap)`
    /// and the read is chunked, so a lying length cannot reserve memory
    /// or read past the cap.
    fn read_leaf(&mut self, declared: u64, cap: usize) -> Result<Vec<u8>, ProbeError> {
        let want = declared.min(cap as u64) as usize;
        let mut out = vec![0u8; want];
        if want > 0 {
            let at = self.pos;
            self.read_exact_at(at, &mut out)?;
        }
        Ok(out)
    }

    fn read_leaf_at(&mut self, at: u64, declared: u64, cap: usize) -> Result<Vec<u8>, ProbeError> {
        self.seek_to(at);
        self.read_leaf(declared, cap)
    }

    fn read_string_at(&mut self, at: u64, declared: u64) -> Result<Option<String>, ProbeError> {
        self.seek_to(at);
        self.read_string(declared)
    }

    /// A short string leaf, lossily decoded, control characters dropped
    /// (they would otherwise reach a UI or a filename) and trimmed.
    fn read_string(&mut self, declared: u64) -> Result<Option<String>, ProbeError> {
        let raw = self.read_leaf(declared, MAX_STRING)?;
        let end = raw.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
        let s: String = String::from_utf8_lossy(&raw[..end])
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let s = s.trim().to_string();
        Ok((!s.is_empty()).then_some(s))
    }
}

fn be_uint(b: &[u8]) -> Option<u64> {
    (b.len() <= 8).then(|| b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

/// Reduce `w:h` by their gcd, for a display-aspect string.
fn ratio(w: u64, h: u64) -> Option<String> {
    if w == 0 || h == 0 {
        return None;
    }
    let (mut a, mut b) = (w, h);
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    Some(format!("{}:{}", w / a, h / a))
}

fn round3(v: f64) -> Option<f64> {
    (v.is_finite() && v > 0.0 && v < 10_000.0).then(|| (v * 1000.0).round() / 1000.0)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Probe a media file. Fixed contract: the daemon calls this over a
/// [`LiveProbeReader`] for a downloading job and over a plain
/// [`std::fs::File`] for a finished one.
///
/// A PARTIAL answer is `Ok`: only "cannot even identify the container"
/// and hard structural corruption are `Err`.
pub fn probe<R: Read + Seek>(r: &mut R, hint: ProbeHint) -> Result<MediaInfo, ProbeError> {
    let mut rd = Rd::new(r, hint.known_size)?;
    let mut magic = [0u8; 12];
    // A file shorter than 12 bytes is not a container; read what there
    // is so a 4-byte EBML magic still identifies.
    let head = rd.end.min(12) as usize;
    match rd.read_exact_at(0, &mut magic[..head]) {
        Ok(()) => {}
        Err(e) if e.is_gap() => return Err(ProbeError::NotYet),
        Err(e) => return Err(e),
    }
    let magic = &magic[..head];
    let container = sniff(magic).ok_or(ProbeError::UnknownContainer)?;
    let mut info = MediaInfo::new(container);
    if let Some(name) = hint.filename.as_deref()
        && let Some(ext) = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
        && !ext_agrees(container, &ext)
    {
        info.warn(format!("file named .{ext} but the bytes are {container:?}").to_lowercase());
    }
    match container {
        Container::Mkv | Container::Webm => ebml::parse(&mut rd, &mut info)?,
        Container::Mp4 => isobmff::parse(&mut rd, &mut info)?,
        Container::Avi => riff::parse(&mut rd, &mut info)?,
        Container::Unknown => return Err(ProbeError::UnknownContainer),
    }
    info.playback = classify(&mut info);
    Ok(info)
}

/// Container from the first bytes. The filename never overrides this -
/// a `.mp4` holding Matroska is a mislabelled file, not an MP4, and the
/// panel says so.
fn sniff(b: &[u8]) -> Option<Container> {
    if b.len() >= 4 && b[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        // DocType decides Mkv vs Webm; assume Matroska until the EBML
        // header says otherwise.
        return Some(Container::Mkv);
    }
    if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"AVI " {
        return Some(Container::Avi);
    }
    if b.len() >= 8 {
        let size = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let plausible = size == 0 || size == 1 || size >= 8;
        let known = matches!(
            &b[4..8],
            b"ftyp" | b"moov" | b"mdat" | b"free" | b"skip" | b"wide" | b"styp" | b"sidx"
        );
        if plausible && known {
            return Some(Container::Mp4);
        }
    }
    None
}

/// The extension a container's own bytes call for, for a payload that
/// arrived with NO extension at all - which is what an indexer that
/// obfuscates the filenames inside an NZB produces.
///
/// Head-only and allocation-free on purpose: the callers run over every
/// file in a finished job's directory and must not pay a container
/// parse just to ask what a file is. The bytes decide, exactly as in
/// [`sniff`] - but this is only ever asked about a file that named
/// nothing, so there is no claim here for the bytes to override.
///
/// NOT ONLY RENAME PASSES, which is what this said until 31 Aug 2026.
/// `nzbfast`'s `smart::looks_like_video_bytes` - the keep-media-only
/// CLEANUP door - asks it too, and answering NO there means the file is
/// DELETED. So the two failure directions are not symmetric any more: a
/// name this declines to offer costs a hash-named file, and a container
/// it stops recognising costs the file itself. NARROWING [`sniff`]'s
/// accepted first-box set is therefore a data-loss change in a crate
/// this one does not build, and wants that door read first. It was one
/// caller short of that door for months precisely because the door
/// spelled the same three magics by hand instead of asking here, which
/// is the drift `smart/videoext.rs` documents three instances of.
pub fn container_ext(head: &[u8]) -> Option<&'static str> {
    match sniff(head)? {
        Container::Mkv => Some("mkv"),
        Container::Webm => Some("webm"),
        Container::Mp4 => Some("mp4"),
        Container::Avi => Some("avi"),
        Container::Unknown => None,
    }
}

fn ext_agrees(c: Container, ext: &str) -> bool {
    match c {
        Container::Mkv => matches!(ext, "mkv" | "mk3d" | "mka"),
        Container::Webm => matches!(ext, "webm" | "mkv"),
        Container::Mp4 => matches!(ext, "mp4" | "m4v" | "mov" | "m4a" | "ts"),
        Container::Avi => ext == "avi",
        Container::Unknown => true,
    }
}

/// The playback rule. Evaluated over ENABLED tracks only; subtitle
/// codecs never vote.
fn classify(info: &mut MediaInfo) -> PlaybackPath {
    let vids: Vec<&VideoTrack> = info.video.iter().filter(|v| v.enabled).collect();
    if vids.is_empty() {
        return PlaybackPath::Unknown;
    }
    let sup = |canon: &str, is_video: bool| codec::support_of(canon, is_video);
    if vids
        .iter()
        .any(|v| sup(&v.codec, true) == CodecSupport::NotRecognized)
    {
        return PlaybackPath::Unknown;
    }
    let auds: Vec<&AudioTrack> = info.audio.iter().filter(|a| a.enabled).collect();
    let v_all = |set: &[CodecSupport]| vids.iter().all(|v| set.contains(&sup(&v.codec, true)));
    let a_all = |set: &[CodecSupport]| auds.iter().all(|a| set.contains(&sup(&a.codec, false)));

    // One line naming the track that forced a transcode - "it needs
    // transcoding" with no reason is the kind of message that generates
    // a support question.
    let mut notes: Vec<String> = Vec::new();
    for v in &vids {
        if sup(&v.codec, true) == CodecSupport::Transcode {
            notes.push(format!("{} video needs transcoding", v.codec));
        }
    }
    for a in &auds {
        match sup(&a.codec, false) {
            CodecSupport::Transcode => notes.push(format!("{} audio needs transcoding", a.codec)),
            CodecSupport::NotRecognized => {
                notes.push(format!("unrecognized audio codec {}", a.codec_id))
            }
            _ => {}
        }
    }

    let native = [CodecSupport::Native];
    let remuxable = [CodecSupport::Native, CodecSupport::RemuxOk];
    let path = match info.container {
        Container::Mp4 if v_all(&native) && a_all(&native) => PlaybackPath::Native,
        Container::Mkv | Container::Webm if v_all(&remuxable) && a_all(&remuxable) => {
            PlaybackPath::Remux
        }
        _ if !notes.is_empty() => PlaybackPath::Transcode,
        // Recognised codecs in a container no browser opens (AVI, or an
        // MP4 whose audio only survives a remux): a transcoder is the
        // honest answer until phase 2 widens the remux path.
        Container::Avi | Container::Mp4 => PlaybackPath::Transcode,
        _ => PlaybackPath::Unknown,
    };
    for n in notes {
        info.warn(n);
    }
    path
}

/// ISO 639 in whatever spelling the container used, as lowercase BCP 47.
/// "" / "und" / anything unusable becomes "und" - the wire always
/// carries a string, and the panel shows "unknown".
///
/// The 639-2/B and /T tables are [`crate::media::normalise_lang`]'s, not
/// a second copy: that is the one place in the tree that knows `ger` and
/// `deu` are the same language. What is added here is the region
/// subtag - `pt-br` stays `pt-br`, because a viewer choosing an audio
/// track cares that it is the Brazilian dub.
pub fn normalize_lang(raw: &str) -> String {
    let low = raw.trim().to_ascii_lowercase();
    let mut parts = low.split(['-', '_']);
    let primary = parts.next().unwrap_or("");
    let ok = |s: &str| s.chars().all(|c| c.is_ascii_lowercase());
    let head = match crate::media::normalise_lang(primary) {
        Some(two) => two,
        // 639-3 codes with no 2-letter form (fil, ceb) are valid BCP 47
        // and pass through; placeholders and junk do not.
        None if primary.len() == 3 && ok(primary) && !matches!(primary, "und" | "mis" | "zxx") => {
            primary.to_string()
        }
        None => return "und".to_string(),
    };
    let tail: Vec<&str> = parts
        .filter(|p| (2..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()))
        .collect();
    if tail.is_empty() {
        head
    } else {
        format!("{head}-{}", tail.join("-"))
    }
}

// ---------------------------------------------------------------------------
// The live reader
// ---------------------------------------------------------------------------

/// `Read + Seek` over a still-downloading output. A read whose first
/// byte has not landed yields `WouldBlock` instead of waiting - the
/// contrast with the playback reader (`serve::stream::LiveRangeReader`,
/// which sleeps up to five minutes) is deliberate: that is right for a
/// player holding a socket and wrong for a panel that polls.
pub struct LiveProbeReader {
    pub w: std::sync::Arc<crate::disk::FileWriter>,
    pub f: std::fs::File,
    pub pos: u64,
}

impl Read for LiveProbeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.w.size || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64)
            .min(self.w.size - self.pos)
            .min(256 * 1024);
        // covered_intervals, not covered: a read that starts on landed
        // bytes and runs into a hole returns the covered prefix, so
        // forward progress stays monotone.
        //
        // No decryptor arm any more: an encrypted store output holds
        // PLAINTEXT while it downloads (plaintext-once), so the probe
        // reads it exactly like any other file. Until TODO 27 phase 3
        // such a file was ciphertext until the finish pass, and this
        // reader carried a `StreamCrypt` plus the widened
        // `covered_bounds` the CBC chain needed.
        let avail = self
            .w
            .covered_intervals(self.pos, want)
            .iter()
            .find(|&&(s, _)| s == self.pos)
            .map(|&(s, e)| e - s)
            .unwrap_or(0);
        if avail == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "gap"));
        }
        let n = avail as usize;
        crate::disk::read_exact_at(&self.f, &mut buf[..n], self.pos)?;
        self.pos += avail;
        Ok(n)
    }
}

impl Seek for LiveProbeReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        // Position arithmetic only: seeking over a gap costs nothing,
        // which is what lets the MP4 walk reach a trailing moov across
        // an mdat that has not arrived.
        let base = match from {
            SeekFrom::Start(n) => {
                self.pos = n;
                return Ok(n);
            }
            SeekFrom::End(d) => (self.w.size as i128) + i128::from(d),
            SeekFrom::Current(d) => (self.pos as i128) + i128::from(d),
        };
        if base < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = base.min(u64::MAX as i128) as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(codec: &str) -> VideoTrack {
        VideoTrack {
            codec: codec.into(),
            codec_id: codec.into(),
            width: 1920,
            height: 1080,
            display_ar: None,
            fps: None,
            bit_depth: None,
            hdr: None,
            profile: None,
            level: None,
            bitrate: None,
            codec_rfc6381: None,
            enabled: true,
            default: true,
        }
    }

    fn a(codec: &str) -> AudioTrack {
        AudioTrack {
            codec: codec.into(),
            codec_id: codec.into(),
            lang: "und".into(),
            channels: 2,
            channel_layout: "stereo".into(),
            sample_rate: None,
            title: None,
            default: true,
            forced: false,
            bitrate: None,
            codec_rfc6381: None,
            enabled: true,
        }
    }

    fn path_of(c: Container, vs: &[VideoTrack], aus: &[AudioTrack]) -> PlaybackPath {
        let mut i = MediaInfo::new(c);
        i.video = vs.to_vec();
        i.audio = aus.to_vec();
        classify(&mut i)
    }

    #[test]
    fn the_playback_rule_covers_every_branch() {
        // h264+aac in MP4 is the one shape a browser plays as-is.
        assert_eq!(
            path_of(Container::Mp4, &[v("h264")], &[a("aac")]),
            PlaybackPath::Native
        );
        // The same codecs in Matroska need the container swapped.
        assert_eq!(
            path_of(Container::Mkv, &[v("h264")], &[a("aac")]),
            PlaybackPath::Remux
        );
        assert_eq!(
            path_of(Container::Webm, &[v("vp9")], &[a("opus")]),
            PlaybackPath::Remux
        );
        // One transcode-only track decides for the whole file.
        assert_eq!(
            path_of(Container::Mkv, &[v("hevc")], &[a("aac")]),
            PlaybackPath::Transcode
        );
        assert_eq!(
            path_of(Container::Mp4, &[v("h264")], &[a("eac3")]),
            PlaybackPath::Transcode
        );
        // Nothing parsed yet, or a video codec we do not know at all.
        assert_eq!(
            path_of(Container::Mp4, &[], &[a("aac")]),
            PlaybackPath::Unknown
        );
        assert_eq!(
            path_of(Container::Mkv, &[v("wmv3")], &[a("aac")]),
            PlaybackPath::Unknown
        );
        // AVI: recognised codecs, container no browser opens.
        assert_eq!(
            path_of(Container::Avi, &[v("mpeg4")], &[a("mp3")]),
            PlaybackPath::Transcode
        );
    }

    #[test]
    fn a_disabled_track_does_not_decide_playback() {
        let mut hevc = v("hevc");
        hevc.enabled = false;
        // A disabled HEVC track alongside a live h264 one must not
        // condemn the file to the transcode path - it is still listed
        // in the panel, it just does not vote.
        assert_eq!(
            path_of(Container::Mp4, &[v("h264"), hevc], &[a("aac")]),
            PlaybackPath::Native
        );
        let mut dts = a("dts");
        dts.enabled = false;
        assert_eq!(
            path_of(Container::Mp4, &[v("h264")], &[a("aac"), dts]),
            PlaybackPath::Native
        );
    }

    #[test]
    fn the_transcode_reason_names_the_track() {
        let mut i = MediaInfo::new(Container::Mkv);
        i.video = vec![v("hevc")];
        i.audio = vec![a("truehd")];
        i.playback = classify(&mut i);
        assert_eq!(i.playback, PlaybackPath::Transcode);
        assert!(
            i.warnings
                .iter()
                .any(|w| w == "hevc video needs transcoding")
        );
        assert!(
            i.warnings
                .iter()
                .any(|w| w == "truehd audio needs transcoding")
        );
    }

    #[test]
    fn language_tags_normalise_and_keep_their_region() {
        assert_eq!(normalize_lang("ger"), "de");
        assert_eq!(normalize_lang("fre"), "fr");
        assert_eq!(normalize_lang("eng"), "en");
        assert_eq!(normalize_lang("EN"), "en");
        // The region says which dub this is; a viewer picking a track
        // wants it, so unlike the naming path we keep it.
        assert_eq!(normalize_lang("pt-BR"), "pt-br");
        assert_eq!(normalize_lang("zh-Hans"), "zh-hans");
        // 639-3 with no two-letter form is still a valid BCP 47 tag.
        assert_eq!(normalize_lang("ceb"), "ceb");
        // Placeholders and junk are "nobody said".
        for raw in ["", "und", "zxx", "mis", "x@!", "123", "qqqq"] {
            assert_eq!(normalize_lang(raw), "und", "{raw}");
        }
    }

    #[test]
    fn a_warning_is_never_repeated() {
        let mut i = MediaInfo::new(Container::Mkv);
        i.incomplete("chapters not yet downloaded");
        i.incomplete("chapters not yet downloaded");
        i.warn("chapters not yet downloaded");
        assert_eq!(i.warnings.len(), 1);
        assert!(!i.complete);
    }

    #[test]
    fn the_sniffer_believes_bytes_not_names() {
        assert_eq!(
            sniff(&[0x1A, 0x45, 0xDF, 0xA3, 0, 0, 0, 0]),
            Some(Container::Mkv)
        );
        assert_eq!(sniff(b"RIFF\0\0\0\0AVI "), Some(Container::Avi));
        assert_eq!(sniff(b"\0\0\0\x20ftypisom"), Some(Container::Mp4));
        assert_eq!(sniff(b"\0\0\0\x08free\0\0\0\0"), Some(Container::Mp4));
        assert_eq!(sniff(b"RIFF\0\0\0\0WAVE"), None);
        assert_eq!(sniff(b"not a container"), None);
        assert_eq!(sniff(b""), None);
        // A plausible-looking size in front of an unknown fourcc is not
        // an MP4 - the box type has to be one we know.
        assert_eq!(sniff(b"\0\0\0\x20zzzz1234"), None);
    }

    #[test]
    fn display_aspect_reduces() {
        assert_eq!(ratio(1920, 1080).as_deref(), Some("16:9"));
        assert_eq!(ratio(720, 576).as_deref(), Some("5:4"));
        assert_eq!(ratio(0, 576), None);
    }
}
