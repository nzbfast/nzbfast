//! The write half: a fragmented MP4 a browser's MediaSource will accept.
//!
//! Two products. An **init segment** (`ftyp` + `moov`) describes the
//! tracks and carries no samples; a **fragment** (`moof` + `mdat`) is a
//! couple of seconds of payload with a table in front of it. That split
//! is the whole reason this feature can work on a half-downloaded file:
//! the init needs only the container's header, and every fragment after
//! it is independent, so playback can start as soon as the header plus
//! one group of pictures has landed.
//!
//! ## Byte-copy, not re-encode
//!
//! No sample payload is touched. Matroska stores AVC and HEVC NAL units
//! already length-prefixed - the same framing an `mdat` uses - AV1 as
//! the low-overhead OBU stream `av1C` describes, AAC as raw frames
//! without an ADTS header, and Opus as raw packets. So the remux is a
//! copy, and the byte-identity test can be an exact one.
//!
//! What IS rebuilt is the SampleEntry, because MP4 and Matroska spell
//! the same decoder configuration differently: Matroska keeps the raw
//! record in `CodecPrivate` and MP4 wraps it in a box, sometimes with
//! the field order reversed (`OpusHead` is little-endian and `dOps` is
//! big-endian, which is the single most common way to get this wrong).
//! From an MP4 source nothing is rebuilt at all - the entry is copied
//! through, which is exact and cannot drift.

use super::samples::{RemuxError, Sample, SelectedTrack, TrackConfig, TrackKind};

// ---------------------------------------------------------------------------
// Box writer
// ---------------------------------------------------------------------------

/// Big-endian box writer with size patching.
///
/// `open` reserves four bytes for the size and remembers where; `close`
/// fills them in. Sizes therefore telescope by construction rather than
/// by arithmetic done twice, which is the class of bug that produces a
/// file every parser rejects for a different reason.
#[derive(Default)]
pub struct BoxWriter {
    buf: Vec<u8>,
    stack: Vec<usize>,
}

impl BoxWriter {
    /// An empty writer with no box open.
    pub fn new() -> Self {
        BoxWriter::default()
    }

    /// Open a box, reserving four bytes for the size `close` patches in.
    /// Every `open` needs a matching `close`.
    pub fn open(&mut self, fourcc: &[u8; 4]) {
        self.stack.push(self.buf.len());
        self.buf.extend_from_slice(&[0, 0, 0, 0]);
        self.buf.extend_from_slice(fourcc);
    }

    /// A FullBox: a box whose first four payload bytes are a version and
    /// 24 flag bits.
    pub fn full(&mut self, fourcc: &[u8; 4], version: u8, flags: u32) {
        self.open(fourcc);
        self.u8(version);
        self.buf.extend_from_slice(&flags.to_be_bytes()[1..]);
    }

    /// Close the innermost open box and patch its size.
    ///
    /// # Panics
    ///
    /// Panics when no box is open, which is a mux bug rather than
    /// anything the input can cause.
    pub fn close(&mut self) {
        let at = self.stack.pop().expect("close without open");
        let len = (self.buf.len() - at) as u32;
        self.buf[at..at + 4].copy_from_slice(&len.to_be_bytes());
    }

    /// Append one byte.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    /// Append a big-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Append a big-endian `i16`.
    pub fn i16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Append a big-endian `u32`.
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Append a big-endian `i32`.
    pub fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Append a big-endian `u64`.
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Append raw bytes verbatim.
    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    /// Append `n` zero bytes.
    pub fn zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }
    /// Bytes written so far, open boxes included.
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    /// True when nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    /// Take the finished buffer.
    ///
    /// Every box must be closed first; a debug build asserts it, since
    /// an unclosed box means a zero size field and a file every parser
    /// rejects differently.
    pub fn take(self) -> Vec<u8> {
        debug_assert!(self.stack.is_empty(), "unclosed box");
        self.buf
    }
    /// Patch a big-endian `i32` already written at `at`. Used once, for
    /// the `trun` data offsets, which cannot be known until every trun
    /// in the fragment has been sized.
    fn patch_i32(&mut self, at: usize, v: i32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }
}

/// The identity 3x3 matrix every `tkhd` and `mvhd` carries, as 16.16
/// fixed point.
const IDENTITY: [u32; 9] = [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000];

/// The movie timescale. Fragments carry their own per-track timescales,
/// so this one only has to be a sane unit for a zero duration.
const MOVIE_TIMESCALE: u32 = 1000;

// ---------------------------------------------------------------------------
// Init segment
// ---------------------------------------------------------------------------

/// The `ftyp` + `moov` header an fMP4 client primes a SourceBuffer
/// with, plus what a caller needs to convert timings into it.
pub struct InitSegment {
    pub(crate) bytes: Vec<u8>,
    /// Output timescale per selected track, in the tracks' own order.
    pub track_timescales: Vec<u32>,
}

/// Build `ftyp` + `moov` for the selected tracks.
pub fn build_init(tracks: &[SelectedTrack]) -> Result<InitSegment, RemuxError> {
    if tracks.is_empty() {
        return Err(RemuxError::NoUsableTrack);
    }
    let mut w = BoxWriter::new();

    w.open(b"ftyp");
    w.bytes(b"iso5");
    w.u32(512);
    for b in [b"iso5", b"iso6", b"cmfc", b"mp41", b"dash"] {
        w.bytes(b);
    }
    w.close();

    w.open(b"moov");

    w.full(b"mvhd", 0, 0);
    w.u32(0); // creation time
    w.u32(0); // modification time
    w.u32(MOVIE_TIMESCALE);
    w.u32(0); // duration: unknown, this is a fragmented file
    w.u32(0x0001_0000); // rate 1.0
    w.u16(0x0100); // volume 1.0
    w.u16(0); // reserved
    w.zeros(8); // reserved
    for m in IDENTITY {
        w.u32(m);
    }
    w.zeros(24); // pre_defined
    w.u32(tracks.len() as u32 + 1); // next_track_ID
    w.close();

    for t in tracks {
        write_trak(&mut w, t)?;
    }

    w.open(b"mvex");
    for t in tracks {
        w.full(b"trex", 0, 0);
        w.u32(t.id);
        w.u32(1); // default_sample_description_index
        w.u32(0); // default_sample_duration
        w.u32(0); // default_sample_size
        // Non-sync by default; every sample states its own flags in trun.
        w.u32(0x0101_0000);
        w.close();
    }
    w.close(); // mvex

    w.close(); // moov

    Ok(InitSegment {
        bytes: w.take(),
        track_timescales: tracks.iter().map(|t| t.timescale.max(1)).collect(),
    })
}

fn write_trak(w: &mut BoxWriter, t: &SelectedTrack) -> Result<(), RemuxError> {
    let video = t.kind == TrackKind::Video;
    w.open(b"trak");

    // flags: enabled | in_movie | in_preview
    w.full(b"tkhd", 0, 0x0000_0007);
    w.u32(0); // creation
    w.u32(0); // modification
    w.u32(t.id);
    w.u32(0); // reserved
    w.u32(0); // duration
    w.zeros(8); // reserved
    w.u16(0); // layer
    w.u16(0); // alternate_group
    w.u16(if video { 0 } else { 0x0100 }); // volume
    w.u16(0); // reserved
    for m in IDENTITY {
        w.u32(m);
    }
    // 16.16 fixed display size; zero for audio.
    w.u32(if video { u32::from(t.width) << 16 } else { 0 });
    w.u32(if video { u32::from(t.height) << 16 } else { 0 });
    w.close();

    w.open(b"mdia");

    w.full(b"mdhd", 0, 0);
    w.u32(0);
    w.u32(0);
    w.u32(t.timescale.max(1));
    w.u32(0); // duration
    // ISO 639-2/T packed five bits per letter: "und".
    w.u16(0x55C4);
    w.u16(0); // pre_defined
    w.close();

    w.full(b"hdlr", 0, 0);
    w.u32(0); // pre_defined
    w.bytes(if video { b"vide" } else { b"soun" });
    w.zeros(12); // reserved
    w.bytes(b"nzbfast\0");
    w.close();

    w.open(b"minf");
    if video {
        w.full(b"vmhd", 0, 1);
        w.u16(0); // graphicsmode
        w.zeros(6); // opcolor
        w.close();
    } else {
        w.full(b"smhd", 0, 0);
        w.u16(0); // balance
        w.u16(0); // reserved
        w.close();
    }

    w.open(b"dinf");
    w.full(b"dref", 0, 0);
    w.u32(1); // entry_count
    // Self-contained: the data is in this file.
    w.full(b"url ", 0, 1);
    w.close();
    w.close();
    w.close(); // dinf

    w.open(b"stbl");
    w.full(b"stsd", 0, 0);
    w.u32(1); // entry_count
    write_sample_entry(w, t)?;
    w.close(); // stsd
    // The four empty tables a fragmented file still has to declare.
    for f in [b"stts", b"stsc", b"stco"] {
        w.full(f, 0, 0);
        w.u32(0);
        w.close();
    }
    w.full(b"stsz", 0, 0);
    w.u32(0); // sample_size
    w.u32(0); // sample_count
    w.close();
    w.close(); // stbl

    w.close(); // minf
    w.close(); // mdia
    w.close(); // trak
    Ok(())
}

/// The 78-byte fixed part of a VisualSampleEntry, up to the codec's
/// configuration child.
fn visual_prefix(w: &mut BoxWriter, width: u16, height: u16) {
    w.zeros(6); // reserved
    w.u16(1); // data_reference_index
    w.zeros(16); // pre_defined + reserved
    w.u16(width);
    w.u16(height);
    w.u32(0x0048_0000); // horizresolution 72 dpi
    w.u32(0x0048_0000); // vertresolution
    w.u32(0); // reserved
    w.u16(1); // frame_count
    w.zeros(32); // compressorname
    w.u16(24); // depth
    w.i16(-1); // pre_defined
}

/// The 28-byte fixed part of an AudioSampleEntry.
fn audio_prefix(w: &mut BoxWriter, channels: u16, rate: u32) {
    w.zeros(6); // reserved
    w.u16(1); // data_reference_index
    w.zeros(8); // reserved
    w.u16(channels.max(1));
    w.u16(16); // samplesize
    w.u16(0); // pre_defined
    w.u16(0); // reserved
    // 16.16 fixed. A rate above 65535 cannot be written here, which is
    // why Opus entries always declare 48000 and let dOps carry the truth.
    w.u32(u32::from(u16::try_from(rate.min(65535)).unwrap_or(48_000)) << 16);
}

fn write_sample_entry(w: &mut BoxWriter, t: &SelectedTrack) -> Result<(), RemuxError> {
    match &t.config {
        // An MP4 source: the entry is already exactly what we need.
        TrackConfig::Mp4Entry { entry, .. } => {
            w.bytes(entry);
            Ok(())
        }
        TrackConfig::Avc(rec) => {
            if rec.first() != Some(&1) {
                return Err(RemuxError::Unsupported(
                    "h264",
                    "the configuration record does not start with version 1".into(),
                ));
            }
            w.open(b"avc1");
            visual_prefix(w, t.width, t.height);
            w.open(b"avcC");
            w.bytes(rec);
            w.close();
            w.close();
            Ok(())
        }
        TrackConfig::Hevc(rec) => {
            // hvc1 rather than hev1: the parameter sets live in the
            // record, which is what Matroska's CodecPrivate always
            // carries, and Safari only accepts hvc1.
            w.open(b"hvc1");
            visual_prefix(w, t.width, t.height);
            w.open(b"hvcC");
            w.bytes(rec);
            w.close();
            w.close();
            Ok(())
        }
        TrackConfig::Av1(rec) => {
            if rec.first().is_none_or(|b| b & 0x80 == 0) {
                return Err(RemuxError::Unsupported(
                    "av1",
                    "the configuration record has no marker bit".into(),
                ));
            }
            w.open(b"av01");
            visual_prefix(w, t.width, t.height);
            w.open(b"av1C");
            w.bytes(rec);
            w.close();
            w.close();
            Ok(())
        }
        TrackConfig::Vp9(rec) => {
            w.open(b"vp09");
            visual_prefix(w, t.width, t.height);
            w.full(b"vpcC", 1, 0);
            if rec.len() >= 8 {
                w.bytes(rec);
            } else {
                // Matroska carries no VP9 configuration record, so this
                // is the conventional default: profile 0, level 3.0,
                // 8-bit 4:2:0. Browsers read the profile and bit depth
                // and ignore the rest.
                w.u8(0); // profile
                w.u8(10); // level 3.0
                w.u8(0x82); // 8-bit, 4:2:0 colocated, studio range
                w.u8(1); // colour_primaries BT.709
                w.u8(1); // transfer_characteristics
                w.u8(1); // matrix_coefficients
                w.u16(0); // codecInitializationDataSize
            }
            w.close();
            w.close();
            Ok(())
        }
        TrackConfig::Aac(asc) => {
            w.open(b"mp4a");
            audio_prefix(w, t.channels, t.sample_rate);
            w.full(b"esds", 0, 0);
            // An AudioSpecificConfig we were not given is synthesised
            // from the channel count and sample rate, which is what the
            // old SBR-era Matroska files that omit it need.
            let asc: Vec<u8> = if asc.is_empty() {
                synth_asc(t.sample_rate, t.channels)
            } else {
                asc.clone()
            };
            write_esds(w, t.id, &asc);
            w.close();
            w.close();
            Ok(())
        }
        TrackConfig::Opus(head) => {
            if head.len() < 19 {
                return Err(RemuxError::Unsupported(
                    "opus",
                    "the OpusHead record is too short".into(),
                ));
            }
            w.open(b"Opus");
            // Opus in MP4 always declares 48 kHz here; the real input
            // rate lives in dOps.
            audio_prefix(w, u16::from(head[9]).max(1), 48_000);
            w.full(b"dOps", 0, 0);
            // OpusHead is little-endian and dOps is big-endian. This
            // byte swap is the whole content of the box.
            w.u8(head[9]); // OutputChannelCount
            w.u16(u16::from_le_bytes([head[10], head[11]])); // PreSkip
            w.u32(u32::from_le_bytes([head[12], head[13], head[14], head[15]]));
            w.i16(i16::from_le_bytes([head[16], head[17]])); // OutputGain
            let family = head[18];
            w.u8(family);
            if family != 0 {
                // StreamCount, CoupledCount, ChannelMapping[N] follow
                // verbatim - they are single bytes, so no swap applies.
                w.bytes(&head[19..]);
            }
            w.close();
            w.close();
            Ok(())
        }
        TrackConfig::Flac(streaminfo) => {
            if streaminfo.len() < 34 {
                return Err(RemuxError::Unsupported(
                    "flac",
                    "the STREAMINFO block is too short".into(),
                ));
            }
            w.open(b"fLaC");
            audio_prefix(w, t.channels, t.sample_rate);
            w.full(b"dfLa", 0, 0);
            // One metadata block, last-block flag set, type 0
            // (STREAMINFO), then its 24-bit length and body.
            w.u8(0x80);
            let n = u32::try_from(streaminfo.len().min(34)).unwrap_or(34);
            w.bytes(&n.to_be_bytes()[1..]);
            w.bytes(&streaminfo[..34]);
            w.close();
            w.close();
            Ok(())
        }
    }
}

/// The `esds` descriptor chain around an AudioSpecificConfig.
///
/// Each descriptor is a tag byte, a length, and a body. The lengths here
/// are always below 128, so they are single bytes - the multi-byte form
/// exists in the standard but nothing this function can produce needs it.
fn write_esds(w: &mut BoxWriter, track_id: u32, asc: &[u8]) {
    let asc = &asc[..asc.len().min(64)];
    let dsi_len = asc.len() as u8;
    // DecoderConfigDescriptor body: 13 fixed bytes + the DSI descriptor.
    let dcd_len = 13 + 2 + dsi_len;
    // ES_Descriptor body: 3 fixed bytes + DCD + SLConfig.
    let es_len = 3 + 2 + dcd_len + 2 + 1;

    w.u8(0x03); // ES_DescrTag
    w.u8(es_len);
    w.u16(u16::try_from(track_id).unwrap_or(1));
    w.u8(0); // stream priority, no dependencies, no URL

    w.u8(0x04); // DecoderConfigDescrTag
    w.u8(dcd_len);
    w.u8(0x40); // objectTypeIndication: MPEG-4 audio
    w.u8(0x15); // streamType 5 (audio), upStream 0, reserved 1
    w.bytes(&[0, 0, 0]); // bufferSizeDB
    w.u32(0); // maxBitrate
    w.u32(0); // avgBitrate

    w.u8(0x05); // DecSpecificInfoTag
    w.u8(dsi_len);
    w.bytes(asc);

    w.u8(0x06); // SLConfigDescrTag
    w.u8(1);
    w.u8(0x02); // predefined: MP4 timestamps
}

/// A two-byte AudioSpecificConfig for AAC-LC, for the sources that omit
/// one: five bits of object type, four of sample-rate index, four of
/// channel configuration, then padding.
fn synth_asc(rate: u32, channels: u16) -> Vec<u8> {
    const RATES: [u32; 13] = [
        96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025,
        8_000, 7_350,
    ];
    let idx = RATES.iter().position(|r| *r == rate).unwrap_or(3) as u16;
    let ch = channels.clamp(1, 7);
    let bits: u16 = (2 << 11) | (idx << 7) | (ch << 3);
    bits.to_be_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Fragments
// ---------------------------------------------------------------------------

/// Writes `moof` + `mdat` pairs and keeps the per-track tick cursors that
/// make `tfdt` absolute.
pub struct FragmentWriter {
    seq: u32,
    /// Track ids in output order, so a fragment's trafs are ordered.
    order: Vec<u32>,
    /// Warnings raised while muxing, for the panel.
    pub warnings: Vec<String>,
}

impl FragmentWriter {
    /// A writer for `tracks`, in the order their trafs will appear.
    /// The sequence number starts at 0 and advances per fragment.
    pub fn new(tracks: &[SelectedTrack]) -> Self {
        FragmentWriter {
            seq: 0,
            order: tracks.iter().map(|t| t.id).collect(),
            warnings: Vec::new(),
        }
    }

    /// How many fragments have been written so far, which is also the
    /// next fragment's `mfhd` sequence number.
    pub fn sequence(&self) -> u32 {
        self.seq
    }

    /// One fragment from decode-ordered samples whose payloads are
    /// already in hand.
    ///
    /// The two-pass shape is forced by the format: `trun.data_offset` is
    /// measured from the first byte of `moof`, so it cannot be written
    /// until every `traf` has been sized. The offsets are therefore
    /// emitted as placeholders, the `moof` is closed, and the two (or
    /// more) `i32`s are patched.
    pub fn fragment(&mut self, samples: &[(Sample, Vec<u8>)]) -> Vec<u8> {
        self.seq += 1;
        let mut w = BoxWriter::new();
        let moof_at = w.len();

        // Per track, in output order: the samples belonging to it.
        let groups: Vec<(u32, Vec<usize>)> = self
            .order
            .iter()
            .map(|id| {
                let idx = samples
                    .iter()
                    .enumerate()
                    .filter(|(_, (s, _))| s.track == *id)
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                (*id, idx)
            })
            .filter(|(_, idx)| !idx.is_empty())
            .collect();

        w.open(b"moof");
        w.full(b"mfhd", 0, 0);
        w.u32(self.seq);
        w.close();

        let mut patch_at: Vec<usize> = Vec::with_capacity(groups.len());
        for (id, idx) in &groups {
            w.open(b"traf");
            // default-base-is-moof: every data_offset in this traf is
            // measured from the start of the enclosing moof, which is
            // what makes a fragment self-contained.
            w.full(b"tfhd", 0, 0x02_0000);
            w.u32(*id);
            w.close();

            w.full(b"tfdt", 1, 0);
            w.u64(samples[idx[0]].0.dts);
            w.close();

            // data-offset | sample-duration | sample-size | sample-flags
            // | sample-composition-time-offset, version 1 so the
            // composition offsets are signed.
            w.full(b"trun", 1, 0x0000_0F01);
            w.u32(idx.len() as u32);
            patch_at.push(w.len());
            w.i32(0); // data_offset placeholder
            for (n, i) in idx.iter().enumerate() {
                let (s, _) = &samples[*i];
                // A sample with no stated duration borrows the next
                // one's decode time, and the last sample of a fragment
                // borrows its predecessor's - standard practice, and
                // invisible to a player that has the next fragment.
                let dur = s.dur.unwrap_or_else(|| {
                    idx.get(n + 1)
                        .map(|j| samples[*j].0.dts.saturating_sub(s.dts))
                        .and_then(|d| u32::try_from(d).ok())
                        .or_else(|| {
                            n.checked_sub(1)
                                .and_then(|p| idx.get(p))
                                .map(|j| s.dts.saturating_sub(samples[*j].0.dts))
                                .and_then(|d| u32::try_from(d).ok())
                        })
                        .unwrap_or(0)
                });
                w.u32(dur);
                w.u32(s.size);
                w.u32(sample_flags(s.keyframe));
                w.i32(s.cts_offset);
            }
            w.close(); // trun
            w.close(); // traf
        }
        w.close(); // moof
        let moof_len = w.len() - moof_at;

        // mdat payloads, each track's samples contiguous and in the same
        // order the trun described them.
        let mut running = moof_len + 8; // past moof and mdat's own header
        for (k, (_, idx)) in groups.iter().enumerate() {
            w.patch_i32(patch_at[k], i32::try_from(running).unwrap_or(i32::MAX));
            running += idx.iter().map(|i| samples[*i].1.len()).sum::<usize>();
        }
        w.open(b"mdat");
        for (_, idx) in &groups {
            for i in idx {
                w.bytes(&samples[*i].1);
            }
        }
        w.close();
        w.take()
    }
}

/// `sample_flags` for a `trun` entry.
///
/// A sync sample declares "nothing depends on me being a reference" and
/// clears the non-sync bit; everything else declares the opposite. This
/// pair is what lets a browser seek to a fragment boundary at all.
fn sample_flags(keyframe: bool) -> u32 {
    if keyframe {
        // sample_depends_on = 2 (does not depend on others)
        0x0200_0000
    } else {
        // sample_depends_on = 1, sample_is_non_sync_sample = 1
        0x0101_0000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avc_track() -> SelectedTrack {
        SelectedTrack {
            id: 1,
            kind: TrackKind::Video,
            src_id: 1,
            timescale: 1000,
            // Minimal AVCDecoderConfigurationRecord: version 1, baseline
            // 3.0, four-byte NAL lengths, no parameter sets.
            config: TrackConfig::Avc(vec![1, 0x42, 0x00, 0x1E, 0xFF, 0xE0, 0x00]),
            width: 1920,
            height: 1080,
            channels: 0,
            sample_rate: 0,
            default_dur: Some(40),
            codec: "h264".into(),
        }
    }

    fn aac_track() -> SelectedTrack {
        SelectedTrack {
            id: 2,
            kind: TrackKind::Audio,
            src_id: 2,
            timescale: 48_000,
            config: TrackConfig::Aac(vec![0x11, 0x90]),
            width: 0,
            height: 0,
            channels: 2,
            sample_rate: 48_000,
            default_dur: Some(1024),
            codec: "aac".into(),
        }
    }

    /// Where a container box's children begin, relative to the box.
    ///
    /// Most are plain containers whose children start right after the
    /// eight-byte header. Three are not, and each one is a place a muxer
    /// can silently produce an init segment that no browser will parse:
    /// `stsd` puts a version, flags and an entry count in front of its
    /// entries, and the sample entries themselves carry a fixed visual
    /// or audio record before the configuration box a decoder needs.
    fn child_offset(fourcc: &[u8]) -> Option<usize> {
        match fourcc {
            b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"dinf" | b"mvex" | b"moof"
            | b"traf" => Some(8),
            b"stsd" => Some(16),
            b"avc1" | b"hvc1" | b"av01" | b"vp09" => Some(8 + 78),
            b"mp4a" | b"Opus" | b"fLaC" => Some(8 + 28),
            _ => None,
        }
    }

    /// Walk a box tree and assert every size lands exactly on its
    /// parent's end. A file whose sizes do not telescope is rejected by
    /// every demuxer, each with a different message.
    fn check_telescopes(b: &[u8], mut at: usize, end: usize, depth: usize) -> Vec<String> {
        let mut seen = Vec::new();
        assert!(depth < 12, "box nesting is out of control");
        while at + 8 <= end {
            let size = u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize;
            let fourcc = &b[at + 4..at + 8];
            assert!(size >= 8, "box {fourcc:?} declares size {size}");
            assert!(
                at + size <= end,
                "box {:?} at {at} size {size} overruns its parent end {end}",
                String::from_utf8_lossy(fourcc)
            );
            seen.push(String::from_utf8_lossy(fourcc).to_string());
            if let Some(skip) = child_offset(fourcc) {
                seen.extend(check_telescopes(b, at + skip, at + size, depth + 1));
            }
            at += size;
        }
        assert_eq!(at, end, "boxes do not fill their parent exactly");
        seen
    }

    #[test]
    fn init_boxes_telescope_and_carry_what_mse_needs() {
        let tracks = vec![avc_track(), aac_track()];
        let init = build_init(&tracks).unwrap();
        let seen = check_telescopes(&init.bytes, 0, init.bytes.len(), 0);
        for want in [
            "ftyp", "moov", "mvhd", "trak", "mdhd", "stsd", "mvex", "trex",
        ] {
            assert!(seen.contains(&want.to_string()), "init has no {want}");
        }
        assert_eq!(seen.iter().filter(|f| *f == "trex").count(), 2);
        assert_eq!(seen.iter().filter(|f| *f == "trak").count(), 2);
        assert!(seen.contains(&"avcC".to_string()));
        assert!(seen.contains(&"esds".to_string()));
        assert_eq!(init.track_timescales, vec![1000, 48_000]);
    }

    /// The single most common way to get Opus wrong: OpusHead is
    /// little-endian and dOps is big-endian.
    #[test]
    fn dops_is_the_big_endian_twin_of_opushead() {
        let mut head = b"OpusHead".to_vec();
        head.push(1); // version
        head.push(2); // channels
        head.extend_from_slice(&312u16.to_le_bytes()); // pre-skip
        head.extend_from_slice(&48_000u32.to_le_bytes());
        head.extend_from_slice(&(-256i16).to_le_bytes()); // output gain
        head.push(0); // mapping family
        let t = SelectedTrack {
            id: 2,
            kind: TrackKind::Audio,
            src_id: 2,
            timescale: 48_000,
            config: TrackConfig::Opus(head),
            width: 0,
            height: 0,
            channels: 2,
            sample_rate: 48_000,
            default_dur: None,
            codec: "opus".into(),
        };
        let init = build_init(&[t]).unwrap();
        let at = find_box(&init.bytes, b"dOps").expect("no dOps");
        let body = &init.bytes[at + 8..];
        assert_eq!(body[0], 0, "dOps version");
        assert_eq!(body[4], 2, "OutputChannelCount");
        assert_eq!(u16::from_be_bytes([body[5], body[6]]), 312, "PreSkip");
        assert_eq!(
            u32::from_be_bytes([body[7], body[8], body[9], body[10]]),
            48_000
        );
        assert_eq!(i16::from_be_bytes([body[11], body[12]]), -256);
        assert_eq!(body[13], 0, "ChannelMappingFamily");
    }

    /// esds descriptor lengths have to agree with what follows them, or
    /// the decoder configuration is silently unreadable.
    #[test]
    fn esds_descriptor_lengths_are_consistent() {
        let init = build_init(&[aac_track()]).unwrap();
        let at = find_box(&init.bytes, b"esds").expect("no esds");
        let b = &init.bytes[at..];
        let size = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let body = &b[12..size]; // past box header + version/flags
        assert_eq!(body[0], 0x03, "ES_DescrTag");
        let es_len = body[1] as usize;
        assert_eq!(es_len + 2, body.len(), "ES_Descriptor length");
        assert_eq!(body[5], 0x04, "DecoderConfigDescrTag");
        let dcd_len = body[6] as usize;
        assert_eq!(body[7], 0x40, "objectTypeIndication");
        let dsi_at = 7 + 13;
        assert_eq!(body[dsi_at], 0x05, "DecSpecificInfoTag");
        let dsi_len = body[dsi_at + 1] as usize;
        assert_eq!(dsi_len, 2);
        assert_eq!(&body[dsi_at + 2..dsi_at + 4], &[0x11, 0x90]);
        // The DCD length must cover its own fixed part plus the DSI.
        assert_eq!(dcd_len, 13 + 2 + dsi_len);
        let sl_at = dsi_at + 2 + dsi_len;
        assert_eq!(body[sl_at], 0x06, "SLConfigDescrTag");
    }

    fn find_box(b: &[u8], fourcc: &[u8; 4]) -> Option<usize> {
        b.windows(4).position(|w| w == fourcc).map(|i| i - 4)
    }

    #[test]
    fn a_fragment_offset_lands_on_its_own_payload() {
        let tracks = vec![avc_track(), aac_track()];
        let mut fw = FragmentWriter::new(&tracks);
        let s = |track: u32, dts: u64, size: u32, key: bool| Sample {
            track,
            dts,
            cts_offset: 0,
            dur: Some(40),
            keyframe: key,
            src_off: 0,
            size,
            dts_ns: dts * 1_000_000,
        };
        let samples = vec![
            (s(1, 0, 4, true), vec![0xAA; 4]),
            (s(1, 40, 3, false), vec![0xBB; 3]),
            (s(2, 0, 5, true), vec![0xCC; 5]),
        ];
        let frag = fw.fragment(&samples);
        check_telescopes(&frag, 0, frag.len(), 0);
        let mdat = find_box(&frag, b"mdat").expect("no mdat");
        // Payloads are grouped by track, in output order.
        assert_eq!(
            &frag[mdat + 8..mdat + 8 + 7],
            &[0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB]
        );
        assert_eq!(&frag[mdat + 15..mdat + 20], &[0xCC; 5]);

        // Both data offsets, read as the format defines them (from the
        // first byte of moof), must point at the right payload.
        let mut offs = Vec::new();
        let mut at = 0usize;
        while let Some(i) = frag[at..].windows(4).position(|w| w == b"trun") {
            let t = at + i + 4;
            // version/flags, sample_count, data_offset
            offs.push(
                i32::from_be_bytes([frag[t + 8], frag[t + 9], frag[t + 10], frag[t + 11]]) as usize,
            );
            at = t + 4;
        }
        assert_eq!(offs.len(), 2);
        assert_eq!(frag[offs[0]], 0xAA);
        assert_eq!(frag[offs[1]], 0xCC);
        assert_eq!(fw.sequence(), 1);
    }

    #[test]
    fn mfhd_sequence_numbers_increase() {
        let tracks = vec![avc_track()];
        let mut fw = FragmentWriter::new(&tracks);
        let mk = |dts: u64| {
            vec![(
                Sample {
                    track: 1,
                    dts,
                    cts_offset: 0,
                    dur: Some(40),
                    keyframe: true,
                    src_off: 0,
                    size: 2,
                    dts_ns: dts * 1_000_000,
                },
                vec![1, 2],
            )]
        };
        let a = fw.fragment(&mk(0));
        let b = fw.fragment(&mk(40));
        let seq = |f: &[u8]| {
            let at = find_box(f, b"mfhd").unwrap();
            u32::from_be_bytes([f[at + 12], f[at + 13], f[at + 14], f[at + 15]])
        };
        assert_eq!(seq(&a), 1);
        assert_eq!(seq(&b), 2);
        // tfdt carries the absolute decode time, not a per-fragment one.
        let tfdt = |f: &[u8]| {
            let at = find_box(f, b"tfdt").unwrap();
            u64::from_be_bytes(f[at + 12..at + 20].try_into().unwrap())
        };
        assert_eq!(tfdt(&a), 0);
        assert_eq!(tfdt(&b), 40);
    }

    #[test]
    fn a_synthesised_asc_reads_back_as_aac_lc() {
        let asc = synth_asc(48_000, 2);
        assert_eq!(asc.len(), 2);
        let bits = u16::from_be_bytes([asc[0], asc[1]]);
        assert_eq!(bits >> 11, 2, "AAC-LC object type");
        assert_eq!((bits >> 7) & 0xF, 3, "48 kHz index");
        assert_eq!((bits >> 3) & 0xF, 2, "stereo");
        // An unknown rate falls back to 48 kHz rather than to index 0,
        // which would claim 96 kHz and play everything at half speed.
        assert_eq!(
            (u16::from_be_bytes(synth_asc(12_345, 1).try_into().unwrap()) >> 7) & 0xF,
            3
        );
    }

    #[test]
    fn a_sync_sample_and_a_delta_sample_have_the_flags_seeking_needs() {
        assert_eq!(sample_flags(true), 0x0200_0000);
        assert_eq!(sample_flags(false), 0x0101_0000);
    }
}
