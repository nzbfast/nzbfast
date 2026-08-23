//! The live remux session: samples in, fragments out, one file at a time.
//!
//! A session is a cursor over a file that is probably still downloading.
//! It hands back an init segment as soon as the container's header is
//! readable, then a fragment every couple of seconds of content, and it
//! says "not yet" - rather than lying, stalling or truncating - whenever
//! the next thing it needs has not landed.
//!
//! ## The property that matters
//!
//! **The output does not depend on the arrival order of the input.** A
//! file that is fully downloaded before the first `pull`, and the same
//! file downloaded in shuffled pieces while the session runs, produce
//! byte-identical output. That falls out of one rule, which every branch
//! here obeys: a missing byte NEVER changes what is emitted, only when.
//! Nothing is flushed early because a wait expired, no fragment is cut
//! short because the next sample was cold, and a sample whose payload is
//! not covered is held intact until it is. `Emit::NotYet` is the only
//! thing a gap can cause.
//!
//! Get that wrong and the failure is not a crash - it is a file that
//! plays, and is subtly different every time, which is exactly the class
//! of bug nobody finds by watching it work once.

use super::fmp4::{FragmentWriter, InitSegment, build_init};
use super::samples::{
    Cues, MkvLayout, MkvSampleIter, Mp4Layout, Mp4SampleIter, Mp4Track, RemuxError, Sample,
    SampleIter, SelectedTrack, TrackKind, mkv_layout, mp4_layout, mp4_sync_before, read_cues,
    select_mkv, select_mp4,
};
use super::source::Source;
use super::{Container, sniff};
use std::time::Duration;

/// Target content per fragment. Two seconds is the figure every adaptive
/// player and every MSE implementation is tuned around.
const FRAG_TARGET_NS: u64 = 2_000_000_000;
/// A group of pictures longer than this gets its own oversized fragment
/// rather than being cut mid-GOP - a fragment that does not start on a
/// keyframe is one a browser cannot seek to.
const FRAG_MAX_NS: u64 = 6_000_000_000;
/// Hard ceiling on one fragment's payload, so a pathological file cannot
/// make the session hold an unbounded buffer.
const FRAG_MAX_BYTES: usize = 64 << 20;

/// Every sample's presentation time, in nanoseconds, from `stts`.
///
/// Bounded: `stts` is a run-length table read off the wire, and while
/// the layout walk already clips the RUN COUNT to the box that holds it,
/// the counts inside those runs are still the file's own numbers. A
/// ceiling here keeps a hostile table from turning a playlist request
/// into an unbounded loop. Ten million samples is over four days of
/// 30 fps video, so nothing real is truncated.
fn mp4_sample_times_ns(t: &Mp4Track) -> Vec<u64> {
    const MAX_SAMPLES: usize = 10_000_000;
    let ts = u64::from(t.timescale.max(1));
    let mut out = Vec::new();
    let mut dts = 0u64;
    for &(count, dur) in &t.stts {
        for _ in 0..count {
            if out.len() >= MAX_SAMPLES {
                return out;
            }
            out.push(dts.saturating_mul(1_000_000_000) / ts);
            dts = dts.saturating_add(u64::from(dur));
        }
    }
    out
}

/// Where the fragment boundaries WILL fall, computed from keyframe times
/// alone - the playlist an HLS client needs, without remuxing the file to
/// find out.
///
/// This exists because `fragment_index` cannot answer the question: it is
/// filled as fragments are emitted, so it is empty when a playlist is
/// asked for and complete only after the whole file has been walked.
/// Building a playlist from it would mean remuxing a file in order to
/// describe it.
///
/// It can be computed instead because [`RemuxSession::is_boundary`]
/// depends on nothing else: a fragment opens on a video keyframe once
/// `FRAG_TARGET_NS` has elapsed since the last one. Same rule, same
/// inputs, same answer - and `plan_matches_the_fragments_actually_emitted`
/// pins the two together so an edit to one that forgets the other fails
/// loudly rather than producing a playlist that lies by a fraction of a
/// second per segment.
///
/// `keyframes_ns` must be sorted presentation times of VIDEO keyframes
/// (Matroska Cues, or ISO-BMFF `stss` resolved through `stts`).
/// `end_ns` closes the last segment. An empty or single-keyframe input
/// yields one segment covering the file, which is what an audio-only or
/// all-intra file should get.
///
/// The one case it cannot predict is the `FRAG_MAX_BYTES` cut, which the
/// session's own comment calls the only cut that can land mid-GOP and
/// which a real file never reaches. A segment is therefore defined as
/// every fragment from one planned start to the next, so a byte-capped
/// split stays invisible to the client.
pub fn plan_fragments(keyframes_ns: &[u64], end_ns: u64) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let Some(&first) = keyframes_ns.first() else {
        return if end_ns > 0 {
            vec![(0, end_ns)]
        } else {
            Vec::new()
        };
    };
    let mut start = first;
    for &k in keyframes_ns.iter().skip(1) {
        // The session's rule, verbatim: only a keyframe may open a
        // fragment, and only once the target has elapsed.
        if k.saturating_sub(start) >= FRAG_TARGET_NS {
            out.push((start, k - start));
            start = k;
        }
    }
    if end_ns > start {
        out.push((start, end_ns - start));
    } else if out.is_empty() {
        // A file whose duration we do not know still has one segment.
        out.push((start, 0));
    }
    out
}

/// What a `pull` produced.
pub enum Emit {
    /// `ftyp` + `moov`. Always the first thing a session yields.
    Init(Vec<u8>),
    /// `moof` + `mdat`.
    Fragment(Vec<u8>),
    /// The bytes at `need_off` have not arrived. Retryable, always: the
    /// session's state is exactly what it was before the call.
    NotYet { need_off: u64 },
    /// The walk reached the end of the file.
    Eos,
}

/// One entry in the fragment index: enough to describe a fragment in a
/// playlist without re-muxing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragRef {
    pub(crate) n: u32,
    pub(crate) t_ns: u64,
    pub(crate) dur_ns: u64,
    /// The span of the SOURCE file the fragment was built from, so a
    /// caller can ask whether it is downloaded before advertising it.
    pub src_span: (u64, u64),
}

enum Layout {
    Mkv(Box<MkvLayout>),
    Mp4(Box<Mp4Layout>),
}

pub struct RemuxSession {
    layout: Layout,
    iter: Box<dyn SampleIter>,
    frag: FragmentWriter,
    init: InitSegment,
    tracks: Vec<SelectedTrack>,
    sent_init: bool,
    /// The open fragment.
    pending: Vec<(Sample, Vec<u8>)>,
    pending_bytes: usize,
    frag_start_ns: u64,
    /// A sample whose header was read but whose payload is not covered,
    /// or which begins the next fragment. Held so a retry never re-reads
    /// and never double-counts.
    held: Option<Sample>,
    eos: bool,
    /// Set once the last pending samples have been flushed.
    flushed: bool,
    /// Cached Matroska cue points, parsed at most once per session.
    cues: Option<Cues>,
    pub fragment_index: Vec<FragRef>,
    pub warnings: Vec<String>,
}

impl RemuxSession {
    /// Open a session over `src`. `want_audio` indexes the container's
    /// audio tracks; `None` takes the default one.
    ///
    /// Reads only the container header, so this succeeds on a download
    /// that has barely started - and fails with a pending error, not a
    /// permanent one, when even that much is missing.
    pub fn new(
        src: &dyn Source,
        want_audio: Option<usize>,
        wait: Duration,
    ) -> Result<Self, RemuxError> {
        let mut magic = [0u8; 12];
        let head = src.size().min(12) as usize;
        src.read_at_wait(0, &mut magic[..head], wait)?;
        let container = sniff(&magic[..head]);
        let (layout, tracks, iter): (Layout, Vec<SelectedTrack>, Box<dyn SampleIter>) =
            match container {
                Some(Container::Mkv) | Some(Container::Webm) => {
                    let lay = mkv_layout(src, wait)?;
                    let tracks = select_mkv(&lay, want_audio)?;
                    let it = MkvSampleIter::new(&lay, &tracks)?;
                    (Layout::Mkv(Box::new(lay)), tracks, Box::new(it))
                }
                Some(Container::Mp4) => {
                    let lay = mp4_layout(src, wait)?;
                    let tracks = select_mp4(&lay, want_audio)?;
                    let it = Mp4SampleIter::new(&lay, &tracks)?;
                    (Layout::Mp4(Box::new(lay)), tracks, Box::new(it))
                }
                _ => {
                    return Err(RemuxError::Unsupported(
                        "container",
                        "only Matroska and MP4 can be remuxed".into(),
                    ));
                }
            };
        let init = build_init(&tracks)?;
        let frag = FragmentWriter::new(&tracks);
        Ok(RemuxSession {
            layout,
            iter,
            frag,
            init,
            tracks,
            sent_init: false,
            pending: Vec::new(),
            pending_bytes: 0,
            frag_start_ns: 0,
            held: None,
            eos: false,
            flushed: false,
            cues: None,
            fragment_index: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// The init segment on its own, for a client priming a SourceBuffer.
    pub fn init_bytes(&self) -> &[u8] {
        &self.init.bytes
    }

    pub fn tracks(&self) -> &[SelectedTrack] {
        &self.tracks
    }

    /// The file's duration when the container stated one.
    pub fn duration_ms(&self) -> Option<u64> {
        match &self.layout {
            Layout::Mkv(l) => l.duration_ns.map(|ns| ns / 1_000_000),
            Layout::Mp4(l) => l.duration_ns().map(|ns| ns / 1_000_000),
        }
    }

    /// True when this file carries a keyframe index, so an arbitrary
    /// seek can be answered.
    pub fn seekable(&self) -> bool {
        match &self.layout {
            Layout::Mkv(l) => l.cues_off.is_some(),
            Layout::Mp4(_) => true,
        }
    }

    /// The segments an HLS playlist should advertise, as
    /// `(start_ns, dur_ns)` - read from the container's own keyframe
    /// index, without walking a sample.
    ///
    /// This is [`plan_fragments`] fed the real index: Matroska Cues, or
    /// ISO-BMFF `stss` resolved through `stts`. A file with no index
    /// answers `NoIndex` rather than guessing, because a playlist whose
    /// segment starts are invented is worse than no playlist - the
    /// client seeks to a time the segment does not begin at and the
    /// picture stutters instead of failing.
    pub fn segments(
        &self,
        src: &dyn Source,
        wait: Duration,
    ) -> Result<Vec<(u64, u64)>, RemuxError> {
        let keys = self.keyframes_ns(src, wait)?;
        // Where the last segment ends. The declared duration is the
        // obvious answer and cannot be the only one: a container is free
        // to state a duration shorter than the samples it carries (the
        // mkv fixture declares 1.92 s and holds 11.5 s), and believing
        // it drops every segment past the claim - the client simply
        // cannot play the end of the file.
        //
        // So take whichever is longer: what the file CLAIMS, or what its
        // own index SHOWS, the latter extended by one keyframe gap so
        // the final keyframe gets a segment of about the same length as
        // its neighbours. That last term is an estimate, and it is the
        // only one here - it moves the end of the last segment, never
        // the start of any segment, which is the number a client seeks
        // against.
        let last = keys.last().copied().unwrap_or(0);
        let gap = match keys.len() {
            0 | 1 => 0,
            n => last.saturating_sub(keys[n - 2]),
        };
        let end = self
            .duration_ms()
            .map(|ms| ms.saturating_mul(1_000_000))
            .unwrap_or(0)
            .max(last.saturating_add(gap));
        Ok(plan_fragments(&keys, end))
    }

    /// Presentation times of the video track's keyframes.
    fn keyframes_ns(&self, src: &dyn Source, wait: Duration) -> Result<Vec<u64>, RemuxError> {
        let Some(vt) = self.tracks.iter().find(|t| t.kind == TrackKind::Video) else {
            // Audio-only: no keyframe index, and none is needed - the
            // planner cuts such a file on the clock.
            return Ok(Vec::new());
        };
        match &self.layout {
            Layout::Mkv(l) => {
                let cues = read_cues(src, l, vt.src_id, wait)?;
                Ok(cues
                    .points
                    .iter()
                    .map(|(ticks, _)| ticks.saturating_mul(l.timestamp_scale_ns))
                    .collect())
            }
            Layout::Mp4(l) => {
                let t = l
                    .tracks
                    .iter()
                    .find(|t| t.track_id == vt.src_id)
                    .ok_or(RemuxError::NoIndex)?;
                let Some(stss) = &t.stss else {
                    // No sync table means every sample is a sync sample.
                    // Every frame being a cut point is not a useful
                    // index, and the planner would cut on the first one
                    // past the target anyway - so hand it the sample
                    // times and let it choose.
                    return Ok(mp4_sample_times_ns(t));
                };
                let times = mp4_sample_times_ns(t);
                Ok(stss
                    .iter()
                    // stss numbers samples from ONE; a malformed zero
                    // saturates to the first sample rather than wrapping
                    // (see mp4_sync_before, same table, same trap).
                    .filter_map(|n| times.get(u64::from(*n).saturating_sub(1) as usize).copied())
                    .collect())
            }
        }
    }

    fn video_id(&self) -> Option<u32> {
        self.tracks
            .iter()
            .find(|t| t.kind == TrackKind::Video)
            .map(|t| t.id)
    }

    fn warn(&mut self, m: impl Into<String>) {
        let m = m.into();
        if !self.warnings.contains(&m) {
            self.warnings.push(m);
        }
    }

    /// Would `s` open a new fragment?
    ///
    /// Only a video keyframe may, because a fragment a browser cannot
    /// seek to is worse than one that runs long. An audio-only file has
    /// no such constraint and cuts on the clock.
    fn is_boundary(&self, s: &Sample) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        let elapsed = s.dts_ns.saturating_sub(self.frag_start_ns);
        match self.video_id() {
            Some(v) => s.track == v && s.keyframe && elapsed >= FRAG_TARGET_NS,
            None => elapsed >= FRAG_TARGET_NS,
        }
    }

    /// Close the open fragment and record it in the index.
    fn emit_fragment(&mut self) -> Emit {
        let n = self.frag.sequence();
        let t_ns = self.pending.first().map_or(0, |(s, _)| s.dts_ns);
        let last_ns = self.pending.last().map_or(t_ns, |(s, _)| s.dts_ns);
        let lo = self
            .pending
            .iter()
            .map(|(s, _)| s.src_off)
            .min()
            .unwrap_or(0);
        let hi = self
            .pending
            .iter()
            .map(|(s, _)| s.src_off + u64::from(s.size))
            .max()
            .unwrap_or(0);
        let bytes = self.frag.fragment(&self.pending);
        self.fragment_index.push(FragRef {
            n: n + 1,
            t_ns,
            dur_ns: last_ns.saturating_sub(t_ns),
            src_span: (lo, hi),
        });
        self.pending.clear();
        self.pending_bytes = 0;
        for w in std::mem::take(&mut self.frag.warnings) {
            self.warn(w);
        }
        Emit::Fragment(bytes)
    }

    /// Pump the session. See [`Emit`]; nothing here blocks longer than
    /// `wait` on any single read.
    pub fn pull(&mut self, src: &dyn Source, wait: Duration) -> Result<Emit, RemuxError> {
        if !self.sent_init {
            self.sent_init = true;
            return Ok(Emit::Init(self.init.bytes.clone()));
        }
        loop {
            // The end of the file: flush what is open, then stop.
            if self.eos {
                if !self.pending.is_empty() {
                    let e = self.emit_fragment();
                    self.flushed = true;
                    return Ok(e);
                }
                return Ok(Emit::Eos);
            }

            let s = match self.held.take() {
                Some(s) => s,
                None => match self.iter.next(src, wait) {
                    Ok(Some(s)) => s,
                    Ok(None) => {
                        self.eos = true;
                        continue;
                    }
                    // A gap in the STRUCTURE, not the payload. Same
                    // answer: come back, nothing has changed.
                    Err(e) if e.is_pending() => {
                        return Ok(Emit::NotYet {
                            need_off: self.next_need_off(),
                        });
                    }
                    Err(e) => return Err(e),
                },
            };

            // A fragment that has run past the hard ceiling has a group
            // of pictures longer than any player expects. Say so once -
            // it explains a seek that lands seconds off.
            if self.is_boundary(&s) {
                if s.dts_ns.saturating_sub(self.frag_start_ns) > FRAG_MAX_NS {
                    self.warn("this file has groups of pictures longer than six seconds");
                }
                self.held = Some(s);
                // Read BEFORE the emit: `emit_fragment` zeroes
                // `pending_bytes`, so asking after it always answered 0
                // and every prefetch asked for the 4 MiB floor whatever
                // the fragment actually weighed.
                let ahead = (self.pending_bytes as u64).max(4 << 20);
                let e = self.emit_fragment();
                // Keep the download one fragment ahead of the muxer.
                if let Some(h) = &self.held {
                    src.prefetch(h.src_off, ahead);
                }
                return Ok(e);
            }

            // A SINGLE sample larger than the whole fragment budget can
            // never be carried by any fragment, first or not - and the
            // cut below cannot help, because with nothing pending there is
            // nothing to cut. The cap has to bite BEFORE the allocation:
            // an MP4 sample size is an untrusted u32 that the parser only
            // checks against the source length, so one 512 MiB sample used
            // to allocate a payload-sized input buffer plus another
            // payload-sized copy in the fMP4 writer - times sixteen
            // concurrent remux workers (Codex sweep 12 Aug F3).
            if s.size as usize > FRAG_MAX_BYTES {
                return Err(RemuxError::Malformed(
                    "sample table",
                    format!(
                        "a single sample declares {} bytes, past the {} MiB fragment limit",
                        s.size,
                        FRAG_MAX_BYTES >> 20
                    ),
                ));
            }
            // The byte ceiling is the one cut that can land mid-GOP. It
            // exists so a malformed file cannot make us buffer without
            // limit, and a real one never reaches it.
            if !self.pending.is_empty()
                && self.pending_bytes.saturating_add(s.size as usize) > FRAG_MAX_BYTES
            {
                self.warn("a single group of pictures exceeded the fragment size limit");
                self.held = Some(s);
                return Ok(self.emit_fragment());
            }

            // Now the payload. This is the only place a download's
            // progress is allowed to matter, and all it can do is delay.
            let mut buf = vec![0u8; s.size as usize];
            if s.size > 0 {
                match src.read_at_wait(s.src_off, &mut buf, wait) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        let need = s.src_off;
                        src.prefetch(need, u64::from(s.size).max(1 << 20));
                        self.held = Some(s);
                        return Ok(Emit::NotYet { need_off: need });
                    }
                    // Past the end of the file is the end of the walk,
                    // not a failure: a truncated download still plays
                    // everything before the truncation.
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        self.eos = true;
                        continue;
                    }
                    Err(e) => return Err(RemuxError::Io(e)),
                }
            }
            if self.pending.is_empty() {
                self.frag_start_ns = s.dts_ns;
            }
            self.pending_bytes += buf.len();
            self.pending.push((s, buf));
        }
    }

    /// Where the next byte the session wants is. Used only to tell a
    /// waiting client what it is waiting for.
    fn next_need_off(&self) -> u64 {
        self.held
            .as_ref()
            .map(|s| s.src_off)
            .or_else(|| {
                self.pending
                    .last()
                    .map(|(s, _)| s.src_off + u64::from(s.size))
            })
            .unwrap_or(0)
    }

    /// True once every sample has been emitted.
    pub fn is_complete(&self) -> bool {
        self.eos && self.pending.is_empty() && self.flushed
    }

    /// Reposition to the keyframe at or before `t_ms`, returning the
    /// time actually landed on.
    ///
    /// The snap matters to the client: MSE has to know what the first
    /// fragment's timestamp will be, and a player told "1200 ms" that
    /// receives 960 ms of content shows the seek as having failed.
    pub fn seek(&mut self, src: &dyn Source, t_ms: u64, wait: Duration) -> Result<u64, RemuxError> {
        // Drop the open fragment FIRST: its samples are before the
        // target and the client has moved past them. It has to happen
        // here and not after the walk, because positioning the walk ends
        // by holding the keyframe it landed on - and clearing `held`
        // afterwards would throw away the one sample the whole seek was
        // for, leaving the next fragment opening on a delta frame.
        self.pending.clear();
        self.pending_bytes = 0;
        self.held = None;
        let landed_ns = match &self.layout {
            Layout::Mkv(lay) => {
                let lay = lay.clone();
                let track = self
                    .tracks
                    .iter()
                    .find(|t| t.kind == TrackKind::Video)
                    .or_else(|| self.tracks.first())
                    .map(|t| t.src_id)
                    .unwrap_or(1);
                if self.cues.is_none() {
                    self.cues = Some(read_cues(src, &lay, track, wait)?);
                }
                let cues = self.cues.as_ref().expect("just parsed");
                let want_ticks = t_ms
                    .saturating_mul(1_000_000)
                    .checked_div(lay.timestamp_scale_ns.max(1))
                    .unwrap_or(0);
                // The greatest cue at or before the target; before the
                // first cue, the first one.
                let (cue_ticks, at) = cues
                    .points
                    .iter()
                    .rev()
                    .find(|(t, _)| *t <= want_ticks)
                    .copied()
                    .or_else(|| cues.points.first().copied())
                    .ok_or(RemuxError::NoIndex)?;
                self.iter.seek(src, at, cue_ticks)?;
                // Cues point at a cluster that normally OPENS with the
                // keyframe. Normally. Skipping forward to the first real
                // video keyframe costs nothing when they are right and
                // is the whole difference when they are not.
                let landed = self.skip_to_keyframe(src, wait)?;
                landed.unwrap_or(cue_ticks.saturating_mul(lay.timestamp_scale_ns))
            }
            Layout::Mp4(lay) => {
                let lay = lay.clone();
                let vt = self
                    .tracks
                    .iter()
                    .find(|t| t.kind == TrackKind::Video)
                    .or_else(|| self.tracks.first())
                    .ok_or(RemuxError::NoUsableTrack)?;
                let track = lay
                    .tracks
                    .iter()
                    .find(|t| t.track_id == vt.src_id)
                    .ok_or(RemuxError::NoUsableTrack)?;
                let ticks = (u128::from(t_ms) * u128::from(track.timescale) / 1000) as u64;
                let idx = mp4_sync_before(track, ticks).ok_or(RemuxError::NoIndex)?;
                self.iter.seek(src, idx, 0)?;
                let per_tick = 1_000_000_000u128 / u128::from(track.timescale.max(1));
                let _ = per_tick;
                // The iterator's own cursor now holds the exact time.
                self.skip_to_keyframe(src, wait)?.unwrap_or(0)
            }
        };
        self.eos = false;
        self.flushed = false;
        self.frag_start_ns = landed_ns;
        // The init has already been sent on this connection's first
        // pull; a seek reopens the response, so it is sent again.
        self.sent_init = false;
        Ok(landed_ns / 1_000_000)
    }

    /// Advance the iterator to the next video keyframe, holding it for
    /// the next `pull`. Reads headers only - no payload is fetched, so a
    /// seek costs one small read per skipped block and never waits on
    /// megabytes the client will not receive.
    fn skip_to_keyframe(
        &mut self,
        src: &dyn Source,
        wait: Duration,
    ) -> Result<Option<u64>, RemuxError> {
        let video = self.video_id();
        // Bounded: a cue pointing into a stretch with no keyframe at all
        // must end as an error, not as a walk to the end of the file.
        for _ in 0..200_000 {
            match self.iter.next(src, wait)? {
                None => return Ok(None),
                Some(s) => {
                    let want = match video {
                        Some(v) => s.track == v && s.keyframe,
                        None => true,
                    };
                    if want {
                        let ns = s.dts_ns;
                        self.held = Some(s);
                        return Ok(Some(ns));
                    }
                }
            }
        }
        Err(RemuxError::NoIndex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediaprobe::source::MemSource;
    use crate::mediaprobe::testmux;

    /// The planner and the emitter must agree, because an HLS playlist
    /// is a PROMISE about where segments begin: a client told a segment
    /// starts at 4.000 s that receives one starting at 3.840 s does not
    /// error, it drifts, and drift is the failure nobody finds by
    /// watching it work once.
    ///
    /// So this walks the fixture for real, takes the fragment starts the
    /// session actually emitted, and asserts `plan_fragments` predicts
    /// exactly those from keyframe times alone. Edit `is_boundary`
    /// without editing the planner and this fails.
    #[test]
    fn plan_matches_the_fragments_actually_emitted() {
        use crate::mediaprobe::samples::{mkv_layout, read_cues};

        let src = MemSource(testmux::mkv_remux_fixture());
        let mut s = RemuxSession::new(&src, None, Duration::ZERO).unwrap();
        while let Emit::Init(_) | Emit::Fragment(_) = s.pull(&src, Duration::ZERO).unwrap() {}
        let actual: Vec<u64> = s.fragment_index.iter().map(|f| f.t_ns).collect();
        assert!(
            actual.len() > 2,
            "fixture emitted {} fragments",
            actual.len()
        );

        // The planner gets the file's OWN keyframe index, not the
        // answer: the fixture cues every cluster (480 ms apart) while
        // fragments are 2 s, so the planner has to discard four
        // keyframes in five. Feeding it the emitted starts instead would
        // have made this test agree with itself.
        let lay = mkv_layout(&src, Duration::ZERO).unwrap();
        let cues = read_cues(&src, &lay, 1, Duration::ZERO).unwrap();
        let keyframes: Vec<u64> = cues
            .points
            .iter()
            .map(|(ticks, _)| ticks * lay.timestamp_scale_ns)
            .collect();
        assert!(
            keyframes.len() > actual.len() * 3,
            "the cue index ({}) is not denser than the fragments ({}), so this \
             test would not exercise the selection",
            keyframes.len(),
            actual.len()
        );

        let end = actual.last().copied().unwrap_or(0) + 1;
        let planned: Vec<u64> = plan_fragments(&keyframes, end)
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        assert_eq!(
            planned, actual,
            "the planner and the emitter disagree about where fragments begin"
        );
    }

    /// `segments()` reads the container's own index and must land on the
    /// same starts the walk produces - in BOTH containers, because the
    /// two index formats are unrelated (Matroska Cues by time, ISO-BMFF
    /// stss by sample number through stts) and only one of them was ever
    /// exercised by the fixture above.
    #[test]
    fn segments_match_the_walk_in_both_containers() {
        for (what, bytes) in [
            ("mkv", testmux::mkv_remux_fixture()),
            ("mp4", testmux::mp4_remux_fixture()),
        ] {
            let src = MemSource(bytes);
            let mut s = RemuxSession::new(&src, None, Duration::ZERO).unwrap();
            let planned: Vec<u64> = s
                .segments(&src, Duration::ZERO)
                .unwrap_or_else(|e| panic!("{what}: segments() failed: {e}"))
                .into_iter()
                .map(|(t, _)| t)
                .collect();
            while let Emit::Init(_) | Emit::Fragment(_) = s.pull(&src, Duration::ZERO).unwrap() {}
            let actual: Vec<u64> = s.fragment_index.iter().map(|f| f.t_ns).collect();
            assert!(!actual.is_empty(), "{what}: no fragments emitted");
            // The planner may advertise a final segment the walk closes
            // as part of the previous one, so compare the shared prefix
            // and require it to be the whole of the emitted list.
            assert_eq!(
                planned.get(..actual.len()),
                Some(&actual[..]),
                "{what}: planned {planned:?} does not open with emitted {actual:?}"
            );
        }
    }

    /// The rule itself, on synthetic keyframe times: cut on the first
    /// keyframe at or past two seconds, never before, and never on a
    /// non-keyframe.
    #[test]
    fn the_planner_cuts_on_the_first_keyframe_past_the_target() {
        // Keyframes every 0.5 s. Boundaries land on 0, 2, 4, 6 s.
        let kf: Vec<u64> = (0..17).map(|i| i * 500_000_000).collect();
        let plan = plan_fragments(&kf, 8_000_000_000);
        let starts: Vec<u64> = plan.iter().map(|(t, _)| *t).collect();
        assert_eq!(starts, vec![0, 2_000_000_000, 4_000_000_000, 6_000_000_000]);
        assert!(plan.iter().all(|(_, d)| *d == 2_000_000_000));

        // Sparse keyframes cannot be cut closer than they occur: a
        // 5-second GOP is one 5-second segment, not a lie about 2.
        let sparse = vec![0, 5_000_000_000, 10_000_000_000];
        let plan = plan_fragments(&sparse, 15_000_000_000);
        assert_eq!(
            plan,
            vec![
                (0, 5_000_000_000),
                (5_000_000_000, 5_000_000_000),
                (10_000_000_000, 5_000_000_000)
            ]
        );

        // No keyframes at all (audio-only) is one segment, not a panic.
        assert_eq!(plan_fragments(&[], 3_000_000_000), vec![(0, 3_000_000_000)]);
        assert!(plan_fragments(&[], 0).is_empty());
    }

    /// A container we cannot remux is refused up front, not discovered
    /// halfway through a response.
    #[test]
    fn an_avi_is_refused_before_any_bytes_are_promised() {
        let src = MemSource(testmux::avi());
        let Err(e) = RemuxSession::new(&src, None, Duration::ZERO) else {
            panic!("an AVI was accepted for remux");
        };
        assert!(matches!(e, RemuxError::Unsupported("container", _)), "{e}");
    }

    /// The first pull is the init segment and it needs only the header,
    /// which is what lets playback start before the file is down.
    #[test]
    fn the_first_pull_is_the_init_segment() {
        let src = MemSource(testmux::mkv_remux_fixture());
        let mut s = RemuxSession::new(&src, None, Duration::ZERO).unwrap();
        match s.pull(&src, Duration::ZERO).unwrap() {
            Emit::Init(b) => {
                assert_eq!(&b[4..8], b"ftyp");
                assert!(b.windows(4).any(|w| w == b"moov"));
            }
            _ => panic!("first pull was not the init segment"),
        }
    }
}
