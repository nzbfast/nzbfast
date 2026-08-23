//! The remuxer, measured against the bytes it was given (TODO §73 phase 3).
//!
//! The load-bearing test here is [`remux_byte_identity`]: it takes the
//! output apart with an independent box walker, slices every sample out
//! of every `mdat` using only the offsets the file itself declares, and
//! asserts the result is byte-for-byte the elementary stream that went
//! in. That single assertion covers the passthrough claim and the
//! `data_offset` arithmetic at once - if either is wrong, the payload it
//! reconstructs is not the payload that was muxed.
//!
//! The other property worth naming is in [`partial_serve_30_100`]: the
//! same file remuxed from a complete source and from one arriving in
//! pieces must produce identical bytes. A remuxer that flushes early
//! under pressure passes every other test here and fails that one.

use nzbkit::mediaprobe::samples::{RemuxError, mkv_layout, read_cues};
use nzbkit::mediaprobe::session::{Emit, RemuxSession};
use nzbkit::mediaprobe::source::{MemSource, PartialSource, Source};
use nzbkit::mediaprobe::testmux;
use std::time::Duration;

const NOW: Duration = Duration::ZERO;

// ---------------------------------------------------------------------------
// An independent reader for the files the muxer produces
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TrunEntry {
    duration: u32,
    size: u32,
    flags: u32,
    cts: i32,
}

#[derive(Debug, Clone)]
struct Traf {
    track_id: u32,
    base_dts: u64,
    data_offset: i32,
    entries: Vec<TrunEntry>,
}

#[derive(Debug, Clone)]
struct Fragment {
    seq: u32,
    trafs: Vec<Traf>,
    /// The whole fragment, so payload slicing uses the file's own
    /// offsets rather than anything the test knows.
    bytes: Vec<u8>,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
}

/// Top-level boxes of a stream, as `(fourcc, start, end)`.
fn top_boxes(b: &[u8]) -> Vec<([u8; 4], usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= b.len() {
        let size = be32(b, at) as usize;
        assert!(size >= 8, "box at {at} declares size {size}");
        assert!(at + size <= b.len(), "box at {at} overruns the stream");
        out.push(([b[at + 4], b[at + 5], b[at + 6], b[at + 7]], at, at + size));
        at += size;
    }
    assert_eq!(at, b.len(), "boxes do not tile the stream");
    out
}

/// Where a box's children start, relative to the box. Not always eight:
/// `stsd` writes a version, flags and a count first, and a sample entry
/// carries a fixed visual or audio record before its configuration box.
fn child_offset(fourcc: &[u8]) -> Option<usize> {
    match fourcc {
        b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"dinf" | b"mvex" | b"moof" | b"traf" => {
            Some(8)
        }
        b"stsd" => Some(16),
        b"avc1" | b"hvc1" | b"av01" | b"vp09" => Some(8 + 78),
        b"mp4a" | b"Opus" | b"fLaC" => Some(8 + 28),
        _ => None,
    }
}

/// Every box with `fourcc`, at any depth, as `(start, end)`.
fn find_all(b: &[u8], start: usize, end: usize, fourcc: &[u8; 4]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = start;
    while at + 8 <= end {
        let size = be32(b, at) as usize;
        assert!(size >= 8);
        let this = [b[at + 4], b[at + 5], b[at + 6], b[at + 7]];
        if &this == fourcc {
            out.push((at, at + size));
        }
        if let Some(skip) = child_offset(&this) {
            out.extend(find_all(b, at + skip, at + size, fourcc));
        }
        at += size;
    }
    out
}

/// Parse one `moof` + `mdat` pair.
fn parse_fragment(bytes: &[u8]) -> Fragment {
    let boxes = top_boxes(bytes);
    assert_eq!(boxes.len(), 2, "a fragment is exactly moof + mdat");
    assert_eq!(&boxes[0].0, b"moof");
    assert_eq!(&boxes[1].0, b"mdat");
    let (moof_at, moof_end) = (boxes[0].1, boxes[0].2);

    let mfhd = find_all(bytes, moof_at + 8, moof_end, b"mfhd");
    assert_eq!(mfhd.len(), 1);
    let seq = be32(bytes, mfhd[0].0 + 12);

    let mut trafs = Vec::new();
    let mut at = moof_at + 8;
    while at + 8 <= moof_end {
        let size = be32(bytes, at) as usize;
        let this = &bytes[at + 4..at + 8];
        if this == b"traf" {
            trafs.push(parse_traf(bytes, at + 8, at + size));
        }
        at += size;
    }
    Fragment {
        seq,
        trafs,
        bytes: bytes.to_vec(),
    }
}

fn parse_traf(b: &[u8], start: usize, end: usize) -> Traf {
    let (mut track_id, mut base_dts, mut data_offset) = (0u32, 0u64, 0i32);
    let mut entries = Vec::new();
    let mut at = start;
    while at + 8 <= end {
        let size = be32(b, at) as usize;
        match &b[at + 4..at + 8] {
            b"tfhd" => {
                let flags = be32(b, at + 8) & 0x00FF_FFFF;
                assert_eq!(flags, 0x02_0000, "tfhd must set default-base-is-moof");
                track_id = be32(b, at + 12);
            }
            b"tfdt" => {
                assert_eq!(b[at + 8], 1, "tfdt must be version 1");
                base_dts = be64(b, at + 12);
            }
            b"trun" => {
                assert_eq!(b[at + 8], 1, "trun must be version 1 for signed cts");
                let flags = be32(b, at + 8) & 0x00FF_FFFF;
                assert_eq!(flags, 0x0F01, "trun flags");
                let count = be32(b, at + 12) as usize;
                data_offset = be32(b, at + 16) as i32;
                let mut e = at + 20;
                for _ in 0..count {
                    entries.push(TrunEntry {
                        duration: be32(b, e),
                        size: be32(b, e + 4),
                        flags: be32(b, e + 8),
                        cts: be32(b, e + 12) as i32,
                    });
                    e += 16;
                }
                assert_eq!(e, at + size, "trun does not fill its box");
            }
            _ => {}
        }
        at += size;
    }
    Traf {
        track_id,
        base_dts,
        data_offset,
        entries,
    }
}

impl Fragment {
    /// The payloads of one track, sliced out of `mdat` using only the
    /// `data_offset` the file declares.
    fn payloads(&self, track_id: u32) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for t in self.trafs.iter().filter(|t| t.track_id == track_id) {
            // Measured from the first byte of moof, which is byte 0 of a
            // fragment we were handed whole.
            let mut at = usize::try_from(t.data_offset).expect("negative data offset");
            for e in &t.entries {
                let n = e.size as usize;
                assert!(at + n <= self.bytes.len(), "sample runs past the fragment");
                out.push(self.bytes[at..at + n].to_vec());
                at += n;
            }
        }
        out
    }
}

/// Run a session to the end over a complete source.
fn run_to_end(src: &dyn Source) -> (Vec<u8>, Vec<Fragment>) {
    let mut s = RemuxSession::new(src, None, NOW).expect("session");
    let mut init = Vec::new();
    let mut frags = Vec::new();
    for _ in 0..100_000 {
        match s.pull(src, NOW).expect("pull") {
            Emit::Init(b) => init = b,
            Emit::Fragment(b) => frags.push(parse_fragment(&b)),
            Emit::NotYet { need_off } => panic!("a complete source blocked at {need_off}"),
            Emit::Eos => return (init, frags),
        }
    }
    panic!("the session never reached the end of the file");
}

// ---------------------------------------------------------------------------
// 1. Byte identity
// ---------------------------------------------------------------------------

/// The remux is a copy. Every payload byte that went in comes out, in
/// order, sliced back out of the output using only the output's own
/// offset arithmetic.
#[test]
fn remux_byte_identity() {
    let bytes = testmux::mkv_remux_fixture();
    let src = MemSource(bytes);
    let (_, frags) = run_to_end(&src);
    assert!(frags.len() >= 2, "expected several fragments");

    let (want_video, want_audio) = testmux::mkv_remux_streams();
    let got_video: Vec<Vec<u8>> = frags.iter().flat_map(|f| f.payloads(1)).collect();
    let got_audio: Vec<Vec<u8>> = frags.iter().flat_map(|f| f.payloads(2)).collect();

    assert_eq!(got_video.len(), want_video.len(), "video sample count");
    assert_eq!(got_audio.len(), want_audio.len(), "audio sample count");
    assert_eq!(got_video, want_video, "video payloads are not identical");
    assert_eq!(got_audio, want_audio, "audio payloads are not identical");
}

/// The same claim for an MP4 source, where the timing has to survive as
/// well: ticks are copied, not converted, and the composition offsets
/// the source declared come out unchanged.
#[test]
fn mp4_source_roundtrip() {
    let src = MemSource(testmux::mp4_remux_fixture());
    let (init, frags) = run_to_end(&src);
    let (want_video, want_audio) = testmux::mp4_remux_streams();

    let got_video: Vec<Vec<u8>> = frags.iter().flat_map(|f| f.payloads(1)).collect();
    let got_audio: Vec<Vec<u8>> = frags.iter().flat_map(|f| f.payloads(2)).collect();
    assert_eq!(got_video, want_video, "video payloads");
    assert_eq!(got_audio, want_audio, "audio payloads");

    // The source timescale is copied verbatim, so decode times are the
    // source's own tick values with nothing rounded.
    let mdhd = find_all(&init, 0, init.len(), b"mdhd");
    let timescales: Vec<u32> = mdhd.iter().map(|(at, _)| be32(&init, at + 20)).collect();
    assert_eq!(timescales, vec![90_000, 48_000]);

    // Composition offsets: every third video sample is displayed 6000
    // ticks after it decodes, exactly as the fixture wrote them.
    let cts: Vec<i32> = frags
        .iter()
        .flat_map(|f| f.trafs.iter().filter(|t| t.track_id == 1))
        .flat_map(|t| t.entries.iter().map(|e| e.cts))
        .collect();
    assert_eq!(cts.len(), want_video.len());
    for (i, c) in cts.iter().enumerate() {
        let want = if i % 3 == 0 { 6_000 } else { 0 };
        assert_eq!(*c, want, "composition offset of sample {i}");
    }

    // Decode times advance by the source's own delta, in source ticks.
    let dts: Vec<u64> = frags
        .iter()
        .flat_map(|f| f.trafs.iter().filter(|t| t.track_id == 1))
        .map(|t| t.base_dts)
        .collect();
    for w in dts.windows(2) {
        assert!(w[1] > w[0], "video tfdt must advance");
        assert!(
            (w[1] - w[0]).is_multiple_of(3_000),
            "video tfdt is not on a source tick boundary"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The init segment
// ---------------------------------------------------------------------------

#[test]
fn init_parses() {
    let src = MemSource(testmux::mkv_remux_fixture());
    let (init, _) = run_to_end(&src);
    let boxes = top_boxes(&init);
    assert_eq!(&boxes[0].0, b"ftyp");
    assert_eq!(&boxes[1].0, b"moov");
    assert_eq!(
        boxes.len(),
        2,
        "an init segment is ftyp + moov and nothing else"
    );

    // The movie timescale, and one trex per track so a fragment needs no
    // defaults it does not carry.
    let mvhd = find_all(&init, boxes[1].1 + 8, boxes[1].2, b"mvhd");
    assert_eq!(be32(&init, mvhd[0].0 + 20), 1000, "mvhd timescale");
    let trex = find_all(&init, boxes[1].1 + 8, boxes[1].2, b"trex");
    assert_eq!(trex.len(), 2, "one trex per track");
    let ids: Vec<u32> = trex.iter().map(|(at, _)| be32(&init, at + 12)).collect();
    assert_eq!(ids, vec![1, 2]);

    // The Matroska CodecPrivate reaches avcC untouched: it already IS an
    // AVCDecoderConfigurationRecord, and rewriting it would be the bug.
    let avcc = find_all(&init, boxes[1].1 + 8, boxes[1].2, b"avcC");
    assert_eq!(avcc.len(), 1, "one avcC");
    assert_eq!(init[avcc[0].0 + 8], 1, "avcC configurationVersion");

    // A Matroska timestamp scale of a million nanoseconds is a timescale
    // of a thousand ticks per second, on both tracks.
    let mdhd = find_all(&init, boxes[1].1 + 8, boxes[1].2, b"mdhd");
    let timescales: Vec<u32> = mdhd.iter().map(|(at, _)| be32(&init, at + 20)).collect();
    assert_eq!(timescales, vec![1000, 1000]);
}

// ---------------------------------------------------------------------------
// 3. Fragment invariants
// ---------------------------------------------------------------------------

#[test]
fn fragment_invariants() {
    let src = MemSource(testmux::mkv_remux_fixture());
    let (_, frags) = run_to_end(&src);

    // Sequence numbers strictly increase; MSE rejects a repeat.
    for w in frags.windows(2) {
        assert!(w[1].seq > w[0].seq, "mfhd sequence must increase");
    }
    assert_eq!(frags[0].seq, 1);

    for track in [1u32, 2] {
        let mut last: Option<u64> = None;
        let mut running = 0u64;
        for f in &frags {
            for t in f.trafs.iter().filter(|t| t.track_id == track) {
                if let Some(l) = last {
                    assert!(
                        t.base_dts >= l,
                        "tfdt went backwards on track {track}: {l} then {}",
                        t.base_dts
                    );
                    // tfdt is absolute: it equals the running sum of
                    // every duration emitted before it.
                    assert_eq!(
                        t.base_dts, running,
                        "tfdt on track {track} is not the running decode time"
                    );
                }
                if last.is_none() {
                    running = t.base_dts;
                }
                last = Some(t.base_dts);
                running += t.entries.iter().map(|e| u64::from(e.duration)).sum::<u64>();
            }
        }
    }

    // Every fragment opens on a sync sample of the video track: a
    // fragment a browser cannot seek to is worse than one that runs long.
    for f in &frags {
        let v = f
            .trafs
            .iter()
            .find(|t| t.track_id == 1)
            .expect("every fragment carries video");
        assert_eq!(
            v.entries[0].flags, 0x0200_0000,
            "fragment {} does not open on a sync sample",
            f.seq
        );
        // And each traf's payload lands inside its own fragment.
        for t in &f.trafs {
            let at = t.data_offset as usize;
            let n: usize = t.entries.iter().map(|e| e.size as usize).sum();
            assert!(at + n <= f.bytes.len(), "traf payload runs past its mdat");
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Determinism across arrival patterns
// ---------------------------------------------------------------------------

/// The property the whole live path rests on: what comes out does not
/// depend on when the input arrived.
///
/// The partial source's wait can never be satisfied by time passing, so
/// a session that finishes here has made progress on coverage alone.
#[test]
fn partial_serve_30_100() {
    let bytes = testmux::mkv_remux_fixture();
    let total = bytes.len() as u64;
    let want = {
        let src = MemSource(bytes.clone());
        collect_output(&src)
    };

    for shuffled in [false, true] {
        let src = PartialSource::new(bytes.clone());
        // The head, plus the tail where the Cues live.
        src.land(0, total * 3 / 10);
        // The tail, where the Cues live: the same window the download's
        // playhead promotion keeps hot for exactly this reason.
        src.land(total.saturating_sub(8_192), 8_192);

        let mut s = RemuxSession::new(&src, None, NOW).expect("session over a partial file");
        let mut got = Vec::new();
        let mut blocked = false;
        for _ in 0..100_000 {
            match s.pull(&src, NOW).expect("pull") {
                Emit::Init(b) | Emit::Fragment(b) => got.extend(b),
                Emit::NotYet { need_off } => {
                    assert!(need_off > 0, "blocked at the very start of the file");
                    blocked = true;
                    break;
                }
                Emit::Eos => panic!("a 30% file reached the end of the stream"),
            }
        }
        assert!(blocked, "a 30% file never blocked");
        assert!(!got.is_empty(), "nothing was emitted before the hole");

        // The rest arrives, in order or not.
        if shuffled {
            let mut at = total;
            while at > 0 {
                let step = 4_096.min(at);
                src.land(at - step, step);
                at -= step;
            }
        } else {
            src.land_all();
        }

        for _ in 0..100_000 {
            match s.pull(&src, NOW).expect("pull after the rest landed") {
                Emit::Init(b) | Emit::Fragment(b) => got.extend(b),
                Emit::NotYet { need_off } => panic!("still blocked at {need_off}"),
                Emit::Eos => break,
            }
        }
        assert_eq!(
            got.len(),
            want.len(),
            "output length changed with the arrival pattern (shuffled: {shuffled})"
        );
        assert!(
            got == want,
            "output bytes changed with the arrival pattern (shuffled: {shuffled})"
        );
    }
}

fn collect_output(src: &dyn Source) -> Vec<u8> {
    let mut s = RemuxSession::new(src, None, NOW).expect("session");
    let mut out = Vec::new();
    for _ in 0..100_000 {
        match s.pull(src, NOW).expect("pull") {
            Emit::Init(b) | Emit::Fragment(b) => out.extend(b),
            Emit::NotYet { need_off } => panic!("blocked at {need_off}"),
            Emit::Eos => return out,
        }
    }
    panic!("never reached the end");
}

/// A held sample is not re-read and not double-counted: pulling a
/// blocked session repeatedly changes nothing.
#[test]
fn a_blocked_pull_is_idempotent() {
    let bytes = testmux::mkv_remux_fixture();
    let total = bytes.len() as u64;
    let src = PartialSource::new(bytes.clone());
    src.land(0, total / 4);
    src.land(total.saturating_sub(65_536), 65_536);

    let mut s = RemuxSession::new(&src, None, NOW).unwrap();
    let mut got = Vec::new();
    loop {
        match s.pull(&src, NOW).unwrap() {
            Emit::Init(b) | Emit::Fragment(b) => got.extend(b),
            Emit::NotYet { .. } => break,
            Emit::Eos => panic!("a quarter of a file reached the end"),
        }
    }
    // Ten more pulls against the same coverage must add nothing.
    for _ in 0..10 {
        match s.pull(&src, NOW).unwrap() {
            Emit::NotYet { .. } => {}
            _ => panic!("a blocked session emitted something on a retry"),
        }
    }
    src.land_all();
    let mut after = got.clone();
    loop {
        match s.pull(&src, NOW).unwrap() {
            Emit::Init(b) | Emit::Fragment(b) => after.extend(b),
            Emit::NotYet { need_off } => panic!("still blocked at {need_off}"),
            Emit::Eos => break,
        }
    }
    let want = collect_output(&MemSource(bytes));
    assert_eq!(after, want, "retries perturbed the output");
}

// ---------------------------------------------------------------------------
// 6. Seek
// ---------------------------------------------------------------------------

#[test]
fn seek_maps_to_keyframe() {
    let bytes = testmux::mkv_remux_fixture();
    let src = MemSource(bytes.clone());
    let mut s = RemuxSession::new(&src, None, NOW).unwrap();
    assert!(s.seekable(), "the fixture has Cues");

    // Clusters open at 0, 480, 960 and 1440 ms and each opens with a
    // keyframe, so 1200 ms snaps back to 960.
    let landed = s.seek(&src, 1_200, NOW).unwrap();
    assert_eq!(landed, 960, "seek did not snap to the keyframe before it");

    // Init is re-sent (the response is a new one), then the first
    // fragment starts exactly at the landed time, on a sync sample.
    match s.pull(&src, NOW).unwrap() {
        Emit::Init(_) => {}
        _ => panic!("a seek must re-send the init segment"),
    }
    let Emit::Fragment(f) = s.pull(&src, NOW).unwrap() else {
        panic!("no fragment after the seek");
    };
    let f = parse_fragment(&f);
    let v = f.trafs.iter().find(|t| t.track_id == 1).unwrap();
    assert_eq!(v.base_dts, 960, "tfdt is not the seek target");
    assert_eq!(v.entries[0].flags, 0x0200_0000, "not a sync sample");

    // A seek before the first cue lands on the first one, not below it.
    let mut s = RemuxSession::new(&src, None, NOW).unwrap();
    assert_eq!(s.seek(&src, 0, NOW).unwrap(), 0);
}

/// A file with no index refuses an arbitrary seek rather than guessing;
/// forward playback from the start still works.
#[test]
fn a_file_without_cues_refuses_to_seek() {
    // mkv_padded's cluster is junk, but the header is a real one and it
    // carries no Cues element at all.
    let src = MemSource(testmux::mkv_padded(4_096));
    let lay = mkv_layout(&src, NOW).unwrap();
    assert!(lay.cues_off.is_none());
    assert!(matches!(
        read_cues(&src, &lay, 1, NOW),
        Err(RemuxError::NoIndex)
    ));
}

// ---------------------------------------------------------------------------
// 7. Malformed input
// ---------------------------------------------------------------------------

/// Corruptions that have to end as an error or a short read, never as a
/// panic, an allocation sized by the file's own claim, or a walk that
/// does not terminate.
#[test]
fn malformed_block_safety() {
    let base = testmux::mkv_remux_fixture();

    // Find the first SimpleBlock so the corruptions land on a real one.
    let block_at = find_simple_block(&base).expect("fixture has a SimpleBlock");
    // id (1) + size (4, testmux always writes four) + track vint (1)
    // + rel (2) = the flags byte.
    let flags_at = block_at + 1 + 4 + 1 + 2;
    let size_at = block_at + 1;

    let cases: Vec<(&str, Box<dyn Fn(&mut Vec<u8>)>)> = vec![
        (
            "a lace count claiming more frames than the payload holds",
            Box::new(move |b: &mut Vec<u8>| {
                b[flags_at] |= 0x06; // EBML lacing
                b[flags_at + 1] = 255; // 256 frames
            }),
        ),
        (
            "a Xiph size run that overruns the payload",
            Box::new(move |b: &mut Vec<u8>| {
                b[flags_at] = (b[flags_at] & !0x06) | 0x02;
                b[flags_at + 1] = 3;
                for i in 2..8 {
                    b[flags_at + i] = 255;
                }
            }),
        ),
        (
            "an EBML lace delta that underflows below zero",
            Box::new(move |b: &mut Vec<u8>| {
                b[flags_at] |= 0x06;
                b[flags_at + 1] = 2; // three frames
                b[flags_at + 2] = 0x81; // first size 1
                b[flags_at + 3] = 0x80; // delta -63
            }),
        ),
        (
            "an element size vint declaring eight bytes past the end",
            Box::new(move |b: &mut Vec<u8>| {
                b[size_at] = 0x01;
                for i in 1..8 {
                    b[size_at + i] = 0xFF;
                }
            }),
        ),
        (
            "fixed lacing with a remainder that does not divide",
            Box::new(move |b: &mut Vec<u8>| {
                b[flags_at] = (b[flags_at] & !0x06) | 0x04;
                b[flags_at + 1] = 6; // seven frames, payload is not a multiple
            }),
        ),
        (
            "a block header running past the element",
            Box::new(move |b: &mut Vec<u8>| {
                // A one-byte SimpleBlock cannot hold a track number, a
                // timestamp and a flags byte.
                b[size_at] = 0x10;
                b[size_at + 1] = 0;
                b[size_at + 2] = 0;
                b[size_at + 3] = 1;
            }),
        ),
        (
            "an unknown-size cluster with nothing after it",
            Box::new(|b: &mut Vec<u8>| {
                if let Some(at) = find_cluster(b) {
                    // Replace the four-byte size with an unknown-size
                    // vint and pad the rest with Void.
                    b[at + 4] = 0xFF;
                    b[at + 5] = 0xEC;
                    b[at + 6] = 0x81;
                    b[at + 7] = 0x00;
                }
            }),
        ),
    ];

    for (name, corrupt) in cases {
        let mut bytes = base.clone();
        corrupt(&mut bytes);
        let src = MemSource(bytes);
        // Either the session refuses to open, or it walks to an end.
        // Both are fine; hanging, panicking or allocating on the file's
        // own claim are not.
        let Ok(mut s) = RemuxSession::new(&src, None, NOW) else {
            continue;
        };
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 200_000, "{name}: the walk did not terminate");
            match s.pull(&src, NOW) {
                Ok(Emit::Init(_)) | Ok(Emit::Fragment(_)) => {}
                Ok(Emit::NotYet { .. }) => panic!("{name}: a complete source blocked"),
                Ok(Emit::Eos) | Err(_) => break,
            }
        }
    }
}

/// An MP4 whose offset tables point outside the file is rejected rather
/// than read: the value cannot become right by waiting for more bytes.
#[test]
fn mp4_offsets_past_the_file_are_refused() {
    let mut bytes = testmux::mp4_remux_fixture();
    let stco = find_all(&bytes, 0, bytes.len(), b"stco");
    assert!(!stco.is_empty(), "fixture has an stco");
    // Point the first chunk a long way past the end.
    let at = stco[0].0 + 16;
    bytes[at..at + 4].copy_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
    let src = MemSource(bytes);
    let mut s = RemuxSession::new(&src, None, NOW).expect("the header still parses");
    let mut err = None;
    for _ in 0..1000 {
        match s.pull(&src, NOW) {
            Ok(Emit::Eos) => break,
            Ok(_) => {}
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    assert!(
        err.is_some(),
        "an offset past the end of the file was accepted"
    );
}

fn find_simple_block(b: &[u8]) -> Option<usize> {
    // The first 0xA3 whose four following bytes are a testmux size vint
    // (top nibble 0x10), inside the clusters.
    (0..b.len().saturating_sub(8)).find(|&i| b[i] == 0xA3 && b[i + 1] & 0xF0 == 0x10)
}

fn find_cluster(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == [0x1F, 0x43, 0xB6, 0x75])
}
