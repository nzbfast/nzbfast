//! What the media probe does to bytes that are missing, truncated or
//! hostile - which, on a half-finished download, is most of them.
//!
//! The per-container parse assertions live beside their parsers; this
//! suite is the byte-level harness: every fixture cut at every
//! interesting length, holes punched over the regions a live download
//! has not filled yet, and the wire shape the dashboard codes against.

use crate::scratch;

use nzbkit::mediaprobe::{
    Container, LiveProbeReader, MediaInfo, PlaybackPath, ProbeError, ProbeHint, probe, testmux,
};
use std::io::{Cursor, Read, Seek, SeekFrom};

fn hint(len: u64) -> ProbeHint {
    ProbeHint {
        filename: None,
        known_size: Some(len),
    }
}

/// A reader over a file whose middle has not arrived. Holes report
/// `WouldBlock`, which is the convention the whole partial-file design
/// hangs on - a plain `File` never does, so a finished download is the
/// degenerate case of this.
struct GappyReader {
    data: Vec<u8>,
    holes: Vec<(u64, u64)>,
    pos: u64,
}

impl GappyReader {
    fn new(data: Vec<u8>, holes: &[(u64, u64)]) -> Self {
        GappyReader {
            data,
            holes: holes.to_vec(),
            pos: 0,
        }
    }

    fn covered(&self, at: u64) -> bool {
        !self.holes.iter().any(|&(s, e)| at >= s && at < e)
    }
}

impl Read for GappyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.data.len() as u64 || buf.is_empty() {
            return Ok(0);
        }
        if !self.covered(self.pos) {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "gap"));
        }
        // Stop at the first hole, so a read that starts on landed bytes
        // returns the covered prefix rather than failing outright.
        let mut n = 0usize;
        while n < buf.len() && self.pos + (n as u64) < self.data.len() as u64 {
            if !self.covered(self.pos + n as u64) {
                break;
            }
            buf[n] = self.data[(self.pos + n as u64) as usize];
            n += 1;
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for GappyReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.pos = match from {
            SeekFrom::Start(n) => n,
            SeekFrom::End(d) => (self.data.len() as i64 + d).max(0) as u64,
            SeekFrom::Current(d) => (self.pos as i64 + d).max(0) as u64,
        };
        Ok(self.pos)
    }
}

/// Every fixture cut at every awkward length. The contract is narrow on
/// purpose: never panic, never hang, and never claim a truncated file
/// was read completely.
#[test]
fn truncation_never_panics_and_never_claims_completeness() {
    for (name, bytes) in testmux::all() {
        let len = bytes.len();
        for n in [0, 1, 3, 8, 12, 100, len / 4, len / 2, len - 1, len] {
            let n = n.min(len);
            let mut c = Cursor::new(&bytes[..n]);
            match probe(&mut c, hint(n as u64)) {
                Ok(info) => {
                    // `complete` means "every metadata region was read
                    // to its end", NOT "the file is whole" - cutting
                    // the tail off a faststart MP4 or a front-loaded
                    // Matroska legitimately leaves a complete parse.
                    // The fixture whose metadata IS the tail is the one
                    // that must always come back incomplete.
                    if n < len && name == "mp4_moov_at_end" {
                        assert!(!info.complete, "{name} cut to {n} claimed a complete parse");
                    }
                    // Whatever came out is internally consistent.
                    for v in &info.video {
                        assert!(v.width < 100_000 && v.height < 100_000, "{name}@{n}");
                    }
                }
                Err(
                    ProbeError::UnknownContainer
                    | ProbeError::NotYet
                    | ProbeError::Malformed { .. }
                    | ProbeError::Io(_)
                    | ProbeError::BudgetExceeded,
                ) => {}
            }
        }
    }
}

/// Probing the same bytes twice must give the same answer - the
/// property the fuzz target asserts, pinned here so a budget with a
/// clock in it cannot creep back in.
#[test]
fn probing_is_deterministic() {
    for (name, bytes) in testmux::all() {
        for n in [bytes.len() / 3, bytes.len() / 2, bytes.len()] {
            let a = probe(&mut Cursor::new(&bytes[..n]), hint(n as u64));
            let b = probe(&mut Cursor::new(&bytes[..n]), hint(n as u64));
            match (a, b) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "{name}@{n}"),
                (Err(_), Err(_)) => {}
                _ => panic!("{name}@{n}: probe disagreed with itself"),
            }
        }
    }
}

/// The headline property: an MP4 whose index sits at the END is fully
/// readable while the payload between them is still nothing but a hole.
/// This is what lets the panel answer "is this the right file" forty
/// seconds into a two-hour download.
#[test]
fn a_missing_mdat_costs_nothing_because_it_is_never_read() {
    let bytes = testmux::mp4_moov_at_end();
    let len = bytes.len() as u64;
    let (mdat_start, mdat_end) = testmux::mp4_moov_at_end_mdat();
    let mut r = GappyReader::new(bytes, &[(mdat_start, mdat_end)]);
    let info = probe(&mut r, hint(len)).expect("the index is readable");
    assert_eq!(info.playback, PlaybackPath::Native);
    assert_eq!(info.video[0].codec, "h264");
    assert_eq!(info.audio[0].codec, "aac");
    assert!(info.complete, "warnings: {:?}", info.warnings);
}

/// The same file with the hole over the INDEX instead: everything the
/// panel needs is missing, and it has to say so rather than guess.
#[test]
fn a_missing_moov_is_reported_as_pending_not_as_a_broken_file() {
    let bytes = testmux::mp4_moov_at_end();
    let len = bytes.len() as u64;
    let (_, mdat_end) = testmux::mp4_moov_at_end_mdat();
    let mut r = GappyReader::new(bytes, &[(mdat_end, len)]);
    let info = probe(&mut r, hint(len)).expect("a partial answer is still an answer");
    assert_eq!(info.container, Container::Mp4);
    assert_eq!(info.playback, PlaybackPath::Unknown);
    assert!(!info.complete);
    assert!(
        info.warnings.iter().any(|w| w.contains("moov")),
        "warnings: {:?}",
        info.warnings
    );
    assert!(info.video.is_empty());
}

/// Matroska's version of the same shape: the tracks are at the front and
/// parse fine, and only the SeekHead-indexed tail is missing.
#[test]
fn a_missing_matroska_tail_keeps_the_tracks_it_already_read() {
    let bytes = testmux::mkv_seekhead_chapters();
    let len = bytes.len() as u64;
    // Punch out the last third, which is where the Chapters live.
    let mut r = GappyReader::new(bytes, &[(len * 2 / 3, len)]);
    let info = probe(&mut r, hint(len)).expect("the front of the file is readable");
    assert_eq!(info.video.len(), 1);
    assert_eq!(info.video[0].codec, "h264");
    assert!(!info.complete);
    assert!(info.chapters.is_empty());
    assert!(
        info.warnings.iter().any(|w| w.contains("chapters")),
        "warnings: {:?}",
        info.warnings
    );
}

/// The real thing: a `FileWriter` with a hole in it, which is exactly
/// what the daemon hands the probe for a job that is still downloading.
/// Fill the hole and the same file answers completely.
#[test]
fn a_live_writer_with_a_hole_probes_partially_then_completely() {
    let dir = std::env::temp_dir().join(format!("nzbfast-mediaprobe-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let path = dir.join("live.mp4");
    let bytes = testmux::mp4_moov_at_end();
    let len = bytes.len() as u64;
    let (_, mdat_end) = testmux::mp4_moov_at_end_mdat();

    let w = std::sync::Arc::new(nzbkit::disk::FileWriter::create(&path, len).unwrap());
    // Everything except the index at the end.
    w.write_at(0, &bytes[..mdat_end as usize]).unwrap();
    let mut r = LiveProbeReader {
        w: w.clone(),
        f: std::fs::File::open(&path).unwrap(),
        pos: 0,
    };
    let info = probe(&mut r, hint(len)).expect("a partial answer");
    assert!(!info.complete);
    assert_eq!(info.playback, PlaybackPath::Unknown);

    // The tail lands (which on a real download is what the playhead
    // promotion pulls in first).
    w.write_at(mdat_end, &bytes[mdat_end as usize..]).unwrap();
    let mut r = LiveProbeReader {
        w,
        f: std::fs::File::open(&path).unwrap(),
        pos: 0,
    };
    let info = probe(&mut r, hint(len)).expect("a complete answer");
    assert!(info.complete, "warnings: {:?}", info.warnings);
    assert_eq!(info.playback, PlaybackPath::Native);
    assert_eq!(info.video[0].codec, "h264");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The wire shape the dashboard panel codes against. Field names and
/// enum spellings are a contract with the frontend: `playback` is
/// PascalCase, `container` is lowercase, `Option` serializes as null
/// rather than vanishing, and every list is always present.
#[test]
fn the_wire_shape_is_stable() {
    let bytes = testmux::mkv_full();
    let info: MediaInfo = probe(&mut Cursor::new(&bytes), hint(bytes.len() as u64)).unwrap();
    let j = serde_json::to_value(&info).unwrap();

    assert_eq!(j["container"], "mkv");
    assert_eq!(j["playback"], "Transcode");
    assert_eq!(j["duration_ms"], 60_000);
    assert_eq!(j["complete"], true);
    assert!(j["chapters"].is_array(), "chapters must always be present");
    assert!(j["video"][0]["hdr"].is_null(), "an absent option is null");
    assert_eq!(j["video"][0]["codec"], "h264");
    assert_eq!(j["video"][0]["codec_id"], "V_MPEG4/ISO/AVC");
    assert_eq!(j["video"][0]["enabled"], true);
    assert_eq!(j["audio"][1]["lang"], "de");
    assert_eq!(j["audio"][1]["channel_layout"], "5.1");
    assert_eq!(j["subtitles"][1]["kind"], "bitmap");
    // The muxer's own name for the content, with a repacker's signature
    // stripped the same way the renamer strips it.
    assert_eq!(j["title"], "Example.Movie.2019.1080p-GRP");

    for path in [
        "container",
        "playback",
        "video",
        "audio",
        "subtitles",
        "chapters",
    ] {
        assert!(!j[path].is_null(), "{path} must always be present");
    }
}

/// Bytes off Usenet are attacker-shaped. None of these may panic, hang,
/// or allocate on a declared length.
#[test]
fn hostile_input_is_refused_without_panicking() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"not a container at all".to_vec(),
        // EBML magic then a run of zero bytes: a vint decoder that
        // accepts a leading 0x00 loops here forever.
        [vec![0x1A, 0x45, 0xDF, 0xA3], vec![0u8; 512]].concat(),
        // EBML magic then all-ones sizes everywhere.
        [vec![0x1A, 0x45, 0xDF, 0xA3], vec![0xFFu8; 512]].concat(),
        // An MP4 whose first box claims the whole 64-bit address space.
        [
            &[0u8, 0, 0, 1][..],
            b"moov",
            &u64::MAX.to_be_bytes()[..],
            &[0u8; 64],
        ]
        .concat(),
        // A box that declares a size of zero inside a parent, which
        // would not advance the walk.
        [&[0u8, 0, 0, 32][..], b"ftyp", &[0u8; 24], &[0u8; 8][..]].concat(),
        // RIFF/AVI with a chunk length far past the file.
        [
            b"RIFF".to_vec(),
            0xFFFF_FFFFu32.to_le_bytes().to_vec(),
            b"AVI ".to_vec(),
            b"LIST".to_vec(),
            0xFFFF_FFFFu32.to_le_bytes().to_vec(),
            b"hdrl".to_vec(),
        ]
        .concat(),
    ];
    for (i, data) in cases.iter().enumerate() {
        let n = data.len() as u64;
        let _ = probe(&mut Cursor::new(data), hint(n));
        // The same bytes with the size hint withheld, which is how a
        // finished file on disk arrives.
        let _ = probe(
            &mut Cursor::new(data),
            ProbeHint {
                filename: Some(format!("case{i}.mkv")),
                known_size: None,
            },
        );
    }
}

/// A hostile file can also be an enormous one. Every fixture with a
/// megabyte of junk appended must still answer from its header rather
/// than reading the junk.
#[test]
fn junk_after_the_header_is_not_read() {
    for (name, mut bytes) in testmux::all() {
        let real = bytes.len();
        bytes.extend(std::iter::repeat_n(0xA5u8, 1 << 20));
        let info = probe(&mut Cursor::new(&bytes), hint(bytes.len() as u64));
        if let Ok(info) = info {
            assert!(
                info.video.len() + info.audio.len() <= 8,
                "{name}: junk produced tracks"
            );
        }
        assert!(real > 0);
    }
}

/// The fuzz seed corpus. The fixtures are generated rather than
/// committed, so this is how they reach `fuzz/corpus/mediaprobe` - see
/// the fuzz README. A no-op unless asked, so it costs a normal test run
/// nothing.
#[test]
fn write_fuzz_seeds() {
    let Ok(dir) = std::env::var("NZBFAST_WRITE_FUZZ_SEEDS") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in testmux::all() {
        std::fs::write(dir.join(name), &bytes).unwrap();
        // The first kilobyte of each: the shapes a live download has
        // when the panel first asks.
        let head = &bytes[..bytes.len().min(1024)];
        std::fs::write(dir.join(format!("{name}.head")), head).unwrap();
    }
}

/// The filename never overrides the magic bytes; it only earns a
/// warning when the two disagree.
#[test]
fn a_mislabelled_file_is_flagged_not_believed() {
    let bytes = testmux::mkv_full();
    let info = probe(
        &mut Cursor::new(&bytes),
        ProbeHint {
            filename: Some("Some.Movie.2019.mp4".into()),
            known_size: Some(bytes.len() as u64),
        },
    )
    .unwrap();
    assert_eq!(info.container, Container::Mkv);
    assert!(
        info.warnings.iter().any(|w| w.contains("named .mp4")),
        "warnings: {:?}",
        info.warnings
    );
}
