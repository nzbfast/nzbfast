//! What extension a finished job's feature file should CARRY.
//!
//! Split out of smart.rs rather than added to it: that file sits at its
//! TODO 106 size ceiling, and the rule is that the numbers only go down.

use super::{VIDEO_EXTS, ext_of};
use std::path::Path;

/// The video extension this path should carry: the one it already names
/// when that is a known video extension, or - for a payload that arrived
/// with no extension at all (issue #43) - the container its first bytes
/// sniff as. `None` = not a video, and the caller leaves the file alone.
///
/// A NAMED extension is authoritative and is never second-guessed; the
/// sniff is reached only by a file naming nothing at all. That is the
/// same line `nzbkit::extract::is_final_file` draws for
/// payload-over-archive names, and for the same reason: sniffing
/// everything would rename a mislabelled file out from under the name
/// its poster chose.
///
/// Deliberately NOT used by `largest_video`, which feeds the
/// keep-media-only and sample sweeps: widening what counts as a video
/// there would turn a directory those passes currently decline to touch
/// into one they will delete from. That is a different decision from
/// naming a file, and not this one's to make.
/// One MPEG-TS packet. The sync byte repeats at exactly this stride,
/// and that stride is the whole reason the format is recognisable.
const TS_PACKET: usize = 188;

/// How many consecutive packets must sync before a file is called a
/// transport stream. Four is far past coincidence and still inside one
/// read, and all four are REQUIRED: a file too short to hold them is
/// not a transport stream under any reading. Scaling the count down to
/// whatever the file happened to be long enough for accepted a single
/// 0x47 at offset 0 from anything 188 to 375 bytes long - which is one
/// byte of evidence, the very rule this constant exists to replace
/// (Codex sweep 7, M7).
const TS_SYNCS: usize = 4;

/// Fill as much of `buf` as the file has, returning how many bytes
/// landed. `read_exact` cannot be used: the buffer is now larger than
/// plenty of legitimate short headers.
fn read_head(f: &mut std::fs::File, buf: &mut [u8]) -> Option<usize> {
    use std::io::Read;
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    (n >= 12).then_some(n)
}

/// Does this head sync like an MPEG transport stream?
///
/// It used to be `head[0] == 0x47` and nothing else, which is one byte
/// of evidence: GIF87a/GIF89a open with 0x47 ("G"), as does every text
/// file starting with a capital G. A hash-named GIF beside a hash-named
/// feature therefore counted as a second video - `rename_movie` sees
/// two and skips the rename, and `tv_sort` computes one canonical
/// target for both - so an obfuscated release kept its hash because of
/// a thumbnail. A lone one was offered to the user as `Title.ts`
/// (Codex sweep 6, N6).
///
/// The sync repeating on the 188-byte stride is what actually
/// identifies the format. `container_ext` has already declined the
/// file, so nothing else is riding on this.
///
/// BDAV/m2ts, whose sync sits at offset 4 behind a timecode, is still
/// unrecognised here - a coverage gap, and the safe side of one.
fn is_transport_stream(head: &[u8]) -> bool {
    head.len() >= TS_SYNCS * TS_PACKET && (0..TS_SYNCS).all(|i| head[i * TS_PACKET] == 0x47)
}

pub(super) fn video_ext(path: &Path) -> Option<String> {
    let named = ext_of(path);
    if !named.is_empty() {
        return VIDEO_EXTS.contains(&named.as_str()).then_some(named);
    }
    use std::io::Seek;
    // Enough to carry four MPEG-TS packets, which is what makes that
    // format's one-byte sync distinguishable from any other file that
    // happens to open with 0x47. Short files simply read short.
    let mut buf = [0u8; TS_SYNCS * TS_PACKET];
    let mut f = std::fs::File::open(path).ok()?;
    let n = read_head(&mut f, &mut buf)?;
    let head: [u8; 12] = buf.get(..12)?.try_into().ok()?;
    let ext = match nzbkit::mediaprobe::container_ext(&head) {
        Some(e) => e,
        // `container_ext` knows EBML, AVI and ISO-BMFF - the containers
        // the probe can walk. It does NOT know the MPEG family, yet
        // `looks_like_video_bytes` preserves an extensionless MPEG
        // program stream or transport stream from cleanup and
        // VIDEO_EXTS names mpg/mpeg/ts/m2ts as videos. So a hash-named
        // TS payload was rescued from deletion and then skipped by
        // every rename path - kept, and still unnamed (Codex sweep 5,
        // L4). Answered here rather than by widening `container_ext`,
        // whose callers ask "can the remuxer walk this", which for these
        // two is still no.
        None if head[..4] == [0x00, 0x00, 0x01, 0xBA] => return Some("mpg".to_string()),
        None if is_transport_stream(&buf[..n]) => return Some("ts".to_string()),
        None => return None,
    };
    // Container magic cannot tell audio-only from video, and no number
    // of head bytes would fix that: `.mka` IS Matroska (DocType
    // "matroska", same as `.mkv`) and `.m4a` IS an MP4 brand. So an
    // obfuscated post that ships an external audio track beside the
    // feature - both extensionless, the ordinary issue #43 shape -
    // sniffed BOTH as video, and the two then computed the same rename
    // target: read_dir order picked a winner and the loser kept its hash
    // name. The user gets an "episode" that plays no picture. Track
    // types are the only honest discriminator, so ask for them.
    let known_size = f.metadata().ok().map(|m| m.len());
    f.rewind().ok()?;
    let hint = nzbkit::mediaprobe::ProbeHint {
        filename: None,
        known_size,
    };
    match nzbkit::mediaprobe::probe(&mut f, hint) {
        // Read to the END of every metadata region the container needed
        // AND carrying no enabled video track: audio, and not a thing to
        // name as the feature.
        //
        // `complete` is load-bearing, not belt-and-braces. `probe`
        // returns partial information as Ok - a file whose trailing
        // `moov` sits past the parser's element budget comes back Ok
        // with NO tracks seen yet - and reading that as "no video" would
        // refuse a valid extensionless feature the magic alone used to
        // accept. That is a regression rather than an uncovered format,
        // so an incomplete probe falls through to the sniff below
        // (Codex sweep 5, M10).
        Ok(info) if info.complete && !info.has_video() => None,
        // Anything else - including a probe that failed on a container
        // it could not walk - leaves the sniff standing, so #43's
        // ordinary "extensionless video" case renames exactly as before.
        _ => Some(ext.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn named_wins_bytes_only_speak_for_the_nameless() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mkv = {
            let mut v = vec![0x1A, 0x45, 0xDF, 0xA3];
            v.extend_from_slice(&[0u8; 64]);
            v
        };

        // Named video extension: taken as-is, no read at all.
        assert_eq!(
            video_ext(&at(&dir, "a.mkv", b"not really")).as_deref(),
            Some("mkv")
        );
        // Named NON-video extension: never sniffed, whatever the bytes say.
        assert_eq!(video_ext(&at(&dir, "a.nfo", &mkv)), None);
        // No extension: the bytes decide.
        assert_eq!(
            video_ext(&at(&dir, "9f2c1ab7", &mkv)).as_deref(),
            Some("mkv")
        );
        // No extension and not a container: still nothing.
        assert_eq!(video_ext(&at(&dir, "9f2c1ab8", b"just some bytes")), None);
        // Too short to carry a magic: not a container.
        assert_eq!(video_ext(&at(&dir, "9f2c1ab9", b"abc")), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The MPEG family is a video to every other part of this file, so
    /// it has to be one here too (Codex sweep 5, L4). `VIDEO_EXTS` names
    /// mpg/mpeg/ts/m2ts and `looks_like_video_bytes` rescues these two
    /// from cleanup; before this they were rescued and then never named.
    #[test]
    fn the_mpeg_family_is_nameable_without_an_extension() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vext-mpeg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut ps = vec![0x00, 0x00, 0x01, 0xBA];
        ps.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            video_ext(&at(&dir, "aa11bb22", &ps)).as_deref(),
            Some("mpg")
        );

        // TS is a 188-byte-packet stream: the sync byte at the head of
        // every packet is what identifies it, so the fixture is real
        // packets rather than a run of 0x47.
        let mut ts = Vec::new();
        for _ in 0..TS_SYNCS {
            ts.push(0x47u8);
            ts.extend_from_slice(&[0x11u8; TS_PACKET - 1]);
        }
        assert_eq!(video_ext(&at(&dir, "cc33dd44", &ts)).as_deref(), Some("ts"));

        // A named one is still judged on its name, not sniffed.
        assert_eq!(video_ext(&at(&dir, "x.nfo", &ps)), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One byte of evidence is not a transport stream.
    ///
    /// GIF87a/GIF89a opens with 0x47, and so does any text file
    /// starting with a capital G. As `head[0] == 0x47`, a hash-named
    /// thumbnail beside a hash-named feature was a SECOND video:
    /// `rename_movie` sees two candidates and leaves both alone, so an
    /// obfuscated release kept its hash because of a GIF, and a lone
    /// one was renamed to `Title.ts` and offered as playable (Codex
    /// sweep 6, N6).
    #[test]
    fn a_gif_is_not_a_transport_stream() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vext-gif-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0u8; 1024]);
        assert_eq!(
            video_ext(&at(&dir, "8b21ff03", &gif)),
            None,
            "an extensionless GIF is not a video"
        );
        assert_eq!(
            video_ext(&at(
                &dir,
                "8b21ff04",
                b"Generated by the encoder, no video here at all."
            )),
            None,
            "nor is a text file that happens to start with G"
        );
        // And the arm the 1030-byte fixture above never reached: a file
        // long enough for ONE packet and no more used to have its sync
        // count scaled down to one, which is `head[0] == 0x47` again
        // under a longer name (Codex sweep 7, M7). 188 to 375 bytes is
        // the window; 256 sits in the middle of it.
        let mut short_gif = b"GIF89a".to_vec();
        short_gif.extend_from_slice(&[0u8; 250]);
        assert_eq!(
            video_ext(&at(&dir, "8b21ff06", &short_gif)),
            None,
            "one packet of room is not four packets of evidence"
        );

        // The whole failing shape: the GIF must not make the feature
        // stop being the lone video in the directory.
        let mut feature = nzbkit::mediaprobe::testmux::mkv_full();
        feature.extend_from_slice(&[0u8; 2048]);
        std::fs::write(dir.join("8b21ff05"), &feature).unwrap();
        assert_eq!(
            crate::smart::nameless_video(&dir)
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
            Some("8b21ff05".to_string()),
            "the feature is still the only video here"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An INCOMPLETE probe is not proof of "no video".
    ///
    /// Codex sweep 5, M10, against the fix above: `probe` returns
    /// partial information as `Ok` - a valid MP4 whose `moov` sits past
    /// the parser's element budget comes back Ok with no tracks seen -
    /// and reading that as "audio" refuses a valid extensionless feature
    /// that the magic alone used to accept. That would be a REGRESSION,
    /// not an uncovered format, so the sniff has to stand whenever the
    /// probe did not finish.
    #[test]
    fn an_unfinished_probe_leaves_the_sniff_standing() {
        use nzbkit::mediaprobe::{ProbeHint, probe, testmux};
        let dir = std::env::temp_dir().join(format!("nzbfast-vext-part-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A real ftyp, then a `moov` whose declared length runs off the
        // end of the file: legal magic, tracks unreachable.
        let mut truncated = testmux::mp4box(b"ftyp", b"isom\0\0\x02\0isomiso2avc1mp41");
        truncated.extend_from_slice(&[0, 0, 0xFF, 0, b'm', b'o', b'o', b'v']);
        truncated.extend_from_slice(&[0u8; 64]);

        let p = at(&dir, "7c4d0e11", &truncated);
        // Precondition: this is the shape M10 describes - the probe
        // SUCCEEDS, reports itself incomplete, and has found no video.
        let mut f = std::fs::File::open(&p).unwrap();
        if let Ok(info) = probe(&mut f, ProbeHint::default()) {
            assert!(!info.complete, "fixture must probe incomplete");
            assert!(!info.has_video(), "fixture must have found no video yet");
        }
        // So the container magic must still speak for it.
        assert_eq!(video_ext(&p).as_deref(), Some("mp4"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An extensionless AUDIO container must not be offered as the file
    /// to name as the feature. Sweep finding, 18 Aug 2026: `.mka` is
    /// Matroska - same magic, same DocType "matroska" as `.mkv` - so the
    /// byte sniff called it video. An obfuscated post that ships an
    /// external audio track beside the feature then had two files
    /// computing the SAME rename target, `read_dir` order picked the
    /// winner, and the loser kept its hash name. Whoever won, the user
    /// could end up with an "episode" that plays no picture.
    ///
    /// The pair below is the actual failing shape, not a reduction: both
    /// files nameless, both sniffing as "mkv", distinguishable only by
    /// track type.
    #[test]
    fn a_nameless_audio_container_is_not_a_video() {
        use nzbkit::mediaprobe::testmux;
        let dir = std::env::temp_dir().join(format!("nzbfast-vext-mka-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Audio-only Matroska, no extension: refused.
        assert_eq!(video_ext(&at(&dir, "3a1f0c92", &testmux::mka())), None);

        // Its video sibling, equally nameless, still renames - the fix
        // must not cost issue #43 its whole point.
        assert_eq!(
            video_ext(&at(&dir, "3a1f0c93", &testmux::mkv_full())).as_deref(),
            Some("mkv")
        );

        // A named .mka is refused by the extension rule before any of
        // this, and a named .mkv is taken on its name without a read -
        // pinned here so the two routes cannot drift apart.
        assert_eq!(video_ext(&at(&dir, "b.mka", &testmux::mka())), None);
        assert_eq!(
            video_ext(&at(&dir, "b.mkv", &testmux::mka())).as_deref(),
            Some("mkv")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
