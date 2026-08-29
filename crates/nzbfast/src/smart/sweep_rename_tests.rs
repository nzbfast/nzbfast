//! `smart` unit tests, part 2: the junk sweep, keep-media-only, the
//! empty-directory prune, and every renaming path (movies, TV,
//! episode titles, de-obfuscation). Part 1 is tests.rs; shared
//! helpers are in testkit.rs.

use super::testkit::*;
use super::*;

/// The Supergirl case: a 56-byte extensionless scrap packed inside the
/// RAR, left beside a 20 GB feature because nothing could classify it.
/// Tests the predicate directly - driving sweep_junk would mean
/// toggling the process-global Trash flag, which races other tests.
#[test]
fn a_nameless_scrap_is_junk_only_when_the_delete_can_be_undone() {
    let dir = std::env::temp_dir().join(format!("nzbfast-scrap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let feat = 20_000_000_000u64;
    let mk = |name: &str, body: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    };

    let scrap = mk("GqRTzbOIvUzZg1hqbipRind85vn", &[b'x'; 56]);
    assert!(
        is_nameless_scrap(&scrap, "", feat, true),
        "the reported leftover"
    );
    // The whole point of the gate: permanent delete, so do not guess.
    assert!(!is_nameless_scrap(&scrap, "", feat, false));
    // No feature identified = music/books/software, where extensionless
    // files are legitimate.
    assert!(!is_nameless_scrap(&scrap, "", 0, true));

    // Must never fire on these.
    let big = mk("NoExtensionButBig", &vec![0u8; 8192]);
    assert!(
        !is_nameless_scrap(&big, "", feat, true),
        "8 KB is over the ceiling"
    );
    let named = mk("notes.xyz", b"hi");
    assert!(
        !is_nameless_scrap(&named, "xyz", feat, true),
        "an unknown ext is somebody's file"
    );
    for (n, magic) in [
        ("tiny_rar", &b"Rar!\x1a\x07\x00"[..]),
        ("tiny_zip", &b"PK\x03\x04xxxx"[..]),
        ("tiny_mkv", &b"\x1aE\xdf\xa3xxxx"[..]),
        ("tiny_pdf", &b"%PDF-1.7xx"[..]),
    ] {
        let f = mk(n, magic);
        assert!(
            !is_nameless_scrap(&f, "", feat, true),
            "{n}: magic must save it"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sweep_junk_keeps_media_and_feature() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-sweep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    // Feature is small here, but it's the largest video → protected even
    // though its name contains no "sample".
    std::fs::write(dir.join("The.Feature.mkv"), vec![0u8; 4096]).unwrap();
    std::fs::write(dir.join("The.Feature.en.srt"), b"subs").unwrap();
    for j in ["a.par2", "a.nzb", "a.sfv", "a.nfo", "info.txt", "read.url"] {
        std::fs::write(dir.join(j), b"x").unwrap();
    }
    std::fs::write(dir.join("sample.mkv"), b"clip").unwrap();
    std::fs::write(dir.join("sub/proof.mkv"), b"clip").unwrap();
    let n = sweep_junk(&dir);
    assert_eq!(n, 8, "6 furniture files + 2 sample/proof clips");
    assert!(dir.join("The.Feature.mkv").exists(), "feature kept");
    assert!(dir.join("The.Feature.en.srt").exists(), "subtitle kept");
    assert!(!dir.join("sample.mkv").exists());
    assert!(!dir.join("sub/proof.mkv").exists());
    assert!(!dir.join("a.par2").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sweep that would delete EVERY file in the release does nothing.
///
/// Found 12 Aug on the torture corpus: advO's SFX members unpacked
/// correctly and the daemon then deleted the payload, because that
/// payload is `test.txt.txt` and `.txt` is on JUNK_EXTS. The job
/// finished Completed holding two `.exe` files and nothing else, which
/// read as an unpack failure and was not one. Same premise as
/// `keep_media_only`'s no-video guard: with every file classified as
/// furniture there is nothing here to tell payload FROM, and an empty
/// output directory is the one answer that cannot be right.
#[test]
fn a_sweep_that_would_empty_the_release_is_skipped_whole() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-alljunk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The advO shape: the entire payload is a text file.
    std::fs::write(dir.join("test.txt.txt"), b"123").unwrap();
    std::fs::write(dir.join("release.nfo"), b"scene info").unwrap();
    assert_eq!(sweep_junk(&dir), 0, "nothing may be swept");
    assert!(dir.join("test.txt.txt").exists(), "the payload survives");
    assert!(
        dir.join("release.nfo").exists(),
        "all-or-nothing, not a pick"
    );

    // One real payload file beside them and the sweep behaves as before:
    // the guard is about emptying the release, not about .txt.
    std::fs::write(dir.join("payload.bin"), vec![0u8; 8192]).unwrap();
    assert_eq!(
        sweep_junk(&dir),
        2,
        "furniture goes once something survives"
    );
    assert!(dir.join("payload.bin").exists());
    assert!(!dir.join("test.txt.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Obfuscated posts write hash-named, extensionless recovery volumes
/// (the yEnc header name wins over the NZB subject), which the
/// extension list alone can't see. Reported in the wild: a whole
/// 7-volume PAR2 set left beside the episode with junk-sweep on.
#[test]
fn sweep_junk_drops_extensionless_par2_by_magic() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-obfpar2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Show.S01E02.mkv"), vec![0u8; 4096]).unwrap();
    // Hash-named recovery volumes, exactly as they land on disk.
    for h in [
        "a3fe9c80619b8674f7630bf390f2dc32",
        "f72b9763eb8f689acefad6891cbf876c",
    ] {
        let mut body = b"PAR2\x00PKT".to_vec();
        body.extend_from_slice(&[0u8; 64]);
        std::fs::write(dir.join(h), body).unwrap();
    }
    // A hash-named file that is NOT par2 stays: the magic decides,
    // not the shape of the name.
    std::fs::write(
        dir.join("cc1a4c408b0b5990ca51a83ec219bca2"),
        b"not a par2 file",
    )
    .unwrap();
    let n = sweep_junk(&dir);
    assert_eq!(n, 2, "both obfuscated recovery volumes swept");
    assert!(dir.join("Show.S01E02.mkv").exists(), "episode kept");
    assert!(!dir.join("a3fe9c80619b8674f7630bf390f2dc32").exists());
    assert!(!dir.join("f72b9763eb8f689acefad6891cbf876c").exists());
    assert!(
        dir.join("cc1a4c408b0b5990ca51a83ec219bca2").exists(),
        "non-par2 blob is not swept on name shape alone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keep_media_only_spares_all_episodes() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepmedia-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Season pack: every episode must survive, not just the largest.
    for v in ["ep01.mkv", "ep02.mkv", "ep03.mkv"] {
        std::fs::write(dir.join(v), vec![0u8; 4096]).unwrap();
    }
    std::fs::write(dir.join("ep01.srt"), b"subs").unwrap();
    for junk in ["poster.jpg", "a.par2", "notes.txt", "sample.mkv"] {
        std::fs::write(dir.join(junk), b"x").unwrap();
    }
    let n = keep_media_only(&dir);
    assert_eq!(n, 4, "jpg + par2 + txt + the sample clip");
    assert!(dir.join("ep01.mkv").exists());
    assert!(dir.join("ep02.mkv").exists());
    assert!(dir.join("ep03.mkv").exists());
    assert!(dir.join("ep01.srt").exists(), "subtitle kept");
    assert!(!dir.join("poster.jpg").exists());
    assert!(!dir.join("sample.mkv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The daemon's own `.nzbfast.*` namespace is not the job's clutter.
///
/// `keep_media_only` sweeps everything that is not media, companion or
/// archive, and neither `.nzbfast.journal` (the live resume record) nor
/// `.nzbfast.manifest` (the settle checksums a later verify reads) is
/// any of the three - so before the guard this sweep deleted both. It
/// was the ONLY directory walker in the tree that did not honour the
/// prefix; diag.rs, repair.rs and the three sites in unpack.rs all do.
///
/// The path that reaches it is the SECOND pass: an unlock re-runs the
/// whole tail over a directory the first pass already wrote them into.
#[test]
fn keep_media_only_spares_the_daemon_namespace() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("movie.mkv"), vec![0u8; 4096]).unwrap();
    std::fs::write(dir.join(".nzbfast.manifest"), b"{\"v\":1}").unwrap();
    std::fs::write(dir.join(".nzbfast.journal"), b"resume state").unwrap();
    std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
    let n = keep_media_only(&dir);
    assert_eq!(n, 1, "only the poster goes");
    assert!(
        dir.join(".nzbfast.manifest").exists(),
        "the settle manifest is ours, not the job's clutter"
    );
    assert!(
        dir.join(".nzbfast.journal").exists(),
        "the resume journal is ours too"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: keep-media-only deleted every non-video file, so an
/// archive we could not unpack - the ONLY copy of the payload - was
/// destroyed by the tidy-up that ran right after we told the user to
/// unpack it by hand. Job Completed, folder empty, nothing to show.
#[test]
fn keep_media_only_spares_still_packed_archives() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keeparc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("movie.mkv"), vec![0u8; 4096]).unwrap();
    for packed in ["extras.zip", "bonus.rar", "more.7z", "split.zip.001"] {
        std::fs::write(dir.join(packed), b"PK\x03\x04still packed").unwrap();
    }
    std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
    let n = keep_media_only(&dir);
    assert_eq!(n, 1, "only the poster goes");
    for packed in ["extras.zip", "bonus.rar", "more.7z", "split.zip.001"] {
        assert!(
            dir.join(packed).exists(),
            "{packed} is payload we could not unpack"
        );
    }
    // A .cbz is the deliverable, not packaging - but it is also not
    // media, so keep-media-only is still allowed to sweep it.
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: the same job as `keep_media_only_spares_still_packed_archives`
/// in its OBFUSCATED dress - hash names, no extensions, which is how the
/// majority of real posts arrive. `looks_like_named_rar` is a name
/// grammar, so it saw nothing here and keep-media-only deleted the entire
/// volume set: the only copy of a payload we had just told the user we
/// could not unpack. The 7z and zip shapes beside it were already sniffed;
/// only RAR was judged on its name.
///
/// This is the negative case that matters for any spent-volume cleanup:
/// the extraction did NOT succeed here (the feature beside them is a
/// sample, not the payload), so the volumes are the whole download and
/// must survive every sweep.
#[test]
fn keep_media_only_spares_obfuscated_rar_volumes() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepobf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The set we could not unpack: hash-named, extensionless, Rar! magic.
    let vols = [
        "301c0186f3bbdc58ac03a8739f989391c4",
        "a845657a411e3164c9d1e3f2c93235de3c",
        "6d248ae899f4e2bbe7b8778510c80e6053",
    ];
    for v in vols {
        let mut body = b"Rar!\x1a\x07\x01\x00".to_vec();
        body.extend_from_slice(&[0u8; 64]);
        std::fs::write(dir.join(v), body).unwrap();
    }
    // A video has to be present or the sweep declines to run at all
    // (see `keep_media_only_leaves_a_video_less_job_alone`).
    std::fs::write(dir.join("teaser.mkv"), vec![0u8; 4096]).unwrap();
    std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
    // A hash-named blob that is NOT a RAR is still clutter: the magic
    // decides, never the shape of the name.
    std::fs::write(
        dir.join("cc98d076ce474159bec6a0fe670059ee32"),
        b"not an archive",
    )
    .unwrap();
    let n = keep_media_only(&dir);
    assert_eq!(n, 2, "the poster and the non-archive blob go, nothing else");
    for v in vols {
        assert!(dir.join(v).exists(), "{v} is the only copy of the payload");
    }
    assert!(dir.join("teaser.mkv").exists());
    assert!(!dir.join("poster.jpg").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The junk sweep never removes an archive - named or obfuscated -
/// because it cannot tell a volume the job has finished with from the
/// only copy of a payload nothing unpacked. Spent volumes are the
/// extraction pass's own to remove, from its own record of what it
/// consumed; nothing that only sees the finished directory may guess.
#[test]
fn sweep_junk_never_removes_an_archive() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-sweeparc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Feature.mkv"), vec![0u8; 4096]).unwrap();
    let mut body = b"Rar!\x1a\x07\x01\x00".to_vec();
    body.extend_from_slice(&[0u8; 64]);
    std::fs::write(dir.join("301c0186f3bbdc58ac03a8739f989391c4"), &body).unwrap();
    std::fs::write(dir.join("Feature.part01.rar"), &body).unwrap();
    std::fs::write(dir.join("Feature.nfo"), b"x").unwrap();
    let n = sweep_junk(&dir);
    assert_eq!(n, 1, "only the nfo is furniture");
    assert!(dir.join("301c0186f3bbdc58ac03a8739f989391c4").exists());
    assert!(dir.join("Feature.part01.rar").exists());
    assert!(dir.join("Feature.mkv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: a bare-numeric split zip carries the magic in part 1
/// only, so the per-file guard spared `.001` and deleted `.002`
/// onward - a third of an archive, left behind a history note telling
/// the user the verified archive was waiting in the folder.
#[test]
fn keep_media_only_spares_every_part_of_a_split_zip() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepsplit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let parts = ["Movie.2019.1080p-TEST.001", "Movie.2019.1080p-TEST.002"];
    std::fs::write(dir.join(parts[0]), b"PK\x03\x04first part").unwrap();
    std::fs::write(dir.join(parts[1]), b"raw continuation bytes").unwrap();
    std::fs::write(dir.join("a.par2"), b"x").unwrap();
    // An extracted feature beside the split set the extractor could not
    // open: without a video present the sweep now declines to run at all
    // (see `keep_media_only_leaves_a_video_less_job_alone`), and this
    // test is about the zip parts, not that guard.
    std::fs::write(dir.join("Movie.2019.1080p-TEST.mkv"), vec![0u8; 4096]).unwrap();
    let n = keep_media_only(&dir);
    assert_eq!(n, 1, "only the par2 goes");
    for p in parts {
        assert!(dir.join(p).exists(), "{p} is a part of the only payload");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: keep-media-only kept videos, subtitles and still-packed
/// archives and deleted everything else with no backstop, so a release
/// whose payload is not a recognised video - a disc image, a music
/// album, an ebook - was deleted IN FULL and the job still reported
/// Completed over an empty folder. nzbkit classifies everything as
/// Movie/Tv, so a FLAC album passes the kind gate that guards this.
#[test]
fn keep_media_only_leaves_a_video_less_job_alone() {
    let _steady = trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-keepnovid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // A disc image is the payload, and its .nfo/.jpg are beside it.
    let iso = root.join("Movie.2019.BluRay.ISO");
    std::fs::create_dir_all(&iso).unwrap();
    for f in ["movie.iso", "movie.nfo", "cover.jpg"] {
        std::fs::write(iso.join(f), vec![0u8; 4096]).unwrap();
    }
    assert_eq!(
        keep_media_only(&iso),
        2,
        "the .iso IS the video; the nfo and jpg go"
    );
    assert!(iso.join("movie.iso").exists(), "the payload");
    assert!(!iso.join("cover.jpg").exists());
    assert!(!iso.join("movie.nfo").exists());

    // A music album: no video at all, so the sweep declines to run.
    let album = root.join("Adele - 30 (2021) FLAC");
    std::fs::create_dir_all(&album).unwrap();
    let tracks = [
        "01 - Strangers By Nature.flac",
        "02 - Easy On Me.flac",
        "album.cue",
        "cover.jpg",
    ];
    for f in tracks {
        std::fs::write(album.join(f), vec![0u8; 4096]).unwrap();
    }
    assert_eq!(
        keep_media_only(&album),
        0,
        "nothing here is safe to classify"
    );
    for f in tracks {
        assert!(album.join(f).exists(), "{f} is the payload, not clutter");
    }

    // Same for a book release, whatever the extension.
    let book = root.join("Some.Author.-.Some.Book.epub");
    std::fs::create_dir_all(&book).unwrap();
    std::fs::write(book.join("book.epub"), vec![0u8; 4096]).unwrap();
    std::fs::write(book.join("book.pdf"), vec![0u8; 4096]).unwrap();
    assert_eq!(keep_media_only(&book), 0);
    assert!(book.join("book.epub").exists());
    assert!(book.join("book.pdf").exists());

    // The case the no-video guard cannot catch, and the one a user
    // category makes ordinary: non-video payload WITH a video beside
    // it. A comics category declaring base Movie ships fifty .cbz
    // files and one bonus .mp4; the guard passes, and before
    // PAYLOAD_EXTS the fifty were deleted as "non-media".
    let comics = root.join("Some.Comic.Vol.01-03.2026.COMIC-GRP");
    std::fs::create_dir_all(&comics).unwrap();
    let keep = [
        "vol01.cbz",
        "vol02.cbr",
        "vol03.pdf",
        "extras.mp3",
        "read.epub",
        "album.cue",
        "bonus.mp4",
    ];
    for f in keep {
        std::fs::write(comics.join(f), vec![0u8; 4096]).unwrap();
    }
    std::fs::write(comics.join("cover.jpg"), vec![0u8; 4096]).unwrap();
    std::fs::write(comics.join("info.nfo"), vec![0u8; 4096]).unwrap();
    assert_eq!(
        keep_media_only(&comics),
        2,
        "only the jpg and nfo are clutter"
    );
    for f in keep {
        assert!(comics.join(f).exists(), "{f} is payload and was deleted");
    }

    // An audiobook set beside a bonus video: same shape, same rule.
    let audio = root.join("Author.-.Book.Audiobook.M4B");
    std::fs::create_dir_all(&audio).unwrap();
    for f in ["part1.m4b", "part2.m4b", "interview.mkv"] {
        std::fs::write(audio.join(f), vec![0u8; 4096]).unwrap();
    }
    std::fs::write(audio.join("thumbs.db"), vec![0u8; 4096]).unwrap();
    assert_eq!(keep_media_only(&audio), 1);
    assert!(audio.join("part1.m4b").exists() && audio.join("part2.m4b").exists());

    let _ = std::fs::remove_dir_all(&root);
}

/// A disc rip is unplayable with any of its structure files missing,
/// and an external audio track can be the point of the release.
#[test]
fn keep_media_only_keeps_disc_structure_and_companion_tracks() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepdisc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("feature.m2ts"), vec![0u8; 4096]).unwrap();
    let keep = [
        "index.bdmv",
        "00800.mpls",
        "VTS_01_0.ifo",
        "VTS_01_0.bup",
        "track.mka",
    ];
    for f in keep {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    std::fs::write(dir.join("cover.jpg"), b"x").unwrap();
    assert_eq!(keep_media_only(&dir), 1, "only the jpg goes");
    for f in keep {
        assert!(dir.join(f).exists(), "{f} belongs to the disc");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// keep-media-only judges by extension and deletes what it does not
/// recognise, so a hash-named payload with NO extension was removed
/// outright. One properly named video in the same folder is enough to
/// arm the sweep, and "one named file plus one hash-named one" is an
/// ordinary obfuscated-post shape - so the user lost a file with no
/// copy anywhere.
#[test]
fn keep_media_only_spares_extensionless_video_payload() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepext-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A named video arms the sweep.
    std::fs::write(dir.join("Show.S01E05.1080p.WEB.mkv"), vec![0u8; 4096]).unwrap();

    // Extensionless payload, one per container magic we accept.
    let mut mkv = vec![0x1A, 0x45, 0xDF, 0xA3];
    mkv.extend(std::iter::repeat_n(0u8, 4096));
    std::fs::write(dir.join("0aF3xQ"), &mkv).unwrap();
    let mut mp4 = vec![0u8; 4];
    mp4.extend_from_slice(b"ftypisom");
    mp4.extend(std::iter::repeat_n(0u8, 4096));
    std::fs::write(dir.join("9zZq11"), &mp4).unwrap();
    let mut avi = Vec::from(*b"RIFF\0\0\0\0AVI ");
    avi.extend(std::iter::repeat_n(0u8, 4096));
    std::fs::write(dir.join("kk22ww"), &avi).unwrap();

    // Extensionless junk that is NOT a container still goes.
    std::fs::write(dir.join("readme_no_ext"), b"just some text here").unwrap();

    let removed = keep_media_only(&dir);
    assert!(dir.join("0aF3xQ").exists(), "matroska payload must survive");
    assert!(dir.join("9zZq11").exists(), "mp4 payload must survive");
    assert!(dir.join("kk22ww").exists(), "avi payload must survive");
    assert!(
        !dir.join("readme_no_ext").exists(),
        "non-container junk still goes"
    );
    assert_eq!(removed, 1, "only the junk file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: the companion list carried ac3 and dts but not eac3,
/// which is what nearly every current Atmos or DD+ remux ships its
/// external track as. keep-media-only deleted it, the job reported
/// Completed, and the user was left with a video missing the audio
/// the release existed for - with no copy anywhere to restore from.
#[test]
fn keep_media_only_keeps_modern_external_audio_tracks() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepaudio-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Film.2024.2160p.REMUX.mkv"), vec![0u8; 4096]).unwrap();
    let tracks = [
        "Film.2024.eac3",
        "Film.2024.ec3",
        "Film.2024.truehd",
        "Film.2024.thd",
        "Film.2024.dtshd",
        "Film.2024.aac",
        "Film.2024.opus",
        "Film.2024.mp3",
        "Film.2024.wav",
    ];
    for f in tracks {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
    assert_eq!(keep_media_only(&dir), 1, "only the jpg should go");
    for f in tracks {
        assert!(
            dir.join(f).exists(),
            "{f} is the release's audio and cannot be recovered once deleted"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sweep_junk_keeps_feature_titled_proof() {
    let _steady = trash_globals_steady();
    // Regression: the 2005 film "Proof" - the feature's name contains
    // "proof" but it is the whole download and must never be swept.
    let dir = std::env::temp_dir().join(format!("nzbfast-proof-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let feat = "Proof.2005.1080p.BluRay.x264-GRP.mkv";
    std::fs::write(dir.join(feat), vec![0u8; 4096]).unwrap();
    for j in ["a.par2", "a.nfo", "info.txt"] {
        std::fs::write(dir.join(j), b"x").unwrap();
    }
    let n = sweep_junk(&dir);
    assert_eq!(n, 3, "only the 3 furniture files");
    assert!(dir.join(feat).exists(), "feature titled Proof kept");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sweep_junk_keeps_proof_season_pack() {
    let _steady = trash_globals_steady();
    // Regression: a "Proof" season pack - every episode name contains
    // "proof" and all are feature-sized. The old substring rule deleted
    // every episode (largest_video returned None -> keep=None).
    let dir = std::env::temp_dir().join(format!("nzbfast-proofpack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let eps = [
        "Proof.S01E01.1080p.mkv",
        "Proof.S01E02.1080p.mkv",
        "Proof.S01E03.1080p.mkv",
    ];
    for ep in eps {
        std::fs::write(dir.join(ep), vec![0u8; 4096]).unwrap();
    }
    std::fs::write(dir.join("a.par2"), b"x").unwrap();
    let n = sweep_junk(&dir);
    assert_eq!(n, 1, "only the par2 file");
    for ep in eps {
        assert!(dir.join(ep).exists(), "episode {ep} kept");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sweep_junk_still_drops_a_real_sample() {
    let _steady = trash_globals_steady();
    // A genuine teaser (tiny) beside a full-size feature is still swept.
    let dir = std::env::temp_dir().join(format!("nzbfast-realsample-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("The.Movie.2024.1080p.mkv"), vec![0u8; 8192]).unwrap();
    std::fs::write(dir.join("sample.mkv"), vec![0u8; 64]).unwrap(); // <15% of feature
    let n = sweep_junk(&dir);
    assert_eq!(n, 1, "the tiny sample");
    assert!(dir.join("The.Movie.2024.1080p.mkv").exists());
    assert!(!dir.join("sample.mkv").exists(), "tiny teaser swept");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sweep_junk_takes_the_emptied_sample_folder_too() {
    let _steady = trash_globals_steady();
    // The husk of a swept `Sample/` folder used to survive the sweep,
    // so a tidied job still looked untidied. A folder that still holds
    // something - here the subtitle sidecars - stays.
    let dir = std::env::temp_dir().join(format!("nzbfast-emptydir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Sample")).unwrap();
    std::fs::create_dir_all(dir.join("Subs")).unwrap();
    std::fs::create_dir_all(dir.join("Proof/inner")).unwrap();
    std::fs::write(dir.join("The.Movie.2024.1080p.mkv"), vec![0u8; 8192]).unwrap();
    std::fs::write(dir.join("Sample/sample.mkv"), vec![0u8; 64]).unwrap();
    std::fs::write(dir.join("Subs/english.srt"), b"1").unwrap();

    let n = sweep_junk(&dir);

    assert_eq!(n, 1, "the sample clip");
    assert!(!dir.join("Sample").exists(), "emptied sample folder pruned");
    assert!(
        !dir.join("Proof").exists(),
        "empty folder and its empty child pruned"
    );
    assert!(dir.join("Subs/english.srt").exists(), "subtitle kept");
    assert!(
        dir.join("Subs").exists(),
        "folder that still holds a file stays"
    );
    assert!(
        dir.join("The.Movie.2024.1080p.mkv").exists(),
        "feature kept"
    );
    assert!(dir.exists(), "the job's own directory is never pruned");
    let _ = std::fs::remove_dir_all(&dir);
}

/// macOS drops a `.DS_Store` into every folder the Finder has opened,
/// and nothing in the junk sweep can see it (no extension for
/// `JUNK_EXTS`, 6148 bytes is over `is_nameless_scrap`'s ceiling), so
/// the swept `Sample/` husk survived every download on a Mac.
#[test]
fn prune_takes_a_folder_left_holding_only_finder_droppings() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dsstore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Sample")).unwrap();
    std::fs::create_dir_all(dir.join("Proof")).unwrap();
    std::fs::write(dir.join("Sample/.DS_Store"), vec![0u8; 6148]).unwrap();
    std::fs::write(dir.join("Proof/._clip.mkv"), b"resource fork").unwrap();
    // The job's own directory keeps its .DS_Store: it is never pruned,
    // so there is nothing to clear it out of the way for.
    std::fs::write(dir.join(".DS_Store"), vec![0u8; 6148]).unwrap();

    let n = prune_empty_dirs(&dir, 0);

    assert_eq!(n, 2, "both husks");
    assert!(
        !dir.join("Sample").exists(),
        "a folder holding only .DS_Store is empty"
    );
    assert!(
        !dir.join("Proof").exists(),
        "…and so is one holding only an AppleDouble"
    );
    assert!(
        dir.join(".DS_Store").exists(),
        "the job's own dir is left alone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `._name` big enough to BE something is content, whatever the
/// prefix says. The husk sweep deletes permanently, so a mis-packed
/// archive member or a poster-named extra called `._big.mkv` must
/// survive its own folder rather than be classified away by name.
#[test]
fn prune_keeps_a_folder_holding_a_payload_sized_appledouble() {
    let dir = std::env::temp_dir().join(format!("nzbfast-adbig-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Big")).unwrap();
    std::fs::create_dir_all(dir.join("Small")).unwrap();
    std::fs::write(dir.join("Big/._big.mkv"), vec![0u8; 2 * 1024 * 1024]).unwrap();
    // The genuine article, in the same sweep: still swept.
    std::fs::write(dir.join("Small/._clip.mkv"), b"resource fork").unwrap();

    let n = prune_empty_dirs(&dir, 0);

    assert_eq!(n, 1, "only the husk");
    assert!(
        dir.join("Big/._big.mkv").exists(),
        "2 MiB is not a resource fork"
    );
    assert!(dir.join("Big").exists(), "…so its folder is not empty");
    assert!(!dir.join("Small").exists(), "a real AppleDouble still goes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// …but a dropping beside real content is not licence to delete the
/// folder, and the dropping itself stays where the folder stays.
#[test]
fn prune_keeps_a_folder_where_finder_droppings_sit_beside_content() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dskeep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Subs")).unwrap();
    std::fs::write(dir.join("Subs/.DS_Store"), vec![0u8; 6148]).unwrap();
    std::fs::write(dir.join("Subs/english.srt"), b"1").unwrap();

    assert_eq!(prune_empty_dirs(&dir, 0), 0);

    assert!(dir.join("Subs/english.srt").exists(), "content kept");
    assert!(
        dir.join("Subs/.DS_Store").exists(),
        "not ours to remove while the folder lives"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prune_stops_at_the_depth_cap() {
    // Bounds the recursion on a tree we did not build. At the cap the
    // walk simply stops: deeper empties stay, nothing panics.
    let dir = std::env::temp_dir().join(format!("nzbfast-prunedepth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut deep = dir.clone();
    for i in 0..(PRUNE_MAX_DEPTH + 2) {
        deep = deep.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    prune_empty_dirs(&dir, 0);
    assert!(
        deep.exists(),
        "below the cap the walk stops rather than recursing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tv_rename_in_place_with_suffix() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-tvrename-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    std::fs::write(dir.join(format!("{stem}.mkv")), b"v").unwrap();
    std::fs::write(dir.join("sample.mkv"), b"s").unwrap();
    let n = tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default());
    assert_eq!(n, 1);
    assert!(dir.join("My Show - S01E02 [1080p].mkv").exists());
    assert!(dir.join("sample.mkv").exists(), "sample untouched");
    // delete_filed_episode still finds the suffixed name.
    assert_eq!(
        delete_filed_episode(&dir, stem, &FiledTail::suffix(" [1080p]")).removed,
        1
    );
    assert!(!dir.join("My Show - S01E02 [1080p].mkv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rename_movie_file_and_folder() {
    let root = std::env::temp_dir().join(format!("nzbfast-mvren-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let stem = "Example.Movie.2024.1080p.BluRay.x264-FGT";
    let out = root.join(stem);
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();
    std::fs::write(out.join(format!("{stem}.en.srt")), b"subs").unwrap();
    std::fs::write(out.join("sample.mkv"), b"s").unwrap();
    let dest = rename_movie(&root, &out, "Example Movie (2024) [1080p]").unwrap();
    assert_eq!(dest, root.join("Example Movie (2024) [1080p]"));
    assert!(
        dest.join("Example Movie (2024) [1080p].mkv").exists(),
        "feature renamed"
    );
    assert!(
        dest.join("Example Movie (2024) [1080p].en.srt").exists(),
        "sub re-stemmed"
    );
    assert!(dest.join("sample.mkv").exists(), "sample untouched");
    assert!(!out.exists(), "old folder gone");
    // Collision: a second job renaming to the same base gets ".2".
    let out2 = root.join(format!("{stem}.dup"));
    std::fs::create_dir_all(&out2).unwrap();
    std::fs::write(out2.join(format!("{stem}.mkv")), b"video2").unwrap();
    let dest2 = rename_movie(&root, &out2, "Example Movie (2024) [1080p]").unwrap();
    assert_eq!(dest2, root.join("Example Movie (2024) [1080p].2"));
    // Two videos → folder renamed, files left as-is (no fold-to-one).
    let outm = root.join("Double.Feature.2001.1080p");
    std::fs::create_dir_all(&outm).unwrap();
    std::fs::write(outm.join("cd1.mkv"), b"a").unwrap();
    std::fs::write(outm.join("cd2.mkv"), b"b").unwrap();
    let destm = rename_movie(&root, &outm, "Double Feature (2001)").unwrap();
    assert!(destm.join("cd1.mkv").exists() && destm.join("cd2.mkv").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// Stage 4's movie leg emits a file stem AND a folder name. Both used
/// to go through a sanitiser that only blanked illegal glyphs, so a
/// hidden name, a name Windows truncates, or a device stem all got
/// through - while enqueue-time folder naming had already been fixed.
#[test]
fn movie_rename_emits_portable_names() {
    for (base, want) in [
        (".Hidden Movie (2024)", "Hidden Movie (2024)"),
        ("Movie (2024). ", "Movie (2024)"),
        ("CON", "_CON"),
        ("Alien: Romulus (2024)", "Alien - Romulus (2024)"),
    ] {
        let root = scratch("mvsafe");
        let out = root.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("blob.mkv"), b"v").unwrap();
        std::fs::write(out.join("blob.en.srt"), b"s").unwrap();

        let dest = rename_movie(&root, &out, base).unwrap();
        assert_eq!(dest, root.join(want), "folder for {base:?}");
        assert!(
            dest.join(format!("{want}.mkv")).exists(),
            "feature for {base:?}"
        );
        assert!(
            dest.join(format!("{want}.en.srt")).exists(),
            "sidecar for {base:?}"
        );
        assert_portable(want);
        let _ = std::fs::remove_dir_all(&root);
    }

    // Negative: an ordinary base is passed through untouched, glyph
    // for glyph - hardening must not reshape a name that was fine.
    let root = scratch("mvplain");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("blob.mkv"), b"v").unwrap();
    let plain = "The Matrix (1999) [1080p BluRay x264]-AMIABLE";
    assert_eq!(rename_movie(&root, &out, plain).unwrap(), root.join(plain));
    let _ = std::fs::remove_dir_all(&root);

    // Nothing nameable in the base: decline rather than invent a
    // placeholder folder for the job.
    let root = scratch("mvnone");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("blob.mkv"), b"v").unwrap();
    assert!(rename_movie(&root, &out, "...").is_none());
    assert!(out.join("blob.mkv").exists(), "payload untouched");
    let _ = std::fs::remove_dir_all(&root);
}

/// The de-obfuscation fallback names the video after the RELEASE, and
/// a release name is whatever the poster typed - including a leading
/// dot or a device stem.
#[test]
fn de_obfuscation_emits_a_portable_name() {
    let out = &scratch("deobf-safe");
    std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
    assert!(rename_obfuscated_video(
        out,
        ".The Movie: Part 2 2024 1080p."
    ));
    assert!(out.join("The Movie - Part 2 2024 1080p.mkv").exists());
    assert_portable("The Movie - Part 2 2024 1080p");

    // A release whose FIRST dotted component is a device name: on
    // Windows "CON.2024.….mkv" opens the console, extension and all.
    let out = &scratch("deobf-dev");
    std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
    assert!(rename_obfuscated_video(out, "CON.2024.1080p.WEB.x264-GRP"));
    assert!(out.join("_CON.2024.1080p.WEB.x264-GRP.mkv").exists());

    // Nothing nameable in the release name: leave the blob alone
    // rather than rename it to a placeholder.
    let out = &scratch("deobf-none");
    std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
    assert!(!rename_obfuscated_video(out, ". . ."));
    assert!(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv").exists());
}

/// The TV leg emits a show directory, a season directory and an
/// episode stem, all built on the show title, so the same rules apply
/// - and a device-named show directory cannot be created at all on
/// Windows.
#[test]
fn tv_paths_are_portable() {
    let (dir, base) = tv_path("CON S01E02 1080p WEB-GRP").unwrap();
    assert_eq!(dir, "_CON/Season 01");
    assert_eq!(base.as_deref(), Some("_CON - S01E02"));

    let (dir, base) = tv_path("Alien: Romulus S01E02 1080p WEB-GRP").unwrap();
    assert_eq!(dir, "Alien - Romulus/Season 01");
    assert_eq!(base.as_deref(), Some("Alien - Romulus - S01E02"));

    // Negative: an ordinary show is filed exactly as it always was.
    let (dir, base) = tv_path("The.Bear.S03E05.1080p.WEB-DL-GRP").unwrap();
    assert_eq!(dir, "The Bear/Season 03");
    assert_eq!(base.as_deref(), Some("The Bear - S03E05"));

    // Whatever the stem, every component we emit is usable. The
    // parser strips the dot shapes before they reach the sanitiser;
    // this pins that they cannot come back.
    for stem in [
        ". Hidden Show S01E02 1080p",
        "Show. S01E02 1080p",
        "CON S01E02 1080p",
        "COM1 S01E02 1080p",
        "Alien: Romulus S01E02 1080p",
    ] {
        let (dir, base) = tv_path(stem).unwrap();
        for part in dir.split('/') {
            assert_portable(part);
        }
        assert_portable(&base.unwrap());
    }
}

/// Filing and un-filing must agree on the emitted shape: the season
/// folder, the episode name and `delete_filed_episode`'s matcher all
/// derive from the same sanitised title, so a title carrying a colon
/// must round-trip.
#[test]
fn a_sanitised_show_still_files_and_unfiles() {
    let _steady = trash_globals_steady();
    let root = scratch("tvsafe");
    let stem = "Alien: Romulus S01E02 1080p WEB-GRP";
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("blob.mkv"), b"v").unwrap();

    let dest = tv_organize(
        &root.join("tv"),
        stem,
        &out,
        " [1080p]",
        &EpisodeTitles::default(),
    )
    .unwrap();
    assert_eq!(
        dest,
        root.join("tv").join("Alien - Romulus").join("Season 01")
    );
    assert!(dest.join("Alien - Romulus - S01E02 [1080p].mkv").exists());

    assert_eq!(
        delete_filed_episode(&dest, stem, &FiledTail::suffix(" [1080p]")).removed,
        1
    );
    assert!(!dest.join("Alien - Romulus - S01E02 [1080p].mkv").exists());
    let _ = std::fs::remove_dir_all(&root);
}

// -----------------------------------------------------------------
// TODO 78: episode titles in TV names.
// -----------------------------------------------------------------

/// A show whose episode list the enrichment cache already holds.
fn titles_of(eps: &[(u32, u32, &str)]) -> EpisodeTitles {
    EpisodeTitles::new(eps.iter().map(|&(s, e, n)| (s, e, n.to_string())))
}

/// The shape the whole feature exists to produce, end to end: the
/// title lands in the filed name, the job's own record of what it
/// wrote agrees with what is on disk, and both the delete and the
/// play path can still find the file afterwards.
#[test]
fn an_episode_title_reaches_the_filed_name_and_stays_findable() {
    let _steady = trash_globals_steady();
    let root = scratch("eptitle");
    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    let out = root.join("tv").join(stem);
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();
    // A subtitle posted under the release name. `tv_organize` renames
    // VIDEO_EXTS only, so this keeps the name it arrived with - the
    // documented limit of `is_rename_tail`, unchanged by titles.
    std::fs::write(out.join(format!("{stem}.en.srt")), b"subs").unwrap();
    let titles = titles_of(&[(1, 1, "Pilot"), (1, 2, "The Ceremony")]);

    let dest = tv_organize(&root.join("tv"), stem, &out, " [1080p]", &titles).unwrap();
    let filed = dest.join("My Show - S01E02 - The Ceremony [1080p].mkv");
    assert!(filed.is_file(), "the title is in the name");
    assert!(
        dest.join(format!("{stem}.en.srt")).exists(),
        "a sidecar keeps its posted name, exactly as before titles"
    );

    // What the job records is what filing wrote - the whole basis of
    // matching the file again later.
    let tail = FiledTail {
        title: filed_title_segment(stem, " [1080p]", &titles),
        suffix: " [1080p]".into(),
    };
    assert_eq!(tail.title, " - The Ceremony");
    assert_eq!(
        find_filed_episode_media(&dest, stem, &tail).as_deref(),
        Some(filed.as_path()),
        "play finds the titled episode"
    );
    assert_eq!(delete_filed_episode(&dest, stem, &tail).removed, 1);
    assert!(!filed.exists(), "and delete takes it");
    let _ = std::fs::remove_dir_all(&root);
}

/// The ordinary case, and the one that must never regress: the cache
/// does not know this episode, so the name is the one we have always
/// written - byte for byte. An empty [`EpisodeTitles`] (the setting
/// off) takes the same path.
#[test]
fn a_cache_miss_files_exactly_as_it_did_before() {
    for titles in [
        EpisodeTitles::default(),
        // Knows the show, but not this episode.
        titles_of(&[(1, 1, "Pilot"), (2, 2, "Wrong Season")]),
    ] {
        let root = scratch("epmiss");
        let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
        let out = root.join("tv").join(stem);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();

        let dest = tv_organize(&root.join("tv"), stem, &out, " [1080p]", &titles).unwrap();
        assert!(dest.join("My Show - S01E02 [1080p].mkv").is_file());
        assert_eq!(filed_title_segment(stem, " [1080p]", &titles), "");
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Multi-episode posts, Sonarr's conventions: distinct titles join
/// with " + ", and a post carrying both halves of a two-parter says
/// the shared title once.
#[test]
fn multi_episode_titles_join_and_two_parters_collapse() {
    let seg = |stem: &str, titles: &EpisodeTitles| {
        let base = tv_path(stem).and_then(|(_, b)| b).unwrap();
        titles.segment(stem, &base, " [1080p]")
    };

    let distinct = titles_of(&[(1, 1, "Pilot"), (1, 2, "Second Chances")]);
    assert_eq!(
        seg("My.Show.S01E01E02.1080p.WEB-GRP", &distinct),
        " - Pilot + Second Chances"
    );
    // The other spelling of the same range.
    assert_eq!(
        seg("My.Show.S01E01-E02.1080p.WEB-GRP", &distinct),
        " - Pilot + Second Chances"
    );

    // Two-parters, in each spelling the providers use.
    for pair in [
        ("The Ceremony (1)", "The Ceremony (2)"),
        ("The Ceremony: Part 1", "The Ceremony: Part 2"),
        ("The Ceremony, Part One", "The Ceremony, Part Two"),
        ("The Ceremony - Part I", "The Ceremony - Part II"),
    ] {
        let t = titles_of(&[(1, 1, pair.0), (1, 2, pair.1)]);
        assert_eq!(
            seg("My.Show.S01E01E02.1080p.WEB-GRP", &t),
            " - The Ceremony",
            "{pair:?} should collapse to the shared title"
        );
    }

    // A title that merely starts with "Part" is a title.
    let t = titles_of(&[(1, 1, "Part of the Plan"), (1, 2, "Parting Shot")]);
    assert_eq!(
        seg("My.Show.S01E01E02.1080p.WEB-GRP", &t),
        " - Part of the Plan + Parting Shot"
    );

    // A two-parter with nothing BUT the marker keeps both halves:
    // stripping leaves nothing to say.
    let t = titles_of(&[(1, 1, "Part 1"), (1, 2, "Part 2")]);
    assert_eq!(
        seg("My.Show.S01E01E02.1080p.WEB-GRP", &t),
        " - Part 1 + Part 2"
    );

    // A repeated title is said once; a half-known double uses what
    // the cache has.
    let t = titles_of(&[(1, 1, "Reunion"), (1, 2, "Reunion")]);
    assert_eq!(seg("My.Show.S01E01E02.1080p.WEB-GRP", &t), " - Reunion");
    let t = titles_of(&[(1, 1, "Reunion")]);
    assert_eq!(seg("My.Show.S01E01E02.1080p.WEB-GRP", &t), " - Reunion");
}

/// An episode title is a third party's free text. It reaches a
/// filename, so it gets the same treatment the show name does.
#[test]
fn a_hostile_episode_title_is_still_a_safe_filename() {
    let seg = |title: &str| {
        let t = titles_of(&[(1, 2, title)]);
        t.segment("My.Show.S01E02.1080p.WEB-GRP", "My Show - S01E02", "")
    };
    // Path separators cannot survive: this is one component.
    assert_eq!(seg("9/11: The Long Road"), " - 9 11 - The Long Road");
    assert_eq!(seg("Up\\Down"), " - Up Down");
    // Windows strips a trailing dot silently, so we strip it first.
    assert_eq!(seg("The End."), " - The End");
    // Colons expand the way Sonarr's "Smart" rule does.
    assert_eq!(seg("Endgame: Part of It"), " - Endgame - Part of It");
    // Non-ASCII is a title, not a hazard.
    assert_eq!(seg("Le Déluge"), " - Le Déluge");
    // Nothing nameable survives - no segment, and no bare separator
    // left dangling in the filename.
    assert_eq!(seg("///"), "");
    assert_eq!(seg("   "), "");
}

/// The filename budget. A title is the part that gives way: the
/// episode base identifies the episode and the suffix tells one
/// release from another, so neither can be shortened.
#[test]
fn a_long_episode_title_gives_way_to_the_name_around_it() {
    let long = "The Extremely Long Episode Title That Simply Refuses To Stop Going On \
                    And On About Whatever It Is That Happened In This Particular Instalment \
                    Of The Programme Which Nobody Could Reasonably Be Expected To Read All \
                    The Way Through In A File Manager Window";
    let titles = titles_of(&[(1, 2, long)]);
    let base = "My Show - S01E02";
    let seg = titles.segment("My.Show.S01E02.1080p.WEB-GRP", base, " [1080p]");
    let name = format!("{base}{seg} [1080p].mkv");
    assert!(
        name.len() <= COMPONENT_BYTES,
        "{} bytes is over the component limit",
        name.len()
    );
    assert!(name.ends_with(" [1080p].mkv"), "suffix and extension kept");
    assert!(
        long.starts_with(seg.trim_start_matches(TITLE_SEP)),
        "the kept part is a prefix of the real title"
    );
    assert!(
        !seg.ends_with(' ') && long[seg.len() - TITLE_SEP.len()..].starts_with(' '),
        "cut at a word boundary: {seg:?}"
    );

    // A single word longer than the whole budget is cut rather than
    // dropped - something of the title is better than none.
    let wall = "A".repeat(400);
    let titles = titles_of(&[(1, 2, &wall)]);
    let seg = titles.segment("My.Show.S01E02.1080p.WEB-GRP", base, " [1080p]");
    assert!(!seg.is_empty() && seg.len() < 240);

    // No room at all: the title is dropped, never the extension.
    let base = "X".repeat(240);
    let titles = titles_of(&[(1, 2, "Anything")]);
    assert_eq!(
        titles.segment("My.Show.S01E02.1080p.WEB-GRP", &base, ""),
        ""
    );
}

/// A title can contain anything a release name contains - "1080",
/// "S02", a group-shaped word. Filing must still find the same
/// episode when it re-reads the name it wrote, or a second
/// post-processing pass (a password unlock re-runs one) would rename
/// the file again.
#[test]
fn a_title_full_of_release_words_does_not_confuse_the_next_parse() {
    let root = scratch("eproundtrip");
    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join(format!("{stem}.mkv")), b"v").unwrap();
    let titles = titles_of(&[(1, 2, "1080 Miles to S02 BluRay")]);

    assert_eq!(tv_rename(&out, stem, " [1080p]", &titles), 1);
    let filed = out.join("My Show - S01E02 - 1080 Miles to S02 BluRay [1080p].mkv");
    assert!(filed.is_file(), "{:?}", std::fs::read_dir(&out).unwrap());

    // Re-reading our own output finds the SAME episode, so the
    // second pass is a no-op rather than a second rename.
    let written = filed.file_stem().unwrap().to_string_lossy().into_owned();
    assert_eq!(
        tv_path(&written).and_then(|(_, b)| b).as_deref(),
        Some("My Show - S01E02"),
        "the episode base survives its own title"
    );
    assert_eq!(tv_rename(&out, stem, " [1080p]", &titles), 0, "idempotent");
    assert!(filed.is_file());
    let _ = std::fs::remove_dir_all(&root);
}

/// The reason the title is RECORDED rather than recomputed, and the
/// reason `is_rename_tail` refuses a bare " - Something" tail: with
/// titles on, our filename is the same shape as the one Sonarr and
/// Plex write, and the user's own copy of the episode is sitting in
/// the same folder. Only the file we wrote may be touched.
#[test]
fn the_users_own_copy_of_the_episode_is_never_ours() {
    let _steady = trash_globals_steady();
    let root = scratch("eptheirs");
    let season = root.join("The Bear/Season 03");
    std::fs::create_dir_all(&season).unwrap();
    let theirs = season.join("The Bear - S03E05 - Children.mkv");
    let ours = season.join("The Bear - S03E05 - Children [1080p].mkv");
    // Their whole-season library, in Sonarr's default layout.
    let sibling = season.join("The Bear - S03E06 - Doors.mkv");
    for f in [&theirs, &ours, &sibling] {
        std::fs::write(f, b"x").unwrap();
    }

    let stem = "The.Bear.S03E05.1080p.WEB.h264-GRP";
    let tail = FiledTail {
        title: " - Children".into(),
        suffix: " [1080p]".into(),
    };
    assert_eq!(
        find_filed_episode_media(&season, stem, &tail).as_deref(),
        Some(ours.as_path()),
        "play serves the copy we downloaded, not theirs"
    );
    assert_eq!(delete_filed_episode(&season, stem, &tail).removed, 1);
    assert!(!ours.exists(), "ours went");
    assert!(theirs.exists(), "their copy of the same episode survives");
    assert!(sibling.exists(), "and so does the sibling episode");

    // A record with no title recorded (filed before this existed, or
    // with the setting off) matches nothing here rather than
    // guessing - a leftover, never somebody else's episode.
    assert_eq!(
        delete_filed_episode(&season, stem, &FiledTail::suffix(" [1080p]")).removed,
        0
    );
    assert!(theirs.exists() && sibling.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// A season pack renames per episode, so each file gets ITS OWN
/// title - the job's stem names no single episode and cannot answer
/// for any of them.
#[test]
fn a_season_pack_gives_every_episode_its_own_title() {
    let root = scratch("eppack");
    let stem = "My.Show.S01.1080p.WEB.x264-TEST";
    let out = root.join("tv").join(stem);
    std::fs::create_dir_all(&out).unwrap();
    for f in [
        "My.Show.S01E01.1080p.WEB.x264-TEST",
        "My.Show.S01E02.1080p.WEB.x264-TEST",
    ] {
        std::fs::write(out.join(format!("{f}.mkv")), b"v").unwrap();
    }
    let titles = titles_of(&[(1, 1, "Pilot"), (1, 2, "The Ceremony")]);

    let dest = tv_organize(&root.join("tv"), stem, &out, " [1080p]", &titles).unwrap();
    assert!(dest.join("My Show - S01E01 - Pilot [1080p].mkv").is_file());
    assert!(
        dest.join("My Show - S01E02 - The Ceremony [1080p].mkv")
            .is_file()
    );
    // The pack itself records no title: it owns no single episode
    // name, and `filed_bases` refuses it for the same reason.
    assert_eq!(filed_title_segment(stem, " [1080p]", &titles), "");
    let _ = std::fs::remove_dir_all(&root);
}

/// A library filed BEFORE the show name reshaped ("Star Trek
/// Discovery", when ':' was blanked rather than expanded) is still on
/// disk under the old spelling, and delete and play recompute the
/// base at call time. Both must still recognise it, and a new episode
/// must land in that folder rather than starting a second tree.
#[test]
fn a_show_filed_under_the_old_spelling_is_still_ours() {
    let _steady = trash_globals_steady();
    let root = scratch("tvlegacy");
    let stem = "Star Trek: Discovery S01E05 1080p WEB h264-GRP";
    let tv = root.join("tv");
    let old = tv.join("Star Trek Discovery").join("Season 01");
    std::fs::create_dir_all(&old).unwrap();
    let filed = old.join("Star Trek Discovery - S01E05 [1080p].mkv");
    std::fs::write(&filed, b"v").unwrap();

    // Play finds the episode it filed, under either spelling.
    assert_eq!(
        find_filed_episode_media(&old, stem, &FiledTail::suffix(" [1080p]")).as_ref(),
        Some(&filed)
    );

    // A later episode joins the show it belongs to.
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("blob.mkv"), b"v").unwrap();
    let dest = tv_organize(
        &tv,
        "Star Trek: Discovery S01E06 1080p WEB h264-GRP",
        &out,
        " [1080p]",
        &EpisodeTitles::default(),
    )
    .unwrap();
    assert_eq!(dest, old);
    assert!(
        old.join("Star Trek Discovery - S01E06 [1080p].mkv")
            .exists()
    );
    assert!(!tv.join("Star Trek - Discovery").exists(), "no second tree");

    // A NEW season of the same show joins it as well: the folder that
    // decides is the show's, not the season's.
    let out = root.join("job2");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("blob.mkv"), b"v").unwrap();
    let dest = tv_organize(
        &tv,
        "Star Trek: Discovery S02E01 1080p WEB h264-GRP",
        &out,
        " [1080p]",
        &EpisodeTitles::default(),
    )
    .unwrap();
    assert_eq!(dest, tv.join("Star Trek Discovery").join("Season 02"));
    assert!(
        !tv.join("Star Trek - Discovery").exists(),
        "still no second tree"
    );

    // ...and delete-with-files removes the old-spelling episode
    // rather than reporting zero and leaving it behind. E06 stays.
    assert_eq!(
        delete_filed_episode(&old, stem, &FiledTail::suffix(" [1080p]")).removed,
        1
    );
    assert!(!filed.exists());
    assert!(
        old.join("Star Trek Discovery - S01E06 [1080p].mkv")
            .exists()
    );

    // Nothing on disk to inherit: today's spelling is what we write.
    let fresh = scratch("tvfresh");
    let out = fresh.join("job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("blob.mkv"), b"v").unwrap();
    let dest = tv_organize(
        &fresh.join("tv"),
        stem,
        &out,
        " [1080p]",
        &EpisodeTitles::default(),
    )
    .unwrap();
    assert_eq!(
        dest,
        fresh
            .join("tv")
            .join("Star Trek - Discovery")
            .join("Season 01")
    );
    assert!(
        dest.join("Star Trek - Discovery - S01E05 [1080p].mkv")
            .exists()
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&fresh);
}

/// Scratch dir without pulling a dev-dependency into the binary
/// target (smart.rs's tests live in the bin, which has none).
#[test]
fn the_container_outranks_the_name() {
    // The main video's own header answers; the name's claim is the
    // caller's business (finalize_names decides what to do with a
    // disagreement).
    let dir = scratch("measured");
    std::fs::write(
        dir.join("Example.Movie.2024.1080p.mkv"),
        nzbkit::mkv::test_mux(Some(5400.0), Some((1280, 720))),
    )
    .unwrap();
    assert_eq!(measured_res(&dir), Some("720p"));

    // Non-Matroska main video: never probed, never guessed.
    let dir = scratch("measured-mp4");
    std::fs::write(
        dir.join("Example.Movie.2024.mp4"),
        b"\x00\x00\x00\x20ftypisom",
    )
    .unwrap();
    assert_eq!(measured_res(&dir), None);

    // A Matroska that does not parse keeps the claim standing.
    let dir = scratch("measured-junk");
    std::fs::write(dir.join("Example.Movie.2024.mkv"), b"not matroska").unwrap();
    assert_eq!(measured_res(&dir), None);
}

#[test]
fn a_sample_name_running_like_an_episode_survives() {
    let dir = scratch("sample-veto");
    // Small beside the feature, "sample" in the name - but its own
    // header says 50 minutes. That is an episode, not a clip.
    let episode = dir.join("Show.S01E02.sample.mkv");
    std::fs::write(
        &episode,
        nzbkit::mkv::test_mux(Some(50.0 * 60.0), Some((1920, 1080))),
    )
    .unwrap();
    assert!(!is_deletable_sample(&episode, 1 << 30));

    // A real 45-second clip with the same shape still goes.
    let clip = dir.join("Show.S01E02.sample2.mkv");
    std::fs::write(&clip, nzbkit::mkv::test_mux(Some(45.0), Some((1920, 1080)))).unwrap();
    assert!(is_deletable_sample(&clip, 1 << 30));

    // No readable duration: the old name+size verdict stands.
    let blob = dir.join("Show.S01E02.sample3.mkv");
    std::fs::write(&blob, b"junk").unwrap();
    assert!(is_deletable_sample(&blob, 1 << 30));
}

/// The 1.0.9 report: an F1 round finished as
/// "1fRbH6e0eX8v5hv7fSyXgBb.mkv" with every rename option ticked.
/// movie_name declines on event posts by design (renaming each round
/// to "Formula1 (2026)" would collide), but declining must not leave
/// an obfuscated stem when the release name is right there.
#[test]
fn obfuscated_video_takes_the_release_name() {
    let out = &scratch("f1");
    let rel = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR";
    std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"video").unwrap();
    std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.en.srt"), b"subs").unwrap();

    assert!(rename_obfuscated_video(out, rel));
    assert!(
        out.join(format!("{rel}.mkv")).exists(),
        "video takes the release name"
    );
    assert!(
        out.join(format!("{rel}.en.srt")).exists(),
        "sidecar follows, keeping .en"
    );
    assert!(!out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv").exists());
}

#[test]
fn de_obfuscation_leaves_named_and_ambiguous_payloads_alone() {
    let out = &scratch("keep");
    let rel = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p-MWR";

    // A stem the poster actually chose is never overwritten.
    let posted = "Formula1.2026.Round11.Hungary.Race.1080p.mkv";
    std::fs::write(out.join(posted), b"v").unwrap();
    assert!(!rename_obfuscated_video(out, rel));
    assert!(out.join(posted).exists());

    // Two videos: we cannot tell which is "the" file, so do nothing.
    std::fs::remove_file(out.join(posted)).unwrap();
    std::fs::write(out.join("aQ7bZ1x9KpLmNv.mkv"), b"v").unwrap();
    std::fs::write(out.join("bR8cY2y0LqMnOw.mkv"), b"v").unwrap();
    assert!(!rename_obfuscated_video(out, rel));
    assert!(out.join("aQ7bZ1x9KpLmNv.mkv").exists());

    // An obfuscated RELEASE name is no better than the file's own.
    std::fs::remove_file(out.join("bR8cY2y0LqMnOw.mkv")).unwrap();
    assert!(!rename_obfuscated_video(out, "n1iY94U6fTpMVY9GPD"));
    assert!(out.join("aQ7bZ1x9KpLmNv.mkv").exists());

    // A run-together title that happens to be 32 characters long is
    // a name somebody chose, not an md5 - the hash shape is hex.
    let out = &scratch("keep32");
    let long = "ThelordoftheringsReturnoftheking.mkv";
    std::fs::write(out.join(long), b"v").unwrap();
    assert!(!rename_obfuscated_video(out, rel));
    assert!(out.join(long).exists());
}

/// The question synthesised naming asks BEFORE it spends a disk read
/// or a request: is there anything here still wearing a hash?
///
/// It has to answer exactly what `rename_obfuscated_video` fires on,
/// because the two now share an apply path - a disagreement would
/// mean the identifier looked up a film it could never rename, or
/// skipped one it could.
#[test]
fn nameless_video_finds_only_what_is_actually_nameless() {
    // Obfuscated stem: nameless.
    let out = &scratch("nameless-hash");
    std::fs::write(out.join("n1iY94U6fTpMVY9GPD.mkv"), b"v").unwrap();
    assert_eq!(
        nameless_video(out).unwrap().file_name().unwrap(),
        "n1iY94U6fTpMVY9GPD.mkv"
    );

    // Encoder default: nameless too.
    let out = &scratch("nameless-generic");
    std::fs::write(out.join("movie.mp4"), b"v").unwrap();
    assert!(nameless_video(out).is_some());

    // A name a human chose stands, whatever a catalogue might offer.
    let out = &scratch("nameless-named");
    std::fs::write(out.join("Example.Movie.2024.1080p.WEB.x264-GRP.mkv"), b"v").unwrap();
    assert_eq!(nameless_video(out), None);

    // Two videos: we cannot tell which is the feature, so neither is
    // renamed and no lookup is worth making.
    let out = &scratch("nameless-two");
    std::fs::write(out.join("aaaaaaaaaaaaaaaaaa.mkv"), b"v").unwrap();
    std::fs::write(out.join("bbbbbbbbbbbbbbbbbb.mkv"), b"v").unwrap();
    assert_eq!(nameless_video(out), None);

    // A sample clip is not the feature and never counts as one.
    let out = &scratch("nameless-sample");
    std::fs::write(out.join("n1iY94U6fTpMVY9GPD.mkv"), b"v").unwrap();
    std::fs::write(out.join("sample.mkv"), b"v").unwrap();
    assert!(nameless_video(out).is_some());

    // Nothing video-shaped at all.
    let out = &scratch("nameless-none");
    std::fs::write(out.join("readme.nfo"), b"n").unwrap();
    assert_eq!(nameless_video(out), None);
}

/// An identified film's name reaches the payload through the bare
/// apply path, NOT through the release-name one - "Supergirl 2026"
/// carries no resolution, source or group, so `names_the_release`
/// refuses it and always would. The gate is what earned it.
#[test]
fn an_identified_title_renames_where_a_release_name_could_not() {
    let title = "Supergirl 2026";
    let out = &scratch("identified");
    std::fs::write(out.join("n1iY94U6fTpMVY9GPD.mkv"), b"v").unwrap();
    std::fs::write(out.join("n1iY94U6fTpMVY9GPD.en.srt"), b"s").unwrap();

    // The release-name path declines it, as designed.
    assert!(!rename_obfuscated_video(out, title));
    assert!(out.join("n1iY94U6fTpMVY9GPD.mkv").exists(), "nothing moved");

    // The identified path applies it, sidecar and all.
    assert!(rename_nameless_video(out, title));
    assert!(out.join("Supergirl 2026.mkv").exists());
    assert!(
        out.join("Supergirl 2026.en.srt").exists(),
        "sidecar follows"
    );

    // ...and it still refuses a payload that was never nameless, so
    // a wrong verdict cannot overwrite a name the poster gave.
    let out = &scratch("identified-named");
    std::fs::write(out.join("Example.Movie.2024.1080p.WEB-GRP.mkv"), b"v").unwrap();
    assert!(!rename_nameless_video(out, title));
    assert!(out.join("Example.Movie.2024.1080p.WEB-GRP.mkv").exists());
}

/// A stem that is not obfuscated but says nothing - the encoder's
/// default output name - is the other half of the same problem, and
/// the widened gate has to pay for itself on the release side.
#[test]
fn de_obfuscation_replaces_a_generic_stem() {
    let rel = "Example.Movie.2024.1080p.WEB.x264-GRP";

    // "movie.mkv" beside a release name carrying real facts.
    let out = &scratch("generic");
    std::fs::write(out.join("movie.mkv"), b"v").unwrap();
    std::fs::write(out.join("movie.en.srt"), b"s").unwrap();
    assert!(rename_obfuscated_video(out, rel));
    assert!(out.join(format!("{rel}.mkv")).exists());
    assert!(
        out.join(format!("{rel}.en.srt")).exists(),
        "sidecar follows"
    );

    for stem in ["video", "FILM", "output", "encoded", "media", "1", "07"] {
        let out = &scratch("generic-list");
        std::fs::write(out.join(format!("{stem}.mkv")), b"v").unwrap();
        assert!(rename_obfuscated_video(out, rel), "{stem}");
        assert!(out.join(format!("{rel}.mkv")).exists(), "{stem}");
    }

    // Negative: a real name is not generic, so it stands - even
    // though it names the same release we would have written.
    let out = &scratch("generic-real");
    std::fs::write(out.join("Example.Movie.2024.mkv"), b"v").unwrap();
    assert!(!rename_obfuscated_video(out, rel));
    assert!(out.join("Example.Movie.2024.mkv").exists());

    // Negative: near-misses of the generic list keep their names -
    // the list is exact, not a prefix or substring match.
    for stem in [
        "movie2",
        "video_final",
        "Movie 2024",
        "encode",
        "media server",
    ] {
        let out = &scratch("generic-near");
        std::fs::write(out.join(format!("{stem}.mkv")), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, rel), "{stem}");
        assert!(out.join(format!("{stem}.mkv")).exists(), "{stem}");
    }
}

/// A one-digit generic stem is a PREFIX of its numbered neighbours,
/// so the sidecar carry has to stop at an extension boundary: "1.mkv"
/// owns "1.srt" and nothing else. Before the boundary check "10.srt"
/// came out as "…-GRP0.srt" - a mangled name for a subtitle that was
/// never this video's.
#[test]
fn sidecars_are_carried_only_at_an_extension_boundary() {
    let rel = "Example.Movie.2024.1080p.WEB.x264-GRP";
    let out = &scratch("sidecar-boundary");
    std::fs::write(out.join("1.mkv"), b"v").unwrap();
    std::fs::write(out.join("1.srt"), b"s").unwrap();
    std::fs::write(out.join("1.en.srt"), b"s").unwrap();
    std::fs::write(out.join("10.srt"), b"s").unwrap();
    std::fs::write(out.join("12.srt"), b"s").unwrap();

    assert!(rename_obfuscated_video(out, rel));
    assert!(out.join(format!("{rel}.mkv")).exists());
    assert!(
        out.join(format!("{rel}.srt")).exists(),
        "its own sidecar follows"
    );
    assert!(
        out.join(format!("{rel}.en.srt")).exists(),
        "language tail kept"
    );
    // The neighbours are untouched, and no fused name was emitted.
    assert!(out.join("10.srt").exists());
    assert!(out.join("12.srt").exists());
    assert!(!out.join(format!("{rel}0.srt")).exists());
    assert!(!out.join(format!("{rel}2.srt")).exists());

    // Same rule on the movie path, which had the latent form.
    let parent = &scratch("sidecar-boundary-movie");
    let out = &parent.join("job");
    std::fs::create_dir_all(out).unwrap();
    std::fs::write(out.join("1.mkv"), b"v").unwrap();
    std::fs::write(out.join("1.srt"), b"s").unwrap();
    std::fs::write(out.join("10.srt"), b"s").unwrap();
    rename_movie(parent, out, "Example Movie (2024)");
    let dest = parent.join("Example Movie (2024)");
    assert!(dest.join("Example Movie (2024).srt").exists());
    assert!(dest.join("10.srt").exists());
    assert!(!dest.join("Example Movie (2024)0.srt").exists());
}

/// The widened firing condition is only safe because the release
/// name now has to earn it: a title with no resolution, no source
/// and no group is a folder label, not a release, and we decline.
#[test]
fn a_factless_release_name_never_renames() {
    for rel in ["Example Movie", "Some Show", "Holiday 2024"] {
        let out = &scratch("factless");
        std::fs::write(out.join("movie.mkv"), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, rel), "{rel}");
        assert!(out.join("movie.mkv").exists(), "{rel}");

        // Same gate, obfuscated stem: widening did not weaken the
        // long-standing path, it tightened it.
        let out = &scratch("factless-obf");
        std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, rel), "{rel}");
    }

    // Positive control: one hard fact is enough.
    for rel in [
        "Example Movie 1080p",
        "Example Movie WEB-DL",
        "Example.Movie-GRP",
    ] {
        let out = &scratch("factful");
        std::fs::write(out.join("movie.mkv"), b"v").unwrap();
        assert!(rename_obfuscated_video(out, rel), "{rel}");
    }
}

#[test]
fn name_password_conventions() {
    // Double brace (SAB/NZBGet) - the long-standing convention.
    assert_eq!(
        name_password("Rel.Name.2020{{s3cret}}"),
        Some(("s3cret".into(), "Rel.Name.2020".into()))
    );
    // §7b: single brace and password= are recognized AND stripped so
    // the wrapper can't leak a password into the output folder name.
    assert_eq!(
        name_password("Rel.Name.2020{s3cret}"),
        Some(("s3cret".into(), "Rel.Name.2020".into()))
    );
    assert_eq!(
        name_password("Rel.Name.2020 password=s3cret"),
        Some(("s3cret".into(), "Rel.Name.2020".into()))
    );
    assert_eq!(
        name_password("Rel.Name.2020{password=s3cret}"),
        Some(("s3cret".into(), "Rel.Name.2020".into()))
    );
    // Double brace wins when nested; plain names pass through.
    assert_eq!(name_password("Rel{{a}}").map(|(p, _)| p), Some("a".into()));
    assert_eq!(name_password("Plain.Release.2020.1080p"), None);
    assert_eq!(name_password("Rel{}"), None); // empty braces = nothing
}

/// Twelve bytes of Matroska: the EBML magic plus enough padding that a
/// head read of a real container's length succeeds. Body content is
/// irrelevant - every path under test sniffs the head and nothing else.
fn mkv_bytes() -> Vec<u8> {
    let mut v = vec![0x1A, 0x45, 0xDF, 0xA3];
    v.extend_from_slice(&[0u8; 64]);
    v
}

/// Issue #43, the reporter's exact shape: an indexer that obfuscates
/// the filenames INSIDE the NZB posts the feature as a bare hash with
/// no extension at all. The PAR2 set on that report covered only the
/// NFO, so PAR2 deobfuscation named the NFO and had nothing to say
/// about the feature - which then reached `tv_rename` still nameless
/// and was skipped, because an empty extension is not in `VIDEO_EXTS`.
///
/// The release name was never in doubt: it named the directory
/// correctly the whole time.
#[test]
fn an_extensionless_obfuscated_episode_is_renamed_from_the_release() {
    let root = scratch("issue43-tv");
    let stem = "Reacher.S04E03.GERMAN.DL.1080P.WEB.H264-WAYNE";
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    let hash = "86d19367bf4e808ece4c08397985233152af296813a8";
    std::fs::write(out.join(hash), mkv_bytes()).unwrap();

    assert_eq!(
        tv_rename(&out, stem, "", &EpisodeTitles::default()),
        1,
        "the feature is renamed, not skipped for having no extension"
    );
    let filed = out.join("Reacher - S04E03.mkv");
    assert!(
        filed.is_file(),
        "expected {filed:?}, dir holds {:?}",
        std::fs::read_dir(&out)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );
    assert!(!out.join(hash).exists(), "the hash name is gone");
    let _ = std::fs::remove_dir_all(&root);
}

/// The same payload shape down the movie / no-kind arm, which reaches
/// the release name through `rename_obfuscated_video`. The extension
/// has to come from the BYTES: taking it from the (empty) on-disk one
/// produced a trailing-dot name that no player would open.
#[test]
fn an_extensionless_obfuscated_feature_takes_the_release_name_and_a_real_extension() {
    let out = &scratch("issue43-movie");
    let rel = "Example.Movie.2024.1080p.BluRay.x264-GRP";
    let hash = "0f3a91c4bd77e25a8c1b60de4f2a9917";
    std::fs::write(out.join(hash), mkv_bytes()).unwrap();
    std::fs::write(out.join(format!("{hash}.en.srt")), b"subs").unwrap();

    assert!(rename_obfuscated_video(out, rel));
    assert!(
        out.join(format!("{rel}.mkv")).exists(),
        "sniffed .mkv, not a trailing dot"
    );
    assert!(
        out.join(format!("{rel}.en.srt")).exists(),
        "the sidecar still follows a stem that never had an extension"
    );
    assert!(!out.join(hash).exists());
}

/// The guard that keeps this from being a licence to sniff everything.
/// A NAMED extension is authoritative: a file called `.nfo` or `.txt`
/// is not a video however its bytes open, so no rename pass may claim
/// it. Only a file naming NOTHING gets the magic.
#[test]
fn a_named_extension_is_never_second_guessed_by_the_sniff() {
    let out = &scratch("issue43-named");
    // Matroska bytes wearing a .nfo name: still not the feature.
    std::fs::write(out.join("a3f9c2e1b7d04839.nfo"), mkv_bytes()).unwrap();
    assert_eq!(
        nameless_video(out),
        None,
        "a named non-video extension is not sniffed into being a video"
    );
    assert!(!rename_obfuscated_video(
        out,
        "Example.Movie.2024.1080p.BluRay.x264-GRP"
    ));
    assert!(out.join("a3f9c2e1b7d04839.nfo").exists());

    // And an extensionless file that is NOT a container stays put too.
    let out = &scratch("issue43-notvideo");
    std::fs::write(out.join("b4e0d1a2c3f59687"), b"just some bytes here").unwrap();
    assert_eq!(nameless_video(out), None);
}

/// Codex sweep 5, M1/M2/M4: the issue-43 extensionless classifier
/// reached `tv_rename` and nothing else, so every OTHER naming route
/// still selected by extension and walked straight past the very file
/// the job is about.
///
/// Each arm below is a route Codex named, driven through its own
/// function rather than through a fixture with a named `.mkv` - which
/// is exactly why the original #43 tests missed all three.
#[test]
fn every_naming_route_can_see_an_extensionless_feature() {
    let _steady = trash_globals_steady();
    let root = scratch("extless");
    // Real EBML so `video_ext` sniffs it, big enough to beat a sample.
    let mkv = |n: usize| {
        let mut v = vec![0x1A, 0x45, 0xDF, 0xA3];
        v.extend(std::iter::repeat_n(0u8, n));
        v
    };

    // --- M1: season filing must give it the canonical episode NAME ---
    let out = root.join("job1");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("9f2c1ab7d0"), mkv(4096)).unwrap();
    let dest = tv_organize(
        &root.join("tv"),
        "Some Show S01E02 1080p WEB-GRP",
        &out,
        "",
        &EpisodeTitles::default(),
    )
    .expect("filed");
    assert!(
        dest.join("Some Show - S01E02.mkv").exists(),
        "an extensionless episode must arrive in the shared season folder \
         under the canonical name, or Play and delete cannot own it; got {:?}",
        std::fs::read_dir(&dest)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );

    // --- M2: the ordinary movie arm must rename the FILE, not just the folder ---
    let mov = root.join("Some.Movie.2019.1080p-GRP");
    std::fs::create_dir_all(&mov).unwrap();
    std::fs::write(mov.join("a1b2c3d4e5"), mkv(4096)).unwrap();
    let moved = rename_movie(&root, &mov, "Some Movie (2019)").expect("renamed dir");
    assert!(
        moved.join("Some Movie (2019).mkv").exists(),
        "the movie route renamed the folder and left the feature under its hash; got {:?}",
        std::fs::read_dir(&moved)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );

    // --- M4: a nameless SAMPLE must not win the episode name ---
    let two = root.join("job2");
    std::fs::create_dir_all(&two).unwrap();
    // Written sample-first so read_dir order favours the wrong file on
    // any filesystem that preserves creation order.
    std::fs::write(two.join("sample"), mkv(64)).unwrap();
    std::fs::write(two.join("ff00ee11dd"), mkv(8192)).unwrap();
    assert_eq!(
        tv_rename(
            &two,
            "Some Show S01E03 1080p WEB-GRP",
            "",
            &EpisodeTitles::default()
        ),
        1,
        "exactly one file may take the canonical name"
    );
    let named = two.join("Some Show - S01E03.mkv");
    assert!(named.exists(), "the feature must be the one that got named");
    assert_eq!(
        std::fs::metadata(&named).unwrap().len(),
        mkv(8192).len() as u64,
        "the FEATURE took the episode name, not the sample"
    );
    assert!(
        two.join("sample").exists(),
        "the sample keeps its own name rather than being renamed"
    );
}

/// Codex sweep 6, N1: sweep 5's M4 fix reached `tv_rename` and season
/// filing, and left the other two selectors on the extension-gated
/// predicate.
///
/// `nameless_video` is what identify and synthesised naming ask before
/// they spend any network, and `main_payload` is what the .nzb-name
/// route renames. Both counted an extensionless `sample` as ordinary
/// payload, so the feature stayed hashed on one route and the teaser
/// took the release name on the other.
#[test]
fn an_extensionless_sample_loses_the_other_naming_routes_too() {
    let root = scratch("extless-sample");
    let mkv = |n: usize| {
        let mut v = vec![0x1A, 0x45, 0xDF, 0xA3];
        v.extend(std::iter::repeat_n(0u8, n));
        v
    };

    // --- identify / synthesised naming: the feature is still lone ---
    let one = root.join("job1");
    std::fs::create_dir_all(&one).unwrap();
    // Sample first, so read_dir order favours the wrong answer.
    std::fs::write(one.join("sample"), mkv(64)).unwrap();
    std::fs::write(one.join("c0ffee1234"), mkv(8192)).unwrap();
    assert_eq!(
        nameless_video(&one).and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        Some("c0ffee1234".to_string()),
        "two videos means 'cannot tell', so the feature never gets identified at all"
    );

    // --- the .nzb-name route: the teaser is not the main file ---
    // The feature is still PACKED, which is furniture by design, so the
    // sample is the largest thing left - the shape where the name
    // actually lands on it.
    let two = root.join("Some.Release.2024-GRP");
    std::fs::create_dir_all(&two).unwrap();
    std::fs::write(two.join("sample"), mkv(4096)).unwrap();
    std::fs::write(two.join("payload.part01.rar"), vec![0u8; 65_536]).unwrap();
    // The folder takes the name either way; only the FILE is at issue.
    let two = nzbname::rename_from_nzb(&root, &two, "Some Release 2024 GRP.nzb").unwrap_or(two);
    assert!(
        two.join("sample").exists(),
        "the sample keeps its own name; got {:?}",
        std::fs::read_dir(&two)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );
    assert!(
        !two.join("Some Release 2024 GRP.mkv").exists(),
        "and the release name was not put on a teaser"
    );
}

/// Regression (TODO 262's "Left open"): a numbered BYTE SPLIT of a
/// container - `hash.001`, `hash.002`, ... where only part 1 carries the
/// archive's head - lost every part after the first to keep-media-only.
///
/// The zip twin of this was fixed by asking the directory
/// (`keep_media_only_spares_every_part_of_a_split_zip`); the 7z and RAR
/// twins were not, because `sevenz_archive_part` and
/// `looks_like_named_rar` are per-PATH questions and parts 2..=n are raw
/// continuation bytes with nothing in the name or the head to answer
/// them with. So the sweep kept the head and deleted the payload behind
/// it, leaving a stub that still looks like an archive.
#[test]
fn keep_media_only_spares_every_part_of_an_obfuscated_container_split() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keepcsplit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Part 1 opens with the container's head; the rest are the bytes that
    // follow it, uniform-sized the way a byte splitter writes them.
    let mut sevenz = b"7z\xbc\xaf\x27\x1c".to_vec();
    sevenz.resize(4096, 0);
    let mut rar = b"Rar!\x1a\x07\x01\x00".to_vec();
    rar.resize(4096, 0);
    let sets = [
        ("301c0186f3bbdc58ac03a8739f989391c4", sevenz),
        ("a845657a411e3164c9d1e3f2c93235de3c", rar),
    ];
    for (base, head) in &sets {
        std::fs::write(dir.join(format!("{base}.001")), head).unwrap();
        std::fs::write(dir.join(format!("{base}.002")), vec![b'x'; 4096]).unwrap();
        std::fs::write(dir.join(format!("{base}.003")), vec![b'x'; 512]).unwrap();
    }
    // A video has to be present or the sweep declines to run at all
    // (see `keep_media_only_leaves_a_video_less_job_alone`).
    std::fs::write(dir.join("teaser.mkv"), vec![0u8; 4096]).unwrap();
    std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
    // Membership is not "keep anything numbered": a lone numbered blob
    // belongs to no set and is still clutter.
    std::fs::write(dir.join("cc98d076ce474159bec6a0fe670059ee32.001"), b"x").unwrap();
    let n = keep_media_only(&dir);
    for (base, _) in &sets {
        for idx in ["001", "002", "003"] {
            assert!(
                dir.join(format!("{base}.{idx}")).exists(),
                "{base}.{idx} is a part of the only copy of the payload"
            );
        }
    }
    assert_eq!(n, 2, "the poster and the set-less blob go, nothing else");
    assert!(dir.join("teaser.mkv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression (TODO 299's "Left open", closed by §301): the PLAIN
/// reading of the shape above - a numbered byte split with NO archive
/// head on ANY part - and the more destructive of the two.
///
/// The container twin lost all-but-one part, because part 1 could still
/// answer for itself. Here no member can: carrying a head is exactly what
/// disqualifies a set from this reading, so every per-path question
/// `is_packed_archive` asks answers "not an archive" and the sweep took
/// the WHOLE set. `crate::split_part_set` records the three routes that
/// reach this pass with a set still unjoined - none of them a failed
/// join, which fails the job outright and never reaches the sweep at all.
#[test]
fn keep_media_only_spares_every_part_of_a_plain_split() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-keeppsplit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Uniform parts, gapless from 1, and no archive head anywhere - the
    // whole payload is raw bytes, which is what makes the set invisible
    // one file at a time.
    for (idx, len) in [("001", 4096), ("002", 4096), ("003", 512)] {
        std::fs::write(dir.join(format!("Bonus.mkv.{idx}")), vec![b'x'; len]).unwrap();
    }
    // A video has to be present or the sweep declines to run at all
    // (see `keep_media_only_leaves_a_video_less_job_alone`).
    std::fs::write(dir.join("teaser.mkv"), vec![0u8; 4096]).unwrap();
    std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
    // Membership is not "keep anything numbered": a lone numbered blob
    // belongs to no set and is still clutter.
    std::fs::write(dir.join("cc98d076ce474159bec6a0fe670059ee32.001"), b"x").unwrap();
    let n = keep_media_only(&dir);
    for idx in ["001", "002", "003"] {
        assert!(
            dir.join(format!("Bonus.mkv.{idx}")).exists(),
            "Bonus.mkv.{idx} is a part of the only copy of the payload"
        );
    }
    assert_eq!(n, 2, "the poster and the set-less blob go, nothing else");
    assert!(dir.join("teaser.mkv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
