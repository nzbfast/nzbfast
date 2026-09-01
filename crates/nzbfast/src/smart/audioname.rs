//! Naming an obfuscated music track from the tags it arrived carrying.
//!
//! The audio half of issue #43's answer, reported as issue #55: an album
//! posted with obfuscated names lands as a directory of hashes, and
//! every naming pass this crate has is about video.
//!
//! ## What names a track, and in what order
//!
//! Two sources run before this one and neither needs anything here:
//!
//! 1. The PAR2 recovery set, whose FileDesc name is MD5-proven. The
//!    download path renames off it as each slot settles, for payload of
//!    any kind. When the set covers the file, that name stands and this
//!    pass never sees an obfuscated stem to replace.
//! 2. The NZB subject, which is where the on-disk name came from in the
//!    first place. When it is obfuscated there is nothing further in it
//!    to read - the hash on disk IS the subject's answer.
//!
//! What is left is the file's own tags, which is a poster's metadata
//! rather than an inference: the track says what it is called. That is
//! the whole of the evidence this module uses.
//!
//! ## What it refuses
//!
//! A wrong name is worse than an obfuscated one, so every one of these
//! leaves the file exactly as it arrived: a stem that is not obfuscated
//! (a name a human chose stands, whatever a tag says), a named
//! extension that is not audio, bytes that do not sniff as a format
//! [`nzbkit::audiotag`] can read, a tag block with no title in it, a
//! composed name that is itself obfuscated or says nothing, a target
//! that already exists, and - the one that matters most on a
//! compilation - two tracks whose tags compose the SAME name, where
//! both are left alone rather than letting `read_dir` order pick a
//! winner.
//!
//! Deliberately NOT wired into `largest_video` or any cleanup pass, for
//! the reason [`super::videoext`] gives: widening what counts as media
//! there turns a directory those passes decline to touch into one they
//! will delete from. This module only ever renames.

use super::ext_of;
use super::filing::is_generic_stem;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Extensions a candidate may already carry. A file wearing one of
/// these is audio by its own name, so its stem is all that is in
/// question; anything else named is not this pass's business.
const AUDIO_EXTS: &[&str] = &["flac", "mp3", "m4a", "m4b", "ogg", "oga", "opus"];

/// Put each obfuscated audio track's own name on it. Returns how many
/// files were renamed.
pub fn rename_obfuscated_audio(dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    // PLAN, then rename, for the reason `super::tv_rename` plans: two
    // files can compose one name, and which of them gets it must not be
    // a `read_dir` accident. Here the collision is not even resolvable
    // by size - a compilation's two "Intro" tracks are equally real -
    // so a contested name is dropped and both files keep their hash.
    let mut plan: Vec<(PathBuf, String)> = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(name) = track_name(&path) {
            plan.push((path, name));
        }
    }
    let mut renamed = 0;
    for (i, (path, name)) in plan.iter().enumerate() {
        if plan
            .iter()
            .enumerate()
            .any(|(j, (_, n))| j != i && n == name)
        {
            continue; // contested: nobody gets it
        }
        let target = dir.join(name);
        // `symlink_metadata` and not `exists()`: the question this guard
        // has to ask is whether an ENTRY is at the name, because
        // `rename(2)` removes whatever entry is at its destination and
        // never resolves it. `exists()` follows the link and answers
        // false on any error, so a link here - dangling, or onto a share
        // that is not mounted - read as free and the rename below
        // deleted it. The whole argument, the APFS measurement it rests
        // on and why this is NOT the X5-07 containment class are at
        // `tv_rename`'s guard in `smart/filing.rs`; this file's tracks land in
        // the job's own directory, so the population is narrower, and
        // the harms settle it the same way either place: skipping costs
        // a track its tag name and one `mv` undoes that, where the
        // link's target string is the only record of where it pointed.
        //
        // AND IT IS A CLAIM RATHER THAN A LOOK, 31 Aug 2026, for the
        // reason argued in full at that same guard: the `lstat` covered
        // about 1% of its own interval and 96.8% of concurrent arrivals
        // landed in the gap, and `create_new` answers `AlreadyExists`
        // over all four entry kinds the census cares about - so the
        // claim IS this guard, taken atomically rather than in two
        // steps. Plain, not `disk::open_out_leaf_under`: the rename
        // below resolves its destination by path, so a bound claim
        // would refuse a job directory reached through a symlink that
        // the rename itself accepts.
        //
        // `target == *path` stays in front of it because it is not a
        // filesystem question at all - the file already carries the
        // name its tags ask for, and there is nothing to claim.
        if target == *path {
            continue;
        }
        if let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            // Taken is this guard's own answer and stays silent, as the
            // `lstat` was: the track keeps its hash name and the count
            // says so. Anything else is the door being unusable rather
            // than taken, which the rename below would have reported.
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                warn!(target: "smart", "could not claim {}: {e}", target.display());
            }
            continue;
        }
        match std::fs::rename(path, &target) {
            Ok(()) => renamed += 1,
            Err(e) => {
                // Our own placeholder, which would otherwise be a
                // zero-byte file wearing the track's tag name - and a
                // later pass reads it as the name being taken, so the
                // track could never be named again.
                let _ = std::fs::remove_file(&target);
                warn!(
                    target: "smart",
                    "rename {} → {}: {e}",
                    path.display(),
                    target.display()
                );
            }
        }
    }
    if renamed > 0 {
        info!(
            target: "smart",
            "named {renamed} obfuscated audio file(s) from their own tags"
        );
    }
    renamed
}

/// The filename this path's own tags say it should carry, or `None`
/// when any part of the evidence is missing.
fn track_name(path: &Path) -> Option<String> {
    let named = ext_of(path);
    if !named.is_empty() && !AUDIO_EXTS.contains(&named.as_str()) {
        return None;
    }
    let stem = path.file_stem()?.to_string_lossy().into_owned();
    // The poster named it something: that name stands. Same line every
    // rename pass in this crate draws, and the same closed list of
    // stems that say nothing (`super::is_generic_stem`).
    if !nzbkit::release::looks_obfuscated(&stem) && !is_generic_stem(&stem) {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let (sniffed, tags) = nzbkit::audiotag::probe(&mut f)?;
    let title = tags.title?;
    // A named extension is authoritative over the sniff, as it is for
    // video: `.oga` and `.opus` are both Ogg bytes, and the poster's
    // choice between them is not ours to overrule.
    let ext = if named.is_empty() { sniffed } else { &named };
    let stem = compose(tags.track, tags.artist.as_deref(), &title);
    let clean = nzbkit::disk::sanitize_filename(&stem);
    // `sanitize_filename` answers "unnamed" rather than an empty string,
    // which would be a rename to nothing at all.
    if clean == "unnamed" || nzbkit::release::looks_obfuscated(&clean) || is_generic_stem(&clean) {
        return None;
    }
    // Cap the COMPOSED name, not the stem: a stem capped at 255 with
    // `.flac` on the end is 260 bytes and `ENAMETOOLONG` just the same.
    // An ID3 title is poster-supplied and unbounded, and by the time it
    // is read the bytes are on disk, so there is nobody left to refuse
    // to - see `disk::sanitize_filename_capped_for` for that division.
    // It runs AFTER the three checks above on purpose: `cap_component`
    // appends a hex tag, which `looks_obfuscated` would read as noise
    // and decline a perfectly good rename over.
    Some(nzbkit::disk::sanitize_filename_capped(&format!(
        "{clean}.{ext}"
    )))
}

/// `07 - Artist - Title`, dropping whichever parts the tags did not
/// carry. The track number leads because that is the order an album is
/// meant to be read in, and a directory listing sorts on it.
fn compose(track: Option<u32>, artist: Option<&str>, title: &str) -> String {
    let mut s = String::new();
    if let Some(n) = track {
        s.push_str(&format!("{n:02} - "));
    }
    if let Some(a) = artist {
        // A compilation is the case this exists for: the folder names
        // the release, and on a various-artists album the folder cannot
        // name the performer of one track.
        s.push_str(a);
        s.push_str(" - ");
    }
    s.push_str(title);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::audiotag::testtag;

    fn scratch(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-audioname-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn track(dir: &Path, name: &str, n: u32, title: &str) {
        let bytes = testtag::flac(&[
            ("TITLE", title),
            ("ARTIST", "Some Artist"),
            ("ALBUM", "The Album"),
            ("TRACKNUMBER", &n.to_string()),
        ]);
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// The occupancy guard is a CLAIM, so an entry that arrives while
    /// the pass is running cannot be renamed over either.
    ///
    /// The case above asks WHICH QUESTION the guard asks, and the
    /// `symlink_metadata` this door carried until 31 Aug 2026 answers
    /// it exactly as the `create_new` claim does. What separates them is
    /// the gap behind the answer, so this has to race: see
    /// `crate::renameclaim` for the measurement and for why the arrival
    /// hunts the rename rather than sweeping a fixed span. VERIFIED red
    /// with this door alone reverted to the `lstat`.
    #[test]
    fn a_track_name_created_beside_the_pass_is_never_renamed_over() {
        let dir = &scratch("claim-race");
        let obfuscated = "aa45c7a08991e64c86c87cb4a9347db02712db3d54";
        let target = dir.join("01 - Some Artist - First Song.flac");
        crate::renameclaim::never_renames_over_a_neighbour(
            &target,
            300,
            || track(dir, obfuscated, 1, "First Song"),
            || {
                rename_obfuscated_audio(dir);
            },
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The occupancy guard asks about an ENTRY, not about a name that
    /// RESOLVES. `Path::exists` follows symlinks and answers false on
    /// any error, so a link at the track's target name - dangling, or
    /// onto a share that is not mounted - read as "free" and the rename
    /// then destroyed it. `rename(2)` removes whatever entry sits at the
    /// destination and never resolves it, so the loss is real and the
    /// link's target string is not recoverable from anywhere.
    ///
    /// The harms are not symmetric, which is what settles it: skipping
    /// costs the track its tag name and one `mv` puts that back, where
    /// the link is gone for good. Same argument, same shape and the same
    /// measurement as `unpack::published_names`' weak tier (X5-20
    /// residue 1, `b71c37e33`).
    #[test]
    fn a_track_name_already_taken_is_never_renamed_over() {
        let dir = &scratch("occupied");
        track(
            dir,
            "aa45c7a08991e64c86c87cb4a9347db02712db3d54",
            1,
            "First Song",
        );
        // PORTABLE half: an ordinary file at the target is declined, and
        // was declined before this decision too. It is here so Windows
        // runs the guard at all, and as the control that keeps the
        // change specific to what a symlink does.
        std::fs::write(
            dir.join("01 - Some Artist - First Song.flac"),
            b"users copy",
        )
        .unwrap();
        assert_eq!(rename_obfuscated_audio(dir), 0);
        assert_eq!(
            std::fs::read(dir.join("01 - Some Artist - First Song.flac")).unwrap(),
            b"users copy",
            "the file that was already there keeps its bytes"
        );
        let _ = std::fs::remove_dir_all(dir);

        #[cfg(unix)]
        {
            let dir = &scratch("dangling");
            track(
                dir,
                "ab45c7a08991e64c86c87cb4a9347db02712db3d54",
                1,
                "First Song",
            );
            let taken = dir.join("01 - Some Artist - First Song.flac");
            std::os::unix::fs::symlink(dir.join("archived-elsewhere"), &taken).unwrap();
            assert_eq!(
                rename_obfuscated_audio(dir),
                0,
                "a dangling link is an entry, so the name is taken"
            );
            assert!(
                std::fs::symlink_metadata(&taken)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the user's link must still be a link"
            );
            assert!(
                dir.join("ab45c7a08991e64c86c87cb4a9347db02712db3d54")
                    .exists(),
                "and the track keeps the name it arrived with"
            );
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Issue #55, the reporter's exact shape: an album posted with
    /// obfuscated track names lands as a directory of extensionless
    /// hashes, with ONE track correctly named because the recovery set
    /// happened to cover it. The named one is evidence, not a target:
    /// it must come through untouched.
    #[test]
    fn an_obfuscated_album_takes_its_track_names_from_its_own_tags() {
        let dir = &scratch("album");
        track(
            dir,
            "0a45c7a08991e64c86c87cb4a9347db02712db3d541427df65dde0219448",
            1,
            "First Song",
        );
        track(
            dir,
            "3ad5d8da723cfbdaea89349d6f3991ba0990438a309c",
            2,
            "Second Song",
        );
        // The one the PAR2 set named, in the poster's own style.
        std::fs::write(
            dir.join("10-some-artist-tenth-song-8c63a701.flac"),
            testtag::flac(&[("TITLE", "Tenth Song")]),
        )
        .unwrap();

        assert_eq!(rename_obfuscated_audio(dir), 2);
        assert_eq!(
            listing(dir),
            vec![
                "01 - Some Artist - First Song.flac",
                "02 - Some Artist - Second Song.flac",
                "10-some-artist-tenth-song-8c63a701.flac",
            ],
            "the two hashes are named and the poster's own name stands"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Every refusal, each on the file that provokes it. A wrong name
    /// is worse than an obfuscated one, so all five of these must come
    /// through the pass exactly as they went in.
    #[test]
    fn a_track_that_cannot_prove_its_name_keeps_its_hash() {
        let dir = &scratch("refuse");
        // No title in the tag block: nothing to be named after.
        std::fs::write(
            dir.join("b9f6d85e3bbdd2cffdcf5a79b5b5cea593fc5b1741957c4b4977"),
            testtag::flac(&[("ALBUM", "The Album"), ("TRACKNUMBER", "3")]),
        )
        .unwrap();
        // Not a format this can read.
        std::fs::write(
            dir.join("c048f9a409420f24a937fa7b05a5c589dedb27ebd8"),
            b"neither audio nor anything else",
        )
        .unwrap();
        // Tagged, but wearing a name a human chose.
        track(dir, "Some Band - Live At Home", 4, "Fourth Song");
        // Tagged, but named as something that is not audio at all.
        std::fs::write(
            dir.join("d998c02d7d36f5d7c12e29ed0d5e6c32.nfo"),
            testtag::flac(&[("TITLE", "Not A Track")]),
        )
        .unwrap();

        let before = listing(dir);
        assert_eq!(rename_obfuscated_audio(dir), 0);
        assert_eq!(listing(dir), before, "nothing was touched");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two tracks whose tags compose the same name. Neither is more
    /// right than the other, so neither may have it: `read_dir` order
    /// must not decide which track ends up called what.
    #[test]
    fn a_contested_name_is_given_to_nobody() {
        let dir = &scratch("contested");
        track(
            dir,
            "38b6dcb24c39726f7d6c692c97836a5fa8c40713fb",
            1,
            "Intro",
        );
        track(
            dir,
            "73166a9326d96a47942a7e56cd081444d47b878241",
            1,
            "Intro",
        );
        // A third track, uncontested, still gets its name: the refusal
        // is per-name and not a licence to give up on the album.
        track(
            dir,
            "93064d7281cbd5f50653f5a269dc67eaf4323f4c67cf",
            2,
            "Verse",
        );

        assert_eq!(rename_obfuscated_audio(dir), 1);
        assert_eq!(
            listing(dir),
            vec![
                "02 - Some Artist - Verse.flac",
                "38b6dcb24c39726f7d6c692c97836a5fa8c40713fb",
                "73166a9326d96a47942a7e56cd081444d47b878241",
            ]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An obfuscated stem that DOES carry an extension: the stem is the
    /// only thing in question, and the poster's choice of extension
    /// stands over the sniff.
    #[test]
    fn a_named_audio_extension_survives_the_rename() {
        let dir = &scratch("namedext");
        std::fs::write(
            dir.join("c99192fb4cdf2390530821aab815ba8029a7387f06.oga"),
            testtag::ogg_opus(&[("TITLE", "A Song"), ("TRACKNUMBER", "5")]),
        )
        .unwrap();
        std::fs::write(
            dir.join("ad14c4c3eab17b02e7915df2fd9d059e7592e718dc4dc81594.mp3"),
            testtag::mp3_id3v2("Another Song", "Some Artist", "The Album", "6"),
        )
        .unwrap();

        assert_eq!(rename_obfuscated_audio(dir), 2);
        assert_eq!(
            listing(dir),
            vec!["05 - A Song.oga", "06 - Some Artist - Another Song.mp3"],
            ".oga is not rewritten to .opus, and the mp3 keeps its own"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The two obfuscated-payload passes run over the same directory,
    /// and neither may claim the other's file. A video is not a track,
    /// however well it is tagged.
    #[test]
    fn the_video_beside_the_album_is_not_a_track() {
        let dir = &scratch("coexist");
        let mut feature = nzbkit::mediaprobe::testmux::mkv_full();
        feature.extend_from_slice(&[0u8; 2048]);
        std::fs::write(
            dir.join("bc2c1798fd5324a7143ddc58092d157db5d9c02225e8eb"),
            &feature,
        )
        .unwrap();
        track(
            dir,
            "c0843c943e9eaf2b44cc19e5af4978aaad16387e914c",
            3,
            "A Song",
        );

        assert_eq!(rename_obfuscated_audio(dir), 1);
        assert!(
            dir.join("bc2c1798fd5324a7143ddc58092d157db5d9c02225e8eb")
                .exists(),
            "the video keeps its hash for the video pass to answer for"
        );
        assert!(dir.join("03 - Some Artist - A Song.flac").is_file());
        // And the other direction: the named track is no longer
        // obfuscated, so it cannot be mistaken for a second nameless
        // video and stop the feature being the lone one.
        assert_eq!(
            crate::smart::nameless_video(dir)
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
            Some("bc2c1798fd5324a7143ddc58092d157db5d9c02225e8eb".to_string())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A name is composed from what the tags actually carry, and a
    /// target that already exists is never overwritten.
    #[test]
    fn composition_drops_what_the_tags_do_not_carry() {
        assert_eq!(compose(Some(7), Some("A"), "T"), "07 - A - T");
        assert_eq!(compose(Some(7), None, "T"), "07 - T");
        assert_eq!(compose(None, Some("A"), "T"), "A - T");
        assert_eq!(compose(None, None, "T"), "T");

        let dir = &scratch("exists");
        track(
            dir,
            "e03b78d154b889ffaa108b171e8b8be6f599ea603d376d9f52ee416af0",
            1,
            "Taken",
        );
        std::fs::write(dir.join("01 - Some Artist - Taken.flac"), b"already here").unwrap();
        assert_eq!(rename_obfuscated_audio(dir), 0);
        assert!(
            dir.join("e03b78d154b889ffaa108b171e8b8be6f599ea603d376d9f52ee416af0")
                .exists(),
            "the hash stays rather than clobbering the file already there"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
