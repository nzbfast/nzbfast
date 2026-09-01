//! Optical-disc images, and the cue sheet that names one.
//!
//! Split out of smart.rs rather than added to it: `smart.rs` was at
//! 2,872 of its TODO 106 3,000-line ceiling on 30 Aug 2026, and the rule
//! is that the numbers only go down.
//!
//! `keep_media_only` deletes everything it cannot classify, and a CD
//! image is posted as a PAIR - a tiny text `.cue` index beside the
//! track data. `cue` was in `PAYLOAD_EXTS` and `bin` was in no list at
//! all, so the sweep kept the index and deleted the disc: the job
//! reported Completed over a cue sheet pointing at a file that was no
//! longer there, and there is no copy anywhere to restore from
//! (M4-88). Confirmed on origin/main by measurement, not predicted.

use std::collections::HashSet;
use std::path::Path;

/// Disc-image track data and the descriptors that index it.
///
/// `iso` and `img` are NOT here - they are in `VIDEO_EXTS` already,
/// because a disc rip IS the feature for a video release. What was
/// missing is every other way an optical image gets posted: the
/// `.cue`/`.bin` pair a CD rip ships as, Alcohol's `.mds`/`.mdf`,
/// CloneCD's `.ccd` (whose `.img` is covered, and whose `.sub` is in
/// `SUBTITLE_EXTS` by coincidence of extension), Nero's `.nrg`,
/// cdrdao's `.toc`, DiscJuggler's `.cdi` and the Dreamcast `.gdi`.
///
/// `bin` is a generic extension elsewhere in the world, and that is not
/// a reason to leave it out: this list is only ever consulted inside a
/// job that has already cleared the no-video guard, and the standing
/// doctrine for these lists (see `MEDIA_COMPANION_EXTS`) is that
/// keeping a stray file costs disk while deleting a wanted one is
/// unrecoverable. Firmware, a game image and a CD track are all payload
/// under that rule; none of them is Usenet furniture.
pub(super) const DISC_IMAGE_EXTS: &[&str] =
    &["bin", "mdf", "mds", "nrg", "ccd", "toc", "cdi", "gdi"];

/// A cue sheet is long enough to name its tracks and no longer. Past
/// this the file is not a cue sheet whatever it calls itself, and
/// reading it into memory to find out is not something a cleanup pass
/// should do.
const CUE_MAX: u64 = 1 << 20;

/// Every sibling the cue sheets in `dir` NAME, lowercased, as bare file
/// names.
///
/// The extension list above is the belt; this is the braces, and it is
/// the half that reaches what no list can. A cue sheet is a name map -
/// `FILE "Album.bin" BINARY` - so it says which file beside it is the
/// payload, in the poster's own words. That answers the shapes an
/// extension list gets wrong: a lossless rip cued against `.tta`,
/// `.tak` or `.shn` (real formats, in none of our lists) is spared
/// without anyone having had to think of the format first. A file the
/// cue does NOT name is not spared by this arm at all.
///
/// Lowercased bare names rather than resolved paths, for two reasons.
/// Cue sheets are routinely authored on Windows and ship a spelling
/// that differs from the file on disk only in case, and comparing
/// lowercased names makes that a non-event on every filesystem rather
/// than only on the case-insensitive ones. And a `FILE` line is
/// untrusted text from the post: taking only the name component means a
/// cue naming `..\..\something` can never widen this past its own
/// directory. The worst a hostile cue can do is spare a sibling from
/// deletion, which is the safe direction.
pub(super) fn cue_named_files(dir: &Path) -> HashSet<String> {
    let mut named = HashSet::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return named;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_file() || p.extension().is_none_or(|e| !e.eq_ignore_ascii_case("cue")) {
            continue;
        }
        if entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > CUE_MAX {
            continue;
        }
        // A cue sheet is CP1252 or UTF-8 depending on who wrote it, and
        // a byte that decodes to neither must not lose us the whole
        // sheet - the FILE lines are ASCII either way.
        let Ok(text) = std::fs::read(&p) else {
            continue;
        };
        for line in String::from_utf8_lossy(&text).lines() {
            if let Some(name) = cue_file_line(line) {
                named.insert(name);
            }
        }
    }
    named
}

/// The name a single `FILE` line declares, if this is one.
///
/// The grammar is `FILE <name> <type>` with the name quoted whenever it
/// holds a space, which is nearly always. Unquoted names are legal and
/// run to the first space, so the trailing type keyword (`BINARY`,
/// `WAVE`, `MP3`, ...) is what ends them. Only the KEYWORD's case is
/// forgiving: a `REM`-commented line is not a declaration and must not
/// be read as one.
fn cue_file_line(line: &str) -> Option<String> {
    let rest = line.trim_start();
    let rest = rest
        .get(..5)
        .filter(|h| h.eq_ignore_ascii_case("file "))
        .map(|_| &rest[5..])?;
    let rest = rest.trim_start();
    let name = match rest.strip_prefix('"') {
        Some(q) => q.split('"').next()?,
        None => rest.split_whitespace().next()?,
    };
    // Never a path: see the doc comment above.
    let leaf = name
        .rsplit(['/', '\\'])
        .next()
        .map(str::trim)
        .filter(|n| !n.is_empty())?;
    Some(leaf.to_ascii_lowercase())
}

/// Is this file a disc image by extension, or named as payload by a cue
/// sheet sitting beside it?
pub(super) fn is_disc_payload(path: &Path, ext: &str, cue_named: &HashSet<String>) -> bool {
    DISC_IMAGE_EXTS.contains(&ext)
        || path
            .file_name()
            .is_some_and(|n| cue_named.contains(&n.to_string_lossy().to_ascii_lowercase()))
}

/// Is this file part of a cue-named SET - the sheet itself, or a file
/// some sheet beside it names?
///
/// The deletion door asks [`is_disc_payload`]; this is the same evidence
/// answering the RENAME question, and the two are separate because they
/// disagree about the sheet. `keep_media_only` keeps a cue sheet because
/// it is payload. `main_payload` must refuse one because it is a NAME
/// MAP: renaming either half of `Album.cue` + `Album.bin` breaks the
/// link between them, which is the rule `is_packed_archive` already
/// states for a multi-volume set.
///
/// The two halves break differently and both were measured through
/// `rename_from_nzb` before this landed:
///
///  * the DATA half breaks outright. `Album.bin` is the biggest thing
///    in a CD rip and took the release name, leaving `Album.cue`
///    addressing a file that is no longer there - over a Completed job,
///    with nothing anywhere to say so. That is M4-88's failure exactly,
///    reached through the naming door instead of the deletion sweep.
///  * the SHEET half breaks the disc numbering. Spare the data alone
///    and a sheet becomes the biggest thing left, so a two-disc rip came
///    back as `CD1.bin`, `CD1.cue`, `CD2.bin`, `My Album 2024.cue`:
///    nothing dangles, and the reader can no longer tell which sheet is
///    disc 2. A sheet is a few KB of text, so the only job it is ever
///    the largest file in is one with nothing else in it - refusing it
///    costs a rename nobody asked for and buys the numbering back.
///
/// Only the naming door has any business calling this. A job that is
/// ONLY a cue set therefore renames nothing inside it and carries the
/// release name on the folder alone, which is what the disc arm of
/// `main_payload` already does for a DVD or Blu-ray tree.
pub(super) fn is_cue_set_member(name: &str, ext: &str, cue_named: &HashSet<String>) -> bool {
    ext == "cue" || cue_named.contains(&name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_line_yields_the_leaf_name_however_it_is_spelled() {
        assert_eq!(
            cue_file_line("FILE \"Album Name.bin\" BINARY").as_deref(),
            Some("album name.bin")
        );
        assert_eq!(
            cue_file_line("  file \"Track.APE\" WAVE").as_deref(),
            Some("track.ape")
        );
        // Unquoted names end at the type keyword.
        assert_eq!(
            cue_file_line("FILE Album.bin BINARY").as_deref(),
            Some("album.bin")
        );
        // A path is reduced to its leaf, in either separator, so a cue
        // can never reach outside its own directory.
        assert_eq!(
            cue_file_line("FILE \"..\\..\\Windows\\notepad.exe\" BINARY").as_deref(),
            Some("notepad.exe")
        );
        assert_eq!(
            cue_file_line("FILE \"/etc/passwd\" BINARY").as_deref(),
            Some("passwd")
        );
        // Not declarations.
        assert!(cue_file_line("REM FILE \"Album.bin\" BINARY").is_none());
        assert!(cue_file_line("  TRACK 01 AUDIO").is_none());
        assert!(cue_file_line("FILE \"\" BINARY").is_none());
        assert!(cue_file_line("").is_none());
    }

    #[test]
    fn the_sheet_names_its_tracks_and_an_over_long_one_is_not_a_sheet() {
        let dir = std::env::temp_dir().join(format!("nzbfast-cuemap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Album.cue"),
            b"REM GENRE Rock\nFILE \"Album.bin\" BINARY\n  TRACK 01 AUDIO\n",
        )
        .unwrap();
        // Uppercase extension: cue sheets ship from Windows.
        std::fs::write(dir.join("Other.CUE"), b"FILE \"Other.TTA\" WAVE\n").unwrap();
        // Over the ceiling: not a cue sheet whatever it is called.
        std::fs::write(dir.join("Huge.cue"), vec![b'x'; (CUE_MAX + 1) as usize]).unwrap();

        let named = cue_named_files(&dir);
        assert!(named.contains("album.bin"), "{named:?}");
        assert!(named.contains("other.tta"), "lowercased on both sides");
        assert_eq!(
            named.len(),
            2,
            "the over-long file names nothing: {named:?}"
        );

        // The predicate reads the same name whatever case it is on disk.
        assert!(is_disc_payload(&dir.join("ALBUM.BIN"), "bin", &named));
        assert!(is_disc_payload(&dir.join("Other.TTA"), "tta", &named));
        assert!(!is_disc_payload(&dir.join("cover.jpg"), "jpg", &named));
        // The extension arm stands on its own with no sheet at all.
        assert!(is_disc_payload(&dir.join("x.mdf"), "mdf", &HashSet::new()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_rename_door_refuses_both_halves_of_a_cue_set() {
        let named: HashSet<String> = ["album.bin".to_string(), "other.tta".to_string()]
            .into_iter()
            .collect();

        // The data half, in whatever case the sheet or the disk spells it.
        assert!(is_cue_set_member("Album.bin", "bin", &named));
        assert!(is_cue_set_member("ALBUM.BIN", "bin", &named));
        // A format no extension list of ours knows: the sheet is what
        // says it is payload, which is the whole point of reading one.
        assert!(is_cue_set_member("Other.TTA", "tta", &named));
        // The sheet half, which the sets cannot name and which needs no
        // sheet in reach to be refused - a lone sheet is still a name map.
        assert!(is_cue_set_member("CD2.cue", "cue", &named));
        assert!(is_cue_set_member("Stray.cue", "cue", &HashSet::new()));

        // Ordinary payload beside a cue set is untouched: this is the
        // narrow rule, not the whole-job refusal `disc_structure` makes.
        assert!(!is_cue_set_member("Example.Movie.2024.mkv", "mkv", &named));
        assert!(!is_cue_set_member("cover.jpg", "jpg", &named));
        // A disc image the sheets do NOT name is not spared by this arm.
        assert!(!is_cue_set_member("Unrelated.bin", "bin", &named));
    }
}
