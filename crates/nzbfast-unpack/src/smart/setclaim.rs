//! What the SET says, against what the NAME says: the two places the
//! junk sweep still deleted a payload on the strength of a filename.
//!
//! Wave-4 matrix rows M4-54 and M4-68 are one defect in two spellings.
//! `sweep_junk` classifies by EXTENSION, and `is_finder_dropping`
//! classifies by PREFIX plus a size ceiling; both then delete. That is
//! the strongest action in the tree taken on the weakest evidence there
//! is, and the house rule since `wave4-fix-exact-name-authority`
//! (2b7f5495e) is the other way round - a NAME may nominate, only
//! CONTENT may finalize.
//!
//! So this module holds the two content-side answers:
//!
//!   * [`set_declared_paths`] - every path a PAR2 recovery set on disk
//!     declares by FileDesc. A file the set names is a member of the
//!     release by the strongest statement anyone posted about it, and
//!     no extension outranks that.
//!   * [`looks_like_appledouble`] - the AppleDouble magic. `._name` is
//!     a convention, not a reservation, and a 200 KiB `._manual.pdf`
//!     under `Docs/` is a payload wherever the prefix came from.
//!
//! WHY TWO ANSWERS AND NOT ONE, since M4-68's row offers the set claim
//! as its alternative: a set CANNOT protect a `._` path, because it
//! cannot produce one. `nzbkit::disk::sanitize_out_name` runs every
//! component through `sanitize_filename_for`, which does
//! `trim_matches('.')` - a leading dot is hidden, a trailing one is a
//! Windows trap - so a FileDesc naming `Docs/._manual.pdf` lands as
//! `Docs/_manual.pdf` and [`super::is_finder_dropping`] never looks at
//! it twice. The `._` names that do reach a finished directory come
//! from an archive member or from what was already on disk, and nothing
//! on those paths declares anything. Only the content could answer that
//! row. Asserted, not described, in this module's tests.
//!
//! WHERE THIS RUNS, because it is not where the matrix implies. All
//! three sweeps that reach these two rules (`sweep_junk`,
//! `keep_media_only`, `cleanup`) are called only from `serve/` - the
//! CLI `get` path never sweeps - so neither row is reachable from the
//! `e2e_norar` fixtures, and both are pinned here as unit tests instead.
//!
//! WHY THE SET READ IS BOUNDED AND LATE. `sweep_junk` runs at finalize
//! on every movie/TV job with `rename_junk` on, so an unbounded slurp
//! of an obfuscated post's recovery volumes would put the whole set
//! resident behind a cleanup pass - the same trap `collect_par2_bytes`
//! was capped for. The names live in the CRITICAL packets, which the
//! index carries in full and every volume repeats, so a cap that
//! comfortably covers an index costs nothing real: at 4 MiB blocks a
//! 2 TB release's IFSC is about 10 MiB, and [`SET_SCAN_CAP`] sits above
//! it. Past the cap we answer "declared nothing", which is exactly
//! today's behaviour, and say so in the log rather than silently
//! dropping the protection.
//!
//! WHY THE MANIFEST IS NOT THE ANSWER HERE, since it looks like the
//! obvious one: `.nzbfast.manifest` carries the same names with better
//! provenance, and it is written AFTER finalize on purpose
//! (`postproc.rs` - before finalize the names are pre-rename and
//! the directory may not be the final one). It is therefore not on disk
//! when the sweep runs. The `.par2` files ARE, because the sweep is
//! what deletes them.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

/// How many PAR2 bytes one directory's name read may hold at once.
///
/// A fixed figure and deliberately NOT `unpack::par2_scan_cap()`, which
/// scales to a slice of the process budget because the diagnostic pass
/// wants every recovery slice it can hold. This wants only the critical
/// packets, and their size is a property of the SET rather than of the
/// box: an index for a 2 TB release at 4 MiB blocks is about 10 MiB of
/// IFSC, so 16 covers one with room and a bigger machine buys nothing
/// worth reading.
const SET_SCAN_CAP: u64 = 16 << 20;

/// The AppleDouble header magic, big-endian at offset 0. AppleSingle is
/// `0x00051600` and is deliberately NOT accepted: it carries the data
/// fork too, so an AppleSingle file beside a payload is not the empty
/// husk this sweep exists to remove.
///
/// MEASURED, not taken from the spec alone: real `._` files written by
/// macOS itself, found on this box under a downloaded framework bundle,
/// open with exactly these four bytes and run 608 and 624 bytes long -
/// three orders of magnitude under [`super::APPLEDOUBLE_MAX`], which is
/// what makes requiring the magic a tightening that costs no genuine
/// dropping. A constant nobody has seen fire on the real article is the
/// shape that classifies every husk as content and quietly stops the
/// prune working at all.
const APPLEDOUBLE_MAGIC: [u8; 4] = [0x00, 0x05, 0x16, 0x07];

/// The first eight bytes of every `.DS_Store` Finder writes: the version
/// word `00 00 00 01` and then the `Bud1` magic of the B-tree store
/// inside.
///
/// MEASURED, not taken from the format notes alone, for the reason the
/// AppleDouble constant above gives: 60 real `.DS_Store` files found on
/// this box on 30 Aug 2026 open with exactly these eight bytes, all 60
/// of them, at sizes from 6148 to 32772. A constant nobody has seen fire
/// on the real article is the shape that classifies every husk as
/// content and quietly stops the prune working at all.
const DS_STORE_MAGIC: [u8; 8] = [0x00, 0x00, 0x00, 0x01, b'B', b'u', b'd', b'1'];

/// Does `p` look like Finder's own `.DS_Store`, rather than a file that
/// merely carries the name?
///
/// The last NAME-ONLY delete in this pass, and matrix row M4-79 is where
/// it stops being one. [`super::is_finder_dropping`] answered true for
/// `.DS_Store` at ANY size on the strength of the name alone, and
/// [`super::drop_finder_droppings`] then unlinks it with a plain
/// `remove_file` - deliberately not through the Trash, so there is
/// nothing to undo it from. Measured 30 Aug 2026 on origin/main: a 3 MiB
/// file at `Extras/.DS_Store` was taken by `sweep_junk` AND by
/// `prune_empty_dirs`, and the set claim M4-54 added could not save it.
///
/// WHY THE SET CLAIM CANNOT, which is the finding this row is really
/// about and the same shape as M4-68's. A FileDesc naming `.DS_Store`
/// does not LAND as `.DS_Store`: since M4-66 (7dcadf0a1)
/// `sanitize_filename_for` MAPS a leading dot run to `_`, so the set
/// declares `Extras/_DS_Store` while the file on disk is
/// `Extras/.DS_Store`, and [`set_declared_paths`] - measured, not
/// argued - hands back the sanitized path and never covers the real one.
/// So the row's own headline is closed today, and closed COLLATERALLY by
/// a commit about something else, in a rule whose own message records
/// that PRESERVING the dot was considered and rejected on unrelated
/// grounds. That is the whole reason this content half is worth its six
/// lines: the only thing standing between a name-only permanent delete
/// and a payload is a sanitizer decision taken for another purpose, and
/// nothing joined the two. It is asserted here rather than described.
///
/// Empty counts as a dropping. A zero-byte file has nothing to lose
/// either way, and refusing to prune one would leave the `Sample/` husk
/// this pass exists to clear alive on a truncated write.
///
/// WHAT THIS TRADE COSTS, and the measurement behind it is ONE MAC. The
/// 60 files above were found on the dev box; every `.DS_Store` in that
/// sample was written by Finder, which is the only writer this fleet
/// has. A `.DS_Store` produced by something else - a NAS serving the
/// download directory over SMB, or a foreign tool - that does NOT open
/// with `Bud1` is now content, so the folder holding it stops being
/// pruned and the husk survives. That is the direction to fail in: a
/// husk is a directory the user can delete, and the alternative is
/// `drop_finder_droppings` unlinking a file permanently, with no Trash
/// to undo it from, on the strength of a filename. If a husk is ever
/// reported surviving on a NAS, the fix is to widen the MAGIC against a
/// sample from that writer - never to go back to the name.
///
/// Unreadable is NOT a dropping, for [`looks_like_appledouble`]'s
/// reason: a file we cannot open is a file we cannot classify, and the
/// caller deletes what this says yes to.
pub(super) fn looks_like_ds_store(p: &Path) -> bool {
    use std::io::Read;
    let Ok(meta) = p.metadata() else { return false };
    if meta.len() == 0 {
        return true;
    }
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut head = [0u8; 8];
    f.read_exact(&mut head).is_ok() && head == DS_STORE_MAGIC
}

/// Does `p` open with the AppleDouble magic?
///
/// The caller has already established the `._` prefix and the size
/// ceiling; this is the content half, and it is what separates the
/// resource fork macOS drops beside a copied file from a payload that
/// merely starts with the same two characters. M4-68 is that payload:
/// a 200 KiB `Docs/._manual.pdf`, which `prune_empty_dirs` unlinked
/// with a plain `remove_file` - not even through the Trash - as soon as
/// it was the only thing left in its directory. The row calls it a
/// FileDesc name; it cannot be one, for the dot reason in the module
/// note, and where such a name comes from changes nothing about what
/// the bytes are.
///
/// Unreadable is NOT an AppleDouble. A file we cannot open is a file we
/// cannot classify, and the caller deletes what this says yes to.
pub(super) fn looks_like_appledouble(p: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut head = [0u8; 4];
    f.read_exact(&mut head).is_ok() && head == APPLEDOUBLE_MAGIC
}

/// Every path under `dir` that a PAR2 set on disk declares by FileDesc,
/// over the junk sweep's own footprint (top level plus one subdirectory
/// deep, each directory's sets resolved against that directory).
///
/// Returns an empty set when nothing here is a recovery set, which is
/// the ordinary case for an extracted archive post - the surviving
/// `.par2` there covers the volumes the extractor already consumed, so
/// it declares no path that still exists.
pub(super) fn set_declared_paths(dir: &Path) -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    declared_in(dir, &mut out);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if super::is_real_dir(&path) {
            declared_in(&path, &mut out);
        }
    }
    out
}

/// One directory's sets, resolved against that same directory.
fn declared_in(dir: &Path, out: &mut HashSet<PathBuf>) {
    let (bytes, skipped) = match crate::par2scan::collect_par2_bytes(dir, SET_SCAN_CAP) {
        Ok(v) => v,
        Err(_) => return,
    };
    if bytes.is_empty() {
        if skipped > 0 {
            // Said out loud: the sweep is about to classify by name
            // alone in a directory that holds something PAR2-shaped and
            // too big to read. "Shaped" rather than "is a set", because
            // the sniff is the packet magic and a payload can open with
            // it (M4-18) - which is also why this is a warning and not a
            // refusal: over the cap we answer the same "declared
            // nothing" the no-set case answers, which is the behaviour
            // that shipped before this read existed.
            warn!(
                target: "cleanup",
                "{}: {skipped} PAR2-shaped file(s) over the {} MiB name-scan cap - \
                 the junk sweep cannot see what a set there would declare",
                dir.display(),
                SET_SCAN_CAP >> 20
            );
        }
        return;
    }
    let refs: Vec<&[u8]> = bytes.iter().map(|v| v.as_slice()).collect();
    let Ok(sets) = nzbkit::live::pick_sets(&refs) else {
        return;
    };
    let before = out.len();
    for f in sets.iter().flat_map(|s| s.files.iter()) {
        out.insert(nzbkit::disk::join_out_name(
            dir,
            &nzbkit::disk::sanitize_out_name(&f.name),
        ));
    }
    if out.len() > before {
        info!(
            target: "cleanup",
            "{}: {} file(s) declared by a PAR2 set are payload, whatever their extension",
            dir.display(),
            out.len() - before
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::testseam::{par2_index, trash_globals_steady};
    use super::*;

    /// M4-79, the row itself, and the answer is that it is CLOSED at the
    /// door the row names - by a commit about something else. A FileDesc
    /// naming `.DS_Store` cannot put that name on disk, because M4-66's
    /// leading-dot mapping turns it into `_DS_Store`, so the set declares
    /// a path the deleting pass never looks at.
    ///
    /// Pinned rather than written down, because the mapping is the ONLY
    /// thing holding it and was landed for an unrelated reason (its own
    /// message records that preserving the dot was the other candidate).
    /// The day a leading dot survives sanitize, this test says so.
    #[test]
    fn a_set_can_never_declare_a_finder_dropping() {
        for declared in [".DS_Store", "Extras/.DS_Store", "._manual.pdf"] {
            let landed = nzbkit::disk::sanitize_out_name(declared);
            let last = landed.rsplit('/').next().unwrap_or(&landed);
            assert!(
                !last.starts_with('.'),
                "{declared:?} landed as {landed:?}: a declared name that keeps its \
                 leading dot is a payload `is_finder_dropping` decides on, and \
                 `set_declared_paths` resolves the SANITIZED path, so the M4-54 \
                 set claim cannot cover it. Read `looks_like_ds_store`."
            );
        }
    }

    /// M4-79's substance: whatever put the name there, a `.DS_Store`
    /// holding payload is not Finder's and is not deleted for its name.
    ///
    /// Measured on origin/main before the fix: `sweep_junk` took this
    /// 3 MiB file, and so did `prune_empty_dirs` - a plain `remove_file`,
    /// not the Trash, at any size, on the name alone.
    #[test]
    fn a_payload_named_ds_store_is_not_finder_metadata() {
        let _steady = trash_globals_steady();
        let d = scratch("dsstorepayload");
        let movie = vec![7u8; 3 << 20];
        std::fs::create_dir_all(d.join("Extras")).unwrap();
        std::fs::write(d.join("Extras/.DS_Store"), &movie).unwrap();
        assert!(
            !super::super::is_finder_dropping(&d.join("Extras/.DS_Store")),
            "3 MiB that does not open with Bud1 is not Finder's"
        );
        super::super::sweep_junk(&d);
        super::super::prune_empty_dirs(&d, 0);
        assert_eq!(
            std::fs::read(d.join("Extras/.DS_Store")).unwrap(),
            movie,
            "kept, and byte-exact - the delete here is permanent"
        );
    }

    /// The control that keeps the row above from reading as "never touch
    /// a `.DS_Store`": Finder's own, and a truncated one, still go, and
    /// the husk directory still goes with them. Without this pin the fix
    /// silently retires `prune_empty_dirs`.
    #[test]
    fn finders_own_ds_store_still_goes_and_takes_the_husk() {
        let _steady = trash_globals_steady();
        let d = scratch("dsstorehusk");
        std::fs::create_dir_all(d.join("Sample")).unwrap();
        std::fs::create_dir_all(d.join("Proof")).unwrap();
        std::fs::write(d.join("Sample/.DS_Store"), ds_store_bytes()).unwrap();
        std::fs::write(d.join("Proof/.DS_Store"), Vec::new()).unwrap();
        assert_eq!(
            super::super::prune_empty_dirs(&d, 0),
            2,
            "a folder left holding only Finder metadata is empty - the \
             genuine article by its magic, a zero-byte one because there \
             is nothing there to lose either way"
        );
        assert!(!d.join("Sample").exists() && !d.join("Proof").exists());
    }

    /// M4-54. FileDesc publishes the movie as `Great.Movie.nfo`, and
    /// `nfo` is on `JUNK_EXTS`. The all-junk guard cannot save it - one
    /// real `trailer.mp4` beside it is `largest_video`, so survivors is
    /// non-zero and the sweep proceeds - and the payload the recovery
    /// set itself declares is deleted for its extension.
    #[test]
    fn a_set_declared_payload_survives_its_furniture_extension() {
        let _steady = trash_globals_steady();
        let d = scratch("setclaimnfo");
        let movie = vec![7u8; 3 << 20];
        std::fs::write(d.join("Great.Movie.nfo"), &movie).unwrap();
        std::fs::write(d.join("trailer.mp4"), vec![0u8; 4096]).unwrap();
        std::fs::write(
            d.join("release.par2"),
            par2_index(0x31, &[("Great.Movie.nfo", movie.len() as u64)]),
        )
        .unwrap();

        let declared = set_declared_paths(&d);
        assert!(
            declared.contains(&d.join("Great.Movie.nfo")),
            "the set's own FileDesc must be readable at sweep time: {declared:?}"
        );

        let n = super::super::sweep_junk(&d);
        assert!(
            d.join("Great.Movie.nfo").exists(),
            "the PAR2 set DECLARES this file - no extension outranks that (swept {n})"
        );
        assert_eq!(
            std::fs::read(d.join("Great.Movie.nfo")).unwrap(),
            movie,
            "kept, and byte-exact"
        );
        assert!(d.join("trailer.mp4").exists(), "the feature stays");
        assert!(
            !d.join("release.par2").exists(),
            "the recovery file itself is still furniture - the set does not declare it"
        );
    }

    /// Read-only sweep finding 7 (31 Aug 2026): `keep_media_only` never
    /// asked the set at all, where `sweep_junk` above has since M4-54.
    ///
    /// It is the harsher of the two sweeps - under `rename_media_only`
    /// everything that is not a video, a companion track or a still-packed
    /// archive goes - and `looks_like_video_bytes`, the one door that could
    /// have rescued a declared payload, opens EXTENSIONLESS files only. So a
    /// poster who names the feature `Great.Movie.nfo` had the recovery set's
    /// own declared member deleted on a Completed job.
    ///
    /// Three assertions, because a fix that only kept `.nfo` files would
    /// pass the first one: the declared payload stays, the UNDECLARED
    /// sidecar beside it still goes, and the no-video guard is untouched.
    #[test]
    fn keep_media_only_spares_a_set_declared_sidecar() {
        let _steady = trash_globals_steady();
        let d = scratch("keepmediadecl");
        let movie = vec![7u8; 3 << 20];
        std::fs::write(d.join("Great.Movie.nfo"), &movie).unwrap();
        std::fs::write(d.join("Undeclared.nfo"), vec![3u8; 2048]).unwrap();
        std::fs::write(d.join("feature.mkv"), vec![9u8; 8 << 20]).unwrap();
        std::fs::write(
            d.join("release.par2"),
            par2_index(0x37, &[("Great.Movie.nfo", movie.len() as u64)]),
        )
        .unwrap();

        let n = super::super::keep_media_only(&d);
        assert!(
            d.join("Great.Movie.nfo").exists(),
            "the PAR2 set DECLARES this file - no extension outranks that (swept {n})"
        );
        assert_eq!(
            std::fs::read(d.join("Great.Movie.nfo")).unwrap(),
            movie,
            "kept, and byte-exact"
        );
        assert!(
            !d.join("Undeclared.nfo").exists(),
            "an undeclared sidecar is still clutter - the fix must not read \
             as 'never delete an .nfo'"
        );
        assert!(d.join("feature.mkv").exists(), "the feature stays");
    }

    /// The control the row above must not break: an UNDECLARED `.nfo`
    /// beside the same payload is ordinary scene furniture and still
    /// goes. Without this the fix reads as "never delete an .nfo".
    #[test]
    fn an_undeclared_furniture_file_is_still_swept() {
        let _steady = trash_globals_steady();
        let d = scratch("setclaimctl");
        let movie = vec![7u8; 3 << 20];
        std::fs::write(d.join("Great.Movie.nfo"), &movie).unwrap();
        std::fs::write(d.join("trailer.mp4"), vec![0u8; 4096]).unwrap();
        std::fs::write(d.join("release.nfo"), b"scene info").unwrap();
        std::fs::write(
            d.join("release.par2"),
            par2_index(0x31, &[("Great.Movie.nfo", movie.len() as u64)]),
        )
        .unwrap();

        super::super::sweep_junk(&d);
        assert!(d.join("Great.Movie.nfo").exists(), "declared, so payload");
        assert!(
            !d.join("release.nfo").exists(),
            "undeclared furniture still goes - the claim is about the SET, not the extension"
        );
    }

    /// M4-68. A `._`-prefixed payload in a SUBDIRECTORY: the prefix
    /// heuristic plus a 1 MiB ceiling reads it as an AppleDouble husk,
    /// `only_finder_droppings` then calls the directory empty and
    /// `drop_finder_droppings` unlinks the payload with a plain
    /// `remove_file` - not through the Trash, so there is nothing to
    /// undo.
    ///
    /// THE ROOT VIDEO IS NOT WHAT ARMS THIS, and the matrix row says it
    /// is ("plus a real small video at root so the all-junk guard does
    /// not skip the sweep"). Measured by removing it: the payload is
    /// deleted just the same. The guard skips the DELETES and then calls
    /// `prune_empty_dirs` on its way out, so the husk pass runs on both
    /// paths - and on this fixture the guard never fires anyway, because
    /// a `.pdf` is on no junk list and `doomed` is empty. It is kept
    /// because it is the shape the row describes, not because the red
    /// needs it.
    #[test]
    fn a_prefixed_payload_one_level_down_is_not_a_finder_dropping() {
        let _steady = trash_globals_steady();
        let d = scratch("setclaimad");
        std::fs::create_dir_all(d.join("Docs")).unwrap();
        let mut manual = b"%PDF-1.7\n".to_vec();
        manual.resize(200 << 10, b'p');
        std::fs::write(d.join("Docs/._manual.pdf"), &manual).unwrap();
        std::fs::write(d.join("movie.mkv"), vec![0u8; 8192]).unwrap();

        super::super::sweep_junk(&d);
        assert!(
            d.join("Docs/._manual.pdf").exists(),
            "a 200 KiB PDF is payload, whatever its name starts with"
        );
        assert_eq!(
            std::fs::read(d.join("Docs/._manual.pdf")).unwrap(),
            manual,
            "kept, and byte-exact"
        );
        assert!(d.join("Docs").is_dir(), "and its directory stays with it");
    }

    /// The control: a GENUINE AppleDouble in the same position is still
    /// removed, and its emptied husk with it. Without this the fix
    /// reads as "never prune a `._` file", which would leave the
    /// `Sample/.DS_Store` husk `prune_empty_dirs` exists to clear.
    #[test]
    fn a_real_appledouble_husk_is_still_pruned() {
        let _steady = trash_globals_steady();
        let d = scratch("setclaimadctl");
        std::fs::create_dir_all(d.join("Sample")).unwrap();
        std::fs::write(d.join("Sample/._clip.mkv"), appledouble_bytes()).unwrap();
        std::fs::write(d.join("Sample/.DS_Store"), ds_store_bytes()).unwrap();
        std::fs::write(d.join("movie.mkv"), vec![0u8; 8192]).unwrap();

        super::super::sweep_junk(&d);
        assert!(
            !d.join("Sample").exists(),
            "a husk holding only Finder metadata still goes"
        );
        assert!(d.join("movie.mkv").exists());
    }

    /// M4-54 and M4-68 composed, which is the shape the coordination
    /// note warns about: four individually-correct junk rules can delete
    /// one file between them. A nested `Docs/notes.txt` is aimed at by
    /// the extension rule one level down, and the set declares it with
    /// its directory, so this pins that a declared path is resolved as a
    /// TREE and not as a basename.
    ///
    /// AND IT PINS WHY M4-68 COULD NOT BE FIXED THE SAME WAY. That row
    /// offers "never delete a FileDesc-covered path" as an alternative
    /// to sniffing the magic. It does not work, and the reason is one
    /// layer down in `sanitize_out_name`: every component goes through
    /// `sanitize_filename_for`, which does `trim_matches('.')` because a
    /// leading dot is hidden and a trailing one is a Windows trap. So a
    /// FileDesc naming `Docs/._notes.txt` LANDS as `Docs/_notes.txt`,
    /// which `is_finder_dropping` never looks at twice - a set claim can
    /// never protect a `._` path, because a set can never produce one.
    /// The `._` names that do reach a finished directory come from an
    /// archive member or from what was already on disk, and nothing on
    /// those paths declares anything. Only the content could answer it.
    #[test]
    fn a_declared_payload_survives_a_junk_extension_one_level_down() {
        let _steady = trash_globals_steady();
        let d = scratch("setclaimboth");
        std::fs::create_dir_all(d.join("Docs")).unwrap();
        let notes = vec![b'n'; 200 << 10];
        std::fs::write(d.join("Docs/notes.txt"), &notes).unwrap();
        std::fs::write(d.join("movie.mkv"), vec![0u8; 8192]).unwrap();
        std::fs::write(
            d.join("release.par2"),
            par2_index(0x44, &[("Docs/notes.txt", notes.len() as u64)]),
        )
        .unwrap();

        let declared = set_declared_paths(&d);
        assert!(
            declared.contains(&d.join("Docs/notes.txt")),
            "a FileDesc naming a tree declares the path, not the basename: {declared:?}"
        );
        // The dot rule that rules the set claim out for M4-68, asserted
        // rather than described, so nobody re-derives it from the row.
        // The SPELLING moved on 30 Aug 2026 (M4-66) and the rule did
        // not: leading dots are now mapped to `_` rather than deleted,
        // so this is `__notes.txt` and not `_notes.txt`. Still not a
        // `._` name, which is all this assertion is about - and the
        // mapping is what stops a declared `._notes.txt` and a declared
        // `_notes.txt` folding onto one file, which the old deletion
        // did.
        assert_eq!(
            nzbkit::disk::sanitize_out_name("Docs/._notes.txt"),
            "Docs/__notes.txt",
            "a FileDesc cannot land a `._` name, so it cannot declare one"
        );

        super::super::sweep_junk(&d);
        assert!(
            d.join("Docs/notes.txt").exists(),
            "declared by the set, so `.txt` one level down does not take it"
        );
        assert_eq!(std::fs::read(d.join("Docs/notes.txt")).unwrap(), notes);
        assert!(d.join("Docs").is_dir(), "and its directory stays with it");
    }

    /// The predicate itself, both ways, so a caller reading it knows
    /// what it is asserting.
    #[test]
    fn appledouble_is_decided_by_magic_and_never_by_the_name() {
        let d = scratch("setclaimmagic");
        std::fs::write(d.join("._real"), appledouble_bytes()).unwrap();
        assert!(looks_like_appledouble(&d.join("._real")));

        // AppleSingle carries the data fork too - not a husk.
        std::fs::write(d.join("._single"), [0x00, 0x05, 0x16, 0x00, 0, 0, 0, 0]).unwrap();
        assert!(!looks_like_appledouble(&d.join("._single")));

        std::fs::write(d.join("._pdf"), b"%PDF-1.7\n").unwrap();
        assert!(!looks_like_appledouble(&d.join("._pdf")));

        // Shorter than the magic, and unreadable, are both "no": the
        // caller deletes what this says yes to.
        std::fs::write(d.join("._tiny"), b"\x00\x05").unwrap();
        assert!(!looks_like_appledouble(&d.join("._tiny")));
        assert!(!looks_like_appledouble(&d.join("._absent")));
    }

    /// The delete half of matrix row M4-91, and the shape it was left
    /// in. Measured on origin/main at c4d47e276, 31 Aug 2026: both
    /// sweeps deleted this 400 KB episode. `is_deletable_sample` asked
    /// only whether the name carried a marker token and whether the
    /// file was under `SAMPLE_MAX_FRACTION` of the feature - and its
    /// duration veto covers `mkv`/`webm`, two of `VIDEO_EXTS`'
    /// EIGHTEEN, so `.mp4` got no second opinion at all. `proof` is a
    /// whole token here and 400 KB is under 0.15 * 4 MB, so the payload
    /// the user asked for went at rc=0.
    ///
    /// `.mp4` deliberately, and not `.mkv`: the point of the row is the
    /// sixteen extensions the container probe cannot reach. An `.mkv`
    /// episode with a real Matroska header is spared by the veto today
    /// and always was - what is NOT true is that a `.mkv` fixture proves
    /// it, since bytes that do not parse leave `mkv::probe` at `None`
    /// and the veto unreachable.
    #[test]
    fn an_episode_of_a_series_called_proof_is_not_a_teaser_of_its_own_special() {
        let _steady = trash_globals_steady();
        for door in ["junk", "media"] {
            let d = scratch(&format!("proofep{door}"));
            let ep = d.join("Proof.S01E01.mp4");
            let special = d.join("Proof.S01E00.Special.mp4");
            std::fs::write(&ep, vec![7u8; 400 << 10]).unwrap();
            std::fs::write(&special, vec![8u8; 4 << 20]).unwrap();
            let n = if door == "junk" {
                super::super::sweep_junk(&d)
            } else {
                super::super::keep_media_only(&d)
            };
            assert!(
                ep.exists(),
                "{door}: stripping the marker leaves `s01e01`, which names \
                 nothing else here - this is an episode, not a teaser of the \
                 special (swept {n})"
            );
            assert_eq!(
                std::fs::read(&ep).unwrap().len(),
                400 << 10,
                "{door}: kept, and whole - the delete here is permanent"
            );
            assert!(special.exists(), "{door}: the special stays too");
        }
    }

    /// THE CONTROL, and it is the half that matters: a real teaser must
    /// still be DELETED, by both doors, at an extension the container
    /// probe cannot read. Without this the row above passes by retiring
    /// the sweep - which is the whole point of the sample rule.
    ///
    /// `Movie.2024.sample.mp4` beside `Movie.2024.mp4` is the ordinary
    /// scene spelling: strip the marker and what is left IS the
    /// feature's name.
    #[test]
    fn a_real_teaser_is_still_swept_at_an_unprobeable_extension() {
        let _steady = trash_globals_steady();
        for door in ["junk", "media"] {
            let d = scratch(&format!("realteaser{door}"));
            let teaser = d.join("Movie.2024.sample.mp4");
            let feature = d.join("Movie.2024.mp4");
            std::fs::write(&teaser, vec![7u8; 400 << 10]).unwrap();
            std::fs::write(&feature, vec![8u8; 4 << 20]).unwrap();
            let n = if door == "junk" {
                super::super::sweep_junk(&d)
            } else {
                super::super::keep_media_only(&d)
            };
            assert!(
                !teaser.exists(),
                "{door}: a teaser named after the feature beside it is exactly \
                 what this sweep exists to remove (swept {n})"
            );
            assert!(feature.exists(), "{door}: the feature stays");
        }
    }

    /// The obfuscated post, which is the one shape the derived-name test
    /// cannot reach - the teaser's posted name and the feature's have
    /// nothing in common - and which the APPENDED-marker clause carries.
    /// A control for the gate as a whole: it must not have narrowed the
    /// sweep to names that share a stem.
    #[test]
    fn an_appended_marker_is_a_teaser_even_beside_an_unrelated_name() {
        let _steady = trash_globals_steady();
        let d = scratch("obfteaser");
        let teaser = d.join("Movie.Sample.mp4");
        let feature = d.join("Main.Video.mp4");
        std::fs::write(&teaser, vec![7u8; 400 << 10]).unwrap();
        std::fs::write(&feature, vec![8u8; 4 << 20]).unwrap();
        let n = super::super::sweep_junk(&d);
        assert!(
            !teaser.exists(),
            "the marker is the LAST token, which is how a scene post spells a \
             teaser it did not name after anything (swept {n})"
        );
        assert!(feature.exists());
    }

    /// The sibling list is the sweep's WHOLE footprint - both levels it
    /// reaches, read ONCE before anything is deleted - and this drives
    /// the two directions separately because they pin different arms.
    ///
    /// `Sample/` beside the feature is where a scene post puts a teaser,
    /// and it pins the read-once ORDERING: `keep_media_only` removes as
    /// it walks, so a per-directory sibling list gives this teaser no
    /// relatives at all and spares it. Mutation-checked.
    ///
    /// The root teaser with its feature one level down is the half that
    /// pins `files_in_reach`'s DESCENT. The first shape alone does not:
    /// with the descent removed the teaser is still judged against the
    /// root feature and still goes, so that mutation survives - found by
    /// driving it, not by reading. Here the descent is the only thing
    /// that can produce a relative at all, and without it the teaser is
    /// kept for having none.
    #[test]
    fn a_teaser_is_judged_against_both_levels_the_sweep_reaches() {
        let _steady = trash_globals_steady();

        let d = scratch("subdirteaser");
        std::fs::create_dir_all(d.join("Sample")).unwrap();
        let teaser = d.join("Sample/Movie.2024.sample.mp4");
        let feature = d.join("Movie.2024.mp4");
        std::fs::write(&teaser, vec![7u8; 400 << 10]).unwrap();
        std::fs::write(&feature, vec![8u8; 4 << 20]).unwrap();
        let n = super::super::keep_media_only(&d);
        assert!(
            !teaser.exists(),
            "one level down is inside the sweep's own reach, and the feature it \
             is named after is at the root (swept {n})"
        );
        assert!(feature.exists(), "the root feature stays");

        let d2 = scratch("rootteaser");
        std::fs::create_dir_all(d2.join("Video")).unwrap();
        let teaser2 = d2.join("Movie.2024.sample.mp4");
        let feature2 = d2.join("Video/Movie.2024.mp4");
        std::fs::write(&teaser2, vec![7u8; 400 << 10]).unwrap();
        std::fs::write(&feature2, vec![8u8; 4 << 20]).unwrap();
        let n2 = super::super::keep_media_only(&d2);
        assert!(
            !teaser2.exists(),
            "the ONLY name this teaser can be named after is one level down - \
             a sibling list that stops at the root has nothing to compare it \
             to and keeps it (swept {n2})"
        );
        assert!(feature2.exists(), "the feature one level down stays");
    }
}
