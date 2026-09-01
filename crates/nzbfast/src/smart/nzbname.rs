//! Name a finished download after the .nzb file it came from (issue #32,
//! TODO 142) - and the folder rename both this and the auto-renamer end
//! in.
//!
//! A sibling of the auto-rename layer, not a parallel path: the same
//! `finalize_names` decides between them, and the folder half is
//! literally the same code (`rename_dir`, lifted out of `rename_movie`
//! so both callers keep the Windows behaviour that took a bug report to
//! find).
//!
//! What differs is where the name comes from. Auto-rename builds one out
//! of what the release PARSES as - title, year, resolution, group. This
//! takes the .nzb filename as given. The reporter's own case is the
//! argument: they file their NZBs under names they chose, and every
//! clever thing we do to that name is a thing they have to undo.
//!
//! Two rules the shape rests on:
//!
//!  * ONE file is renamed - the biggest that is actually payload. An
//!    episode pack keeps every other episode's name, and a film's
//!    sample, subtitles, .nfo and .par2 keep theirs. Furniture wearing
//!    the release's identity is a hazard we have already paid for once
//!    (a 10 MB "sample" row promoted onto the wall as if it were the
//!    release), and the on-disk version of that mistake is a media
//!    library importing the sample.
//!  * The name is sanitised with `disk::sanitize_filename`, the exact
//!    transform `enqueue` used to build the job folder - NOT
//!    `release::sanitize_name`, which expands colons and collapses
//!    separators. That one produces a nicer name; a nicer name is what
//!    the user turned this option on to stop getting.

use super::*;

/// Put the .nzb file's own name on the finished folder and its main
/// file. Returns the new out_dir when the folder moved, else None -
/// same contract as [`rename_movie`](super::rename_movie).
///
/// `nzb_name` is the job's name as added: `enqueue` takes it from the
/// .nzb filename (or from `nzbname=`, when an *arr sent one - that is
/// the name the client asked for, and it wins on purpose). A trailing
/// `.nzb` is tolerated so a caller holding the raw filename gets the
/// same answer.
pub fn rename_from_nzb(parent: &Path, out_dir: &Path, nzb_name: &str) -> Option<PathBuf> {
    let stem = nzb_name.strip_suffix(".nzb").unwrap_or(nzb_name);
    // A name with no letter or digit in it has nothing to source FROM.
    // `sanitize_filename` would hand back its "unnamed" fallback, which
    // is a fine folder name for a job that has to live somewhere and a
    // terrible thing to rename a finished payload to.
    if !stem.chars().any(char::is_alphanumeric) {
        return None;
    }
    let base = nzbkit::disk::sanitize_filename_capped(stem);
    if base.is_empty() {
        return None;
    }
    if let Some(file) = main_payload(out_dir) {
        rename_main_file(&file, &base);
    }
    // The folder is USUALLY already right: `enqueue` names it from this
    // same string through this same sanitiser, so the only reason to be
    // here is an auto-rename that has since moved it - or a collision
    // suffix, which is load-bearing (a second job's payload lives at the
    // unsuffixed name) and must not be renamed away.
    if dir_is_named_after(out_dir, &base) {
        return None;
    }
    rename_dir(parent, out_dir, &base)
}

/// The finished job's main file: the largest thing under `dir` that is
/// payload rather than furniture.
///
/// "Largest" is the whole definition, and it is the reporter's own
/// answer to what "the main file" means for a download that produces
/// several. Everything else in the directory keeps the name it has.
///
/// Furniture is named explicitly rather than inferred from size:
///
///  * junk extensions (.par2, .nzb, .sfv, .nfo, …) and subtitles -
///    a subtitle re-stemmed onto the release identity is the same
///    category of mistake as a sample, and the sidecar it belonged to
///    is no longer named after it either way;
///  * sample clips, by the same grammar the junk sweep uses;
///  * anything still packed - a `.rar`/`.r00`/`.7z.001` volume is
///    routinely the biggest file in a job that failed to unpack, and
///    renaming one member of a multi-volume set breaks the set. A
///    numbered byte split is that same set with nothing in the name or
///    the head to say so, in both its readings, so it is answered as
///    MEMBERSHIP - see `is_packed_archive`;
///  * either half of a cue-named set. A cue sheet is a NAME MAP, so
///    `Album.bin` taking the release name leaves `Album.cue` addressing
///    a file that is no longer there - the same set-breaking rename as
///    an archive volume, and the same failure M4-88 fixed one door over
///    in the deletion sweep. The sheet is refused too: see
///    `discimage::is_cue_set_member` for what each half costs;
///  * dotfiles. `.nzbfast.journal` and friends are our own state, and
///    they are hidden on macOS and Linux and NOTHING on Windows, so
///    "the user cannot see it" is not a reason it cannot be picked.
///    Named here rather than trusted to be invisible - that assumption
///    has already put a journal in front of a tester once.
///
/// The top level plus one directory down, which is where extraction
/// puts an ordinary release.
///
/// This USED to say "same reach as `main_video`", and that stopped
/// being true when M4-81 widened `largest_video` to walk a disc tree.
/// The two doors disagree ON PURPOSE: that one only ANSWERS a
/// question, so reaching further is free, while this one RENAMES what
/// it picks. DO NOT close the gap by widening this reach. A disc tree
/// has no single "main file" whose name is free to change, so reaching
/// deeper only moves which file gets broken - see the disc arm below,
/// which is the answer instead.
///
/// ## The disc arm
///
/// A job that IS a disc declines outright, and the release name is
/// carried by the folder rename alone. Two shapes were measured
/// BREAKING on origin/main before this landed, driven through
/// `rename_from_nzb`:
///
///  * Blu-ray. `BDMV/STREAM/00000.m2ts` is two down and out of reach,
///    so the biggest thing this could SEE was `BDMV/index.bdmv` - the
///    file a player opens FIRST - and it took the release name. The
///    disc stopped playing, over a **Completed** job, with no error
///    anywhere.
///  * DVD-Video, which is WORSE and was not in the report that led
///    here. `VIDEO_TS/VTS_01_1.VOB` sits at exactly root + one, so
///    this reached the whole payload and renamed it - to
///    `Great.Movie.2024.vob`, lowercasing the extension on the way,
///    while `VIDEO_TS.IFO` goes on addressing it by its old name.
///
/// That is the relpath-preserve rule - a DVD or Blu-ray has to have
/// its directory structure intact to play at all - broken by the
/// NAMING door rather than by the flatten cap M4-71 covered. The
/// test is [`feature::disc_structure`], which walks with the same
/// bounds `largest_video` does; the reasoning for asking the shape
/// question rather than picking a safer file is there.
///
/// Membership is a property of the DIRECTORY a file sits in, so the
/// four sets are rebuilt for each directory this reaches rather than
/// taken once from the top. Built once, they answered a question about
/// the parent for every file one level down, and the parent's sets never
/// contain a subfolder's parts - so every set-based arm of
/// `is_furniture` read a subfolder split as ordinary payload and the
/// largest member took the release name, breaking the set. Observed 25
/// Aug 2026 on the shape TODO 301 recorded as the reachable one: an
/// `Extras/` folder holding a plain headerless split, whose part 1 came
/// back as `Whatever This Is.001`. `keep_media_only` has always
/// recomputed per directory - that asymmetry was the whole defect.
pub fn main_payload(dir: &Path) -> Option<PathBuf> {
    if let Some(marker) = feature::disc_structure(dir) {
        // The one trace a user has of why the option they turned on
        // renamed the folder and nothing inside it.
        info!(
            target: "smart",
            "not naming a file after the nzb: {} is a disc ({}), and every name in a disc tree is load-bearing",
            dir.display(),
            marker.display()
        );
        return None;
    }
    let mut best: Option<(u64, PathBuf)> = None;
    let mut rank = |d: &Path, paths: &[PathBuf]| {
        let zip_parts = zip_part_set(d);
        // Both readings of the numbered byte split - see `is_packed_archive`.
        let mut split_parts = crate::container_part_set(d);
        split_parts.extend(crate::split_part_set(d));
        // A cue sheet names its own track data, so read the sheets once
        // and let them speak for their siblings - the same evidence the
        // deletion sweep reads, answering the rename question here: see
        // `discimage::is_cue_set_member`.
        let cue_named = discimage::cue_named_files(d);
        for path in paths {
            if !is_real_file(path) || is_furniture(path, &zip_parts, &split_parts, &cue_named) {
                continue;
            }
            let len = path.metadata().map(|m| m.len()).unwrap_or(0);
            if best.as_ref().is_none_or(|(b, _)| len > *b) {
                best = Some((len, path.clone()));
            }
        }
    };
    let tops: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    let (subs, files): (Vec<PathBuf>, Vec<PathBuf>) =
        tops.into_iter().partition(|p| is_real_dir(p));
    rank(dir, &files);
    for sub in subs {
        let Ok(rd) = std::fs::read_dir(&sub) else {
            continue;
        };
        let kids: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        rank(&sub, &kids);
    }
    best.map(|(_, p)| p)
}

/// Everything [`main_payload`] refuses to call the main file. See there
/// for why each entry is on the list.
fn is_furniture(
    p: &Path,
    zip_parts: &std::collections::HashSet<PathBuf>,
    split_parts: &std::collections::HashSet<PathBuf>,
    cue_named: &std::collections::HashSet<String>,
) -> bool {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    if name.starts_with('.') {
        return true;
    }
    let ext = ext_of(p);
    is_junk_ext(&ext)
        || SUBTITLE_EXTS.contains(&ext.as_str())
        // By NAME. `main_payload` accepts an extensionless container
        // since #43, and the extension-gated predicate let an
        // extensionless `sample` through as ordinary payload - so a job
        // whose feature was still packed (packed IS furniture) promoted
        // the teaser to the release name (Codex sweep 6, N1). This is a
        // rename decision; the junk sweep's is not, and keeps the
        // narrower rule.
        || is_sample_named(p)
        || is_packed_archive(p, zip_parts, split_parts)
        || discimage::is_cue_set_member(&name, &ext, cue_named)
}

/// `file` -> `base.ext`, in place. Keeps the extension (that is what
/// says what the file IS) and takes no sidecars with it: only the main
/// file is renamed.
fn rename_main_file(file: &Path, base: &str) {
    // The extension it should CARRY. `main_payload` accepts an
    // extensionless container since #43, but deriving the target from
    // `ext_of` alone produced "Chosen Name" with no extension - friendly
    // and still invisible to completed-media discovery and to any
    // library that scans by extension. This route is mutually exclusive
    // with auto-rename and disables the later identify rung, so nothing
    // downstream was going to rescue it (Codex sweep 5, M3).
    let ext = match ext_of(file) {
        e if !e.is_empty() => e,
        _ => super::video_ext(file).unwrap_or_default(),
    };
    // CAPPED on the COMPOSED name, which is
    // `disk::sanitize_filename_capped_for`'s own rule stated at that
    // function and broken here: `base` is already
    // `sanitize_filename_capped`'s output (see `rename_from_nzb`), so for
    // a long .nzb filename it is AT the 255-byte component cap exactly -
    // capping is what produced it - and `{base}.mkv` is 259 bytes, which
    // `rename` refuses with `ENAMETOOLONG`. The rename is then reported
    // and the payload keeps the obfuscated name this door exists to
    // replace.
    //
    // The composed name and not a stem reserve, because this door takes
    // NO sidecars with it (see the header) - it is one composition, so
    // there is no pairing for a shared stem to preserve, which is the
    // only thing a reserve buys. `smart::filing`'s three-name doors are
    // the other case and go through `capped_base` for exactly that
    // reason. Inside the cap this is the plain `format!` byte for byte,
    // so no rename that works today moves.
    let want = if ext.is_empty() {
        base.to_string()
    } else {
        nzbkit::disk::sanitize_filename_capped(&format!("{base}.{ext}"))
    };
    let target = file.with_file_name(&want);
    if target == *file {
        return;
    }
    // `symlink_metadata`, not `exists()`. This site is what "treat 12
    // as a floor" in the census meant: it sits twelve lines from its
    // rename, so the proximity scan that found the other twelve never
    // saw it. The comment below already states the argument exactly -
    // leaving the file alone is cheap and overwriting is not - and
    // `exists()` is what stopped it being true for a symlink, because it
    // FOLLOWS the link and answers false on any error while `rename(2)`
    // removes whatever ENTRY is at the destination and never resolves
    // it. Argued in full at `tv_rename` in `smart/filing.rs`.
    //
    // AND IT IS A CLAIM RATHER THAN A LOOK, 31 Aug 2026, argued in full
    // at that same guard: the `lstat` covered about 1% of its own
    // interval, and `create_new` answers `AlreadyExists` over all four
    // entry kinds - so the claim IS this guard, taken atomically. Plain
    // and not `disk::open_out_leaf_under`, because the rename below
    // resolves its destination by path.
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            // Something in this folder already holds the name. Leaving
            // the main file alone is the cheap outcome; overwriting it
            // is not.
            warn!(
                target: "smart",
                "not naming {} after the nzb: {} already exists",
                file.display(),
                target.display()
            );
        } else {
            // The door is unusable rather than taken - a read-only
            // volume, a parent that went away - which the rename below
            // would have reported, so it still is.
            warn!(
                target: "smart",
                "not naming {} after the nzb: could not claim {}: {e}",
                file.display(),
                target.display()
            );
        }
        return;
    }
    match std::fs::rename(file, &target) {
        Ok(()) => info!(
            target: "smart",
            "named after the nzb: {} -> {}",
            file.display(),
            target.display()
        ),
        Err(e) => {
            // Our own placeholder. Left behind it is a zero-byte file
            // wearing the release name, which the very next pass reads
            // as the name being taken - so one recoverable failure
            // would become a permanent refusal, and completed-media
            // discovery would find the empty one.
            let _ = std::fs::remove_file(&target);
            warn!(
                target: "smart",
                "rename {} -> {}: {e}",
                file.display(),
                target.display()
            );
        }
    }
}

/// Is `out_dir` already the folder `base` would rename it to?
///
/// True for an exact match and for the `.2`/`.3` collision suffixes
/// `choose_out_dir` hands out. The suffix is not noise to be tidied
/// away: it exists because the unsuffixed name is another job's payload,
/// and renaming onto it is the one thing the whole collision ladder is
/// there to prevent.
fn dir_is_named_after(out_dir: &Path, base: &str) -> bool {
    let Some(cur) = out_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
    else {
        return false;
    };
    if cur == base {
        return true;
    }
    cur.strip_prefix(base)
        .and_then(|rest| rest.strip_prefix('.'))
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// Rename the job folder to `parent/base`, with `.2`/`.3` collision
/// suffixes - an existing folder is never overwritten. Returns the new
/// path when it moved, else None (the caller keeps the current one).
///
/// Lifted out of `rename_movie` when the nzb-name option needed the same
/// half. The Windows fallback below is the reason it is shared rather
/// than written twice.
pub(super) fn rename_dir(parent: &Path, out_dir: &Path, base: &str) -> Option<PathBuf> {
    let want = parent.join(base);
    if want == out_dir {
        return None;
    }
    let mut target = want;
    let mut n = 2;
    // `symlink_metadata`, because this loop is looking for a FREE name
    // and a name an entry holds is not one. `Path::exists` follows
    // symlinks and answers false on any error, so the ladder stopped on
    // a dangling link - or one onto a share that is not mounted - and
    // handed a taken name to the rename below.
    //
    // AND IT STAYS A LOOK, deliberately, where the other nine doors on
    // the 31 Aug 2026 occupancy census took a `create_new` claim under
    // `occupancy-claim-the-rest-of-the-class` - this one included
    // `rename_main_file` fifty lines above. The claim closes a
    // check-before-use window in which an entry that arrives is renamed
    // OVER; the paragraph below is the reason there is no such harm
    // here, and it is the source type rather than the timing. A
    // placeholder would also be the wrong shape: it is a FILE, and a
    // directory cannot be renamed onto one at all, so claiming this
    // name would break the rename it is meant to protect. What is left
    // is a liveness question - the ladder may hand back a name that has
    // since been taken and the rename then fails, reported, and the
    // folder keeps its own name.
    //
    // NOTHING IS DESTROYED by getting this wrong, unlike the four guards
    // in `filing.rs` that share the fingerprint, and the reason is the
    // SOURCE TYPE: `out_dir` is a directory, and MEASURED on APFS 31 Aug
    // 2026 `rename(2)` answers ENOTDIR for a directory onto a symlink of
    // either kind. What happened instead is that the rename failed, its
    // entry-by-entry fallback failed EEXIST at `create_dir_all` (a
    // symlink is an existing entry to `mkdir` too), and the folder was
    // not renamed at all - reported as "rename dir ...: Not a directory
    // (and entry by entry: File exists)", about a path the user's own
    // `ls` shows as a broken link. Stepping to `base.2` is what the
    // ladder is for and costs nothing, which is why this one needs no
    // harms argument: it is strictly better in both directions.
    //
    // CAPPED on the composed name, for the same reason and by the same
    // door as `rename_main_file` above: `base` is already at the 255-byte
    // cap for a long .nzb name, so `{base}.2` is 257 and the rename
    // below fails `ENAMETOOLONG`. That failure is loud and costs only the
    // rename - the folder keeps the name it had - but it costs it for
    // every collision rather than none. Note the loop EXITS on such a
    // name rather than spinning: `symlink_metadata` answers Err for a
    // name too long to look up, which reads as free.
    while std::fs::symlink_metadata(&target).is_ok() {
        target = parent.join(nzbkit::disk::sanitize_filename_capped(&format!(
            "{base}.{n}"
        )));
        n += 1;
    }
    match std::fs::rename(out_dir, &target) {
        Ok(()) => {
            info!(
                target: "smart",
                "renamed {} → {}",
                out_dir.display(),
                target.display()
            );
            Some(target)
        }
        // Windows refuses to rename a DIRECTORY while any file inside it is
        // open, and at this point the extractor still holds the payload: it
        // keeps its output writers for the streaming endpoint and stays alive
        // past completion. So this failed with "Access is denied." on every
        // Windows install, and because the payload FILE had already been
        // renamed above (Rust opens with FILE_SHARE_DELETE, which permits
        // renaming a file but not its parent), an obfuscated download was
        // left as `complete/movies/<hash>/Example Movie 2019 1080p.mkv` -
        // half-renamed, which is the worst of both.
        //
        // Moving the CONTENTS across works where moving the container does
        // not, for that same reason: each entry is renamed individually and an
        // open handle does not stop it - proven by the payload rename above
        // succeeding. Handles stay valid afterwards (they follow the file, not
        // the path), so streaming a job whose folder was just renamed keeps
        // working, which is why this is done here rather than by closing the
        // writers: closing them makes a /stream request that is waiting for
        // them hang instead (`stream_of_library_job_triggers_download`).
        //
        // Unix renames directories around open descriptors happily, so it
        // takes the branch above and never reaches this.
        Err(e) => match move_dir_contents(out_dir, &target) {
            Ok(()) => {
                info!(
                    target: "smart",
                    "renamed {} → {} (entry by entry: {e})",
                    out_dir.display(),
                    target.display()
                );
                Some(target)
            }
            Err(e2) => {
                warn!(
                    target: "smart",
                    "rename dir {} → {}: {e} (and entry by entry: {e2})",
                    out_dir.display(),
                    target.display()
                );
                None
            }
        },
    }
}

/// Move everything in `from` into a fresh `to`, then drop the empty `from`.
///
/// The fallback for a directory rename that the platform will not do as one
/// operation - see the call site. `to` must not already exist; the caller
/// picked a free name.
///
/// Every entry moves with a plain rename, so this stays same-filesystem and
/// never copies payload: `to` is a sibling of `from`. A partial failure
/// leaves entries in BOTH places and reports the error, which the caller
/// turns into "the folder was not renamed" - the files are all still present
/// under one name or the other, and nothing is deleted here except the
/// emptied directory itself.
fn move_dir_contents(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        std::fs::rename(entry.path(), to.join(entry.file_name()))?;
    }
    // Only removes it if it really is empty, so a missed entry surfaces as a
    // leftover directory rather than as a deletion.
    std::fs::remove_dir(from)
}

#[cfg(test)]
#[path = "nzbname_tests.rs"]
mod nzbname_tests;
