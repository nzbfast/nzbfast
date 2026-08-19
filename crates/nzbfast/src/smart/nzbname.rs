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
    let base = nzbkit::disk::sanitize_filename(stem);
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
///    renaming one member of a multi-volume set breaks the set;
///  * dotfiles. `.nzbfast.journal` and friends are our own state, and
///    they are hidden on macOS and Linux and NOTHING on Windows, so
///    "the user cannot see it" is not a reason it cannot be picked.
///    Named here rather than trusted to be invisible - that assumption
///    has already put a journal in front of a tester once.
///
/// Same reach as [`main_video`](super::main_video): the top level plus
/// one directory down, which is where extraction puts things.
pub fn main_payload(dir: &Path) -> Option<PathBuf> {
    let zip_parts = zip_part_set(dir);
    let mut best: Option<(u64, PathBuf)> = None;
    let mut consider = |path: PathBuf| {
        if !is_real_file(&path) || is_furniture(&path, &zip_parts) {
            return;
        }
        let len = path.metadata().map(|m| m.len()).unwrap_or(0);
        if best.as_ref().is_none_or(|(b, _)| len > *b) {
            best = Some((len, path));
        }
    };
    let tops: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    for path in tops {
        if is_real_dir(&path) {
            if let Ok(rd) = std::fs::read_dir(&path) {
                for e in rd.flatten() {
                    consider(e.path());
                }
            }
        } else {
            consider(path);
        }
    }
    best.map(|(_, p)| p)
}

/// Everything [`main_payload`] refuses to call the main file. See there
/// for why each entry is on the list.
fn is_furniture(p: &Path, zip_parts: &std::collections::HashSet<PathBuf>) -> bool {
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
        || is_sample_clip(p)
        || is_packed_archive(p, zip_parts)
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
    let want = if ext.is_empty() {
        base.to_string()
    } else {
        format!("{base}.{ext}")
    };
    let target = file.with_file_name(&want);
    if target == *file {
        return;
    }
    if target.exists() {
        // Something in this folder already holds the name. Leaving the
        // main file alone is the cheap outcome; overwriting it is not.
        warn!(
            target: "smart",
            "not naming {} after the nzb: {} already exists",
            file.display(),
            target.display()
        );
        return;
    }
    match std::fs::rename(file, &target) {
        Ok(()) => info!(
            target: "smart",
            "named after the nzb: {} -> {}",
            file.display(),
            target.display()
        ),
        Err(e) => warn!(
            target: "smart",
            "rename {} -> {}: {e}",
            file.display(),
            target.display()
        ),
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
    while target.exists() {
        target = parent.join(format!("{base}.{n}"));
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
