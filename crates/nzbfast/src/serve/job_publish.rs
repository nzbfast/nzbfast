//! Where a finished job's files land, and how a re-run replaces an
//! earlier one.
//!
//! The collision claim (`DirClaim` / `choose_out_dir` / `refile_out_dir`),
//! the aside-and-rename publish over a previous run, the startup sweep
//! that repairs a publish interrupted mid-rename, and the same-directory
//! test all three rely on (TODO 106 code motion out of job.rs, behaviour
//! unchanged).

use super::*;

/// Finish, or undo, a replace that a crash caught between its two renames.
///
/// `publish_over_previous` renames the canonical directory aside, then
/// renames the new payload onto it, and only then removes the aside. It
/// rolls back on a reported error, but a power cut or a kill between the
/// two renames left NO canonical directory at all: the previous
/// completed job's history record pointed at a path that no longer
/// existed, its bytes sat under a pid-suffixed name nothing would ever
/// look at again, and the new payload stayed in its `.2` collision
/// directory. Dashboard "open folder", delete-with-files and any *arr
/// import against that job all hit a missing directory, silently. The
/// aside name appeared in exactly one place in the whole tree - where it
/// is built - so nothing swept, restored or even reported these.
///
/// Only the unambiguous case is repaired: the canonical path is GONE, so
/// the aside is the only copy and belongs back. When both exist the
/// likely story is that the second rename landed and only the cleanup
/// was lost, but "likely" is not enough to delete a directory full of a
/// user's media, so that one is reported and left alone.
pub(in crate::serve) fn recover_interrupted_publishes(out_root: &std::path::Path) {
    // Job directories live at out_root/<name> or out_root/<cat>/<name>,
    // so one level down is enough; this is startup, not a deep walk.
    let mut dirs = vec![out_root.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(out_root) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                dirs.push(e.path());
            }
        }
    }
    for dir in dirs {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let aside = e.path();
            let Some(name) = aside.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // Match the way the aside is BUILT: `<canonical>` + suffix +
            // the parking process's pid, and nothing after it. A plain
            // `find` accepted any name merely containing the suffix, so a
            // user's own "Movie.nzbfast-replaced-Final" would be renamed
            // to "Movie" over their heads - and, worse, the last
            // occurrence is the one we split at, so a canonical name that
            // itself ends in the suffix still resolves correctly.
            let Some((stem, tail)) = name.rsplit_once(REPLACED_SUFFIX) else {
                continue;
            };
            if stem.is_empty() || tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if !aside.is_dir() {
                continue;
            }
            let canon = dir.join(stem);
            if canon.symlink_metadata().is_ok() {
                info!(
                    target: "replace",
                    "{} and {} both exist - an interrupted replace left a spare \
                     copy. Nothing is lost; delete whichever you do not want.",
                    canon.display(),
                    aside.display()
                );
                continue;
            }
            match std::fs::rename(&aside, &canon) {
                Ok(()) => info!(
                    target: "replace",
                    "restored {} from {} - a replace was interrupted before the \
                     new download took its place",
                    canon.display(),
                    aside.display()
                ),
                Err(err) => warn!(
                    target: "replace",
                    "could not restore {} from {}: {err} (the download is intact \
                     under the second name)",
                    canon.display(),
                    aside.display()
                ),
            }
        }
    }
}

/// Who already holds a candidate output directory.
pub(crate) enum DirClaim {
    Free,
    /// Another job is still working in it.
    Active,
    /// A completed job's payload is still there.
    Payload,
}

/// Pick a new job's output directory, and the canonical directory it must
/// publish over on success (`Job::replaces`).
///
/// Two DIFFERENT NZBs whose names sanitize to the same stem and carry no
/// dupe_key (no SxxEyy/year marker - e.g. software or music posts) are not
/// caught by the M14f duplicate hold, so they would share one out_dir.
/// Their pipelines deliberately overlap (A's tail repairs/extracts while
/// B's net leg runs), so B's journal + volume writers truncate the files A
/// is still reading → both corrupt. A colliding job gets its own directory.
///
/// A COMPLETED job's payload claims its directory too. Treating it as
/// inert meant a re-add reused the folder and the very first decoded span
/// truncated the previous, good result - which was then gone for nothing
/// if the replacement failed on missing articles, a password or ENOSPC.
/// The re-add downloads under its own name and takes over the canonical
/// directory only once it has verified. A FAILED job's leftovers are junk
/// and are still reused in place, so retrying a flaky post does not climb
/// .2, .3, .4.
pub(crate) fn choose_out_dir(
    base: &std::path::Path,
    dir_stem: &str,
    claim: &dyn Fn(&std::path::Path) -> DirClaim,
) -> (PathBuf, Option<PathBuf>) {
    let mut candidate = base.to_path_buf();
    let mut replaces = None;
    let mut n = 1u32;
    loop {
        match claim(&candidate) {
            DirClaim::Free => return (candidate, replaces),
            // Only the canonical directory is ever replaced; a numbered
            // sibling left by some earlier collision is left alone.
            DirClaim::Payload if candidate == base => replaces = Some(base.to_path_buf()),
            _ => {}
        }
        n += 1;
        candidate = base.with_file_name(format!("{dir_stem}.{n}"));
    }
}

/// Where a re-queued job that had been TV-filed must download instead.
///
/// Its `out_dir` is the SHARED `Show/Season NN` library folder, so
/// re-queueing it as-is aims the journal, the volume writers and every
/// later "delete this job's files" at a directory belonging to the whole
/// season. This picks the ordinary private directory the job would get on
/// a fresh add - collision rules and all, so it cannot land on another
/// job's folder either.
pub(crate) fn refile_out_dir(
    out_root: &std::path::Path,
    category: &str,
    name: &str,
    claim: &dyn Fn(&std::path::Path) -> DirClaim,
) -> (PathBuf, Option<PathBuf>) {
    let dir_stem = nzbkit::disk::sanitize_filename(name.trim_end_matches(".nzb"));
    let base = if category.is_empty() {
        out_root.join(&dir_stem)
    } else {
        out_root
            .join(nzbkit::disk::sanitize_filename(category))
            .join(&dir_stem)
    };
    choose_out_dir(&base, &dir_stem, claim)
}

/// Take over the canonical output directory from the completed job this
/// one replaces (see `Job::replaces`). Called once the job has finished
/// successfully and before any renaming or relocation, so everything
/// downstream sees the final location.
///
/// The previous result is moved aside first and only deleted once the new
/// payload is in place; if the move in fails, the old result goes straight
/// back and this job keeps its own directory. A re-add that never
/// finishes therefore costs the user nothing - which is the whole point,
/// since reusing the folder used to truncate the good payload with the
/// replacement's first decoded span.
///
/// Returns the directory the job now lives in, or `None` when nothing
/// moved.
pub(crate) fn publish_over_previous(
    out_dir: &std::path::Path,
    canon: &std::path::Path,
) -> Option<PathBuf> {
    if out_dir == canon || !out_dir.exists() {
        return None;
    }
    // Same constant `recover_interrupted_publishes` scans for at startup:
    // a crash between the two renames below leaves this directory as the
    // only copy of the superseded download, and the sweep puts it back.
    let aside = canon.with_file_name(format!(
        "{}{REPLACED_SUFFIX}{}",
        canon.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let parked = canon.symlink_metadata().is_ok();
    if parked && let Err(e) = std::fs::rename(canon, &aside) {
        warn!(
            target: "replace",
            "could not move {} aside: {e} - keeping the new download in {}",
            canon.display(),
            out_dir.display()
        );
        return None;
    }
    match std::fs::rename(out_dir, canon) {
        Ok(()) => {
            if parked && let Err(e) = std::fs::remove_dir_all(&aside) {
                warn!(
                    target: "replace",
                    "previous result left behind in {}: {e}",
                    aside.display()
                );
            }
            info!(target: "replace", "{} → {}", out_dir.display(), canon.display());
            Some(canon.to_path_buf())
        }
        Err(e) => {
            warn!(
                target: "replace",
                "{} → {}: {e} - keeping the new download where it is",
                out_dir.display(),
                canon.display()
            );
            if parked {
                let _ = std::fs::rename(&aside, canon);
            }
            None
        }
    }
}

/// Are these two paths the same directory on disk?
///
/// A byte compare is not enough: a case variant on APFS or NTFS, a
/// symlinked parent, or a "." component all name the same place while
/// comparing unequal - and a move destination that aliases the download
/// folder makes move_tree merge a directory with itself and rename every
/// file in it to "name (2).ext".
///
/// canonicalize only works on paths that exist, so a missing path falls
/// back to the byte compare. That is the safe direction here: the caller
/// has just created the destination, and the check is a guard rail, not
/// a security boundary.
pub(in crate::serve) fn same_dir(a: &std::path::Path, b: &std::path::Path) -> bool {
    a == b
        || match (a.canonicalize(), b.canonicalize()) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
}
