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
pub fn recover_interrupted_publishes(out_root: &std::path::Path) {
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
pub enum DirClaim {
    Free,
    /// Another job is still working in it.
    Active,
    /// A completed job's payload is still there.
    Payload,
    /// The directory holds files and NOTHING in the daemon names it -
    /// so it is not ours, and we know nothing about what is in it. A
    /// hand-organised folder that happens to share the release stem, a
    /// completed payload whose history row the user cleared, the user's
    /// own library under a write-through destination: all read the same
    /// from here, because the only evidence is "occupied and
    /// unrecorded".
    ///
    /// It must NEVER become a replace target. `Payload` is a claim by a
    /// record we hold - "our own completed result of this release" -
    /// and replacing it is the intended semantics: `publish_over_previous`
    /// renames the canonical directory aside and `remove_dir_all`s it
    /// once the new download verifies. Doing that to a stranger's
    /// directory is data loss, and no amount of verification on OUR side
    /// makes it right, because the two are not the same release in any
    /// sense we can check. So this claim only ever makes the job CLIMB:
    /// it downloads at `<stem>.2` and the directory is never touched,
    /// before completion or after.
    Occupied,
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
///
/// An OCCUPIED directory - files in it, and no record of ours naming it -
/// makes the job climb the same way but records NO replace. It is not
/// ours to take over: see [`DirClaim::Occupied`].
///
/// # The climb is CAPPED, and on the COMPOSED name
///
/// `dir_stem` reaches here already capped at 255 bytes -
/// `Daemon::enqueue` and [`refile_out_dir`] both spell it through
/// `disk::sanitize_filename_capped`, and `history`'s arm takes an
/// existing directory's own leaf - so for a long job name it is AT the
/// 255-byte cap exactly, capping being what produced it. `.2` on top of
/// that is 257 bytes and every `mkdir` under it is `ENAMETOOLONG`
/// (measured on APFS 31 Aug 2026: 255 creates, 256 does not), so the
/// FIRST collision handed a job a directory it could not have. The base
/// itself was already covered - that is
/// `an_overlong_job_name_still_gets_a_writable_directory` - and the
/// climb was not, because that pin's claim never collides.
///
/// The COMPOSED name and not a stem reserve, which is
/// `disk::sanitize_filename_capped_for`'s own division: this string is an
/// IDENTITY KEY as much as a path. `Daemon::dir_claim` answers by
/// comparing it against every job's `out_dir`, `reserved` holds it while
/// a recategorize moves into it, and the job record stores it - so a name
/// shortened at the write and not at the key would leave two spellings of
/// one directory, which is how two live jobs come to share a folder.
/// Applying the SAME transform the callers apply to the stem is what
/// keeps the two ends together.
///
/// Termination is unchanged, and it rests on the capping function's HASH
/// TAG rather than on front-preservation the way
/// `disk::disambiguated_out_name`'s does - the front here is `dir_stem`,
/// which every rung shares, and it is the `.{n}` at the TAIL that
/// truncation removes. That is what the tag is for, and it is the same
/// argument `par2repair`'s `.dup-` suffix already rests on. In practice
/// the rungs differ twice over, because `cap_component` carries a short
/// alphanumeric extension across its shortening and `.2` is one. And for
/// a composed name inside the cap this is the plain `format!` byte for
/// byte, so no directory that works today moves.
pub fn choose_out_dir(
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
            // Active and Occupied climb and record nothing. Occupied
            // deliberately so: a directory no record of ours names is
            // not a payload we may publish over - the climb is the
            // whole answer. See [`DirClaim::Occupied`].
            _ => {}
        }
        n += 1;
        candidate = base.with_file_name(nzbkit::disk::sanitize_filename_capped(&format!(
            "{dir_stem}.{n}"
        )));
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
/// Both names it builds are CAPPED, and the cap has to match the one
/// `Daemon::enqueue` applies to the same stem - a stem the two spell
/// differently refiles onto a directory nobody owns, or onto somebody
/// else's. That is the relpath module header's rule about member names
/// (every site must use the ONE function, or a site left behind
/// computes a different name and stops finding the file) applied to a
/// job directory. `disk::sanitize_filename_capped_for` carries why CAP
/// rather than refuse: the name arrives from a .nzb filename or an
/// *arr's `nzbname=`, nothing bounds either, and a 300-byte component
/// is `ENAMETOOLONG` for every `mkdir` under it (measured on APFS
/// 31 Aug 2026 - 255 creates, 300 does not). Pinned by
/// `an_overlong_job_name_still_gets_a_writable_directory`.
pub fn refile_out_dir(
    out_root: &std::path::Path,
    category: &str,
    name: &str,
    claim: &dyn Fn(&std::path::Path) -> DirClaim,
) -> (PathBuf, Option<PathBuf>) {
    let dir_stem = nzbkit::disk::sanitize_filename_capped(name.trim_end_matches(".nzb"));
    let base = if category.is_empty() {
        out_root.join(&dir_stem)
    } else {
        out_root
            .join(nzbkit::disk::sanitize_filename_capped(category))
            .join(&dir_stem)
    };
    choose_out_dir(&base, &dir_stem, claim)
}

/// A hand-over that has happened but is not yet SETTLED: the new payload
/// is at the canonical path and the previous result is parked beside it,
/// waiting for the caller to say whether the replacement was any good.
///
/// # Why this is a handle and not a `PathBuf`
///
/// `publish_over_previous` used to park the old result, rename the new
/// one over it and `remove_dir_all` the old one, all three, before
/// returning - and its caller (`job_finalize::finalize_payload`) only
/// finds out AFTERWARDS whether the replacement is usable at all. An
/// encrypted RAR set completes with its volumes still locked, by design;
/// the unlock ladder runs after publication and can end with no password
/// that opens it. By then the user's earlier, working, unpacked copy of
/// that release had already been deleted, to be replaced by a folder of
/// archives nobody can open. Publication's own contract says the
/// opposite in as many words: a re-add that never finishes costs the
/// user nothing.
///
/// So the delete is the CALLER's, and it has two doors: [`Self::commit`]
/// once the payload is known good, or [`Self::roll_back`], which puts
/// both directories back exactly where they were. Dropping the handle
/// without choosing keeps the parked copy - the safe direction, and the
/// startup sweep reports it.
pub(crate) struct Published {
    /// Where the job lives now: the canonical directory.
    dir: PathBuf,
    /// Where it lived before, which is where a rollback returns it.
    from: PathBuf,
    /// The previous result, parked. `None` when the canonical path was
    /// free and there was nothing to park.
    aside: Option<PathBuf>,
}

impl Published {
    /// The directory the job now lives in.
    pub(crate) fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// The replacement is good: drop the previous result and answer the
    /// directory the job lives in.
    pub(crate) fn commit(self) -> PathBuf {
        if let Some(aside) = &self.aside
            && let Err(e) = std::fs::remove_dir_all(aside)
        {
            warn!(
                target: "replace",
                "previous result left behind in {}: {e}",
                aside.display()
            );
        }
        self.dir
    }

    /// The replacement turned out NOT to be usable - it is still locked,
    /// or the unlock was refused - so undo the hand-over: the new payload
    /// goes back to its own directory and the previous result returns to
    /// the canonical path, byte for byte where each of them started.
    ///
    /// Answers true when the state was restored. A rollback that cannot
    /// complete leaves BOTH copies on disk under distinct names and says
    /// so: nothing is deleted on this path, ever, which is the whole
    /// reason it exists.
    pub(crate) fn roll_back(self) -> bool {
        let Some(aside) = self.aside else {
            // Nothing was parked, so there is no previous result to
            // restore and the new payload simply goes back to its own
            // directory.
            return match std::fs::rename(&self.dir, &self.from) {
                Ok(()) => true,
                Err(e) => {
                    warn!(
                        target: "replace",
                        "{} stays at {}: {e}",
                        self.from.display(),
                        self.dir.display()
                    );
                    false
                }
            };
        };
        if let Err(e) = std::fs::rename(&self.dir, &self.from) {
            warn!(
                target: "replace",
                "could not move the unusable replacement out of {}: {e} - the previous \
                 result is intact at {}",
                self.dir.display(),
                aside.display()
            );
            return false;
        }
        if let Err(e) = std::fs::rename(&aside, &self.dir) {
            // HALF WAY, which is the one state no caller can describe:
            // the canonical name is now EMPTY, the replacement is back
            // at `from` and the previous result is still parked. So the
            // first rename is undone and the hand-over stands as
            // published - `false` then means "nothing moved back", which
            // is what the caller already handles, and the startup sweep
            // reports the parked copy. Nothing is deleted either way.
            warn!(
                target: "replace",
                "could not restore {} from {}: {e} - the hand-over stands and the previous \
                 result is intact under {}",
                self.dir.display(),
                aside.display(),
                aside.display()
            );
            let _ = std::fs::rename(&self.from, &self.dir);
            return false;
        }
        info!(
            target: "replace",
            "{} put back: the replacement at {} is not usable",
            self.dir.display(),
            self.from.display()
        );
        true
    }
}

/// Take over the canonical output directory from the completed job this
/// one replaces (see `Job::replaces`). Called once the job has finished
/// successfully and before any renaming or relocation, so everything
/// downstream sees the final location.
///
/// The previous result is moved aside first and is NOT deleted here at
/// all: the caller settles it through [`Published`], once it knows
/// whether the replacement is usable. If the move in fails, the old
/// result goes straight back and this job keeps its own directory. A
/// re-add that never finishes therefore costs the user nothing - which
/// is the whole point, since reusing the folder used to truncate the good
/// payload with the replacement's first decoded span.
///
/// Returns the hand-over, or `None` when nothing moved.
pub(crate) fn publish_over_previous(
    out_dir: &std::path::Path,
    canon: &std::path::Path,
) -> Option<Published> {
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
            info!(target: "replace", "{} → {}", out_dir.display(), canon.display());
            Some(Published {
                dir: canon.to_path_buf(),
                from: out_dir.to_path_buf(),
                aside: parked.then(|| aside.clone()),
            })
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
pub fn same_dir(a: &std::path::Path, b: &std::path::Path) -> bool {
    a == b
        || match (a.canonicalize(), b.canonicalize()) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    //! The two A6 publication pins. They lived in
    //! `repair/repair_tests.rs` until crate-split step 3 moved `repair`
    //! into `nzbfast-unpack`: neither reads a single thing from that
    //! layer, both drive `choose_out_dir` and `publish_over_previous`
    //! here, and `serve` is a crate away from `repair` now. Moved rather
    //! than dropped, and moved to the side that can see BOTH halves -
    //! which for these two is simply this file.
    use super::*;

    /// Sweep finding A6 (the directory half): the collision walk steps
    /// around a directory whose payload belongs to a COMPLETED job and
    /// records the canonical name to publish over. A FAILED job maps to
    /// `Free` at the call site, so its leftovers are still reused in place.
    #[test]
    fn out_dir_choice_steps_around_a_completed_payload() {
        let base = std::path::Path::new("/dl/tv/Release");
        // Free (nothing there, or a failed job's junk): reuse in place,
        // nothing to replace.
        let (d, r) = choose_out_dir(base, "Release", &|_| DirClaim::Free);
        assert_eq!(d, base);
        assert_eq!(r, None);
        // A completed payload: download beside it, publish over it later.
        let (d, r) = choose_out_dir(base, "Release", &|p| {
            if p == base {
                DirClaim::Payload
            } else {
                DirClaim::Free
            }
        });
        assert_eq!(d, std::path::Path::new("/dl/tv/Release.2"));
        assert_eq!(r, Some(base.to_path_buf()));
        // An ACTIVE job holds the canonical name: step aside as before,
        // and never replace what a running job is writing.
        let (d, r) = choose_out_dir(base, "Release", &|p| {
            if p == base {
                DirClaim::Active
            } else {
                DirClaim::Free
            }
        });
        assert_eq!(d, std::path::Path::new("/dl/tv/Release.2"));
        assert_eq!(r, None);
        // Canonical holds a payload and .2 is busy: land on .3, and still
        // replace only the canonical one.
        let (d, r) = choose_out_dir(base, "Release", &|p| match p.to_string_lossy() {
            c if c.ends_with("Release") => DirClaim::Payload,
            c if c.ends_with("Release.2") => DirClaim::Active,
            _ => DirClaim::Free,
        });
        assert_eq!(d, std::path::Path::new("/dl/tv/Release.3"));
        assert_eq!(r, Some(base.to_path_buf()));
    }

    /// A6 publication: the previous result survives a failed hand-over,
    /// and is replaced only once the new payload is in place.
    #[test]
    fn replacing_a_previous_result_never_loses_it() {
        // The guard is bound and KEPT: rebinding `root` to a `PathBuf`
        // would drop it at the end of that statement and take the tree
        // with it. It removes the directory on the way out, which is
        // why this test ends with its asserts and no `remove_dir_all`.
        let guard = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-a6-replace-{}", std::process::id())),
        );
        let root = guard.to_path_buf();
        let canon = root.join("Release");
        let fresh = root.join("Release.2");
        std::fs::create_dir_all(&canon).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(canon.join("payload.iso"), b"the good old copy").unwrap();
        std::fs::write(fresh.join("payload.iso"), b"the new copy").unwrap();
        assert_eq!(
            publish_over_previous(&fresh, &canon).map(Published::commit),
            Some(canon.clone())
        );
        assert_eq!(
            std::fs::read(canon.join("payload.iso")).unwrap(),
            b"the new copy"
        );
        assert!(!fresh.exists(), "the staged directory was left behind");
        // Nothing aside from the canonical directory survives the swap.
        let left: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left, vec!["Release".to_string()], "leftovers: {left:?}");

        // A job that never produced its directory leaves the old result
        // exactly where it was.
        let missing = root.join("Release.3");
        assert!(publish_over_previous(&missing, &canon).is_none());
        assert_eq!(
            std::fs::read(canon.join("payload.iso")).unwrap(),
            b"the new copy"
        );
        // And a job that already owns the canonical name is a no-op.
        assert!(publish_over_previous(&canon, &canon).is_none());
        assert_eq!(
            std::fs::read(canon.join("payload.iso")).unwrap(),
            b"the new copy"
        );
    }

    /// N1 (reports/code-audit-2026-09-17): the hand-over can be UNDONE,
    /// and undoing it costs neither copy a byte.
    ///
    /// The publication used to park the previous result, rename the new
    /// payload over it and delete the parked copy, all inside one call -
    /// so by the time the finalizer discovered the replacement was a
    /// locked archive set nobody has the password for, the working copy
    /// it replaced was already gone. The delete belongs to the caller
    /// now, and this is the door it takes when the answer is no.
    #[test]
    fn a_rolled_back_publication_puts_both_payloads_back() {
        let guard = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-a6-rollback-{}", std::process::id())),
        );
        let root = guard.to_path_buf();
        let canon = root.join("Release");
        let fresh = root.join("Release.2");
        std::fs::create_dir_all(&canon).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(canon.join("payload.iso"), b"the good old copy").unwrap();
        std::fs::write(fresh.join("set.part01.rar"), b"the locked replacement").unwrap();

        let published = publish_over_previous(&fresh, &canon).expect("the hand-over happens");
        assert_eq!(published.dir(), canon.as_path());
        // Mid-flight: the new payload is at the canonical name and the
        // old one is parked, not deleted.
        assert_eq!(
            std::fs::read(canon.join("set.part01.rar")).unwrap(),
            b"the locked replacement"
        );
        assert!(published.roll_back(), "the rollback must complete");

        assert_eq!(
            std::fs::read(canon.join("payload.iso")).unwrap(),
            b"the good old copy",
            "the previous result did not come back"
        );
        assert_eq!(
            std::fs::read(fresh.join("set.part01.rar")).unwrap(),
            b"the locked replacement",
            "the replacement must survive for the retry a password makes work"
        );
        // Exactly two directories, and no parked copy left over.
        let mut left: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec!["Release".to_string(), "Release.2".to_string()],
            "leftovers: {left:?}"
        );
    }

    /// N1's other arm: a hand-over onto a FREE canonical name rolls back
    /// too, and leaves nothing behind at the name it briefly held.
    ///
    /// `Job::replaces` names a completed payload, but the directory can
    /// be gone by the time the tail runs (the user deleted it, a sweep
    /// took it). There is then nothing to park, and a rollback still has
    /// to return the payload to the directory it downloaded into rather
    /// than leaving it under a name the record does not use.
    #[test]
    fn a_rollback_with_nothing_parked_still_returns_the_payload() {
        let guard = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-a6-rollback-free-{}", std::process::id())),
        );
        let root = guard.to_path_buf();
        let canon = root.join("Release");
        let fresh = root.join("Release.2");
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(fresh.join("set.part01.rar"), b"the locked replacement").unwrap();

        let published = publish_over_previous(&fresh, &canon).expect("the hand-over happens");
        assert!(published.roll_back());
        assert!(!canon.exists(), "the canonical name must be free again");
        assert_eq!(
            std::fs::read(fresh.join("set.part01.rar")).unwrap(),
            b"the locked replacement"
        );
    }
}
