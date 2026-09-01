//! What a finished job's files end up CALLED, and where they end up.
//!
//! One subject: the rename/file pass that runs after unpack and cleanup.
//! `tv_organize` files a TV job into `Show/Season NN/` and renames each
//! episode; `tv_rename` does the renaming half in place; the three
//! `rename_*` doors give a name to a payload that arrived without a
//! usable one (obfuscated, nameless, or a movie in its own folder). The
//! private helpers below exist only to answer "is this name already the
//! release's?" and "which tail is a sidecar's?" for those five.
//!
//! What a filed episode is called - `EpisodeTitles`, `FiledTail`,
//! `filed_bases` and the length-fitting - is episode.rs beside this
//! file: that is the vocabulary, and the delete path reads it too. It
//! stayed in the parent until smart.rs ran out of headroom again and
//! took the same TODO 106 cut this module did.
//!
//! Split out of smart.rs for the size gate (TODO 106); the six public
//! doors are re-exported, so no caller spells a new path.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use super::episode::legacy_tv_path;
use super::sample::is_sample_named;
use super::videoext::video_ext;
use super::{EpisodeTitles, SUBTITLE_EXTS, VIDEO_EXTS, ext_of, nzbname, tv_path};

/// File a completed TV job: move everything in `out_dir` into
/// `dest_parent/[Show]/Season NN/`, renaming video files to
/// "Show - S01E02[ suffix].ext" (each video's own name is parsed first, so
/// a season pack renames per episode; samples keep their names). `suffix`
/// is the auto-rename quality tag (" [1080p]"), or "" for none. Existing
/// targets are never overwritten. Returns the new directory, or None if
/// the stem didn't parse as TV (job left untouched).
///
/// `titles` decorates each episode with its own name when the cache knows
/// it ("Show - S01E02 - Children [1080p].mkv"); an empty one is the
/// ordinary case and leaves every name exactly as it was.
pub fn tv_organize(
    dest_parent: &Path,
    stem: &str,
    out_dir: &Path,
    suffix: &str,
    titles: &EpisodeTitles,
) -> Option<PathBuf> {
    let (subdir, job_base) = match tv_path(stem) {
        Some(t) => t,
        None => {
            info!(target: "smart", "{stem:?} didn't parse as TV - leaving it in place");
            return None;
        }
    };
    // A show already filed under the pre-sanitiser spelling of its name
    // ("Star Trek Discovery", before ": " became " - ") keeps that
    // folder: starting a second tree beside it splits the show in the
    // user's library. Judged on the SHOW folder, not the season one, so
    // a new season joins the show too - and only when today's spelling
    // has no folder yet and the old one does.
    let show_dir = |sub: &str| dest_parent.join(sub.split('/').next().unwrap_or(sub));
    let legacy = legacy_tv_path(stem)
        .filter(|(sub, _)| *sub != subdir && !show_dir(&subdir).is_dir() && show_dir(sub).is_dir());
    let filed_as_legacy = legacy.is_some();
    let (subdir, job_base) = legacy.unwrap_or((subdir, job_base));
    let dest = dest_parent.join(&subdir);
    if dest == out_dir {
        return None;
    }
    if let Err(e) = std::fs::create_dir_all(&dest) {
        warn!(target: "smart", "create {}: {e}", dest.display());
        return None;
    }
    let entries: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    // Plan the whole filing before moving anything. A canonical target
    // that already exists belongs to somebody else (usually the user's
    // existing library), and the old fallback moved our file under its raw
    // release name while later cleanup deleted that pre-existing canonical
    // file. On any collision, keep this job in its private directory where
    // ownership is exact and delete-with-files remains safe.
    let mut planned = Vec::with_capacity(entries.len());
    let mut targets = std::collections::HashSet::new();
    for path in entries {
        let orig_name = match path.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => continue,
        };
        let mut new_name = orig_name.clone();
        // True only when this entry became the canonical "Show - S01E02"
        // episode name; everything else keeps the name it arrived with.
        let mut is_canonical_video = false;
        if path.is_file() {
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let file_stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let is_sample = is_sample_named(&path);
            // The extension the filed episode must CARRY, which since #43
            // need not be the one it arrived with: an extensionless
            // payload takes the one its bytes sniff as. Filing it under
            // its hash instead put an unowned file in a SHARED season
            // folder - Play could not find it and delete-with-files
            // dropped the history row and left it there (Codex sweep 5,
            // M1). `ext` above is still the on-disk name, which is what
            // the non-video branches below key off.
            let ext = video_ext(&path).unwrap_or(ext);
            if VIDEO_EXTS.contains(&ext.as_str()) && !is_sample {
                // The file's own name wins (season packs), else the job's
                // - spelled the way the folder we are filing into is.
                let own = if filed_as_legacy {
                    legacy_tv_path(&file_stem)
                } else {
                    tv_path(&file_stem)
                };
                // Which stem the base came from decides which episode's
                // title belongs on it: a season pack's files each name
                // their own episode, and only when none of them does
                // (a single-episode job) does the job's stem answer.
                let (base, titled_by) = match own.and_then(|(_, b)| b) {
                    Some(b) => (Some(b), file_stem.as_str()),
                    None => (job_base.clone(), stem),
                };
                if let Some(b) = base {
                    let title = titles.segment(titled_by, &b, suffix);
                    new_name = format!("{b}{title}{suffix}.{ext}");
                    is_canonical_video = true;
                }
            }
        }
        let target = dest.join(&new_name);
        // `symlink_metadata`, and here it is a LIVENESS fix rather than
        // the harms one the other four guards in this file are. Nothing
        // is destroyed at this target whichever question is asked: the
        // execute loop below claims every FILE name with `create_new`,
        // which is EEXIST over a link of either kind, and a DIRECTORY
        // entry gets a bare `fs::rename` that the kernel answers ENOTDIR
        // for any symlink destination - both MEASURED on APFS, 31 Aug
        // 2026, alongside the measurement quoted at `tv_rename`.
        //
        // What `exists()` cost instead was this guard's own "still
        // filing" arm. A link at a NON-canonical target - a shared
        // `Subs/`, a generic `.nfo`, most plausibly one onto a share
        // that is not mounted - read as free, so the entry was planned,
        // the `create_new` claim then failed EEXIST, and the loop broke,
        // rolled back and abandoned the whole job. That is verbatim the
        // outcome the second arm below was written to prevent: "aborting
        // the whole job for one of these silently stopped every later
        // episode of a season from filing at all". Asking about the
        // ENTRY fires the guard here, where the job survives it.
        //
        // This is also the one destination in this file that is the
        // USER'S library rather than the job's own directory, so it is
        // the one where a link is most likely to be there at all.
        if std::fs::symlink_metadata(&target).is_ok() || !targets.insert(target.clone()) {
            // The canonical EPISODE name colliding means the season slot
            // belongs to somebody else - usually the user's existing
            // library. Filing beside it under a raw name is what let
            // cleanup delete their copy, so the whole job stays put.
            if is_canonical_video {
                info!(
                    target: "smart",
                    "{} already exists (or two job files map there) - \
                     leaving {:?} in its private folder",
                    target.display(),
                    stem
                );
                return None;
            }
            // Anything else - a shared Subs/ folder, a generic .nfo - is
            // not ours to own and is not what the delete bug was about.
            // Aborting the whole job for one of these silently stopped
            // every later episode of a season from filing at all: these
            // entries keep their original name, so the second episode
            // shipping Subs/ collided forever, with no UI signal.
            info!(
                target: "smart",
                "{} already exists - leaving it behind, still filing {:?}",
                target.display(),
                stem
            );
            continue;
        }
        planned.push((path, target));
    }
    // Returning Some() here is what makes the caller set `filed`, which
    // tells every later "delete this job's files" that this job OWNS the
    // canonical name in the shared season folder. A job that moved
    // nothing must never make that claim: cleanup matches by NAME, so it
    // would delete whichever episode really is there - the exact data
    // loss this planning step exists to prevent. Renames do fail in
    // ordinary life: a NAS blipping read-only, EXDEV on a category
    // folder symlinked to another volume, or a media server holding the
    // file open on Windows.
    let mut done: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(planned.len());
    let mut failed = None;
    for (path, target) in planned {
        // The plan's exists() check happened above, and `rename` REPLACES
        // an existing destination file. Finalize tails run on independent
        // tasks and can overlap - the runner tail, the idle sidecar tail,
        // the set_password unlock tail - so two jobs filing the same
        // episode both saw the slot free, the second silently overwrote
        // the first's bytes, and the first's private folder had already
        // been drained and removed. One payload gone, both jobs claiming
        // filed. Claim the name atomically first, the way move_tree does,
        // then rename over the placeholder we own.
        //
        // Files only. Renaming a directory onto a non-empty one fails
        // rather than replacing it, so a directory entry has nothing to
        // lose, and a placeholder FILE would break the rename outright.
        let mut placeholder = false;
        if !path.is_dir() {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
            {
                Ok(_) => placeholder = true,
                Err(e) => {
                    warn!(
                        target: "smart",
                        "{} was taken before {} could be filed: {e}",
                        target.display(),
                        path.display()
                    );
                    failed = Some(e);
                    break;
                }
            }
        }
        match std::fs::rename(&path, &target) {
            Ok(()) => done.push((path, target)),
            Err(e) => {
                warn!(
                    target: "smart",
                    "move {} → {}: {e}",
                    path.display(),
                    target.display()
                );
                // Our own placeholder would otherwise be left behind as a
                // zero-byte file wearing the episode's canonical name,
                // which later cleanup matches by name.
                if placeholder {
                    let _ = std::fs::remove_file(&target);
                }
                failed = Some(e);
                break;
            }
        }
    }
    if let Some(e) = failed {
        // Put back whatever did land, so the job is left exactly as it
        // was rather than split across two directories with an owner
        // nobody can determine. A rollback that itself fails is logged
        // and still refuses the claim - leaking a file is recoverable,
        // deleting the user's episode is not.
        for (path, target) in done.iter().rev() {
            if let Err(e2) = std::fs::rename(target, path) {
                warn!(
                    target: "smart",
                    "could not undo {} → {}: {e2} (file left in the season folder)",
                    path.display(),
                    target.display()
                );
            }
        }
        info!(
            target: "smart",
            "filing {stem:?} failed ({e}) - left in its private folder, \
             not claiming the season folder"
        );
        return None;
    }
    // Filing NOTHING is not filing. `planned` is empty whenever the job
    // has no entries left to place - most easily an all-junk repost
    // (NFOFIX/DIRFIX/PROOF: only .nfo/.sfv/.par2), because sweep_junk
    // runs first and empties out_dir. Falling through here returned the
    // shared season folder, which makes the caller set `filed`, and
    // delete_filed_episode then matches by canonical NAME and removes the
    // user's real copy of that episode for a job that moved zero bytes.
    //
    // This is the same ownership invariant as the rollback above - the
    // earlier fix enforced only its failed-rename half.
    if done.is_empty() {
        info!(
            target: "smart",
            "nothing to file for {stem:?} - leaving it in its private folder \
             rather than claiming {}",
            dest.display()
        );
        return None;
    }
    let moved = done.len();
    // Only vanishes if everything left it.
    let _ = std::fs::remove_dir(out_dir);
    info!(target: "smart", "filed {moved} item(s) → {}", dest.display());
    Some(dest)
}

/// Auto-rename for TV when the job ISN'T being Season-filed: rename video
/// files IN PLACE to "Show - S01E02[ title][ suffix].ext" (season packs
/// rename per episode; samples untouched). Never overwrites an existing
/// target. Returns how many files were renamed.
pub fn tv_rename(dir: &Path, stem: &str, suffix: &str, titles: &EpisodeTitles) -> usize {
    let job_base = tv_path(stem).and_then(|(_, b)| b);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    // PLAN, then rename. Every file that cannot name its own episode
    // falls back to the job's base, so they all compute the SAME target
    // and `read_dir` order decided which one got it - a sniffable sample
    // beside a hash-named feature could take the episode name and become
    // what Play offers, leaving the real feature under its hash. Sample
    // names are excluded here by NAME alone, because since #43 they need
    // not carry an extension (Codex sweep 5, M4).
    let mut plan: Vec<(PathBuf, String, String, String)> = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() || is_sample_named(&path) {
            continue;
        }
        // The extension the renamed file must carry. An extensionless
        // obfuscated payload takes the one its bytes sniff as, so this
        // pass stops skipping the very file the job is about (#43).
        let Some(ext) = video_ext(&path) else {
            continue;
        };
        let file_stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        // As in `tv_organize`: the stem that named the episode is the
        // stem whose title belongs on it.
        let (base, titled_by) = match tv_path(&file_stem).and_then(|(_, b)| b) {
            Some(b) => (Some(b), file_stem.clone()),
            None => (job_base.clone(), stem.to_string()),
        };
        let Some(b) = base else { continue };
        plan.push((path, ext, b, titled_by));
    }
    // One winner per target: the largest candidate. A teaser that slipped
    // past the name check is smaller than the feature, so size is the
    // tie-break that keeps the feature.
    plan.sort_by_key(|(p, ..)| {
        std::cmp::Reverse(std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
    });
    let mut claimed: Vec<String> = Vec::new();
    let mut renamed = 0;
    for (path, ext, b, titled_by) in plan {
        let title = titles.segment(&titled_by, &b, suffix);
        let name = format!("{b}{title}{suffix}.{ext}");
        let target = dir.join(&name);
        // AN ENTRY AT THE NAME, AND NOT A NAME THAT RESOLVES - the
        // question this guard has to ask, and the difference is a
        // decision rather than a spelling. This is the canonical guard
        // of the five in this file; the other four cite it. It was
        // `exists()`, then `symlink_metadata` (855f7fd91), and is now
        // the `create_new` claim below, which asks the same question
        // `symlink_metadata` asked without leaving a gap behind it.
        // Both moves are argued here, in that order.
        //
        // `Path::exists` FOLLOWS symlinks and answers false on any
        // error, so as an occupancy test it asks whether a name
        // RESOLVES. `rename(2)` asks a different question: it removes
        // whatever ENTRY sits at the destination and never resolves it.
        // Where the two disagree - a dangling link, a link onto a share
        // that is not mounted, a link whose target is unreadable - this
        // guard did not fire and the rename below deleted the user's
        // link. The doc comment above already promised it "never
        // overwrites an existing target"; `exists()` is what made that
        // sentence false.
        //
        // THIS IS NOT THE X5-07 CONTAINMENT CLASS and reaching for that
        // row here is the reflex this paragraph exists to refuse. The
        // fingerprint is identical and the conclusion is the opposite,
        // because the operation underneath is a rename. MEASURED on
        // APFS, 31 Aug 2026: renaming a file over a link that points
        // OUT of the directory leaves the entry a regular file holding
        // the source bytes with the outside inode untouched, and over a
        // DANGLING link nothing is created at the far end at all. X5-07
        // needed `std::fs::copy`, which opens its destination BY NAME
        // with `O_CREAT` and does follow. Nothing here can write
        // outside the directory however the link points.
        //
        // WHAT IS AT STAKE is a directory entry the user created. The
        // harms are not symmetric, which is what settles it: skipping
        // costs the file its canonical name, one `mv` undoes that, and
        // the count this function returns already says it happened -
        // where the link's target string was the only record of where it
        // pointed and nothing brings that back. Same argument, same
        // measurement and the same tier reasoning as the weak tier in
        // `unpack/published_names.rs` (X5-20 residue 1, `b71c37e33`),
        // which is where this rule was first decided.
        //
        // COST: one `create_new` where there was one `stat`, and the
        // case fold is unaffected either way - all three of `stat`,
        // `lstat` and an `O_EXCL` create go through the same lookup and
        // differ only at the final resolve, MEASURED on APFS.
        //
        // THE STATED LIMIT THIS NOTE CARRIED IS CLOSED, 31 Aug 2026,
        // under claim `occupancy-claim-the-rest-of-the-class`. It said
        // the guard is a check before a use, that `exists()` had the
        // identical window, and that closing it wants a per-platform
        // exclusive rename - "`tv_organize` above does close it,
        // because it has a placeholder to claim the name with; this
        // door renames in place and has none". The first two were true.
        // The third was wrong, and it is what kept this open for as
        // long as it was: a door that renames in place can MAKE a
        // placeholder, which is exactly what `tv_organize` does 250
        // lines above. Nothing distinguishes the two doors on this
        // point.
        //
        // MEASURED on the sibling guard in `unpack/published_names.rs`
        // (`20e81a631`): the `lstat` is 968 ns and the rename behind it
        // ~112 us, so the guard covered about 1% of its own interval,
        // and over 20,000 trials 96.8% of concurrent arrivals that got
        // the name landed inside the unprotected part. Not a sliver of
        // the operation - nearly all of it. The same race against the
        // claim loses zero, at a per-trial cost inside the noise.
        //
        // THE CLAIM IS NOT A BELT BESIDE THE GUARD, IT IS THE GUARD, so
        // this is a substitution and not an addition. MEASURED on APFS
        // the same day: `create_new` answers `AlreadyExists` over a
        // regular file, a DANGLING link, a link pointing out of the
        // directory and a directory - the same four answers the `lstat`
        // gave, which is the whole of what the census bought by moving
        // off `exists()`. Nothing above is loosened; only the gap goes.
        //
        // PLAIN `create_new` AND NOT `disk::open_out_leaf_under(..,
        // CreateNew)`, which is what the sibling took, and the
        // difference is a decision rather than a spelling. That door
        // BINDS its destination, and it is paired there with
        // `rename_out_under`, which binds the same way - the two ask
        // one question. This door renames with a plain `fs::rename`,
        // which resolves the destination by path, so a bound claim
        // beside it would ask a STRICTER question than the operation it
        // guards: MEASURED on APFS 31 Aug 2026, the bound claim's
        // `O_DIRECTORY|O_NOFOLLOW` open of the root answers ENOTDIR for
        // a directory that is a symlink, where the plain `create_new`
        // and the `fs::rename` through that same parent both succeed.
        // A category folder symlinked onto another volume is ordinary
        // here - this file's own rollback note names it - so pairing
        // them would refuse those jobs outright. Binding these doors is
        // the X5-07 containment question and is a separate lane
        // (`disk/relpath.rs` has one open on it); it is not this one.
        //
        // WRITTEN OUT AT THE DOOR rather than hoisted into a helper,
        // like `tv_organize`'s and `publish`'s. What differs between
        // the nine doors is the DECLINE - continue, return false,
        // return None, an `io::Error` out - and its wording, which is
        // the whole of what a caller would have to supply anyway; and
        // two of the nine are in `nzbkit`, which cannot see a helper
        // here. Numbers, the per-platform alternative's price and the
        // per-site verdicts:
        // `research/PUBLISH-OCCUPANCY-WINDOW-2026-08-31.md`.
        //
        // The two cheap tests keep their place in front of it: neither
        // is a filesystem question - one compares paths, the other is
        // this pass's own plan dedupe - and `claimed` is not what the
        // claim answers, since it must still refuse a second candidate
        // for a name whose rename FAILED and left the name free.
        if target == path || claimed.iter().any(|c| c == &name) {
            continue;
        }
        if let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            // `AlreadyExists` is this guard's own answer and is silent,
            // exactly as the `lstat` was: the file keeps the name it was
            // posted with and the count this function returns says so.
            // Anything else is the door being unusable rather than taken
            // - a read-only volume, a parent that went away - which the
            // rename below would have reported, so it still is.
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                warn!(
                    target: "smart",
                    "could not claim {}: {e}",
                    target.display()
                );
            }
            continue;
        }
        claimed.push(name);
        match std::fs::rename(&path, &target) {
            Ok(()) => renamed += 1,
            Err(e) => {
                // Our own placeholder, which would otherwise be left as
                // a zero-byte file wearing the episode's canonical name
                // - and cleanup in this module matches by name.
                // `tv_organize` above removes its own for the same
                // reason.
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
    renamed
}

/// A file stem that carries no identity at all: the encoder's default
/// output name, or a bare index from a batch. Exact, case-insensitive,
/// closed list plus one- and two-digit stems - nothing fuzzier, because
/// every entry here is a licence to overwrite a name someone may have
/// chosen. "Movie 2024" and "video_final" are NOT generic; they say
/// something, so they stand.
pub(super) fn is_generic_stem(stem: &str) -> bool {
    let s = stem.trim();
    if matches!(s.len(), 1 | 2) && s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    matches!(
        s.to_ascii_lowercase().as_str(),
        "movie" | "video" | "film" | "output" | "encoded" | "media"
    )
}

/// The part of a sidecar's filename that follows the video's stem
/// (".en.srt"), or None when the sidecar is not this video's at all.
///
/// The boundary is the whole point: a bare `strip_prefix` was safe only
/// while the stem had to be a long obfuscated blob, and with generic
/// stems ([`is_generic_stem`]) in play the video "1.mkv" claimed
/// "10.srt" and "12.srt" and fused their leftover digit onto the new
/// name ("Example.Movie.2024…-GRP0.srt"). The remainder has to start at
/// an extension boundary for the sidecar to be ours.
fn sidecar_tail<'a>(fname: &'a str, stem: &str) -> Option<&'a str> {
    fname
        .strip_prefix(stem)
        .filter(|rest| rest.starts_with('.'))
}

/// Every subtitle sidecar in `files` that belongs to the video stem
/// `old_stem`, paired with the tail it keeps (".en.srt").
///
/// Gathered before the video is renamed, for two reasons that are really
/// one: [`sidecar_tail`] matches on the OLD stem, which the rename is
/// about to take away, and the tails it returns are exactly what the NEW
/// stem has to be budgeted against ([`capped_base`]).
fn sidecars_of(files: &[PathBuf], old_stem: &str) -> Vec<(PathBuf, String)> {
    files
        .iter()
        .filter(|f| SUBTITLE_EXTS.contains(&ext_of(f).as_str()))
        .filter_map(|f| {
            let fname = f.file_name()?.to_string_lossy().into_owned();
            let rest = sidecar_tail(&fname, old_stem)?.to_string();
            Some((f.clone(), rest))
        })
        .collect()
}

/// The ONE stem [`rename_movie`] and [`rename_nameless_video`] give to
/// every name they compose, shortened so the LONGEST of them still fits
/// a filesystem component.
///
/// Three names come off it - `{base}.{ext}`, `{base}{tail}` for each
/// subtitle sidecar, and the job folder - and the sidecar pairing IS the
/// shared stem: a player finds `Movie.en.srt` beside `Movie.mkv` because
/// the two spell one stem. So neither obvious cap is available. Capping
/// the composed names hashes different inputs, so they come back with
/// different tags and the subtitle stops being that video's; capping the
/// stem at 255 leaves `{base}.mkv` four bytes over and the write fails
/// exactly as it did before. `disk::cap_shared_stem` exists for this
/// third answer: tell it the tails, and it shortens the stem far enough
/// that the longest of them still fits.
///
/// `rename_dir`'s `.2`/`.3` collision suffix is deliberately NOT in the
/// budget. It is chosen inside `rename_dir` at the moment of the
/// collision rather than composed here, and in the arm that has a video
/// the extension tail has already left more room than it needs. What is
/// given up is a folder that keeps its old name when a stem using the
/// WHOLE budget collides - which is what every overlong name did on
/// every one of these paths before the cap existed.
fn capped_base(stem: &str, video_tail: &str, sidecars: &[(PathBuf, String)]) -> String {
    let tails = std::iter::once(video_tail).chain(sidecars.iter().map(|(_, t)| t.as_str()));
    nzbkit::disk::cap_shared_stem(stem, tails)
}

/// Does this release name say enough to be worth stamping onto a
/// payload? A non-empty parsed title plus at least one hard provenance
/// fact - resolution, source or group. Port of Sonarr's scene-title
/// check, and like it we prefer false negatives: a name that fails here
/// costs the user an ugly filename, a name that wrongly passes costs
/// them a wrong one.
fn names_the_release(name: &str) -> bool {
    let p = crate::wall::parse_release(name);
    !p.title.trim().is_empty() && (p.res.is_some() || p.source.is_some() || p.group.is_some())
}

/// Last resort for a payload we could not name cleverly: if the main
/// video is still wearing an obfuscated stem, give it the release's own
/// name.
///
/// The smart renamers decline on purpose in several places - an event
/// post whose identity lives after the year ("Formula1.2026.Round11…"),
/// a release with no year and no quality facts, a category that declared
/// no base behaviour. Every one of those declines rests on the same
/// assumption: that leaving the file alone means leaving the POSTER'S
/// name on it, which is a name a human chose. When the post is
/// obfuscated that assumption is simply false, and declining hands the
/// user "1fRbH6e0eX8v5hv7fSyXgBb.mkv" while the folder beside it reads
/// perfectly. So: no clever name available AND nothing worth keeping ->
/// use the release name, which is informative and, unlike a reduced
/// "Title (Year)", still unique per round/episode/event.
///
/// The same argument covers the stem that is not obfuscated but says
/// nothing either: "movie.mkv", "video.mkv", "1.mkv". Those are the
/// encoder's default output name, not a name a human chose for THIS
/// post, so there is nothing to preserve. The list is exact and closed
/// (see [`is_generic_stem`]) - a stem we do not recognise keeps its name.
///
/// Widening what we fire on has to be paid for on the other side, so the
/// release name now has to earn the job: it must parse to a non-empty
/// title AND carry at least one hard provenance fact (resolution, source
/// or group). "Example Movie" with no facts is somebody's folder label,
/// and stamping it onto the payload is not an improvement worth the risk
/// of being wrong.
///
/// Returns true when it renamed something. Deliberately narrow: one
/// non-sample video, a stem worth replacing, and a target that does not
/// already exist.
pub fn rename_obfuscated_video(out_dir: &Path, base: &str) -> bool {
    if base.trim().is_empty() || nzbkit::release::looks_obfuscated(base) {
        return false; // nothing better to offer than what is already there
    }
    if !names_the_release(base) {
        return false; // too little in the release name to trust it
    }
    rename_nameless_video(out_dir, base)
}

/// The lone still-nameless feature video in `dir`, or `None`.
///
/// "Nameless" is the exact condition [`rename_obfuscated_video`] fires
/// on - one non-sample video whose stem is either obfuscated or one of
/// the encoder defaults that say nothing - factored out because
/// synthesised naming has to ask the same question BEFORE it spends any
/// network: there is no point identifying a film whose file already
/// carries a name a human chose.
pub fn nameless_video(dir: &Path) -> Option<PathBuf> {
    let videos: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        // By NAME, like every other rename path: since #43 a sample need
        // not carry an extension, and an extensionless `sample` that
        // sniffs as EBML counted as a second video here - so the lone
        // feature stopped being lone, this returned None, and the
        // feature kept its hash through both identify and synthesised
        // naming (Codex sweep 6, N1). The DELETE sweep stays on
        // `is_sample_clip`; nothing here removes a file.
        .filter(|p| p.is_file() && !is_sample_named(p) && video_ext(p).is_some())
        .collect();
    // More than one and we cannot tell which is the feature; renaming
    // either would be a guess, and CD1/CD2 sets collide.
    let [video] = videos.as_slice() else {
        return None;
    };
    let name = video.file_name()?.to_string_lossy().into_owned();
    let stem = name
        .strip_suffix(&format!(".{}", ext_of(video)))
        .unwrap_or(&name)
        .to_string();
    // The poster named it something: that name stands, whatever a
    // catalogue might have offered.
    (nzbkit::release::looks_obfuscated(&stem) || is_generic_stem(&stem)).then(|| video.clone())
}

/// Put `base` on the lone still-nameless video in `out_dir`, carrying
/// its subtitle sidecars.
///
/// Split from [`rename_obfuscated_video`] so that synthesised naming
/// reaches the same apply path. The two differ only in where the name
/// came from and therefore in what has to be proven about it first: a
/// release name has to earn the job by carrying provenance facts (see
/// [`names_the_release`]), while an identified film's name has already
/// been earned by the acceptance gate - which is a far higher bar, and
/// one a title like "Supergirl 2026" could never clear by grammar
/// alone.
pub fn rename_nameless_video(out_dir: &Path, base: &str) -> bool {
    let files: Vec<PathBuf> = match std::fs::read_dir(out_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => return false,
    };
    let Some(video) = nameless_video(out_dir) else {
        return false;
    };
    let video = &video;
    // Two different extensions, and conflating them is what produced a
    // trailing-dot name: `ext` is what the TARGET must carry (sniffed
    // from the bytes when the payload arrived with none), while the stem
    // strip has to use what is actually ON DISK - for an extensionless
    // file that is nothing, so the whole filename is the stem.
    let Some(ext) = video_ext(video) else {
        return false;
    };
    let on_disk = ext_of(video);
    let Some(old_name) = video.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    let old_stem = if on_disk.is_empty() {
        old_name.clone()
    } else {
        old_name
            .strip_suffix(&format!(".{on_disk}"))
            .unwrap_or(&old_name)
            .to_string()
    };
    let clean = nzbkit::release::sanitize_name(base);
    if clean.is_empty() {
        return false; // nothing nameable survived sanitisation
    }
    // Sidecars are gathered BEFORE the video moves: their tails are what
    // the stem has to be budgeted against, and they are found by the OLD
    // stem, which the rename below is about to take away.
    let sidecars = sidecars_of(&files, &old_stem);
    let clean = capped_base(&clean, &format!(".{ext}"), &sidecars);
    let clean = clean.as_str();
    let target = out_dir.join(format!("{clean}.{ext}"));
    // An ENTRY at the name, not a name that resolves - argued in full at
    // `tv_rename` above. This door lands in the job's own directory
    // rather than the user's library, so the population is narrower, but
    // the harms settle it identically: declining leaves the payload
    // under the name it was posted with, which is exactly what this door
    // exists to improve on and is recoverable, where the link is not.
    //
    // AND IT IS A CLAIM RATHER THAN A LOOK, per `tv_rename` above: the
    // `lstat` covered about 1% of its own interval, so `create_new`
    // asks the same four-answer question atomically. Plain, not
    // `disk::open_out_leaf_under`, for the reason argued there - the
    // rename below resolves its destination by path.
    if target == *video {
        return false;
    }
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        // Taken is this guard's own answer and is silent, as the
        // `lstat` was. Anything else is the door being unusable, which
        // the rename below would have reported.
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            warn!(target: "smart", "could not claim {}: {e}", target.display());
        }
        return false;
    }
    if let Err(e) = std::fs::rename(video, &target) {
        // Our own placeholder: a zero-byte file wearing the name this
        // video failed to take, which the sidecar loop below would then
        // compose its own names off and cleanup matches by name.
        let _ = std::fs::remove_file(&target);
        warn!(
            target: "smart",
            "rename {} -> {}: {e}",
            video.display(),
            target.display()
        );
        return false;
    }
    info!(target: "smart", "de-obfuscated {} -> {}", old_name, target.display());
    // Carry subtitle sidecars along, keeping their language tail.
    for (f, rest) in &sidecars {
        let subtarget = out_dir.join(format!("{clean}{rest}"));
        // Per `tv_rename` above: an entry, not a resolution, and taken
        // as a CLAIM so the answer cannot go stale before the rename.
        // A sidecar is the cheapest thing in this file to decline - it
        // keeps the stem it arrived with beside a video that got the
        // new one - so every failure here is silent, which is what the
        // discarded `rename` result already said.
        if subtarget != *f
            && std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&subtarget)
                .is_ok()
            && std::fs::rename(f, &subtarget).is_err()
        {
            // Our own placeholder, or the next pass finds a zero-byte
            // ".en.srt" and the media player prefers it to the real one.
            let _ = std::fs::remove_file(&subtarget);
        }
    }
    true
}

/// Auto-rename a completed MOVIE / loose-file job to the friendly `base`
/// (already computed by `wall::movie_name`, path-safe, no extension):
/// 1. if the job has exactly ONE top-level feature video, rename it to
///    `base.ext` and re-stem its subtitle sidecars (`.en.srt` kept);
///    multiple videos (CD1/CD2 etc.) are left alone to avoid collisions;
/// 2. rename the job folder to `parent/base`, with `.2`/`.3` collision
///    suffixes - an existing folder is never overwritten.
/// Returns the new out_dir when the folder moved, else None (caller keeps
/// the current path).
pub fn rename_movie(parent: &Path, out_dir: &Path, base: &str) -> Option<PathBuf> {
    // `base` arrives path-safe from `movie_name`, but this is the last
    // point before it becomes a real file stem AND a real folder name, and
    // callers other than finalize_names reach it. Re-running the sanitiser
    // is idempotent, so the cost is one pass over a short string.
    let clean = nzbkit::release::sanitize_name(base);
    if clean.is_empty() {
        return None;
    }
    let base = clean.as_str();
    let files: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    // `video_ext`, not VIDEO_EXTS: an extensionless payload is a video
    // since #43, and selecting on the NAME alone meant the ordinary movie
    // arm saw zero features, renamed the job folder, and left the feature
    // inside it under its hash - while the fallback that would have
    // handled it runs only when `movie_name` returned None (Codex sweep
    // 5, M2). Sample exclusion is by name, for the same reason.
    let videos: Vec<&PathBuf> = files
        .iter()
        .filter(|p| video_ext(p).is_some() && !is_sample_named(p))
        .collect();
    // The one-video arm is resolved BEFORE anything moves: the stem all
    // three names share has to be budgeted against the longest tail it
    // will carry, and the sidecars are found by the OLD stem that the
    // video rename is about to take away.
    let one = match videos.as_slice() {
        [video] => {
            let video: &PathBuf = video;
            // The extension it must CARRY, which for a nameless payload is
            // the sniffed one - the rename below is what gives it that.
            let ext = video_ext(video).unwrap_or_else(|| ext_of(video));
            let old_name = video
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())?;
            // Strip the trailing ".ext" to get the stem prefix subtitles share.
            let old_stem = old_name
                .strip_suffix(&format!(".{ext}"))
                .unwrap_or(&old_name)
                .to_string();
            let sidecars = sidecars_of(&files, &old_stem);
            Some((video, ext, sidecars))
        }
        _ => None,
    };
    // With no video arm nothing is composed off the stem at all - the
    // folder IS the stem - so the budget is empty and this is the plain
    // cap.
    let base = match &one {
        Some((_, ext, sidecars)) => capped_base(base, &format!(".{ext}"), sidecars),
        None => capped_base(base, "", &[]),
    };
    let base = base.as_str();
    if let Some((video, ext, sidecars)) = &one {
        let video = *video;
        let target = out_dir.join(format!("{base}.{ext}"));
        // An ENTRY at the name, not a name that resolves, and taken as
        // a CLAIM rather than a look - both argued in full at
        // `tv_rename` above. The claim's own decline is silent, as the
        // `lstat` was; only a door that is unusable is worth a line,
        // and that is what the rename already reported.
        if target != *video {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
            {
                Ok(_) => {
                    if let Err(e) = std::fs::rename(video, &target) {
                        // Our own placeholder - see `tv_rename`.
                        let _ = std::fs::remove_file(&target);
                        warn!(
                            target: "smart",
                            "rename {} → {}: {e}",
                            video.display(),
                            target.display()
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => warn!(
                    target: "smart",
                    "could not claim {}: {e}",
                    target.display()
                ),
            }
        }
        // Subtitle sidecars whose name starts with the old video stem:
        // "Stem.en.srt" → "base.en.srt", preserving the language tail.
        for (f, rest) in sidecars {
            let subtarget = out_dir.join(format!("{base}{rest}"));
            // Per `tv_rename` above: an entry, not a resolution, and
            // taken as a CLAIM. Silent either way, as the discarded
            // `rename` result already was.
            if subtarget != *f
                && std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&subtarget)
                    .is_ok()
                && std::fs::rename(f, &subtarget).is_err()
            {
                // Our own placeholder - see `rename_nameless_video`.
                let _ = std::fs::remove_file(&subtarget);
            }
        }
    }
    // Rename the folder itself.
    nzbname::rename_dir(parent, out_dir, base)
}
