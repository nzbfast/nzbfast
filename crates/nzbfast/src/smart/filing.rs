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
//! `filed_bases` and the length-fitting - stays in the parent: that is
//! the vocabulary, and the delete path reads it too.
//!
//! Split out of smart.rs for the size gate (TODO 106); the six public
//! doors are re-exported, so no caller spells a new path.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use super::sample::is_sample_named;
use super::videoext::video_ext;
use super::{EpisodeTitles, SUBTITLE_EXTS, VIDEO_EXTS, ext_of, legacy_tv_path, nzbname, tv_path};

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
        if target.exists() || !targets.insert(target.clone()) {
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
        if target == path || target.exists() || claimed.iter().any(|c| c == &name) {
            continue;
        }
        claimed.push(name);
        match std::fs::rename(&path, &target) {
            Ok(()) => renamed += 1,
            Err(e) => warn!(
                target: "smart",
                "rename {} → {}: {e}",
                path.display(),
                target.display()
            ),
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
    let target = out_dir.join(format!("{clean}.{ext}"));
    if target == *video || target.exists() {
        return false;
    }
    if let Err(e) = std::fs::rename(video, &target) {
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
    for f in &files {
        if !SUBTITLE_EXTS.contains(&ext_of(f).as_str()) {
            continue;
        }
        let Some(fname) = f.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if let Some(rest) = sidecar_tail(&fname, &old_stem) {
            let subtarget = out_dir.join(format!("{clean}{rest}"));
            if subtarget != *f && !subtarget.exists() {
                let _ = std::fs::rename(f, &subtarget);
            }
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
    if videos.len() == 1 {
        let video = videos[0];
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
        let target = out_dir.join(format!("{base}.{ext}"));
        if target != *video
            && !target.exists()
            && let Err(e) = std::fs::rename(video, &target)
        {
            warn!(
                target: "smart",
                "rename {} → {}: {e}",
                video.display(),
                target.display()
            );
        }
        // Subtitle sidecars whose name starts with the old video stem:
        // "Stem.en.srt" → "base.en.srt", preserving the language tail.
        for f in &files {
            if !SUBTITLE_EXTS.contains(&ext_of(f).as_str()) {
                continue;
            }
            let fname = match f.file_name() {
                Some(n) => n.to_string_lossy().into_owned(),
                None => continue,
            };
            if let Some(rest) = sidecar_tail(&fname, &old_stem) {
                let subtarget = out_dir.join(format!("{base}{rest}"));
                if subtarget != *f && !subtarget.exists() {
                    let _ = std::fs::rename(f, &subtarget);
                }
            }
        }
    }
    // Rename the folder itself.
    nzbname::rename_dir(parent, out_dir, base)
}
