//! Which file in a finished job IS the movie.
//!
//! Split out of smart.rs rather than added to it, for the reason
//! `sample.rs` next door gives: `smart.rs` was at 2,817 of its TODO 106
//! 3,000-line ceiling on 30 Aug 2026 and the numbers only go down. The subject is one question -
//! the walk that answers "the biggest video in this job" - and it is
//! worth its own file because every "ask the payload itself" question
//! in the tree is asked of the answer.

use super::{VIDEO_EXTS, ext_of, is_real_dir, is_real_file};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

/// Deepest directory nesting [`largest_video`] walks, counting the job
/// root as 0.
///
/// The same number, for the same reason, as `PRUNE_MAX_DEPTH` beside it
/// in smart.rs: our own extraction preserves provably safe member paths
/// (`sanitize_out_name`, capped at 16 components), so this bounds those
/// trees as well as ones something else built, and bounds the walk with
/// it. Reusing the sibling walker's depth is deliberate - it is not a
/// new claim about how deep a job tree gets, it is the existing one.
///
/// It has to be more than the 1 this walk used to do, and more than 2,
/// because the real disc structures are:
///
/// - DVD-Video `VIDEO_TS/VTS_01_1.VOB` - 1 deep, which is why the old
///   reach happened to work for DVDs and for nothing else;
/// - Blu-ray `BDMV/STREAM/00000.m2ts` - 2 deep (M4-81);
/// - AVCHD `AVCHD/BDMV/STREAM/00000.MTS`, and camcorder posts that keep
///   the card layout, `PRIVATE/AVCHD/BDMV/STREAM/00000.MTS` - 3 and 4;
///
/// and a poster who wraps the whole disc in a release folder adds one
/// more to any of them. 8 covers every one of those with room, and is
/// not a number this walk has to get exactly right: too deep costs a
/// bounded number of `read_dir` calls, too shallow silently reports
/// that a 20 GB disc rip has no video in it at all.
const FEATURE_MAX_DEPTH: u32 = 8;

/// Directory entries [`largest_video`] will look at before it stops.
///
/// The depth cap alone does not bound the work - a tree can be wide as
/// well as deep - and this walk is on the finish path, called several
/// times per job (both sweeps, plus `main_video` for the container
/// probes). A real Blu-ray tree is a few hundred entries and a season
/// pack a few dozen, so this is three orders of magnitude of headroom:
/// it exists so "the cleanup walk" can never be the answer to why a job
/// took a long time to finish, not to refuse any tree anyone will ever
/// post. Hitting it returns the best found so far rather than None -
/// a partial answer to "which file is the movie" is worth more than
/// none, and none is what the old one-level walk already gave.
const FEATURE_MAX_ENTRIES: usize = 50_000;

#[cfg(test)]
thread_local! {
    /// Test-only override for [`FEATURE_MAX_ENTRIES`] (31 Aug 2026 residue
    /// item 2): a 50,000-entry fixture to pin the real value costs more than
    /// the arm is worth, so nothing exercised it from either side. THREAD-local
    /// rather than a process-global static, for the same test-global-gate
    /// reason `disk/relpath.rs`'s racing-window seam is - each test's own
    /// thread arms and clears its own override, so two tests on different
    /// threads cannot fight over one shared flag.
    static FEATURE_MAX_ENTRIES_OVERRIDE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// [`FEATURE_MAX_ENTRIES`], or this thread's test override if one is
/// armed via [`with_feature_max_entries`].
fn feature_max_entries() -> usize {
    #[cfg(test)]
    {
        if let Some(n) = FEATURE_MAX_ENTRIES_OVERRIDE.with(|c| c.get()) {
            return n;
        }
    }
    FEATURE_MAX_ENTRIES
}

/// RAII handle from [`with_feature_max_entries`]. Dropping it - including
/// on an early return or a panic - clears the override, so a forgotten
/// guard cannot leak a small budget into whatever test runs next on this
/// thread.
#[cfg(test)]
struct FeatureMaxEntriesGuard;

#[cfg(test)]
impl Drop for FeatureMaxEntriesGuard {
    fn drop(&mut self) {
        FEATURE_MAX_ENTRIES_OVERRIDE.with(|c| c.set(None));
    }
}

/// Arm [`FEATURE_MAX_ENTRIES_OVERRIDE`] for this thread until the
/// returned guard drops.
#[cfg(test)]
fn with_feature_max_entries(n: usize) -> FeatureMaxEntriesGuard {
    FEATURE_MAX_ENTRIES_OVERRIDE.with(|c| c.set(Some(n)));
    FeatureMaxEntriesGuard
}

/// Directory names that mean "these bytes are a disc, and every name
/// inside them is load-bearing".
///
/// A closed, standardised set: each of these exists for exactly one
/// purpose and nothing else has a reason to use the name, which is what
/// makes a name test sound here where it would not be elsewhere in this
/// tree. Matched case-insensitively - `sanitize_out_name` preserves
/// whatever case was posted, and rippers write both `VIDEO_TS` and
/// `Video_TS`.
///
/// `CERTIFICATE`, the sibling of `BDMV` on a real Blu-ray, is
/// deliberately NOT here. It is an ordinary English word and a plausible
/// folder name in a job that is not a disc at all, and a real Blu-ray
/// always carries `BDMV` beside it - so it adds no reach and only false
/// positives.
const DISC_STRUCTURE_DIRS: &[&str] = &["BDMV", "VIDEO_TS", "AUDIO_TS", "AVCHD", "HVDVD_TS"];

/// Extensions only a disc structure produces, for the flattened post
/// that carries no directory to match on.
///
/// A SUBSET of smart.rs's `MEDIA_COMPANION_EXTS` and not a reuse of it,
/// because that list answers a different question: it is everything
/// `keep_media_only` must not delete beside a video, so it also carries
/// `sup` subtitles and a dozen external audio formats. Those ship beside
/// an ordinary single-file release every day and say nothing about a
/// disc. `jar` is out for the same reason from the other side - it is a
/// generic archive extension everywhere else - and `aob` is left to
/// `AUDIO_TS` above, which is the only place a DVD-Audio object lives.
/// The subset relation is pinned by a test, so an extension added there
/// cannot silently be one this never learns about.
const DISC_STRUCTURE_EXTS: &[&str] = &["bdmv", "mpls", "clpi", "bdjo", "ifo", "bup", "cpi", "mpl"];

/// One bounded breadth-first walk, shared by every question this file
/// answers about a finished job's shape.
///
/// `visit` is handed every entry and whether the walk considers it a
/// real directory (the same `is_real_dir` answer that decides descent,
/// so a caller never pays for that stat twice), and ends the walk early
/// by returning [`ControlFlow::Break`].
///
/// A directory that will not open is SKIPPED, the root included, so a
/// caller that found nothing cannot tell "the tree holds none of what I
/// asked for" from "I could not read it". `largest_video` used to spell
/// that distinction out with a `read_dir(dir).ok()?` before its loop and
/// it never bought anything: both answers are None through an
/// `Option` return, and they still are through this one. It is not
/// reported here rather than reported unfalsifiably.
///
/// Written once for two askers rather than copied, which is this repo's
/// standing rule about hand-copied siblings: the depth and entry bounds
/// below are the claim, and a second walk is a second place for that
/// claim to be wrong.
fn walk_job(dir: &Path, mut visit: impl FnMut(&Path, bool) -> ControlFlow<()>) {
    let mut budget = feature_max_entries();
    // Breadth-first over (directory, depth). A SUBdirectory that will
    // not open is skipped rather than fatal - the rest of the tree still
    // has the answer in it.
    let mut queue: Vec<(PathBuf, u32)> = vec![(dir.to_path_buf(), 0)];
    let mut head = 0usize;
    while head < queue.len() {
        let (at, depth) = queue[head].clone();
        head += 1;
        let Ok(rd) = std::fs::read_dir(&at) else {
            continue;
        };
        for entry in rd.flatten() {
            if budget == 0 {
                return;
            }
            budget -= 1;
            let path = entry.path();
            let is_dir = is_real_dir(&path);
            if visit(&path, is_dir).is_break() {
                return;
            }
            if is_dir && depth < FEATURE_MAX_DEPTH {
                queue.push((path, depth + 1));
            }
        }
    }
}

/// The first thing under `dir` that says this job IS a disc - a
/// `BDMV`/`VIDEO_TS`/… directory, or a structure file from a flattened
/// post - or None.
///
/// Exists for the one question the naming door has to ask before it
/// renames anything. The relpath-preserve rule this product ships is
/// that a DVD or Blu-ray has to have its directory structure intact to
/// play at all, and a disc's FILE names are half of that structure:
/// `.mpls` playlists and `.clpi` clip-info files address
/// `BDMV/STREAM/00000.m2ts` BY NUMBER, and `VIDEO_TS.IFO` addresses
/// `VTS_01_1.VOB` by name, so a
/// disc tree has no single "main file" whose name is free to change. It
/// is not that the biggest file is hard to find - it is that renaming
/// whichever file you find breaks the disc.
///
/// Returns the marker rather than a bool so the decline can say what it
/// saw. A user who turned name-from-nzb on and got no rename has one
/// line in the log to explain it, and "which file made us think this"
/// is the only fact that line needs.
///
/// The same walk, and therefore the same depth and entry bounds, as
/// [`largest_video`] - a wrapper folder around a disc is exactly the
/// shape both have to see through, and a disc marker below the depth cap
/// is one this declines to notice for the same bounded-work reason the
/// feature below it goes unfound.
pub(super) fn disc_structure(dir: &Path) -> Option<PathBuf> {
    let mut found: Option<PathBuf> = None;
    walk_job(dir, |path, is_dir| {
        let hit = if is_dir {
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .is_some_and(|n| {
                    DISC_STRUCTURE_DIRS
                        .iter()
                        .any(|d| n.eq_ignore_ascii_case(d))
                })
        } else {
            is_real_file(path) && DISC_STRUCTURE_EXTS.contains(&ext_of(path).as_str())
        };
        if hit {
            found = Some(path.to_path_buf());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    });
    found
}

/// The largest video file anywhere in `dir`, or None.
///
/// The main feature - protected from the junk sweep regardless of its
/// name, so a film or season titled "Proof"/"Sample" is still
/// recognised as the feature and never deleted.
///
/// ## Why this walks deeper than the sweeps that call it
///
/// It used to be the job root plus ONE subdirectory, which is where
/// extraction puts an ordinary release - and where `sweep_junk` and
/// `keep_media_only` still classify, because those two DELETE what they
/// reach and reaching further is the direction that cannot be taken
/// back. This one deletes nothing. It answers a question, and the
/// answer being wrong is what makes the sweeps wrong.
///
/// Measured on origin/main (M4-81): an honest Blu-ray tree -
/// `BDMV/STREAM/00000.m2ts` at 20 GB - beside a 40 MB `sample.mkv` at
/// the root gave `largest_video` the SAMPLE, and `main_video` then
/// ruled the sample out by name and returned None. So the job with the
/// disc in it reported no video at all: `measured_res` and
/// `container_title` declined, `keep_media_only`'s feature guard read
/// "no video in this job - left alone", and every question the tail
/// asks of the payload was answered about a teaser or not at all.
///
/// Widening the ANSWER while leaving the sweeps' reach alone only ever
/// makes them more correct, and the two ways it moves them are both the
/// right direction:
///
/// - `feature_len` becomes the disc's, not the teaser's, so the 40 MB
///   `sample.mkv` beside a 20 GB feature is finally the teaser it looks
///   like, instead of being spared for being the biggest thing in a job
///   whose real payload was invisible;
/// - `keep_media_only`'s no-video guard stops firing on disc rips, so a
///   job that IS a disc gets the pass the user asked for.
///
/// Nothing DEEPER than the sweeps reach becomes deletable, because they
/// still do not go there. The feature itself, when it is two or more
/// down, is out of their reach by construction rather than by the
/// `keep` guard - which is why that guard is left exactly as it was.
///
/// Symlinked directories are not followed, for [`is_real_dir`]'s
/// reason one step removed: this walk deletes nothing itself, but it
/// sets the size every deletion threshold is measured against, and a
/// link out of the job would let an unrelated file decide what inside
/// the job counts as a teaser.
pub(super) fn largest_video(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    walk_job(dir, |path, is_dir| {
        if !is_dir && is_real_file(path) && VIDEO_EXTS.contains(&ext_of(path).as_str()) {
            let len = path.metadata().map(|m| m.len()).unwrap_or(0);
            if best.as_ref().is_none_or(|(b, _)| len > *b) {
                best = Some((len, path.to_path_buf()));
            }
        }
        // Never breaks: the LARGEST video is not known until the bounded
        // walk has finished, and hitting the entry budget hands back the
        // best found so far rather than None - a partial answer to "which
        // file is the movie" is worth more than none, and none is what
        // the old one-level walk already gave.
        ControlFlow::Continue(())
    });
    best.map(|(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::super::testkit::scratch;
    use super::super::{is_deletable_sample, keep_media_only, main_video};
    use super::*;

    fn mk(root: &Path, rel: &str, len: usize) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![b'x'; len]).unwrap();
    }

    /// M4-81 itself: the Blu-ray main title is two directories down and
    /// a teaser sits at the root. Measured FAILING on origin/main - the
    /// walk returned `sample.mkv`, and `main_video` then filtered that
    /// by name and said the job had no video at all.
    #[test]
    fn the_blu_ray_main_title_two_directories_down_is_the_feature() {
        let d = scratch("bdmv2deep");
        mk(&d, "BDMV/STREAM/00000.m2ts", 40_000);
        mk(&d, "BDMV/STREAM/00001.m2ts", 400);
        mk(&d, "BDMV/index.bdmv", 10);
        mk(&d, "CERTIFICATE/id.bdmv", 10);
        mk(&d, "sample.mkv", 4_000);
        assert_eq!(
            largest_video(&d),
            Some(d.join("BDMV/STREAM/00000.m2ts")),
            "the 40 KB m2ts two down is the feature, not the 4 KB root teaser"
        );
        // The half that made the old behaviour worse than picking the
        // wrong file: `main_video` rules a sample-named pick out, so a
        // job holding a whole Blu-ray answered None.
        assert_eq!(main_video(&d), Some(d.join("BDMV/STREAM/00000.m2ts")),);
        drop(d);
    }

    /// The camcorder / AVCHD depth, four down, and a release folder
    /// wrapper on top of a Blu-ray, three down. Both are shapes the
    /// old reach and a cap of 2 would each have missed.
    #[test]
    fn the_avchd_and_wrapped_disc_depths_are_reached() {
        let d = scratch("avchd");
        mk(&d, "PRIVATE/AVCHD/BDMV/STREAM/00000.MTS", 9_000);
        mk(&d, "clip.mp4", 100);
        assert_eq!(
            largest_video(&d),
            Some(d.join("PRIVATE/AVCHD/BDMV/STREAM/00000.MTS")),
        );
        drop(d);

        let d = scratch("wrapped");
        mk(
            &d,
            "Movie.2024.COMPLETE.BLURAY/BDMV/STREAM/00000.m2ts",
            9_000,
        );
        mk(&d, "Movie.2024.COMPLETE.BLURAY/sample.mkv", 100);
        assert_eq!(
            largest_video(&d),
            Some(d.join("Movie.2024.COMPLETE.BLURAY/BDMV/STREAM/00000.m2ts")),
        );
        drop(d);
    }

    /// The DVD shape that already worked keeps working, and the plain
    /// one-level release does too - this widening must not move any
    /// answer it was already getting right.
    #[test]
    fn the_shapes_that_already_worked_are_unchanged() {
        let d = scratch("dvd");
        mk(&d, "VIDEO_TS/VTS_01_1.VOB", 5_000);
        mk(&d, "VIDEO_TS/VIDEO_TS.IFO", 10);
        assert_eq!(largest_video(&d), Some(d.join("VIDEO_TS/VTS_01_1.VOB")));
        drop(d);

        let d = scratch("flat");
        mk(&d, "Show.S01E01.mkv", 5_000);
        mk(&d, "Subs/Show.S01E01.en.srt", 10);
        mk(&d, "sample.mkv", 100);
        assert_eq!(largest_video(&d), Some(d.join("Show.S01E01.mkv")));
        drop(d);

        // No video anywhere is still None, which is what
        // `keep_media_only`'s guard is written against.
        let d = scratch("novideo");
        mk(&d, "a/b/c/notes.txt", 10);
        assert_eq!(largest_video(&d), None);
        drop(d);

        // An unreadable root is None, not "no video" - a distinction
        // the old walk made with `read_dir(dir).ok()?` and this one
        // keeps.
        assert_eq!(largest_video(Path::new("/nonexistent-nzbfast-probe")), None);
    }

    /// The depth cap is a cap: past it the walk stops rather than
    /// running to the 16 components `sanitize_out_name` allows.
    #[test]
    fn the_depth_cap_bounds_the_walk() {
        let d = scratch("deepcap");
        let deep: String = (0..=FEATURE_MAX_DEPTH)
            .map(|i| format!("d{i}/"))
            .collect::<String>()
            + "buried.mkv";
        mk(&d, &deep, 9_000);
        mk(&d, "shallow.mkv", 100);
        assert_eq!(
            largest_video(&d),
            Some(d.join("shallow.mkv")),
            "a video below FEATURE_MAX_DEPTH must not be reached"
        );
        // ...and exactly at the cap it IS reached, so the cap is off by
        // nothing and the test above is about the cap rather than about
        // the walk being broken.
        let at: String = (0..FEATURE_MAX_DEPTH)
            .map(|i| format!("d{i}/"))
            .collect::<String>()
            + "atcap.mkv";
        mk(&d, &at, 20_000);
        assert_eq!(largest_video(&d), Some(d.join(&at)));
        drop(d);
    }

    /// The entry budget is a cap too, and until now nothing drove it -
    /// a real 50,000-entry fixture costs more than the arm is worth
    /// (31 Aug 2026 residue item 2). [`with_feature_max_entries`] shrinks
    /// it to 2 for this test only.
    ///
    /// The tree is two single-entry directories deep on purpose, so the
    /// count is exact regardless of `read_dir`'s own order: the root
    /// holds exactly `small.mkv` and `chain/`, which is exactly the
    /// budget, so both are SEEN and `chain/` is queued - but the budget
    /// is spent before `chain/`'s own one entry, `big.mkv`, is ever
    /// looked at. The walk must return the best it found before running
    /// out, not None and not the file it never reached.
    #[test]
    fn the_entry_budget_bounds_the_walk() {
        let d = scratch("entrycap");
        mk(&d, "small.mkv", 50);
        mk(&d, "chain/big.mkv", 9_000);

        {
            let _cap = with_feature_max_entries(2);
            assert_eq!(
                largest_video(&d),
                Some(d.join("small.mkv")),
                "the budget must stop the walk before it reaches chain/big.mkv"
            );
        }

        // The arm BITES: with it out of the way the same tree really
        // does hold a bigger video, so the result above was the cap
        // enforcing itself and not a tree that never had one.
        assert_eq!(
            largest_video(&d),
            Some(d.join("chain/big.mkv")),
            "without the small override the tree's real feature is chain/big.mkv"
        );
        drop(d);
    }

    /// A symlinked directory is not walked into: this answer sets the
    /// size every deletion threshold is measured against, so a link out
    /// of the job must not decide what inside it is a teaser.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_walked_into() {
        let outside = scratch("symtarget");
        mk(&outside, "huge.mkv", 50_000);
        let d = scratch("symjob");
        mk(&d, "real.mkv", 1_000);
        std::os::unix::fs::symlink(&outside, d.join("extras")).unwrap();
        assert_eq!(largest_video(&d), Some(d.join("real.mkv")));
        drop(d);
        drop(outside);
    }

    /// The other end of M4-81, in the terms the user sees it: the walk
    /// is only worth widening if the SWEEP that asks it then behaves.
    ///
    /// The chain this closes is `e2e_relpath`'s
    /// `a_four_deep_bluray_tree_lands_intact` (the tree really does
    /// reach disk two and four directories down, through a real run)
    /// plus this (the sweep asks the right file how big the feature
    /// is). There is deliberately no e2e between them: both sweeps are
    /// daemon settings, run from `serve::naming`, and the CLI path the
    /// no-RAR suites drive never calls either - so an e2e there could
    /// only re-assert the tree, which is already pinned.
    ///
    /// Before the widening, `largest_video` on this tree returned the
    /// 4 KB `sample.mkv`, so `feature_len` was 4 KB, `is_deletable_sample`
    /// measured the teaser against ITSELF and spared it, and the user
    /// got the sweep they asked for with the one file it exists to
    /// remove left behind.
    #[test]
    fn keep_media_only_measures_the_teaser_against_the_disc_not_against_itself() {
        let _steady = super::super::testkit::trash_globals_steady();
        let d = scratch("keepdisc2deep");
        mk(&d, "BDMV/STREAM/00000.m2ts", 40_000);
        mk(&d, "BDMV/index.bdmv", 10);
        mk(&d, "sample.mkv", 400); // 1% of the feature, well under
        mk(&d, "cover.jpg", 10); // ordinary clutter, goes either way
        keep_media_only(&d);
        assert!(
            !d.join("sample.mkv").exists(),
            "the teaser must be measured against the 40 KB disc title, \
             not against itself"
        );
        assert!(
            d.join("BDMV/STREAM/00000.m2ts").exists(),
            "the sweep does not reach two deep and must not have"
        );
        assert!(d.join("BDMV/index.bdmv").exists(), "disc structure stays");
        assert!(!d.join("cover.jpg").exists(), "clutter still goes");
        drop(d);
    }

    /// M4-92, PINNED AS IT STANDS rather than changed: a disc image
    /// outranks a smaller playable remux in the same job, because
    /// `VIDEO_EXTS` carries `iso`/`img` on purpose so that a disc rip
    /// posted alone IS the feature.
    ///
    /// This test asserts today's answer so that moving it is a
    /// decision somebody makes rather than a drift. What it costs is
    /// real and measured: `measured_res` and `container_title` are
    /// Matroska-only, and an `.iso` can never answer either, so a job
    /// holding a probeable remux gets no container measurement at all
    /// - the subject line's resolution claim stands unchallenged. What
    /// preferring the remux would cost is real too and points the
    /// other way: a disc rip posted WITH a bonus featurette would hand
    /// the featurette's name, length and resolution to the job. Which
    /// of those two the product wants is not a question this walk can
    /// answer from the bytes - both shapes are common and nothing in
    /// the files separates them - so it is a product decision and not
    /// a defect to fix on sight. Until one is made, the rule is the
    /// one `VIDEO_EXTS` already states, said out loud here.
    ///
    /// If it is ever changed: prefer the playable container only where
    /// it SHARES A STEM with the image (`Show.S01E01.mkv` beside
    /// `Show.S01E01.iso` - two spellings of one title). Preferring it
    /// unconditionally regresses the disc-plus-featurette post, and a
    /// size threshold would be a number with no corpus behind it.
    #[test]
    fn a_disc_image_still_outranks_a_smaller_remux_beside_it() {
        let d = scratch("isoremux");
        mk(&d, "Show.S01E01.mkv", 4_000);
        mk(&d, "Show.S01E01.iso", 8_000);
        assert_eq!(largest_video(&d), Some(d.join("Show.S01E01.iso")));
        assert_eq!(main_video(&d), Some(d.join("Show.S01E01.iso")));
        // The remux is not junk, so nothing deletes it - the cost is
        // identity, never the file. 4 GB against 8 GB is half, well
        // clear of SAMPLE_MAX_FRACTION, so the sample rule does not
        // reach it either.
        assert!(!is_deletable_sample(
            &d.join("Show.S01E01.mkv"),
            8_000,
            &super::super::files_in_reach(&d)
        ));
        drop(d);
    }

    /// The predicate the naming door asks before it renames anything.
    /// Each disc format at its own real depth, plus the wrapper a poster
    /// adds - the same populations `largest_video`'s own cases use,
    /// asked the other question.
    #[test]
    fn every_disc_layout_answers_and_names_its_marker() {
        for (tag, rel, marker) in [
            ("bd", "BDMV/STREAM/00000.m2ts", "BDMV"),
            ("dvd", "VIDEO_TS/VTS_01_1.VOB", "VIDEO_TS"),
            ("dvda", "AUDIO_TS/ATS_01_1.AOB", "AUDIO_TS"),
            ("hddvd", "HVDVD_TS/HV000I01.EVO", "HVDVD_TS"),
            (
                "avchd",
                "PRIVATE/AVCHD/BDMV/STREAM/00000.MTS",
                "PRIVATE/AVCHD",
            ),
            (
                "wrapped",
                "Movie.2024.COMPLETE.BLURAY/BDMV/STREAM/00000.m2ts",
                "Movie.2024.COMPLETE.BLURAY/BDMV",
            ),
            // Lower case: rippers write both spellings and
            // `sanitize_out_name` preserves whichever was posted.
            ("lower", "video_ts/vts_01_1.vob", "video_ts"),
        ] {
            let d = scratch(tag);
            mk(&d, rel, 9_000);
            assert_eq!(
                disc_structure(&d),
                Some(d.join(marker)),
                "{tag}: {rel} is a disc and {marker} is what says so"
            );
            drop(d);
        }
    }

    /// The flattened post, which has no directory to match on, and the
    /// four structure extensions that carry it. `.vob`/`.m2ts` are NOT
    /// markers - they are ordinary video by extension and a job holding
    /// one loose is not a disc.
    #[test]
    fn a_flattened_post_is_a_disc_by_its_structure_files() {
        for ext in ["bdmv", "mpls", "clpi", "ifo", "bup", "bdjo", "cpi", "mpl"] {
            let d = scratch("flatdisc");
            mk(&d, "00000.m2ts", 9_000);
            mk(&d, &format!("00000.{ext}"), 10);
            assert_eq!(
                disc_structure(&d),
                Some(d.join(format!("00000.{ext}"))),
                ".{ext} is produced by nothing but a disc"
            );
            drop(d);
        }
    }

    /// The other direction, and the one that keeps this from being a
    /// blanket decline. None of these is a disc, and three of the four
    /// are extensions `MEDIA_COMPANION_EXTS` carries for a different
    /// question - what `keep_media_only` must not delete beside a video.
    #[test]
    fn an_ordinary_release_is_not_a_disc() {
        let d = scratch("notdisc");
        mk(&d, "Example.Movie.2024.mkv", 9_000);
        mk(&d, "Example.Movie.2024.sup", 100); // PGS subtitle
        mk(&d, "Example.Movie.2024.eac3", 100); // external Atmos track
        mk(&d, "extras/bonus.jar", 10); // generic archive everywhere else
        mk(&d, "Subs/Example.Movie.2024.en.srt", 10);
        assert_eq!(disc_structure(&d), None);
        drop(d);

        // An unreadable root is None, the same answer as a tree with no
        // disc in it - see `walk_job`, which does not distinguish them
        // because neither caller's return type could carry it.
        assert_eq!(
            disc_structure(Path::new("/nonexistent-nzbfast-probe")),
            None
        );
    }

    /// A `BDMV` that is a SYMLINK is not walked into and is not a
    /// marker: our own extraction never makes one, so it points
    /// somewhere this job does not own - the same reasoning
    /// [`is_real_dir`] carries for the walk it bounds.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_disc_directory_is_not_a_marker() {
        let outside = scratch("symdisc-target");
        mk(&outside, "STREAM/00000.m2ts", 9_000);
        let d = scratch("symdisc");
        mk(&d, "real.mkv", 1_000);
        std::os::unix::fs::symlink(&outside, d.join("BDMV")).unwrap();
        assert_eq!(disc_structure(&d), None);
        drop(d);
        drop(outside);
    }

    /// The depth bound is the SAME bound `largest_video` walks under,
    /// because they are one walk. Pinned from both sides so a marker
    /// exactly at the cap is still seen.
    #[test]
    fn the_disc_probe_shares_the_depth_cap() {
        let d = scratch("discdepth");
        let deep: String = (0..=FEATURE_MAX_DEPTH)
            .map(|i| format!("d{i}/"))
            .collect::<String>()
            + "BDMV/index.bdmv";
        mk(&d, &deep, 10);
        assert_eq!(disc_structure(&d), None, "past the cap is not reached");
        let at: String = (0..FEATURE_MAX_DEPTH)
            .map(|i| format!("e{i}/"))
            .collect::<String>()
            + "index.bdmv";
        mk(&d, &at, 10);
        assert_eq!(disc_structure(&d), Some(d.join(&at)));
        drop(d);
    }

    /// The list relation this file's own doc comment claims, held
    /// mechanically: every disc-structure extension is one
    /// `keep_media_only` already refuses to delete. The two lists cannot
    /// be derived from each other - `MEDIA_COMPANION_EXTS` also carries
    /// subtitles and external audio, and nothing mechanical separates
    /// those from disc structure - so what is checkable is the
    /// containment, which is the direction that matters: an extension
    /// this declines on must not be one the sweep would delete anyway.
    #[test]
    fn the_disc_extensions_are_a_subset_of_the_companion_list() {
        for ext in DISC_STRUCTURE_EXTS {
            assert!(
                super::super::MEDIA_COMPANION_EXTS.contains(ext),
                "{ext} is a disc-structure extension that keep_media_only would delete"
            );
        }
    }
}
