//! Is this file a teaser, and may a sweep delete it?
//!
//! Split out of smart.rs rather than added to it: `smart.rs` was at
//! 4,024 lines against its TODO 106 baseline on 18 Aug 2026, and the
//! rule is that the numbers only go down.
//! These three predicates are one subject - what a "sample"/"proof" name
//! is worth - and the distinction between the RENAME question and the
//! DELETE question is the whole reason they are separate functions.

use super::{VIDEO_EXTS, ext_of};
use std::path::{Path, PathBuf};

pub(super) fn stem_lower(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// A "sample"/"proof"-named video. Name only - NOT sufficient on its own to
/// delete a file (see `is_deletable_sample`); used by the non-destructive
/// rename paths to leave a likely teaser un-renamed.
pub(super) fn is_sample_clip(p: &Path) -> bool {
    is_sample_named(p) && VIDEO_EXTS.contains(&ext_of(p).as_str())
}

/// The NAME half of [`is_sample_clip`], with no extension requirement.
///
/// Separate on purpose, and used only by the RENAME paths. Since #43 an
/// extensionless payload can be a video, so a file literally called
/// `sample` with EBML bytes was invisible to the extension-gated check
/// and could take the canonical episode name from the feature. Widening
/// `is_sample_clip` itself would have fixed that and also widened
/// `is_deletable_sample`, which decides what a sweep may DELETE - the
/// one direction the rename paths are not allowed to move (Codex sweep
/// 5, M4).
///
/// A WHOLE TOKEN, never a substring, since matrix row M4-91. `contains`
/// answered true for `Bulletproof.S01E01.mkv`, `Foolproof.2003.mkv` and
/// `The.Sampler.2011.mkv` - names in which no poster ever said "teaser",
/// and in which the letters are part of another word. Measured 30 Aug
/// 2026 on origin/main: `Bulletproof.S01E01.mkv` beside a larger special
/// was SKIPPED at plan time (its bytes never crossed the wire) and
/// `main_video` was `None` for a directory holding nothing else, so the
/// resolution and container-title questions went unanswered for a title
/// whose only offence was spelling.
///
/// Nothing real is lost by requiring the boundary. Every scene spelling
/// of a teaser delimits the word - `sample.mkv`, `Movie.2024.sample.mkv`,
/// `sample-Movie.2024.mkv`, `movie_sample.mkv` - and a glued
/// `moviesample.mkv` that stops being recognised costs one downloaded
/// teaser the user can delete, against a payload they cannot get back.
/// Trailing digits stay in (`sample01`, `proof2`): posters number them,
/// and no title is a marker word followed by nothing but digits.
pub(super) fn is_sample_named(p: &Path) -> bool {
    tokens(&stem_lower(p)).any(is_marker)
}

/// The two words a teaser's filename carries.
const SAMPLE_MARKERS: [&str; 2] = ["sample", "proof"];

/// Is this one token a marker - the bare word, or the word with a run of
/// digits after it (`sample01`)?
fn is_marker(t: &str) -> bool {
    SAMPLE_MARKERS.iter().any(|m| {
        t.strip_prefix(m)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
    })
}

/// Split an already-lowercased stem on scene delimiters. Anything that is
/// not alphanumeric separates, which covers `.`, `-`, `_`, space and the
/// brackets, and keeps `s01e01` and `sample01` whole.
fn tokens(stem: &str) -> impl DoubleEndedIterator<Item = &str> {
    stem.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
}

/// The stem with its marker tokens removed, rejoined with `.` so two
/// names written with different delimiters compare equal.
fn without_markers(stem: &str) -> String {
    tokens(stem)
        .filter(|t| !is_marker(t))
        .collect::<Vec<_>>()
        .join(".")
}

/// Delimiter-aligned prefix: `movie.2024` is a prefix of
/// `movie.2024.part01` and of itself, and is NOT a prefix of
/// `movie.2024extra`. Both sides are already normalised by
/// [`without_markers`] or by the caller.
fn is_token_prefix(a: &str, b: &str) -> bool {
    a.is_empty() || b == a || b.starts_with(&format!("{a}."))
}

/// Does this marker-named file read as a teaser OF one of the other
/// names in the job, rather than as a title that merely contains the
/// word? The question matrix row M4-91 turns on.
///
/// A teaser is NAMED AFTER the thing it is a teaser of: strip the marker
/// tokens and what is left is the release's own name, or nothing at all.
/// A title that happens to contain the word is left holding the REST of
/// its own title, which is nobody else's name.
///
///   - `sample.mkv` -> nothing left, so a teaser of whatever is here.
///   - `Movie.2024.sample.mkv` -> `movie.2024`, and `Movie.2024.mkv`
///     (or `Movie.2024.part01.rar`) is right there.
///   - `sample-Movie.2024.mkv` -> the same, from the prefix spelling.
///   - `Proof.S01E01.mkv` -> `s01e01`, which is not the name of
///     `Proof.S01E00.Special.mkv` or of anything else. Not a teaser.
///   - `Free.Sample.2019.mkv` -> `free.2019`, likewise.
///
/// TWO comparisons, and the asymmetry between them is the whole rule.
///
///   - What is left of MY name is a prefix of the other's WHOLE name.
///     That is the marker-as-addition case above, and it is deliberately
///     against the other's full stem rather than its stripped one:
///     stripping both and accepting a PREFIX makes `Free.Sample.2019`
///     look derived from `Free.Sample.2019.Extras`, which is the one
///     shape that survives every other test here.
///   - Or what is left of my name EQUALS what is left of theirs. That
///     covers the feature whose OWN title carries a marker word -
///     `Proof.2005.1080p.sample.mkv` beside `Proof.2005.1080p.mkv`,
///     where the first comparison cannot fire, because the other name
///     starts with the marker and so is no prefix of mine. Equality and
///     never prefix: it says the two names are the SAME release once the
///     marker words are gone, which is exactly what "the feature's name
///     plus a teaser marker" means, while a prefix here would readmit
///     `Free.Sample.2019` against its own `.Extras`.
///
/// It errs toward KEEPING, which is the direction this whole module is
/// required to err in: anything it declines to call a teaser is simply
/// downloaded, and the post-download sweep - which has the bytes and
/// probes the duration - still gets the final say on deleting it.
///
/// With no other name at all this answers false, which is the same rule,
/// and the same reason, as `feature_len == 0` below: a job whose only
/// video is marker-named IS the release the user asked for.
fn is_teaser_of_any<'a>(stem: &str, others: impl Iterator<Item = &'a str>) -> bool {
    let mine = without_markers(stem);
    let full = tokens(stem).collect::<Vec<_>>().join(".");
    // The marker is the LAST thing in the name. Scene posts APPEND it, so
    // this is the shape that does not need a relative to be recognised -
    // and it is the only one that reaches an obfuscated post, where the
    // teaser's posted name and the feature's have nothing in common
    // (`Movie.Sample.mkv` beside `Main.Video.mkv`). Found by the full e2e
    // suite: the rule without it declined that, which is the fixture
    // matrix row M4-29 pins the skip with.
    // No `!mine.is_empty()` guard here, deliberately: a stem that is
    // NOTHING but markers is already carried by `derived`, since an empty
    // remainder is a prefix of every name. Keeping both would be two
    // sufficient guards over one case, which makes neither falsifiable -
    // and a mutation of this line proved exactly that before it went.
    let appended = tokens(stem).next_back().is_some_and(is_marker);
    // `others` are FILENAMES: take each one's stem, lowercase it and
    // rejoin its tokens, so the two sides are normalised the same way and
    // a delimiter or a capital cannot decide this.
    let mut seen = false;
    let mut derived = false;
    let mut named_after_me = false;
    for other in others {
        seen = true;
        let theirs = stem_lower(Path::new(other));
        let theirs_full = tokens(&theirs).collect::<Vec<_>>().join(".");
        derived |= is_token_prefix(&mine, &theirs_full)
            || (!mine.is_empty() && mine == without_markers(&theirs));
        // THE VETO, and it outranks BOTH tests above. If another file
        // here is named after ME - my whole name, marker words included,
        // as a proper prefix of theirs - then those words are my TITLE
        // and not something a poster appended, so I am the release and
        // it is the extra. `Free.Sample.mkv` beside
        // `Free.Sample.Extras.mkv` needs it against both: `sample` is
        // last, AND stripping it leaves `free`, which prefixes their
        // name. It has to be a PROPER prefix - an equal name is the same
        // release, which is what a teaser and its feature look like once
        // the marker is gone. It is also what a teaser and its OWN
        // sidecar look like: `Movie.2024.sample.srt` beside
        // `Movie.2024.sample.mkv` normalises to the same tokens, and
        // without the properness test that subtitle would veto the
        // teaser it belongs to. Pinned - the guard is not reachable from
        // any other shape.
        named_after_me |= is_token_prefix(&full, &theirs_full) && full != theirs_full;
    }
    seen && !named_after_me && (derived || appended)
}

/// [`is_teaser_of_any`] over the files in a finished directory: the
/// sibling-aware half of [`is_sample_clip`], for the callers that have a
/// directory to look at.
pub(super) fn is_teaser_beside(p: &Path, siblings: &[PathBuf]) -> bool {
    if !is_sample_clip(p) {
        return false;
    }
    is_teaser_of_any(
        &stem_lower(p),
        siblings
            .iter()
            .filter(|o| o.as_path() != p)
            .filter_map(|o| o.file_name().and_then(|n| n.to_str())),
    )
}

/// Fraction of the feature's size below which a "sample"/"proof"-named video
/// is treated as a throwaway teaser. A real teaser is a tiny slice of the
/// feature; a same-size file that merely has "proof"/"sample" in its title
/// (the 2005 film "Proof", a "Proof" season pack, or a job that is itself
/// only a sample) is NOT a teaser. Name alone silently deleted real content.
const SAMPLE_MAX_FRACTION: f64 = 0.15;

/// A deletable teaser: a teaser OF something else in this directory AND
/// much smaller than the feature. With `feature_len == 0` (no feature to
/// compare against) nothing qualifies, so a lone sample-named download is
/// never destroyed.
///
/// `siblings` is the sweep's whole footprint, from
/// [`super::files_in_reach`] - every real file it can see, taken ONCE
/// before anything is deleted, so the answer cannot depend on `read_dir`
/// order or on how much of the sweep has already run.
///
/// THE SIBLING TEST GATES, it does not merely add. Until 31 Aug 2026 this
/// decided on name and size alone, with a duration veto that covered
/// `mkv`/`webm` - two of `VIDEO_EXTS`' eighteen - and only when
/// `nzbkit::mkv::probe` could read a header. Measured on origin/main at
/// c4d47e276: `Proof.S01E01.mp4` (400 KB) beside
/// `Proof.S01E00.Special.mp4` (4 MB) was deleted by BOTH `sweep_junk` and
/// `keep_media_only` - 400 KB is under 0.15 * 4 MB, `proof` is a whole
/// token, and `.mp4` gets no probe. That is the payload the user asked
/// for, gone, at rc=0.
///
/// So the third opinion is the one already written for the plan-time
/// twin, and it is extension-blind where the probe is not: is this name a
/// teaser OF something here ([`is_teaser_beside`], and read
/// [`is_teaser_of_any`] for why each comparison is the shape it is)? An
/// mkv episode is spared by its header and an mp4 one by its name, and a
/// genuine teaser is named after the thing it teases in every scene
/// spelling, so the answer for the file this rule exists to remove is
/// unchanged.
///
/// THE DURATION VETO IS DELIBERATELY NOT WIDENED past `mkv`/`webm`.
/// `nzbkit` has no mp4 or avi probe and building one for this would be a
/// container parser written to answer a naming question; the sibling test
/// reaches all eighteen extensions at once. The veto stays because it is
/// the STRONGER evidence where it is available - a file whose own header
/// says it runs fifty minutes is not a teaser whatever it is named beside
/// - and because dropping it would retire the only arm that can spare a
/// mislabelled episode in a directory that has nothing else to compare it
/// against.
///
/// WHAT GATING COSTS, said rather than left to be found. A marker-named
/// clip whose name reads as nobody's teaser - `sample_teaser_clip.mkv`
/// beside `Movie.2024.mkv`, where the marker is neither last nor leaves
/// the feature's name behind - is now KEPT where it used to go. That is
/// one small file the user can delete, against a payload they cannot get
/// back, and it is the direction this whole module is required to err in.
/// The same holds for a feature that lives two or more directories deep:
/// `super::files_in_reach` reaches one level, so a teaser at the root has
/// no relative there to be named after and is kept - the cost
/// [`super::files_in_reach`] already states for [`super::main_video`].
pub(super) fn is_deletable_sample(p: &Path, feature_len: u64, siblings: &[PathBuf]) -> bool {
    if feature_len == 0 || !is_teaser_beside(p, siblings) {
        return false;
    }
    let len = p.metadata().map(|m| m.len()).unwrap_or(0);
    if (len as f64) >= (feature_len as f64) * SAMPLE_MAX_FRACTION {
        return false;
    }
    // Name and size both say sample; the container gets a veto. A real
    // episode with "sample" in its title sits small beside a
    // double-length special, but its own header says it runs like an
    // episode - nothing that long is deleted on a name.
    if matches!(ext_of(p).as_str(), "mkv" | "webm")
        && let Some(i) = nzbkit::mkv::probe(p)
        && i.duration_secs.is_some_and(|d| d >= 15.0 * 60.0)
    {
        return false;
    }
    true
}

/// Plan-time twin of [`is_deletable_sample`]: which of a job's payload
/// files may be left UNFETCHED entirely, given only what the NZB
/// declares - names and byte counts, no file on disk to probe.
///
/// `files` is `(posted filename, declared bytes)` for the job's DATA
/// files in NZB order; the caller drops the PAR2 entries first, since
/// recovery data is never a sample and must never be skipped. The
/// returned vector is aligned with the input.
///
/// The decision reuses the sweep's own two halves and adds nothing of
/// its own: [`is_sample_clip`] for the name (sample/proof stem AND a
/// video extension) and `SAMPLE_MAX_FRACTION` for the size. What it
/// cannot reuse is the container probe - `is_deletable_sample` opens
/// the file and refuses to call anything that RUNS like an episode a
/// teaser, and here there is no file yet. The relative-size test is
/// the plan-time stand-in for that duration gate, and like it, the
/// answer errs toward downloading: a sample-named file large enough to
/// plausibly BE the feature is fetched, and the post-download sweep -
/// which does have the bytes, and does probe the duration - gets the
/// final say on deleting it.
///
/// "The feature", measured the only way a plan can:
///
/// - the largest single OTHER video, because a video stands alone (a
///   season pack is ten features, not one, so ten episodes must not
///   sum into a feature that makes each of them look like a teaser),
/// - or the sum of every other NON-video file, because those are
///   pieces: a 20-part RAR set is one feature split twenty ways, and
///   comparing a sample against one 50 MB volume would never skip
///   anything.
///
/// Whichever is larger; and with no other payload at all the figure is
/// zero, which skips nothing. That zero is the sole-video guard, and
/// it is the same rule (and the same reason) as
/// `is_deletable_sample`'s `feature_len == 0`: a job whose only video
/// is sample-named IS the release the user asked for - a genuine
/// teaser post, or a feature whose title merely says "Proof" - and
/// name-based classification has destroyed real payload here before
/// (issue #40, the named `.cbr`). Nothing is skipped without a bigger
/// thing to be a sample OF.
pub(crate) fn skippable_samples(files: &[(String, u64)]) -> Vec<bool> {
    let is_video = |n: &str| VIDEO_EXTS.contains(&ext_of(Path::new(n)).as_str());
    files
        .iter()
        .enumerate()
        .map(|(i, (name, len))| {
            if !is_sample_clip(Path::new(name.as_str())) {
                return false;
            }
            let mut biggest_video = 0u64;
            let mut pieces = 0u64;
            for (j, (other, olen)) in files.iter().enumerate() {
                if j == i {
                    continue;
                }
                if is_video(other) {
                    biggest_video = biggest_video.max(*olen);
                } else {
                    // Saturating: declared byte counts are
                    // poster-typed, and a sum that wraps would hand
                    // back a tiny feature and skip real payload.
                    pieces = pieces.saturating_add(*olen);
                }
            }
            let feature = biggest_video.max(pieces);
            if feature == 0 || (*len as f64) >= (feature as f64) * SAMPLE_MAX_FRACTION {
                return false;
            }
            // M4-91: the name still has to read as a teaser OF something
            // here. Size alone let `Proof.S01E01.mkv` (400 MB) be skipped
            // beside `Proof.S01E00.Special.mkv` (3 GB) - 400 is under
            // 0.15 * 3000 - so an episode of a series called Proof never
            // crossed the wire, at a `--skip-samples` the user turned on
            // to save a teaser's bytes. There is no duration probe to
            // catch it here (there is no file yet), and the post-download
            // sweep never gets a chance either: the bytes are the thing
            // that was skipped.
            let mine = stem_lower(Path::new(name.as_str()));
            is_teaser_of_any(
                &mine,
                files
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, (other, _))| other.as_str()),
            )
        })
        .collect()
}

#[cfg(test)]
mod skip_tests {
    use super::*;

    const MB: u64 = 1 << 20;
    const GB: u64 = 1 << 30;

    fn skip(files: &[(&str, u64)]) -> Vec<bool> {
        let owned: Vec<(String, u64)> = files.iter().map(|(n, b)| (n.to_string(), *b)).collect();
        skippable_samples(&owned)
    }

    /// M4-91, the row's own headline. A series called Proof: the episode
    /// is 400 MB, the double-length special beside it is 3 GB, and 400 is
    /// under 0.15 * 3000 - so `--skip-samples`, a setting the user turned
    /// on to save a teaser's bytes, declined to fetch an episode.
    ///
    /// Measured RED on origin/main 30 Aug 2026: `[true, false]`. There is
    /// no second chance for this one - the post-download sweep probes the
    /// duration and would have kept it, but the bytes are what was
    /// skipped, so the sweep never sees a file at all.
    #[test]
    fn a_title_that_merely_contains_the_word_is_not_a_teaser() {
        // The whole token IS there, and it is still not a teaser: strip
        // it and `s01e01` is left, which is nobody else's name.
        assert_eq!(
            skip(&[
                ("Proof.S01E01.mkv", 400 * MB),
                ("Proof.S01E00.Special.mkv", 3000 * MB),
            ]),
            [false, false]
        );
        // The word is not even a token - it is inside another one.
        assert_eq!(
            skip(&[
                ("Bulletproof.S01E01.mkv", 400 * MB),
                ("Bulletproof.S01E00.Special.mkv", 3000 * MB),
            ]),
            [false, false]
        );
        // A title whose own words are the markers, beside a bigger extra.
        assert_eq!(
            skip(&[
                ("Free.Sample.2019.mkv", 400 * MB),
                ("Free.Sample.2019.Extras.mkv", 3000 * MB),
            ]),
            [false, false]
        );
        assert_eq!(
            skip(&[
                ("The.Sampler.2011.mkv", 400 * MB),
                ("The.Sampler.2011.Bonus.mkv", 3000 * MB),
            ]),
            [false, false]
        );
    }

    /// The direction the row above must not cost, pinned in the same test
    /// so neither can be relaxed alone: every real spelling of a teaser
    /// is still skipped, INCLUDING beside a feature whose own title
    /// carries the marker word.
    #[test]
    fn every_real_spelling_of_a_teaser_is_still_skipped() {
        for (teaser, feature) in [
            ("sample.mkv", "Great.Movie.2024.mkv"),
            ("Sample.mkv", "Great.Movie.2024.mkv"),
            ("sample01.mkv", "Great.Movie.2024.mkv"),
            ("Great.Movie.2024.sample.mkv", "Great.Movie.2024.mkv"),
            ("Great.Movie.2024.SAMPLE.mkv", "Great.Movie.2024.mkv"),
            ("great_movie_2024_sample.mkv", "Great.Movie.2024.mkv"),
            ("sample-Great.Movie.2024.mkv", "Great.Movie.2024.mkv"),
            ("Great.Movie.2024.proof.mkv", "Great.Movie.2024.mkv"),
            // The feature's own title says Proof, and its teaser still
            // reads as derived from it.
            ("Proof.2005.1080p.sample.mkv", "Proof.2005.1080p.mkv"),
        ] {
            assert_eq!(
                skip(&[(teaser, 40 * MB), (feature, 8 * GB)]),
                [true, false],
                "{teaser:?} beside {feature:?}"
            );
        }
    }

    /// The APPENDED marker and its veto, which is the half of M4-91 that
    /// the unit fixtures alone did not find: the full e2e suite did,
    /// because M4-29's own fixture is exactly this shape and the first
    /// cut of the derived-name rule declined it.
    ///
    /// A teaser reaching an OBFUSCATED post shares nothing with the
    /// feature's posted name - there is no relative to be derived from -
    /// so a marker in final position has to stand on its own. What keeps
    /// that from readmitting a title is the other direction: if another
    /// file here is named after ME, those words are my title.
    #[test]
    fn an_appended_marker_stands_alone_unless_something_is_named_after_it() {
        // M4-29's fixture: nothing in common but the marker.
        assert_eq!(
            skip(&[("Movie.Sample.mkv", 40 * MB), ("Main.Video.mkv", 400 * MB)]),
            [true, false]
        );
        // The veto. `Free.Sample.2019.Extras.mkv` is named after
        // `Free.Sample.2019.mkv`, so the film is the film.
        assert_eq!(
            skip(&[
                ("Free.Sample.mkv", 40 * MB),
                ("Free.Sample.Extras.mkv", 400 * MB),
            ]),
            [false, false]
        );
        // A teaser with a sidecar of its OWN. The subtitle's stem
        // normalises to the teaser's exactly, so the veto must not read
        // it as "something is named after me" - an equal name is the
        // same release, not a derivative of it.
        assert_eq!(
            skip(&[
                ("Movie.2024.mkv", 8 * GB),
                ("Movie.2024.sample.mkv", 40 * MB),
                ("Movie.2024.sample.srt", 40 * 1024),
            ]),
            [false, true, false]
        );
        // And the marker in any position OTHER than last still needs a
        // relative, which is what keeps the row's own headline fixed.
        assert_eq!(
            skip(&[
                ("Proof.S01E01.mkv", 400 * MB),
                ("Proof.S01E00.Special.mkv", 3000 * MB),
            ]),
            [false, false]
        );
    }

    /// The shape the setting exists for: a teaser beside the real
    /// release, in both of the two ways a release is posted.
    #[test]
    fn a_teaser_beside_a_feature_is_skipped() {
        // Single-file post.
        assert_eq!(
            skip(&[
                ("Movie.2024.1080p-GRP.mkv", 8 * GB),
                ("movie-sample.mkv", 40 * MB)
            ]),
            [false, true]
        );
        // RAR set: no other VIDEO exists, so the feature is the volumes
        // summed. Measured against one 50 MB volume nothing would ever
        // skip, which is the whole reason pieces sum.
        let mut rars: Vec<(&str, u64)> = (0..20)
            .map(|_| ("Movie.2024.1080p-GRP.part.rar", 50 * MB))
            .collect();
        rars.push(("Movie.2024.1080p-GRP-sample.mkv", 30 * MB));
        rars.push(("Movie.2024.1080p-GRP.nfo", 4096));
        let v = skip(&rars);
        assert!(v[20], "the sample is 30 MB against a 1 GB set");
        assert!(v[..20].iter().all(|&s| !s), "no volume is ever a sample");
        assert!(!v[21], "and the .nfo is not a video");
    }

    /// The size gate, from both sides. This is the plan-time stand-in
    /// for the duration gate: a "sample" big enough to plausibly be the
    /// feature is DOWNLOADED, and the post-download sweep - which can
    /// open it and read its running time - decides from there.
    #[test]
    fn a_sample_name_on_a_feature_sized_file_is_kept() {
        // 14% of the feature: a teaser.
        assert!(
            skip(&[
                ("The.Feature.mkv", 100 * GB / 10),
                ("sample.mkv", 14 * GB / 10)
            ])[1]
        );
        // 16%: too much of the feature to throw away on a name.
        assert!(
            !skip(&[
                ("The.Feature.mkv", 100 * GB / 10),
                ("sample.mkv", 16 * GB / 10)
            ])[1]
        );
        // Same size as the feature - a repost, a mislabelled episode,
        // or a job that IS a sample. Never skipped.
        assert_eq!(
            skip(&[
                ("The.Feature.mkv", 4 * GB),
                ("Show.Free.Sample.mkv", 4 * GB)
            ]),
            [false, false]
        );
    }

    /// The sole-video guard (issue #40's lesson: a name is not proof).
    /// With nothing bigger for it to be a sample OF, a sample-named
    /// video is the release.
    #[test]
    fn the_only_video_in_a_job_is_never_skipped() {
        // A genuine sample-only post.
        assert_eq!(skip(&[("teaser-sample.mkv", 60 * MB)]), [false]);
        // The 2005 film "Proof", posted as one file with its furniture.
        assert!(
            !skip(&[
                ("Proof.2005.1080p.BluRay-GRP.mkv", 7 * GB),
                ("Proof.2005.1080p.BluRay-GRP.nfo", 2048),
                ("Proof.2005.1080p.BluRay-GRP.sfv", 512),
            ])[0],
            "the furniture beside it is not a feature it could be a sample of"
        );
        // Subtitles are not payload the sample could be a teaser for
        // either - a few KB cannot make a 4 GB file look small.
        assert!(
            !skip(&[
                ("Sample.Sized.Feature-sample.mkv", 4 * GB),
                ("subs.srt", 40 * 1024)
            ])[0]
        );
    }

    /// A season pack is ten features, not one - so the episodes must
    /// not sum into a "feature" that makes each of them a teaser. One
    /// episode whose title carries the word is still an episode.
    #[test]
    fn a_season_pack_does_not_sum_into_a_feature() {
        let mut pack: Vec<(&str, u64)> = (0..9)
            .map(|_| ("Show.S01E01.1080p-GRP.mkv", 15 * GB / 10))
            .collect();
        pack.push(("Show.S01E10.The.Free.Sample.1080p-GRP.mkv", 15 * GB / 10));
        assert!(
            skip(&pack).iter().all(|&s| !s),
            "summed, the other nine would make a 13.5 GB feature and this \
             1.5 GB episode a teaser of it"
        );
    }

    /// Only VIDEO samples, and only ones the name actually claims.
    /// `is_sample_clip` owns both halves - restated here because THIS
    /// is the caller that never downloads the bytes at all.
    #[test]
    fn nothing_else_is_a_skippable_sample() {
        let feature = ("Feature.mkv", 8 * GB);
        for other in [
            // Not sample-named.
            ("Movie.2024.1080p-GRP.mkv", 40 * MB),
            // Sample-named, not a video: an audio release's teaser, a
            // proof JPEG, the sweep's business and not this one's.
            ("sample.mp3", 4 * MB),
            ("proof.jpg", 200 * 1024),
            // A PAR2 volume that merely mentions the word. The caller
            // drops recovery data before we ever see it; this pins the
            // extension half in case one ever slips through.
            ("sample.vol000+01.par2", 50 * MB),
        ] {
            assert!(!skip(&[feature, other])[1], "{}", other.0);
        }
    }
}

#[cfg(test)]
mod name_tests {
    use super::super::testkit::*;
    use super::*;

    /// M4-91's other half. `main_video` is what `measured_res` and
    /// `identity::container_title` ask, so a directory it answers `None`
    /// for has no payload-side opinion at all: the poster's subject line
    /// stands unchallenged on resolution and title.
    ///
    /// Measured `None` on origin/main 30 Aug 2026 for BOTH of the first
    /// two directories below.
    #[test]
    fn the_feature_is_found_for_a_title_that_contains_the_word() {
        for (label, names) in [
            (
                "a series called Proof: both stems carry the word, so \
                 whichever was largest was rejected",
                &["Proof.S01E01.mkv", "Proof.S01E00.Special.mkv"][..],
            ),
            (
                "the word is inside another one",
                &["Bulletproof.S01E01.mkv"][..],
            ),
            (
                "a job whose ONLY video is marker-named IS the release \
                 the user asked for",
                &["Great.Movie.2024.sample.mkv"][..],
            ),
        ] {
            let d = scratch("mainvideo");
            for (i, n) in names.iter().enumerate() {
                std::fs::write(d.join(n), vec![0u8; 4096 * (i + 1)]).unwrap();
            }
            let got = super::super::main_video(&d);
            assert!(got.is_some(), "{label}: {names:?} -> None");
        }
    }

    /// The direction the pin above must not cost: a marker-named file
    /// that really IS named after something else here is still not the
    /// feature, however big it is - the protective half of the old
    /// name-only filter, kept.
    #[test]
    fn a_teaser_is_still_not_the_feature_however_big() {
        let d = scratch("mainvideoctl");
        // A mislabelled post: the sample-named file is the LARGEST.
        std::fs::write(d.join("Great.Movie.2024.mkv"), vec![0u8; 4096]).unwrap();
        std::fs::write(d.join("Great.Movie.2024.sample.mkv"), vec![0u8; 40960]).unwrap();
        assert_eq!(
            super::super::main_video(&d),
            None,
            "named after the file beside it, so it is a teaser whatever \
             the byte counts say"
        );
        // And the ordinary shape still resolves to the feature.
        let d2 = scratch("mainvideoctl2");
        std::fs::write(d2.join("Great.Movie.2024.mkv"), vec![0u8; 40960]).unwrap();
        std::fs::write(d2.join("Great.Movie.2024.sample.mkv"), vec![0u8; 4096]).unwrap();
        assert_eq!(
            super::super::main_video(&d2).unwrap().file_name().unwrap(),
            "Great.Movie.2024.mkv"
        );
    }

    /// The token rule itself, both ways, at the boundary the row is
    /// about. `is_sample_named` reaches seven callers (the plan-time
    /// skip, the sweep's delete gate, `main_video`, `is_furniture` and
    /// three filing paths), so this is the one predicate worth pinning
    /// on its own.
    #[test]
    fn a_marker_is_a_whole_token_and_never_a_substring() {
        for n in [
            "sample.mkv",
            "SAMPLE.mkv",
            "sample01.mkv",
            "proof2.mkv",
            "Movie.2024.sample.mkv",
            "sample-Movie.2024.mkv",
            "movie_sample.mkv",
            "movie sample.mkv",
            "Movie.2024.proof.jpg",
            "[sample].mkv",
        ] {
            assert!(is_sample_named(Path::new(n)), "should be a marker: {n}");
        }
        for n in [
            "Bulletproof.2024.mkv",
            "Foolproof.2003.mkv",
            "The.Sampler.2011.mkv",
            "Samples.of.Life.mkv",
            "presample.mkv",
            "Rasputin.1996.mkv",
            "Great.Movie.2024.mkv",
        ] {
            assert!(!is_sample_named(Path::new(n)), "not a marker: {n}");
        }
    }
}
