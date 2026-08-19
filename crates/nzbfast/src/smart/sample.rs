//! Is this file a teaser, and may a sweep delete it?
//!
//! Split out of smart.rs rather than added to it: that file sits at its
//! TODO 106 size ceiling, and the rule is that the numbers only go down.
//! These three predicates are one subject - what a "sample"/"proof" name
//! is worth - and the distinction between the RENAME question and the
//! DELETE question is the whole reason they are separate functions.

use super::{VIDEO_EXTS, ext_of};
use std::path::Path;

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
pub(super) fn is_sample_named(p: &Path) -> bool {
    let s = stem_lower(p);
    s.contains("sample") || s.contains("proof")
}

/// Fraction of the feature's size below which a "sample"/"proof"-named video
/// is treated as a throwaway teaser. A real teaser is a tiny slice of the
/// feature; a same-size file that merely has "proof"/"sample" in its title
/// (the 2005 film "Proof", a "Proof" season pack, or a job that is itself
/// only a sample) is NOT a teaser. Name alone silently deleted real content.
const SAMPLE_MAX_FRACTION: f64 = 0.15;

/// A deletable teaser: sample/proof-named AND much smaller than the feature.
/// With `feature_len == 0` (no feature to compare against) nothing qualifies,
/// so a lone sample-named download is never destroyed.
pub(super) fn is_deletable_sample(p: &Path, feature_len: u64) -> bool {
    if feature_len == 0 || !is_sample_clip(p) {
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
            feature > 0 && (*len as f64) < (feature as f64) * SAMPLE_MAX_FRACTION
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
