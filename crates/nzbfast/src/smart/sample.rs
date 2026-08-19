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
