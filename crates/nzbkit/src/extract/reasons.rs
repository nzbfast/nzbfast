//! The extractor's leaf helpers: the collision key output names are
//! claimed under, and the wording a blocker or a nested fallback reaches
//! the report with. Pure functions over names, errors and enum variants -
//! no extractor state - moved out of `extract/mod.rs` bodily so that file
//! stays inside its size-gate baseline (the TODO 106 pattern `names.rs`
//! already follows; glob-imported by `mod.rs`, so every caller in this
//! module tree is unchanged).
//!
//! The two `*_reason` functions are load-bearing prose, not labels: the
//! finish ladder pattern-matches SUBSTRINGS of what they return, so each
//! carries a note about which words it must and must not contain.

use crate::rar::MapBlocker;
use std::io;

pub(super) fn nofile() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no backing data")
}

/// Collision key for the chain-shared output-name set. On a case-insensitive
/// volume `README` and `readme` name ONE object, so claiming both would let
/// the second `FileWriter::create` (truncating) clobber the first; folding to
/// lowercase makes the second name disambiguate instead. On a case-sensitive
/// volume they are genuinely distinct files, so the exact name is kept and
/// neither gets needlessly renamed.
///
/// `fold` is PROBED from the output volume (`disk::case_insensitive_dir`) and
/// threaded down the chain next to `names_taken`, so every level keys that
/// shared set identically. It is deliberately not `cfg!(target_os)`: the
/// Linux container/NAS build writing to a CIFS/SMB or exFAT share is
/// case-insensitive, and that is precisely the deployment where losing an
/// output file hurts most.
pub(super) fn name_collision_key(fold: bool, name: &str) -> String {
    if fold {
        name.to_lowercase()
    } else {
        name.to_string()
    }
}

/// Reword a child-level fallback reason for the parent's report. The
/// caller keys VOLUME-level remediation (unrar passes, loose-volume job
/// failure) off substrings of top-level reasons ("compressed",
/// "encrypted"/"password", "held-bytes cap", "incomplete mapping"); a
/// nested demotion has already materialized the level-1 file - exactly
/// the single-level output, which the disk post-pass handles - so its
/// reason must never pattern-match those branches.
pub(super) fn nested_reason(why: &str) -> String {
    let safe: String = if why.contains("compressed") {
        "inner archive is not store-mode".to_string()
    } else if why.contains("password") || why.contains("encrypted") {
        "inner archive is protected".to_string()
    } else if why.contains("held-bytes cap") {
        "inner holds budget exceeded".to_string()
    } else if why.contains("incomplete mapping") {
        "inner mapping unfinished at end of download".to_string()
    } else {
        why.to_string()
    };
    format!("nested fallback: {safe}")
}

pub(super) fn blocker_reason(b: &MapBlocker) -> &'static str {
    match b {
        MapBlocker::NotRar => "not a RAR volume",
        MapBlocker::EncryptedHeaders => "encrypted headers (password required)",
        MapBlocker::NotStore => "compressed or encrypted entries",
        // Deliberately free of "compressed": the finish ladder's first arm
        // keys on that substring and would run an unrar attempt that cannot
        // succeed without a password, failing a job whose volumes are fine.
        // "encrypted"/"password" route it to the locked-no-password arm
        // (volumes kept, 🔒 prompt), matching EncryptedHeaders sets.
        MapBlocker::EncryptedNoPassword => "encrypted entries (password required)",
        MapBlocker::BadPassword => "wrong archive password",
        MapBlocker::Corrupt(w) => w,
    }
}

// ---------------------------------------------------------------------------
// Demote markers. A chase that gives up materializes its container into
// the output directory, and WHO OWNS the file it left is what these say.
// The caller (`nzbfast`'s `diag::sevenz_disk_fallback`) filters a marked
// reason out of the RAR unrar ladder entirely, because that ladder
// reasons about RAR VOLUMES and every one of its three arms misreads a
// container's wording: "held-bytes cap" as an unowned set, "encrypted"
// as a locked one, both ending at `try_unrar` over a directory with no
// RAR in it - which answers false and fails a job that is fine.
//
// The underlying reason stays readable INSIDE the string; several
// callers key on substrings of it.
//
// They live here rather than in `mod.rs` for this file's stated reason -
// wording is what it holds, and mod.rs sits against its size ceiling -
// and are re-exported from there, so every `nzbkit::extract::` caller is
// unchanged.
// ---------------------------------------------------------------------------

/// Reason prefix for a demote of a TOP-LEVEL 7z chase. The archive
/// materializes into the output directory, which is precisely the disk
/// post-pass's input, so the demote is owned - the caller must keep it
/// out of the RAR unpack ladder (handing a directory holding one .7z to
/// unrar fails a job that is fine). The underlying reason, "held-bytes
/// cap: chase memory" included, stays readable inside the string.
pub const SEVENZ_DISK_FALLBACK_PREFIX: &str = "7z materialized for the disk pass: ";

/// [`SEVENZ_DISK_FALLBACK_PREFIX`]'s zip twin: a demoted top-level zip
/// chase leaves a `.zip` the disk post-pass owns (its ladder step 5),
/// and its reason text must stay out of the RAR unpack ladder for the
/// same three-arms-all-wrong reason.
pub const ZIP_DISK_FALLBACK_PREFIX: &str = "zip materialized for the disk pass: ";

/// The same marker for a SELF-EXTRACTOR the offset-0 sniff started the
/// mapper inside (TODO 94 C): the demote materializes the posted
/// `.exe`/`.bin`/`.sfx` whole, stub included, and the get tail's SFX arm
/// carves and unpacks that - so it is owned like the two above and must
/// stay out of the RAR unrar ladder for the same reason. Unmarked, that
/// ladder ran `unrar` over a directory holding one `.exe` and failed the
/// job; `nzbfast`'s `sfx_locked_fallback` carries the one exception.
pub const SFX_DISK_FALLBACK_PREFIX: &str = "SFX materialized for the disk pass: ";

/// [`SEVENZ_DISK_FALLBACK_PREFIX`]'s tar twin (TODO 163 item 6): a
/// demoted top-level tar chase leaves a `.tar` in the output directory,
/// which is exactly where a posted `.tar` landed before that arm
/// existed - and, since the disk half landed on 23 Aug 2026, exactly
/// what the post-pass ladder's tar arm owns.
///
/// The filter is unchanged by that, and re-read when the arm was built:
/// it was never "nothing unpacks a tar", it is "the RAR ladder is the
/// wrong owner". That ladder reasons about RAR VOLUMES, and this
/// reason's text ("symlink", "held-bytes cap") steers all three of its
/// arms at a directory holding no RAR. The demote is now the same story
/// as the 7z and zip prefixes above in every respect: marked here,
/// filtered out of the unrar ladder, and picked up one pass later by
/// the disk arm that does own it.
pub const TAR_DISK_FALLBACK_PREFIX: &str = "tar materialized for the disk pass: ";
