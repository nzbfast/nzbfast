//! What a file's NAME says about the archive it might be - and, where
//! the name cannot answer, what its first bytes say.
//!
//! Pure functions over a path: no directory scan, no extraction state,
//! nothing above this module in the crate. They are here rather than in
//! `unpack` and `rarfix` because the callers span every layer -
//! `manifest` certifies a settled directory and has to know which files
//! the extraction ladder was entitled to consume, `smart` asks the same
//! question of one path while filing, and the ladder itself asks it
//! constantly. Leaving the grammar beside the ladder made the lowest
//! layer of the crate-split plan depend on the unpack one for a string
//! test (step 1 of
//! research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md).
//!
//! The magic sniffs read the first few bytes and answer false on any
//! error, including a path that will not open - by contract, because
//! every caller is asking "should I treat this as an archive" and the
//! honest answer for a file it cannot read is no.
//!
//! They read those bytes through [`nzbkit::headpeek`], which reads a
//! given file's head ONCE per (path, file identity) and answers the
//! repeats from a `stat`. That is not a micro-optimisation: the unpack
//! ladder asks these three questions of the same file from a dozen
//! different sites, and on a 2,048-member set that was 98% of the
//! post-download tail. The measurement, and why the memo cannot go
//! stale, are in the `headpeek` module docs.

/// Does the file start with the RAR marker (`Rar!`, v4 or v5)?
pub fn rar_magic(path: &std::path::Path) -> bool {
    nzbkit::headpeek::head(path).is_some_and(|h| h.starts_with(b"Rar!"))
}

/// Does the file start with the RAR5 RECOVERY-VOLUME marker
/// (`Rar!\x1aRev`)?
///
/// A `.rev` is not payload and never extracts: it is the spare parity a
/// `rar -rv` set carries so a missing volume can be rebuilt, and the
/// repair rung owns it. It matters here because it starts with `Rar!`
/// and therefore passes [`rar_magic`], so without this the obfuscated
/// arm collects it as a candidate volume, the parser correctly refuses
/// it with `UnsupportedSignature`, and a set whose payload extracted
/// perfectly is reported as a failure - measured 3 Sep 2026 against the
/// `rar5_rev_present` and `rar5_rev_rebuild` robustness fixtures, where
/// `nzbfast extract` exited 1 having written every expected byte, and
/// in the rebuild case having USED the same `.rev` to reconstruct the
/// deleted volume first (research/RAR-PERF-AUDIT-2026-09-02.md round 43).
///
/// RAR 3.x `.rev` files carry the ORDINARY `Rar!\x1a\x07\x00` marker and
/// parse cleanly into a memberless archive, which the extract arm
/// already handles as its no-op `has_member == false` shape; only the
/// RAR5 spelling needed naming. Do not widen this to `.rev` by NAME -
/// obfuscated posts strip extensions, and the whole point of the
/// obfuscated arm is that names cannot be trusted.
pub fn rar_recovery_volume_magic(path: &std::path::Path) -> bool {
    nzbkit::headpeek::head(path).is_some_and(|h| h.starts_with(b"Rar!\x1aRev"))
}

/// Does the file start with the 7-Zip signature (`7z\xBC\xAF\x27\x1C`)?
pub fn sevenz_magic(path: &std::path::Path) -> bool {
    nzbkit::headpeek::head(path)
        .is_some_and(|h| h.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))
}

/// If `name` is a split 7-Zip part (`<base>.7z.<NNN>`), return the shared
/// base and the numeric part index.
pub fn split_7z_part(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    head.to_lowercase()
        .ends_with(".7z")
        .then(|| (head.to_string(), tail.parse().ok().unwrap_or(u32::MAX)))
}

/// The name grammar the RAR extract paths share: `.rar`/`.rNN` by name, or
/// a rollover (`.sNN`…) / numeric (`.001`) extension carrying the Rar!
/// magic. Factored out so obfuscation detection can ask the inverse.
pub fn looks_like_named_rar(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    let by_name = name.ends_with(".rar")
        || name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
        });
    let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
        let t = &name[p + 1..];
        (t.len() >= 3
            && (b's'..=b'z').contains(&t.as_bytes()[0])
            && t[1..].bytes().all(|c| c.is_ascii_digit()))
            || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
    });
    by_name || (rollover_or_numeric && rar_magic(path))
}

/// Is this single path a 7z container or one part of a split set? The
/// per-path twin of `rarfix::sevenz::collect_sevenz_archives`' grouping
/// grammar, for callers that ask about one file rather than scanning a
/// directory.
pub fn sevenz_archive_part(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    name.ends_with(".7z") || split_7z_part(&name).is_some() || sevenz_magic(path)
}

/// Does this file open with the `PAR2\0PKT` packet magic?
///
/// The one test that recognises an obfuscated recovery volume, whose name
/// carries nothing: the magic is unambiguous, no media container starts
/// with it, and it decides where the extension cannot. Three callers had
/// grown their own copy of these eight bytes; a fourth would have been
/// one too many, since the whole class of bug this answers (issue #9) is
/// a path that checked the NAME because the content test was somewhere
/// else. `smart::par2_magic` is the same test on the extraction side.
pub fn file_starts_with_par2_magic(path: &std::path::Path) -> bool {
    nzbkit::headpeek::head(path).is_some_and(|h| h.file_len >= 8 && h.starts_with(b"PAR2\x00PKT"))
}
