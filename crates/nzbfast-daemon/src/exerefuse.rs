//! Refuse executables in a completed media download (TODO 358 item 13,
//! Weaver parity, decision D2 in
//! `research/WEAVER-PARITY-PHASE0-2026-11-08.md` section 3).
//!
//! Weaver 0.15.0 fails ANY job holding one of ten executable
//! extensions, which also fails every software post. D2 kept the list
//! and the default-on, and narrowed the scope to the one the indexer's
//! junk rule M32 already draws: an executable riding a MEDIA-shaped
//! release is the malware shape, and a software release legitimately
//! ships one. So a job fails here only when its name or its category
//! reads as media, and software and unclassified jobs are left alone.
//!
//! The kind comes from the same classifier everything else uses
//! (`categories::classify`, which is `parse_release` plus the user's own
//! categories), and the exemption from `Kind::may_carry_executables`,
//! which is M32's scope stated once for both callers. What this module
//! adds is only what the indexer never needed: the job's CATEGORY, and
//! the narrowing that an unclassified (`Other`) name is not evidence of
//! media.
//!
//! Separate from `cleanup_exts` on purpose: that list DELETES files from
//! a successful job and says nothing; this one FAILS the job, so an *arr
//! sees Failed and re-grabs. The refused files are taken out of the
//! folder as well, the way the cleanup sweep takes its own, so an
//! executable is never left beside the media for anyone to open.

use super::*;
use nzbkit::categories::{BaseBehavior, CustomCategory};
use nzbkit::release::Kind;

/// Weaver's ten, in its order. `refuse_exts` starts as this list on a
/// fresh install; an empty list turns the check off.
pub const REFUSE_EXTS_DEFAULT: [&str; 10] = [
    "exe", "bat", "cmd", "com", "scr", "msi", "vbs", "ps1", "lnk", "js",
];

/// [`REFUSE_EXTS_DEFAULT`] as the owned list the daemon holds.
pub fn refuse_exts_default() -> Vec<String> {
    REFUSE_EXTS_DEFAULT.iter().map(|e| e.to_string()).collect()
}

/// The `refuse_exts` setter's parse: the cleanup list's own grammar
/// ("exe, .bat, *.cmd"), kept to bare extensions. A name pattern means
/// something on a DELETE list and nothing on this one, which matches a
/// file's extension and no more, so it is dropped rather than carried as
/// an entry that can never fire.
pub fn parse_refuse_exts(v: &str) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for e in crate::smart::parse_ext_list(v) {
        if !crate::smart::is_cleanup_pattern(&e) && !list.contains(&e) {
            list.push(e);
        }
    }
    list
}

/// Does a parsed NAME say media for this rule? M32's scope, minus
/// `Other`, and only with evidence.
///
/// The evidence is not optional: `parse_release` guesses `Movie` for any
/// readable words, so without it a job called "release" (which is what
/// an SFX self-extractor post is often called) was refused as a film.
/// `carries_media_evidence` is the indexer's own junk_v6 marker list,
/// the same one that scores an evidence-free "movie" as junk.
///
/// A user category counts by the base it DECLARED, as everywhere else a
/// custom kind's behaviour is decided (`categories::base_of`): a
/// movie-like or tv-like category is media, a category declared with no
/// base behaviour is not known to be. Its pattern matching the name is
/// evidence enough.
fn name_is_media(p: &nzbkit::release::Parsed, cats: &[CustomCategory]) -> bool {
    match &p.kind {
        Kind::Other => false,
        kind @ Kind::Custom(_) => matches!(
            nzbkit::categories::base_of(kind, cats),
            BaseBehavior::Movie | BaseBehavior::Tv
        ),
        k => !k.may_carry_executables() && p.carries_media_evidence(),
    }
}

/// Does a job CATEGORY name say media? Read word by word, so the *arr
/// spellings ("tv-sonarr", "Movies 4K", "radarr") count as well as the
/// shipped defaults (`tv`, `movies`, `music`, `books`). A category that
/// also names software ("pc-games") is not media, and `*` names nothing.
fn category_is_media(cat: &str) -> bool {
    const MEDIA: &[&str] = &[
        "movie",
        "movies",
        "film",
        "films",
        "tv",
        "series",
        "shows",
        "anime",
        "music",
        "audio",
        "audiobook",
        "audiobooks",
        "book",
        "books",
        "ebook",
        "ebooks",
        "comics",
        "sports",
        "sonarr",
        "radarr",
        "lidarr",
        "readarr",
        "whisparr",
    ];
    category_words(cat)
        .iter()
        .any(|w| MEDIA.contains(&w.as_str()))
        && !category_is_software(cat)
}

/// Does a job CATEGORY name software (`software`, `apps`, `pc-games`)?
/// The VETO over both halves of [`media_shaped`]: a software release
/// legitimately ships its own executable, so a job filed under one is
/// never refused, whatever its name parses as.
fn category_is_software(cat: &str) -> bool {
    const SOFTWARE: &[&str] = &["software", "apps", "app", "games", "game", "pc"];
    category_words(cat)
        .iter()
        .any(|w| SOFTWARE.contains(&w.as_str()))
}

/// A category name's words, lowercased, split on anything that is not a
/// letter or a digit.
fn category_words(cat: &str) -> Vec<String> {
    cat.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// Is this job media-shaped: does its NAME classify as media, or does
/// its CATEGORY name say so? Either is enough (D2's "name or category"),
/// unless the category names SOFTWARE, which vetoes both: a game or an
/// app with a year in its name (`Football.Manager.2024-RUNE`,
/// `TurboTax.2023`) parses as a film with year evidence, and refusing
/// the `setup.exe` it ships is the one outcome D2 rules out (pre-release
/// sweep, 9 Nov 2026).
pub fn media_shaped(name: &str, cat: &str, cats: &[CustomCategory]) -> bool {
    !category_is_software(cat)
        && (name_is_media(&nzbkit::categories::classify(name, cats), cats)
            || category_is_media(cat))
}

/// The sentence a refused job fails with, in the failure reasons' own
/// shape: what happened first, then why, then what was done about it.
fn refusal_message(found: &[PathBuf], removed: usize) -> String {
    let first = found
        .first()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let what = match found.len() {
        1 => format!("an executable ({first})"),
        n => format!("{n} executables ({first} and {} more)", n - 1),
    };
    let fate = match (found.len(), removed) {
        (_, 0) => "left in the download folder",
        (1, _) => "removed",
        (n, r) if r == n => "removed",
        _ => "partly removed",
    };
    format!(
        "refused: the download contains {what}, which a media release never ships - \
         likely malware, so it was {fate}"
    )
}

/// Ask the question of one finished payload. `Some(sentence)` = refuse:
/// the job is media-shaped, `refuse_exts` is not empty, and `dir` holds
/// at least one file it names; the files have been taken out of `dir`
/// by the time this returns. `None` = nothing to refuse, and nothing
/// was touched.
pub fn refuse_executables(d: &Daemon, dir: &Path, name: &str, cat: &str) -> Option<String> {
    let exts = d.refuse_exts.lock_ok().clone();
    if exts.is_empty() {
        return None;
    }
    let cats = d.custom_categories.read_ok().clone();
    if !media_shaped(name, cat, &cats) {
        return None;
    }
    let found = crate::smart::refused_files(dir, &exts);
    if found.is_empty() {
        return None;
    }
    let removed = crate::smart::remove_refused(dir, &found);
    let why = refusal_message(&found, removed);
    warn!(target: "queue", "{name:?}: {why}");
    Some(why)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_or_the_category_makes_a_job_media_shaped() {
        let none: &[CustomCategory] = &[];
        // Named as media, whatever the category.
        assert!(media_shaped(
            "The.Matrix.1999.1080p.BluRay.x264-GRP",
            "*",
            none
        ));
        assert!(media_shaped(
            "Show.Name.S01E02.1080p.WEB.h264-GRP",
            "",
            none
        ));
        // An obfuscated name says nothing, so the category decides.
        assert!(media_shaped("a8f3c9d2e1b04f6a9c7e", "movies", none));
        assert!(media_shaped("a8f3c9d2e1b04f6a9c7e", "tv-sonarr", none));
        assert!(!media_shaped("a8f3c9d2e1b04f6a9c7e", "*", none));
        // Bare words parse as a "movie" with no evidence, and are not
        // media: the daemon_sfx fixture's "release.nzb" is this case.
        assert!(!media_shaped("release", "*", none));
        assert!(!media_shaped("my holiday video", "", none));
        // Software is exempt by name (M32), and a software category
        // does not make an obfuscated job media.
        assert!(!media_shaped(
            "Some.Tool.v2.1.3.x64.Incl.Keygen-GRP",
            "*",
            none
        ));
        assert!(!media_shaped("a8f3c9d2e1b04f6a9c7e", "software", none));
        assert!(!media_shaped("a8f3c9d2e1b04f6a9c7e", "pc-games", none));
        // ...and a software category vetoes the NAME half too (pre-release
        // sweep, 9 Nov 2026). A game or an app with a year in its name
        // parses as a film with year evidence, so in a games or software
        // category its own `setup.exe` was deleted and the job failed -
        // the one refusal D2 says must never happen.
        for (name, cat) in [
            ("Football.Manager.2024-RUNE", "games"),
            ("TurboTax.2023.Deluxe", "software"),
            ("Football.Manager.2024-RUNE", "pc-games"),
            ("Some.App.2024.x64", "apps"),
        ] {
            assert!(!media_shaped(name, cat, none), "{name} in {cat}");
        }
        // The veto is the CATEGORY's: the same name filed as a film is
        // still refused, and so is a film name with no category at all.
        assert!(media_shaped("Football.Manager.2024-RUNE", "movies", none));
        assert!(media_shaped(
            "The.Matrix.1999.1080p.BluRay.x264-GRP",
            "",
            none
        ));
    }

    #[test]
    fn the_setter_keeps_bare_extensions_only() {
        assert_eq!(parse_refuse_exts("EXE, .bat, *.cmd"), ["exe", "bat", "cmd"]);
        assert!(parse_refuse_exts("").is_empty());
        assert_eq!(parse_refuse_exts("exe, *setup*"), ["exe"]);
    }

    #[test]
    fn the_reason_names_the_file_and_what_was_done() {
        let one = [PathBuf::from("/dl/x/setup.exe")];
        let m = refusal_message(&one, 1);
        assert!(m.starts_with("refused: the download contains an executable (setup.exe)"));
        assert!(m.ends_with("so it was removed"));
        let two = [PathBuf::from("/dl/x/a.exe"), PathBuf::from("/dl/x/b.lnk")];
        assert!(refusal_message(&two, 0).contains("2 executables (a.exe and 1 more)"));
        assert!(refusal_message(&two, 0).ends_with("left in the download folder"));
        // Copy rule: no em or en dash in a user-facing sentence.
        assert!(!m.contains(['\u{2014}', '\u{2013}']));
    }
}
