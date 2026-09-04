//! Release-name grammar: pure string functions over the name a release
//! was SUBMITTED under, with no disk and no state behind them.
//!
//! Here rather than in `smart`, which owns naming once the payload has
//! landed, because the askers span every layer: `diag` reads the
//! password convention out of an .nzb filename before anything has been
//! fetched, `newznab` folds indexer spellings of one release together
//! while searching, and the daemon does both. Leaving these two beside
//! the filing code had the lowest layer of the crate-split plan, and the
//! metadata one beside it, reaching up into the unpack layer for a
//! `to_lowercase` (step 1 of
//! research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md).
//!
//! `smart` re-exports both, so the filing code and its tests still spell
//! them the way they always did.

/// Archive-password conventions in a submitted NZB name, most explicit
/// first: `Name{{pw}}` (SAB/NZBGet), `Name password=pw`, `Name{pw}`
/// (single brace - some indexers). Returns (password, cleaned name);
/// the wrapper ALWAYS comes off the name so a password never leaks into
/// the display name or the output folder.
pub fn name_password(name: &str) -> Option<(String, String)> {
    if let (Some(a), Some(b)) = (name.find("{{"), name.rfind("}}"))
        && b > a + 2
    {
        let pw = name[a + 2..b].to_string();
        let clean = format!("{}{}", &name[..a], &name[b + 2..])
            .trim()
            .to_string();
        return Some((pw, clean));
    }
    if let Some(i) = name.to_ascii_lowercase().find("password=") {
        let pw = name[i + 9..].trim().trim_end_matches('}').to_string();
        if !pw.is_empty() {
            let clean = name[..i]
                .trim_end_matches(['{', ' ', '.', '-', '_'])
                .trim()
                .to_string();
            return Some((pw, clean));
        }
    }
    if let (Some(a), Some(b)) = (name.find('{'), name.rfind('}'))
        && b > a + 1
    {
        let pw = &name[a + 1..b];
        if !pw.is_empty() && !pw.contains(['{', '}']) {
            let clean = format!("{}{}", &name[..a], &name[b + 1..])
                .trim()
                .to_string();
            return Some((pw.to_string(), clean));
        }
    }
    None
}

// Written in `job_dupe.rs`, moved to `smart::episode` by TODO 276
// item 3 (reducing a release name to its identity key is what naming is
// for, and the duplicate check is only one of its callers), and moved
// down here by the crate-split prep for the reason in the module note
// above - `newznab` is one of those callers and sits in a sibling layer.
/// Reduce a release name to its bare letter/digit sequence, lowercased,
/// with every separator and decoration collapsed to a single space.
///
/// Unicode-aware, and that is the whole point: an ASCII-only filter
/// erased every non-Latin letter, so `電影甲.2024.1080p.WEB-DL.x264-GRP`
/// and `電影乙.2024.1080p.WEB-DL.x264-GRP` reduced to the SAME key and
/// collided as duplicates, while an all-CJK name reduced to the empty
/// string - an identity so unspecific that the exact-duplicate check
/// has to refuse it, so a genuine re-send of that release was admitted
/// as new (Codex sweep J, 13 Aug 2026). ASCII names flatten exactly as
/// they always did; `to_lowercase` differs from `to_ascii_lowercase`
/// only on characters the old filter was deleting anyway.
pub fn flatten_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect()
}
