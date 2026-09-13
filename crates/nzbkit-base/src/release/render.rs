//! The other direction: turning a [`super::Parsed`] back into text a
//! human reads - the quality badge, the style-driven suffix, the
//! path-safe movie base name, and the two separator rules underneath it.
//! Nothing here parses; everything here formats.
//!
//! Cut out of `release.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,391 of the size gate's 4,000-line file ceiling. Verbatim move; the
//! public items keep their `release::` paths through the `pub use` beside
//! the `mod` declaration, so no caller changes.

use super::*;

/// Short quality label for card badges: "2160p REMUX", "1080p WEB", …
pub fn quality_label(p: &Parsed) -> String {
    let mut s = p.res.clone().unwrap_or_default();
    if p.remux {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str("REMUX");
    } else if let Some(src) = &p.source {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(src);
    }
    s
}

// ---------------------------------------------------------------------------
// Friendly-name builder (auto-rename): reassemble a clean, informative name
// from the parsed facts. Shared so downloader and indexer name alike.
// ---------------------------------------------------------------------------

/// Which quality facts a friendly name should carry. Title + year are
/// always present; each of these is an independent user toggle.
#[derive(Debug, Clone, Copy, Default)]
pub struct NameStyle {
    pub resolution: bool,
    pub video_codec: bool,
    pub audio_codec: bool,
    /// Source medium (BluRay/WEB/…) or REMUX.
    pub source: bool,
    /// Trailing release-group tag ("-FGT").
    pub group: bool,
    /// Wrap the year in parentheses: "Title (1999)" rather than
    /// "Title 1999". Off by default. Note that "Title (Year)" is the
    /// folder shape Plex, Jellyfin and Radarr match against, so anyone
    /// feeding a media server usually wants this on.
    pub year_parens: bool,
    /// Wrap the quality facts in square brackets: "… [1080p x265]" rather
    /// than "… 1080p x265". Off by default.
    pub quality_brackets: bool,
    /// Carry the words the parser did not recognise into the name, so
    /// releases that differ only in those words stay distinguishable:
    /// "Formula1 2026 Round11 Hungary Race" and "… Hungary Qualifying"
    /// rather than two folders both called "Formula1 (2026)".
    ///
    /// Only ever adds words to a name we would otherwise DECLINE to
    /// build (see movie_name) - it cannot reshape a film that already
    /// names cleanly, because a film that parses cleanly leaves nothing
    /// in `extra`.
    pub extra_words: bool,
}

/// Quality suffix built from the style-enabled facts, e.g.
/// " [1080p x265 DTS-HD]" (or " 1080p x265 DTS-HD" without
/// `style.quality_brackets`), plus a "-GROUP" tail when `style.group`.
/// Empty string when nothing is enabled or nothing is known - the caller
/// appends it directly to a base name.
pub fn quality_suffix(p: &Parsed, style: &NameStyle) -> String {
    let mut parts: Vec<String> = Vec::new();
    if style.resolution
        && let Some(r) = &p.res
    {
        parts.push(r.clone());
    }
    if style.source {
        if p.remux {
            parts.push("REMUX".to_string());
        } else if let Some(s) = &p.source {
            parts.push(s.clone());
        }
    }
    if style.video_codec
        && let Some(v) = &p.vcodec
    {
        parts.push(v.clone());
    }
    if style.audio_codec
        && let Some(a) = &p.acodec
    {
        parts.push(a.clone());
    }
    let mut out = String::new();
    if !parts.is_empty() {
        out.push(' ');
        if style.quality_brackets {
            out.push('[');
        }
        out.push_str(&parts.join(" "));
        if style.quality_brackets {
            out.push(']');
        }
    }
    if style.group
        && let Some(g) = &p.group
    {
        out.push_str(&format!("-{g}"));
    }
    out
}

/// Friendly base name (no extension) for a movie / loose file:
/// "The Matrix (1999)" plus the style suffix. Path-safe. Returns None when
/// there's nothing better to offer than the original - an obfuscated /
/// unparseable stem, or an empty title.
pub fn movie_name(p: &Parsed, style: &NameStyle) -> Option<String> {
    if p.kind == Kind::Other {
        return None;
    }
    let title = p.title.trim();
    if title.is_empty() {
        return None;
    }
    // A release whose identity lives AFTER the year is not a film with a
    // release date - it is one event in a season ("Formula1.2026.Round11.
    // Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p…"). Reducing it to
    // "Title (Year)" renames every round and every session of the year to
    // the same string, which collides on disk.
    //
    // The words that tell those apart are sitting right there in `extra`
    // - "Round11 Hungary Race" vs "Round11 Hungary Qualifying" - so with
    // extra_words on we keep them and the collision never arises. With it
    // off we decline as before and the poster's own name survives, which
    // is the safer default for anyone who does not want tokens the parser
    // failed to understand appearing in their filenames.
    //
    // Note this arm cannot touch an ordinary film: a film that parses
    // cleanly leaves `extra` EMPTY (measured across editions, cuts, AKA
    // titles, foreign-language and scene-noise shapes), so everything
    // below only ever fires on releases we would otherwise refuse to
    // name at all.
    let mut extra = String::new();
    if !p.extra.is_empty() {
        match extra_words(p) {
            // Either the option is off, or nothing presentable survived
            // the filter and we would be back to the bare colliding
            // "Title (Year)". Both mean: leave it as the poster named it.
            Some(w) if style.extra_words => extra = w,
            _ => return None,
        }
    }
    let suffix = quality_suffix(p, style);
    // Only rename when there's an anchor that makes the name more
    // informative - a year (the hallmark of a real movie post), at least
    // one enabled quality fact, or the event words we just kept. A bare,
    // yearless, quality-less stem ("somefile") could be anything; leave
    // it as the poster named it.
    if p.year.is_none() && suffix.is_empty() && extra.is_empty() {
        return None;
    }
    let mut base = match p.year {
        Some(y) if style.year_parens => format!("{title} ({y})"),
        Some(y) => format!("{title} {y}"),
        None => title.to_string(),
    };
    if !extra.is_empty() {
        base.push(' ');
        base.push_str(&extra);
    }
    base.push_str(&suffix);
    // Nothing nameable survived sanitisation (a title that was all
    // punctuation): decline, as everywhere else here, so the poster's own
    // name stands rather than a placeholder.
    let name = sanitize_name(&base);
    if name.is_empty() { None } else { Some(name) }
}

/// The unrecognised words of a release, filtered down to what is worth
/// putting in a filename, or None if nothing is.
///
/// "Not a codec or a format" needs no list here: anything the parser
/// recognised as resolution, codec, source, language, edition or group
/// was consumed into a typed field and never reaches `extra`. What is
/// left is the release's own vocabulary - "Round11", "Hungary", "Race",
/// "Chiefs", "vs", "Sinner" - plus the occasional scrap. So this filters
/// for presentability rather than meaning: no dictionary, because the
/// useful words here are overwhelmingly proper nouns, event jargon and
/// numbered rounds that no dictionary contains.
pub(super) fn extra_words(p: &Parsed) -> Option<String> {
    /// Enough to tell two events apart without rebuilding the whole
    /// release name; past this a post is padding, not describing.
    const MAX_WORDS: usize = 6;
    const MAX_LEN: usize = 24;

    let group = p.group.as_deref().unwrap_or_default();
    let mut out: Vec<&str> = Vec::new();
    for w in &p.extra {
        let w = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if w.is_empty() || w.len() > MAX_LEN {
            continue;
        }
        // The group already has its own opt-in tag; don't duplicate it.
        if !group.is_empty() && w.eq_ignore_ascii_case(group) {
            continue;
        }
        if w.chars().all(|c| c.is_ascii_digit()) {
            // Short bare numbers are half of an event's identity ("03"
            // in "Week 03", "311" in a UFC card), so keep them - but
            // NOT via looks_obfuscated, which judges whole stems and
            // rightly calls any letterless string unpresentable. A long
            // bare number is a size, a date fragment or an id.
            if w.len() > 4 {
                continue;
            }
        } else if looks_obfuscated(w) {
            // A hash or a scrambled blob describes nothing.
            continue;
        }
        out.push(w);
        if out.len() == MAX_WORDS {
            break;
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join(" "))
}

/// Spell a colon out as a separator instead of losing it. A colon is
/// illegal on Windows and carries path meaning there, but in a title it
/// is doing real work ("Alien: Romulus", "Dune: Part Two"), and blanking
/// it to a space read as two titles run together. The convention every
/// library uses: ": " becomes " - ", a bare ":" becomes "-".
pub(super) fn expand_colons(t: &str) -> String {
    let mut out = String::with_capacity(t.len() + 2);
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ':' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&' ') {
            chars.next();
            out.push_str(" - ");
        } else {
            out.push('-');
        }
    }
    out
}

/// Collapse a separator run that colon expansion doubled up ("Title - -
/// Sub", "Title--Sub") back down to one. Only runs of TWO OR MORE hyphens
/// are touched, so a hyphenated word ("Spider-Man") and an ordinary
/// " - " are left exactly as they were.
pub(super) fn collapse_separators(t: &str) -> String {
    let chars: Vec<char> = t.chars().collect();
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '-' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        let (mut hyphens, mut spaced) = (0, false);
        while i < chars.len() && (chars[i] == '-' || chars[i] == ' ') {
            if chars[i] == '-' {
                hyphens += 1;
            } else {
                spaced = true;
            }
            i += 1;
        }
        if hyphens < 2 {
            out.extend(&chars[start..i]);
        } else if spaced {
            out.push_str(" - ");
        } else {
            out.push('-');
        }
    }
    out
}

/// Strip path-hostile characters and collapse whitespace for a file/dir
/// name. Keeps brackets/parens (used by the quality suffix).
///
/// The result then goes through the same strong guarantees enqueue-time
/// folder naming uses ([`crate::disk::sanitize_filename`]), with the
/// Windows rules forced ON regardless of host: a finished tree gets moved
/// to a NAS/SMB share, so a leading dot (hidden), a trailing dot (silently
/// truncated) or a reserved device stem ("CON") is a problem everywhere,
/// not just on a Windows box. Without this, stage 4 could emit names that
/// enqueue-time naming had already been fixed to reject.
///
/// Returns an EMPTY string when nothing nameable survives, so callers
/// decline rather than emit `sanitize_filename`'s "unnamed" placeholder or
/// a bare-dot component.
pub fn sanitize_name(t: &str) -> String {
    let expanded = collapse_separators(&expand_colons(t));
    let mapped: String = expanded
        .chars()
        .map(|c| if "/\\:*?\"<>|".contains(c) { ' ' } else { c })
        .collect();
    let collapsed = mapped.split_whitespace().collect::<Vec<_>>().join(" ");
    // A colon at the very start or end leaves a dangling separator behind.
    let collapsed = collapsed
        .trim_start_matches("- ")
        .trim_end_matches(" -")
        .trim();
    // A leading dot is TITLE noise, and dropping it belongs here rather
    // than in the sanitizer. `sanitize_filename_for` stopped deleting
    // leading dots on 30 Aug 2026 (M4-66) because doing so folded two
    // DECLARED member names - `.movie.mkv` and `movie.mkv` - onto one
    // on-disk name, and a declared name is an identity the sanitizer may
    // not quietly discard; it maps the dots to `_` instead. Nothing in
    // this function is a declared name. `t` is a release TITLE - an NZB
    // subject, a spot, a poster's typed line - being turned into
    // something a human wants to read, so `.Hidden Movie (2024)` should
    // name a folder `Hidden Movie (2024)` and not `_Hidden Movie (2024)`.
    // Two different questions, answered in the two different places that
    // own them.
    let collapsed = collapsed.trim_start_matches('.').trim_start();
    if !collapsed.chars().any(|c| c.is_alphanumeric()) {
        return String::new();
    }
    crate::disk::sanitize_filename_for(collapsed, true)
}
