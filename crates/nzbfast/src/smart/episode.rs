//! What a filed TV episode is CALLED, and how to recognise one on disk.
//!
//! One subject, in three layers. `tv_path` turns a release stem into the
//! filing target (`Show/Season 03` plus `Show - S03E05`), and
//! `legacy_tv_path` computes what the builds before the strong sanitiser
//! wrote, because a library filed by one of those is still on disk.
//! `FiledTail`, `EpisodeTitles` and `filed_title_segment` are the
//! vocabulary of the tail that follows the base - the episode title and
//! the quality suffix - with the length-fitting that keeps a name inside
//! a filesystem component. `filed_bases`, `is_filed_episode_file`,
//! `find_filed_episode_media` and `delete_filed_episode` are the other
//! direction: given a stem and the tail the job recorded, which files in
//! a SHARED season folder are this episode's, so Play and
//! delete-with-files act on the right ones and nothing else.
//!
//! The three layers travel together because ownership of a name is
//! decided by the whole of it: a delete that knew only the suffix half
//! matched nothing once a title was in the name, which silently turned
//! "delete this episode" into a no-op.
//!
//! What the rename/file PASS does with all this - `tv_organize`,
//! `tv_rename` and the three name-giving doors - is filing.rs beside it;
//! that module's header used to say this vocabulary "stays in the
//! parent", which was true until smart.rs ran out of headroom again.
//!
//! Split out of smart.rs for the size gate (TODO 106); every public and
//! crate-visible door is re-exported from the parent, so no caller
//! spells a new path.

use std::path::{Path, PathBuf};

use tracing::warn;

use super::{Removed, VIDEO_EXTS, delete_to_trash, ext_of, is_real_file, remove_user_file};

/// TV filing target for a release stem, from wall.rs's parser:
/// subdirectory ("The Bear/Season 03") plus, when a specific episode is
/// known, the rename base ("The Bear - S03E05"). None = not confidently
/// TV (movies, obfuscated names, unknown season) - the job stays where it
/// landed rather than being mis-filed.
///
/// A daily show carries no season/episode numbers at all, only the air
/// date ("The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP"), and requiring a
/// season left every one of them unfiled and unrenamed. Their identity IS
/// the date, so they file under `Show/Season YYYY` as
/// `Show - YYYY.MM.DD` - the convention Sonarr and every library reads
/// back. Only a date that survives [`nzbkit::release::air_date_parts`]
/// counts, and a title that reads as a hash is refused outright: the
/// parser's `daily` flag fires on any 8-digit run, which is enough to
/// say "not a movie" but not enough to write a name with.
pub fn tv_path(stem: &str) -> Option<(String, Option<String>)> {
    tv_path_as(stem, sanitize)
}

/// [`tv_path`] as the builds before the strong sanitiser computed it:
/// the show's path-hostile glyphs blanked to a space and nothing else,
/// so a colon left "Star Trek Discovery" where today it leaves
/// "Star Trek - Discovery".
///
/// A library filed by one of those builds is still on disk under the old
/// spelling, and both the delete and the play path RECOMPUTE the base
/// from the stem at call time - so without this an episode filed last
/// week stopped being recognised as its own job's file: delete-with-files
/// removed nothing and Play reported no playable file. Filing consults it
/// too, or the same show would start a second tree beside the first.
pub(super) fn legacy_tv_path(stem: &str) -> Option<(String, Option<String>)> {
    tv_path_as(stem, legacy_sanitize)
}

fn tv_path_as(stem: &str, show_of: impl Fn(&str) -> String) -> Option<(String, Option<String>)> {
    let p = crate::wall::parse_release(stem);
    if p.kind != crate::wall::Kind::Tv {
        return None;
    }
    let show = show_of(&p.title);
    if show.is_empty() {
        return None;
    }
    let Some(season) = p.season.filter(|&s| s > 0) else {
        if title_is_unpresentable(&p.title) {
            return None;
        }
        let (year, air) = nzbkit::release::air_date_parts(p.date.as_deref()?)?;
        return Some((
            format!("{show}/Season {year}"),
            Some(format!("{show} - {air}")),
        ));
    };
    let dir = format!("{show}/Season {season:02}");
    // Multi-episode posts keep the whole range in the filed name
    // ("Show - S01E01-E02") so the second episode isn't silently
    // dropped from the library.
    let base = p.episode.map(|e| match p.episode2 {
        Some(e2) => format!("{show} - S{season:02}E{e:02}-E{e2:02}"),
        None => format!("{show} - S{season:02}E{e:02}"),
    });
    Some((dir, base))
}

// ---------------------------------------------------------------------------
// Episode titles in TV names (TODO 78) - the last *arr rename parity piece.
// ---------------------------------------------------------------------------

/// What TV filing wrote after the episode base, as the job recorded it at
/// the moment it wrote it: the episode-title segment (`" - Children"`,
/// empty unless the `rename_episode_titles` setting was on AND the cache
/// knew the title) and the quality suffix (`" [1080p]"`).
///
/// The two travel together because ownership of a name inside a SHARED
/// season folder is decided by the WHOLE tail - see
/// [`is_filed_episode_file`]. A delete that knew only the suffix half
/// matched nothing at all once a title was in the name, which silently
/// turned "delete this episode" and "play this episode" into no-ops.
///
/// A struct rather than two more `&str` parameters for the reason
/// [`crate::serve::FinalizeJob`] is one: they are the same type, and a
/// caller that swapped them would have compiled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FiledTail {
    pub title: String,
    pub suffix: String,
}

impl FiledTail {
    /// The quality suffix alone - every filed job carried exactly this
    /// before episode titles existed, and a record written back then
    /// still means it.
    ///
    /// Tests only: production builds this from the job record, where the
    /// title half comes from the same place and cannot be forgotten.
    #[cfg(test)]
    pub fn suffix(suffix: &str) -> Self {
        Self {
            title: String::new(),
            suffix: suffix.to_string(),
        }
    }

    pub(crate) fn lowered(&self) -> Self {
        Self {
            title: self.title.to_ascii_lowercase(),
            suffix: self.suffix.to_ascii_lowercase(),
        }
    }
}

/// Bytes one path component gets on every filesystem this lands on -
/// ext4, APFS, NTFS, and the SMB/NFS shares `move_completed` writes to.
pub(super) const COMPONENT_BYTES: usize = 255;

/// Room held back from [`COMPONENT_BYTES`] for the extension chain, so
/// the title's budget depends only on the episode base and the quality
/// suffix.
///
/// It has to. The title is RECORDED ([`FiledTail`]) and later matched
/// literally, while the extension differs between files of one episode -
/// a `.mkv` feature beside its `.en.srt`. Budgeting against the real
/// extension would truncate the two differently and the record could
/// only hold one of the answers.
const EXT_RESERVE: usize = 16;

/// How many episodes one post may claim before we stop collecting titles
/// for it. A double or triple is ordinary; a range in the dozens is a
/// season pack wearing an episode's clothes, and joining 24 titles
/// produces a name that is all truncation and no information.
const MAX_EP_SPAN: u32 = 8;

/// The separator between the episode base and its title, which is
/// Sonarr's default and what Plex, Jellyfin and Emby read back.
pub(super) const TITLE_SEP: &str = " - ";

/// Episode titles for ONE show, read out of the enrichment cache before
/// any renaming starts.
///
/// Cache-only by construction: this owns its answers already, so no
/// rename can reach the network however obscure the show is or however
/// long the job runs. That is the house rule stated in `tasks.rs` -
/// network lives on the enricher threads - and it is also why a cache
/// miss simply produces the name we produced before this existed, rather
/// than a deferred second rename. A rename that lands after an *arr has
/// imported the file breaks the import (memory `nzbfast-auto-rename`).
///
/// Empty is the ordinary case, and means every name below is
/// byte-identical to what it was.
#[derive(Clone, Debug, Default)]
pub struct EpisodeTitles {
    by_num: std::collections::HashMap<(u32, u32), String>,
}

impl EpisodeTitles {
    /// Build from `(season, episode, title)` triples - the shape
    /// `wall::EpInfo` carries out of the `eplist:*` cache blob. Blank
    /// titles are dropped here so no caller has to test for them.
    pub fn new(eps: impl IntoIterator<Item = (u32, u32, String)>) -> Self {
        Self {
            by_num: eps
                .into_iter()
                .filter(|(_, _, name)| !name.trim().is_empty())
                .map(|(s, e, name)| ((s, e), name))
                .collect(),
        }
    }

    /// The `" - Episode Title"` segment for a release stem, ready to sit
    /// between `base` and `suffix`, or an empty string when there is no
    /// title to write.
    ///
    /// `base` and `suffix` are passed only for their LENGTH: the finished
    /// component has to fit a filesystem name, and the title is the part
    /// that gives way (the base identifies the episode and the suffix
    /// tells one release from another - neither can be shortened without
    /// breaking something).
    pub fn segment(&self, stem: &str, base: &str, suffix: &str) -> String {
        if self.by_num.is_empty() {
            return String::new();
        }
        let Some((season, ep, ep2)) = confident_episode(stem) else {
            return String::new();
        };
        let Some(joined) = self.joined(season, ep, ep2) else {
            return String::new();
        };
        // The same strong, colon-aware sanitiser the show name gets: a
        // title arrives from a third party and can hold anything a
        // human typed, including "/" and a trailing dot.
        let title = nzbkit::release::sanitize_name(&joined);
        if title.is_empty() {
            return String::new();
        }
        let spent = base.len() + TITLE_SEP.len() + suffix.len() + EXT_RESERVE;
        let title = fit_title(&title, COMPONENT_BYTES.saturating_sub(spent));
        if title.is_empty() {
            return String::new();
        }
        format!("{TITLE_SEP}{title}")
    }

    /// Every title this post covers, as one string.
    ///
    /// Sonarr's conventions, because the libraries downstream were built
    /// against them: distinct titles join with `" + "`, and a post that
    /// covers both halves of a two-parter collapses to the shared stem
    /// ("The Ceremony (1)" + "The Ceremony (2)" -> "The Ceremony")
    /// rather than repeating it. Episodes the cache doesn't know are
    /// skipped, so a partly-known double still gets the title it has.
    fn joined(&self, season: u32, ep: u32, ep2: Option<u32>) -> Option<String> {
        let last = ep2
            .filter(|&e2| e2 > ep)
            .unwrap_or(ep)
            .min(ep.saturating_add(MAX_EP_SPAN - 1));
        let titles: Vec<&str> = (ep..=last)
            .filter_map(|e| self.by_num.get(&(season, e)))
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .collect();
        let first = *titles.first()?;
        // Part collapse. Judged on ALL of them, and only when what is
        // left still says something: a two-parter titled bare "Part 1" /
        // "Part 2" strips to nothing, and joining those is the honest
        // answer.
        if titles.len() > 1 {
            let stem = strip_part_marker(first);
            if !stem.is_empty()
                && titles
                    .iter()
                    .all(|t| strip_part_marker(t).eq_ignore_ascii_case(stem))
            {
                return Some(stem.to_string());
            }
        }
        let mut out: Vec<&str> = Vec::with_capacity(titles.len());
        for t in titles {
            if !out.iter().any(|seen| seen.eq_ignore_ascii_case(t)) {
                out.push(t);
            }
        }
        Some(out.join(" + "))
    }
}

/// The episode-title segment filing wrote for a job's OWN episode, which
/// is what [`FiledTail`] has to record so a later delete or play can find
/// the file again.
///
/// Computed from the same inputs `tv_organize` computes it from, so for
/// the single-episode jobs that ownership matching applies to at all it
/// is the same string. (A season pack has no single episode base -
/// [`filed_bases`] is empty for one - so it never reaches a matcher.)
///
/// One seam is deliberately not chased: a show still filed under a
/// PRE-sanitiser folder name ([`legacy_tv_path`]) has a base of a
/// different length, so a title long enough to be truncated could be
/// truncated by one word more or less there. The consequence is a name
/// this stops recognising, which leaves a file behind - the cheap
/// mistake this whole matcher exists to prefer.
pub fn filed_title_segment(stem: &str, suffix: &str, titles: &EpisodeTitles) -> String {
    match tv_path(stem) {
        Some((_, Some(base))) => titles.segment(stem, &base, suffix),
        _ => String::new(),
    }
}

/// The season and episode numbers behind a release stem, but only when
/// [`tv_path`] would also have built a specific episode base from it.
///
/// Kept in step with `tv_path_as`'s confident arm on purpose: a title may
/// only ever decorate a name that already names one episode. A dated
/// show (no season, no number) is deliberately excluded - the cache is
/// keyed by season and number, and matching one by airdate is the
/// separate piece of work TODO 78 records as a follow-up.
fn confident_episode(stem: &str) -> Option<(u32, u32, Option<u32>)> {
    let p = crate::wall::parse_release(stem);
    if p.kind != crate::wall::Kind::Tv {
        return None;
    }
    let season = p.season.filter(|&s| s > 0)?;
    Some((season, p.episode?, p.episode2))
}

/// A title with its trailing part marker removed: "The Ceremony (2)",
/// "The Ceremony: Part 2", "The Ceremony, Part Two" all reduce to "The
/// Ceremony". Returns the title unchanged when it carries no marker.
///
/// Only a marker at the END counts, and only a recognised NUMBER after
/// the word: "Part of the Plan" and "Parting Shot" are titles, not
/// halves of one.
fn strip_part_marker(title: &str) -> &str {
    let s = title.trim_end();
    // "The Ceremony (2)"
    if let Some(body) = s.strip_suffix(')')
        && let Some(open) = body.rfind('(')
        && is_part_number(&body[open + 1..])
    {
        return trim_marker_sep(&body[..open]);
    }
    // "The Ceremony: Part 2" and every separator it is written with.
    // `to_ascii_lowercase` preserves byte length, so the offset it finds
    // indexes the original.
    let lower = s.to_ascii_lowercase();
    if let Some(at) = lower.rfind("part ")
        && is_part_number(&s[at + "part ".len()..])
    {
        return trim_marker_sep(&s[..at]);
    }
    s
}

fn trim_marker_sep(s: &str) -> &str {
    s.trim_end().trim_end_matches([':', '-', ',']).trim_end()
}

/// Does this read as a part number - "2", "Two", "II"? Closed lists, not
/// a parser: everything it accepts is a word we DELETE from the user's
/// filename, so a false positive costs information that was in the title.
fn is_part_number(tok: &str) -> bool {
    let t = tok.trim();
    if !t.is_empty() && t.len() <= 3 && t.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    matches!(
        t.to_ascii_lowercase().as_str(),
        "one" | "two" | "three" | "four" | "five" | "six" | "i" | "ii" | "iii" | "iv" | "v" | "vi"
    )
}

/// Cut a title down to `room` BYTES at a word boundary, or to nothing
/// when no useful piece of it fits.
///
/// Bytes, not characters: the limit filesystems enforce is on the encoded
/// name, and a Cyrillic or Japanese title spends two or three bytes per
/// character. Never splits a UTF-8 sequence, and prefers a whole-word cut
/// so the result reads as a shortened title rather than as damage.
fn fit_title(title: &str, room: usize) -> String {
    if title.len() <= room {
        return title.to_string();
    }
    // Longest prefix inside the budget that is also a character boundary.
    let mut end = room.min(title.len());
    while end > 0 && !title.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &title[..end];
    // Back off to the last word boundary, unless that would leave a
    // fragment too short to say anything - a single word longer than the
    // whole budget is better cut mid-word than dropped.
    let at_word = cut.rfind(' ').unwrap_or(0);
    let kept = if at_word * 2 >= end {
        &cut[..at_word]
    } else {
        cut
    };
    // Truncation can expose a trailing separator or a dot, which is what
    // `sanitize_name` had already removed from the end of the full title.
    kept.trim_end()
        .trim_end_matches([',', ':', ';', '-', '_', '.', '('])
        .trim_end()
        .to_string()
}

/// Delete the file(s) a completed job was TV-filed to, WITHOUT touching
/// the shared `Show/Season NN` directory or any sibling episode.
///
/// After TV filing a job's `out_dir` is the shared season folder, so
/// `remove_dir_all` on it wipes the whole season (bug sweep: an "upgrade"
/// or a history "delete files" destroyed every episode). We instead match
/// only files whose name begins with this release's episode-unique base
/// (`Show - S03E05.`), which catches the renamed video and any sidecar
/// sharing that stem (see [`is_rename_tail`] for the sidecars it can't
/// reach) but never a sibling - E06's files begin `Show - S03E06.`.
///
/// The episode base alone is NOT release-specific: an upgrade files the
/// better copy into the same season folder under the same
/// `Show - S03E05` base, differing only in the quality suffix
/// [`tv_organize`] appended. Matching on the base plus ANY rename tail is
/// therefore quality-blind, and deleting the superseded copy took the
/// freshly-downloaded replacement with it - the user ended up with
/// neither. `suffix` is THIS release's [`nzbkit::release::quality_suffix`]
/// (recomputed by the caller from the job's own stem and the live
/// NameStyle, exactly as filing computed it), and the tail must begin with
/// it before any of the checks below run. An empty `suffix` means
/// auto-rename was off, so the base alone is all filing had - today's
/// behaviour.
///
/// Returns how many files went, and the first refusal if any (see
/// [`FiledDelete`]). Removes 0 (a deliberate no-op, never a broad delete)
/// when the episode can't be identified confidently - a release that
/// didn't parse as a specific episode, or a filed name that didn't follow
/// the rename (season-pack / collision fallback / a suffix that no longer
/// matches because the naming settings changed).
pub fn delete_filed_episode(dir: &Path, stem: &str, tail: &FiledTail) -> FiledDelete {
    let bases = filed_bases(stem);
    if bases.is_empty() {
        return FiledDelete::default();
    }
    // Read once, for the whole delete: see `remove_user_file`.
    // Inline rather than parked with the sweeps' deferred worker ON
    // PURPOSE: this deletes inside the user's LIBRARY, where a hidden
    // staging folder is not ours to create - and it is one file, bounded
    // by TRASH_DEADLINE plus the latch.
    let recoverable = delete_to_trash();
    let tail_lower = tail.lowered();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return FiledDelete::default();
    };
    let mut out = FiledDelete::default();
    // Optimistic until the first removal, then only as strong as the
    // weakest one: a set of files where some reached a Trash and some
    // did not is not recoverable, and saying so would send the user
    // looking for a file that is not there.
    let mut all_trashed = true;
    let mut any_removed = false;
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if is_filed_episode_file(&name, &bases, &tail_lower) {
            match remove_user_file(&path, recoverable) {
                Ok(how) => {
                    out.removed += 1;
                    any_removed = true;
                    all_trashed &= how == Removed::Trashed;
                }
                Err(e) => {
                    warn!(target: "smart", "delete filed {}: {e}", path.display());
                    // First refusal only: they all carry the same reason
                    // (one volume, one Trash), and the caller shows this
                    // to a person rather than listing every file.
                    out.kept.get_or_insert_with(|| e.to_string());
                }
            }
        }
    }
    out.removed_as = if any_removed && all_trashed {
        Removed::Trashed
    } else {
        Removed::Gone
    };
    out
}

/// What one [`delete_filed_episode`] managed to do.
///
/// The count alone was enough while a failed delete could only be a
/// permanent-delete error nobody could act on. Now a recoverable delete
/// the Trash refuses LEAVES the episode in the user's library (see
/// [`remove_user_file`]) while its History row goes, so the reason has to
/// travel back to whoever can put it in front of them.
pub struct FiledDelete {
    /// How many files were removed.
    pub removed: usize,
    /// Why at least one file is still in the library, when one is.
    pub kept: Option<String>,
    /// What the removals actually were. `Gone` unless EVERY one of them
    /// was verified into a Trash: a mixed outcome must not be reported
    /// as recoverable, because the half the user goes looking for may be
    /// the half that is not there.
    pub removed_as: Removed,
}

impl Default for FiledDelete {
    fn default() -> Self {
        FiledDelete {
            removed: 0,
            kept: None,
            // Nothing was removed, so there is nothing to promise back.
            removed_as: Removed::Gone,
        }
    }
}

// Moved here from `serve/job_dupe.rs` by TODO 276 item 3: reducing a
// release name to its identity key is what this module is for, and the
// duplicate check is only one of its two callers.
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
pub(crate) fn flatten_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect()
}

/// Every spelling of this release's filed episode base, ASCII-lowercased:
/// the one filing would write today, plus the one an older build wrote
/// for the same release when the show name reshapes (see
/// [`legacy_tv_path`]). Empty when the stem doesn't name one episode.
pub(crate) fn filed_bases(stem: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(2);
    for path in [tv_path(stem), legacy_tv_path(stem)] {
        if let Some((_, Some(base))) = path {
            let base = base.to_ascii_lowercase();
            if !out.contains(&base) {
                out.push(base);
            }
        }
    }
    out
}

/// Does `name` belong to the release filed under one of `bases` with
/// `tail`?
///
/// The one rule that decides ownership inside a SHARED season folder, so
/// both the delete ([`delete_filed_episode`]) and the play
/// ([`find_filed_episode_media`]) paths ask it rather than each carrying
/// their own idea of "this job's file": match "Show - S03E05", then the
/// episode title THIS job wrote (when it wrote one), then THIS release's
/// own quality suffix, then only a tail our own rename can produce -
/// never another quality of the same episode, a sibling ("…E06"), a
/// longer episode number ("…E050"), or the user's own Sonarr/Plex file.
///
/// The title is matched LITERALLY, from the job's own record of what it
/// wrote ([`FiledTail`]), never recomputed: the cache behind it is
/// refreshed every 12 hours and a provider that re-spells an episode
/// would otherwise re-point this at a file that no longer exists - or,
/// worse, at a neighbouring one. A record that carries no title (every
/// job filed before this existed, and every job filed with the setting
/// off) leaves this exactly as it was.
///
/// All arguments arrive ASCII-lowercased.
pub(crate) fn is_filed_episode_file(name: &str, bases: &[String], tail_lower: &FiledTail) -> bool {
    /// An empty part of the tail matches without consuming anything -
    /// which is what makes "no title recorded" mean "as it was before".
    fn strip<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        if prefix.is_empty() {
            Some(s)
        } else {
            s.strip_prefix(prefix)
        }
    }
    bases.iter().any(|base_lower| {
        name.strip_prefix(base_lower.as_str())
            .and_then(|rest| strip(rest, &tail_lower.title))
            .and_then(|rest| strip(rest, &tail_lower.suffix))
            .is_some_and(is_rename_tail)
    })
}

/// The video file a TV-filed job actually owns in its shared
/// `Show/Season NN` folder, for playing back a completed history row.
///
/// "The biggest media file in `out_dir`" is the right answer for an
/// unfiled job, whose directory is private, and the wrong one here: a
/// filed job's `out_dir` is the whole season, so pressing Play on E01
/// served whichever episode happened to be largest - usually E02. Ownership
/// in a shared folder is exactly what [`is_filed_episode_file`] decides for
/// the delete path, so this asks the same question and serves what it
/// names.
///
/// Top level only, and videos only: filing renames the episode to
/// `Show - S03E05 [1080p].mkv` in the season folder itself, while any
/// subdirectory the job shipped (`Subs/`, `extras/`) moved in under its own
/// name and is not ours to claim. Symlinks are never served (see
/// [`is_real_file`]) - a RAR can carry one, and "the file matching this
/// name" would otherwise resolve a planted link to anything the daemon can
/// read.
///
/// Returns None when nothing matches - a season pack, a collision
/// fallback, files moved away by hand, or naming settings that changed
/// since filing. The caller reports "no playable file" rather than falling
/// back to a guess, because every guess here is a sibling episode.
pub fn find_filed_episode_media(dir: &Path, stem: &str, tail: &FiledTail) -> Option<PathBuf> {
    let bases = filed_bases(stem);
    if bases.is_empty() {
        return None;
    }
    let tail_lower = tail.lowered();
    let mut hits: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            is_real_file(p)
                && VIDEO_EXTS.contains(&ext_of(p).as_str())
                && p.file_name().is_some_and(|n| {
                    is_filed_episode_file(
                        &n.to_string_lossy().to_ascii_lowercase(),
                        &bases,
                        &tail_lower,
                    )
                })
        })
        .collect();
    // Sorted, not largest-first: "the biggest match" is the quality-blind
    // pick that [`delete_filed_episode`]'s doc comment describes going
    // wrong, and the suffix has already narrowed this to one release. Sort
    // only so a directory listing's arbitrary order cannot make two calls
    // disagree.
    hits.sort();
    hits.into_iter().next()
}

/// Is `rest` - everything after the episode base in a filed file's name -
/// a tail OUR rename produced, rather than part of a longer title?
///
/// The only shapes [`nzbkit::release::quality_suffix`] can emit are the
/// empty string, `" [tokens]"`, `"-Group"`, and `" [tokens]-Group"`, always
/// followed by `"."` and an extension. That tail belongs to the VIDEO file
/// [`tv_organize`] renamed - and to any sidecar that happens to share the
/// renamed stem, since `.srt`/`.nfo` are matched by the same base. Sidecars
/// are NOT generally renamed, though: `tv_organize` rewrites only
/// [`VIDEO_EXTS`], so a subtitle posted as `Show.S03E05.720p-GRP.en.srt`
/// keeps that name in the shared season folder and never matches this tail.
/// The limitation is [`delete_filed_episode`]'s: it leaves such a sidecar
/// behind. Deliberate - an unmatched name cannot be proven to be ours, and
/// a stray subtitle is a far cheaper mistake than a deleted episode.
///
/// Accepting a bare leading space instead matched the DEFAULT Sonarr/Plex
/// layout - `The Bear - S03E05 - Children.mkv` leaves `" - Children.mkv"` -
/// so deleting a job filed into the user's real library season folder
/// deleted the user's own copy of the episode, which we never downloaded
/// and cannot replace.
///
/// Whatever follows the base is refused when it reads as the second
/// episode of a range, in EVERY separator the convention is written with:
/// our own multi-episode name is `Show - S03E05-E06`, and the user's
/// library may hold `-06`, `.06`, `.E06`, `.S03E06`, `x06` or `_06`. Each
/// of those files carries E06's only copy as well, and we never downloaded
/// E06. Only `-` and `.` can reach an accepting arm at all; the rest fall
/// through to the final refusal, and are pinned by test.
///
/// `rest` arrives ASCII-lowercased from [`delete_filed_episode`]; the
/// `e`-prefix checks assume that.
pub(super) fn is_rename_tail(rest: &str) -> bool {
    // Optional " [1080p WEB h264]".
    let rest = match rest.strip_prefix(" [") {
        Some(r) => match r.split_once(']') {
            Some((_, tail)) => tail,
            None => return false,
        },
        None => rest,
    };
    if let Some(tail) = rest.strip_prefix('.') {
        // Our own tail is nothing but the extension chain (".mkv",
        // ".en.srt"), so only the FIRST segment could be a range's second
        // episode - later ones are the extension. A dot-spelled range
        // ("Show - S03E05.06.mkv") lands here rather than in the group
        // arm below, so it needs the same refusal.
        let first = tail.split('.').next().unwrap_or_default();
        let token = first.split([' ', '[']).next().unwrap_or_default();
        return !tail.is_empty() && !reads_as_episode_number(token);
    }
    // Optional "-GRP". A group token is one word, so a space anywhere in
    // it means this is a title, not our suffix.
    let Some(g) = rest.strip_prefix('-') else {
        return false;
    };
    let Some((group, ext)) = g.split_once('.') else {
        return false;
    };
    !group.is_empty()
        && !ext.is_empty()
        && !group.contains([' ', '[', ']'])
        && !(group.starts_with('e') && group[1..].starts_with(|c: char| c.is_ascii_digit()))
        // A group that reads as an episode number is the second episode of
        // a range ("Show - S03E05-06"), never a release group. Groups that
        // merely BEGIN with a digit ("3LT0N", "2HD") are real and stay ours.
        && !reads_as_episode_number(group)
}

/// Does this lowercased token read as an episode number - the second half
/// of a multi-episode range - rather than as part of our own suffix?
///
/// The three spellings a range's second episode takes once its separator
/// has been consumed: bare `06`, `e06`, and the full `s03e06`. A token that
/// merely CONTAINS digits is not one, which is what keeps real release
/// groups (`3lt0n`, `2hd`) and quality tokens (`x264`, `1080p`) ours.
pub(super) fn reads_as_episode_number(tok: &str) -> bool {
    fn digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }
    if digits(tok) {
        return true;
    }
    if let Some(ep) = tok.strip_prefix('e') {
        return digits(ep);
    }
    match tok.strip_prefix('s').and_then(|r| r.split_once('e')) {
        Some((season, ep)) => digits(season) && digits(ep),
        None => false,
    }
}

/// Does this parsed title read as a hash rather than a show name?
///
/// [`nzbkit::release::looks_obfuscated`] judges a stem as posted, but a
/// title reaches us AFTER the parser has title-cased a single-case stem
/// ("nzqymzflnjiyztgyntcynzzytq" -> "Nzqymzflnjiyztgyntcynzzytq"), which
/// is exactly the transformation its single-case rule can no longer see
/// through. Judging the lowered form as well restores it; a real title
/// carries separators and is refused by every anchored rule whatever its
/// case.
fn title_is_unpresentable(title: &str) -> bool {
    nzbkit::release::looks_obfuscated(title)
        || nzbkit::release::looks_obfuscated(&title.to_ascii_lowercase())
}

/// Strip path-hostile characters from a show title. The show directory
/// and every episode name below are built on it, so it gets the same
/// strong, colon-aware treatment as the movie path - see
/// [`nzbkit::release::sanitize_name`]. Empty means nothing nameable
/// survived, and [`tv_path`] declines.
fn sanitize(t: &str) -> String {
    nzbkit::release::sanitize_name(t)
}

/// What [`sanitize`] was before it grew colon expansion and the strong
/// filename rules: path-hostile glyphs blanked, whitespace collapsed.
/// Never used to write a new name - only to RECOGNISE the names older
/// builds already wrote (see [`legacy_tv_path`]).
fn legacy_sanitize(t: &str) -> String {
    t.chars()
        .map(|c| if "/\\:*?\"<>|".contains(c) { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
