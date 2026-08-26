//! Smart Folders + cleanup rules (two organizational features in the
//! spirit of Usenapp's).
//!
//! - A rules engine evaluated at enqueue: each rule matches the NZB name
//!   (regex, falling back to plain keyword) plus optional size bounds,
//!   and routes the job to a category (= out_root subfolder). First
//!   match wins. A rule can additionally ask for TV filing: at
//!   completion the job is moved to `[Show]/Season NN/` and its video
//!   renamed `Show - S01E02.ext`, reusing wall.rs's scene-name parser.
//! - Cleanup rules: a list of file extensions deleted from a job's
//!   folder after it completes successfully.

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::MutexExt;
use serde::{Deserialize, Serialize};

/// One Smart Folder rule as stored in settings.json ("smart_folders").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub name: String,
    /// Regex on the NZB name (case-insensitive). A pattern that doesn't
    /// compile is used as a plain keyword substring instead, so
    /// "matrix" and "^The\.Bear\." both do what they look like.
    #[serde(default, rename = "match")]
    pub pattern: String,
    /// Skip the rule when THIS matches (same regex-or-keyword rules).
    #[serde(default)]
    pub not_match: String,
    /// Size bounds in bytes, 0 = unbounded. The UI sends SAB-style
    /// strings ("200M"); both forms deserialize.
    #[serde(default, deserialize_with = "de_size")]
    pub min_size: u64,
    #[serde(default, deserialize_with = "de_size")]
    pub max_size: u64,
    /// Category to file the job under (empty = keep the caller's).
    #[serde(default)]
    pub category: String,
    /// File as TV at completion: [Show]/Season NN/ + video rename.
    #[serde(default)]
    pub tv_sort: bool,
}

/// Accept a byte count or a "200M"-style string (what the row editor
/// sends verbatim from its text input).
fn de_size<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    struct V;
    impl serde::de::Visitor<'_> for V {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bytes or a size string like 200M")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u64, E> {
            Ok(v.max(0) as u64)
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<u64, E> {
            Ok(v.max(0.0) as u64)
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<u64, E> {
            if s.trim().is_empty() {
                return Ok(0);
            }
            crate::sizes::parse_size(s).ok_or_else(|| E::custom(format!("bad size {s:?}")))
        }
    }
    d.deserialize_any(V)
}

/// Case-insensitive regex match; a pattern that isn't a valid regex is
/// read as a `*`/`?` glob if it carries one and as a keyword substring
/// if it does not. Empty pattern matches everything. The one
/// implementation lives in nzbkit::categories (user categories ride the
/// same rule syntax - 24D); this delegate keeps every caller here
/// byte-compatible.
fn pat_match(pattern: &str, name: &str) -> bool {
    nzbkit::categories::pat_match(pattern, name)
}

impl Rule {
    pub fn matches(&self, name: &str, size: u64) -> bool {
        if !pat_match(&self.pattern, name) {
            return false;
        }
        if !self.not_match.trim().is_empty() && pat_match(&self.not_match, name) {
            return false;
        }
        if self.min_size > 0 && size < self.min_size {
            return false;
        }
        if self.max_size > 0 && size > self.max_size {
            return false;
        }
        true
    }
}

/// First rule matching this job, or None. Rule order IS priority.
pub fn first_match<'a>(rules: &'a [Rule], name: &str, size: u64) -> Option<&'a Rule> {
    rules.iter().find(|r| r.matches(name, size))
}

/// "par2, sfv, .srr" → ["par2", "sfv", "srr"] (lowercased, dots and
/// leading wildcards stripped - people paste "*.par2" from other apps).
///
/// §163 item 2: an entry that is a real PATTERN keeps its shape instead.
/// The strip above exists because `*.par2` means "the par2 extension",
/// and it must go on meaning that - but it also flattened `Subs/*` and
/// `*sample*.mkv` to a bare extension, which is not what either of those
/// says. [`is_cleanup_pattern`] is the test, and the two kinds live in
/// one list because a pattern is self-describing: it carries a separator
/// or a wildcard, and a bare extension never can.
///
/// Backslashes are folded to `/` here so a Windows-shaped `Subs\*`
/// means the same thing as the posix spelling, and [`cleanup`] has one
/// separator to match against rather than two.
pub fn parse_ext_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|e| e.trim().to_ascii_lowercase().replace('\\', "/"))
        .map(|e| {
            if is_cleanup_pattern(&e) {
                e
            } else {
                e.trim_start_matches(['*', '.']).to_string()
            }
        })
        .filter(|e| !e.is_empty())
        .collect()
}

/// Is this cleanup-list entry a pattern rather than a bare extension?
///
/// Yes when it carries a path separator, or a wildcard that survives the
/// leading `*.` a pasted `*.par2` starts with. That second half is the
/// whole subtlety: `*.par2` has a wildcard and is NOT a pattern, because
/// stripping the lead leaves `par2` with nothing wild in it, while
/// `*.r??` leaves `r??` and is.
pub fn is_cleanup_pattern(e: &str) -> bool {
    e.contains('/') || e.trim_start_matches(['*', '.']).contains(['*', '?'])
}

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
fn legacy_tv_path(stem: &str) -> Option<(String, Option<String>)> {
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
const COMPONENT_BYTES: usize = 255;

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
const TITLE_SEP: &str = " - ";

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

/// Every spelling of this release's filed episode base, ASCII-lowercased:
/// the one filing would write today, plus the one an older build wrote
/// for the same release when the show name reshapes (see
/// [`legacy_tv_path`]). Empty when the stem doesn't name one episode.
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
fn is_rename_tail(rest: &str) -> bool {
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
fn reads_as_episode_number(tok: &str) -> bool {
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

/// Video payload. Disc images (`iso`/`img`) count: they ARE the feature for
/// a disc rip, so they must be recognised as the largest video (the sample
/// gate measures against it) as well as kept.
const VIDEO_EXTS: &[&str] = &[
    "mkv", "mp4", "avi", "m4v", "mov", "wmv", "mpg", "mpeg", "ts", "m2ts", "webm", "flv", "divx",
    "vob", "iso", "img",
];

/// Disc-structure and companion-track files that belong to a video payload
/// without being one: a BDMV/VIDEO_TS tree is unplayable with any of them
/// missing, and an external audio track is the release's whole point when
/// the video ships without it. Kept by `keep_media_only`, which would
/// otherwise leave a disc rip that cannot be opened.
/// The audio list has to stay ahead of what releases actually ship. It
/// carried ac3 and dts but not eac3, which is what nearly every current
/// Atmos or DD+ remux posts its external track as - so keep-media-only
/// deleted the one file the release existed for, reported Completed, and
/// left the user no copy anywhere. When in doubt add the extension:
/// keeping a stray audio file costs disk, deleting a wanted one is
/// unrecoverable.
const MEDIA_COMPANION_EXTS: &[&str] = &[
    "bdmv", "mpls", "clpi", "ifo", "bup", "sup", // disc structure and subs
    "mka", "m4a", "ac3", "eac3", "ec3", "dts", "dtshd", "truehd", "thd", "flac", "aac", "opus",
    "mp3", "wav", // external audio tracks
];

/// Subtitle sidecars - kept alongside the media by every cleanup mode.
const SUBTITLE_EXTS: &[&str] = &["srt", "sub", "idx", "ass", "ssa", "vtt", "smi"];

/// Payload that is not video and never clutter: music, audiobooks,
/// books, comics, and the cue/log sheet a lossless rip is verified with.
///
/// `keep_media_only` guards a video-less job by refusing to run at all,
/// which was enough while every release was a film or an episode. User
/// categories (24D) broke that premise: a comics or audiobook category
/// declaring base Movie, shipping ONE bonus .mp4 beside fifty .cbz
/// files, passed the guard and lost the fifty. `.flac`, `.m4a` and
/// `.cbr` survived only by accident - the first two sit in the companion
/// list, and a .cbr is a RAR to `is_packed_archive`. Extension lists are
/// the wrong place to be lucky, so the payload formats are named.
const PAYLOAD_EXTS: &[&str] = &[
    // audio
    "mp3", "m4b", "opus", "ogg", "oga", "wav", "aiff", "aif", "wma", "alac", "ape", "wv", "cue",
    "log", // books and comics
    "epub", "mobi", "azw", "azw3", "pdf", "cbz", "cbr", "cb7", "djvu",
];

/// Usenet furniture removed by `sweep_junk`: PAR2 recovery, the posted
/// NZB, checksum/verification files, scene .nfo/.txt, and website droppings.
/// Deliberately excludes archives (.rar/.7z - a job that still needs them
/// isn't done) and executables (software payloads).
const JUNK_EXTS: &[&str] = &[
    "par2", "nzb", "sfv", "nfo", "url", "txt", "srr", "srs", "diz", "md5", "sha", "sha256",
    "website",
];

/// Is this extension Usenet furniture rather than payload?
///
/// The one reader of [`JUNK_EXTS`] outside this module is the post-drain
/// census (issue #23): a metadata file the recovery set does not cover
/// must not fail a download whose payload is whole. Exposed as a
/// predicate rather than the list so the exclusions that make the list
/// safe - archives and executables are NOT here - travel with it.
pub fn is_junk_ext(ext: &str) -> bool {
    JUNK_EXTS.contains(&ext)
}

fn ext_of(p: &Path) -> String {
    p.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// A still-packed archive volume or part: RAR (`.rar`/`.rNN`, rollover
/// and numeric volumes by magic, or extensionless by magic), 7z (`.7z`,
/// `.7z.NNN`, obfuscated), or any zip shape [`nzbkit::zip`] knows.
///
/// `sweep_junk` gets this for free by simply not listing archives in
/// `JUNK_EXTS`, but `keep_media_only` deletes everything that is not
/// media, and an archive we could not unpack is the ONLY copy of the
/// payload. Deleting it left the user with an empty folder, a job marked
/// Completed, and one log line to explain it - the exact shape a zip post
/// used to fail in. Anything still packed stays; the user needs it.
///
/// The extensionless RAR sniff closes the last hole in that rule. An
/// obfuscated post strips extensions and renames its volumes to hashes,
/// so `looks_like_named_rar` - a pure name grammar - sees nothing, while
/// the 7z and zip collectors beside it already sniff exactly this shape.
/// A set we could not unpack (encrypted with no password, unrepairable,
/// a format we don't read) was therefore kept when it was named and
/// deleted when it was obfuscated, and obfuscated is the common case: the
/// whole payload went, with the recovery volumes that could have rebuilt
/// it, on the single most-encountered release shape on usenet.
///
/// Sniffing only where there is NO extension is the same standing rule
/// `nzbkit::zip::is_container` and `sevenz_archive_part` follow: a payload
/// that carries a name (`.mkv`, `.cbz`) is judged on that name and is
/// never opened by this path.
///
/// `zip_parts` is the directory's zip membership from [`zip_part_set`],
/// because some parts cannot answer for themselves: see there.
///
/// `split_parts` is that same move for the RAR and 7z twins of that
/// shape - a numbered byte split whose head sits in part 1 alone - from
/// [`crate::container_part_set`], which reads them with the extractor's
/// own grammar: see there.
/// It carries the PLAIN reading too, unioned in at both call sites from
/// [`crate::split_part_set`]: no part there has a head, so there is no
/// member to spare and the sweep took the whole set (§301).
fn is_packed_archive(
    p: &Path,
    zip_parts: &std::collections::HashSet<PathBuf>,
    split_parts: &std::collections::HashSet<PathBuf>,
) -> bool {
    crate::looks_like_named_rar(p)
        || (p.extension().is_none() && crate::rar_magic(p))
        || crate::sevenz_archive_part(p)
        || zip_parts.contains(p)
        || split_parts.contains(p)
        || nzbkit::zip::is_container(p)
}

/// Does an EXTENSIONLESS file begin like a video container?
///
/// keep-media-only decides by extension, and anything unrecognised is
/// deleted - so a hash-named payload with no extension at all was
/// removed outright. The no-video guard did not save it either: one
/// properly named video in the same folder is enough to arm the sweep,
/// and an obfuscated post that decodes to one named file plus one
/// hash-named one is an ordinary shape. The archive check above already
/// rescues the packed case; this covers the unpacked one.
///
/// Same standing rule as `is_packed_archive`: sniffing happens ONLY
/// where there is no extension. A file that carries a name is judged on
/// that name and is never opened here.
fn looks_like_video_bytes(p: &Path) -> bool {
    use std::io::Read;
    if p.extension().is_some() {
        return false;
    }
    let mut b = [0u8; 12];
    if std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        return false;
    }
    // Matroska/WebM (EBML), MP4/MOV family (....ftyp), AVI (RIFF....AVI ),
    // MPEG program stream, and the MPEG-TS 0x47 sync byte.
    b[..4] == [0x1A, 0x45, 0xDF, 0xA3]
        || &b[4..8] == b"ftyp"
        || (&b[..4] == b"RIFF" && &b[8..12] == b"AVI ")
        || b[..4] == [0x00, 0x00, 0x01, 0xBA]
        || b[0] == 0x47
}

/// Every file in `dir` that belongs to a zip container, asked as SETS.
///
/// A bare-numeric split zip (`movie.001`, `.002`, `.003`) carries the
/// magic in part 1 only - the rest are raw continuation bytes with
/// nothing in the name or the head to identify them. Asking each file on
/// its own therefore spared `.001` and deleted `.002` onward, leaving a
/// fragment that can never be opened beside a note telling the user the
/// verified archive was waiting for them. `nzbkit::zip::scan` gates the
/// whole set on part 1 and hands back every member, which is the same
/// collector the reporting path uses.
fn zip_part_set(dir: &Path) -> std::collections::HashSet<PathBuf> {
    nzbkit::zip::scan(dir)
        .into_iter()
        .flat_map(|f| f.parts)
        .collect()
}

/// Does the file start with the `PAR2\0PKT` packet magic? Obfuscated
/// posts name their recovery volumes as hashes with no extension - the
/// NZB subject may still read `…vol-01.par2`, but the on-disk name comes
/// from the yEnc header, so `ext_of` sees nothing and the extension list
/// below can't recognise them. The magic is unambiguous (no media
/// container starts with it), so it decides where the name can't. Same
/// detection main.rs's `dir_has_par2` uses for the repair side.
fn par2_magic(p: &Path) -> bool {
    use std::io::Read as _;
    let mut head = [0u8; 8];
    std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut head))
        .map(|()| &head == b"PAR2\x00PKT")
        .unwrap_or(false)
}

/// A real directory - NOT a symlink pointing at one.
///
/// `Path::is_dir` follows symlinks, and every walker below pairs it with
/// `read_dir` and then deletes what it finds. A completed job containing
/// `extras -> /media/shared` therefore had its cleanup pass walk into the
/// real target and delete files there: removing `job/extras/file.nfo`
/// resolves through the link to `/media/shared/file.nfo`. Native extraction
/// never materialises a symlink, but an external extractor or pre-existing
/// filesystem state can, and "we don't create them" is not a boundary.
pub(crate) fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// A real file - NOT a symlink pointing at one. Same reason as
/// [`is_real_dir`]: the walkers delete what they classify, and following a
/// link means deleting outside the job.
pub(crate) fn is_real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Deepest directory nesting [`prune_empty_dirs`] will walk. Our own
/// extraction cannot nest at all (`sanitize_filename` maps the path
/// separators out of archive entry names), so this only ever bounds a tree
/// something else built, and bounds the recursion with it.
const PRUNE_MAX_DEPTH: u32 = 8;

/// Finder metadata macOS drops into any folder it has looked at: the
/// per-folder `.DS_Store`, and the `._name` AppleDouble carrying the
/// resource fork of a file copied to a non-native filesystem.
///
/// Neither is content. Left in place they keep a swept `Sample/` husk
/// alive forever - `.DS_Store` has no extension to match (`ext_of` gives
/// "" for a dotfile, so `JUNK_EXTS` never sees it) and at 6148 bytes it is
/// over `is_nameless_scrap`'s 4 KB ceiling, so nothing in the junk sweep
/// can reach it and `prune_empty_dirs` then finds the directory non-empty.
/// A real file, a subdirectory and a symlink all still count as content.
///
/// `.DS_Store` is decided on the name alone - that name is Finder's, and
/// nothing else writes it. `._name` is NOT: the prefix is a convention, not
/// a reservation, and a mis-packed archive or a poster-named extra can
/// carry a real payload called `._something.mkv`. Since the caller deletes
/// what this classifies, and deletes it permanently
/// ([`drop_finder_droppings`]), an AppleDouble must also LOOK like one.
/// Size is the check that costs nothing and cannot be spoofed by a name: a
/// genuine AppleDouble holds a resource fork plus xattrs, which is a few
/// KB in the ordinary case and a few hundred KB in the worst one, so
/// [`APPLEDOUBLE_MAX`] sits an order of magnitude above anything real
/// while still excluding every payload worth losing.
fn is_finder_dropping(p: &Path) -> bool {
    let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    if !is_real_file(p) {
        return false;
    }
    if name == ".DS_Store" {
        return true;
    }
    name.starts_with("._") && p.metadata().is_ok_and(|m| m.len() <= APPLEDOUBLE_MAX)
}

/// Largest `._name` file still treated as an AppleDouble sidecar rather
/// than content. See [`is_finder_dropping`].
const APPLEDOUBLE_MAX: u64 = 1024 * 1024;

/// Is every remaining entry of `d` a Finder dropping? (True for an already
/// empty directory, which the caller then removes on its own.)
fn only_finder_droppings(d: &Path) -> bool {
    std::fs::read_dir(d).is_ok_and(|rd| rd.flatten().all(|e| is_finder_dropping(&e.path())))
}

/// Delete the Finder droppings in `d` so the husk can go.
///
/// A plain `remove_file`, deliberately NOT `remove_user_file`: this is the
/// OS's own metadata about a folder that is about to stop existing, not
/// anything the user downloaded or could want back, and routing it to the
/// Trash would put `.DS_Store` files in front of them for no reason.
fn drop_finder_droppings(d: &Path) {
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if is_finder_dropping(&path)
            && let Err(e) = std::fs::remove_file(&path)
        {
            warn!(target: "cleanup", "{}: {e}", path.display());
        }
    }
}

/// Remove subdirectories of `dir` that a sweep just emptied: the `Sample/`
/// or `Proof/` folder whose clips have gone, plus any now-empty parent
/// above it. The sweeps delete files one subdirectory deep but left the
/// husk behind, and a completed job still showing a `Sample` folder reads
/// as though the sweep never ran - NZBGet's DeleteSamples takes the
/// directory too.
///
/// Only a directory whose whole subtree is empty goes. Anything holding a
/// file stays, and so does every parent above it. A symlink counts as
/// content and is never followed or removed: it is not ours, and
/// `remove_dir` on the parent would be the least of what walking into it
/// could cost (see [`is_real_dir`]).
///
/// "Empty" tolerates Finder metadata - see [`is_finder_dropping`]. On
/// macOS the sweep took the sample clip and left `Sample/.DS_Store`, so
/// the husk this exists to remove survived every download.
///
/// `dir` itself is never removed however empty it ends up - the job owns
/// it, and the state that a job's own output directory is missing is one
/// the rest of post-processing does not expect. Returns how many
/// directories went; deliberately NOT folded into the sweeps' file counts.
fn prune_empty_dirs(dir: &Path, depth: u32) -> usize {
    if depth >= PRUNE_MAX_DEPTH {
        return 0;
    }
    let mut removed = 0;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !is_real_dir(&path) {
            continue;
        }
        // Depth-first: emptying a child can empty its parent.
        removed += prune_empty_dirs(&path, depth + 1);
        if only_finder_droppings(&path) {
            drop_finder_droppings(&path);
        }
        if std::fs::read_dir(&path).is_ok_and(|mut r| r.next().is_none()) {
            match std::fs::remove_dir(&path) {
                Ok(()) => {
                    info!(target: "cleanup", "empty dir {}", path.display());
                    removed += 1;
                }
                Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
            }
        }
    }
    removed
}

/// The largest video file in `dir` (top level + one subdir deep), or None.
/// The main feature - protected from the junk sweep regardless of its name,
/// so a film or season titled "Proof"/"Sample" is still recognised as the
/// feature and never deleted.
/// The resolution the payload's own container reports, when the job has
/// a Matroska main video. The subject line's claim is the poster's; the
/// header is the file's, and where the two disagree the header wins
/// (see `finalize_names`). One bounded head read; anything unreadable
/// returns None and the claim stands.
pub fn measured_res(dir: &Path) -> Option<&'static str> {
    let video = main_video(dir)?;
    if !matches!(ext_of(&video).as_str(), "mkv" | "webm") {
        return None;
    }
    let i = nzbkit::mkv::probe(&video)?;
    Some(nzbkit::mkv::res_bucket(i.width?, i.height?))
}

/// The job's feature: the biggest video in the finished directory, with
/// the sample clip ruled out. What every "ask the payload itself"
/// question is asked of, so they all agree on which file they mean.
pub fn main_video(dir: &Path) -> Option<PathBuf> {
    largest_video(dir).filter(|v| !is_sample_clip(v))
}

fn largest_video(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    let mut consider = |path: PathBuf| {
        if !is_real_file(&path) || !VIDEO_EXTS.contains(&ext_of(&path).as_str()) {
            return;
        }
        let len = path.metadata().map(|m| m.len()).unwrap_or(0);
        if best.as_ref().is_none_or(|(b, _)| len > *b) {
            best = Some((len, path));
        }
    };
    let tops: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    for path in tops {
        if is_real_dir(&path) {
            if let Ok(rd) = std::fs::read_dir(&path) {
                for e in rd.flatten() {
                    consider(e.path());
                }
            }
        } else {
            consider(path);
        }
    }
    best.map(|(_, p)| p)
}

/// Does this cleanup-list entry select this file?
///
/// `ext` and `name` are the file's own, already lowercased; `rel` is its
/// path relative to the job folder, with `/` separators, which for a
/// one-level sweep is either `name` or `sub/name`.
///
/// The three kinds, and why a pattern is matched against one thing or
/// the other rather than both: a bare extension is today's rule
/// unchanged; a pattern WITHOUT a separator is about the filename, so it
/// applies at every level the sweep reaches (`*sample*` should find a
/// sample wherever the unpack put it); a pattern WITH one is about
/// placement, so it is matched against the relative path and `Subs/*`
/// therefore means the Subs folder rather than anything named Subs.
fn cleanup_selects(entry: &str, ext: &str, name: &str, rel: &str) -> bool {
    if !is_cleanup_pattern(entry) {
        return entry == ext;
    }
    crate::rss::glob_match(entry, if entry.contains('/') { rel } else { name })
}

/// Delete files matching `exts` from `dir` (top level plus one
/// subdirectory level - where extraction puts things). Logs each
/// removal; returns `(total, par2)` - how many files went, and how many
/// of those were `.par2` recovery files. The split exists for the
/// history drawer's one-line cleanup report: recovery files are deleted
/// by a default most users never chose (`par_cleanup`), so "12 of those
/// were par2" is the half of the count that answers "where did my
/// recovery data go".
///
/// An entry is a bare extension or a pattern - see [`parse_ext_list`]
/// and [`cleanup_selects`]. The par2 half of the count is taken off the
/// file's own extension either way, so a pattern that happens to sweep
/// recovery files still reports them as recovery files.
pub fn cleanup(dir: &Path, exts: &[String]) -> (usize, usize) {
    let mut removed = 0;
    let mut par2 = 0;
    // Read once, for the whole sweep: see `remove_user_file`.
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    let mut sweep = |d: &Path, prefix: &str| {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let rel = format!("{prefix}{name}");
            if exts.iter().any(|e| cleanup_selects(e, &ext, &name, &rel)) {
                match remove_swept_file(&path, recoverable, staging.as_deref()) {
                    Ok(_) => {
                        info!(target: "cleanup", "removed {}", path.display());
                        removed += 1;
                        if ext == "par2" {
                            par2 += 1;
                        }
                    }
                    Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
                }
            }
        }
    };
    sweep(dir, "");
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                let sub = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                sweep(&path, &format!("{sub}/"));
            }
        }
    }
    (removed, par2)
}

/// Recoverable delete for anything that came out of a user's download.
///
/// The cleanup passes used to call `remove_file` directly, so a file the
/// junk heuristics got wrong was gone for good - and those heuristics are
/// exactly the kind that get things wrong (obfuscated posts have no
/// reliable names, and "Proof" once cost a real release). The Trash makes
/// every one of those calls reversible by the person best placed to judge
/// it, which is the whole difference between a wrong guess and data loss.
///
/// Deliberately NOT used for our own spool, journals or placeholders:
/// those are internal churn, and routing them here would bury the user's
/// Trash under files they never saw and cannot act on.
///
/// A recoverable delete NEVER becomes a permanent one. When no Trash will
/// take the path this returns an error and the file stays exactly where it
/// is - see [`trash_attempt`]. It used to hard-delete instead, on the
/// reasoning that leaving clutter forever was worse; that reasoning had it
/// backwards. Every caller of this is a heuristic ("this looks like junk",
/// "this looks like a sample"), the Trash is the only thing that makes a
/// wrong guess survivable, and "the Trash refused, so destroy it" turns
/// the one failure the setting promised to soften into the very outcome it
/// promised to prevent. A user who genuinely wants permanent deletes turns
/// `delete_to_trash` off - the NAS/seedbox default on Linux - and that
/// path is untouched.
///
/// `recoverable` is passed IN rather than read from the process-global
/// here, so one sweep decides once (at its entry) and every file it touches
/// is treated the same way. Re-reading the flag per file meant a settings
/// change - or, in the test suite, another test's `set_delete_to_trash` -
/// landed halfway through a sweep and split it between the two behaviours.
pub fn remove_user_file(path: &Path, recoverable: bool) -> std::io::Result<Removed> {
    if recoverable_wanted(recoverable, path) {
        return match trash_attempt(path) {
            TrashVerdict::Took => Ok(Removed::Trashed),
            TrashVerdict::TookButGone | TrashVerdict::NotFound => Ok(Removed::Gone),
            TrashVerdict::Refused(why) => Err(refusal(&why)),
        };
    }
    // A bounded call that gave up may STILL be running, and Finder may
    // yet move the file to the Trash behind us. Then this direct delete
    // races it and loses with NotFound - which is the outcome we wanted
    // (the file is gone), not a failure to report to the caller.
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Removed::Gone),
        Err(e) => Err(e),
        Ok(()) => Ok(Removed::Gone),
    }
}

/// [`remove_user_file`] for a whole DIRECTORY: a completed job's private
/// output folder, deleted as one recoverable unit. One Trash call moves
/// the folder intact - the user gets "the download I deleted" back as a
/// single restorable item, not a thousand loose files - and it costs the
/// same one bounded call a single file does.
///
/// This is what makes the "Deleted files go to the Trash" promise hold
/// for the deletes users actually perform: history "delete + files", a
/// queue delete with files, and the watchlist delete_old upgrade all end
/// at a job directory, and every one of them used to be a bare
/// `remove_dir_all` that no setting could soften.
///
/// This is the delete where refusing to hard-delete matters most: the
/// argument in [`remove_user_file`] applies to a stray `.nfo`, and here it
/// applies to an entire finished download. A `remove_dir_all` behind a
/// failed Trash call is unrecoverable by anyone, and it lands on the user
/// who ASKED for recoverable deletes. The directory is left alone and the
/// caller says so instead.
pub fn remove_user_dir(path: &Path, recoverable: bool) -> std::io::Result<Removed> {
    if recoverable_wanted(recoverable, path) {
        return match trash_attempt(path) {
            TrashVerdict::Took => Ok(Removed::Trashed),
            TrashVerdict::TookButGone | TrashVerdict::NotFound => Ok(Removed::Gone),
            TrashVerdict::Refused(why) => Err(refusal(&why)),
        };
    }
    // NotFound tolerated for the same race as remove_user_file - and for
    // the ordinary case of a job whose directory was never created.
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Removed::Gone),
        Err(e) => Err(e),
        Ok(()) => Ok(Removed::Gone),
    }
}

/// What one recoverable-delete attempt settled on.
/// What a removal actually DID, as opposed to what the setting asked
/// for.
///
/// The distinction is load-bearing and was missing: "its files went to
/// the Trash" used to be reconstructed by the callers from two globals
/// (`delete_to_trash()` and `!trash_unresponsive()`), never from what
/// happened to those files. On 4 Aug that told a user a 14 GB download
/// was recoverable while it had in fact been destroyed outright - the
/// setting was on, nothing had timed out, and the backend returned Ok.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removed {
    /// In a Trash it can be restored from. Only ever reported when that
    /// has been CHECKED, never inferred from the setting.
    Trashed,
    /// Gone, with no promise of getting it back. Covers a deliberate
    /// permanent delete, a path that was already absent, and the case
    /// above: a Trash route that reported success and left nothing
    /// recoverable behind it.
    Gone,
}

/// Did `path` actually land somewhere it can be restored from?
///
/// Asked AFTER a Trash route reports success, because that success means
/// only "a backend returned Ok". macOS has two routes and both can
/// answer Ok while the bytes are gone: on a volume whose per-user Trash
/// is not usable - an external disk mounted `noowners` is the ordinary
/// way to get one - Finder's scripted `delete` performs the delete
/// -immediately behaviour its GUI would warn about, and says it worked.
///
/// Deliberately biased towards claiming recoverable: only a positive
/// look in the expected place, coming back empty, downgrades the answer.
/// Anything we cannot determine stays `Trashed`, because crying wolf on
/// a delete that WAS recoverable is its own harm.
/// What the Trash roots held that could be mistaken for this delete,
/// taken BEFORE it happens.
///
/// Without it the check answers "recoverable" for a name that was
/// already sitting there: `~/.Trash` keeps things for weeks, so the
/// second delete of `Movie.mkv` - or a delete of anything whose name
/// starts with a stem already in there - matched an entry from days
/// ago and reported a hard delete as restorable. The claim has to be
/// about an entry that appeared, not one that exists.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct TrashBefore {
    /// The exact target name already present in some root.
    exact: bool,
    /// Every stem-prefixed name already present, across all roots.
    names: std::collections::HashSet<std::ffi::OsString>,
}

#[cfg(target_os = "macos")]
fn trash_snapshot(path: &Path) -> TrashBefore {
    let mut before = TrashBefore::default();
    let Some(name) = path.file_name() else {
        return before;
    };
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string_lossy().into_owned());
    for root in trash_roots(path) {
        if root.join(name).exists() {
            before.exact = true;
        }
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.take(4096).flatten() {
            if e.file_name().to_string_lossy().starts_with(&stem) {
                before.names.insert(e.file_name());
            }
        }
    }
    before
}

/// The two places macOS puts a trashed item: the boot volume's per-user
/// Trash, and a per-volume `.Trashes/<uid>` for anything else. A path
/// under /Volumes/<name> is checked against its own volume first, then
/// the home one - a cross-volume trash lands in the latter.
#[cfg(target_os = "macos")]
fn trash_roots(path: &Path) -> Vec<std::path::PathBuf> {
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    let comps: Vec<_> = path.components().collect();
    if comps.len() > 2 && path.starts_with("/Volumes") {
        let vol: std::path::PathBuf = comps[..3].iter().collect();
        roots.push(
            vol.join(".Trashes")
                // SAFETY: getuid(2) takes no arguments, touches no
                // memory and cannot fail; it is unsafe only because it
                // is an extern "C" call.
                .join(unsafe { libc::getuid() }.to_string()),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(std::path::PathBuf::from(home).join(".Trash"));
    }
    roots
}

#[cfg(target_os = "macos")]
fn landed_in_a_trash(path: &Path, before: &TrashBefore) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return true;
    };
    let roots = trash_roots(path);
    if roots.is_empty() {
        return true;
    }
    // Finder disambiguates a name collision by appending to the stem, so
    // an exact hit is the common case and a prefix match covers the
    // rest. Bounded: a long-untended Trash must not turn one delete into
    // a directory walk of tens of thousands of entries.
    //
    // Matched against the BEFORE snapshot throughout: an entry that was
    // already there is somebody else's old delete, and it is the whole
    // reason this check could say "recoverable" about files that had
    // just been destroyed outright.
    for root in &roots {
        if !before.exact && root.join(&name).exists() {
            return true;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        for e in entries.take(4096).flatten() {
            if e.file_name().to_string_lossy().starts_with(&stem)
                && !before.names.contains(&e.file_name())
            {
                return true;
            }
        }
    }
    false
}

/// Every other platform's backend is a real XDG Trash or Recycle Bin,
/// which does not have the "reported success, deleted anyway" mode this
/// guards against. Nothing to second-guess.
#[cfg(not(target_os = "macos"))]
#[derive(Default)]
struct TrashBefore;

#[cfg(not(target_os = "macos"))]
fn trash_snapshot(_path: &Path) -> TrashBefore {
    TrashBefore
}

#[cfg(not(target_os = "macos"))]
fn landed_in_a_trash(_path: &Path, _before: &TrashBefore) -> bool {
    true
}

enum TrashVerdict {
    /// A Trash route took `path` and it was found afterwards in a Trash
    /// it can be restored from.
    Took,
    /// A Trash route reported success, but nothing recoverable is there:
    /// the path is gone for good. The files ARE removed - the caller
    /// asked for that - but nothing may claim they can be restored.
    TookButGone,
    /// There was nothing at `path` to take.
    NotFound,
    /// No Trash route would take it. Carries the reason for the log. The
    /// caller must NOT fall back to a permanent delete: see
    /// [`remove_user_file`].
    Refused(String),
}

/// The error a refused recoverable delete comes back as. Worded to be
/// READ: a user who asked for recoverable deletes needs to know why their
/// files are still there and what to change, not just that something
/// failed. It reaches them through the dashboard's kept-files notice as
/// well as the log now, so it has to stand up in front of a person.
///
/// Deliberately does NOT name the path, though it once did. Every caller
/// already prints it - `remove_job_files`, the filed-episode sweep, the
/// deferred-trash drain and the watch-folder ingest all log
/// `<path>: <this>` - so the path came out twice in a row on every line,
/// and the notice repeats it a third time in its own sentence.
fn refusal(why: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "the Trash would not take it ({why}). If something else has the \
         files open - a virus scanner or a backup tool often does, for a \
         while after a big download - deleting again in a few minutes \
         usually works. If it keeps happening, turn off \"Deleted files go \
         to the Trash\" in Settings to remove files outright rather than \
         leave them."
    ))
}

/// `NZBFAST_NO_TRASH=1` forces every recoverable delete down the plain
/// permanent-delete branch, as if `delete_to_trash` were off - the
/// explicit override for anything outside [`under_temp_dir`]'s rule,
/// whose doc carries the Finder "-43" story both of them exist to stop.
///
/// It also closes a hole `cfg(test)` could not: the `TRASH` flag defaults
/// off under `cfg(test)` so cleanup suites do not empty their fixtures
/// into the developer's real ~/.Trash, but `cfg!(test)` is evaluated when
/// the LIBRARY is compiled and an integration test links the ordinary
/// non-test build, so every test under `tests/` got the flag ON.
///
/// Read once and cached: this sits under per-file cleanup sweeps.
fn trash_disabled_by_env() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| {
        std::env::var("NZBFAST_NO_TRASH").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    })
}

/// Nothing under the OS temp directory is ever worth a recoverable
/// delete, and asking for one there is actively harmful. The Trash exists
/// so a WRONG GUESS about the user's data survives, and a path in
/// `$TMPDIR` is not the user's data by construction - it is our own
/// scratch, or a test's fixtures, which the OS may reclaim at any moment.
/// Binning it only leaves the user junk to empty, named after something
/// they never had.
///
/// It is also where the recoverable route MISBEHAVES. On macOS the Trash
/// is scripted through Finder and the call is bounded ([`trash_attempt`]),
/// so we give up waiting, the owner of the scratch directory removes it,
/// and Finder arrives to find nothing there: a modal "-43" dialog on the
/// desktop, minutes after the run that caused it and attributed to
/// nothing. The integration suites hit this constantly - each drives a
/// real `nzbfast` child against a `nzbfast-*` scratch dir in `$TMPDIR`,
/// where the library-side `cfg(test)` default that keeps the UNIT tests
/// off Finder cannot reach a spawned binary - so fixing it here fixes all
/// 122 child-spawn sites at once, and the next test someone writes.
///
/// Compared by canonical path so the macOS `/var` -> `/private/var`
/// symlink cannot slip a temp path past the check. An uncanonicalizable
/// path (already gone, unreadable parent) falls back to the path as
/// given: this is a "make it permanent" decision, and the safe direction
/// when unsure is to leave the caller's recoverable request alone.
fn under_temp_dir(path: &Path) -> bool {
    // The library's OWN unit tests are the one place a temp path must
    // still reach the Trash: `trash_tests` proves the recoverable route
    // works and its fixtures can only live in `$TMPDIR`. They are safe
    // there for the reason the integration suites are not - `TRASH`
    // defaults OFF under `cfg(test)`, so those three serialized,
    // self-cleaning tests are the only callers that ever arrive here
    // recoverable. This gate is aimed squarely at the build they cannot
    // cover: the binary a test spawns, where `cfg!(test)` is false.
    if cfg!(test) {
        return false;
    }
    path_is_under(path, &std::env::temp_dir())
}

/// The prefix test behind [`under_temp_dir`], split out so it is testable:
/// `under_temp_dir` answers false under `cfg(test)` by design, so a unit
/// test can never reach the comparison through it.
fn path_is_under(path: &Path, base: &Path) -> bool {
    fn real(p: &Path) -> std::path::PathBuf {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    }
    real(path).starts_with(real(base))
}

/// Fold the overrides into a caller's `recoverable` request. Applied at
/// the two public entry points rather than inside [`trash_attempt`],
/// because they have to mean "delete it permanently", not "refuse and
/// leave it" - a refusal would leave every affected file on disk, which
/// for a temp path is the opposite of what anyone wants.
fn recoverable_wanted(recoverable: bool, path: &Path) -> bool {
    recoverable && !trash_disabled_by_env() && !under_temp_dir(path)
}

/// One recoverable attempt against the Trash.
fn trash_attempt(path: &Path) -> TrashVerdict {
    // Nothing there to bin. Checked BEFORE the backend on purpose: macOS's
    // Finder route reports a path it cannot see as a CLASS error
    // ("Handler can't handle objects of this class", -10010), not as "not
    // found" - the crate only canonicalizes the parent, so a missing leaf
    // sails through to the AppleScript. That produced a live WARN reading
    // "could not move <a user's download> to the Trash - deleting it
    // instead" for a directory that had already gone, which is the most
    // alarming line we could print about a no-op. It is also the shape of
    // the race the old direct-delete fallback swallowed as NotFound.
    // NotFound only. `is_err()` swallowed every other stat failure too -
    // EACCES on a parent that lost search permission, EIO/ESTALE on a
    // dropped SMB or NFS mount - and reported each as "the Trash took
    // it": `Ok(())` out of `remove_user_dir`, `FilesGone::Yes`, no
    // `note_delete_kept`, no warning, and the history row dropped. A NAS
    // user reclaiming space from a share that had just gone away was
    // told the files were deleted while the whole payload was still
    // sitting there, named by nothing - the exact failure class the
    // kept-files notice exists to close. The non-recoverable arms
    // already tolerate only NotFound; this one is now consistent with
    // them.
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return TrashVerdict::NotFound;
    }
    if trash_unresponsive() {
        return TrashVerdict::Refused("the Trash is not responding".to_string());
    }
    // Taken BEFORE the call: "is it in the Trash now" cannot tell a
    // fresh entry from one that was already sitting there under the
    // same name.
    let before = trash_snapshot(path);
    match trash_delete_gated(|| trash_delete_bounded(path)) {
        // Ok from the backend is not the answer on its own - see
        // `landed_in_a_trash`.
        Ok(()) => {
            if landed_in_a_trash(path, &before) {
                TrashVerdict::Took
            } else {
                warn!(
                    target: "files",
                    "the Trash reported success for {} but nothing restorable is there - \
                     reporting it as deleted, because that is what happened. A volume \
                     whose per-user Trash is unusable (an external disk mounted \
                     `noowners` is the common one) deletes outright and says it worked.",
                    path.display()
                );
                TrashVerdict::TookButGone
            }
        }
        // Another caller was inside the process's first Trash call when we
        // arrived, and it came back unresponsive. We never made a call of
        // our own, but the verdict is the same one we would have got.
        Err(None) => TrashVerdict::Refused("the Trash is not responding".to_string()),
        Err(Some(e)) => {
            // On a headless Mac the crate's Finder/AppleScript backend
            // does not fail fast: every call blocks ~2 minutes before
            // "AppleEvent timed out (-1712)". A queue of three jobs
            // carries dozens of par2/nfo cleanup files, and those
            // serialized stalls measured as 720 s of a 863 s job - the
            // job is not done until its cleanup is. One timeout means
            // every later call will stall the same way, so the rest of
            // the process stops asking - `trash_delete_gated` has already
            // latched that, before it let anyone else past, and all that
            // is left here is to say so. Ordinary failures (a volume with
            // no trash at all) stay per-path: they are instant and the
            // next file may live somewhere else entirely.
            if looks_like_a_trash_timeout(&e) {
                warn!(
                    target: "cleanup",
                    "the Trash is not responding (headless session?) - \
                     not asking it again this run"
                );
            }
            first_refusal_hint();
            TrashVerdict::Refused(e)
        }
    }
}

/// Said once per process, the first time a recoverable delete is refused.
///
/// The per-path errors go where the caller logs them (a sweep line, a job
/// line), and each one on its own reads like a transient hiccup. This is
/// the sentence that explains the pattern: files are being LEFT, on
/// purpose, and there are exactly two ways out. Once, not per file - a
/// junk sweep refused is a dozen lines by itself.
fn first_refusal_hint() {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    warn!(
        target: "cleanup",
        "the Trash refused a delete, so files are being left in place \
         rather than permanently deleted. Turn off \"Deleted files go to \
         the Trash\" in Settings if you want them removed outright"
    );
}

/// How long a single Trash call may hold up a finished job before we stop
/// waiting for it. Only meaningful on macOS - see `trash_delete_bounded`.
///
/// Generous ON PURPOSE. The Trash is what makes a wrong junk-heuristic
/// guess reversible by the user, which is the whole reason cleanup routes
/// through it, so treating a merely SLOW Finder as a dead one would trade
/// that away for the rest of the process. A healthy Finder answers in
/// milliseconds; nothing legitimate takes half a minute.
#[cfg(target_os = "macos")]
const TRASH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// `trash::delete`, but it cannot hold a finished job hostage.
///
/// On macOS the crate's backend asks Finder over AppleScript and waits
/// with no application-level timeout, so on a headless session (ssh, a
/// launchd daemon, a login window nobody has touched) every call blocks
/// for about two minutes before returning "AppleEvent timed out (-1712)".
/// Cleanup runs INSIDE post-processing and a job is not filed to history
/// until it returns, so those stalls are wall-clock the user sees as a
/// download that finished but never appeared: one measured job spent
/// 720 s of its 863 s exactly here. `TRASH_UNRESPONSIVE` already stops
/// the SECOND call paying it, but the first one still did.
///
/// So: run the call on its own thread and stop waiting at
/// `TRASH_DEADLINE`. The thread is left to finish on its own - AppleEvent
/// has no cancel, and abandoning it is the point. The caller then leaves
/// the file alone, and tolerates the race where Finder eventually wins
/// (the path is simply gone next time anyone looks).
///
/// Every other platform calls straight through: the XDG and Windows
/// backends are local filesystem work with no interprocess wait to bound,
/// and a thread per file would be cost for nothing.
///
/// macOS has a SECOND route, and this is where it is taken. See
/// [`trash_via_file_manager`]. The other two platforms have exactly one
/// each, and both fail for reasons no retry would fix - a Windows volume
/// with the Recycle Bin turned off, a mapped network drive that has none,
/// an item too big for the bin's quota; a freedesktop trash on a
/// read-only or foreign-uid mount. Those come back as a refusal and the
/// file stays, which is the same answer this reaches on macOS when both
/// routes are out: the platforms differ in how many chances they get, not
/// in what happens when they are spent.
fn trash_delete_bounded(path: &Path) -> Result<(), String> {
    // No `return`: on non-mac targets the macos block below is stripped,
    // making this block the tail expression - a `return` here trips
    // clippy's needless_return on the Linux CI runner, the only clippy
    // that ever compiles this arm.
    #[cfg(not(any(target_os = "macos", target_os = "android", target_os = "ios")))]
    {
        trash::delete(path).map_err(|e| e.to_string())
    }
    // Android and iOS have no system trash; refuse and the file stays,
    // exactly like the other platforms when their routes are spent.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = path;
        Err("no system trash on this platform".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        if !finder_is_out() {
            match trash_via_finder(path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        target: "cleanup",
                        "Finder would not bin {} ({e}) - using the volume's \
                         own Trash from now on",
                        path.display()
                    );
                    FINDER_IS_OUT.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        trash_via_file_manager(path)
    }
}

/// The Finder/AppleScript route, bounded. First choice on macOS because it
/// is the only one that records "Put Back", so a user restoring a wrongly
/// swept file gets it back WHERE IT WAS rather than having to know where
/// that was.
#[cfg(target_os = "macos")]
fn trash_via_finder(path: &Path) -> Result<(), String> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let p = path.to_path_buf();
    match run_bounded(TRASH_DEADLINE, move || {
        let mut ctx = trash::TrashContext::new();
        ctx.set_delete_method(DeleteMethod::Finder);
        ctx.delete(&p).map_err(|e| e.to_string())
    }) {
        Some(r) => r,
        None => {
            warn!(
                target: "cleanup",
                "Finder did not answer within {}s for {} (headless session?)",
                TRASH_DEADLINE.as_secs(),
                path.display()
            );
            Err("timed out".to_string())
        }
    }
}

/// `NSFileManager.trashItemAtURL`, the route Finder cannot refuse on our
/// behalf: it moves the item into the OWNING VOLUME's `.Trashes/<uid>`
/// itself, with no Finder, no AppleScript and no GUI session in the way.
///
/// It exists here because the Finder route fails in ways that have nothing
/// to do with whether a Trash is available:
///  * `-10010` ("Handler can't handle objects of this class") for a path
///    Finder cannot resolve. Seen live on 3 Aug 2026 against a directory
///    on an external volume;
///  * `-1712` (AppleEvent timed out) on a headless session, which used to
///    condemn the whole process to permanent deletes for its lifetime;
///  * an automation permission prompt nobody is there to answer.
///
/// Measured against an external APFS volume on Apple silicon: Finder
/// 259 ms for one directory, this 40 ms, both landing in the volume's own
/// `/Volumes/<vol>/.Trashes/<uid>`. The one thing it does not do
/// is record Put Back (a macOS bug the crate documents), which is why it
/// is the SECOND choice and not the first - a restore is a drag out of the
/// Trash rather than one menu item, and that is a far smaller loss than
/// the delete it replaces.
///
/// Bounded like the Finder call: this one has no interprocess wait to
/// hang on, but a stale network mount can still block a filesystem call,
/// and a bounded failure now means "leave the file", not "destroy it".
#[cfg(target_os = "macos")]
fn trash_via_file_manager(path: &Path) -> Result<(), String> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let p = path.to_path_buf();
    match run_bounded(TRASH_DEADLINE, move || {
        let mut ctx = trash::TrashContext::new();
        ctx.set_delete_method(DeleteMethod::NsFileManager);
        ctx.delete(&p).map_err(|e| e.to_string())
    }) {
        Some(r) => r,
        None => Err("timed out".to_string()),
    }
}

/// Latched the first time the Finder route fails, for any reason: every
/// later call on this volume - and most likely every later call at all -
/// goes straight to [`trash_via_file_manager`]. Deliberately never reset,
/// like `TRASH_UNRESPONSIVE`: re-probing costs up to `TRASH_DEADLINE` per
/// delete and buys nothing but a Put Back entry.
///
/// Note what this latch does NOT mean: the Trash is still working. Only
/// `TRASH_UNRESPONSIVE` says there is no route at all.
#[cfg(target_os = "macos")]
static FINDER_IS_OUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "macos")]
fn finder_is_out() -> bool {
    FINDER_IS_OUT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Run `f` on its own thread and give up waiting after `deadline`.
/// `None` means it had not finished in time; the thread keeps running.
///
/// Split out from `trash_delete_bounded` so the give-up path is testable
/// without a Finder to hang: the whole point of this code is the case
/// that cannot be reproduced on a healthy developer machine.
///
/// `test` as well as `macos` in the gate: only the macOS path calls this
/// at runtime, but the tests below cover it on every platform, and
/// without `test` here a Linux or Windows build warns it is unused.
#[cfg(any(target_os = "macos", test))]
fn run_bounded<T: Send + 'static>(
    deadline: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The receiver is gone once we time out; that send failing is the
        // expected outcome, not an error worth surfacing.
        let _ = tx.send(f());
    });
    rx.recv_timeout(deadline).ok()
}

/// Make one Trash call, with the process's FIRST one serialized so a dead
/// Finder is probed once and not once per concurrent caller.
///
/// `TRASH_UNRESPONSIVE` stops a second call paying the deadline - but only
/// once the first has finished paying it. The check and the latch are not
/// atomic, so any two callers that overlap both read it clear, both start
/// a probe, and both pay `TRASH_DEADLINE` in full. A queue soak on a
/// headless bench box caught exactly that: "the Trash is not responding"
/// printed twice in one leg, ~60 s added to a 208 s queue.
///
/// That soak ran before §64, when the finalize sweeps still called the
/// Trash inline, and two jobs finishing together was the way to reproduce
/// it. They park now (`remove_swept_file`), so sweeps are no longer the
/// overlap - but four callers still reach the Trash directly and three of
/// them are on different threads: the `deferred_trash` worker draining its
/// queue, `delete_filed_episode` filing into the user's library, the
/// watch-dir delete in `serve/tasks.rs`, and a sweep whose park failed
/// (read-only tree, EXDEV, no parent) falling back inline. A worker
/// mid-probe while an episode is filed is the same 2 x 30 s.
///
/// So whoever gets here first probes alone and everyone else waits for the
/// verdict instead of asking again. `Err(None)` is that verdict coming
/// back unresponsive: the caller made no call at all and must delete
/// directly. The latch is set before the gate is released, so a waiter
/// always sees it.
///
/// The gate costs a healthy Trash nothing beyond that first call: any
/// answer - even a failure - proves the backend is alive, and from then on
/// the gate is never taken again and deletes run as concurrently as they
/// always did. Deliberately not `cfg(macos)`: only macOS bounds the call,
/// but every platform reads the latch, and `trash::delete` is what it is.
///
/// The call is passed in rather than made here so the tests can supply one
/// that hangs - same reason `run_bounded` is split out. A Finder that does
/// not answer is the one case a healthy developer machine cannot produce.
fn trash_delete_gated(call: impl FnOnce() -> Result<(), String>) -> Result<(), Option<String>> {
    let _gate = if trash_answered() {
        None
    } else {
        let held = FIRST_TRASH_CALL.lock_ok();
        // Settled while we queued: the thread ahead of us got an answer, so
        // there is nothing left to serialize. Hand the gate straight on
        // rather than holding it across our own call.
        if trash_answered() { None } else { Some(held) }
    };
    // The check that got the caller here is stale - the thread ahead of us
    // may have latched the Trash off while we waited on the gate.
    if trash_unresponsive() {
        return Err(None);
    }
    let outcome = call();
    match &outcome {
        Err(e) if looks_like_a_trash_timeout(e) => {
            // Under the gate on purpose: every thread queued behind us
            // reads this the moment it wakes, and skips the Trash.
            TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        _ => TRASH_ANSWERED.store(true, std::sync::atomic::Ordering::Relaxed),
    }
    outcome.map_err(Some)
}

/// The two shapes a Trash call that gave up comes back as: the crate's own
/// wording, and the raw AppleEvent code behind it.
fn looks_like_a_trash_timeout(msg: &str) -> bool {
    msg.contains("timed out") || msg.contains("-1712")
}

/// Held for the duration of the process's first Trash call - see
/// `trash_delete_gated`. Never taken again once `TRASH_ANSWERED` is set.
static FIRST_TRASH_CALL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set once any Trash call has come back, success or ordinary failure:
/// proof the backend answers, and the point past which the first-call gate
/// has nothing left to protect.
static TRASH_ANSWERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn trash_answered() -> bool {
    TRASH_ANSWERED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Latched when a Trash call gives up waiting - and on macOS only once
/// BOTH routes have (`trash_delete_bounded` falls through to
/// `NSFileManager` before it reports a failure at all). Deliberately never
/// reset: a backend that timed out once will do it again, and each probe
/// costs up to `TRASH_DEADLINE` of a live job.
///
/// Read publicly as "is a recoverable delete actually available", which is
/// why a Finder failure must not set it: `FINDER_IS_OUT` covers that, and
/// the volume's own Trash still works.
static TRASH_UNRESPONSIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub fn trash_unresponsive() -> bool {
    TRASH_UNRESPONSIVE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Where a sweep of `dir` parks recoverable deletes: a hidden folder
/// BESIDE the swept directory, so the park is a same-volume rename.
///
/// Beside, not inside, for two reasons that are both load-bearing. Inside
/// the swept tree the sweep's own one-level descent would walk into it and
/// re-delete what it just parked. And `finalize_names` may move the whole
/// job directory (onto a NAS, into a season folder) the moment the sweep
/// returns - a parked file must stay put while that happens, or the queued
/// path goes stale and the junk rides along into the library.
/// pub(crate): the engine-side sweeps (spent obfuscated volumes in
/// unpack/obfuscated.rs, consumed adoption sources in get/settle.rs and
/// get/tail.rs) park the same way the finalize sweeps do, for the same
/// §64 reason - their deletes run in a job's tail, and an inline Trash
/// call is a Finder wait the job pays.
pub(crate) fn trash_staging_dir(dir: &Path) -> Option<PathBuf> {
    Some(dir.parent()?.join(".nzbfast-trash"))
}

/// The sweeps' delete: like `remove_user_file`, but a recoverable delete
/// is parked in `staging` for the background worker instead of talking to
/// the Trash inline. The rename is what actually empties the job
/// directory, and it is instant - so a slow Finder can no longer hold
/// `finalize_completed` (and with it the job's history entry) hostage.
/// See §64: the first Trash call of a headless process used to cost the
/// finalize path 30 s, and before the bound, minutes per file.
///
/// Any staging failure (no parent, EXDEV, a read-only tree) falls through
/// to the inline delete, which still works everywhere it used to.
pub(crate) fn remove_swept_file(
    path: &Path,
    recoverable: bool,
    staging: Option<&Path>,
) -> std::io::Result<Removed> {
    // When the latch is set there is no Trash to park FOR: the inline path
    // refuses and leaves the file, and a staging folder full of files
    // nobody will ever dispose of is worse than the file where it was.
    if recoverable
        && !trash_unresponsive()
        && let Some(root) = staging
        && deferred_trash::stage(path, root).is_ok()
    {
        // Staged, not yet disposed of. The worker decides the real
        // outcome later, so this promises nothing: the sweeps that use
        // this path do not report a fate to the user.
        return Ok(Removed::Gone);
    }
    remove_user_file(path, recoverable)
}

/// One background worker owns every conversation with the Trash, so no
/// job's finalize ever waits on Finder. See the module for the whole
/// rationale; it lives in its own file under the §91 rule.
mod deferred_trash;

/// Is the Trash somewhere the user can actually find and empty?
///
/// On macOS and Windows, yes: one Trash, one Recycle Bin, both in front
/// of the person the recoverability is for.
///
/// On Linux, no - and worse than no. When the download volume is not the
/// volume the home trash lives on (which is every NAS, every container,
/// every seedbox), the freedesktop rules send the file to a
/// `.Trash-<uid>` directory the crate CREATES at the top of the download
/// volume. So "recoverable" quietly means "moved to another folder on
/// the same disk, forever": the space never comes back, nothing in the
/// UI says where it went, and no desktop is running to empty it. It cost
/// a user their SSD a directory at a time, reported from Unraid on
/// 2 Aug 2026, and they left for another downloader over it.
///
/// So the recoverable default follows the platform, and Linux installs
/// delete outright unless the operator turns `delete_to_trash` back on.
/// Cleanup still tells the log what it removed either way.
///
/// FreeBSD is in the same carve-out for the same reason, not by analogy:
/// the `trash` crate routes every unix except macOS through its one
/// freedesktop backend, so a FreeBSD install reaches the identical
/// `.Trash-<uid>`-on-the-download-volume code, and the population that
/// runs nzbfast on FreeBSD - NAS boxes, jails, headless servers - is the
/// population with no desktop session to ever empty it.
const fn trash_suits_this_platform() -> bool {
    !cfg!(any(target_os = "linux", target_os = "freebsd"))
}

/// Process-global so the free functions in here need no Daemon handle.
///
/// Defaults OFF under `cfg(test)`: the cleanup suites delete hundreds of
/// fixture files, and with the Trash on they would empty them into the
/// developer's real ~/.Trash and race each other through this one flag.
/// The test that covers the Trash path opts in explicitly.
static TRASH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(!cfg!(test) && trash_suits_this_platform());
pub fn set_delete_to_trash(on: bool) {
    TRASH.store(on, std::sync::atomic::Ordering::Relaxed);
}
pub fn delete_to_trash() -> bool {
    TRASH.load(std::sync::atomic::Ordering::Relaxed)
}

/// Where CLEANUP deletes go - the garbage class: spent archive volumes
/// after a successful unpack, consumed adoption sources, sniffed
/// recovery files, and the junk sweep. Separate from `delete_to_trash`
/// (which keeps governing deletes of the downloads THEMSELVES - queue
/// and history deletes, watchlist upgrades, library episode drops)
/// because the two classes pull opposite ways: garbage is high-volume
/// and worthless-by-verdict (50 GB of spent volumes fills a Trash
/// nobody empties), while a deleted download is the user's own data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CleanupMode {
    /// Ride `delete_to_trash`, exactly the pre-setting behavior.
    Follow,
    /// Always recoverable, even when download deletes are permanent.
    Trash,
    /// Always permanent, even when download deletes go to the Trash.
    Delete,
}

impl CleanupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CleanupMode::Follow => "follow",
            CleanupMode::Trash => "trash",
            CleanupMode::Delete => "delete",
        }
    }
    pub fn parse(v: &str) -> Option<CleanupMode> {
        match v {
            "follow" => Some(CleanupMode::Follow),
            "trash" => Some(CleanupMode::Trash),
            "delete" => Some(CleanupMode::Delete),
            _ => None,
        }
    }
}

/// Process-global like `TRASH`, for the same reason. 0=follow 1=trash
/// 2=delete; default `follow` so an upgrade changes nobody's behavior.
static CLEANUP_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
pub fn set_cleanup_mode(m: CleanupMode) {
    let v = match m {
        CleanupMode::Follow => 0,
        CleanupMode::Trash => 1,
        CleanupMode::Delete => 2,
    };
    CLEANUP_MODE.store(v, std::sync::atomic::Ordering::Relaxed);
}
pub fn cleanup_mode() -> CleanupMode {
    match CLEANUP_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => CleanupMode::Trash,
        2 => CleanupMode::Delete,
        _ => CleanupMode::Follow,
    }
}

/// The `recoverable` flag a GARBAGE sweep should pass to
/// [`remove_user_file`] / [`remove_swept_file`]. Read once at a sweep's
/// entry, same contract as `delete_to_trash`.
pub fn cleanup_recoverable() -> bool {
    match cleanup_mode() {
        CleanupMode::Follow => delete_to_trash(),
        CleanupMode::Trash => true,
        CleanupMode::Delete => false,
    }
}

/// A scrap left inside an archive: no extension at all, and far too small
/// to be anything a user asked for, sitting next to an identified feature.
///
/// Found via a Supergirl release whose junk sweep left a 56-byte file
/// called `GqRTzbOIvUzZg1hqbipRind85vn` beside a 20 GB mkv. It is not in
/// the nzb - every POSTED file there is `30fb7ada….NN` or `.par2`, fully
/// obfuscated - so it came out of the RAR, packed by whoever made the
/// release. Nothing else in `sweep_junk` could see it: no extension to
/// match, not PAR2 magic, and not sample-shaped.
///
/// Kept deliberately narrow, because this is the rule most likely to eat
/// something real:
///  * no extension WHATSOEVER - an unknown extension is somebody's file,
///    and a subtitle or a companion track always has one;
///  * a hard byte ceiling, not a ratio - "small next to a 20 GB feature"
///    would cover a 20 MB file;
///  * only where a feature video was actually identified, so this cannot
///    fire on a music, book or software release, which is exactly where
///    extensionless files are legitimate;
///  * never anything that starts with an archive or media magic number,
///    however small.
fn is_nameless_scrap(p: &Path, ext: &str, feature_len: u64, recoverable: bool) -> bool {
    // ONLY when the delete can be undone. `sweep_junk_drops_extensionless_par2_by_magic`
    // pins the opposite rule - a hash-named blob that is NOT par2 stays,
    // because the magic decides and not the shape of the name - and that
    // invariant was written when a wrong guess was permanent. It still
    // holds wherever it still matters: with the Trash off (NAS, container)
    // this rule is simply not applied, and behaviour is exactly as before.
    if !recoverable || !ext.is_empty() || feature_len == 0 {
        return false;
    }
    let Ok(md) = std::fs::metadata(p) else {
        return false;
    };
    if md.len() > 4096 {
        return false;
    }
    let mut head = [0u8; 8];
    let read = std::fs::File::open(p)
        .and_then(|mut f| {
            use std::io::Read;
            f.read(&mut head)
        })
        .unwrap_or(0);
    let head = &head[..read];
    const MAGIC: &[&[u8]] = &[
        b"Rar!",
        b"PK\x03\x04",
        b"7z\xbc\xaf",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ",
        b"\x1aE\xdf\xa3",
        b"RIFF",
        b"%PDF",
        b"\x89PNG",
        b"\xff\xd8\xff",
        b"ID3",
    ];
    !MAGIC.iter().any(|m| head.starts_with(m))
}

/// Auto-rename companion: remove usenet furniture (`.par2`/`.nzb`/`.sfv`/
/// `.nfo`/…, see `JUNK_EXTS`) and sample/proof clips left beside the media,
/// top level + one subdir deep. Never deletes a subtitle, and never the
/// main feature (the largest video) - so a film literally titled "Sample"
/// survives. Returns how many files went.
pub fn sweep_junk(dir: &Path) -> usize {
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    let keep = largest_video(dir);
    let keep_len = keep
        .as_ref()
        .and_then(|p| p.metadata().ok())
        .map(|m| m.len())
        .unwrap_or(0);
    // Classify the whole sweep footprint BEFORE deleting any of it, so the
    // all-junk guard below can see the release as it stands rather than as
    // the sweep has already left it.
    let classify = |d: &Path, doomed: &mut Vec<PathBuf>, survivors: &mut usize| {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            if keep.as_ref() == Some(&path) {
                *survivors += 1;
                continue;
            }
            let ext = ext_of(&path);
            // Magic sniff only where the name has already failed to
            // identify the file: never open a video or a subtitle, so a
            // payload can't be reached by this path however it decodes.
            let sniffable =
                !VIDEO_EXTS.contains(&ext.as_str()) && !SUBTITLE_EXTS.contains(&ext.as_str());
            let junk = JUNK_EXTS.contains(&ext.as_str())
                || (sniffable && par2_magic(&path))
                || is_deletable_sample(&path, keep_len)
                || is_nameless_scrap(&path, &ext, keep_len, recoverable);
            if junk {
                doomed.push(path);
            } else {
                *survivors += 1;
            }
        }
    };
    let mut doomed: Vec<PathBuf> = Vec::new();
    let mut survivors = 0usize;
    classify(dir, &mut doomed, &mut survivors);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                classify(&path, &mut doomed, &mut survivors);
            }
        }
    }
    // A sweep that would delete EVERY file in the release does nothing.
    //
    // This function's premise is "keep the payload, drop the furniture
    // beside it" - and when every file it can see is furniture, the
    // premise does not hold: there is nothing here it can tell payload
    // FROM. Exactly the guard `keep_media_only` already applies when it
    // finds no video, and for the same reason. The shapes this bites are
    // real: a release whose whole payload is a text file (found 12 Aug on
    // the torture corpus, where the SFX set unpacked correctly and then
    // lost `test.txt.txt` to the `.txt` entry in JUNK_EXTS), an info-only
    // post, a release that is nothing but its own recovery set. An empty
    // output directory is a worse answer than one file the user can
    // delete, and unlike the delete it is not something they can undo.
    //
    // Deliberately all-or-nothing rather than "keep the largest": ranking
    // furniture invents a payload the sweep has no way to identify, and
    // leaves the other files gone. Skipping says what actually happened.
    if survivors == 0 && !doomed.is_empty() {
        info!(
            target: "cleanup",
            "junk sweep skipped in {}: all {} file(s) look like furniture, \
             and emptying the release is never the right answer",
            dir.display(),
            doomed.len()
        );
        prune_empty_dirs(dir, 0);
        return 0;
    }
    let mut removed = 0;
    for path in doomed {
        match remove_swept_file(&path, recoverable, staging.as_deref()) {
            Ok(_) => {
                info!(target: "cleanup", "junk {}", path.display());
                removed += 1;
            }
            Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
        }
    }
    prune_empty_dirs(dir, 0);
    removed
}

/// Aggressive cleanup: delete everything in `dir` that is NOT a video, a
/// subtitle / companion-track file, or a still-packed archive (top level +
/// one subdir deep). Keeps ALL real videos - a season pack stays whole -
/// but drops sample/proof clips. Returns the number of files removed.
///
/// A job with no video at all is left completely alone: see the guard.
pub fn keep_media_only(dir: &Path) -> usize {
    let mut removed = 0;
    // Read once, for the whole sweep: see `remove_user_file`.
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    // The feature size gates sample deletion: a same-size episode in a
    // "Proof"/"Sample" season pack is kept, only a small teaser is dropped.
    let Some(feature) = largest_video(dir) else {
        // No video anywhere in the job, so this function's premise - "keep
        // the media, drop the clutter beside it" - does not hold: there is
        // nothing here it can tell payload from clutter BY, so a music
        // album, an audiobook, a comic or an ebook release would be
        // deleted in full and the job would still report Completed over an
        // empty folder. Reached whenever a user category with base Movie
        // or Tv holds non-video content, which is most of them.
        //
        // This guard is necessary but NOT sufficient: one bonus .mp4 in
        // such a job passes it. That is what PAYLOAD_EXTS is for.
        info!(
            target: "cleanup",
            "keep-media-only: no video in {} - left alone",
            dir.display()
        );
        return 0;
    };
    let feature_len = feature.metadata().map(|m| m.len()).unwrap_or(0);
    let mut sweep = |d: &Path| {
        // Once per directory, not once per file: split sets are only
        // recognisable as sets.
        let zip_parts = zip_part_set(d);
        let mut split_parts = crate::container_part_set(d);
        split_parts.extend(crate::split_part_set(d)); // both readings, see `is_packed_archive`
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            let ext = ext_of(&path);
            let is_media =
                VIDEO_EXTS.contains(&ext.as_str()) && !is_deletable_sample(&path, feature_len);
            // Subtitles plus the disc-structure / companion-track files a
            // video payload is incomplete without - see MEDIA_COMPANION_EXTS.
            let is_companion = SUBTITLE_EXTS.contains(&ext.as_str())
                || MEDIA_COMPANION_EXTS.contains(&ext.as_str())
                || PAYLOAD_EXTS.contains(&ext.as_str());
            // An archive still sitting here is payload we could not
            // unpack, not clutter - see `is_packed_archive`. An
            // extensionless file that opens like a video is payload too,
            // just unpacked - see `looks_like_video_bytes`.
            if is_media
                || is_companion
                || is_packed_archive(&path, &zip_parts, &split_parts)
                || looks_like_video_bytes(&path)
            {
                continue;
            }
            match remove_swept_file(&path, recoverable, staging.as_deref()) {
                Ok(_) => {
                    info!(target: "cleanup", "non-media {}", path.display());
                    removed += 1;
                }
                Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
            }
        }
    };
    sweep(dir);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                sweep(&path);
            }
        }
    }
    prune_empty_dirs(dir, 0);
    removed
}

/// Move a finished job's tree into `dst`, merging with whatever is
/// already there (a Season folder on a NAS accumulates episodes across
/// jobs). Same-filesystem with no pre-existing destination = one rename;
/// a same-filesystem merge goes entry by entry, which is again nothing
/// but renames. Different filesystems - a NAS share is the whole point
/// of this helper - means the bytes have to be copied, so the tree is
/// staged beside the destination and published only once it is whole:
/// see [`staged_move`]. A name collision keeps the existing destination
/// file and lands ours beside it with a " (n)" suffix - completed
/// downloads are never overwritten. Empty source dirs are removed as
/// they drain.
/// Distinguishes the staging directories of concurrent moves that share a
/// destination. See [`move_tree`].
static MOVE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Dark knob: run the copy half of a move at background disk-I/O
/// priority. `NZBFAST_MOVE_IOPOL=throttle|utility|off` - unset means off
/// until the default is priced (see research/MOVE-INTERFERENCE-2026-08-05.md).
///
/// Only the COPY side is ever demoted. Renames are metadata and never
/// contend with a download's writes; the clone that `std::fs::copy` makes
/// on same-volume APFS is one too (measured: 4 GiB in 0.05 s with zero
/// foreground impact).
fn move_iopol() -> Option<&'static str> {
    match std::env::var("NZBFAST_MOVE_IOPOL").ok()?.as_str() {
        "throttle" => Some("throttle"),
        "utility" => Some("utility"),
        _ => None,
    }
}

/// Lower the calling thread's disk-I/O priority while a bulk copy runs,
/// and RESTORE it on drop: moves run on tokio's blocking pool, whose
/// threads are reused, so a policy left set would demote whatever
/// unrelated work lands on this thread next (a spool write, a directory
/// sweep, another job's unlock).
///
/// macOS: `setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, ..)` -
/// the mechanism Time Machine and Spotlight use, enforced in the kernel's
/// I/O scheduler. Linux: `ioprio_set` to the idle class, best effort (it
/// only shapes traffic under the CFQ/BFQ/mq-deadline schedulers; on none
/// it is a no-op, which is fine for an opt-in knob). Windows: not
/// implemented - `THREAD_MODE_BACKGROUND_BEGIN` also drops memory and
/// scheduling priority, which is a bigger hammer than this knob promises,
/// so it stays out until someone measures it.
struct BackgroundIo {
    #[cfg(target_os = "macos")]
    prev: i32,
    // `libc::syscall` is variadic and takes/returns `c_long`, which is
    // 32-bit on 32-bit Linux (armv7). Typing this i64 built fine on
    // x86_64/aarch64 and pushed 8-byte variadic args at a kernel wrapper
    // expecting longs on armv7 - where ARM EABI also 8-byte-aligns them,
    // so the restore would have addressed the wrong argument slots.
    #[cfg(target_os = "linux")]
    prev: libc::c_long,
}

#[cfg(target_os = "macos")]
mod iopol {
    pub const IOPOL_TYPE_DISK: i32 = 0;
    pub const IOPOL_SCOPE_THREAD: i32 = 1;
    pub const IOPOL_THROTTLE: i32 = 3;
    pub const IOPOL_UTILITY: i32 = 4;
    unsafe extern "C" {
        pub fn getiopolicy_np(iotype: i32, scope: i32) -> i32;
        pub fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
    }
}

impl BackgroundIo {
    /// Demote this thread per the knob; `None` when the knob is off (or
    /// the platform has nothing to set), which callers hold just the same.
    fn engage() -> Option<Self> {
        let which = move_iopol()?;
        #[cfg(target_os = "macos")]
        {
            let policy = if which == "throttle" {
                iopol::IOPOL_THROTTLE
            } else {
                iopol::IOPOL_UTILITY
            };
            // SAFETY: both calls take three ints and touch no memory of
            // ours. They act on the CALLING thread's own I/O policy,
            // which is what makes the paired restore in `Drop` correct -
            // see this type's doc comment.
            unsafe {
                let prev = iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD);
                if iopol::setiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD, policy)
                    != 0
                {
                    return None;
                }
                Some(Self { prev })
            }
        }
        #[cfg(target_os = "linux")]
        {
            // Both spellings demote to the idle class: Linux has no
            // in-between the knob's two names map onto cleanly, and
            // "utility" meaning "idle" beats the surprise of a knob that
            // works on one platform and silently not the other.
            let _ = which;
            const IOPRIO_WHO_PROCESS: libc::c_long = 1;
            const IOPRIO_CLASS_IDLE: libc::c_long = 3;
            // SAFETY: `syscall` is variadic, so the argument types have
            // to match the kernel's ABI by hand: both ioprio calls take
            // `long` arguments and return an int, which is what is
            // passed. Neither reads or writes user memory, and `who = 0`
            // means the calling thread, so this changes nothing outside
            // this process.
            unsafe {
                let prev =
                    libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0 as libc::c_long);
                if libc::syscall(
                    libc::SYS_ioprio_set,
                    IOPRIO_WHO_PROCESS,
                    0 as libc::c_long,
                    IOPRIO_CLASS_IDLE << 13,
                ) != 0
                {
                    return None;
                }
                Some(Self { prev })
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = which;
            None
        }
    }
}

impl Drop for BackgroundIo {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        // SAFETY: three ints, no memory touched, and it acts on the
        // calling thread - the same thread `engage` demoted, since this
        // guard is neither Send nor Sync by construction (it is held
        // across no await and moved to no other thread).
        unsafe {
            let _ =
                iopol::setiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD, self.prev);
        }
        #[cfg(target_os = "linux")]
        // SAFETY: as the macos arm above - a raw syscall taking only
        // integer arguments, touching no memory, and acting on the
        // calling thread, which is the same thread `engage` demoted
        // because this guard is neither Send nor Sync by construction.
        unsafe {
            const IOPRIO_WHO_PROCESS: libc::c_long = 1;
            let _ = libc::syscall(
                libc::SYS_ioprio_set,
                IOPRIO_WHO_PROCESS,
                0 as libc::c_long,
                self.prev,
            );
        }
    }
}

/// A pacing hook for the copy half of a move: called once per copied
/// chunk with its size, and free to sleep. See `Daemon::mover_pacer` -
/// the mover uses it so a NAS copy never slows a live download.
pub type PaceFn<'a> = dyn Fn(u64) + Send + Sync + 'a;

/// Name the failing step and its operand on an io::Error. A move is a
/// dozen different syscalls over two trees, and the bare "Permission
/// denied (os error 13)" one of them bubbled up on 7 Aug 2026 said
/// nothing about WHICH call on WHICH path refused - that cost hours
/// against a guest SMB mount. The original error rides along whole, so
/// the "(os error N)" substring `disk_full_failure` matches stays
/// present, and the kind is preserved for callers that match on it.
fn err_at(op: &str, path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{op} {}: {e}", path.display()))
}

/// [`err_at`] for the two-operand steps (copy, rename).
fn err_between(op: &str, from: &Path, to: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        e.kind(),
        format!("{op} {} -> {}: {e}", from.display(), to.display()),
    )
}

pub fn move_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    move_tree_paced(src, dst, None)
}

pub fn move_tree_paced(src: &Path, dst: &Path, pace: Option<&PaceFn<'_>>) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| err_at("create dir", parent, e))?;
    }
    if !dst.exists() {
        // Fast path: same filesystem, nothing to merge.
        if std::fs::rename(src, dst).is_ok() {
            return Ok(());
        }
    }
    // Staging is a sibling of the destination, so it shares the
    // destination's filesystem and everything published out of it is a
    // plain rename.
    //
    // The name identifies this MOVE, not the destination. Two jobs can
    // share a `dst` - with TV filing, every episode of a season lands in
    // the same `Season NN` folder - and their post-processing tails run
    // concurrently. A name derived from `dst` alone gave both of them one
    // staging directory, and each cleared it before staging its own tree:
    // one payload was published into the other's place, the loser's source
    // was then drained, and both jobs reported success. A hard kill now
    // leaves its staging directory behind rather than having the next move
    // to the same folder clear it, which costs disk space until it is
    // deleted and never costs a payload.
    let mut staging_name = std::ffi::OsString::from(".");
    staging_name.push(
        dst.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("job")),
    );
    staging_name.push(format!(
        ".moving.{}.{}",
        std::process::id(),
        MOVE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let staging = dst.with_file_name(staging_name);
    if !rename_reaches(src, &staging) {
        return staged_move(src, dst, &staging, pace);
    }
    std::fs::create_dir_all(dst).map_err(|e| err_at("create dir", dst, e))?;
    for entry in std::fs::read_dir(src).map_err(|e| err_at("read dir", src, e))? {
        let entry = entry.map_err(|e| err_at("read dir", src, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // `is_real_dir`, not `is_dir`: the latter follows symlinks, so a
        // job containing `extras -> /external` used to make this function
        // read_dir THROUGH the link and move the target's children into the
        // completed destination, deleting them from where they actually
        // lived. A link is moved as the link object it is, never walked.
        if is_real_dir(&from) {
            move_tree_paced(&from, &to, pace)?;
        } else {
            let target = reserve_free_name(&to)?;
            if std::fs::rename(&from, &target).is_err() {
                if is_symlink(&from) {
                    // Cross-device and a symlink: `copy` would follow it and
                    // write the TARGET's bytes here, so leave the link where
                    // it is rather than silently turning it into a fat copy
                    // of something outside the job.
                    let _ = std::fs::remove_file(&target); // our placeholder
                    warn!(
                        target: "move",
                        "left symlink in place (cross-device): {}",
                        from.display()
                    );
                    continue;
                }
                // One filesystem and the rename STILL failed, so fall back
                // to a copy for this file alone; make it durable before the
                // source goes. A failure in either half leaves `target`
                // holding zero, partial or unflushed bytes under the
                // payload's own file name, and an importer scanning the
                // destination would take that as the episode. The source
                // has not been touched yet at this point, so dropping our
                // half-written copy can never cost the only copy - the file
                // simply has not moved.
                let _bg = BackgroundIo::engage();
                let copied = copy_verified_paced(&from, &target, pace)
                    .and_then(|()| sync_written_file(&target));
                if let Err(e) = copied {
                    if let Err(rm) = std::fs::remove_file(&target) {
                        // Whatever broke the copy can break the unlink too
                        // (a share that dropped answers both with EIO), so
                        // say the fragment may still be sitting there.
                        warn!(
                            target: "move",
                            "could not remove the partial copy {}: {rm}",
                            target.display()
                        );
                    }
                    return Err(e);
                }
                std::fs::remove_file(&from)
                    .map_err(|e| err_at("remove copied source", &from, e))?;
            }
        }
    }
    let _ = std::fs::remove_dir(src); // only removes if now empty
    Ok(())
}

/// Can a rename move things out of `src` and into `probe_dst`'s directory,
/// or do the two sit on different filesystems?
///
/// Asked with an EMPTY directory of our own, never with payload: the probe
/// is created inside `src` and renamed to where the staging directory would
/// go. It decides only which of two correct routes [`move_tree`] takes, so
/// a wrong answer costs speed, not data - which is why this asks the
/// filesystem the exact question rather than approximating it from device
/// numbers that Windows does not expose.
fn rename_reaches(src: &Path, probe_dst: &Path) -> bool {
    let probe = src.join(".nzbfast-moving-probe");
    let _ = std::fs::remove_dir(&probe); // abandoned by an earlier crash
    if std::fs::create_dir(&probe).is_err() {
        return false;
    }
    let same = std::fs::rename(&probe, probe_dst).is_ok();
    let _ = std::fs::remove_dir(if same { probe_dst } else { &probe });
    same
}

/// The cross-device half of [`move_tree`]: copy the whole tree into
/// `staging`, publish it, and only then delete the source.
///
/// Copying file by file straight into `dst` is what used to SPLIT a payload
/// across two filesystems. Each source file was deleted the moment its copy
/// landed, so a failure partway (ENOSPC, EIO, a share that dropped) left
/// some episodes on the NAS and the rest in the download folder, while the
/// caller reported one directory as the job's home - an importer then took
/// whichever fragment it was pointed at as the whole release. Staging keeps
/// the source whole until the destination is, so a failure costs the move
/// and never the payload. It is the shape the spool migration already uses.
fn staged_move(
    src: &Path,
    dst: &Path,
    staging: &Path,
    pace: Option<&PaceFn<'_>>,
) -> std::io::Result<()> {
    // Held for the whole copy: this is the multi-GB bulk transfer that
    // competes with a live download's write side. Dropped before the
    // publish renames and the source drain - they are metadata and the
    // download should not have to wait behind an idle-class unlink queue.
    let bg = BackgroundIo::engage();
    let mut copied = std::collections::HashSet::new();
    if let Err(e) = copy_tree_into_paced(src, staging, &mut copied, pace).and_then(|()| {
        drop(bg);
        publish_staged(staging, dst)
    }) {
        // Nothing in `src` has been deleted, so the payload is still whole
        // where it was and the caller is right to report the move as not
        // taken. Drop what is still staged; note this cannot un-publish a
        // merge that failed part way, so `dst` may keep the entries that
        // were already renamed into it, under the payload's own names.
        // They are copies - the originals are all still in `src`.
        let _ = std::fs::remove_dir_all(staging);
        return Err(e);
    }
    drain_copied(src, &copied);
    Ok(())
}

/// Publish a staged tree into its final home. `staging` is a sibling of
/// `dst`, so every step is a same-filesystem rename: ONE for the whole
/// directory when nothing is there yet, and otherwise entry by entry so a
/// Season folder already holding episodes keeps them.
fn publish_staged(staging: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() && std::fs::rename(staging, dst).is_ok() {
        // Persist the name before the caller deletes the source.
        return sync_dir(dst.parent().unwrap_or(dst));
    }
    std::fs::create_dir_all(dst).map_err(|e| err_at("create dir", dst, e))?;
    for entry in std::fs::read_dir(staging).map_err(|e| err_at("read dir", staging, e))? {
        let entry = entry.map_err(|e| err_at("read dir", staging, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if is_real_dir(&from) {
            publish_staged(&from, &to)?;
        } else {
            let target = reserve_free_name(&to)?;
            if let Err(e) = std::fs::rename(&from, &target) {
                let _ = std::fs::remove_file(&target); // our placeholder
                return Err(err_between("publish rename", &from, &target, e));
            }
        }
    }
    let _ = std::fs::remove_dir(staging); // only removes if now empty
    sync_dir(dst)
}

/// Delete what [`copy_tree`] reproduced at the destination and leave what
/// it skipped. Symlinks are the reason it is not a `remove_dir_all`:
/// `copy_tree` does not follow them, so the link object here is still the
/// only one and stays put, exactly as a cross-device move has always left
/// it.
///
/// `copied` is the manifest [`copy_tree_into_paced`] filled in, and ONLY
/// those files are deleted. Re-walking the source instead deleted whatever
/// the walk found, including files that appeared AFTER the copy pass - a
/// post-processing script's output, a user's drop-in - which were therefore
/// deleted having never been copied anywhere, so they existed nowhere
/// afterwards. Anything not in the manifest stays where it is.
///
/// Best effort by design. The payload is already whole and durable at the
/// destination by the time this runs, so a source file that will not go is
/// clutter to report - failing the move over it would tell the caller
/// nothing had moved when everything had.
fn drain_copied(src: &Path, copied: &std::collections::HashSet<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(src) else {
        return;
    };
    for entry in rd.flatten() {
        let from = entry.path();
        if is_real_dir(&from) {
            drain_copied(&from, copied);
        } else if is_real_file(&from) {
            if !copied.contains(&from) {
                warn!(
                    target: "move",
                    "appeared after the copy, so it stays where it is: {}",
                    from.display()
                );
                continue;
            }
            if let Err(e) = std::fs::remove_file(&from) {
                warn!(
                    target: "move",
                    "copied, but the source stays: {} ({e})",
                    from.display()
                );
            }
        } else {
            warn!(
                target: "move",
                "left symlink in place (cross-device): {}",
                from.display()
            );
        }
    }
    let _ = std::fs::remove_dir(src); // only removes if now empty
}

/// Recursively COPY `src` into `dst`, fsyncing every file as it lands.
///
/// The copying twin of [`move_tree`], and the engine of its cross-device
/// path: for anything that must be able to fail without having touched the
/// source. Deleting each source file as soon as its copy is durable is what
/// leaves half the state at the destination and half at the source with no
/// single complete copy, so callers copy first and publish second.
/// Symlinks are skipped rather than followed, for the reason in
/// [`is_real_dir`].
pub fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_tree_into_paced(src, dst, &mut std::collections::HashSet::new(), None)
}

/// [`copy_tree`], recording every SOURCE file it actually reproduced in
/// `copied`. The record is what lets [`drain_copied`] delete exactly what
/// was copied and nothing that arrived later.
fn copy_tree_into_paced(
    src: &Path,
    dst: &Path,
    copied: &mut std::collections::HashSet<PathBuf>,
    pace: Option<&PaceFn<'_>>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| err_at("create dir", dst, e))?;
    for entry in std::fs::read_dir(src).map_err(|e| err_at("read dir", src, e))? {
        let entry = entry.map_err(|e| err_at("read dir", src, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if is_real_dir(&from) {
            copy_tree_into_paced(&from, &to, copied, pace)?;
        } else if is_real_file(&from) {
            copy_verified_paced(&from, &to, pace)?;
            sync_written_file(&to)?;
            copied.insert(from);
        }
    }
    sync_dir(dst)
}

/// `std::fs::copy`, refusing to call a short copy done. The source is
/// only ever deleted against what this wrote, so the check runs before
/// anything downstream can trust the destination: a filesystem that
/// silently truncated (an SMB share at quota, a FUSE layer that dropped
/// a write) must fail the move while the source is still whole, not be
/// discovered by the player. Sizes, not hashes - the byte-for-byte cost
/// belongs to the transports that are known to lie, and none of the
/// failures seen in the field so far kept the length intact.
/// [`copy_verified`], chunked and paced when a hook is supplied. The
/// manual 4 MiB loop exists for the pacing case only: fs::copy is one
/// opaque syscall-driven burst, and a cap that cannot breathe between
/// chunks is not a cap. No pace = the fast path, unchanged.
fn copy_verified_paced(from: &Path, to: &Path, pace: Option<&PaceFn<'_>>) -> std::io::Result<()> {
    let Some(pace) = pace else {
        return copy_verified(from, to);
    };
    use std::io::{Read, Write};
    let mut src = std::fs::File::open(from).map_err(|e| err_at("open source", from, e))?;
    let mut dst = std::fs::File::create(to).map_err(|e| err_at("create", to, e))?;
    let mut buf = vec![0u8; 4 << 20];
    let mut wrote: u64 = 0;
    loop {
        let n = src.read(&mut buf).map_err(|e| err_at("read", from, e))?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])
            .map_err(|e| err_at("write", to, e))?;
        wrote += n as u64;
        pace(n as u64);
    }
    dst.flush().map_err(|e| err_at("write", to, e))?;
    drop(dst);
    let want = std::fs::metadata(from)
        .map_err(|e| err_at("stat source", from, e))?
        .len();
    if wrote != want {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "short copy {} -> {}: wrote {wrote} of {want} bytes",
                from.display(),
                to.display()
            ),
        ));
    }
    Ok(())
}

fn copy_verified(from: &Path, to: &Path) -> std::io::Result<()> {
    let wrote = std::fs::copy(from, to).map_err(|e| err_between("copy", from, to, e))?;
    let want = std::fs::metadata(from)
        .map_err(|e| err_at("stat source", from, e))?
        .len();
    if wrote != want {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "short copy {} -> {}: wrote {wrote} of {want} bytes",
                from.display(),
                to.display()
            ),
        ));
    }
    Ok(())
}

/// fsync a directory, so the names created in it survive power loss.
///
/// Syncing a file persists its CONTENTS; the directory entry pointing at it
/// is separate metadata and needs its own flush. Without this a rename can be
/// reported successful and still be absent after a crash. Unix only - Windows
/// has no directory handle to flush this way, and `File::open` on a directory
/// fails there, so it is a deliberate no-op.
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| err_at("fsync dir", dir, e))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// fsync a file we have just written, addressed by its path.
///
/// The handle has to be WRITABLE. Unix flushes a read-only descriptor quite
/// happily, so `File::open(p)?.sync_all()` looked correct here for as long
/// as this code existed - but Windows answers `FlushFileBuffers` on a
/// read-only handle with ERROR_ACCESS_DENIED, and that one difference broke
/// every cross-device move and the spool migration on Windows. `copy_tree`
/// failed on the FIRST file it copied, so `staged_move` returned "Access is
/// denied." having moved nothing, and `spool_dir` logged that it could not
/// move the daemon state out of the download folder and carried on using
/// the old location. Neither ever lost a byte - both are written to fail
/// with the source still whole - but on Windows neither could ever succeed,
/// and a download folder and a library on two different drives is the
/// ordinary Windows setup.
///
/// Measured directly on x86-64 Windows (rustc 1.97.1): a read-only handle
/// gives os error 5, a writable one gives Ok(()).
fn sync_written_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // Deliberately unchanged: a read-only descriptor is a valid fsync
        // target here, and it flushes a mode-444 file, which opening for
        // write would not even be allowed to touch.
        std::fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| err_at("fsync", path, e))
    }
    #[cfg(not(unix))]
    {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(f) => return f.sync_all().map_err(|e| err_at("fsync", path, e)),
            // `fs::copy` reproduces the source's read-only ATTRIBUTE, and
            // such a file cannot be flushed through ANY handle on Windows.
            // Clear the bit, flush, put it back: we own this copy, and
            // skipping the flush instead would hand the caller an
            // undurable destination to delete the source against, which is
            // the one failure staging exists to prevent.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => return Err(e),
        }
        let md = std::fs::metadata(path).map_err(|e| err_at("stat", path, e))?;
        let mut relaxed = md.permissions();
        // clippy::permissions_set_readonly_false objects that this leaves a
        // file world-writable, which is a statement about Unix modes, and
        // this arm is `cfg(not(unix))`. On Windows it clears the read-only
        // ATTRIBUTE - the entire point of the block - and the original
        // permissions go back on after the flush. std exposes no other
        // stable way to touch that attribute.
        #[expect(clippy::permissions_set_readonly_false)]
        relaxed.set_readonly(false);
        std::fs::set_permissions(path, relaxed).map_err(|e| err_at("set permissions", path, e))?;
        let flushed = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| err_at("fsync", path, e));
        std::fs::set_permissions(path, md.permissions())
            .map_err(|e| err_at("set permissions", path, e))?;
        flushed
    }
}

/// Is this path a symlink (rather than what it points at)?
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// CLAIM the first free variant of `path`: itself, else "stem (2).ext",
/// "stem (3).ext", … The returned path exists as an empty file that this
/// call created and therefore owns.
///
/// Reserving matters because `exists()` is not an ownership primitive. The
/// old version only *looked* for a free name, so two movers racing the same
/// destination both saw "free" and both picked it: on unix the second
/// `rename` silently replaced the first's bytes, and both sources were then
/// deleted, so one payload was gone with both movers reporting success.
/// `create_new` is atomic, so exactly one caller can win each name.
fn reserve_free_name(path: &Path) -> std::io::Result<PathBuf> {
    use std::io::ErrorKind;
    let mut candidate = path.to_path_buf();
    let stem = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = path.parent().unwrap_or(Path::new(""));
    for n in 2.. {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                candidate = parent.join(format!("{stem} ({n}){ext}"));
            }
            Err(e) => return Err(err_at("reserve name", &candidate, e)),
        }
    }
    unreachable!()
}

/// File a completed TV job: move everything in `out_dir` into
/// `dest_parent/[Show]/Season NN/`, renaming video files to
/// "Show - S01E02[ suffix].ext" (each video's own name is parsed first, so
/// a season pack renames per episode; samples keep their names). `suffix`
/// is the auto-rename quality tag (" [1080p]"), or "" for none. Existing
/// targets are never overwritten. Returns the new directory, or None if
/// the stem didn't parse as TV (job left untouched).
///
/// `titles` decorates each episode with its own name when the cache knows
/// it ("Show - S01E02 - Children [1080p].mkv"); an empty one is the
/// ordinary case and leaves every name exactly as it was.
pub fn tv_organize(
    dest_parent: &Path,
    stem: &str,
    out_dir: &Path,
    suffix: &str,
    titles: &EpisodeTitles,
) -> Option<PathBuf> {
    let (subdir, job_base) = match tv_path(stem) {
        Some(t) => t,
        None => {
            info!(target: "smart", "{stem:?} didn't parse as TV - leaving it in place");
            return None;
        }
    };
    // A show already filed under the pre-sanitiser spelling of its name
    // ("Star Trek Discovery", before ": " became " - ") keeps that
    // folder: starting a second tree beside it splits the show in the
    // user's library. Judged on the SHOW folder, not the season one, so
    // a new season joins the show too - and only when today's spelling
    // has no folder yet and the old one does.
    let show_dir = |sub: &str| dest_parent.join(sub.split('/').next().unwrap_or(sub));
    let legacy = legacy_tv_path(stem)
        .filter(|(sub, _)| *sub != subdir && !show_dir(&subdir).is_dir() && show_dir(sub).is_dir());
    let filed_as_legacy = legacy.is_some();
    let (subdir, job_base) = legacy.unwrap_or((subdir, job_base));
    let dest = dest_parent.join(&subdir);
    if dest == out_dir {
        return None;
    }
    if let Err(e) = std::fs::create_dir_all(&dest) {
        warn!(target: "smart", "create {}: {e}", dest.display());
        return None;
    }
    let entries: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    // Plan the whole filing before moving anything. A canonical target
    // that already exists belongs to somebody else (usually the user's
    // existing library), and the old fallback moved our file under its raw
    // release name while later cleanup deleted that pre-existing canonical
    // file. On any collision, keep this job in its private directory where
    // ownership is exact and delete-with-files remains safe.
    let mut planned = Vec::with_capacity(entries.len());
    let mut targets = std::collections::HashSet::new();
    for path in entries {
        let orig_name = match path.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => continue,
        };
        let mut new_name = orig_name.clone();
        // True only when this entry became the canonical "Show - S01E02"
        // episode name; everything else keeps the name it arrived with.
        let mut is_canonical_video = false;
        if path.is_file() {
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let file_stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let is_sample = is_sample_named(&path);
            // The extension the filed episode must CARRY, which since #43
            // need not be the one it arrived with: an extensionless
            // payload takes the one its bytes sniff as. Filing it under
            // its hash instead put an unowned file in a SHARED season
            // folder - Play could not find it and delete-with-files
            // dropped the history row and left it there (Codex sweep 5,
            // M1). `ext` above is still the on-disk name, which is what
            // the non-video branches below key off.
            let ext = video_ext(&path).unwrap_or(ext);
            if VIDEO_EXTS.contains(&ext.as_str()) && !is_sample {
                // The file's own name wins (season packs), else the job's
                // - spelled the way the folder we are filing into is.
                let own = if filed_as_legacy {
                    legacy_tv_path(&file_stem)
                } else {
                    tv_path(&file_stem)
                };
                // Which stem the base came from decides which episode's
                // title belongs on it: a season pack's files each name
                // their own episode, and only when none of them does
                // (a single-episode job) does the job's stem answer.
                let (base, titled_by) = match own.and_then(|(_, b)| b) {
                    Some(b) => (Some(b), file_stem.as_str()),
                    None => (job_base.clone(), stem),
                };
                if let Some(b) = base {
                    let title = titles.segment(titled_by, &b, suffix);
                    new_name = format!("{b}{title}{suffix}.{ext}");
                    is_canonical_video = true;
                }
            }
        }
        let target = dest.join(&new_name);
        if target.exists() || !targets.insert(target.clone()) {
            // The canonical EPISODE name colliding means the season slot
            // belongs to somebody else - usually the user's existing
            // library. Filing beside it under a raw name is what let
            // cleanup delete their copy, so the whole job stays put.
            if is_canonical_video {
                info!(
                    target: "smart",
                    "{} already exists (or two job files map there) - \
                     leaving {:?} in its private folder",
                    target.display(),
                    stem
                );
                return None;
            }
            // Anything else - a shared Subs/ folder, a generic .nfo - is
            // not ours to own and is not what the delete bug was about.
            // Aborting the whole job for one of these silently stopped
            // every later episode of a season from filing at all: these
            // entries keep their original name, so the second episode
            // shipping Subs/ collided forever, with no UI signal.
            info!(
                target: "smart",
                "{} already exists - leaving it behind, still filing {:?}",
                target.display(),
                stem
            );
            continue;
        }
        planned.push((path, target));
    }
    // Returning Some() here is what makes the caller set `filed`, which
    // tells every later "delete this job's files" that this job OWNS the
    // canonical name in the shared season folder. A job that moved
    // nothing must never make that claim: cleanup matches by NAME, so it
    // would delete whichever episode really is there - the exact data
    // loss this planning step exists to prevent. Renames do fail in
    // ordinary life: a NAS blipping read-only, EXDEV on a category
    // folder symlinked to another volume, or a media server holding the
    // file open on Windows.
    let mut done: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(planned.len());
    let mut failed = None;
    for (path, target) in planned {
        // The plan's exists() check happened above, and `rename` REPLACES
        // an existing destination file. Finalize tails run on independent
        // tasks and can overlap - the runner tail, the idle sidecar tail,
        // the set_password unlock tail - so two jobs filing the same
        // episode both saw the slot free, the second silently overwrote
        // the first's bytes, and the first's private folder had already
        // been drained and removed. One payload gone, both jobs claiming
        // filed. Claim the name atomically first, the way move_tree does,
        // then rename over the placeholder we own.
        //
        // Files only. Renaming a directory onto a non-empty one fails
        // rather than replacing it, so a directory entry has nothing to
        // lose, and a placeholder FILE would break the rename outright.
        let mut placeholder = false;
        if !path.is_dir() {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
            {
                Ok(_) => placeholder = true,
                Err(e) => {
                    warn!(
                        target: "smart",
                        "{} was taken before {} could be filed: {e}",
                        target.display(),
                        path.display()
                    );
                    failed = Some(e);
                    break;
                }
            }
        }
        match std::fs::rename(&path, &target) {
            Ok(()) => done.push((path, target)),
            Err(e) => {
                warn!(
                    target: "smart",
                    "move {} → {}: {e}",
                    path.display(),
                    target.display()
                );
                // Our own placeholder would otherwise be left behind as a
                // zero-byte file wearing the episode's canonical name,
                // which later cleanup matches by name.
                if placeholder {
                    let _ = std::fs::remove_file(&target);
                }
                failed = Some(e);
                break;
            }
        }
    }
    if let Some(e) = failed {
        // Put back whatever did land, so the job is left exactly as it
        // was rather than split across two directories with an owner
        // nobody can determine. A rollback that itself fails is logged
        // and still refuses the claim - leaking a file is recoverable,
        // deleting the user's episode is not.
        for (path, target) in done.iter().rev() {
            if let Err(e2) = std::fs::rename(target, path) {
                warn!(
                    target: "smart",
                    "could not undo {} → {}: {e2} (file left in the season folder)",
                    path.display(),
                    target.display()
                );
            }
        }
        info!(
            target: "smart",
            "filing {stem:?} failed ({e}) - left in its private folder, \
             not claiming the season folder"
        );
        return None;
    }
    // Filing NOTHING is not filing. `planned` is empty whenever the job
    // has no entries left to place - most easily an all-junk repost
    // (NFOFIX/DIRFIX/PROOF: only .nfo/.sfv/.par2), because sweep_junk
    // runs first and empties out_dir. Falling through here returned the
    // shared season folder, which makes the caller set `filed`, and
    // delete_filed_episode then matches by canonical NAME and removes the
    // user's real copy of that episode for a job that moved zero bytes.
    //
    // This is the same ownership invariant as the rollback above - the
    // earlier fix enforced only its failed-rename half.
    if done.is_empty() {
        info!(
            target: "smart",
            "nothing to file for {stem:?} - leaving it in its private folder \
             rather than claiming {}",
            dest.display()
        );
        return None;
    }
    let moved = done.len();
    // Only vanishes if everything left it.
    let _ = std::fs::remove_dir(out_dir);
    info!(target: "smart", "filed {moved} item(s) → {}", dest.display());
    Some(dest)
}

/// Auto-rename for TV when the job ISN'T being Season-filed: rename video
/// files IN PLACE to "Show - S01E02[ title][ suffix].ext" (season packs
/// rename per episode; samples untouched). Never overwrites an existing
/// target. Returns how many files were renamed.
pub fn tv_rename(dir: &Path, stem: &str, suffix: &str, titles: &EpisodeTitles) -> usize {
    let job_base = tv_path(stem).and_then(|(_, b)| b);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    // PLAN, then rename. Every file that cannot name its own episode
    // falls back to the job's base, so they all compute the SAME target
    // and `read_dir` order decided which one got it - a sniffable sample
    // beside a hash-named feature could take the episode name and become
    // what Play offers, leaving the real feature under its hash. Sample
    // names are excluded here by NAME alone, because since #43 they need
    // not carry an extension (Codex sweep 5, M4).
    let mut plan: Vec<(PathBuf, String, String, String)> = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() || is_sample_named(&path) {
            continue;
        }
        // The extension the renamed file must carry. An extensionless
        // obfuscated payload takes the one its bytes sniff as, so this
        // pass stops skipping the very file the job is about (#43).
        let Some(ext) = video_ext(&path) else {
            continue;
        };
        let file_stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        // As in `tv_organize`: the stem that named the episode is the
        // stem whose title belongs on it.
        let (base, titled_by) = match tv_path(&file_stem).and_then(|(_, b)| b) {
            Some(b) => (Some(b), file_stem.clone()),
            None => (job_base.clone(), stem.to_string()),
        };
        let Some(b) = base else { continue };
        plan.push((path, ext, b, titled_by));
    }
    // One winner per target: the largest candidate. A teaser that slipped
    // past the name check is smaller than the feature, so size is the
    // tie-break that keeps the feature.
    plan.sort_by_key(|(p, ..)| {
        std::cmp::Reverse(std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
    });
    let mut claimed: Vec<String> = Vec::new();
    let mut renamed = 0;
    for (path, ext, b, titled_by) in plan {
        let title = titles.segment(&titled_by, &b, suffix);
        let name = format!("{b}{title}{suffix}.{ext}");
        let target = dir.join(&name);
        if target == path || target.exists() || claimed.iter().any(|c| c == &name) {
            continue;
        }
        claimed.push(name);
        match std::fs::rename(&path, &target) {
            Ok(()) => renamed += 1,
            Err(e) => warn!(
                target: "smart",
                "rename {} → {}: {e}",
                path.display(),
                target.display()
            ),
        }
    }
    renamed
}

/// A file stem that carries no identity at all: the encoder's default
/// output name, or a bare index from a batch. Exact, case-insensitive,
/// closed list plus one- and two-digit stems - nothing fuzzier, because
/// every entry here is a licence to overwrite a name someone may have
/// chosen. "Movie 2024" and "video_final" are NOT generic; they say
/// something, so they stand.
fn is_generic_stem(stem: &str) -> bool {
    let s = stem.trim();
    if matches!(s.len(), 1 | 2) && s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    matches!(
        s.to_ascii_lowercase().as_str(),
        "movie" | "video" | "film" | "output" | "encoded" | "media"
    )
}

/// The part of a sidecar's filename that follows the video's stem
/// (".en.srt"), or None when the sidecar is not this video's at all.
///
/// The boundary is the whole point: a bare `strip_prefix` was safe only
/// while the stem had to be a long obfuscated blob, and with generic
/// stems ([`is_generic_stem`]) in play the video "1.mkv" claimed
/// "10.srt" and "12.srt" and fused their leftover digit onto the new
/// name ("Example.Movie.2024…-GRP0.srt"). The remainder has to start at
/// an extension boundary for the sidecar to be ours.
fn sidecar_tail<'a>(fname: &'a str, stem: &str) -> Option<&'a str> {
    fname
        .strip_prefix(stem)
        .filter(|rest| rest.starts_with('.'))
}

/// Does this release name say enough to be worth stamping onto a
/// payload? A non-empty parsed title plus at least one hard provenance
/// fact - resolution, source or group. Port of Sonarr's scene-title
/// check, and like it we prefer false negatives: a name that fails here
/// costs the user an ugly filename, a name that wrongly passes costs
/// them a wrong one.
fn names_the_release(name: &str) -> bool {
    let p = crate::wall::parse_release(name);
    !p.title.trim().is_empty() && (p.res.is_some() || p.source.is_some() || p.group.is_some())
}

/// Last resort for a payload we could not name cleverly: if the main
/// video is still wearing an obfuscated stem, give it the release's own
/// name.
///
/// The smart renamers decline on purpose in several places - an event
/// post whose identity lives after the year ("Formula1.2026.Round11…"),
/// a release with no year and no quality facts, a category that declared
/// no base behaviour. Every one of those declines rests on the same
/// assumption: that leaving the file alone means leaving the POSTER'S
/// name on it, which is a name a human chose. When the post is
/// obfuscated that assumption is simply false, and declining hands the
/// user "1fRbH6e0eX8v5hv7fSyXgBb.mkv" while the folder beside it reads
/// perfectly. So: no clever name available AND nothing worth keeping ->
/// use the release name, which is informative and, unlike a reduced
/// "Title (Year)", still unique per round/episode/event.
///
/// The same argument covers the stem that is not obfuscated but says
/// nothing either: "movie.mkv", "video.mkv", "1.mkv". Those are the
/// encoder's default output name, not a name a human chose for THIS
/// post, so there is nothing to preserve. The list is exact and closed
/// (see [`is_generic_stem`]) - a stem we do not recognise keeps its name.
///
/// Widening what we fire on has to be paid for on the other side, so the
/// release name now has to earn the job: it must parse to a non-empty
/// title AND carry at least one hard provenance fact (resolution, source
/// or group). "Example Movie" with no facts is somebody's folder label,
/// and stamping it onto the payload is not an improvement worth the risk
/// of being wrong.
///
/// Returns true when it renamed something. Deliberately narrow: one
/// non-sample video, a stem worth replacing, and a target that does not
/// already exist.
pub fn rename_obfuscated_video(out_dir: &Path, base: &str) -> bool {
    if base.trim().is_empty() || nzbkit::release::looks_obfuscated(base) {
        return false; // nothing better to offer than what is already there
    }
    if !names_the_release(base) {
        return false; // too little in the release name to trust it
    }
    rename_nameless_video(out_dir, base)
}

/// The lone still-nameless feature video in `dir`, or `None`.
///
/// "Nameless" is the exact condition [`rename_obfuscated_video`] fires
/// on - one non-sample video whose stem is either obfuscated or one of
/// the encoder defaults that say nothing - factored out because
/// synthesised naming has to ask the same question BEFORE it spends any
/// network: there is no point identifying a film whose file already
/// carries a name a human chose.
pub fn nameless_video(dir: &Path) -> Option<PathBuf> {
    let videos: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        // By NAME, like every other rename path: since #43 a sample need
        // not carry an extension, and an extensionless `sample` that
        // sniffs as EBML counted as a second video here - so the lone
        // feature stopped being lone, this returned None, and the
        // feature kept its hash through both identify and synthesised
        // naming (Codex sweep 6, N1). The DELETE sweep stays on
        // `is_sample_clip`; nothing here removes a file.
        .filter(|p| p.is_file() && !is_sample_named(p) && video_ext(p).is_some())
        .collect();
    // More than one and we cannot tell which is the feature; renaming
    // either would be a guess, and CD1/CD2 sets collide.
    let [video] = videos.as_slice() else {
        return None;
    };
    let name = video.file_name()?.to_string_lossy().into_owned();
    let stem = name
        .strip_suffix(&format!(".{}", ext_of(video)))
        .unwrap_or(&name)
        .to_string();
    // The poster named it something: that name stands, whatever a
    // catalogue might have offered.
    (nzbkit::release::looks_obfuscated(&stem) || is_generic_stem(&stem)).then(|| video.clone())
}

/// Put `base` on the lone still-nameless video in `out_dir`, carrying
/// its subtitle sidecars.
///
/// Split from [`rename_obfuscated_video`] so that synthesised naming
/// reaches the same apply path. The two differ only in where the name
/// came from and therefore in what has to be proven about it first: a
/// release name has to earn the job by carrying provenance facts (see
/// [`names_the_release`]), while an identified film's name has already
/// been earned by the acceptance gate - which is a far higher bar, and
/// one a title like "Supergirl 2026" could never clear by grammar
/// alone.
pub fn rename_nameless_video(out_dir: &Path, base: &str) -> bool {
    let files: Vec<PathBuf> = match std::fs::read_dir(out_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => return false,
    };
    let Some(video) = nameless_video(out_dir) else {
        return false;
    };
    let video = &video;
    // Two different extensions, and conflating them is what produced a
    // trailing-dot name: `ext` is what the TARGET must carry (sniffed
    // from the bytes when the payload arrived with none), while the stem
    // strip has to use what is actually ON DISK - for an extensionless
    // file that is nothing, so the whole filename is the stem.
    let Some(ext) = video_ext(video) else {
        return false;
    };
    let on_disk = ext_of(video);
    let Some(old_name) = video.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    let old_stem = if on_disk.is_empty() {
        old_name.clone()
    } else {
        old_name
            .strip_suffix(&format!(".{on_disk}"))
            .unwrap_or(&old_name)
            .to_string()
    };
    let clean = nzbkit::release::sanitize_name(base);
    if clean.is_empty() {
        return false; // nothing nameable survived sanitisation
    }
    let target = out_dir.join(format!("{clean}.{ext}"));
    if target == *video || target.exists() {
        return false;
    }
    if let Err(e) = std::fs::rename(video, &target) {
        warn!(
            target: "smart",
            "rename {} -> {}: {e}",
            video.display(),
            target.display()
        );
        return false;
    }
    info!(target: "smart", "de-obfuscated {} -> {}", old_name, target.display());
    // Carry subtitle sidecars along, keeping their language tail.
    for f in &files {
        if !SUBTITLE_EXTS.contains(&ext_of(f).as_str()) {
            continue;
        }
        let Some(fname) = f.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if let Some(rest) = sidecar_tail(&fname, &old_stem) {
            let subtarget = out_dir.join(format!("{clean}{rest}"));
            if subtarget != *f && !subtarget.exists() {
                let _ = std::fs::rename(f, &subtarget);
            }
        }
    }
    true
}

/// Auto-rename a completed MOVIE / loose-file job to the friendly `base`
/// (already computed by `wall::movie_name`, path-safe, no extension):
/// 1. if the job has exactly ONE top-level feature video, rename it to
///    `base.ext` and re-stem its subtitle sidecars (`.en.srt` kept);
///    multiple videos (CD1/CD2 etc.) are left alone to avoid collisions;
/// 2. rename the job folder to `parent/base`, with `.2`/`.3` collision
///    suffixes - an existing folder is never overwritten.
/// Returns the new out_dir when the folder moved, else None (caller keeps
/// the current path).
pub fn rename_movie(parent: &Path, out_dir: &Path, base: &str) -> Option<PathBuf> {
    // `base` arrives path-safe from `movie_name`, but this is the last
    // point before it becomes a real file stem AND a real folder name, and
    // callers other than finalize_names reach it. Re-running the sanitiser
    // is idempotent, so the cost is one pass over a short string.
    let clean = nzbkit::release::sanitize_name(base);
    if clean.is_empty() {
        return None;
    }
    let base = clean.as_str();
    let files: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    // `video_ext`, not VIDEO_EXTS: an extensionless payload is a video
    // since #43, and selecting on the NAME alone meant the ordinary movie
    // arm saw zero features, renamed the job folder, and left the feature
    // inside it under its hash - while the fallback that would have
    // handled it runs only when `movie_name` returned None (Codex sweep
    // 5, M2). Sample exclusion is by name, for the same reason.
    let videos: Vec<&PathBuf> = files
        .iter()
        .filter(|p| video_ext(p).is_some() && !is_sample_named(p))
        .collect();
    if videos.len() == 1 {
        let video = videos[0];
        // The extension it must CARRY, which for a nameless payload is
        // the sniffed one - the rename below is what gives it that.
        let ext = video_ext(video).unwrap_or_else(|| ext_of(video));
        let old_name = video
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())?;
        // Strip the trailing ".ext" to get the stem prefix subtitles share.
        let old_stem = old_name
            .strip_suffix(&format!(".{ext}"))
            .unwrap_or(&old_name)
            .to_string();
        let target = out_dir.join(format!("{base}.{ext}"));
        if target != *video
            && !target.exists()
            && let Err(e) = std::fs::rename(video, &target)
        {
            warn!(
                target: "smart",
                "rename {} → {}: {e}",
                video.display(),
                target.display()
            );
        }
        // Subtitle sidecars whose name starts with the old video stem:
        // "Stem.en.srt" → "base.en.srt", preserving the language tail.
        for f in &files {
            if !SUBTITLE_EXTS.contains(&ext_of(f).as_str()) {
                continue;
            }
            let fname = match f.file_name() {
                Some(n) => n.to_string_lossy().into_owned(),
                None => continue,
            };
            if let Some(rest) = sidecar_tail(&fname, &old_stem) {
                let subtarget = out_dir.join(format!("{base}{rest}"));
                if subtarget != *f && !subtarget.exists() {
                    let _ = std::fs::rename(f, &subtarget);
                }
            }
        }
    }
    // Rename the folder itself.
    nzbname::rename_dir(parent, out_dir, base)
}

// ---------------------------------------------------------------------------
// M24 passworded archives (the survey's #2 Usenapp borrow)
// ---------------------------------------------------------------------------

/// Read a SAB/NZBGet-compatible passwords file: plain text, one
/// password per line, tried top to bottom. Surrounding whitespace is
/// stripped and blank lines are skipped - SABnzbd's exact reading
/// (`misc.get_all_passwords` strips `"\r\n "`), and a superset of
/// NZBGet's (UnpackController trims trailing CR/LF only), so one file
/// serves all three programs. No comment syntax on purpose: both
/// competitors treat every non-blank line as a password, and a `#`
/// convention here would make a shared file try that line there.
/// A missing or unreadable file is an empty list, never an error - the
/// file is optional and the operator may delete it.
pub fn read_password_file(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

// Where the operator's passwords file lives for the code that cannot
// reach the daemon, and the non-RAR half of `unlock`.
mod unlockpw;
// `encrypted_rar` is not re-exported: its one caller outside the module
// is `unlock`, which lives down there with it now, and the scan test
// reaches it by path.
pub use unlockpw::{encrypted_archive, operator_passwords, set_operator_password_file, unlock};

// §99: the try-order heuristic over that file - remember which
// password unlocked which site's / poster's downloads and try the
// likely line first.
mod pwassoc;
pub use pwassoc::{dominant_poster, nzb_poster, order_passwords, record_password_assoc};

// Child module files, not inline: the cases below were most of this
// file's length and smart.rs sits under a size-gate baseline (TODO
// 106), same pattern as cleanup_mode_tests.rs. Two of them because one
// was 3,264 lines - over the gate's own ceiling - so the split is by
// topic: filing and the mover in `tests`, sweeping and renaming in
// `sweep_rename_tests`, with what both need in `testkit`.
mod sample;
pub(crate) use sample::skippable_samples;
use sample::{is_deletable_sample, is_sample_clip, is_sample_named};
mod audioname;
pub use audioname::rename_obfuscated_audio;
mod videoext;
use videoext::video_ext;

#[cfg(test)]
mod sweep_rename_tests;
#[cfg(test)]
mod testkit;
// The trash tests' process-global serialisation lives in testkit (it is
// test-only, and testkit is already the test-only module), but its
// callers are spread across smart's four test children AND
// serve/tests_jobs.rs. Re-exported here so every one of them keeps
// reaching it at the path it always used.
#[cfg(test)]
pub(crate) use testkit::{
    force_trash_unresponsive, one_trash_test_at_a_time, trash_globals_steady,
};
#[cfg(test)]
mod tests;

#[cfg(test)]
mod trash_tests;

/// Put the configured permissions on a finished download (#20).
///
/// `umask` is the same number the shell and the linuxserver containers
/// use, because that is what every guide about this prints: directories
/// get `0o777 & !umask`, files `0o666 & !umask`, so the recommended `002`
/// gives 775/664 and today's `0022` gives 755/644.
///
/// `root` is the job's final directory and is walked in full. `up_to` is
/// the download root, and the directories BETWEEN the two get the
/// directory mode as well - non-recursively, so nothing else living under
/// them is touched. That part is not decoration: to import by renaming,
/// an *arr has to unlink the job directory out of its parent, and unlink
/// needs write permission on the PARENT, not on the directory being
/// moved. Setting only the job's own tree produces a download the *arr
/// can read and still cannot import.
///
/// Errors are logged once and otherwise swallowed. A mode we could not
/// set is a slower import, while refusing to finish the job over it would
/// turn a permissions preference into a failed download.
#[cfg(unix)]
pub fn apply_out_umask(root: &std::path::Path, up_to: Option<&std::path::Path>, umask: u32) {
    use std::os::unix::fs::PermissionsExt;
    let dir_mode = 0o777 & !umask;
    let file_mode = 0o666 & !umask;
    let mut failed: Option<String> = None;
    let mut chmod = |p: &std::path::Path, mode: u32| {
        if let Err(e) = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
            && failed.is_none()
        {
            failed = Some(format!("{}: {e}", p.display()));
        }
    };
    // The job's own tree.
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        chmod(&dir, dir_mode);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            // symlink_metadata: never follow a link out of the tree and
            // re-mode whatever it points at.
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => stack.push(p),
                Ok(m) if m.is_file() => chmod(&p, file_mode),
                _ => {}
            }
        }
    }
    // ...and every directory between it and the download root, so the
    // *arr can rename the job out of the one holding it.
    if let Some(stop) = up_to {
        let mut cur = root.parent();
        while let Some(p) = cur {
            if !p.starts_with(stop) {
                break;
            }
            chmod(p, dir_mode);
            if p == stop {
                break;
            }
            cur = p.parent();
        }
    }
    if let Some(first) = failed {
        tracing::warn!(target: "disk", "could not set output permissions ({first})");
    }
}

/// Windows has no mode bits; the setting is stored and reported so a
/// config survives a round trip through either platform.
#[cfg(not(unix))]
pub fn apply_out_umask(_root: &std::path::Path, _up_to: Option<&std::path::Path>, _umask: u32) {}

#[cfg(all(test, unix))]
mod out_umask_tests;

// Child module file, not inline: smart.rs sits under a size-gate
// baseline (TODO 106) and test growth belongs beside it, same pattern
// as pool/unit_tests.rs.
#[cfg(test)]
mod cleanup_mode_tests;

// TODO 142 / issue #32: naming a finished job after its .nzb file, and
// the folder rename it shares with `rename_movie`. A production child
// module for the same size-gate reason.
pub mod nzbname;
pub use nzbname::rename_from_nzb;
