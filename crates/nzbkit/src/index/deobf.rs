//! Prototype of the two jobs people mix up when they say "indexers
//! deobfuscate".
//!
//! Job 1 is glue: turn header rows into an NZB. nZEDb's CollectionKey
//! (leftover token + group id + part-total) does this. A stable Nyuu
//! hash filename glues; a pesto random-per-article subject does not.
//! Glue is not a title.
//!
//! Job 2 is naming: put a human title on that NZB. Commercial sites are
//! TOLD the title (uploader NZB, ngPost, filename import). The join
//! that makes that title stick to a dark scan row is the msgid-set
//! quorum already shipped as `corr_confirm_once`. This module extracts
//! that join so it can be tested without a daemon or a live indexer.
//!
//! Do not treat leftover grouping as a dehasher. Glue is not a title.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};

use super::*;
use crate::nzbimport::{MIN_MSGID_QUORUM, nzb_identity};
use claims::{NameClaim, NameEvidence, ProvenOutcome, msgid_set_key};
use ingest::{quoted_name, session_tag, split_subject, stem_obfuscated};

/// nZEDb-shaped collection identity: the leftover subject token, the
/// group, and the `(part/total)` denominator. Articles with no counter
/// still get a collection (`part_total = 0`), matching nZEDb.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CollectionKey {
    pub leftover: String,
    pub group: String,
    pub part_total: u32,
}

/// Leftover token + part-total from one OVER subject.
///
/// This is the cheap half of nZEDb `collectionsCleaner`: quoted yEnc
/// filename if present, else the first non-furniture token. It is NOT
/// the 1,157-regex cleaner and is not trying to be. The quoted-name
/// path is what Nyuu `-hp` still gives you (stable hash filename);
/// the blob path is what pesto randomizes per article.
pub fn leftover_token(subject: &str) -> (String, u32) {
    let (base, total) = match split_subject(subject) {
        Some((base, _, total)) => (base, total),
        None => (subject.to_string(), 0),
    };
    if let Some(name) = quoted_name(subject).or_else(|| quoted_name(&base)) {
        return (name, total);
    }
    let tok = base
        .split_whitespace()
        .find(|t| {
            !t.eq_ignore_ascii_case("yenc")
                && !t.starts_with('[')
                && !t.starts_with('<')
                && t.chars().any(|c| c.is_ascii_alphanumeric())
        })
        .unwrap_or(base.trim())
        .to_string();
    (tok, total)
}

/// True only when the leftover token already looks like a release
/// title. Hash filenames, mixed-case blobs, and hex stems fail this:
/// grouping them produced an NZB, not a name.
pub fn leftover_is_a_title(leftover: &str) -> bool {
    if leftover.is_empty() {
        return false;
    }
    let stem = crate::names::release_stem(leftover);
    let p = crate::release::parse_release(&stem);
    !stem_obfuscated(&stem, &p)
}

/// Same 4 h window `session.rs` uses for sibling association. A size+date
/// hunt around a dark row is looking for the NZB that posting produced,
/// not a neighbour from a different day.
pub const HUNT_TIME_WINDOW: i64 = 4 * 3600;

/// Size slack floor: 1 MB. nzbindex coarsens size filters to MB; 5% of
/// a 4 GB row is 200 MB, so this only binds on small payloads.
pub const HUNT_MIN_SLACK: u64 = 1_000_000;

/// Size slack is 1/`HUNT_SIZE_SLACK_DIV` of the payload (5%).
pub const HUNT_SIZE_SLACK_DIV: u64 = 20;

/// Indexer search params for a dark row that has no corr-suggested
/// title. `q` is empty for a size+date hunt (F5 item 2's quota-expensive
/// path) and is a leftover token or a parsed next-episode string when
/// those exist.
///
/// Times are unix seconds. Newznab `minage`/`maxage` are days and
/// nzbindex size filters are MB; a production mapper has to coarsen.
/// This type does not change `SearchQuery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuntQuery {
    pub q: String,
    pub min_bytes: u64,
    pub max_bytes: u64,
    pub posted_from: i64,
    pub posted_to: i64,
    /// Empty means unconstrained. Newznab listings often carry
    /// `<poster>`; a size+date window of identical scene titles still
    /// splits when the dark row's poster is unique among the hits.
    pub poster: String,
}

/// Size+date window around a dark row. Empty `q`: there is no title to
/// search. Slack is 5% of the payload, floored at [`HUNT_MIN_SLACK`].
pub fn hunt_from_dark(total_bytes: u64, first_posted: i64) -> HuntQuery {
    let slack = (total_bytes / HUNT_SIZE_SLACK_DIV).max(HUNT_MIN_SLACK);
    HuntQuery {
        q: String::new(),
        min_bytes: total_bytes.saturating_sub(slack),
        max_bytes: total_bytes.saturating_add(slack),
        posted_from: first_posted.saturating_sub(HUNT_TIME_WINDOW),
        posted_to: first_posted.saturating_add(HUNT_TIME_WINDOW),
        poster: String::new(),
    }
}

/// [`hunt_from_dark`] plus a poster constraint. Empty poster is the
/// unconstrained hunt. Does not change [`hunt_for_dark`].
pub fn hunt_from_dark_with_poster(total_bytes: u64, first_posted: i64, poster: &str) -> HuntQuery {
    let mut q = hunt_from_dark(total_bytes, first_posted);
    q.poster = poster.trim().to_string();
    q
}

/// Use a leftover token as an indexer `q=`. Dump sites that index the
/// posted filename can hit on that; the leftover is still not a title.
pub fn leftover_as_query(leftover: &str) -> HuntQuery {
    HuntQuery {
        q: leftover.trim().to_string(),
        min_bytes: 0,
        max_bytes: u64::MAX,
        posted_from: i64::MIN,
        posted_to: i64::MAX,
        poster: String::new(),
    }
}

/// D1 wanted-title hunt: the user already named what they want, so
/// `q=` is a search string again. Same join as F5 item 1; this only
/// builds the query. Does not change `SearchQuery`.
pub fn hunt_wanted(title: &str) -> HuntQuery {
    leftover_as_query(title)
}

/// Per-row pick for a standalone dark wall row. A leftover that already
/// looks like a title is a dump-site `q=` (unconstrained size/age). A
/// hash leftover has no search string, so size+date. Does not change
/// `hunts_from_dark_siblings`: those siblings are obfuscated by
/// construction and must not copy the named neighbour's title.
pub fn hunt_for_dark(leftover: &str, total_bytes: u64, first_posted: i64) -> HuntQuery {
    if leftover_is_a_title(leftover) {
        leftover_as_query(leftover)
    } else {
        hunt_from_dark(total_bytes, first_posted)
    }
}

/// Newznab `minage`/`maxage` are whole days. Floor/ceil the unix window
/// so a mapper that only has days still includes every row the unix
/// window would have, including a catalog `pubDate` stored at midnight.
pub fn coarsen_age_days(mut q: HuntQuery) -> HuntQuery {
    const DAY: i64 = 86_400;
    if q.posted_from != i64::MIN {
        q.posted_from = q.posted_from.div_euclid(DAY) * DAY;
    }
    if q.posted_to != i64::MAX {
        q.posted_to = q.posted_to.div_euclid(DAY) * DAY + (DAY - 1);
    }
    q
}

/// nzbindex size filters are whole MB (decimal, same unit as
/// [`HUNT_MIN_SLACK`]). Floor min, ceil max so a mapper that only has
/// MB still includes every row the byte window would have. Leaves 0 /
/// [`u64::MAX`] alone (unconstrained leftover/wanted/next).
pub fn coarsen_size_mb(mut q: HuntQuery) -> HuntQuery {
    const MB: u64 = 1_000_000;
    if q.min_bytes != 0 {
        q.min_bytes = (q.min_bytes / MB) * MB;
    }
    if q.max_bytes != u64::MAX {
        q.max_bytes = q.max_bytes.div_ceil(MB).saturating_mul(MB);
    }
    q
}

/// 30 min window. Tighter than [`HUNT_TIME_WINDOW`]. A dump leftover
/// `q=` inside this still names when pubDate is close; a 2 h indexer
/// skew misses. Not the default cascade for that reason.
pub const HUNT_TIGHT_WINDOW: i64 = 30 * 60;

/// Filename stem: strip a short alphanumeric extension when the stem is
/// long enough to stay distinctive. Dump sites that index without `.mkv`
/// still match; a 12+ char hash stem is not a title.
pub fn leftover_stem(leftover: &str) -> &str {
    let t = leftover.trim();
    if let Some((stem, ext)) = t.rsplit_once('.')
        && (1..=5).contains(&ext.len())
        && ext.chars().all(|c| c.is_ascii_alphanumeric())
        && stem.len() >= 12
    {
        return stem;
    }
    t
}

/// Leading hex run of [`leftover_stem`]. Shared by prefix and suffix
/// helpers so a dump that keeps only the tail of a hash still sees the
/// same digits the prefix path would have used.
fn leftover_hex_run(leftover: &str) -> String {
    leftover_stem(leftover)
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect()
}

/// First 12 hex digits of [`leftover_stem`], or None when the stem is
/// not a 12+ hex run. Truncated dump columns still contain this; a
/// scene title does not.
fn leftover_hex12(leftover: &str) -> Option<String> {
    let prefix: String = leftover_hex_run(leftover).chars().take(12).collect();
    (prefix.len() == 12).then_some(prefix)
}

/// Last `n` hex digits of [`leftover_hex_run`], or None when the run
/// is shorter than `n`. A dump that keeps a suffix of the hash column
/// still contains this; a 12-hex prefix of the same run does not.
pub(super) fn leftover_hex_tail(leftover: &str, n: usize) -> Option<String> {
    let hex = leftover_hex_run(leftover);
    (n > 0 && hex.len() >= n).then(|| hex[hex.len() - n..].to_string())
}

/// Last 12 hex digits of the stem run. Windowed `q=` of this names a
/// suffix-truncated dump the prefix step misses.
fn leftover_hex12_tail(leftover: &str) -> Option<String> {
    leftover_hex_tail(leftover, 12)
}

/// Last 8 hex digits of the stem run. Windowed `q=` of this names a
/// short suffix dump the 12-hex suffix step misses.
fn leftover_hex8_tail(leftover: &str) -> Option<String> {
    leftover_hex_tail(leftover, 8)
}

/// Leftover as `q=` inside the dark row's size+date window. Dump sites
/// that index the posted filename name in one fetch; unconstrained
/// leftover `q=` can hit an older re-post of the same hash filename.
pub fn leftover_with_window(leftover: &str, total_bytes: u64, first_posted: i64) -> HuntQuery {
    let mut q = hunt_from_dark(total_bytes, first_posted);
    q.q = leftover.trim().to_string();
    q
}

/// [`leftover_with_window`] using [`leftover_stem`]. Same window, but
/// `q=` is the stem so a dump that strips `.mkv` still hits.
pub fn leftover_stem_with_window(leftover: &str, total_bytes: u64, first_posted: i64) -> HuntQuery {
    leftover_with_window(leftover_stem(leftover), total_bytes, first_posted)
}

/// [`leftover_with_window`] with [`HUNT_TIGHT_WINDOW`]. A bake-off
/// variant: wins on a close dump, loses on 2 h pubDate skew.
pub fn leftover_with_tight_window(
    leftover: &str,
    total_bytes: u64,
    first_posted: i64,
) -> HuntQuery {
    let mut q = leftover_with_window(leftover, total_bytes, first_posted);
    q.posted_from = first_posted.saturating_sub(HUNT_TIGHT_WINDOW);
    q.posted_to = first_posted.saturating_add(HUNT_TIGHT_WINDOW);
    q
}

/// First 12 hex digits of the stem as `q=` inside the size+date window.
/// A dump that truncates the filename column can hit this; a full-hash
/// dump already hits on the stem. A short prefix can flood, but the
/// size+date window still bounds the listing. Later cascade step: a
/// miss on stem/full costs zero fetches, so a truncated dump still
/// names in one.
pub fn leftover_hex_prefix_with_window(
    leftover: &str,
    total_bytes: u64,
    first_posted: i64,
) -> HuntQuery {
    leftover_with_window(
        leftover_hex12(leftover)
            .as_deref()
            .unwrap_or(leftover.trim()),
        total_bytes,
        first_posted,
    )
}

/// [`leftover_hex_prefix_with_window`] without the size+date window.
/// Hits a truncated dump column; also re-admits yesterday's re-post of
/// the same hash prefix. Cascade uses the windowed form for that reason.
pub fn leftover_hex_prefix(leftover: &str) -> HuntQuery {
    leftover_as_query(
        leftover_hex12(leftover)
            .as_deref()
            .unwrap_or(leftover.trim()),
    )
}

/// Last 12 hex digits of the stem as `q=` inside the size+date window.
/// A dump that keeps a suffix of the hash column hits this; the prefix
/// step and leftover `q=` of the full filename do not.
pub fn leftover_hex_suffix_with_window(
    leftover: &str,
    total_bytes: u64,
    first_posted: i64,
) -> HuntQuery {
    leftover_with_window(
        leftover_hex12_tail(leftover)
            .as_deref()
            .unwrap_or(leftover.trim()),
        total_bytes,
        first_posted,
    )
}

/// [`leftover_hex_suffix_with_window`] without the size+date window.
pub fn leftover_hex_suffix(leftover: &str) -> HuntQuery {
    leftover_as_query(
        leftover_hex12_tail(leftover)
            .as_deref()
            .unwrap_or(leftover.trim()),
    )
}

/// Last 8 hex digits of the stem as `q=` inside the size+date window.
/// A dump that keeps a short suffix of the hash column hits this; the
/// 12-hex suffix step does not contain-match an 8-hex posted_name.
pub fn leftover_hex8_suffix_with_window(
    leftover: &str,
    total_bytes: u64,
    first_posted: i64,
) -> HuntQuery {
    leftover_with_window(
        leftover_hex8_tail(leftover)
            .as_deref()
            .unwrap_or(leftover.trim()),
        total_bytes,
        first_posted,
    )
}

/// [`leftover_hex8_suffix_with_window`] without the size+date window.
pub fn leftover_hex8_suffix(leftover: &str) -> HuntQuery {
    leftover_as_query(
        leftover_hex8_tail(leftover)
            .as_deref()
            .unwrap_or(leftover.trim()),
    )
}

/// Ordered hunts for one dark row. Scene leftover: unconstrained `q=`
/// first (already a title). Hash leftover: stem-inside-window, then the
/// full leftover inside the same window when that differs, then a 12-hex
/// prefix of the stem when that differs again, then a 12-hex suffix of
/// the same run when that differs again, then an 8-hex suffix when that
/// differs again, then empty-`q` size+date.
/// Never copies a named sibling's title into `q`.
pub fn hunt_cascade_for_dark(
    leftover: &str,
    total_bytes: u64,
    first_posted: i64,
) -> Vec<HuntQuery> {
    let leftover = leftover.trim();
    let mut out = Vec::new();
    if leftover_is_a_title(leftover) {
        out.push(leftover_as_query(leftover));
    } else if !leftover.is_empty() {
        let stem_q = leftover_stem_with_window(leftover, total_bytes, first_posted);
        let full_q = leftover_with_window(leftover, total_bytes, first_posted);
        let hex_q = leftover_hex_prefix_with_window(leftover, total_bytes, first_posted);
        let hex_tail_q = leftover_hex_suffix_with_window(leftover, total_bytes, first_posted);
        let hex8_tail_q = leftover_hex8_suffix_with_window(leftover, total_bytes, first_posted);
        out.push(stem_q.clone());
        if stem_q != full_q {
            out.push(full_q.clone());
        }
        if hex_q != stem_q && hex_q != full_q {
            out.push(hex_q.clone());
        }
        if hex_tail_q != stem_q && hex_tail_q != full_q && hex_tail_q != hex_q {
            out.push(hex_tail_q.clone());
        }
        if hex8_tail_q != stem_q
            && hex8_tail_q != full_q
            && hex8_tail_q != hex_q
            && hex8_tail_q != hex_tail_q
        {
            out.push(hex8_tail_q);
        }
    }
    out.push(hunt_from_dark(total_bytes, first_posted));
    out
}

/// [`hunt_cascade_for_dark`] whose size+date fallback is poster-
/// constrained. Leftover `q=` steps stay unconstrained: a dump-site
/// filename hit does not need the poster. Geek leftover misses cost
/// zero fetches, then the poster window can still name a same-title
/// clone listing in one.
pub fn hunt_cascade_with_poster(
    leftover: &str,
    total_bytes: u64,
    first_posted: i64,
    poster: &str,
) -> Vec<HuntQuery> {
    let mut out = hunt_cascade_for_dark(leftover, total_bytes, first_posted);
    out.pop();
    out.push(hunt_from_dark_with_poster(
        total_bytes,
        first_posted,
        poster,
    ));
    out
}

/// Fetch catalog NZBs until one names a dark row, or `budget` fetches
/// are spent. Size+date hunts return many similar-size hits; msgid-join
/// is the discriminator and each fetch costs quota. `Applied` /
/// `Replaced` stop; `Confirmed` / `Conflict` / `Recorded` do not - a
/// same-size neighbour whose NZB is already applied is a miss for this
/// dark row, not a reason to stop spending quota. Returns how many
/// NZBs were opened, then the joins.
pub fn hunt_until_named(
    ix: &mut Index,
    hits: &[&CatalogRow],
    now: i64,
    source: &str,
    budget: usize,
) -> Result<(usize, Vec<IndexerJoin>), NameFromNzbError> {
    let mut out = Vec::new();
    let mut fetched = 0;
    for row in hits.iter().take(budget) {
        fetched += 1;
        let joins = ix.name_from_indexer_nzb(&row.title, &row.nzb, now, source)?;
        let named = joins_named(&joins);
        out.extend(joins);
        if named {
            break;
        }
    }
    Ok((fetched, out))
}

/// Walk [`hunt_cascade_for_dark`] (or any query list): catalog, rank,
/// fetch until Applied/Replaced, spend remaining budget on the next
/// query. A leftover-window miss spends zero fetches and falls through.
pub fn hunt_until_named_queries(
    ix: &mut Index,
    queries: &[HuntQuery],
    catalog: &[CatalogRow],
    target_bytes: u64,
    target_posted: i64,
    rank: HitRank,
    now: i64,
    source: &str,
    mut budget: usize,
) -> Result<(usize, Vec<IndexerJoin>), NameFromNzbError> {
    let mut fetched_total = 0;
    let mut out = Vec::new();
    for q in queries {
        if budget == 0 {
            break;
        }
        let hits = rank_hits(hunt_catalog(q, catalog), target_bytes, target_posted, rank);
        let (fetched, joins) = hunt_until_named(ix, &hits, now, source, budget)?;
        fetched_total += fetched;
        budget = budget.saturating_sub(fetched);
        let named = joins_named(&joins);
        out.extend(joins);
        if named {
            break;
        }
    }
    Ok((fetched_total, out))
}

/// Drive several hunts off one remaining daily quota (`CONFIRM_PER_DAY`
/// leftover at the start of the tick). Stops when the quota is spent.
/// Each hunt still uses msgid-join as the discriminator. Production
/// would search the indexer per `HuntQuery`; the mock reuses one catalog.
pub fn hunt_until_quota(
    ix: &mut Index,
    hunts: &[HuntQuery],
    catalog: &[CatalogRow],
    now: i64,
    source: &str,
    mut daily_left: usize,
) -> Result<(usize, Vec<IndexerJoin>), NameFromNzbError> {
    let mut fetched_total = 0;
    let mut out = Vec::new();
    for q in hunts {
        if daily_left == 0 {
            break;
        }
        let hits = hunt_catalog(q, catalog);
        let (fetched, joins) = hunt_until_named(ix, &hits, now, source, daily_left)?;
        fetched_total += fetched;
        daily_left = daily_left.saturating_sub(fetched);
        out.extend(joins);
    }
    Ok((fetched_total, out))
}

/// Next-episode `q=` from a named sibling's stem. Association only: this
/// is a search string, not a name to copy. Hash leftovers have no season
/// and return None.
pub fn hunt_next_episode(named_title: &str) -> Option<HuntQuery> {
    let p = crate::release::parse_release(named_title);
    let season = p.season?;
    let last_ep = p.episode2.or(p.episode)?;
    if season == 0 || last_ep == 0 {
        return None;
    }
    let next = last_ep.saturating_add(1);
    Some(HuntQuery {
        q: format!("{} s{season:02}e{next:02}", p.title),
        min_bytes: 0,
        max_bytes: u64::MAX,
        posted_from: i64::MIN,
        posted_to: i64::MAX,
        poster: String::new(),
    })
}

/// Next-episode `q=` with the named sibling's size slack. Age stays
/// unconstrained: a later episode is outside the named row's 4 h
/// window. Size slack drops a 720p neighbour listed ahead of the 4K
/// match. Movies still return None.
pub fn hunt_next_episode_sized(named_title: &str, named_bytes: u64) -> Option<HuntQuery> {
    let mut q = hunt_next_episode(named_title)?;
    let slack = (named_bytes / HUNT_SIZE_SLACK_DIV).max(HUNT_MIN_SLACK);
    q.min_bytes = named_bytes.saturating_sub(slack);
    q.max_bytes = named_bytes.saturating_add(slack);
    Some(q)
}

/// One row of a mock indexer listing. Production would fetch NZBs from
/// enclosures; tests carry the XML on the row so the join stays in-process.
#[derive(Debug, Clone)]
pub struct CatalogRow {
    pub title: String,
    pub posted_name: String,
    pub bytes: u64,
    pub posted: i64,
    pub nzb: Vec<u8>,
    /// Empty means the listing did not carry a poster. An empty hunt
    /// poster matches every row, including these.
    pub poster: String,
}

pub(super) fn catalog_norm(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '.' | '_' | '-' => ' ',
            _ => c.to_ascii_lowercase(),
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Filter a mock catalog the way F5 item 2 would filter indexer hits:
/// size and date always, text only when `q` is non-empty. Text matches
/// `posted_name` or `title` after dots/underscores/hyphens become spaces,
/// so a leftover hash filename hits a dump-site filename column and a
/// scene `q=` hits a dotted scene title.
pub fn hunt_catalog<'a>(q: &HuntQuery, catalog: &'a [CatalogRow]) -> Vec<&'a CatalogRow> {
    let needle = catalog_norm(&q.q);
    catalog
        .iter()
        .filter(|row| {
            row.bytes >= q.min_bytes
                && row.bytes <= q.max_bytes
                && row.posted >= q.posted_from
                && row.posted <= q.posted_to
                && (q.poster.is_empty() || row.poster == q.poster)
        })
        .filter(|row| {
            if needle.is_empty() {
                return true;
            }
            catalog_norm(&row.posted_name).contains(&needle)
                || catalog_norm(&row.title).contains(&needle)
        })
        .collect()
}

/// How to order [`hunt_catalog`] hits before spending quota. Rank with
/// the dark row's own bytes/posted, not the query midpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitRank {
    /// Keep indexer listing order.
    Catalog,
    ClosestSize,
    ClosestTime,
    /// Size first, then time. The default for a size+date fallback
    /// whose listing is full of similar payloads.
    ClosestSizeThenTime,
    /// Inverse document frequency of title tokens. A listing of eight
    /// `Decoy.Show.NN` clones plus one real show puts the real show
    /// first. Eight clones of the SAME title (repacks) all score equal
    /// and keep listing order.
    RareTitle,
}

/// Reorder catalog hits. Ties keep listing order (`sort_by_key` is
/// stable). Empty input stays empty.
pub fn rank_hits(
    mut hits: Vec<&CatalogRow>,
    target_bytes: u64,
    target_posted: i64,
    rank: HitRank,
) -> Vec<&CatalogRow> {
    match rank {
        HitRank::Catalog => {}
        HitRank::ClosestSize => hits.sort_by_key(|r| r.bytes.abs_diff(target_bytes)),
        HitRank::ClosestTime => hits.sort_by_key(|r| r.posted.abs_diff(target_posted)),
        HitRank::ClosestSizeThenTime => {
            hits.sort_by_key(|r| {
                (
                    r.bytes.abs_diff(target_bytes),
                    r.posted.abs_diff(target_posted),
                )
            });
        }
        HitRank::RareTitle => hits = rank_hits_rare_title(hits),
    }
    hits
}

pub(super) fn title_tokens(title: &str) -> Vec<String> {
    catalog_norm(title)
        .split_whitespace()
        .filter(|t| t.len() >= 2)
        .map(str::to_string)
        .collect()
}

pub(super) fn idf_scores(docs: &[Vec<String>]) -> Vec<u64> {
    if docs.is_empty() {
        return Vec::new();
    }
    let n = docs.len() as u64;
    let mut df: HashMap<String, u64> = HashMap::new();
    for toks in docs {
        let mut seen = HashSet::new();
        for t in toks {
            if seen.insert(t.as_str()) {
                *df.entry(t.clone()).or_insert(0) += 1;
            }
        }
    }
    docs.iter()
        .map(|toks| {
            toks.iter()
                .map(|t| n.saturating_mul(1_000) / df.get(t).copied().unwrap_or(n).max(1))
                .sum()
        })
        .collect()
}

/// 0 when the listing poster equals `want`. Empty `want` is unconstrained
/// (everyone misses), so this never invents a match on omitted posters.
pub(super) fn poster_rank_miss(row_poster: &str, want: &str) -> u8 {
    if !want.is_empty() && row_poster == want {
        0
    } else {
        1
    }
}

/// Rank by inverse document frequency of [`CatalogRow::title`] tokens.
/// Shared tokens (`web`, `h264`, `grp`) score low; a unique show name
/// scores high. Stable on ties. Empty or singleton listings are a no-op.
pub fn rank_hits_rare_title(hits: Vec<&CatalogRow>) -> Vec<&CatalogRow> {
    if hits.len() < 2 {
        return hits;
    }
    let docs: Vec<Vec<String>> = hits.iter().map(|r| title_tokens(&r.title)).collect();
    let scores = idf_scores(&docs);
    let mut order: Vec<usize> = (0..hits.len()).collect();
    order.sort_by_key(|&i| Reverse(scores[i]));
    order.into_iter().map(|i| hits[i]).collect()
}

/// Prefer a matching poster, then size, then time. Does not drop rows
/// whose listing omitted poster: those all miss and fall through to
/// size/time, so a dump still names in one via closest time.
pub fn rank_hits_prefer_poster<'a>(
    mut hits: Vec<&'a CatalogRow>,
    poster: &str,
    target_bytes: u64,
    target_posted: i64,
) -> Vec<&'a CatalogRow> {
    hits.sort_by_key(|r| {
        (
            poster_rank_miss(&r.poster, poster),
            r.bytes.abs_diff(target_bytes),
            r.posted.abs_diff(target_posted),
        )
    });
    hits
}

/// RareTitle, then poster as a tiebreak. Identical-title clones
/// (GeekClone) that still carry distinct posters name in one fetch.
/// Same-poster clones keep listing order. Omitted posters all miss
/// and RareTitle decides alone.
pub fn rank_hits_rare_title_then_poster<'a>(
    hits: Vec<&'a CatalogRow>,
    poster: &str,
) -> Vec<&'a CatalogRow> {
    if hits.len() < 2 {
        return hits;
    }
    let docs: Vec<Vec<String>> = hits.iter().map(|r| title_tokens(&r.title)).collect();
    let scores = idf_scores(&docs);
    let mut order: Vec<usize> = (0..hits.len()).collect();
    order.sort_by_key(|&i| {
        (
            Reverse(scores[i]),
            poster_rank_miss(&hits[i].poster, poster),
        )
    });
    order.into_iter().map(|i| hits[i]).collect()
}

/// Exact byte match first, then poster, then time. Splits a same-size
/// clone listing the way PreferPoster does, without IDF.
pub fn rank_hits_exact_then_poster<'a>(
    mut hits: Vec<&'a CatalogRow>,
    poster: &str,
    target_bytes: u64,
    target_posted: i64,
) -> Vec<&'a CatalogRow> {
    hits.sort_by_key(|r| {
        let exact = if r.bytes == target_bytes { 0u8 } else { 1 };
        (
            exact,
            poster_rank_miss(&r.poster, poster),
            r.posted.abs_diff(target_posted),
        )
    });
    hits
}

/// Byte-prefix length of leftover vs `posted_name` after [`catalog_norm`].
/// A dump that truncates the filename column still shares a long prefix
/// with a hash leftover; a Geek scene name shares none.
pub fn leftover_posted_lcp(leftover: &str, posted_name: &str) -> usize {
    let a = catalog_norm(leftover);
    let b = catalog_norm(posted_name);
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

/// Longest common substring of leftover vs `posted_name` after
/// [`catalog_norm`]. A dump that keeps only a tail of the hash still
/// shares a long run with the leftover; a prefix LCP of those two is
/// zero. Contiguous on purpose: token Jaccard shares no whole tokens
/// with a truncated hash, and LCP is already the prefix arm.
pub fn leftover_posted_lcs(leftover: &str, posted_name: &str) -> usize {
    let a = catalog_norm(leftover).into_bytes();
    let b = catalog_norm(posted_name).into_bytes();
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let mut prev = vec![0usize; b.len() + 1];
    let mut cur = vec![0usize; b.len() + 1];
    let mut best = 0usize;
    for &ca in &a {
        for (j, &cb) in b.iter().enumerate() {
            cur[j + 1] = if ca == cb { prev[j] + 1 } else { 0 };
            best = best.max(cur[j + 1]);
        }
        std::mem::swap(&mut prev, &mut cur);
        cur.fill(0);
    }
    best
}

/// Longest leftover/`posted_name` prefix first, then RareThenPoster.
/// Dump leftover-boost without a `q=` the indexer would ignore; Geek
/// leftover-miss falls through to unique titles then unique posters.
pub fn rank_hits_lcp_then_rare_then_poster<'a>(
    hits: Vec<&'a CatalogRow>,
    leftover: &str,
    poster: &str,
) -> Vec<&'a CatalogRow> {
    if hits.len() < 2 {
        return hits;
    }
    let docs: Vec<Vec<String>> = hits.iter().map(|r| title_tokens(&r.title)).collect();
    let scores = idf_scores(&docs);
    let mut order: Vec<usize> = (0..hits.len()).collect();
    order.sort_by_key(|&i| {
        (
            Reverse(leftover_posted_lcp(leftover, &hits[i].posted_name)),
            Reverse(scores[i]),
            poster_rank_miss(&hits[i].poster, poster),
        )
    });
    order.into_iter().map(|i| hits[i]).collect()
}

/// Longest leftover/`posted_name` substring first, then RareThenPoster.
/// Empty-`q` backup when truncation is not a clean 12-hex suffix: last
/// 8 of a hash, garbage wrap, an indexer that ignores `q=` on
/// `posted_name`. Does not replace leftover_boosts; that stays the
/// cheap exact-contain check.
pub fn rank_hits_lcs_then_rare_then_poster<'a>(
    hits: Vec<&'a CatalogRow>,
    leftover: &str,
    poster: &str,
) -> Vec<&'a CatalogRow> {
    if hits.len() < 2 {
        return hits;
    }
    let docs: Vec<Vec<String>> = hits.iter().map(|r| title_tokens(&r.title)).collect();
    let scores = idf_scores(&docs);
    let mut order: Vec<usize> = (0..hits.len()).collect();
    order.sort_by_key(|&i| {
        (
            Reverse(leftover_posted_lcs(leftover, &hits[i].posted_name)),
            Reverse(scores[i]),
            poster_rank_miss(&hits[i].poster, poster),
        )
    });
    order.into_iter().map(|i| hits[i]).collect()
}

/// Exact-byte hits, RareThenPoster inside that set, then the rest.
/// GeekNear names without IDF; identical-bytes omit-poster still names
/// via RareTitle once the exact-byte set is the whole listing.
pub fn rank_hits_exact_then_rare_then_poster<'a>(
    hits: Vec<&'a CatalogRow>,
    poster: &str,
    target_bytes: u64,
) -> Vec<&'a CatalogRow> {
    let exact: Vec<_> = hits
        .iter()
        .copied()
        .filter(|r| r.bytes == target_bytes)
        .collect();
    let rest: Vec<_> = hits
        .iter()
        .copied()
        .filter(|r| r.bytes != target_bytes)
        .collect();
    let mut out = rank_hits_rare_title_then_poster(exact, poster);
    out.extend(rank_hits_rare_title_then_poster(rest, poster));
    out
}

/// Newest `posted` first, poster as a tiebreak. Names GeekNear when
/// times flatten but posters differ; omit-poster + flat time is listing
/// order.
pub fn rank_hits_newest_then_poster<'a>(
    mut hits: Vec<&'a CatalogRow>,
    poster: &str,
) -> Vec<&'a CatalogRow> {
    hits.sort_by_key(|r| (Reverse(r.posted), poster_rank_miss(&r.poster, poster)));
    hits
}

/// Client-side leftover hint over a size+date listing. Indexers that
/// do not search `posted_name` still return it; boosting a leftover
/// match names in one fetch without a `q=` the indexer would ignore.
/// A Geek row whose posted_name is already a scene title does not match
/// a hash leftover, so this does not invent a name. A 12-hex prefix or
/// suffix of the stem is also a hit: a dump that truncates either end
/// of the filename column still surfaces first, bounded by the
/// size+date window. Not an LCS check: that hides the split a suffix
/// `q=` already names.
pub fn leftover_boosts(row: &CatalogRow, leftover: &str) -> bool {
    let stem_n = catalog_norm(leftover_stem(leftover));
    let hay_p = catalog_norm(&row.posted_name);
    let hay_t = catalog_norm(&row.title);
    let stem_hit = !stem_n.is_empty() && (hay_p.contains(&stem_n) || hay_t.contains(&stem_n));
    let hex_hit =
        leftover_hex12(leftover).is_some_and(|hex| hay_p.contains(&hex) || hay_t.contains(&hex));
    let hex_tail_hit = leftover_hex12_tail(leftover)
        .is_some_and(|hex| hay_p.contains(&hex) || hay_t.contains(&hex));
    stem_hit || hex_hit || hex_tail_hit
}

/// [`rank_hits`] with leftover matches first. Ties keep listing order.
pub fn rank_hits_with_leftover<'a>(
    mut hits: Vec<&'a CatalogRow>,
    leftover: &str,
    target_bytes: u64,
    target_posted: i64,
    rank: HitRank,
) -> Vec<&'a CatalogRow> {
    if matches!(rank, HitRank::RareTitle) {
        let boosted: Vec<_> = hits
            .iter()
            .copied()
            .filter(|r| leftover_boosts(r, leftover))
            .collect();
        let rest: Vec<_> = hits
            .iter()
            .copied()
            .filter(|r| !leftover_boosts(r, leftover))
            .collect();
        let mut out = rank_hits_rare_title(boosted);
        out.extend(rank_hits_rare_title(rest));
        return out;
    }
    hits.sort_by_key(|r| {
        let boost = if leftover_boosts(r, leftover) { 0u8 } else { 1 };
        match rank {
            HitRank::Catalog => (boost, 0u64, 0u64),
            HitRank::ClosestSize => (boost, r.bytes.abs_diff(target_bytes), 0),
            HitRank::ClosestTime => (boost, r.posted.abs_diff(target_posted), 0),
            HitRank::ClosestSizeThenTime => (
                boost,
                r.bytes.abs_diff(target_bytes),
                r.posted.abs_diff(target_posted),
            ),
            HitRank::RareTitle => (boost, 0, 0),
        }
    });
    hits
}

/// Newznab that has age days but no size params: coarsen the unix
/// window to days, search with unconstrained bytes, then drop rows
/// outside the original byte window on this side.
pub fn hunt_catalog_newznab_then_size<'a>(
    q: &HuntQuery,
    catalog: &'a [CatalogRow],
) -> Vec<&'a CatalogRow> {
    let aged = coarsen_age_days(q.clone());
    let listing = HuntQuery {
        q: q.q.clone(),
        min_bytes: 0,
        max_bytes: u64::MAX,
        posted_from: aged.posted_from,
        posted_to: aged.posted_to,
        poster: q.poster.clone(),
    };
    hunt_catalog(&listing, catalog)
        .into_iter()
        .filter(|row| row.bytes >= q.min_bytes && row.bytes <= q.max_bytes)
        .collect()
}

/// Send coarsened age+size (what Newznab / nzbindex actually take),
/// then drop rows the original unix window would have excluded. A
/// leftover `q=` coarsened to whole days can otherwise re-admit
/// yesterday's re-post of the same hash filename.
pub fn hunt_catalog_mapped_then_filter<'a>(
    q: &HuntQuery,
    catalog: &'a [CatalogRow],
) -> Vec<&'a CatalogRow> {
    let mapped = coarsen_size_mb(coarsen_age_days(q.clone()));
    hunt_catalog(&mapped, catalog)
        .into_iter()
        .filter(|row| {
            row.bytes >= q.min_bytes
                && row.bytes <= q.max_bytes
                && row.posted >= q.posted_from
                && row.posted <= q.posted_to
        })
        .collect()
}

/// Group headers the way a header-only indexer glues parts of one file.
/// Indices are into the input slice. A Nyuu hash-filename posting lands
/// in one bucket; pesto random subjects land one-per-article.
pub fn group_by_leftover<'a, I>(headers: I) -> BTreeMap<CollectionKey, Vec<usize>>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out: BTreeMap<CollectionKey, Vec<usize>> = BTreeMap::new();
    for (i, (subject, group)) in headers.into_iter().enumerate() {
        let (leftover, part_total) = leftover_token(subject);
        out.entry(CollectionKey {
            leftover,
            group: group.to_string(),
            part_total,
        })
        .or_default()
        .push(i);
    }
    out
}

/// Group headers that share a leading `[i/N]` session tag (same N and
/// group). That glues FILES of one shattered posting. It is still not
/// a title.
pub fn group_by_session<'a, I>(headers: I) -> BTreeMap<(i64, String), Vec<usize>>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out: BTreeMap<(i64, String), Vec<usize>> = BTreeMap::new();
    for (i, (subject, group)) in headers.into_iter().enumerate() {
        if let Some((_, total)) = session_tag(subject) {
            out.entry((total, group.to_string())).or_default().push(i);
        }
    }
    out
}

/// One release the commercial NZB named, and what `apply_proven_name`
/// did with that claim.
#[derive(Debug, Clone)]
pub struct IndexerJoin {
    pub release_id: i64,
    pub matched: usize,
    pub outcome: ProvenOutcome,
}

#[derive(Debug, thiserror::Error)]
pub enum NameFromNzbError {
    #[error("NZB parse: {0}")]
    Nzb(#[from] crate::nzb::NzbError),
    #[error("index: {0}")]
    Db(#[from] rusqlite::Error),
}

impl Index {
    /// Apply a title a commercial indexer was TOLD onto dark scan rows
    /// whose message-ids the NZB contains, at the same quorum
    /// `corr_confirm_once` uses (`MIN_MSGID_QUORUM` on the reverse map).
    ///
    /// `title` is the search-listing / filename name, not a leftover
    /// token and not the NZB `<meta type="title">` unless the caller
    /// chose that. Grouping never calls this.
    pub fn name_from_indexer_nzb(
        &mut self,
        title: &str,
        nzb_xml: &[u8],
        now: i64,
        source: &str,
    ) -> Result<Vec<IndexerJoin>, NameFromNzbError> {
        let ident = nzb_identity(nzb_xml)?;
        Ok(self.name_from_indexer_ident(title, &ident, now, source)?)
    }

    /// [`Self::name_from_indexer_nzb`] with the NZB ALREADY PARSED.
    ///
    /// This split is not a convenience. `Index` sits behind the
    /// daemon's single index mutex, and that write side is the one
    /// measured starving the download runner (`with_index_mut`'s own
    /// note); parsing a multi-megabyte NZB inside the lock hold would
    /// put an XML parse in front of every scan and search. Production
    /// lanes parse outside the lock and call THIS; the mock-catalog
    /// helpers above hold no lock and call the parsing wrapper.
    pub fn name_from_indexer_ident(
        &mut self,
        title: &str,
        ident: &crate::nzbimport::NzbIdentity,
        now: i64,
        source: &str,
    ) -> rusqlite::Result<Vec<IndexerJoin>> {
        if ident.lead_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut per: HashMap<i64, Vec<&str>> = HashMap::new();
        for id in &ident.lead_ids {
            for (rid, _) in self.find_releases_by_msgids(std::iter::once(id.as_str()))? {
                per.entry(rid).or_default().push(id.as_str());
            }
        }
        let mut out = Vec::new();
        for (rid, mids) in per {
            if mids.len() < MIN_MSGID_QUORUM {
                continue;
            }
            let claim = NameClaim {
                name: title.to_string(),
                evidence: NameEvidence::MsgidSet,
                key: msgid_set_key(&mids),
                source: source.into(),
            };
            let outcome = self.apply_proven_name(rid, &claim, now)?;
            out.push(IndexerJoin {
                release_id: rid,
                matched: mids.len(),
                outcome,
            });
        }
        Ok(out)
    }

    /// F5 item 2 fan-out: session siblings of a named wall row that
    /// still have empty `pre_title`. Each hunt is size+date around
    /// THAT sibling (empty `q`). Association may surface the neighbour;
    /// it must not copy the named row's title into `q`.
    pub fn hunts_from_dark_siblings(
        &self,
        named_id: i64,
        limit: usize,
    ) -> rusqlite::Result<Vec<(i64, HuntQuery)>> {
        let mut out = Vec::new();
        for s in self.session_siblings(named_id, limit)? {
            let pre: String = self.db.query_row(
                "SELECT pre_title FROM releases WHERE id=?1",
                [s.rel.id],
                |r| r.get(0),
            )?;
            if !pre.is_empty() {
                continue;
            }
            out.push((
                s.rel.id,
                hunt_from_dark(s.rel.total_bytes, s.rel.first_posted),
            ));
        }
        Ok(out)
    }

    /// Dark rows whose CLUSTER STEM already reads as a release title -
    /// the leftover-as-title population, walking DOWN from `before_id`
    /// so a lane with a cursor never re-buys the same head every tick.
    ///
    /// `junk < 50` is the SQL half and it is doing real work: it rides
    /// the partial `idx_rel_visible_posted` arm, and obfuscated stems
    /// score junk 70, so it lands close to the shape wanted before a
    /// single row is deserialized (census 1 Sep 2026: 22,444,517 dark
    /// rows, 22,216,485 of them junk >= 70). `leftover_is_a_title` is
    /// the exact half, applied in Rust because it parses.
    ///
    /// Dark is `pre_title = ''`, NOT `title_key`: the stem being
    /// scene-shaped is exactly why this row is worth a search, and is
    /// not itself a name (`apply_proven_name` writes `pre_title`).
    /// Returns the rows that PASSED, and the lowest id this call
    /// EXAMINED. A caller's cursor must advance on the second, not the
    /// first: the Rust filter runs after the SQL `LIMIT`, so a window
    /// of 200 candidate rows can pass none of them while millions
    /// remain below it. Advancing on the passing rows alone would
    /// re-read the same window forever, and treating an empty result
    /// as "no candidates left" would end the lap at the first window
    /// that happened to filter to nothing. `None` - and only `None` -
    /// means the SQL itself returned nothing, which is the bottom.
    pub fn dark_title_leftovers(
        &self,
        before_id: i64,
        limit: usize,
    ) -> rusqlite::Result<(Vec<(i64, String)>, Option<i64>)> {
        let mut stmt = self.db.prepare_cached(
            "SELECT id, stem FROM releases
              WHERE pre_title='' AND junk < 50 AND id < ?1
              ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![before_id, limit as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let examined = rows.iter().map(|(id, _)| *id).min();
        Ok((
            rows.into_iter()
                .filter(|(_, stem)| leftover_is_a_title(stem))
                .collect(),
            examined,
        ))
    }

    /// Proven names newest first, walking DOWN `name_claims.id` from
    /// `before_id` - the next-episode hunt's pick source. Returns the
    /// claim id (the caller's cursor), the release's `pre_title`, and
    /// its size.
    ///
    /// Keyed off `name_claims` rather than `releases` because there is
    /// no index on `pre_title` and named rows are a very thin slice
    /// (24,093 of 22.4M on the live index, 1 Sep 2026); the claims
    /// table is already ordered by when the name arrived, which is
    /// also the order worth hunting - the episode we named a minute
    /// ago is the one whose successor is most likely listed.
    ///
    /// `pre_title` is re-read from `releases` and non-empty is
    /// required: a claim can exist at a tier that never became the
    /// applied name.
    pub fn named_for_next_episode(
        &self,
        before_id: i64,
        limit: usize,
    ) -> rusqlite::Result<Vec<(i64, String, u64)>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT c.id, r.pre_title, r.total_bytes
               FROM name_claims c JOIN releases r ON r.id = c.release_id
              WHERE r.pre_title <> '' AND c.id < ?1
              ORDER BY c.id DESC LIMIT ?2",
        )?;
        // House SQLite: total_bytes is INTEGER, read as i64 then cast
        // (u64: FromSql is not implemented in rusqlite 0.40.2).
        let rows = stmt
            .query_map(rusqlite::params![before_id, limit as i64], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// Did this join set NAME a dark row?
///
/// The hunt's stop rule, in ONE place because two loops need to agree
/// exactly: `hunt_until_named` here, and the daemon's confirm-lane
/// hunt, whose catalog is behind HTTP and so cannot share the loop
/// itself. `Applied` / `Replaced` stop the hunt; `Confirmed` /
/// `Conflict` / `Recorded` do NOT - a same-size neighbour whose NZB is
/// already applied is a miss for THIS dark row, not a reason to stop
/// spending the user's quota.
pub fn joins_named(joins: &[IndexerJoin]) -> bool {
    joins
        .iter()
        .any(|j| matches!(j.outcome, ProvenOutcome::Applied | ProvenOutcome::Replaced))
}
