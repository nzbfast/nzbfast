//! M35: pull search - the Newznab CLIENT side. The user's configured
//! third-party indexers (NZBGeek, DrunkenSlug, a Prowlarr instance, ...)
//! are queried from inside nzbfast; results merge into the wall search
//! and grabs ride the same fetch-by-URL path `addurl` uses.
//!
//! This module is pure: URL building, XML parsing and budget arithmetic,
//! no I/O. `serve/fetch.rs` owns the HTTP calls (through
//! `ssrf_safe_agent`) and `serve/indexers.rs` the caps/result caches
//! and the API modes.
//!
//! Protocol notes that shape the code:
//! - Errors usually arrive as HTTP 200 with an `<error code=.../>`
//!   document (100-102 credentials, 500 API-hit limit, 501 grab limit),
//!   so every body goes through [`parse_error`] before anything else.
//! - Results are RSS 2.0 items whose `<enclosure url>` is the NZB link
//!   and whose `<newznab:attr>` elements carry size/category/grabs.
//! - Accounts are metered in API hits and grabs per day; [`Usage`]
//!   counts both so optional per-indexer budgets can gate politely.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::rss::{attr, tag_text, unescape};

/// One configured third-party indexer (the `indexers` setting).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IndexerConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub apikey: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Lower wins when merged results collide on the same release.
    #[serde(default)]
    pub priority: i32,
    /// Daily API-hit budget; 0 = unmetered (we still count).
    #[serde(default)]
    pub hits_per_day: u32,
    /// Daily grab budget; 0 = unmetered.
    #[serde(default)]
    pub grabs_per_day: u32,
}

fn default_true() -> bool {
    true
}

impl IndexerConfig {
    /// The API endpoint. The user may paste a site root or a full
    /// endpoint; keep whatever path they gave (Prowlarr endpoints look
    /// like `http://host:9696/1/api`) and append `/api` only when the
    /// path does not already end in it.
    pub fn endpoint(&self) -> String {
        let base = self.url.trim().trim_end_matches('/');
        if base.ends_with("/api") {
            base.to_string()
        } else {
            format!("{base}/api")
        }
    }

    /// What makes this entry a distinct FAR END, for keying per-endpoint
    /// runtime state (caps, limit backoffs).
    ///
    /// Deliberately not the name. The name is a label the user types and
    /// retypes, and Settings tests a DRAFT entry before saving it - so a
    /// draft that borrowed a saved entry's name published its caps under
    /// that name, and cancelling the edit left the saved entry planning
    /// its searches against a site it never pointed at. The apikey is in
    /// the key because the same host answers different caps per account
    /// (a VIP tier advertising id search that the free tier does not).
    pub fn identity(&self) -> String {
        format!("{}\u{1}{}", self.endpoint(), self.apikey.trim())
    }
}

/// What `t=caps` said this indexer can do.
#[derive(Debug, Clone, Default)]
pub struct Caps {
    pub server: String,
    /// Top-level `<category>` entries only - enough to show the user
    /// what the site carries; subcats share their parent's thousand.
    pub categories: Vec<(u32, String)>,
    pub search: bool,
    pub tvsearch: Vec<String>,
    pub movie: Vec<String>,
    pub limit_max: u32,
    pub limit_default: u32,
}

/// One search. `q` alone is the free-text case; the id/episode fields
/// are the M35 phase-2 precision path, used only when the indexer's
/// caps say it supports them (see [`plan_query`]).
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub q: String,
    pub cats: Vec<u32>,
    pub limit: u32,
    pub offset: u32,
    /// IMDb id for `t=movie`. Either "tt0110912" or bare digits: the
    /// protocol wants it WITHOUT the tt, and [`search_url`] strips it.
    pub imdbid: String,
    /// TheTVDB series id for `t=tvsearch`.
    pub tvdbid: String,
    pub season: Option<u32>,
    pub ep: Option<u32>,
}

/// Which `t=` mode a query should use against one indexer, decided by
/// that indexer's caps.
///
/// The ids are worth the trouble - a free-text search for a common
/// title drags in every other release whose name contains those words,
/// while `imdbid=` is exact - but an indexer that does not advertise
/// the parameter will either ignore it (answering with an unfiltered
/// feed) or error. So an id is only ever sent to an indexer whose caps
/// advertise that exact param name, and everything else falls back to
/// `t=search`, which every conforming indexer must implement.
///
/// Season/episode are different: `s01e02` in a free-text query is a
/// perfectly good filter against scene names, so when `tvsearch` is
/// unavailable they fold into `q` the way our own facade does.
#[cfg(feature = "indexer")]
pub fn plan_query(caps: Option<&Caps>, q: &SearchQuery) -> SearchQuery {
    let has = |list: &[String], name: &str| list.iter().any(|p| p == name);
    let mut out = q.clone();
    let (tv, movie) = match caps {
        Some(c) => (c.tvsearch.as_slice(), c.movie.as_slice()),
        None => (&[][..], &[][..]),
    };
    // TV: keep tvdbid only if advertised; season/ep only if advertised.
    //
    // The id must not cost the episode filter. An indexer that takes
    // `tvdbid` but not `season`/`ep` would answer a request for one
    // episode with the whole series feed, where the free-text fold at
    // the bottom still narrows it to s01e02 - so the id wins only when
    // the episode fields either ride along or were never asked for.
    // Untested and unreachable until the wall's pull-search learned to
    // send an id at all (it had none to send before TODO 187).
    let episode_ok = (q.season.is_none() && q.ep.is_none()) || (has(tv, "season") && has(tv, "ep"));
    if !q.tvdbid.is_empty() && has(tv, "tvdbid") && episode_ok {
        out.imdbid.clear();
        return out;
    }
    if (q.season.is_some() || q.ep.is_some()) && has(tv, "season") && has(tv, "ep") {
        out.tvdbid.clear();
        out.imdbid.clear();
        return out;
    }
    // Movies: imdbid only if advertised.
    if !q.imdbid.is_empty() && has(movie, "imdbid") {
        out.tvdbid = String::new();
        out.season = None;
        out.ep = None;
        return out;
    }
    // Nothing usable: plain free-text, with the episode marker folded
    // into q so a TV search still narrows.
    out.imdbid.clear();
    out.tvdbid.clear();
    if let (Some(s), Some(e)) = (q.season, q.ep) {
        out.q = format!("{} s{s:02}e{e:02}", q.q).trim().to_string();
    }
    out.season = None;
    out.ep = None;
    out
}

/// One result item off an indexer's search response.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub title: String,
    /// The NZB link (enclosure url, else `<link>`). Carries the user's
    /// apikey - never serialize this to a browser or a log.
    pub link: String,
    pub guid: String,
    pub size: u64,
    pub cat: u32,
    /// Upload time (usenetdate attr, else pubDate), unix; 0 = unknown.
    pub posted: i64,
    pub grabs: u32,
}

/// Why a query failed, mapped from the protocol's error space.
#[derive(Debug, Clone, PartialEq)]
pub enum NewznabError {
    /// 100-199: bad/suspended key, insufficient permissions.
    Auth(u16, String),
    /// 500 API-hit limit / 501 grab limit / HTTP 429. The caller backs
    /// this indexer off for the day rather than retrying.
    Limit(u16, String),
    /// Anything else the indexer reported.
    Api(u16, String),
}

impl std::fmt::Display for NewznabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (code, msg) = match self {
            NewznabError::Auth(c, m) | NewznabError::Limit(c, m) | NewznabError::Api(c, m) => {
                (c, m)
            }
        };
        write!(f, "{msg} (code {code})")
    }
}

/// The `<error code=... description=.../>` document, when the response
/// IS one. Newznab reports errors with HTTP 200, so every body comes
/// through here before any other parse. Only a document-level `<error`
/// counts - a description mentioning "error" inside a result feed does
/// not.
pub fn parse_error(xml: &str) -> Option<NewznabError> {
    // trim_start uses Unicode White_Space, which does NOT include U+FEFF, and
    // a PHP-stack indexer emitting a BOM before <?xml made every <error>
    // document unparseable here. That is not cosmetic: parse_error is what
    // raises NewznabError::Limit, so without it the daily-quota answer reads
    // as an empty result set, the backoff never engages, and we keep hammering
    // an account that is already over quota.
    let mut t = xml.trim_start_matches('\u{feff}').trim_start();
    if let Some(rest) = t.strip_prefix("<?xml") {
        t = rest
            .split_once("?>")
            .map(|(_, r)| r)
            .unwrap_or(rest)
            .trim_start();
    }
    let rest = t.strip_prefix("<error")?;
    let tag = &rest[..rest.find('>').unwrap_or(rest.len())];
    let code: u16 = attr(tag, "code")?.parse().ok()?;
    let desc = unescape(attr(tag, "description").unwrap_or(""));
    Some(match code {
        100..=199 => NewznabError::Auth(code, desc),
        500 | 501 => NewznabError::Limit(code, desc),
        _ => NewznabError::Api(code, desc),
    })
}

/// Percent-encode a query value (RFC 3986 unreserved set kept).
pub fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The request URL for one indexer. The mode follows the query's id
/// fields, which [`plan_query`] has already reconciled against caps:
/// `tvdbid`/`season`/`ep` mean `t=tvsearch`, `imdbid` means `t=movie`,
/// and everything else is `t=search`.
pub fn search_url(cfg: &IndexerConfig, q: &SearchQuery) -> String {
    let tv = !q.tvdbid.is_empty() || q.season.is_some() || q.ep.is_some();
    let mode = if tv {
        "tvsearch"
    } else if !q.imdbid.is_empty() {
        "movie"
    } else {
        "search"
    };
    let mut u = format!(
        "{}?t={mode}&extended=1&apikey={}&q={}",
        cfg.endpoint(),
        urlenc(&cfg.apikey),
        urlenc(&q.q)
    );
    if tv {
        if !q.tvdbid.is_empty() {
            u.push_str(&format!("&tvdbid={}", urlenc(&q.tvdbid)));
        }
        if let Some(s) = q.season {
            u.push_str(&format!("&season={s}"));
        }
        if let Some(e) = q.ep {
            u.push_str(&format!("&ep={e}"));
        }
    } else if !q.imdbid.is_empty() {
        // The protocol wants the bare number, without the "tt".
        let id = q.imdbid.trim_start_matches("tt");
        u.push_str(&format!("&imdbid={}", urlenc(id)));
    }
    if !q.cats.is_empty() {
        let cats: Vec<String> = q.cats.iter().map(u32::to_string).collect();
        u.push_str("&cat=");
        u.push_str(&cats.join(","));
    }
    if q.limit > 0 {
        u.push_str(&format!("&limit={}", q.limit));
    }
    if q.offset > 0 {
        u.push_str(&format!("&offset={}", q.offset));
    }
    u
}

/// The `t=caps` request URL. Caps needs no apikey by spec, but real
/// sites (and Prowlarr) accept and sometimes want one - send it when we
/// have it.
pub fn caps_url(cfg: &IndexerConfig) -> String {
    if cfg.apikey.is_empty() {
        format!("{}?t=caps", cfg.endpoint())
    } else {
        format!("{}?t=caps&apikey={}", cfg.endpoint(), urlenc(&cfg.apikey))
    }
}

/// One named `<newznab:attr>` value inside an item block.
fn nn_attr(item: &str, name: &str) -> Option<String> {
    item.split("<newznab:attr").skip(1).find_map(|a| {
        let a = &a[..a.find('>').unwrap_or(a.len())];
        (attr(a, "name") == Some(name))
            .then(|| attr(a, "value").map(str::to_string))
            .flatten()
    })
}

/// Parse a `t=caps` document. Tolerant like the RSS parser - a missing
/// section just leaves its field at the default.
pub fn parse_caps(xml: &str) -> Caps {
    let mut caps = Caps::default();
    let one_tag = |open: &str| -> Option<String> {
        let p = xml.find(open)?;
        let end = xml[p..].find('>').map(|e| p + e)?;
        Some(xml[p..end].to_string())
    };
    if let Some(t) = one_tag("<server") {
        caps.server = unescape(
            attr(&t, "title")
                .or_else(|| attr(&t, "appversion"))
                .unwrap_or(""),
        );
    }
    if let Some(t) = one_tag("<limits") {
        caps.limit_max = attr(&t, "max").and_then(|v| v.parse().ok()).unwrap_or(0);
        caps.limit_default = attr(&t, "default")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
    }
    let params = |t: &str| -> Vec<String> {
        attr(t, "supportedParams")
            .unwrap_or("")
            .split(',')
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };
    if let Some(t) = one_tag("<search ") {
        caps.search = attr(&t, "available") == Some("yes");
    }
    if let Some(t) = one_tag("<tv-search")
        && attr(&t, "available") == Some("yes")
    {
        caps.tvsearch = params(&t);
    }
    if let Some(t) = one_tag("<movie-search")
        && attr(&t, "available") == Some("yes")
    {
        caps.movie = params(&t);
    }
    // Top-level categories only: `<category id name>`; `<subcat>` rides
    // its parent's thousand and is noise at this level.
    let mut rest = xml;
    while let Some(p) = rest.find("<category") {
        let tail = &rest[p..];
        let end = tail.find('>').unwrap_or(tail.len());
        let tag = &tail[..end];
        if let (Some(id), Some(name)) = (
            attr(tag, "id").and_then(|v| v.parse().ok()),
            attr(tag, "name"),
        ) {
            caps.categories.push((id, unescape(name)));
        }
        rest = &tail[end..];
    }
    caps
}

/// Parse a search response into result items. Call [`parse_error`]
/// first; a feed with zero items is a valid "nothing found".
pub fn parse_results(xml: &str) -> Vec<SearchResult> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find("<item") {
        let Some(close) = rest[open..].find("</item>") else {
            break;
        };
        let item = &rest[open..open + close];
        let title = tag_text(item, "title").map(unescape).unwrap_or_default();
        let enclosure = item.find("<enclosure").map(|p| {
            let end = item[p..].find('>').map(|e| p + e).unwrap_or(item.len());
            &item[p..end]
        });
        let link = enclosure
            .and_then(|e| attr(e, "url"))
            .map(str::to_string)
            .or_else(|| tag_text(item, "link").map(str::to_string))
            .map(|l| unescape(&l))
            .unwrap_or_default();
        let size = enclosure
            .and_then(|e| attr(e, "length"))
            .and_then(|v| v.parse().ok())
            .filter(|s| *s > 0)
            .or_else(|| nn_attr(item, "size").and_then(|v| v.parse().ok()))
            .unwrap_or(0);
        let cat = nn_attr(item, "category")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let posted = nn_attr(item, "usenetdate")
            .and_then(|v| parse_rfc2822(&v))
            .or_else(|| tag_text(item, "pubDate").and_then(parse_rfc2822))
            .unwrap_or(0);
        let grabs = nn_attr(item, "grabs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let guid = tag_text(item, "guid")
            .map(unescape)
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| link.clone());
        if !title.is_empty() && !link.is_empty() {
            out.push(SearchResult {
                title,
                link,
                guid,
                size,
                cat,
                posted,
                grabs,
            });
        }
        rest = &rest[open + close + 7..];
    }
    out
}

/// Days from civil date (Howard Hinnant's algorithm), the inverse of
/// `civil_from_days` in serve/disk.rs.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 2822-ish date ("Tue, 02 Jul 2026 15:04:05 +0000") to unix. The
/// zone forms seen in real feeds: +hhmm/-hhmm, GMT/UT/UTC, bare Z.
/// Anything unparseable is None, which the caller treats as "age
/// unknown", never as 1970.
pub fn parse_rfc2822(s: &str) -> Option<i64> {
    let s = s.trim();
    let s = s.split_once(',').map(|(_, r)| r).unwrap_or(s);
    let mut it = s.split_whitespace();
    let day: u32 = it.next()?.parse().ok()?;
    let mon = match it.next()?.to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    if !(1..=31).contains(&day) || !(1980..=3000).contains(&year) {
        return None;
    }
    let mut hms = it.next()?.split(':');
    let h: i64 = hms.next()?.parse().ok()?;
    let mi: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    // Lower bounds as well as upper: these are i64s parsed straight out of
    // an indexer's `usenetdate`, and a negative hour sails past an
    // upper-bound-only check and then overflows `h * 3600` below (a debug
    // panic inside the thread::scope search fan-out, a wrong timestamp in
    // release). The contract is that anything unparseable is None.
    if !(0..=23).contains(&h) || !(0..=59).contains(&mi) || !(0..=60).contains(&sec) {
        return None;
    }
    let off = match it.next().unwrap_or("+0000") {
        z if z.starts_with('+') || z.starts_with('-') => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits = &z[1..];
            if digits.len() == 4 && digits.bytes().all(|b| b.is_ascii_digit()) {
                let zh: i64 = digits[..2].parse().ok()?;
                let zm: i64 = digits[2..].parse().ok()?;
                sign * (zh * 3600 + zm * 60)
            } else {
                0
            }
        }
        _ => 0, // GMT/UT/UTC/Z and unknown names
    };
    Some(days_from_civil(year, mon, day) * 86_400 + h * 3600 + mi * 60 + sec - off)
}

/// The name half of the cross-indexer identity: the same release posted
/// once is listed by every indexer that scanned it, and they do not
/// agree on how to write its name down. Dots against spaces against
/// underscores, capitalisation, a trailing `.nzb` - all of it is one
/// indexer's formatting of the same string, carrying no information
/// about the release itself, so all of it is flattened away.
///
/// This is deliberately the SAME reduction the duplicate check uses
/// (`serve::job::flatten_name`, behind `exact_dupe_key`), not a second
/// fuzzy rule of its own: everything that survives it is a real
/// difference. `Show.S01E02.1080p-GRP` and `Show S01E02 1080p-GRP` are
/// one release; a 1080p and a 2160p, two cuts, or two groups keep their
/// distinguishing token and never meet. String-similarity scoring is
/// out of bounds here for the reason it is out of bounds in the dupe
/// check: a rule loose enough to catch an appended tag is loose enough
/// to read a spin-off as its parent, and hiding a release the user
/// wanted is worse than listing it twice.
#[cfg(feature = "indexer")]
pub fn release_ident(title: &str) -> String {
    let t = title.trim();
    // Some indexers hand back the NZB's filename rather than the
    // release name. The extension is the only part of that which is
    // theirs rather than the release's.
    //
    // char_indices, not a byte slice: the fourth-from-last CHARACTER is
    // where the extension would start, and a raw `len - 4` splits a
    // multi-byte one and panics.
    let t = match t.char_indices().nth_back(3) {
        Some((i, _)) if t[i..].eq_ignore_ascii_case(".nzb") => &t[..i],
        _ => t,
    };
    let flat = crate::serve::job::flatten_name(t);
    let ident = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    // A title with no letter or digit anywhere in it reduces to nothing,
    // and an empty identity would fold every such title into one row.
    // Fall back to the raw name: unmergeable is the honest answer when
    // there is nothing left to compare.
    if ident.is_empty() {
        t.to_lowercase()
    } else {
        ident
    }
}

/// How far two indexers' sizes for one release may differ and still be
/// read as the same post. They rarely agree exactly: some count the
/// par2 set and the nzb, some only the payload, and some repeat
/// whatever the poster claimed.
///
/// A percentage rather than a fixed bucket, because the accounting
/// differences scale with the release, with a floor so a small post
/// still gets usable slack. The old key bucketed on `size / 50 MB`,
/// which is not a tolerance at all: two sizes one byte apart landed in
/// different buckets whenever they straddled a boundary, so the merge
/// silently missed a share of the copies it was meant to catch.
///
/// 20%, widened from 2% on 19 Aug 2026 by a measured pair the reporter
/// of #44 posted: one release, two indexers, 80.4 GB against 91.9 GB.
/// That is +14.3%, and it is not two releases - it is payload against
/// payload plus yEnc plus a par2 set (80.4 x 1.037 x 1.10 = 91.7). 2%
/// had no example behind it and split the very case the merge exists
/// for.
///
/// This only ever runs on copies whose titles ALREADY reduced to one
/// `release_ident`, and by then size is weak evidence: what genuinely
/// distinguishes two releases - group tag, REPACK, resolution, encode -
/// lives in the title, which already matched byte for byte. So the
/// guard is kept coarse rather than removed (a 1 GB and an 8 GB post
/// under one name are not one release), but it should fire on a gap no
/// accounting difference can explain, not on the ordinary ones.
///
/// The two errors are also not equally costly. Merging too eagerly
/// costs one caret: every copy is listed under the row with its own
/// size, so the reader still sees both. Splitting too eagerly is
/// invisible, and looks exactly like the bug #44 reported. Prefer the
/// recoverable error.
#[cfg(feature = "indexer")]
pub fn size_slack(size: u64) -> u64 {
    (size / 5).max(50 * 1024 * 1024)
}

/// Cut a name group's copies into size clusters. `sizes` must be sorted
/// ascending; the returned ranges index into it and cover it exactly.
///
/// Each cluster is anchored on its smallest member and admits everything
/// within that member's slack. Anchoring rather than comparing
/// neighbours is what stops a chain of near-misses from dragging one
/// cluster arbitrarily wide.
///
/// Size 0 means "this indexer did not say", not "an empty release". An
/// unknown size is no evidence AGAINST a name that already matches, so
/// those copies join the first cluster rather than each becoming a row
/// of its own; with nothing but unknowns, the name is all the evidence
/// there is and they form a single cluster.
#[cfg(feature = "indexer")]
pub fn size_clusters(sizes: &[u64]) -> Vec<std::ops::Range<usize>> {
    debug_assert!(
        sizes.windows(2).all(|w| w[0] <= w[1]),
        "sizes must be sorted"
    );
    let mut out = Vec::new();
    if sizes.is_empty() {
        return out;
    }
    let Some(first_known) = sizes.iter().position(|&s| s > 0) else {
        out.push(0..sizes.len());
        return out;
    };
    let mut anchor = sizes[first_known];
    let mut start = 0;
    for (i, &s) in sizes.iter().enumerate().skip(first_known) {
        if s > anchor.saturating_add(size_slack(anchor)) {
            out.push(start..i);
            start = i;
            anchor = s;
        }
    }
    out.push(start..sizes.len());
    out
}

/// Per-day hit/grab counters, persisted in `.spool/indexer-usage.json`.
/// Counting is unconditional; gating happens only when the indexer's
/// budget field is set. Keys are indexer names.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// UTC day number (unix days) the counters belong to.
    pub day: i64,
    #[serde(default)]
    pub hits: HashMap<String, u32>,
    #[serde(default)]
    pub grabs: HashMap<String, u32>,
}

impl Usage {
    /// Reset the counters when the UTC day has rolled over.
    pub fn roll(&mut self, now_ts: i64) {
        let day = now_ts.div_euclid(86_400);
        if day != self.day {
            *self = Usage {
                day,
                ..Default::default()
            };
        }
    }

    pub fn hit_allowed(&self, cfg: &IndexerConfig) -> bool {
        cfg.hits_per_day == 0 || self.hits.get(&cfg.name).copied().unwrap_or(0) < cfg.hits_per_day
    }

    pub fn grab_allowed(&self, cfg: &IndexerConfig) -> bool {
        cfg.grabs_per_day == 0
            || self.grabs.get(&cfg.name).copied().unwrap_or(0) < cfg.grabs_per_day
    }

    pub fn count_hit(&mut self, name: &str) {
        *self.hits.entry(name.to_string()).or_insert(0) += 1;
    }

    pub fn count_grab(&mut self, name: &str) {
        *self.grabs.entry(name.to_string()).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str) -> IndexerConfig {
        IndexerConfig {
            name: "geek".into(),
            url: url.into(),
            apikey: "K1".into(),
            enabled: true,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        }
    }

    #[test]
    fn endpoint_normalization() {
        // Site root, trailing slash, ready-made endpoint, Prowlarr path.
        assert_eq!(
            cfg("https://api.nzbgeek.info").endpoint(),
            "https://api.nzbgeek.info/api"
        );
        assert_eq!(
            cfg("https://api.nzbgeek.info/").endpoint(),
            "https://api.nzbgeek.info/api"
        );
        assert_eq!(
            cfg("https://idx.example/api").endpoint(),
            "https://idx.example/api"
        );
        assert_eq!(
            cfg("http://nas:9696/1/api/").endpoint(),
            "http://nas:9696/1/api"
        );
    }

    #[test]
    fn search_urls() {
        let q = SearchQuery {
            q: "Kill Bill & more".into(),
            cats: vec![2000, 5000],
            limit: 100,
            ..Default::default()
        };
        let u = search_url(&cfg("https://idx.example"), &q);
        assert_eq!(
            u,
            "https://idx.example/api?t=search&extended=1&apikey=K1&q=Kill%20Bill%20%26%20more&cat=2000,5000&limit=100"
        );
    }

    #[cfg(feature = "indexer")]
    fn caps_with(tv: &[&str], movie: &[&str]) -> Caps {
        Caps {
            tvsearch: tv.iter().map(|s| s.to_string()).collect(),
            movie: movie.iter().map(|s| s.to_string()).collect(),
            search: true,
            ..Default::default()
        }
    }

    /// An id is only ever sent to an indexer that advertises it; every
    /// other case degrades to a free-text search, which is mandatory in
    /// the protocol. Sending imdbid to a site that ignores it would
    /// answer a specific-film request with an unfiltered feed.
    #[cfg(feature = "indexer")]
    #[test]
    fn query_planning_follows_caps() {
        let tvq = SearchQuery {
            q: "Show Name".into(),
            tvdbid: "12345".into(),
            season: Some(1),
            ep: Some(2),
            ..Default::default()
        };
        // Full TV support: the id wins and the episode fields ride along.
        let p = plan_query(
            Some(&caps_with(&["q", "tvdbid", "season", "ep"], &[])),
            &tvq,
        );
        assert_eq!(
            (p.tvdbid.as_str(), p.season, p.ep),
            ("12345", Some(1), Some(2))
        );
        assert!(search_url(&cfg("https://x"), &p).contains("t=tvsearch&"));

        // season/ep advertised but not tvdbid: keep the episode fields,
        // drop the id.
        let p = plan_query(Some(&caps_with(&["q", "season", "ep"], &[])), &tvq);
        assert!(p.tvdbid.is_empty() && p.season == Some(1));

        // tvdbid advertised but not season/ep: the id alone would widen
        // an episode request to the whole series, so the episode marker
        // in `q` wins instead.
        let p = plan_query(Some(&caps_with(&["q", "tvdbid"], &[])), &tvq);
        assert_eq!(p.q, "Show Name s01e02");
        assert!(p.tvdbid.is_empty() && p.season.is_none());
        // Same caps, no episode asked for: nothing to lose, id sent.
        let p = plan_query(
            Some(&caps_with(&["q", "tvdbid"], &[])),
            &SearchQuery {
                season: None,
                ep: None,
                ..tvq.clone()
            },
        );
        assert_eq!(p.tvdbid.as_str(), "12345");

        // No tv-search at all: fold s01e02 into q and go free-text.
        let p = plan_query(Some(&caps_with(&[], &[])), &tvq);
        assert_eq!(p.q, "Show Name s01e02");
        assert!(p.tvdbid.is_empty() && p.season.is_none());
        let u = search_url(&cfg("https://x"), &p);
        assert!(u.contains("t=search&") && !u.contains("season="), "{u}");

        // Movies: imdbid only when advertised, and the tt is stripped.
        let mq = SearchQuery {
            q: "Kill Bill".into(),
            imdbid: "tt0266697".into(),
            ..Default::default()
        };
        let p = plan_query(Some(&caps_with(&[], &["q", "imdbid"])), &mq);
        let u = search_url(&cfg("https://x"), &p);
        assert!(
            u.contains("t=movie&") && u.contains("imdbid=0266697"),
            "{u}"
        );
        let p = plan_query(Some(&caps_with(&[], &["q"])), &mq);
        assert!(p.imdbid.is_empty());
        assert!(search_url(&cfg("https://x"), &p).contains("t=search&"));

        // Unknown caps (never probed) are treated as "supports nothing
        // beyond the mandatory search".
        let p = plan_query(None, &mq);
        assert!(p.imdbid.is_empty());
        assert!(search_url(&cfg("https://x"), &p).contains("t=search&"));
    }

    #[test]
    fn error_documents() {
        let e = parse_error(
            r#"<?xml version="1.0"?><error code="100" description="Incorrect user credentials"/>"#,
        );
        assert_eq!(
            e,
            Some(NewznabError::Auth(100, "Incorrect user credentials".into()))
        );
        let e = parse_error(r#"<error code="500" description="Request limit reached"/>"#);
        assert_eq!(
            e,
            Some(NewznabError::Limit(500, "Request limit reached".into()))
        );
        // A result feed is not an error, even when a title says "error".
        let feed = r#"<?xml version="1.0"?><rss><channel><item><title>error.of.the.day</title></item></channel></rss>"#;
        assert_eq!(parse_error(feed), None);
        // Garbage is not an error document either.
        assert_eq!(parse_error("<error code=\"nope\"/>"), None);
        assert_eq!(parse_error(""), None);
    }

    #[test]
    fn caps_documents() {
        let caps = parse_caps(
            r#"<?xml version="1.0"?><caps>
  <server title="NZBGeek" appversion="1.1"/>
  <limits max="100" default="100"/>
  <searching>
    <search available="yes" supportedParams="q"/>
    <tv-search available="yes" supportedParams="q,rid,tvdbid,season,ep"/>
    <movie-search available="no" supportedParams="q,imdbid"/>
  </searching>
  <categories>
    <category id="2000" name="Movies &amp; Films"><subcat id="2040" name="HD"/></category>
    <category id="5000" name="TV"/>
  </categories>
</caps>"#,
        );
        assert_eq!(caps.server, "NZBGeek");
        assert_eq!((caps.limit_max, caps.limit_default), (100, 100));
        assert!(caps.search);
        assert_eq!(caps.tvsearch, vec!["q", "rid", "tvdbid", "season", "ep"]);
        assert!(
            caps.movie.is_empty(),
            "available=no must not advertise params"
        );
        assert_eq!(
            caps.categories,
            vec![(2000, "Movies & Films".into()), (5000, "TV".into())]
        );
        // Degenerate caps: everything at defaults, nothing panics.
        let none = parse_caps("<caps></caps>");
        assert!(!none.search && none.categories.is_empty());
    }

    #[test]
    fn result_items() {
        let xml = r#"<?xml version="1.0"?><rss><channel>
<item><title>Show.S01E02.1080p.WEB</title>
<guid isPermaLink="false">abc-123</guid>
<pubDate>Tue, 21 Jul 2026 10:00:00 +0000</pubDate>
<enclosure url="https://idx/get/abc?apikey=k" length="3221225472" type="application/x-nzb"/>
<newznab:attr name="category" value="5040"/>
<newznab:attr name="grabs" value="42"/>
<newznab:attr name="usenetdate" value="Mon, 20 Jul 2026 09:00:00 +0000"/>
</item>
<item><title>Movie.2026.720p</title>
<link>https://idx/get/def</link>
<newznab:attr name="size" value="1500000000"/>
</item>
</channel></rss>"#;
        let items = parse_results(xml);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Show.S01E02.1080p.WEB");
        assert_eq!(items[0].link, "https://idx/get/abc?apikey=k");
        assert_eq!(items[0].size, 3_221_225_472);
        assert_eq!(items[0].cat, 5040);
        assert_eq!(items[0].grabs, 42);
        // usenetdate (the upload) wins over pubDate (the indexing).
        assert_eq!(
            items[0].posted,
            parse_rfc2822("Mon, 20 Jul 2026 09:00:00 +0000").unwrap()
        );
        assert_eq!(items[1].size, 1_500_000_000);
        assert_eq!(items[1].cat, 0);
        // Hostile shapes: truncated item, attr with no value, empty doc.
        assert!(parse_results("<item><title>half").is_empty());
        assert!(parse_results("").is_empty());
        let odd = parse_results(
            "<item><title>t</title><link>http://x</link><newznab:attr name=\"size\"/></item>",
        );
        assert_eq!(odd[0].size, 0);
    }

    #[test]
    fn rfc2822_dates() {
        // 21 Jul 2026 is 20 years after the classic Go reference epoch
        // sanity anchor: check against a value computed independently
        // (days_from_civil(2026,7,21) = 20655).
        assert_eq!(
            parse_rfc2822("Tue, 21 Jul 2026 00:00:00 +0000"),
            Some(20655 * 86_400)
        );
        // Zone math: +0200 is two hours EARLIER in unix time.
        assert_eq!(
            parse_rfc2822("Tue, 21 Jul 2026 02:00:00 +0200"),
            Some(20655 * 86_400)
        );
        assert_eq!(
            parse_rfc2822("21 Jul 2026 00:00:00 GMT"),
            Some(20655 * 86_400)
        );
        // Garbage in the wild: never Some(1970-ish), just None.
        assert_eq!(parse_rfc2822(""), None);
        assert_eq!(parse_rfc2822("Tue, 99 Jul 2026 00:00:00 +0000"), None);
        assert_eq!(parse_rfc2822("Tue, 21 Foo 2026 00:00:00 +0000"), None);
        assert_eq!(parse_rfc2822("Tue, 21 Jul 1969 00:00:00 +0000"), None);
    }

    /// The merge must fire on formatting disagreements and must NOT fire
    /// on anything that distinguishes one release from another. Both
    /// directions are pinned, because loosening this key is the failure
    /// that hides a release the user wanted.
    #[cfg(feature = "indexer")]
    #[test]
    fn release_ident_folds_formatting_and_nothing_else() {
        // Every way six indexers might write one release down.
        let forms = [
            "Show.Name.S01E02.1080p.WEB-DL.x264-GRP",
            "Show Name S01E02 1080p WEB-DL x264-GRP",
            "Show_Name_S01E02_1080p_WEB-DL_x264-GRP",
            "SHOW.NAME.S01E02.1080P.WEB-DL.X264-GRP",
            "Show.Name.S01E02.1080p.WEB-DL.x264-GRP.nzb",
            "  Show.Name.S01E02.1080p.WEB-DL.x264-GRP  ",
        ];
        let want = release_ident(forms[0]);
        for f in forms {
            assert_eq!(release_ident(f), want, "{f} should fold onto the same row");
        }

        // ...and every real difference survives. A resolution, a codec, a
        // source, a group, an episode, a sequel, an appended language
        // tag: merging any of these would show the user one row and
        // silently drop the copy they came for.
        let base = "Show.Name.S01E02.1080p.WEB-DL.x264-GRP";
        for other in [
            "Show.Name.S01E02.2160p.WEB-DL.x264-GRP",
            "Show.Name.S01E02.1080p.WEB-DL.x265-GRP",
            "Show.Name.S01E02.1080p.BluRay.x264-GRP",
            "Show.Name.S01E02.1080p.WEB-DL.x264-OTHER",
            "Show.Name.S01E03.1080p.WEB-DL.x264-GRP",
            "Show.Name.S01E02.1080p.WEB-DL.x264-GRP.GERMAN",
            "Show.Name.2.S01E02.1080p.WEB-DL.x264-GRP",
        ] {
            assert_ne!(release_ident(base), release_ident(other), "{other}");
        }

        // The `.nzb` strip is a suffix, not a substring: a release whose
        // name merely contains it keeps every token.
        assert_ne!(
            release_ident("Foo.nzb.Bar-GRP"),
            release_ident("Foo.Bar-GRP")
        );

        // A name with no letter or digit in it reduces to nothing, and an
        // empty identity would fold every such title into one row.
        assert_ne!(release_ident("!!!"), release_ident("???"));

        // Non-Latin names keep their identity (the flattener is
        // Unicode-aware; see `flatten_name`'s CJK note).
        assert_ne!(
            release_ident("\u{7535}\u{5f71}\u{7532}.2024.1080p-GRP"),
            release_ident("\u{7535}\u{5f71}\u{4e59}.2024.1080p-GRP")
        );
        assert_eq!(
            release_ident("\u{7535}\u{5f71}\u{7532}.2024.1080p-GRP"),
            release_ident("\u{7535}\u{5f71}\u{7532} 2024 1080P-grp")
        );
    }

    /// The exact pair the reporter of issue #44 posted, carried through
    /// both halves of the key at once: two indexers' copies of one
    /// release, differing on the name axis only by dots against spaces,
    /// and on the size axis by 14.3%.
    ///
    /// Kept as its own test because each half passing in isolation is
    /// what made this look fixed when it was not: the titles reduced to
    /// one ident from the day `release_ident` landed, and the row still
    /// split, because 2% of slack could not hold a par2 set.
    #[cfg(feature = "indexer")]
    #[test]
    fn issue_44_reported_pair_lands_in_one_row() {
        const GB: u64 = 1024 * 1024 * 1024;
        let spaced =
            "Anyone But You 2023 2160p UHD BluRay REMUX DV HDR10 HEVC TrueHD 7.1 Atmos + Multi-d3g";
        let dotted =
            "Anyone.But.You.2023.2160p.UHD.BluRay.REMUX.DV.HDR10.HEVC.TrueHD.7.1.Atmos.+.Multi-d3g";
        assert_eq!(
            release_ident(spaced),
            release_ident(dotted),
            "dots against spaces is a spelling difference, not a different release"
        );
        // Sorted ascending, as `size_clusters` requires: 80.4 GB from
        // Tabula Rasa, 91.9 GB from altHUB.
        let sizes = [80_400 * GB / 1000, 91_900 * GB / 1000];
        let clusters = size_clusters(&sizes);
        assert_eq!(clusters.len(), 1, "one release, one row: {clusters:?}");
    }

    /// Sizes cluster by tolerance, not by bucket. The bucket this
    /// replaced split any pair that straddled a 50 MB boundary, however
    /// close together they were.
    #[cfg(feature = "indexer")]
    #[test]
    fn size_clusters_tolerate_accounting_and_split_real_differences() {
        const MB: u64 = 1024 * 1024;
        // Spelled out rather than compared against a one-element list of
        // Range, which clippy reads as a mistyped `[0; n]`.
        let one = |v: &[u64]| {
            let c = size_clusters(v);
            c.len() == 1 && c[0] == (0..v.len())
        };

        // A par2-overhead wobble, sitting exactly across a 50 MB
        // boundary: one release, one row.
        assert!(one(&[50 * MB - 1, 50 * MB + 1]));
        // Two genuinely different releases under one name: two rows.
        assert_eq!(
            size_clusters(&[1_000 * MB, 8_000 * MB]),
            vec![0..1, 1..2],
            "a 1 GB and an 8 GB post are not the same release"
        );
        // The pair the reporter of #44 posted: one release under one
        // name, 80.4 GB from one indexer and 91.9 GB from another. The
        // gap is payload against payload plus yEnc plus par2, not two
        // releases, and at 2% slack this split - which was the whole
        // complaint.
        assert!(
            one(&[80_400 * MB, 91_900 * MB]),
            "one release's two indexers disagreeing by 14% is accounting, not a second release"
        );
        // A gap no accounting difference reaches is still two rows.
        assert_eq!(size_clusters(&[40_000 * MB, 60_000 * MB]), vec![0..1, 1..2]);

        // Anchored, not chained: sizes each within slack of the one
        // before still split, or a long tail would drift a cluster
        // arbitrarily wide.
        assert_eq!(
            size_clusters(&[1_000 * MB, 1_150 * MB, 1_300 * MB, 1_450 * MB]),
            vec![0..2, 2..4]
        );

        // An indexer that reported no size at all rides with the first
        // real cluster rather than becoming a row of its own.
        assert_eq!(
            size_clusters(&[0, 1_000 * MB, 9_000 * MB]),
            vec![0..2, 2..3]
        );
        // Nothing but unknowns: the name is all the evidence there is.
        assert!(one(&[0, 0]));
        assert!(size_clusters(&[]).is_empty());
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn budgets() {
        let mut u = Usage::default();
        u.roll(20_655 * 86_400 + 100);
        let mut c = cfg("https://x");
        c.hits_per_day = 2;
        assert!(u.hit_allowed(&c));
        u.count_hit("geek");
        u.count_hit("geek");
        assert!(!u.hit_allowed(&c), "budget of 2 gates the third hit");
        // Midnight UTC rolls the counters; same day does not.
        u.roll(20_655 * 86_400 + 200);
        assert!(!u.hit_allowed(&c));
        u.roll(20_656 * 86_400 + 100);
        assert!(u.hit_allowed(&c));
        // Unmetered still counts but never gates.
        c.hits_per_day = 0;
        for _ in 0..100 {
            u.count_hit("geek");
        }
        assert!(u.hit_allowed(&c));
    }
}
