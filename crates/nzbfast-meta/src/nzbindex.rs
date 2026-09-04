//! TODO 297: the nzbindex.com CLIENT side - a second search source
//! beside the Newznab one, over that site's own documented JSON API.
//!
//! This module is pure: URL building and JSON parsing, no I/O.
//! `indexers.rs` owns the HTTP calls and dispatches to it on
//! [`crate::newznab::SourceKind`], so every fan-out that already asks a
//! Newznab account - pull search, the hunt, the watchlist, the `nzblnk:`
//! ladder - asks an nzbindex entry too with no second code path. The
//! results are [`crate::newznab::SearchResult`] and the errors are
//! [`crate::newznab::NewznabError`] for exactly that reason: a new
//! result type would have meant a parallel merge, a parallel token
//! cache and a parallel grab, and the grab is the part that must not be
//! forked (it is what binds a link to the origin that offered it).
//!
//! # Why this is an adapter and not the scraper we declined
//!
//! Issue #57 was answered on 24 Aug 2026 by declining raw-site support,
//! because binsearch and nzbking offer no API and an HTML scraper rots
//! silently. That is still true of those two. `https://nzbindex.com/api`
//! is a documented JSON API, so this is the same class of surface the
//! Newznab client consumes, one schema over.
//!
//! # Protocol notes that shape the code (verified live 26 Aug 2026)
//!
//! - `/api/search?q=...` takes `max`, `sort`, `minage`, `maxage`,
//!   `minsize`, `maxsize`, `poster`, `groups` (repeatable), `complete`
//!   and `page`, and answers
//!   `{"data":{"content":[...],"page":{...}},"error":false,"errorMessage":""}`.
//! - Ages are DAYS and sizes are MEGABYTES, which is not the unit any
//!   other size in this codebase is in - see [`search_url`].
//! - The NZB is at `/api/download/<id>.nzb`. **The `.nzb` suffix is
//!   load-bearing**: without it the path 307s to `/api/download/<id>`,
//!   which answers 404. Measured both ways.
//! - `/api/collection/<id>` retrieves the collection RECORD (its file
//!   list with `totalParts`/`availableParts`), not the NZB. TODO 297
//!   describes it as "retrieves by id", which is true and is not the
//!   download.
//! - There are no CATEGORIES and no id search: it indexes raw subjects,
//!   so a `cat=`, an `imdbid=` or a `tvdbid=` has nowhere to go. A
//!   caller's category filter is dropped and its season/episode folds
//!   into the query text, which is what a scene name carries anyway.
//! - An EMPTY `q` is not an error - it answers the whole firehose
//!   (10,000 elements). [`search_url`] is never called with one; the
//!   dispatcher refuses it first, because a search that silently became
//!   "everything nzbindex has" is worse than one that failed.

use crate::netfetch::urlenc;
use crate::newznab::{IndexerConfig, NewznabError, SearchQuery, SearchResult};

/// Rows per request when the caller did not say. Their own default is
/// 25, which is thin for a merge against Newznab results that arrive
/// 100 at a time.
pub const DEFAULT_MAX: u32 = 100;

/// The search request URL for one nzbindex entry.
///
/// Three deliberate losses against the Newznab mapping, all of them
/// because the far end has no such concept rather than because we chose
/// not to send it:
///
/// - **Categories are dropped.** nzbindex indexes raw subjects and
///   publishes no category space. Sending `cat=5000` would be ignored at
///   best; silently narrowing our own result set to match a Newznab
///   category would be worse, because the rows it would drop are the
///   ones this source exists to find.
/// - **`imdbid`/`tvdbid` are dropped.** There is no id search. The
///   Newznab client guards these behind a caps probe for the same
///   reason (`plan_query`): an id sent to a site that does not advertise
///   it comes back as an unfiltered feed.
/// - **Season/episode fold into the text**, exactly as `plan_query`
///   does when caps are unavailable. `s01e02` is a perfectly good filter
///   against a scene name.
///
/// `offset` becomes a PAGE, which is the only paging this API has: it
/// is floor-divided by the page size, so an offset that is not a whole
/// number of pages lands on the page containing it rather than
/// silently on page 0.
pub fn search_url(cfg: &IndexerConfig, q: &SearchQuery) -> String {
    let max = if q.limit > 0 { q.limit } else { DEFAULT_MAX };
    // Season/episode fold into the text; the ids have nowhere to go.
    let text = match (q.season, q.ep) {
        (Some(s), Some(e)) => format!("{} s{s:02}e{e:02}", q.q).trim().to_string(),
        (Some(s), None) => format!("{} s{s:02}", q.q).trim().to_string(),
        _ => q.q.trim().to_string(),
    };
    let mut u = format!("{}/search?q={}&max={max}", cfg.endpoint(), urlenc(&text));
    // Newest first, which is the order the pull-search rows are sorted
    // into anyway - so the truncation at `max` drops the oldest rows
    // rather than an arbitrary slice.
    u.push_str("&sort=agedesc");
    if q.offset > 0 && max > 0 {
        u.push_str(&format!("&page={}", q.offset / max));
    }
    // The raw-subject wariness, made explicit. `complete` is the one
    // filter that changes what the user SEES rather than how much of it
    // there is: an unfiltered nzbindex query lists collections that are
    // missing parts and can never finish. Default on - see
    // `NzbIndexOpts::default` for the argument.
    if cfg.nzbindex.complete_only {
        u.push_str("&complete=1");
    }
    // MEGABYTES, and this is the trap in the whole mapping: every other
    // size in this codebase is bytes. The config field says `_mb` for
    // that reason and is passed through untouched.
    if cfg.nzbindex.min_size_mb > 0 {
        u.push_str(&format!("&minsize={}", cfg.nzbindex.min_size_mb));
    }
    if cfg.nzbindex.max_size_mb > 0 {
        u.push_str(&format!("&maxsize={}", cfg.nzbindex.max_size_mb));
    }
    // DAYS.
    if cfg.nzbindex.min_age_days > 0 {
        u.push_str(&format!("&minage={}", cfg.nzbindex.min_age_days));
    }
    if cfg.nzbindex.max_age_days > 0 {
        u.push_str(&format!("&maxage={}", cfg.nzbindex.max_age_days));
    }
    // Repeated, not comma-joined: their docs spell it
    // `groups=one&groups=two`.
    for g in cfg.nzbindex.groups.iter().filter(|g| !g.trim().is_empty()) {
        u.push_str(&format!("&groups={}", urlenc(g.trim())));
    }
    push_key(&mut u, cfg);
    u
}

/// The NZB download URL for one collection id.
///
/// **The `.nzb` suffix is required.** `/api/download/<id>` 307s to
/// itself and answers 404; `/api/download/<id>.nzb` answers
/// `application/x-nzb`. Measured 26 Aug 2026.
pub fn download_url(cfg: &IndexerConfig, id: &str) -> String {
    let mut u = format!("{}/download/{}.nzb", cfg.endpoint(), urlenc(id));
    push_key(&mut u, cfg);
    u
}

/// The probe URL used to prove an entry works at all: a real search,
/// narrow, because this API has no `t=caps` to ask.
pub fn probe_url(cfg: &IndexerConfig) -> String {
    let mut u = format!("{}/search?q=test&max=1", cfg.endpoint());
    push_key(&mut u, cfg);
    u
}

/// Append `&key=` when the entry has one.
///
/// Their docs say every request wants a key "to identify your
/// application and to allow more requests per second", and the site
/// answers without one - so this is optional rather than credentials,
/// and an entry with a blank key is a working entry, not a broken one.
///
/// It is still a SECRET in a URL. The credential never reaches a log or
/// the browser: `redact_apikey` matches on `key=`, which covers this
/// spelling and Newznab's `apikey=` both (one is a suffix of the other),
/// `redact_url_creds` drops the whole query string, and the browser only
/// ever sees an opaque grab token.
fn push_key(u: &mut String, cfg: &IndexerConfig) {
    let k = cfg.apikey.trim();
    if !k.is_empty() {
        u.push_str(&format!("&key={}", urlenc(k)));
    }
}

/// One row of `data.content`, parsed strictly.
///
/// `id` and `name` are REQUIRED and everything else defaults, which is
/// the split that makes [`parse_results`] able to tell "no matches"
/// from "their schema moved": a row we cannot name or fetch is not a
/// result, and a whole page of them is a broken adapter.
fn row(v: &serde_json::Value, cfg: &IndexerConfig) -> Option<SearchResult> {
    let id = v.get("id")?.as_str()?.trim();
    let name = v.get("name")?.as_str()?.trim();
    if id.is_empty() || name.is_empty() {
        return None;
    }
    Some(SearchResult {
        title: name.to_string(),
        link: download_url(cfg, id),
        guid: id.to_string(),
        size: v
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        // nzbindex publishes no category space. 0 is what the Newznab
        // parser leaves when an item carries no category attr, so every
        // downstream reader already handles it.
        cat: 0,
        posted: v
            .get("posted")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        // No grab counter in this API. 0 sorts last on the grabs
        // tiebreak, which is the honest position for "unknown".
        grabs: 0,
    })
}

/// Parse a search response.
///
/// **Strict on purpose, and this is the whole point of the function.**
/// A hardcoded third-party endpoint with its own schema is a rot risk -
/// it is the same objection that killed the scraper answer on #57, just
/// weaker - so the failure has to be LEGIBLE. When their schema moves,
/// a tolerant parser finds no rows it recognises and returns an empty
/// list, and an empty list is indistinguishable from "nothing matched
/// your search": the source looks like it is working and quietly
/// contributes nothing, forever. So:
///
/// - a body that is not JSON is an error, not zero results;
/// - `error: true` is the API's own error channel and is reported with
///   whatever it said;
/// - `data.content` missing or not an array is an error naming the
///   field, because that is the shape a rename would take;
/// - and a `content` that IS a non-empty array none of whose rows yield
///   an id and a name is an error too. That last one is the case a
///   field rename actually produces (`id` -> `collectionId` gives 25
///   rows and 25 unparseable ones), and it is the only one a
///   row-tolerant parser would swallow.
///
/// An `content: []` is the one empty answer that is NOT an error: it is
/// this API saying it has nothing, which is a real and common result.
pub fn parse_results(
    body: &str,
    cfg: &IndexerConfig,
) -> std::result::Result<Vec<SearchResult>, NewznabError> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|_| {
        // The body itself is never quoted: it is a third party's text
        // and it echoes our own request back (key included) often
        // enough that this codebase already has a scrubber for the
        // habit. The shape is what the user can act on.
        NewznabError::Api(
            0,
            "nzbindex: the response was not JSON - their API may have changed, \
             or something between us and them answered instead"
                .into(),
        )
    })?;
    if let Some(e) = parse_error(&v) {
        return Err(e);
    }
    let content = v.get("data").and_then(|d| d.get("content"));
    let Some(arr) = content.and_then(serde_json::Value::as_array) else {
        return Err(NewznabError::Api(
            0,
            "nzbindex: no data.content array in the response - their API has changed \
             and this source needs updating"
                .into(),
        ));
    };
    let out: Vec<SearchResult> = arr.iter().filter_map(|r| row(r, cfg)).collect();
    if out.is_empty() && !arr.is_empty() {
        return Err(NewznabError::Api(
            0,
            format!(
                "nzbindex: {} result(s) came back but none carried an id and a name - \
                 their API has changed and this source needs updating",
                arr.len()
            ),
        ));
    }
    Ok(out)
}

/// The API's own error channel: a top-level `error: true` with an
/// `errorMessage`. Their errors arrive as HTTP 200 the way Newznab's
/// do, so every body comes through here before anything else.
///
/// Rate limiting maps to [`NewznabError::Limit`] so the existing
/// per-entry backoff engages - that is the whole reason these reuse the
/// Newznab error type rather than getting one of their own. Their
/// documented reason for wanting a key is "to allow more requests per
/// second", so a rate refusal is the error this source is most likely
/// to meet, and the match is on the MESSAGE because the API publishes
/// no code space to switch on.
pub fn parse_error(v: &serde_json::Value) -> Option<NewznabError> {
    if v.get("error").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    let msg = v
        .get("errorMessage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim();
    let msg = if msg.is_empty() {
        "nzbindex reported an error but did not say what".to_string()
    } else {
        format!("nzbindex: {msg}")
    };
    let low = msg.to_ascii_lowercase();
    if low.contains("rate") || low.contains("limit") || low.contains("too many") {
        return Some(NewznabError::Limit(429, msg));
    }
    if low.contains("key") || low.contains("auth") || low.contains("forbidden") {
        return Some(NewznabError::Auth(100, msg));
    }
    Some(NewznabError::Api(0, msg))
}

#[cfg(test)]
#[path = "nzbindex_tests.rs"]
mod tests;
