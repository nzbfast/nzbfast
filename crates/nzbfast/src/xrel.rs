//! xREL P2P release lookup: a release name to an IMDb id, keyless.
//!
//! The gap this fills is specific. Scene predbs (and srrdb) carry the
//! scene groups and a good deal of scene-WEB, but the true-P2P "tagger"
//! groups - BYNDR and its neighbours - are absent from them, so a
//! perfectly well-named download from one of those groups still has no
//! identity to hang metadata on. xREL's P2P section carries exactly
//! those, with an `imdb:tt…` id, within a couple of days of posting, on
//! a documented keyless API.
//!
//! This is an enricher for content we can already NAME. It answers "what
//! is this release" and never "what is this obfuscated post" - the query
//! is a title, so a post with no readable name has nothing to ask with.
//!
//! Rate limits are published (xrel.to/wiki/2727) and the search methods
//! carry their own, tighter one: 2 calls per 5 seconds, under a 900/hour
//! ceiling. Both are honoured by `Provider::Xrel`, and the call sites
//! spend at most one search per user action.

use crate::ratelimit::{self, Provider};

/// One P2P release as xREL describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrelRelease {
    /// The release name ("Supergirl.2026.1080P.WEB.H264-POKE").
    pub dirname: String,
    /// Release group tag ("POKE"), empty when they did not say.
    pub group: String,
    /// IMDb id in `tt` form, empty when the entry carries none.
    pub imdb: String,
}

/// Pure parse of a `/v2/search/releases.json` body.
///
/// Entries with no IMDb id are kept: the caller matches on `dirname`,
/// and an entry that merely confirms the group tag is still worth
/// nothing to it - but dropping them here would make "we found the
/// release and it has no id" indistinguishable from "we found nothing",
/// and those are different answers.
pub fn parse_releases(body: &str) -> Vec<XrelRelease> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(results) = v.get("results").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    results
        .iter()
        .filter_map(|r| {
            let dirname = r.get("dirname")?.as_str()?.trim().to_string();
            if dirname.is_empty() {
                return None;
            }
            Some(XrelRelease {
                dirname,
                group: r
                    .get("group_name")
                    .and_then(|g| g.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                imdb: imdb_of(r),
            })
        })
        .collect()
}

/// The ids ride in `ext_info.uris` as prefixed strings
/// (`"imdb:tt8814476"`), alongside other services' - so this picks by
/// PREFIX rather than by position. A `uris` list whose first entry is a
/// TheMovieDB link is a real shape, and reading it positionally would
/// file a TMDB id in an IMDb column.
fn imdb_of(rel: &serde_json::Value) -> String {
    let Some(uris) = rel
        .get("ext_info")
        .and_then(|e| e.get("uris"))
        .and_then(|u| u.as_array())
    else {
        return String::new();
    };
    // Validated INSIDE the search, not after it: a first `imdb:` entry
    // that is malformed (or empty) used to be the answer, and a valid
    // one further down the list was never looked at.
    uris.iter()
        .filter_map(|u| u.as_str())
        .filter_map(|u| u.strip_prefix("imdb:").map(str::trim))
        .find(|id| {
            id.len() > 2 && id.starts_with("tt") && id[2..].chars().all(|c| c.is_ascii_digit())
        })
        .unwrap_or("")
        .to_string()
}

/// Search the P2P section for `query`. Empty on any failure, including
/// offline - the caller's fallback is the metadata it already had.
///
/// QUEUES for its rate-limit slot, so it belongs on a background path
/// (a finished download's identity pass), never on one a click is
/// waiting behind - see [`try_search_p2p`].
pub fn search_p2p(query: &str) -> Vec<XrelRelease> {
    let Some(url) = url_for(query) else {
        return Vec::new();
    };
    ratelimit::acquire(Provider::Xrel);
    fetch(&url)
}

/// [`search_p2p`] for an interactive path: REFUSES rather than queues
/// when the next slot is further out than `max_wait`.
///
/// The search budget here is 2 calls per 5 seconds, so a burst of
/// clicks would otherwise park one blocking API worker per click for
/// seconds at a time - which is how a dashboard stops polling. An
/// enrichment nobody asked for explicitly must never be the reason a
/// search feels slow: no slot, no id, same results.
#[cfg(feature = "indexer")]
pub fn try_search_p2p(query: &str, max_wait: std::time::Duration) -> Vec<XrelRelease> {
    let Some(url) = url_for(query) else {
        return Vec::new();
    };
    if !ratelimit::try_acquire(Provider::Xrel, max_wait) {
        return Vec::new();
    }
    fetch(&url)
}

fn url_for(query: &str) -> Option<String> {
    let q = query.trim();
    (!q.is_empty() && crate::identity::may_call_out()).then(|| {
        format!(
            "https://api.xrel.to/v2/search/releases.json?q={}&p2p=1",
            crate::newznab::urlenc(q)
        )
    })
}

fn fetch(url: &str) -> Vec<XrelRelease> {
    match crate::netfetch::shared_enrich_agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
    {
        Ok(r) => r
            .into_string()
            .map(|b| parse_releases(&b))
            .unwrap_or_default(),
        Err(e) => {
            if let ureq::Error::Status(code @ (429 | 503), r) = &e {
                // They send GitHub-style headers; `X-RateLimit-Reset` is
                // an absolute unix time, so it is not a wait in seconds
                // and must not be handed to `penalise` as one. Only the
                // standard header is trusted.
                let wait = r
                    .header("Retry-After")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(if *code == 429 { 30 } else { 5 });
                ratelimit::penalise(Provider::Xrel, wait);
            }
            Vec::new()
        }
    }
}

/// Release name (lowercased) to IMDb id, for the entries that carry one.
///
/// EXACT names only, and no consensus fallback - unlike
/// [`imdb_for_release`], which answers about one release the caller
/// already believes it has identified. A pull search is free text: "the
/// matrix" legitimately returns several different films, and taking the
/// majority id across them would stamp one film's id onto another's row.
#[cfg(feature = "indexer")]
pub fn by_dirname(hits: &[XrelRelease]) -> std::collections::HashMap<String, String> {
    hits.iter()
        .filter(|h| !h.imdb.is_empty())
        .map(|h| (h.dirname.to_ascii_lowercase(), h.imdb.clone()))
        .collect()
}

/// The IMDb id xREL holds for a specific release name, or for the query
/// as a whole when the exact name is not among the answers.
///
/// Exact-name agreement is preferred because it is the strongest claim
/// available: the same release, same group. Falling back to "every P2P
/// hit for this query agrees on one id" is safe for the case that
/// matters (a tagger group's own encode of a film, listed beside its
/// siblings); a query that turns up two different films agrees on
/// nothing and yields nothing.
pub fn imdb_for_release(name: &str, hits: &[XrelRelease]) -> String {
    let want = name.trim().to_ascii_lowercase();
    if let Some(exact) = hits
        .iter()
        .find(|h| h.dirname.to_ascii_lowercase() == want && !h.imdb.is_empty())
    {
        return exact.imdb.clone();
    }
    let mut ids = hits
        .iter()
        .map(|h| h.imdb.as_str())
        .filter(|i| !i.is_empty());
    let Some(first) = ids.next() else {
        return String::new();
    };
    if ids.all(|i| i == first) {
        first.to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed copy of the live 28 Jul answer for the POKE case the
    /// research doc used - the tagger group scene sources miss.
    const REAL: &str = r#"{
      "total": 38,
      "results": [
        {"id":"9c5559763680e4","dirname":"Supergirl.2026.HDR.2160P.WEB.H265-POKE",
         "group_name":"POKE","time":1785107350,
         "ext_info":{"type":"movie","title":"Supergirl","uris":["imdb:tt8814476"]}},
        {"id":"aac877153680e3","dirname":"Supergirl.2026.1080P.WEB.H264-POKE",
         "group_name":"POKE","time":1785107314,
         "ext_info":{"type":"movie","title":"Supergirl","uris":["imdb:tt8814476"]}}
      ]}"#;

    #[test]
    fn the_real_response_yields_names_groups_and_ids() {
        let hits = parse_releases(REAL);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].dirname, "Supergirl.2026.HDR.2160P.WEB.H265-POKE");
        assert_eq!(hits[0].group, "POKE");
        assert_eq!(hits[0].imdb, "tt8814476");
    }

    #[test]
    fn ids_are_picked_by_prefix_not_by_position() {
        let body = r#"{"results":[{"dirname":"A.Film.2019-GRP","group_name":"GRP",
            "ext_info":{"uris":["themoviedb:12345","tvmaze:99","imdb:tt0076759"]}}]}"#;
        assert_eq!(parse_releases(body)[0].imdb, "tt0076759");
        // No IMDb entry at all: the release is still reported, without one.
        let body = r#"{"results":[{"dirname":"A.Film.2019-GRP",
            "ext_info":{"uris":["themoviedb:12345"]}}]}"#;
        assert_eq!(parse_releases(body)[0].imdb, "");
        // A malformed id is not an id.
        let body = r#"{"results":[{"dirname":"A.Film.2019-GRP",
            "ext_info":{"uris":["imdb:nm0000123","imdb:ttxyz","imdb:tt"]}}]}"#;
        assert_eq!(parse_releases(body)[0].imdb, "");
    }

    #[test]
    fn malformed_bodies_are_no_results_not_a_panic() {
        for body in [
            "",
            "null",
            "not json",
            r#"{"results":null}"#,
            r#"{"total":0,"results":[]}"#,
            r#"{"results":[{"group_name":"POKE"}]}"#, // no dirname
            r#"{"results":[{"dirname":"   "}]}"#,
        ] {
            assert!(parse_releases(body).is_empty(), "{body:?}");
        }
        // A wrongly-typed `ext_info` costs the ID, not the release: the
        // caller may still be matching names.
        let odd = r#"{"results":[{"dirname":"A.Film.2019-GRP","ext_info":"not an object"}]}"#;
        let hits = parse_releases(odd);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].imdb, "");
    }

    #[test]
    fn an_exact_name_match_outranks_the_consensus() {
        let hits = vec![
            XrelRelease {
                dirname: "A.Film.2019.1080p-GRP".into(),
                group: "GRP".into(),
                imdb: "tt1111111".into(),
            },
            XrelRelease {
                dirname: "B.Film.2019.1080p-GRP".into(),
                group: "GRP".into(),
                imdb: "tt2222222".into(),
            },
        ];
        assert_eq!(
            imdb_for_release("a.film.2019.1080p-grp", &hits),
            "tt1111111"
        );
        // No exact match, and the hits disagree: no answer rather than a
        // coin toss, because this id goes on a history record.
        assert_eq!(imdb_for_release("C.Film.2019-GRP", &hits), "");
        // No exact match but unanimous: the query found one film's
        // encodes, which is the case this exists for.
        let agree: Vec<_> = hits
            .iter()
            .cloned()
            .map(|mut h| {
                h.imdb = "tt1111111".into();
                h
            })
            .collect();
        assert_eq!(imdb_for_release("C.Film.2019-GRP", &agree), "tt1111111");
        assert_eq!(imdb_for_release("X", &[]), "");
    }
}
