//! srrdb archive-CRC lookup: a payload CRC32 to a canonical release
//! name and an IMDb id, keyless, in one request.
//!
//! Where the CRC comes from: a RAR header that is not password-encrypted
//! states the CRC32 of each inner file, and the extractor already reads
//! those headers on the way past. So for a set whose headers open, we
//! hold an exact key into srrdb's index without fetching one extra byte
//! from usenet and without hashing anything ourselves.
//!
//! Exact key, not a tolerance. That is what separates this from the
//! size-and-date correlation the earlier research closed: a CRC32 either
//! is in their index or is not, and a hit is a certain identification of
//! the same bytes rather than a plausible neighbour.
//!
//! Applicability is narrow and known: header-encrypted (`-hp`) archives
//! expose no inner CRC at all, and among *obfuscated* posts `-hp` is the
//! common case. This pays on the ordinary scene-WEB set whose subject
//! was scrambled but whose archive was not, and it costs one request.
//!
//! Politeness is structural, because srrdb's terms ask callers to use
//! the API rather than scrape it: at most one lookup per finished
//! download, a process-lifetime cache so a retried or re-downloaded job
//! never asks twice, a token bucket in front, and silence on every
//! error. Nothing here retries.

use crate::tools::MutexExt;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::identity::SrrHit;
use crate::ratelimit::{self, Provider};

/// srrdb reports the id as a bare number ("15239678"); every other id in
/// this daemon (`titles.imdb`, Wikidata P345, TVmaze externals) is the
/// `tt` form, and a column carrying both spellings joins to nothing.
///
/// Zero-padded to seven digits, which is how IMDb itself writes the
/// short ones - `tt76759` is not a URL, `tt0076759` is.
fn tconst(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() || raw == "0" {
        return String::new();
    }
    if let Some(rest) = raw.strip_prefix("tt") {
        return if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
            raw.to_string()
        } else {
            String::new()
        };
    }
    if !raw.chars().all(|c| c.is_ascii_digit()) {
        return String::new();
    }
    format!("tt{raw:0>7}")
}

/// Pure parse of a `/v1/search/archive-crc:` response body.
///
/// A CRC32 is 32 bits, so a collision across the whole of srrdb is not
/// impossible - but a collision produces MORE THAN ONE result, and this
/// declines the whole answer in that case rather than picking one. A
/// name is about to be stamped on a user's file; "probably this one" is
/// not good enough for that, and a decline costs only the name we did
/// not have anyway.
pub fn parse_archive_crc(body: &str) -> Option<SrrHit> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let results = v.get("results")?.as_array()?;
    let [only] = results.as_slice() else {
        return None;
    };
    let release = only.get("release")?.as_str()?.trim().to_string();
    if release.is_empty() {
        return None;
    }
    let imdb = only
        .get("imdbId")
        .map(|i| match i {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => String::new(),
        })
        .map(|s| tconst(&s))
        .unwrap_or_default();
    Some(SrrHit { release, imdb })
}

/// Every CRC this process has asked about, and what came back. `None` is
/// cached as deliberately as a hit: a CRC srrdb does not hold will not
/// start being held during one daemon's lifetime, and re-asking on every
/// retry of a failing job is exactly the scraping the terms ask us not
/// to do.
fn cache() -> &'static Mutex<HashMap<u32, Option<SrrHit>>> {
    static C: OnceLock<Mutex<HashMap<u32, Option<SrrHit>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look one inner-file CRC32 up. `None` for "not found", for "asked and
/// got no usable answer", and for "offline" alike - the caller's
/// fallback is the name it already had, so the three do not need telling
/// apart.
pub fn archive_crc(crc: u32) -> Option<SrrHit> {
    if let Some(cached) = cache().lock_ok().get(&crc) {
        return cached.clone();
    }
    let (hit, answered) = fetch(crc);
    // Only what the SERVICE said is worth remembering. A refusal to call
    // out, a transport error and a 429 say nothing about this CRC, and
    // caching them for the process lifetime left every later retry of the
    // job nameless long after the network came back.
    if answered {
        cache().lock_ok().insert(crc, hit.clone());
    }
    hit
}

/// `(answer, answered)` - see [`archive_crc`] for why the second half
/// exists. `answered` is false whenever we never got a body to read.
fn fetch(crc: u32) -> (Option<SrrHit>, bool) {
    if !crate::identity::may_call_out() {
        return (None, false);
    }
    // Upper hex, no separator, as the endpoint's own examples write it.
    let url = format!("https://api.srrdb.com/v1/search/archive-crc:{crc:08X}");
    ratelimit::acquire(Provider::Srrdb);
    let resp = crate::netfetch::shared_enrich_agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .call();
    match resp {
        Ok(r) => match r.into_string() {
            Ok(body) => (parse_archive_crc(&body), true),
            Err(_) => (None, false),
        },
        Err(e) => {
            // Back off the whole lane on an explicit "slow down", so the
            // next finished download does not walk into the same wall.
            if let ureq::Error::Status(code @ (429 | 503), r) = &e {
                let wait = r
                    .header("Retry-After")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(if *code == 429 { 30 } else { 5 });
                ratelimit::penalise(Provider::Srrdb, wait);
            }
            (None, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live 28 Jul round-trip, byte for byte, so a future edit to
    /// the parser is measured against what the service actually sends.
    const REAL: &str = r#"{"results":[{"release":"Dune.Part.Two.2024.1080p.WEB.h264-ETHEL","date":"2024-04-15 01:04:34","hasNFO":"yes","hasSRS":"yes","isForeign":"no","imdbId":"15239678","size":9309662767}],"resultsCount":1,"warnings":[],"query":["073E0DDF"]}"#;

    #[test]
    fn the_real_response_yields_a_name_and_a_tconst() {
        let hit = parse_archive_crc(REAL).expect("the live shape parses");
        assert_eq!(hit.release, "Dune.Part.Two.2024.1080p.WEB.h264-ETHEL");
        assert_eq!(hit.imdb, "tt15239678");
    }

    /// A CRC32 collision produces two results. Picking one would stamp
    /// the wrong film's name onto a user's download, so the whole answer
    /// is declined.
    #[test]
    fn an_ambiguous_crc_is_declined_not_guessed() {
        let two = r#"{"results":[{"release":"A.Film.2019-GRP","imdbId":"1"},
                                 {"release":"Another.Film.2020-GRP","imdbId":"2"}],
                      "resultsCount":2}"#;
        assert_eq!(parse_archive_crc(two), None);
    }

    #[test]
    fn empty_and_malformed_answers_are_no_answer() {
        assert_eq!(
            parse_archive_crc(r#"{"results":[],"resultsCount":0}"#),
            None
        );
        assert_eq!(parse_archive_crc(r#"{"results":[{"imdbId":"1"}]}"#), None);
        assert_eq!(parse_archive_crc(r#"{"results":[{"release":"  "}]}"#), None);
        assert_eq!(parse_archive_crc("not json at all"), None);
        assert_eq!(parse_archive_crc(""), None);
        // An HTML error page is a plausible thing for a CDN to answer with.
        assert_eq!(parse_archive_crc("<html><body>502</body></html>"), None);
    }

    /// A release with no IMDb id on file is still a name worth having.
    #[test]
    fn a_missing_id_leaves_the_name_usable() {
        let body = r#"{"results":[{"release":"Some.Software.2019-GRP"}],"resultsCount":1}"#;
        assert_eq!(parse_archive_crc(body).unwrap().imdb, "");
        // …and so does an id that is not a number.
        let body = r#"{"results":[{"release":"X.2019-GRP","imdbId":"none"}],"resultsCount":1}"#;
        assert_eq!(parse_archive_crc(body).unwrap().imdb, "");
        // Some endpoints send it as a JSON number rather than a string.
        let body = r#"{"results":[{"release":"X.2019-GRP","imdbId":76759}],"resultsCount":1}"#;
        assert_eq!(parse_archive_crc(body).unwrap().imdb, "tt0076759");
    }

    #[test]
    fn ids_normalise_to_the_tt_form_the_rest_of_the_daemon_uses() {
        assert_eq!(tconst("15239678"), "tt15239678");
        assert_eq!(tconst("76759"), "tt0076759"); // padded, as IMDb writes it
        assert_eq!(tconst("tt15239678"), "tt15239678");
        assert_eq!(tconst("0"), "");
        assert_eq!(tconst(""), "");
        assert_eq!(tconst("nm0000123"), "");
        assert_eq!(tconst("tt"), "");
    }
}
