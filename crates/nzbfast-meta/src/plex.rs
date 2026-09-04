//! TODO 151 (issue #36): Plex's own wire formats, as the first list
//! source. Pure parsing and address building - no I/O, no daemon.
//! `crates/nzbfast-daemon/src/listsrc.rs` owns the fetching, exactly as `newznab.rs` and
//! `indexers.rs` divide the M35 client.
//!
//! Three shapes live here, because a Plex watchlist is reachable two
//! ways and the second one has to be linked first:
//!
//! 1. **The Watchlist RSS feed** the user pastes in. An `<item>` per
//!    title, with `<category>` saying `show` or `movie` and a `<guid>`
//!    carrying an `imdb://` / `tvdb://` / `tmdb://` id. There is no year
//!    element, which is fine: we match on title and year and a year-less
//!    item matches any year.
//! 2. **The account watchlist** at `discover.provider.plex.tv`, which
//!    needs a token and returns the WHOLE list rather than the most
//!    recent 50. Watchlist data is account-level cloud data, so a
//!    server-scoped token does not reach it.
//! 3. **The plex.tv PIN flow** that produces that token, which is the
//!    only version of account linking worth shipping: the user approves
//!    on Plex's own page and no password ever reaches us.
//!
//! Sonarr and Radarr both REFUSE a watchlist item that carries no
//! external id (their `PlexRssImportParser` needs one to hand to their
//! own metadata layer). We must not: our matching is title + year, so an
//! id-less entry works perfectly well and dropping it would silently
//! lose titles. The ids are kept anyway - they cost nothing and are the
//! obvious way to make matching precise later - but nothing sends them
//! anywhere, and a tvdbid in particular must never reach a Newznab
//! indexer (M35 deliberately sends none).
//!
//! Tolerance rule, the same one `rss.rs` settled on: junk INSIDE a
//! document is skipped rather than failing the fetch, but a body that is
//! not the document at all must FAIL. An expired Plex token is answered
//! with an HTTP 200 that is not a watchlist, and a tolerant parser would
//! record that as a healthy list with nothing on it - which is the one
//! reading that could unwatch everything.

use crate::listsrc::ListEntry;
use crate::rss::{attr, elem_tags, find_elem, tag_text, unescape, wrong_document};

/// Where a linked account's watchlist is read. The older
/// `metadata.provider.plex.tv` path is deprecated and answered 404 for
/// third-party readers when it moved.
pub const DISCOVER_BASE: &str = "https://discover.provider.plex.tv";
/// How many titles one page asks for. 300 is what watchlistarr uses.
pub const PAGE_SIZE: usize = 300;
/// Stop paging here no matter what the server says. A watchlist is
/// hundreds of titles; 20 pages is 6,000, and the cap exists so a server
/// that ignores the container offsets cannot loop for ever.
pub const MAX_PAGES: usize = 20;
/// Where the PIN flow starts.
pub const PIN_URL: &str = "https://plex.tv/api/v2/pins?strong=true";
/// The page the user approves the code on.
pub const LINK_PAGE: &str = "https://plex.tv/link";
/// What we tell Plex we are, in `X-Plex-Product`. It is what the user
/// sees in their Plex account's authorised-devices list, so it is the
/// product name and nothing cleverer.
pub const PRODUCT: &str = "nzbfast";

/// One page of the account watchlist.
///
/// `includeElements=Guid` is what makes the external ids arrive at all;
/// `sort=watchlistedAt:desc` puts the newest first, so a truncated read
/// still carries the titles most likely to be wanted.
///
/// The token is NOT in here on purpose. It goes in the `X-Plex-Token`
/// header instead, which keeps it out of every error message that names
/// the url - ureq's errors lead with the url, and the log tee mirrors
/// them into the dashboard's log.
pub fn watchlist_url(start: usize) -> String {
    format!(
        "{DISCOVER_BASE}/library/sections/watchlist/all\
         ?includeFields=title,type,year&includeElements=Guid\
         &sort=watchlistedAt:desc&X-Plex-Container-Start={start}\
         &X-Plex-Container-Size={PAGE_SIZE}"
    )
}

/// Where a started PIN is polled for its token.
pub fn pin_poll_url(id: &str) -> String {
    format!("https://plex.tv/api/v2/pins/{id}")
}

/// A started PIN link. `token` is empty until the user has approved it,
/// which is the entire state machine.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Pin {
    /// Plex's id for this pin, used to poll it.
    pub id: String,
    /// The four-character code the user types at [`LINK_PAGE`].
    pub code: String,
    /// The account token, once approved. Empty means "not yet".
    pub token: String,
}

/// Read a `POST /pins` or `GET /pins/{id}` answer.
///
/// Nothing from the body is echoed into the error: this is a remote
/// server's text on its way to a dashboard toast.
pub fn parse_pin(body: &str) -> Result<Pin, String> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| "Plex did not answer the link request with a code".to_string())?;
    let id = match &v["id"] {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => String::new(),
    };
    if id.is_empty() {
        return Err("Plex did not answer the link request with a code".into());
    }
    Ok(Pin {
        id,
        code: v["code"].as_str().unwrap_or_default().trim().to_string(),
        // `authToken` is null until the user approves the code. That is
        // the normal answer to most polls, not a failure.
        token: v["authToken"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .to_string(),
    })
}

/// The tag text and inner XML of every element in `xml` whose local name
/// is `local`; a self-closing element yields an empty body.
///
/// Built on `rss.rs`'s scanner rather than beside it - this crate has one
/// XML reader and it stays that way.
fn blocks<'a>(xml: &'a str, local: &str) -> Vec<(&'a str, &'a str)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some((open, name)) = find_elem(&xml[at..], local) {
        let open = at + open;
        let Some(gt) = xml[open..].find('>').map(|g| open + g) else {
            break;
        };
        let tag = &xml[open..gt];
        if tag.ends_with('/') {
            out.push((tag, ""));
            at = gt + 1;
            continue;
        }
        let close = format!("</{name}>");
        match xml[gt + 1..].find(&close) {
            Some(e) => {
                out.push((tag, &xml[gt + 1..gt + 1 + e]));
                at = gt + 1 + e + close.len();
            }
            None => {
                // An unclosed element: take the tag, keep scanning.
                out.push((tag, ""));
                at = gt + 1;
            }
        }
    }
    out
}

/// Plex's word for what a title is, in ours. `None` for anything else,
/// which is skipped: a wrong kind would watch the wrong shape (a film
/// has one slot, a series has one per episode), and guessing is worse
/// than leaving one title out of a list the user can see.
fn kind_of(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().as_str() {
        "show" | "series" | "tv" => Some("tv"),
        "movie" | "film" => Some("movie"),
        _ => None,
    }
}

/// Split a trailing `(YYYY)` off a title.
///
/// The RSS feed has no year element, and some feeds put the year in the
/// title instead. Where it is there it is worth having - it is what
/// tells the two films called "Dune" apart - and where it is not, a
/// year-less item still matches, so this never has to guess.
fn split_year(title: &str) -> (String, Option<u32>) {
    let t = title.trim();
    if t.ends_with(')')
        && let Some(open) = t.rfind('(')
        && let Ok(y) = t[open + 1..t.len() - 1].parse::<u32>()
        && (1870..=2200).contains(&y)
    {
        return (t[..open].trim().to_string(), Some(y));
    }
    (t.to_string(), None)
}

/// Every `imdb://` / `tmdb://` / `tvdb://` id in a blob of XML.
fn guid_ids(ids: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in ids {
        let id = unescape(id.trim());
        // A plex:// guid is Plex's own internal identity, which means
        // nothing to anyone else. The three that matter are the ones
        // every other tool speaks.
        if !["imdb://", "tmdb://", "tvdb://"]
            .iter()
            .any(|p| id.starts_with(p))
        {
            continue;
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// Parse a Plex **Watchlist RSS** body.
///
/// `Err` only for a body that is not a feed at all - see the module doc.
/// Items it cannot read (no title, an unknown category) are skipped.
pub fn parse_watchlist_rss(xml: &str) -> Result<Vec<ListEntry>, String> {
    const FEED_ROOTS: [&str; 4] = ["rss", "feed", "rdf", "channel"];
    if let Some(what) = wrong_document(xml, &FEED_ROOTS, "a Plex watchlist feed") {
        return Err(what);
    }
    let mut out = Vec::new();
    for (_, item) in blocks(xml, "item") {
        let raw = tag_text(item, "title").map(unescape).unwrap_or_default();
        let (title, year) = split_year(&raw);
        if title.is_empty() {
            continue;
        }
        let Some(kind) = tag_text(item, "category")
            .map(unescape)
            .as_deref()
            .and_then(kind_of)
        else {
            continue;
        };
        out.push(ListEntry {
            title,
            year,
            kind: kind.to_string(),
            ids: guid_ids(
                blocks(item, "guid")
                    .into_iter()
                    .map(|(_, body)| body.to_string()),
            ),
        });
    }
    Ok(out)
}

/// Parse one page of the **account** watchlist from
/// `discover.provider.plex.tv`.
///
/// Returns the entries and how many title elements the page actually
/// carried - the caller pages on the second number, not the first, or a
/// page of titles we skipped would look like the end of the list.
pub fn parse_watchlist_xml(xml: &str) -> Result<(Vec<ListEntry>, usize), String> {
    const ROOTS: [&str; 1] = ["MediaContainer"];
    if let Some(what) = wrong_document(xml, &ROOTS, "a Plex watchlist") {
        return Err(what);
    }
    let mut out = Vec::new();
    let mut seen = 0usize;
    // Plex answers with `Video` for films and `Directory` for shows, and
    // `Metadata` when the request went through the newer JSON-shaped
    // endpoints. All three carry the same attributes, so read all three
    // rather than betting on which one this account's server sends.
    for local in ["Video", "Directory", "Metadata"] {
        for (tag, body) in blocks(xml, local) {
            let Some(kind) = attr(tag, "type").and_then(kind_of) else {
                continue;
            };
            seen += 1;
            let raw = attr(tag, "title").map(unescape).unwrap_or_default();
            // The account endpoint DOES send a year attribute; only fall
            // back to reading one out of the title when it does not.
            let (title, from_title) = split_year(&raw);
            if title.is_empty() {
                continue;
            }
            let year = attr(tag, "year")
                .and_then(|y| y.parse::<u32>().ok())
                .filter(|y| (1870..=2200).contains(y))
                .or(from_title);
            let mut ids: Vec<&str> = elem_tags(body, "Guid");
            if ids.is_empty() {
                ids = elem_tags(body, "guid");
            }
            out.push(ListEntry {
                title,
                year,
                kind: kind.to_string(),
                ids: guid_ids(
                    ids.into_iter()
                        .filter_map(|t| attr(t, "id"))
                        .map(str::to_string),
                ),
            });
        }
    }
    Ok((out, seen))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real Watchlist RSS item, in the shape Sonarr's and Radarr's own
    /// `PlexRssImportParser` reads: title, category, guid, and no year.
    #[test]
    fn a_watchlist_rss_item_becomes_an_entry() {
        let xml = "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>\
            <title>Watchlist</title>\
            <item><title>The Bear</title><category>show</category>\
              <guid isPermaLink=\"false\">tvdb://390545</guid></item>\
            <item><title>Dune: Part Two</title><category>movie</category>\
              <guid isPermaLink=\"false\">imdb://tt15239678</guid></item>\
            </channel></rss>";
        let got = parse_watchlist_rss(xml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].title, "The Bear");
        assert_eq!(got[0].kind, "tv"); // `show` is our "tv"
        assert_eq!(got[0].year, None); // the feed carries no year
        assert_eq!(got[0].ids, vec!["tvdb://390545"]);
        assert_eq!(got[1].kind, "movie");
        assert_eq!(got[1].ids, vec!["imdb://tt15239678"]);
    }

    /// Sonarr and Radarr drop an item with no external id. We must not:
    /// matching is title + year, so it works, and dropping it would lose
    /// a title off the user's own list with nothing said.
    #[test]
    fn an_item_with_no_external_id_still_counts() {
        let xml = "<rss><channel><item><title>Some Film (1998)</title>\
            <category>movie</category></item></channel></rss>";
        let got = parse_watchlist_rss(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].title, "Some Film");
        assert_eq!(got[0].year, Some(1998)); // read off the title
        assert!(got[0].ids.is_empty());
    }

    /// Junk inside a feed is skipped; the feed still parses.
    #[test]
    fn junk_inside_a_feed_is_skipped_not_fatal() {
        let xml = "<rss><channel>\
            <item><title></title><category>movie</category></item>\
            <item><category>show</category></item>\
            <item><title>No Category Here</title></item>\
            <item><title>Odd Kind</title><category>artist</category></item>\
            <item><title>The Bear</title><category>show</category></item>\
            </channel></rss>";
        let got = parse_watchlist_rss(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].title, "The Bear");
    }

    /// The one that matters: an HTTP 200 that is not the document. A
    /// revoked RSS url serves a login page, and a tolerant parser would
    /// call that a healthy list with nothing on it - the single reading
    /// that could unwatch everything.
    #[test]
    fn a_login_page_is_a_failure_not_an_empty_list() {
        let login = "<!DOCTYPE html><html><head><title>Sign in</title></head>\
                     <body><form><input name=\"user\"></form></body></html>";
        let e = parse_watchlist_rss(login).expect_err("a login page is not a feed");
        assert!(e.contains("web page"), "{e}");
        // Nothing of the body is echoed back - it is attacker-shaped text
        // on its way to the dashboard.
        assert!(!e.contains("Sign in"), "{e}");
        assert!(parse_watchlist_rss("").is_err(), "an empty body");
        assert!(
            parse_watchlist_xml(login).is_err(),
            "and the same on the account endpoint"
        );
        assert!(
            parse_watchlist_xml("{\"error\":\"expired\"}").is_err(),
            "a JSON error body is not a watchlist"
        );
        // ...while a genuinely EMPTY list stays healthy, on both legs.
        assert_eq!(
            parse_watchlist_rss("<rss><channel/></rss>").unwrap().len(),
            0
        );
        assert_eq!(
            parse_watchlist_xml("<MediaContainer size=\"0\"/>")
                .unwrap()
                .0
                .len(),
            0
        );
    }

    /// A feed cut off mid-item: what parsed, parses.
    #[test]
    fn a_truncated_feed_keeps_what_it_read() {
        let xml = "<rss><channel>\
            <item><title>The Bear</title><category>show</category></item>\
            <item><title>Half An I";
        let got = parse_watchlist_rss(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].title, "The Bear");
    }

    /// The account endpoint's own shape: `Video` for films, `Directory`
    /// for shows, a `year` attribute, and `<Guid>` CHILDREN rather than
    /// a guid element of its own.
    #[test]
    fn an_account_watchlist_page_becomes_entries() {
        let xml = "<MediaContainer size=\"2\" totalSize=\"2\">\
            <Video ratingKey=\"5d7\" type=\"movie\" title=\"Dune\" year=\"2021\">\
              <Guid id=\"imdb://tt1160419\"/><Guid id=\"tmdb://438631\"/>\
              <Guid id=\"plex://movie/5d7768\"/>\
            </Video>\
            <Directory ratingKey=\"5d9\" type=\"show\" title=\"The Bear\" year=\"2022\">\
              <Guid id=\"tvdb://390545\"/>\
            </Directory>\
            </MediaContainer>";
        let (got, seen) = parse_watchlist_xml(xml).unwrap();
        assert_eq!(seen, 2);
        assert_eq!(got.len(), 2);
        let film = got.iter().find(|e| e.kind == "movie").unwrap();
        assert_eq!(film.title, "Dune");
        assert_eq!(film.year, Some(2021));
        // plex:// is Plex's own identity and means nothing elsewhere.
        assert_eq!(film.ids, vec!["imdb://tt1160419", "tmdb://438631"]);
        let show = got.iter().find(|e| e.kind == "tv").unwrap();
        assert_eq!(show.title, "The Bear");
        assert_eq!(show.year, Some(2022));
    }

    /// `Metadata` is the same title in the newer element name, and a
    /// self-closing element (no `includeElements=Guid`) is still a title.
    #[test]
    fn the_newer_element_name_and_a_childless_entry_both_read() {
        let xml = "<MediaContainer>\
            <Metadata type=\"show\" title=\"Severance\" year=\"2022\"/>\
            </MediaContainer>";
        let (got, seen) = parse_watchlist_xml(xml).unwrap();
        assert_eq!(seen, 1);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, "tv");
        assert!(got[0].ids.is_empty());
    }

    /// Paging counts what the PAGE carried, not what we kept, or one
    /// page of unreadable titles would look like the end of the list.
    #[test]
    fn the_page_count_is_what_arrived_not_what_was_kept() {
        let xml = "<MediaContainer>\
            <Video type=\"movie\" title=\"\"/>\
            <Video type=\"movie\" title=\"Dune\" year=\"2021\"/>\
            <Video type=\"artist\" title=\"Someone\"/>\
            </MediaContainer>";
        let (got, seen) = parse_watchlist_xml(xml).unwrap();
        assert_eq!(got.len(), 1);
        // The empty title counted (it was a film), the artist did not
        // (it was never a watchlist title of a kind we take).
        assert_eq!(seen, 2);
    }

    /// The PIN flow, both halves. `authToken: null` is the normal answer
    /// to almost every poll, not an error.
    #[test]
    fn a_pin_is_read_before_and_after_approval() {
        let started = parse_pin("{\"id\":123456,\"code\":\"WXYZ\",\"authToken\":null}").unwrap();
        assert_eq!(started.id, "123456");
        assert_eq!(started.code, "WXYZ");
        assert!(started.token.is_empty(), "not approved yet");
        let done =
            parse_pin("{\"id\":\"123456\",\"code\":\"WXYZ\",\"authToken\":\"tok-abc\"}").unwrap();
        assert_eq!(done.token, "tok-abc");
        // A body that is not the answer at all fails, and says nothing
        // about what was in it.
        assert!(parse_pin("<html>Sign in</html>").is_err());
        assert!(parse_pin("{\"error\":\"nope\"}").is_err());
    }

    /// The token is never in the address. ureq's errors lead with the
    /// url they were handed and the log tee mirrors them to the
    /// dashboard, so a token in the query string would be a token in the
    /// log the first time Plex answered anything but 200.
    #[test]
    fn the_read_address_carries_no_credential() {
        let u = watchlist_url(300);
        assert!(!u.to_lowercase().contains("x-plex-token"), "{u}");
        assert!(u.contains("X-Plex-Container-Start=300"), "{u}");
        assert!(u.contains("includeElements=Guid"), "{u}");
        assert!(u.starts_with(DISCOVER_BASE), "{u}");
    }
}
