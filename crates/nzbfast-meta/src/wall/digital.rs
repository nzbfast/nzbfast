//! Keyless at-home (digital) movie release calendars - the movie half
//! of the expectation oracle (`tasks/expected.rs`).
//!
//! The oracle wants one thing: which films landed for HOME viewing in a
//! short date window, as `{title, year}`, so the confirm lane can go and
//! search the reference indexer for the post that follows a day-and-date
//! release. `wall::tmdb_digital_releases` answers that from TMDB's
//! `discover` endpoint with `with_release_type=4`, and it needs a key
//! that users of an NZB client cannot legitimately obtain (TMDB declines
//! the application class and requires KYC - memory topic
//! `nzbfast-enrichment-providers`). So on every keyless install the
//! movie half was dormant. This module is the fix (2 Sep 2026).
//!
//! `research/KEYLESS-MOVIE-DATES-2026-09-02.md` probed ten candidate
//! sources live. Two survived every test (no key, reachable headless,
//! robots-permitted, no scrape clause, digital dates kept apart from
//! disc dates, stable server-rendered markup):
//!
//! - **dvdsreleasedates.com** `/digital-releases/<yyyy>/<m>/` - the
//!   PRIMARY. One page per month, grouped under "Tuesday September 8,
//!   2026" headings; each film cell carries the title anchor and a
//!   poster whose filename ends in the release year. Majors and
//!   mid-tier only, which is what gets posted in volume, and it errs
//!   toward missing a small title rather than inventing a date.
//! - **bingebase.com** `/releases/digital/<month>-<yyyy>` - the
//!   FALLBACK, read only when the primary yields nothing for the
//!   window. Broader (about three times the titles), the year is in
//!   the slug, per-day sections carry ISO ids. Its markup is a Tailwind
//!   and Turbo build and may churn, which is why it is second.
//!
//! Rejected with reasons in the memo: Wikidata (two qualified digital
//! dates in a month), JustWatch / Rotten Tomatoes / IMDb (terms forbid
//! it), OMDb (no window query), xREL (no date field), the store RSS
//! feeds (gone), TMDB's keyless exports (no dates), Radarr's metadata
//! relay (a sister project's private TMDB proxy).
//!
//! A TMDB key, when the user has one, is still asked FIRST - it is the
//! richest source and the code was already here. The keyless pair is
//! what runs for everyone else, and what a key-holder falls through to
//! when TMDB answers empty.
//!
//! Both parsers are pure functions over the page text (tested on
//! fixtures under `testdata/`), so a markup change fails a unit test
//! rather than the oracle silently. Both sites can also die the way
//! iTunes did - a 200 with nothing in it - which no fixture can catch,
//! so `digital_calendars_answer_live` is the `#[ignore]`d live smoke in
//! the pattern of `keyless_movie_chain_answers_live`.
//!
//! Stated limits: no cache - the oracle sweeps twice a day and a
//! 3-day window touches at most two month pages, so a fetch per sweep
//! is the whole cost. English month names only, which is what both
//! sites render. The dvdsreleasedates year comes from the poster
//! filename and is 0 when a cell has no poster; the oracle's query
//! tolerates a missing year.

use super::{MovieRelease, get_body};
use crate::ratelimit::Provider;

/// Which calendar answered, for the sweep's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigitalSource {
    Tmdb,
    DvdsReleaseDates,
    BingeBase,
    /// Every source answered empty (or the call-out gate is shut).
    None,
}

/// Films released for home viewing with `gte <= date <= lte` (ISO
/// `YYYY-MM-DD`, inclusive). TMDB first when a key is given, then the
/// keyless primary, then the keyless fallback; the first non-empty
/// answer wins and is named. Empty when nothing answered.
pub fn digital_releases(
    tmdb_key: Option<&str>,
    gte: &str,
    lte: &str,
) -> (Vec<MovieRelease>, DigitalSource) {
    if let Some(k) = tmdb_key.filter(|k| !k.is_empty()) {
        let v = super::tmdb_digital_releases(k, gte, lte);
        if !v.is_empty() {
            return (v, DigitalSource::Tmdb);
        }
    }
    let months = months_in(gte, lte);
    let mut out = Vec::new();
    for (y, m) in &months {
        if let Some(html) = get_body(Provider::DvdsReleaseDates, &dvdsrd_url(*y, *m)) {
            out.extend(parse_dvdsrd_month(&html, gte, lte));
        }
    }
    if !out.is_empty() {
        return (dedup(out), DigitalSource::DvdsReleaseDates);
    }
    for (y, m) in &months {
        if let Some(html) = get_body(Provider::BingeBase, &bingebase_url(*y, *m)) {
            out.extend(parse_bingebase_month(&html, gte, lte));
        }
    }
    if !out.is_empty() {
        return (dedup(out), DigitalSource::BingeBase);
    }
    (Vec::new(), DigitalSource::None)
}

fn dvdsrd_url(y: u32, m: u32) -> String {
    format!("https://www.dvdsreleasedates.com/digital-releases/{y}/{m}/")
}

fn bingebase_url(y: u32, m: u32) -> String {
    format!(
        "https://bingebase.com/releases/digital/{}-{y}",
        MONTHS[(m as usize).clamp(1, 12) - 1]
    )
}

const MONTHS: [&str; 12] = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

/// The `(year, month)` pages a window touches, oldest first, capped at
/// three so a malformed window cannot fan out into a crawl.
fn months_in(gte: &str, lte: &str) -> Vec<(u32, u32)> {
    let (Some(a), Some(b)) = (year_month(gte), year_month(lte)) else {
        return Vec::new();
    };
    let (mut y, mut m) = a;
    let mut out = Vec::new();
    while (y, m) <= b && out.len() < 3 {
        out.push((y, m));
        m += 1;
        if m > 12 {
            m = 1;
            y += 1;
        }
    }
    out
}

fn year_month(iso: &str) -> Option<(u32, u32)> {
    let y = iso.get(0..4)?.parse().ok()?;
    let m: u32 = iso.get(5..7)?.parse().ok()?;
    (1..=12).contains(&m).then_some((y, m))
}

fn in_window(date: &str, gte: &str, lte: &str) -> bool {
    (gte.is_empty() || date >= gte) && (lte.is_empty() || date <= lte)
}

/// Same title and year twice on one page (a re-release row, or the
/// same film under two distributors) is one pick.
fn dedup(v: Vec<MovieRelease>) -> Vec<MovieRelease> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter()
        .filter(|m| seen.insert((m.title.to_lowercase(), m.year)))
        .collect()
}

/// The handful of entities both sites emit in a title.
fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .trim()
        .to_string()
}

fn month_number(name: &str) -> Option<u32> {
    let n = name.to_ascii_lowercase();
    MONTHS.iter().position(|m| *m == n).map(|i| i as u32 + 1)
}

/// "Tuesday September 8, 2026" (the dvdsreleasedates heading) or
/// "Tuesday, 8 September 2026" (bingebase's) to ISO `2026-09-08`.
fn heading_to_iso(text: &str) -> Option<String> {
    let toks: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    // Drop a leading weekday if present, then expect month/day/year in
    // either order for the first two.
    let toks = if toks.len() == 4 {
        &toks[1..]
    } else {
        &toks[..]
    };
    if toks.len() != 3 {
        return None;
    }
    let y: u32 = toks[2].parse().ok()?;
    let (m, d) = match (month_number(toks[0]), toks[0].parse::<u32>().ok()) {
        (Some(m), _) => (m, toks[1].parse::<u32>().ok()?),
        (None, Some(d)) => (month_number(toks[1])?, d),
        _ => return None,
    };
    ((1..=31).contains(&d) && (1900..=2200).contains(&y)).then(|| format!("{y:04}-{m:02}-{d:02}"))
}

/// Pure parse of a dvdsreleasedates.com digital-releases month page.
///
/// Shape (fixture `testdata/dvdsrd-digital-2026-09.html`): each week is
/// a `<td class='reldate '>` heading holding the date text, followed by
/// `<td class='dvdcell'>` cells, one per film, each with a poster
/// `<img src='/posters/110/M/Moana-2026.jpg'>` and a text anchor
/// `<a href='/movies/11703/moana'>Moana</a>`. The year is the poster
/// filename's trailing `-YYYY` (the path varies - `/posters/110/M/` on
/// most cells, `/images/movies/J/` on some - so only the stem is read);
/// the title is the anchor whose body is text rather than an `<img>`.
pub(super) fn parse_dvdsrd_month(html: &str, gte: &str, lte: &str) -> Vec<MovieRelease> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(p) = rest.find("class='reldate") {
        let seg = &rest[p..];
        let block_end = seg[14..]
            .find("class='reldate")
            .map(|i| i + 14)
            .unwrap_or(seg.len());
        let block = &seg[..block_end];
        rest = &seg[block_end..];
        // Heading text: after the cell's `>`, tags stripped, up to the
        // `<div class='distance'>` annotation or the cell's end.
        let Some(gt) = block.find('>') else { continue };
        let head_raw = &block[gt + 1..];
        let head_end = head_raw.find("</td>").unwrap_or(head_raw.len());
        let head = super::strip_tags(&head_raw[..head_end]);
        let head = head.split('(').next().unwrap_or("").trim();
        let Some(date) = heading_to_iso(head) else {
            continue;
        };
        if !in_window(&date, gte, lte) {
            continue;
        }
        for cell in block.split("class='dvdcell'").skip(1) {
            let year = cell
                .find("src='")
                .and_then(|i| {
                    let src = &cell[i + 5..];
                    let end = src.find('\'')?;
                    let stem = src[..end].rsplit('/').next()?;
                    let stem = stem.strip_suffix(".jpg").unwrap_or(stem);
                    stem.rsplit('-').next()?.parse::<u32>().ok()
                })
                .filter(|y| (1900..=2200).contains(y))
                .unwrap_or(0);
            let mut title = None;
            let mut r = cell;
            while let Some(i) = r.find("href='/movies/") {
                let a = &r[i..];
                let Some(gt) = a.find('>') else { break };
                let body = &a[gt + 1..];
                let end = body.find('<').unwrap_or(body.len());
                let text = unescape(&body[..end]);
                if !text.is_empty() {
                    title = Some(text);
                    break;
                }
                r = body;
            }
            if let Some(title) = title {
                out.push(MovieRelease { title, year });
            }
        }
    }
    out
}

/// Pure parse of a bingebase.com digital-releases month page.
///
/// Shape (fixture `testdata/bingebase-digital-2026-09.html`, trimmed to
/// the markers read here): a `<div id="date-2026-09-08">` per day, and
/// inside it one poster anchor per film,
/// `<a href="/movies/one-night-only-2026"><img alt="One Night Only
/// poster">`. The year is the last four-digit token of the slug (a
/// disambiguated slug carries a UUID after the year); the title is the
/// `alt` with its " poster" suffix removed.
pub(super) fn parse_bingebase_month(html: &str, gte: &str, lte: &str) -> Vec<MovieRelease> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut rest = html;
    while let Some(p) = rest.find("id=\"date-") {
        let seg = &rest[p + 9..];
        let block_end = seg.find("id=\"date-").unwrap_or(seg.len());
        let block = &seg[..block_end];
        rest = &seg[block_end..];
        let Some(date) = block.get(0..10).filter(|d| year_month(d).is_some()) else {
            continue;
        };
        if !in_window(date, gte, lte) {
            continue;
        }
        let mut r = block;
        while let Some(i) = r.find("href=\"/movies/") {
            let a = &r[i + 14..];
            let Some(q) = a.find('"') else { break };
            let slug = &a[..q];
            r = &a[q..];
            if !seen.insert(slug.to_string()) {
                continue;
            }
            let year = slug
                .split('-')
                .rfind(|t: &&str| {
                    t.len() == 4 && t.parse::<u32>().is_ok_and(|y| (1900..=2200).contains(&y))
                })
                .and_then(|t| t.parse::<u32>().ok())
                .unwrap_or(0);
            // The alt belongs to this anchor only if it comes before
            // the next film's anchor.
            let next = r.find("href=\"/movies/").unwrap_or(r.len());
            let Some(ai) = r[..next].find("alt=\"") else {
                continue;
            };
            let alt = &r[ai + 5..];
            let Some(ae) = alt.find('"') else { continue };
            let title = unescape(alt[..ae].trim_end_matches(" poster"));
            if !title.is_empty() {
                out.push(MovieRelease { title, year });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DVDSRD: &str = include_str!("testdata/dvdsrd-digital-2026-09.html");
    const BINGE: &str = include_str!("testdata/bingebase-digital-2026-09.html");

    fn titles(v: &[MovieRelease]) -> Vec<&str> {
        v.iter().map(|m| m.title.as_str()).collect()
    }

    #[test]
    fn dvdsrd_month_page_yields_every_dated_film_with_its_year() {
        let v = parse_dvdsrd_month(DVDSRD, "2026-09-01", "2026-09-30");
        // Four Tuesdays: 4 + 4 + 3 + 2 films (counted on the fixture).
        assert_eq!(v.len(), 13, "{:?}", titles(&v));
        assert!(v.iter().all(|m| m.year == 2026), "{v:?}");
        assert!(titles(&v).contains(&"Moana"));
        assert!(titles(&v).contains(&"The Brink of War"));
        assert!(titles(&v).contains(&"Idiots"));
    }

    #[test]
    fn dvdsrd_window_keeps_only_the_weeks_inside_it() {
        let v = parse_dvdsrd_month(DVDSRD, "2026-09-06", "2026-09-09");
        assert_eq!(
            titles(&v),
            ["Moana", "Mutiny", "One Night Only", "Hot Spot"],
            "the 8 September week alone"
        );
        assert!(parse_dvdsrd_month(DVDSRD, "2026-10-01", "2026-10-31").is_empty());
        // An open window takes the whole page.
        assert_eq!(parse_dvdsrd_month(DVDSRD, "", "").len(), 13);
    }

    #[test]
    fn bingebase_month_page_yields_every_card_once_with_the_slug_year() {
        let v = parse_bingebase_month(BINGE, "2026-09-01", "2026-09-30");
        assert_eq!(v.len(), 45, "{:?}", titles(&v));
        // Plain slug year.
        assert!(
            v.iter()
                .any(|m| m.title == "One Night Only" && m.year == 2026)
        );
        // Disambiguated slugs carry a UUID after the year; the year is
        // still the last four-digit token.
        assert!(
            v.iter().any(|m| m.title == "Buzzkill" && m.year == 2026),
            "{v:?}"
        );
        assert!(
            v.iter().any(|m| m.title == "Family" && m.year == 2024),
            "{v:?}"
        );
        // Entities in the alt are decoded.
        assert!(v.iter().any(|m| m.title == "WWE Sunday Night's Main Event"));
    }

    #[test]
    fn bingebase_window_is_per_day() {
        let v = parse_bingebase_month(BINGE, "2026-09-08", "2026-09-08");
        assert_eq!(
            titles(&v),
            [
                "One Night Only",
                "Lockjaw",
                "The Spirit Lock",
                "Stavros Halkias: Uncle Stav"
            ]
        );
        assert_eq!(
            parse_bingebase_month(BINGE, "2026-09-05", "2026-09-06").len(),
            1
        );
    }

    #[test]
    fn headings_in_both_house_styles_become_iso() {
        assert_eq!(
            heading_to_iso("Tuesday September 8, 2026").as_deref(),
            Some("2026-09-08")
        );
        assert_eq!(
            heading_to_iso("Tuesday, 8 September 2026").as_deref(),
            Some("2026-09-08")
        );
        assert_eq!(
            heading_to_iso("September 8, 2026").as_deref(),
            Some("2026-09-08")
        );
        assert_eq!(heading_to_iso("Coming soon"), None);
        assert_eq!(heading_to_iso("Tuesday Septembre 8, 2026"), None);
    }

    #[test]
    fn a_window_maps_to_the_month_pages_it_touches() {
        assert_eq!(months_in("2026-09-04", "2026-09-06"), [(2026, 9)]);
        assert_eq!(
            months_in("2026-12-30", "2027-01-02"),
            [(2026, 12), (2027, 1)]
        );
        // Capped so a bad window cannot become a crawl.
        assert_eq!(months_in("2020-01-01", "2026-01-01").len(), 3);
        assert!(months_in("garbage", "2026-01-01").is_empty());
        assert_eq!(
            dvdsrd_url(2026, 9),
            "https://www.dvdsreleasedates.com/digital-releases/2026/9/"
        );
        assert_eq!(
            bingebase_url(2026, 9),
            "https://bingebase.com/releases/digital/september-2026"
        );
    }

    #[test]
    fn a_shut_callout_gate_answers_none_without_dialling() {
        // Unit builds have the gate shut by construction (identity::
        // may_call_out), so every source answers empty and the verdict
        // says so - the oracle must not read that as "no releases".
        let (v, src) = digital_releases(None, "2026-09-01", "2026-09-03");
        assert!(v.is_empty());
        assert_eq!(src, DigitalSource::None);
        let (v, src) = digital_releases(Some(""), "2026-09-01", "2026-09-03");
        assert!(v.is_empty());
        assert_eq!(src, DigitalSource::None);
    }

    /// Live smoke for both keyless calendars. `#[ignore]`d so no
    /// ordinary run touches the network:
    ///   NZBFAST_TEST_ALLOW_CALLOUT=1 \
    ///     cargo test -p nzbfast digital_calendars_answer_live -- --ignored --nocapture
    /// Exists because both sites can fail the iTunes way - a 200 with
    /// an empty page - which every fixture test above would pass.
    #[test]
    #[ignore]
    fn digital_calendars_answer_live() {
        let today = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let (y, m, _) = crate::logging::civil_from_days(now.div_euclid(86_400));
            (y as u32, m)
        };
        let (y, m) = today;
        let gte = format!("{y:04}-{m:02}-01");
        let lte = format!("{y:04}-{m:02}-31");
        let a = get_body(Provider::DvdsReleaseDates, &dvdsrd_url(y, m))
            .map(|h| parse_dvdsrd_month(&h, &gte, &lte))
            .unwrap_or_default();
        println!(
            "dvdsreleasedates {y}-{m}: {} titles, e.g. {:?}",
            a.len(),
            a.first()
        );
        let b = get_body(Provider::BingeBase, &bingebase_url(y, m))
            .map(|h| parse_bingebase_month(&h, &gte, &lte))
            .unwrap_or_default();
        println!(
            "bingebase {y}-{m}: {} titles, e.g. {:?}",
            b.len(),
            b.first()
        );
        assert!(a.len() >= 5, "dvdsreleasedates answered {} titles", a.len());
        assert!(b.len() >= 5, "bingebase answered {} titles", b.len());
        let (v, src) = digital_releases(None, &gte, &lte);
        assert_eq!(src, DigitalSource::DvdsReleaseDates);
        assert!(!v.is_empty());
    }
}
