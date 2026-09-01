//! M13 poster wall: turn indexed release stems into a browsable catalogue.
//!
//! Two halves:
//! - a scene-name parser (pure, tested) that extracts title / year /
//!   S+E / quality from release stems and produces a dedupe key so five
//!   encodes of one film become one card;
//! - a TMDB enrichment client (metadata + artwork, cached in the index
//!   db + an on-disk art dir by the daemon's background worker). No key
//!   ⇒ the wall still works, text-only.

use crate::MutexExt;
use std::collections::HashMap;
use std::fmt::Write as _;

// Every provider call in this file is paced by a per-provider bucket.
use crate::ratelimit::{self, Provider};

// Release-name parsing moved to nzbkit::release (the indexer
// classifies at ingest - M25 browse view); re-exported so existing
// call sites keep their wall:: paths.
pub use nzbkit::release::{
    Kind, NameStyle, Parsed, movie_name, norm_title, parse_release, quality_label, quality_suffix,
};

// Cast and crew are entities, not a comma-joined string: the struct and
// its storage live in nzbkit::index, and every provider parser below
// fills it.
pub use nzbkit::index::Credit;

// ---------------------------------------------------------------------------
// Metadata lookup (network - daemon background worker only).
//
// Provider chain: TMDB when a key is configured (best data) - but TMDB
// declines API applications for NZB tooling, so the DEFAULT is keyless:
// TVmaze for TV (free, posters+synopsis+ratings), and for movies either
// the user's own free OMDb key or Wikidata + Wikipedia. Same cache
// either way.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TitleMeta {
    /// Provider's id for the match (TMDB/TVmaze/iTunes/AniList) - 0 = not found.
    pub tmdb_id: i64,
    /// WHICH provider `tmdb_id` above belongs to, as that provider's own
    /// name. One `titles` column stores every one of them, and the
    /// numbering schemes are small, dense and unrelated, so an id
    /// without its namespace is not readable: the TV lane alone writes
    /// TVmaze, AniList and TMDB ids into it, and readers that guessed
    /// from `kind` alone resolved one provider's id in another's
    /// (Codex sweep 7, H2). Every parser in this file sets it; the
    /// enricher carries it through to `TitleFill::id_src`.
    pub id_src: String,
    pub overview: String,
    pub rating: f64,
    pub genres: String,
    /// Full image URLs (any provider), empty when absent.
    pub poster_url: String,
    pub backdrop_url: String,
    /// IMDb tconst when the provider knows it (TVmaze externals do).
    pub imdb: String,
    /// Top-billed cast, comma-joined (TVmaze /cast).
    pub actors: String,
    /// Original release / first-air date as ISO `YYYY-MM-DD`, empty when
    /// the provider didn't say. Year alone was too coarse to answer
    /// "what came out this week" - everything from the year landed in one
    /// undifferentiated bucket.
    pub air_date: String,
    /// Cast and crew as entities, when the provider models them that way.
    /// `actors` above stays the rendered credit line the cards already
    /// show - these ride alongside it, and only the providers that hand
    /// over a person handle (TVmaze, Wikidata) fill them.
    pub credits: Vec<Credit>,
}

/// Normalise a provider's date to ISO `YYYY-MM-DD`. The wall orders these
/// as plain strings (ISO sorts chronologically), so a format we can't
/// place is dropped rather than stored: a stray "30 Mar 1999" mixed into
/// an ISO column would sort under "3", wrecking the ordering for every
/// other row. Accepts the ISO prefix every JSON provider emits, plus
/// OMDb's "30 Mar 1999".
pub fn iso_date(s: &str) -> String {
    let s = s.trim();
    let b = s.as_bytes();
    // "YYYY-MM-DD" (optionally followed by a time, as iTunes sends).
    if b.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        return s[..10].to_string();
    }
    // "30 Mar 1999" (OMDb).
    let mut it = s.split_whitespace();
    let (Some(d), Some(m), Some(y), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return String::new();
    };
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let ml = m.to_ascii_lowercase();
    let Some(mi) = MONTHS.iter().position(|x| *x == ml) else {
        return String::new();
    };
    let (Ok(dn), Ok(yn)) = (d.parse::<u32>(), y.parse::<u32>()) else {
        return String::new();
    };
    if !(1..=31).contains(&dn) || !(1000..=9999).contains(&yn) {
        return String::new();
    }
    format!("{yn:04}-{:02}-{dn:02}", mi + 1)
}

/// One lookup via whichever provider fits: TMDB with a key, else
/// TVmaze (tv) / Wikidata (movies). `None` = looked, found nothing.
pub fn lookup(api_key: Option<&str>, kind: &Kind, title: &str, year: u32) -> Option<TitleMeta> {
    // Kind decides the provider FAMILY before the key decides the
    // provider: TMDB is a film/tv database, so a configured key must not
    // divert an album or a book into a movie search - that either stamps
    // the row empty forever or stores a same-named film's date on an
    // album card. Same rule the enrich lane states for its own arms.
    match kind {
        Kind::Tv => match api_key {
            Some(k) => tmdb_lookup(k, kind, title, year),
            None => tvmaze_lookup(title),
        },
        Kind::Movie => match api_key {
            Some(k) => tmdb_lookup(k, kind, title, year),
            None => wikidata_movie(title, year),
        },
        Kind::Music | Kind::Book => media_lookup(kind, title),
        // Custom categories are never enriched: "Formula 1 Round 11"
        // has no meaningful identity at any provider, and a wrong
        // poster is worse than none.
        Kind::Software | Kind::Other | Kind::Custom(_) => None,
    }
}

/// Music / book lookup. The parser stores both halves of the identity in
/// `title` as "Credit - Work" so a card reads properly before any
/// provider answers; the providers need them apart.
pub fn media_lookup(kind: &Kind, title: &str) -> Option<TitleMeta> {
    let (credit, work) = nzbkit::release::credit_split(title).unwrap_or(("", title));
    match kind {
        Kind::Book => openlibrary_lookup(credit, work),
        _ => musicbrainz_lookup(credit, work),
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// TMDB genre ids are stable and documented; a static map beats an extra
/// API round-trip per process.
fn genre_name(id: i64) -> Option<&'static str> {
    Some(match id {
        28 => "Action",
        12 => "Adventure",
        16 => "Animation",
        35 => "Comedy",
        80 => "Crime",
        99 => "Documentary",
        18 => "Drama",
        10751 => "Family",
        14 => "Fantasy",
        36 => "History",
        27 => "Horror",
        10402 => "Music",
        9648 => "Mystery",
        10749 => "Romance",
        878 => "Sci-Fi",
        10770 => "TV Movie",
        53 => "Thriller",
        10752 => "War",
        37 => "Western",
        10759 => "Action & Adventure",
        10762 => "Kids",
        10763 => "News",
        10764 => "Reality",
        10765 => "Sci-Fi & Fantasy",
        10766 => "Soap",
        10767 => "Talk",
        10768 => "War & Politics",
        _ => return None,
    })
}

/// One search round-trip. `None` = looked, found nothing (cache that too).
pub fn tmdb_lookup(api_key: &str, kind: &Kind, title: &str, year: u32) -> Option<TitleMeta> {
    let (path, year_param, date_field) = match kind {
        Kind::Tv => ("tv", "first_air_date_year", "first_air_date"),
        _ => ("movie", "year", "release_date"),
    };
    let mut url = format!(
        "https://api.themoviedb.org/3/search/{path}?api_key={api_key}&query={}",
        percent_encode(title)
    );
    if year > 0 {
        let _ = write!(url, "&{year_param}={year}");
    }
    if cooling_off(Provider::Tmdb) {
        return None;
    }
    ratelimit::acquire(Provider::Tmdb);
    let resp = match crate::netfetch::shared_enrich_agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            // Same rule as get_json: a 429/503 is "ask again later", not
            // an answer. `note_http_err` counts a 429 as a real reply (it
            // is a 4xx), so one rate-limited burst would stamp every row
            // it touched checked-and-empty for good. Penalise so the lane
            // backs off instead of drawing the next 429 immediately.
            if let ureq::Error::Status(code @ (429 | 503), r) = &e {
                note_refusal(Provider::Tmdb, r, if *code == 429 { 30 } else { 5 });
                note_unreachable();
                return None;
            }
            note_http_err(&e);
            return None;
        }
    };
    let body = match resp.into_string() {
        Ok(b) => b,
        Err(_) => {
            note_unreachable();
            return None;
        }
    };
    let v = parse_answer(&body)?;
    let hit = v["results"].get(0)?;
    let genres = hit["genre_ids"]
        .as_array()
        .map(|ids| {
            ids.iter()
                .filter_map(|i| genre_name(i.as_i64()?))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let img = |field: &str, width: &str| {
        hit[field]
            .as_str()
            .map(|p| format!("https://image.tmdb.org/t/p/{width}{p}"))
            .unwrap_or_default()
    };
    Some(TitleMeta {
        tmdb_id: hit["id"].as_i64().unwrap_or(0),
        id_src: "tmdb".into(),
        overview: hit["overview"].as_str().unwrap_or("").to_string(),
        rating: hit["vote_average"].as_f64().unwrap_or(0.0),
        genres,
        poster_url: img("poster_path", "w342"),
        backdrop_url: img("backdrop_path", "w780"),
        imdb: String::new(),
        actors: String::new(),
        air_date: iso_date(hit[date_field].as_str().unwrap_or("")),
        credits: Vec::new(),
    })
}

/// Paced JSON GET. Every provider call in this file goes through a
/// bucket - see `ratelimit` for why the numbers are what they are.
fn get_json(p: Provider, url: &str) -> Option<serde_json::Value> {
    if cooling_off(p) {
        return None;
    }
    ratelimit::acquire(p);
    let resp = match crate::netfetch::shared_enrich_agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            // A 429/503 is the provider saying the bucket is too fast.
            // Slow the whole lane, not just this call: the next title is
            // about to ask the same service the same way.
            if let ureq::Error::Status(code @ (429 | 503), r) = &e {
                note_refusal(p, r, if *code == 429 { 30 } else { 5 });
                // Both codes are "ask again later", not an answer, and
                // this helper has no retry to ask with. `note_http_err`
                // would count the 429 as a real reply (it is a 4xx), so
                // one TVmaze or OMDb 429 would stamp the title checked
                // and blank the row for good. Make the caller skip it.
                note_unreachable();
                return None;
            }
            note_http_err(&e);
            return None;
        }
    };
    match resp.into_string() {
        Ok(body) => parse_answer(&body),
        Err(_) => {
            note_unreachable();
            None
        }
    }
}

/// Strip HTML tags (TVmaze summaries are `<p>…</p>` fragments).
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

/// Pure parse of a TVmaze `singlesearch/shows` response (tested).
fn parse_tvmaze(v: &serde_json::Value) -> Option<TitleMeta> {
    let id = v["id"].as_i64()?;
    let poster = v["image"]["medium"].as_str().unwrap_or("").to_string();
    let backdrop = v["image"]["original"].as_str().unwrap_or("").to_string();
    Some(TitleMeta {
        tmdb_id: id,
        id_src: "tvmaze".into(),
        overview: strip_tags(v["summary"].as_str().unwrap_or("")),
        rating: v["rating"]["average"].as_f64().unwrap_or(0.0),
        genres: v["genres"]
            .as_array()
            .map(|g| {
                g.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        poster_url: poster,
        backdrop_url: backdrop,
        imdb: v["externals"]["imdb"].as_str().unwrap_or("").to_string(),
        actors: String::new(), // separate /cast call - see tvmaze_cast
        air_date: iso_date(v["premiered"].as_str().unwrap_or("")),
        credits: Vec::new(),
    })
}

/// TVmaze: keyless TV metadata, no cast. Kept lean for the one caller
/// that only wants the show id (the watchlist's episode-list refresher);
/// the enricher uses `tvmaze_lookup_full`, which gets cast and crew in
/// this same request.
pub fn tvmaze_lookup(title: &str) -> Option<TitleMeta> {
    let v = get_json(
        Provider::Tvmaze,
        &format!(
            "https://api.tvmaze.com/singlesearch/shows?q={}",
            percent_encode(title)
        ),
    )?;
    parse_tvmaze(&v)
}

/// TVmaze show + cast + crew in ONE request.
///
/// This replaced a lookup followed by a separate `/shows/:id/cast` call.
/// Request budget - not parsing - is what limits enrichment throughput,
/// so halving the calls per show while returning strictly more data
/// (character names, person ids, headshots, the voice flag, and crew
/// with real roles) is the whole point. Measured live on 26 Jul 2026:
/// Severance answers in 35 KB with 11 cast and 71 crew.
pub fn tvmaze_lookup_full(title: &str) -> Option<TitleMeta> {
    let v = get_json(
        Provider::Tvmaze,
        &format!(
            "https://api.tvmaze.com/singlesearch/shows?q={}&embed[]=cast&embed[]=crew",
            percent_encode(title)
        ),
    )?;
    let mut m = parse_tvmaze(&v)?;
    m.credits = parse_tvmaze_credits(&v["_embedded"]);
    m.actors = credit_line(&m.credits, 8);
    Some(m)
}

/// The rendered "starring" line the cards have always shown, now derived
/// from the credit list instead of parsed separately. Cast only: a
/// producer does not belong on that line.
pub fn credit_line(credits: &[Credit], cap: usize) -> String {
    credits
        .iter()
        .filter(|c| c.role == "actor")
        .map(|c| c.name.as_str())
        .take(cap)
        .collect::<Vec<_>>()
        .join(", ")
}

/// How much a crew role earns its place when the list is capped. A show
/// can carry 70+ crew credits and most of them are production staff who
/// mean nothing on a card or a person page; these are the ones that
/// answer "who made this".
fn crew_rank(role: &str) -> u8 {
    match role {
        "creator" => 0,
        "director" => 1,
        r if r.contains("writer") || r.contains("story") || r.contains("teleplay") => 2,
        r if r.contains("composer") || r.contains("music") || r.contains("theme") => 3,
        "executive producer" => 4,
        r if r.contains("producer") => 5,
        r if r.contains("photography") || r.contains("editor") => 6,
        _ => 7,
    }
}

/// Pure parse of a TVmaze `_embedded` block (cast + crew) into credits
/// (tested).
///
/// Crew is capped at `CREW_CAP` by `crew_rank`, so a show with 71 credits
/// keeps its creators, directors, writers and composers and drops the
/// unit production managers - the cap is on storage, not on what the user
/// asked for.
fn parse_tvmaze_credits(emb: &serde_json::Value) -> Vec<Credit> {
    const CREW_CAP: usize = 12;
    struct Person {
        id: i64,
        name: String,
        photo: String,
        born: String,
    }
    let person = |p: &serde_json::Value| -> Option<Person> {
        let name = p["name"].as_str().filter(|n| !n.trim().is_empty())?;
        Some(Person {
            id: p["id"].as_i64().unwrap_or(0),
            name: name.to_string(),
            // `medium` is a portrait crop, which is the shape a headshot
            // is displayed in - `original` is an uncropped still that can
            // be several MB.
            photo: p["image"]["medium"].as_str().unwrap_or("").to_string(),
            // TVmaze publishes no IMDb id for a person (measured: no
            // `externals` here or on /people/:id, and /lookup/people is
            // 404), so the birthday it does publish is the only fact a
            // TVmaze credit can be told apart from a same-named Wikidata
            // one by. `null` for the many people it has no date for.
            born: iso_date(p["birthday"].as_str().unwrap_or("")),
        })
    };
    let mut out: Vec<Credit> = Vec::new();
    if let Some(list) = emb["cast"].as_array() {
        for (i, c) in list.iter().enumerate() {
            let Some(p) = person(&c["person"]) else {
                continue;
            };
            out.push(Credit {
                name: p.name,
                role: "actor".into(),
                // A voice role is a real distinction on an animated show
                // and the flag is right there; folding it into the
                // character keeps it visible without a schema column.
                character: match (c["character"]["name"].as_str(), c["voice"].as_bool()) {
                    (Some(n), Some(true)) if !n.is_empty() => format!("{n} (voice)"),
                    (Some(n), _) => n.to_string(),
                    (None, _) => String::new(),
                },
                // TVmaze returns cast in billing order but numbers
                // nothing, so position IS the billing order. 1-based, so
                // 0 keeps meaning "unranked" everywhere else.
                ord: i as i64 + 1,
                tvmaze_id: p.id,
                photo: p.photo,
                born: p.born,
                ..Default::default()
            });
        }
    }
    let mut crew: Vec<Credit> = Vec::new();
    if let Some(list) = emb["crew"].as_array() {
        for c in list {
            let Some(p) = person(&c["person"]) else {
                continue;
            };
            let role = c["type"].as_str().unwrap_or("").trim().to_lowercase();
            if role.is_empty() {
                continue;
            }
            crew.push(Credit {
                name: p.name,
                role,
                tvmaze_id: p.id,
                photo: p.photo,
                born: p.born,
                ..Default::default()
            });
        }
    }
    crew.sort_by_key(|c| crew_rank(&c.role));
    crew.truncate(CREW_CAP);
    out.extend(crew);
    out
}

/// One episode from a TVmaze episode list (M23d airdate calendar).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EpInfo {
    pub season: u32,
    pub episode: u32,
    pub name: String,
    /// "YYYY-MM-DD"; empty when TVmaze doesn't know yet.
    #[serde(default)]
    pub airdate: String,
    /// The episode synopsis. TVmaze sends one for essentially every
    /// aired episode and we used to throw all of them away, which is
    /// what made "what have I watched, what is next" unanswerable.
    /// `#[serde(default)]` on every field added here: episode lists are
    /// cached as JSON in `kv`, and a blob written before a field existed
    /// must still deserialize rather than emptying the calendar.
    #[serde(default)]
    pub summary: String,
    /// Episode still (medium crop), empty when TVmaze has none.
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub rating: f64,
    /// Minutes; 0 when unknown.
    #[serde(default)]
    pub runtime: u32,
}

/// Pure parse of a TVmaze `/shows/:id/episodes` response (tested).
/// Specials (null episode number) are dropped.
fn parse_tvmaze_episodes(v: &serde_json::Value) -> Vec<EpInfo> {
    v.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|e| {
                    Some(EpInfo {
                        season: e["season"].as_u64()? as u32,
                        episode: e["number"].as_u64()? as u32,
                        name: e["name"].as_str().unwrap_or("").to_string(),
                        airdate: e["airdate"].as_str().unwrap_or("").to_string(),
                        // Provider HTML, same `<p>…</p>` fragments as the
                        // show summary - stripped here so nothing
                        // downstream has to trust it as markup.
                        summary: strip_tags(e["summary"].as_str().unwrap_or("")),
                        image: e["image"]["medium"].as_str().unwrap_or("").to_string(),
                        rating: e["rating"]["average"].as_f64().unwrap_or(0.0),
                        runtime: e["runtime"].as_u64().unwrap_or(0) as u32,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Full episode list (with airdates) for a TVmaze show id.
pub fn tvmaze_episodes(show_id: i64) -> Vec<EpInfo> {
    get_json(
        Provider::Tvmaze,
        &format!("https://api.tvmaze.com/shows/{show_id}/episodes"),
    )
    .map(|v| parse_tvmaze_episodes(&v))
    .unwrap_or_default()
}

/// The TVDB series id TVmaze holds for a show id (TODO 187 backfill).
///
/// One exact GET against `/shows/<id>`, never a search: the row already
/// carries the show id, so there is no title to match and no wrong show
/// to pick. `Some(0)` is a real answer - asked, none published - and is
/// what lets the backfill lane stop asking; `None` is a request that did
/// not land, and must NOT be recorded as "asked".
pub fn tvmaze_tvdb_id(show_id: i64) -> Option<i64> {
    if show_id <= 0 {
        return None;
    }
    let v = get_json(
        Provider::Tvmaze,
        &format!("https://api.tvmaze.com/shows/{show_id}"),
    )?;
    tvdb_of_show(&v, show_id)
}

/// The TVDB id in a `/shows/<id>` payload, when it really is that show.
///
/// TVmaze redirects a merged show id to its survivor, and stamping the
/// survivor's TVDB id on our row would point Sonarr at a different
/// series - so a payload for another show is not an answer about ours.
/// `thetvdb` is a NUMBER, and null for shows TVmaze holds no TVDB entry
/// for, which reads as 0: asked, none published.
fn tvdb_of_show(v: &serde_json::Value, show_id: i64) -> Option<i64> {
    (v["id"].as_i64() == Some(show_id)).then(|| v["externals"]["thetvdb"].as_i64().unwrap_or(0))
}

// ---------------------------------------------------------------------------
// M16 wall-fix: candidate search - the "did you mean?" list behind the
// UI's re-search flow. Same providers as lookup(), but returning SEVERAL
// matches with enough context (year, synopsis snippet, poster URL) for a
// human to pick the right one.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Candidate {
    /// Provider's id (TMDB/TVmaze/iTunes namespaces don't collide in
    /// practice because a title uses one provider at a time).
    pub id: i64,
    /// "movie" | "tv".
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub overview: String,
    pub rating: f64,
    pub genres: String,
    pub poster_url: String,
    pub backdrop_url: String,
    /// IMDb tconst when the provider exposes it (TVmaze externals) -
    /// lets a fix-applied title keep IMDb ratings working.
    pub imdb: String,
    pub provider: String,
    /// ISO release / first-air date, empty when the search response only
    /// carried a year (OMDb's `s=` list does).
    pub air_date: String,
}

fn year_of_date(d: Option<&str>) -> u32 {
    d.and_then(|d| d.get(..4))
        .and_then(|y| y.parse().ok())
        .unwrap_or(0)
}

/// Pure parse of a TMDB search response (movie or tv) → candidates.
fn parse_tmdb_search(v: &serde_json::Value, kind: &Kind) -> Vec<Candidate> {
    let (name_field, date_field, kind_str) = match kind {
        Kind::Tv => ("name", "first_air_date", "tv"),
        _ => ("title", "release_date", "movie"),
    };
    let img = |hit: &serde_json::Value, field: &str, width: &str| {
        hit[field]
            .as_str()
            .map(|p| format!("https://image.tmdb.org/t/p/{width}{p}"))
            .unwrap_or_default()
    };
    v["results"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .take(10)
                .filter_map(|hit| {
                    Some(Candidate {
                        id: hit["id"].as_i64()?,
                        kind: kind_str.to_string(),
                        title: hit[name_field].as_str().unwrap_or("").to_string(),
                        year: year_of_date(hit[date_field].as_str()),
                        overview: hit["overview"].as_str().unwrap_or("").to_string(),
                        rating: hit["vote_average"].as_f64().unwrap_or(0.0),
                        genres: hit["genre_ids"]
                            .as_array()
                            .map(|ids| {
                                ids.iter()
                                    .filter_map(|i| genre_name(i.as_i64()?))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default(),
                        poster_url: img(hit, "poster_path", "w342"),
                        backdrop_url: img(hit, "backdrop_path", "w780"),
                        imdb: String::new(),
                        provider: "tmdb".into(),
                        air_date: iso_date(hit[date_field].as_str().unwrap_or("")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure parse of a TVmaze `search/shows` response → candidates.
fn parse_tvmaze_search(v: &serde_json::Value) -> Vec<Candidate> {
    v.as_array()
        .map(|rs| {
            rs.iter()
                .take(10)
                .filter_map(|r| {
                    let show = &r["show"];
                    let m = parse_tvmaze(show)?;
                    Some(Candidate {
                        id: m.tmdb_id,
                        kind: "tv".into(),
                        title: show["name"].as_str().unwrap_or("").to_string(),
                        year: year_of_date(show["premiered"].as_str()),
                        overview: m.overview,
                        rating: m.rating,
                        genres: m.genres,
                        poster_url: m.poster_url,
                        backdrop_url: m.backdrop_url,
                        imdb: m.imdb,
                        provider: "tvmaze".into(),
                        air_date: m.air_date,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Candidate search for the wall's fix-match UI. `kind` decides the
/// provider (TMDB with a key, else TVmaze for tv / iTunes for movies);
/// `year` is a hint passed to TMDB only (keyless providers return the
/// full list and the user picks).
/// Which bucket `search_candidates` will spend from, without spending
/// anything. The fix-match UI is interactive, so its handler asks first
/// and skips the lookup when the answer would mean queueing - see
/// `ratelimit::try_acquire`.
pub fn search_provider(api_key: Option<&str>, kind: &Kind) -> Provider {
    match (api_key, kind) {
        (Some(_), _) => Provider::Tmdb,
        (None, Kind::Tv) => Provider::Tvmaze,
        (None, _) => Provider::Wikidata,
    }
}

pub fn search_candidates(
    api_key: Option<&str>,
    kind: &Kind,
    query: &str,
    year: u32,
) -> Vec<Candidate> {
    match (api_key, kind) {
        (Some(k), kind) => {
            let (path, year_param) = match kind {
                Kind::Tv => ("tv", "first_air_date_year"),
                _ => ("movie", "year"),
            };
            let mut url = format!(
                "https://api.themoviedb.org/3/search/{path}?api_key={k}&query={}",
                percent_encode(query)
            );
            if year > 0 {
                let _ = write!(url, "&{year_param}={year}");
            }
            get_json(Provider::Tmdb, &url)
                .map(|v| parse_tmdb_search(&v, kind))
                .unwrap_or_default()
        }
        (None, Kind::Tv) => get_json(
            Provider::Tvmaze,
            &format!(
                "https://api.tvmaze.com/search/shows?q={}",
                percent_encode(query)
            ),
        )
        .map(|v| parse_tvmaze_search(&v))
        .unwrap_or_default(),
        (None, _) => wikidata_search(query)
            .map(|(s, e)| parse_wikidata_candidates(&s, &e, year))
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// OMDb (optional free key - the ONLY obtainable key upgrade: TMDB bans
// NZB apps and requires KYC; OMDb's free tier needs just an email).
// 1,000 req/day, looks up by title+year or exactly by IMDb tconst, and
// returns plot, genres, CAST (movies have none keyless) and a poster.
// Data is CC BY-NC - credited in the wall footer.
// ---------------------------------------------------------------------------

// Wikimedia asks for a descriptive User-Agent; ureq's default is not one.
const WIKI_UA: &str = "nzbfast/0.1 (personal media indexer; wall metadata)";

/// Wikimedia reads, paced by the caller's bucket and carrying the
/// descriptive User-Agent Wikimedia asks for.
///
/// The provider is a parameter because Wikidata and Wikipedia do NOT
/// share an allowance - see `ratelimit::Provider::Wikipedia` for the
/// measurement that settled it.
///
/// Wikidata's limit is a quota rather than a rate: ten requests, then
/// 429 until the window turns over ~60 s later. The bucket is sized to
/// stay inside it, so a 429 here now means something else is spending
/// the same allowance from this IP. The retries stay, because a 429
/// costs a title its whole card and the enricher has no other chance at
/// that row until something re-queues it - but the wait goes into the
/// BUCKET rather than into a private sleep, so the whole lane backs off
/// instead of just this one call.
fn get_json_ua(p: Provider, url: &str) -> Option<serde_json::Value> {
    if cooling_off(p) {
        return None;
    }
    const BACKOFF_SECS: [u64; 2] = [5, 15];
    for attempt in 0..=BACKOFF_SECS.len() {
        ratelimit::acquire(p);
        match crate::netfetch::shared_enrich_agent()
            .get(url)
            .set("User-Agent", WIKI_UA)
            .timeout(std::time::Duration::from_secs(10))
            .call()
        {
            Ok(resp) => {
                return match resp.into_string() {
                    Ok(body) => parse_answer(&body),
                    Err(_) => {
                        note_unreachable();
                        None
                    }
                };
            }
            Err(ureq::Error::Status(429, r)) => {
                // The clamp that used to be here is gone: it bounded a
                // private sleep this loop no longer takes, and
                // `penalise` clamps what it sleeps on itself.
                note_refusal(p, &r, BACKOFF_SECS[attempt.min(BACKOFF_SECS.len() - 1)]);
                if attempt == BACKOFF_SECS.len() {
                    // Out of retries, and the whole failure was pacing.
                    // A 429 is a 4xx, so falling into the arm below would
                    // have `note_http_err` call it a real answer and the
                    // caller stamp the title checked for good - an empty
                    // card, permanently, because we were rate-limited.
                    // "We could not ask": leave the row for a later pass.
                    note_unreachable();
                    return None;
                }
            }
            Err(e) => {
                note_http_err(&e);
                return None;
            }
        }
    }
    note_unreachable(); // retries exhausted, still no answer
    None
}

thread_local! {
    /// Did an HTTP call in this thread fail to get an ANSWER, as opposed
    /// to being told "no such thing"?
    ///
    /// The distinction decides whether the enricher may stamp a title as
    /// checked. Every fetcher here collapses failure into `None`, so a
    /// DNS outage, a timeout, a TLS error or a provider 503 looked
    /// exactly like "this title does not exist" - and the lane's `None`
    /// arm calls `title_fill(&Default::default())`, which sets
    /// `checked=now` and `air_tried=1`. `titles_pending_lane` then never
    /// offers the row again. A few seconds of a flaky uplink was enough
    /// to mark hundreds of titles permanently as "no metadata, no art,
    /// no date", recoverable only by `titles_reset_all`. Kind::Other
    /// rows, which have no sleep between them, burned through fastest.
    ///
    /// Thread-local because the enricher lane is one row at a time on
    /// one thread: clear it before a row, read it after.
    static UNREACHABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

thread_local! {
    /// The longest `Retry-After` any provider asked for since
    /// `clear_unreachable` - seconds, 0 for "nobody asked".
    ///
    /// Kept beside `UNREACHABLE` rather than folded into it because the
    /// two answer different questions. UNREACHABLE decides WHETHER the
    /// row may be stamped; this decides how long to wait before trying
    /// again, and until TODO 26c it was parsed at every 429 site,
    /// handed to `ratelimit::penalise`, and then thrown away - so the
    /// lane retried a title on its own blind 60 s ladder and walked
    /// straight back into a `Retry-After: 900`.
    static RETRY_AFTER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn note_unreachable() {
    UNREACHABLE.with(|f| f.set(true));
}

/// Record what a provider asked us to wait. Largest wins: a title that
/// asked three services and was refused by two waits out the longer.
fn note_retry_after(secs: u64) {
    RETRY_AFTER.with(|f| f.set(f.get().max(secs)));
}

/// Record a provider's explicit "not now" - an HTTP 429 or 503 - and
/// answer with how long it asked for.
///
/// One helper for all five call sites because they must not drift: each
/// has to do THREE things off one header, and every one of them has been
/// the bug at some point.
///
/// 1. `penalise` the bucket, so the whole provider slows down rather
///    than this one call (27 Jul: the movie lane's per-title sleep could
///    not see a burst inside one title).
/// 2. Remember the wait for the ROW, so the lane's retry ladder does not
///    walk back into it a minute later (TODO 26c: the header was parsed
///    and dropped here for months).
/// 3. Leave the caller to decide about `note_unreachable`. The two
///    retrying helpers mark it only once their patience is spent, which
///    is the difference between "could not ask" and "had to ask twice".
///
/// A missing or unparseable header falls back to `fallback` - these
/// services do send `Retry-After: <delta-seconds>`, but an HTTP-date
/// form is legal and is not worth a parser here.
fn note_refusal(p: Provider, r: &ureq::Response, fallback: u64) -> u64 {
    let wait = r
        .header("Retry-After")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(fallback);
    ratelimit::penalise(p, wait);
    note_retry_after(wait);
    wait
}

/// Is this provider inside a `Retry-After` it has already given us?
///
/// Then do not spend a request finding out again. The bucket's own
/// penalty is clamped to a minute so no lane thread parks longer than
/// that (see `ratelimit::penalise`), which means without this check the
/// NEXT title in the batch walks into the same refusal - and the one
/// after that. Answering "could not ask" without going near the network
/// is what turns one 429 into one backed-off provider instead of twelve
/// blanked titles.
fn cooling_off(p: Provider) -> bool {
    let left = ratelimit::cooling(p);
    if left.is_zero() {
        return false;
    }
    note_unreachable();
    note_retry_after(left.as_secs().max(1));
    true
}

/// What a whole provider chain concluded about one title (TODO 26c).
///
/// The enricher's stamp is permanent - `title_fill` sets `checked=now`
/// and every lane query requires `checked=0` - so "we looked and there
/// is no such film" and "we could not ask" must never arrive at it as
/// the same value. They did for months, as a bare `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A provider answered with metadata. Stamp it.
    Found,
    /// Every provider we asked answered, and none of them has this
    /// title. Definitive: stamping is correct, and re-asking on a later
    /// pass would just spend the allowance to be told the same thing.
    NotFound,
    /// At least one provider could not be ASKED - a 429, a 5xx, a
    /// timeout, a TLS failure, an unparseable body, or a cooldown it
    /// asked for itself. Not an answer. `retry_after` is the wait the
    /// provider named, when it named one.
    Transient { retry_after: Option<u64> },
}

/// Read the verdict for the row whose chain just finished.
///
/// `found` WINS over a transient failure, and that is deliberate: a
/// title whose first provider was rate-limited and whose second
/// answered has its card, and holding the row open for the one that
/// refused would re-fetch a complete record on every pass forever.
pub fn outcome(found: bool) -> Outcome {
    if found {
        Outcome::Found
    } else if saw_unreachable() {
        Outcome::Transient {
            retry_after: retry_after_hint(),
        }
    } else {
        Outcome::NotFound
    }
}

/// The longest wait a provider asked for in this window, if any.
pub fn retry_after_hint() -> Option<u64> {
    let s = RETRY_AFTER.with(|f| f.get());
    (s > 0).then_some(s)
}

/// A 5xx means the provider is broken right now, which is worth
/// retrying; a 404 or other 4xx is a real answer and must not be.
/// Parse a provider's 200 body, counting an unparseable one as "could
/// not ask", never "looked, found nothing". A captive portal, proxy
/// error page, or CDN interstitial answers 200 with HTML for every
/// request for a few minutes - without the unreachable mark, every
/// title the lane touched in that window was stamped checked-and-empty
/// permanently, the exact mass-blanking UNREACHABLE exists to stop
/// (transport errors and 5xx were caught; 200-with-garbage was not).
fn parse_answer(body: &str) -> Option<serde_json::Value> {
    match serde_json::from_str(body) {
        Ok(v) => Some(v),
        Err(_) => {
            note_unreachable();
            None
        }
    }
}

fn note_http_err(e: &ureq::Error) {
    let no_answer = match e {
        // 408 and 425 are 4xx that say "not now" rather than "no such
        // thing", and 429 is the whole subject of TODO 26c - the call
        // sites above catch it first, but a helper that classified it as
        // a real answer is one refactor away from blanking a title again.
        ureq::Error::Status(code, _) => *code >= 500 || matches!(code, 408 | 425 | 429),
        ureq::Error::Transport(_) => true,
    };
    if no_answer {
        note_unreachable();
    }
}

/// Start a fresh "was anything unreachable" window for one title.
pub fn clear_unreachable() {
    UNREACHABLE.with(|f| f.set(false));
    RETRY_AFTER.with(|f| f.set(0));
}

/// Did any provider call since `clear_unreachable` fail to get an answer?
/// When true, an empty result means "we could not ask", not "there is
/// nothing", and the caller must leave the row unstamped so a later pass
/// retries it.
pub fn saw_unreachable() -> bool {
    UNREACHABLE.with(|f| f.get())
}

/// What one Wikipedia page summary gives us.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WikiPage {
    /// Lead-section plot text (CC BY-SA; attributed in the wall footer).
    pub extract: String,
    /// The infobox image. For a film article this is the POSTER: it is
    /// non-free artwork hosted on en.wikipedia itself rather than on
    /// Commons, which is why Wikidata cannot carry it and P18 offers
    /// something else instead (see `parse_wikidata_film`).
    pub image: String,
}

/// Does this Wikipedia summary describe a film or a TV work?
///
/// Only consulted for an UNQUALIFIED title, where the article name gives
/// no clue. The REST summary's `description` is the short "2016 American
/// action film" line, and the first sentence of the lead says what the
/// subject is; requiring one of them to name a screen work keeps a stem
/// like "Ambulance" from adopting the road-vehicle article's photo as a
/// poster. Only the start of the extract is examined, so a passing
/// mention of filming further down does not qualify an unrelated page.
fn describes_a_screen_work(v: &serde_json::Value) -> bool {
    const MARKS: [&str; 8] = [
        "film",
        "movie",
        "television series",
        "tv series",
        "miniseries",
        "documentary",
        "anime",
        "sitcom",
    ];
    let desc = v["description"].as_str().unwrap_or("").to_ascii_lowercase();
    let lead: String = v["extract"]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect::<String>()
        .to_ascii_lowercase();
    MARKS.iter().any(|m| desc.contains(m) || lead.contains(m))
}

/// Wikipedia REST summary - plot and poster for a movie the metadata
/// provider could not fully answer. Tries the year-disambiguated page
/// first, since "Dune" and "Dune (2021 film)" are different articles.
pub fn wikipedia_page(title: &str, year: u32) -> Option<WikiPage> {
    let variants = if year > 0 {
        vec![
            format!("{title} ({year} film)"),
            format!("{title} (film)"),
            title.to_string(),
        ]
    } else {
        vec![format!("{title} (film)"), title.to_string()]
    };
    for name in variants {
        // The "(2021 film)" and "(film)" forms verify themselves: the
        // article title says what it is. The bare title does not, and it
        // is the last thing tried, so a stem with no year that misses
        // everywhere else landed on whatever article owns that word -
        // "Ambulance" the vehicle, "Sunlight" the phenomenon - and its
        // lead paragraph became the plot and its infobox photo the
        // poster, stamped `checked` so nothing revisited it.
        let self_describing = name != title;
        let url = format!(
            "https://en.wikipedia.org/api/rest_v1/page/summary/{}",
            percent_encode(&name.replace(' ', "_"))
        );
        if let Some(v) = get_json_ua(Provider::Wikipedia, &url)
            && v["type"].as_str() == Some("standard")
            && (self_describing || describes_a_screen_work(&v))
        {
            let page = WikiPage {
                extract: v["extract"].as_str().unwrap_or("").to_string(),
                image: v["originalimage"]["source"]
                    .as_str()
                    .or(v["thumbnail"]["source"].as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            // A disambiguation-ish hit with neither text nor art is
            // not an answer - keep trying the other title forms.
            if !page.extract.is_empty() || !page.image.is_empty() {
                return Some(page);
            }
        }
    }
    None
}

/// Pure parse of an AniList GraphQL Media response (tested).
fn parse_anilist(v: &serde_json::Value) -> Option<TitleMeta> {
    let m = &v["data"]["Media"];
    let id = m["id"].as_i64()?;
    Some(TitleMeta {
        tmdb_id: id,
        // An AniList MEDIA id on what is usually a kind='tv' row. It
        // addresses nothing but AniList - in particular the TVDB
        // backfill must never hand it to TVmaze (Codex sweep 7, H2).
        id_src: "anilist".into(),
        overview: strip_tags(m["description"].as_str().unwrap_or("")),
        rating: m["averageScore"].as_f64().unwrap_or(0.0) / 10.0,
        genres: m["genres"]
            .as_array()
            .map(|g| {
                g.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        poster_url: m["coverImage"]["extraLarge"]
            .as_str()
            .or(m["coverImage"]["large"].as_str())
            .unwrap_or("")
            .to_string(),
        backdrop_url: m["bannerImage"].as_str().unwrap_or("").to_string(),
        imdb: String::new(),
        actors: String::new(),
        // AniList sends the date split into fields, and any of them can be
        // null on an unannounced show - all three or nothing.
        air_date: match (
            m["startDate"]["year"].as_i64(),
            m["startDate"]["month"].as_i64(),
            m["startDate"]["day"].as_i64(),
        ) {
            (Some(y), Some(mo), Some(d)) => iso_date(&format!("{y:04}-{mo:02}-{d:02}")),
            _ => String::new(),
        },
        credits: Vec::new(),
    })
}

/// AniList (keyless GraphQL): anime fallback when TVmaze/iTunes miss -
/// Usenet has plenty of anime groups.
pub fn anilist_lookup(title: &str) -> Option<TitleMeta> {
    let body = serde_json::json!({
        "query": "query($s:String){Media(search:$s,type:ANIME){id \
                  description(asHtml:false) averageScore genres \
                  coverImage{large extraLarge} bannerImage \
                  startDate{year month day}}}",
        "variables": {"s": title},
    });
    if cooling_off(Provider::AniList) {
        return None;
    }
    ratelimit::acquire(Provider::AniList);
    let resp = match crate::netfetch::shared_enrich_agent()
        .post("https://graphql.anilist.co")
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send_string(&body.to_string())
    {
        Ok(r) => r,
        Err(e) => {
            // Same treatment as `get_json`: slow the lane on a 429/503
            // and never let one count as "there is no such anime".
            if let ureq::Error::Status(code @ (429 | 503), r) = &e {
                note_refusal(Provider::AniList, r, if *code == 429 { 30 } else { 5 });
                note_unreachable();
                return None;
            }
            note_http_err(&e);
            return None;
        }
    };
    let body = match resp.into_string() {
        Ok(b) => b,
        Err(_) => {
            note_unreachable();
            return None;
        }
    };
    let v = parse_answer(&body)?;
    parse_anilist(&v)
}

// ---------------------------------------------------------------------------
// Music (MusicBrainz + Cover Art Archive) and books (OpenLibrary).
//
// Both keyless, both probed live on 26 Jul 2026 before a line of this
// was written. MusicBrainz REQUIRES a descriptive User-Agent and
// enforces roughly one request per second - it blocks clients that
// ignore that, so the calls here go through `ratelimit`, not through
// the enricher's sleep-between-titles pacing.
//
// FIELD REUSE IS DELIBERATE, NOT A BUG. `TitleMeta` has eight fields
// built for film and TV, and rather than widen the schema for two more
// kinds we map onto the ones that already read correctly on a card:
//
//   artist / author       -> `actors`   (the card renders it as a credit
//                                        line under the title, which is
//                                        exactly what "by Frank Herbert"
//                                        or "Pink Floyd" wants to be)
//   MB genres / OL subjects -> `genres`
//   first release / publish -> `air_date`
//
// Anyone reading `actors` on a music row and assuming a bug: it is not.
// ---------------------------------------------------------------------------

/// `TitleMeta.tmdb_id` is an i64 and doubles as the "a provider matched
/// this" flag (`titles_missing_date` filters on `tmdb_id <> 0`, and the
/// wall's card treats it as matched). MusicBrainz ids are UUIDs and
/// OpenLibrary keys are strings, so neither fits - a stable hash keeps
/// the found/not-found semantics and stays the same across runs. Never
/// use it to address the provider again; it is a flag, not an id.
fn provider_flag_id(s: &str) -> i64 {
    // FNV-1a, masked to 63 bits so it is always positive.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    ((h & 0x7fff_ffff_ffff_ffff) as i64).max(1)
}

/// Paced, UA-bearing JSON GET. A 429/503 is the provider telling us we
/// are going too fast; the bucket is penalised so the whole lane slows
/// down, not just this one call.
///
/// The retries are patient on purpose. MusicBrainz answers 503 "the
/// server is currently busy" routinely rather than exceptionally -
/// measured, three requests in a row drew one - and the enricher stamps
/// a title `checked` when a lookup returns None, never looking at it
/// again. So on this lane a moment of upstream busyness would otherwise
/// blank an album permanently. Waiting out ~50 s in a background worker
/// is cheap; losing the card is not.
fn get_json_paced(p: Provider, url: &str) -> Option<serde_json::Value> {
    if cooling_off(p) {
        return None;
    }
    const BACKOFF_SECS: [u64; 3] = [5, 15, 30];
    for attempt in 0..=BACKOFF_SECS.len() {
        ratelimit::acquire(p);
        match crate::netfetch::shared_enrich_agent()
            .get(url)
            .set("User-Agent", WIKI_UA)
            .timeout(std::time::Duration::from_secs(10))
            .call()
        {
            Ok(resp) => {
                // Cap the body like `fetch_image` does: a provider that
                // answers with something enormous should cost us memory
                // no faster than one that answers correctly.
                let mut body = String::new();
                use std::io::Read;
                if resp
                    .into_reader()
                    .take(4 * 1024 * 1024)
                    .read_to_string(&mut body)
                    .is_err()
                {
                    note_unreachable();
                    return None;
                }
                return parse_answer(&body);
            }
            Err(ureq::Error::Status(429 | 503, r)) => {
                note_refusal(p, &r, BACKOFF_SECS[attempt.min(BACKOFF_SECS.len() - 1)]);
                if attempt == BACKOFF_SECS.len() {
                    // Still busy after ~50 s. That is "we could not ask",
                    // which is exactly what this function's patience is
                    // for - do not let the caller record it as "nothing".
                    note_unreachable();
                    return None;
                }
            }
            Err(e) => {
                note_http_err(&e);
                return None;
            }
        }
    }
    note_unreachable();
    None
}

/// Comma-join at most `n` names, skipping blanks and duplicates.
fn join_names(it: impl Iterator<Item = String>, n: usize) -> String {
    let mut out: Vec<String> = Vec::new();
    for name in it {
        let name = name.trim().to_string();
        if name.is_empty() || out.iter().any(|x: &String| x.eq_ignore_ascii_case(&name)) {
            continue;
        }
        out.push(name);
        if out.len() == n {
            break;
        }
    }
    out.join(", ")
}

/// Pick the best release-group from a MusicBrainz search (tested pure).
///
/// MusicBrainz returns a `score`, but score alone is not enough: a
/// search for one album returns every release group whose title merely
/// contains the words, all at similar scores. The album title has to
/// match after normalisation or a card gets the wrong cover - the same
/// failure OpenLibrary has, where asking for "Dune" ranks "Children of
/// Dune" first.
fn pick_release_group(v: &serde_json::Value, album: &str) -> Option<serde_json::Value> {
    let want = norm_title(album);
    let groups = v["release-groups"].as_array()?;
    let mut fallback: Option<&serde_json::Value> = None;
    for g in groups {
        let title = g["title"].as_str().unwrap_or("");
        if norm_title(title) == want {
            return Some(g.clone());
        }
        // Highest-scoring near-miss, kept only if nothing matches
        // exactly and it is a strong hit - a scene stem drops
        // punctuation and subtitles, so an exact match is not always
        // available for a correct answer.
        if g["score"].as_i64().unwrap_or(0) >= 90 && fallback.is_none() {
            fallback = Some(g);
        }
    }
    fallback.cloned()
}

/// Pure parse of one MusicBrainz release-group into a card (tested).
fn parse_release_group(g: &serde_json::Value) -> Option<TitleMeta> {
    let mbid = g["id"].as_str()?;
    let artist = join_names(
        g["artist-credit"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c["name"].as_str().map(String::from)),
        4,
    );
    // The search response carries no genres; the lookup below adds them.
    // `primary-type` is the honest one-liner we can build without a
    // second call - "Album", "Live", "Compilation".
    let kind = g["primary-type"].as_str().unwrap_or("").to_string();
    let overview = match (kind.is_empty(), artist.is_empty()) {
        (false, false) => format!("{kind} by {artist}"),
        (false, true) => kind,
        _ => String::new(),
    };
    Some(TitleMeta {
        tmdb_id: provider_flag_id(mbid),
        id_src: "musicbrainz".into(),
        overview,
        rating: 0.0,
        genres: String::new(),
        poster_url: String::new(),
        backdrop_url: String::new(),
        imdb: String::new(),
        actors: artist,
        air_date: iso_date(g["first-release-date"].as_str().unwrap_or("")),
        credits: Vec::new(),
    })
}

/// MusicBrainz release-group search, then the group's genres, then the
/// Cover Art Archive front cover. Three paced calls at most.
pub fn musicbrainz_lookup(artist: &str, album: &str) -> Option<TitleMeta> {
    // "VA" is the scene's tag for a various-artists compilation and
    // means nothing to MusicBrainz, which files them under an artist
    // literally named "Various Artists".
    let artist = if artist.eq_ignore_ascii_case("va") {
        "Various Artists"
    } else {
        artist
    };
    // Fail CLOSED without an artist. `credit_split` returns None on a
    // stem it cannot split, and the caller then passes "" - which made
    // this send `artist:""`, a clause Lucene simply ignores, so the
    // search degenerated to "any release called X". Verified live:
    // album "Nevermind" with no artist returns Red Hot Chili Peppers at
    // score 100, "Thriller" a Richard Grey single. The enricher stamps
    // `checked` one-shot, so a wrong artist, date, overview and cover
    // stick to that title permanently. The book sibling already guards
    // this way. No metadata beats confidently wrong metadata.
    if artist.trim().is_empty() || album.trim().is_empty() {
        return None;
    }
    // Lucene: a bare quote closes the phrase and lets the rest of a
    // release name become query syntax. Backslash first, or it escapes
    // the escapes.
    let lucene = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let query = format!(
        "release:\"{}\" AND artist:\"{}\"",
        lucene(album),
        lucene(artist)
    );
    let search = get_json_paced(
        Provider::MusicBrainz,
        &format!(
            "https://musicbrainz.org/ws/2/release-group?query={}&fmt=json&limit=5",
            percent_encode(&query)
        ),
    )?;
    let group = pick_release_group(&search, album)?;
    let mut meta = parse_release_group(&group)?;
    let mbid = group["id"].as_str()?.to_string();

    // Genres live on the release-group lookup, not on search. MB's
    // `genres` are the curated vocabulary; `tags` are raw user text and
    // measured to be noise ("1973", "5+ wochen", "britannique"), so only
    // genres are read.
    if let Some(full) = get_json_paced(
        Provider::MusicBrainz,
        &format!("https://musicbrainz.org/ws/2/release-group/{mbid}?inc=genres&fmt=json"),
    ) {
        meta.genres = join_names(
            full["genres"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|g| g["name"].as_str().map(title_case)),
            4,
        );
    }
    meta.poster_url = coverart_front(&mbid);
    Some(meta)
}

/// Front cover URL for a release group, or empty. Not every release
/// group has art, and a 404 here is ordinary, not an error.
pub fn coverart_front(mbid: &str) -> String {
    let Some(v) = get_json_paced(
        Provider::CoverArt,
        &format!("https://coverartarchive.org/release-group/{mbid}"),
    ) else {
        return String::new();
    };
    parse_coverart(&v)
}

/// Pure pick of the front cover from a Cover Art Archive index (tested).
/// Prefers the 500px thumbnail over the full-size scan, which can be a
/// 20 MB flatbed image of a gatefold sleeve.
fn parse_coverart(v: &serde_json::Value) -> String {
    let images = v["images"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let front = images
        .iter()
        .find(|i| i["front"].as_bool() == Some(true))
        .or_else(|| images.first());
    let Some(img) = front else {
        return String::new();
    };
    let url = img["thumbnails"]["500"]
        .as_str()
        .or_else(|| img["thumbnails"]["large"].as_str())
        .or_else(|| img["image"].as_str())
        .unwrap_or("");
    // The archive answers with http:// URLs in its JSON even though it
    // serves https perfectly well. Upgrade rather than fetch artwork in
    // the clear.
    match url.strip_prefix("http://") {
        Some(rest) => format!("https://{rest}"),
        None => url.to_string(),
    }
}

/// OpenLibrary subjects are long and full of shelving noise
/// ("Reading Level-Grade 7", "Fiction in English", "Accessible book").
/// Keep the short, genre-shaped ones.
fn useful_subject(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    s.len() <= 24
        && !s.contains(',')
        // "Dune (Imaginary Place)" - a catalogue cross-reference, not a
        // genre. Measured on the live service.
        && !s.contains('(')
        && !l.starts_with("reading level")
        && !l.contains("accessible")
        && !l.contains("in english")
        && !l.contains("protected daisy")
        && !l.contains("large type")
        && !l.contains("overdrive")
        // "New York Times Reviewed", "Times bestseller" - shelf badges.
        && !l.contains("reviewed")
        && !l.contains("bestseller")
}

/// True when a name is written mostly in Latin script. OpenLibrary
/// lists an author's name variants in `author_name` alongside any real
/// co-authors, so a single-author book comes back as
/// "Frank Herbert, Френк Герберт" - the transliteration is a duplicate,
/// not a second author, and it reads as noise on the credit line. Keeping
/// only Latin names once we have one drops the variants while leaving a
/// genuinely non-Latin author (who has no Latin form to prefer) intact.
fn mostly_latin(s: &str) -> bool {
    let letters = s.chars().filter(|c| c.is_alphabetic()).count();
    let latin = s
        .chars()
        .filter(|c| c.is_alphabetic() && c.is_ascii())
        .count();
    letters == 0 || latin * 2 >= letters
}

/// Pick and parse the best OpenLibrary hit (tested pure).
///
/// The re-ranking is the point of this function, not a refinement:
/// OpenLibrary's own relevance order answers `title=Dune&author=Frank
/// Herbert` with "Children of Dune" first and the actual "Dune" seventh
/// (measured). Taking `docs[0]` would put the wrong cover on the card
/// every time a book is part of a series.
fn parse_openlibrary(v: &serde_json::Value, title: &str) -> Option<TitleMeta> {
    let want = norm_title(title);
    let docs = v["docs"].as_array()?;
    let best = docs
        .iter()
        .filter(|d| d["cover_i"].as_i64().is_some() || d["title"].as_str().is_some())
        .max_by_key(|d| {
            let t = norm_title(d["title"].as_str().unwrap_or(""));
            // Exact normalised title wins outright; among equals, the
            // most-published edition is the canonical work.
            let exact = i64::from(t == want) * 1_000_000;
            let starts = i64::from(t.starts_with(&want)) * 100_000;
            exact + starts + d["edition_count"].as_i64().unwrap_or(0).min(99_999)
        })?;
    // Nothing matched even loosely - better no card than the wrong book.
    // A doc with a cover and NO title passes the filter above, and an
    // empty title is a prefix of everything, so the guard used to wave
    // exactly the doc it can say the least about straight through.
    let btitle = norm_title(best["title"].as_str().unwrap_or(""));
    if btitle.is_empty() || (!btitle.starts_with(&want) && !want.starts_with(&btitle)) {
        return None;
    }
    let names: Vec<String> = best["author_name"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str().map(String::from))
        .collect();
    let any_latin = names.iter().any(|n| mostly_latin(n));
    let author = join_names(
        names.into_iter().filter(|n| !any_latin || mostly_latin(n)),
        3,
    );
    let genres = join_names(
        best["subject"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str())
            .filter(|s| useful_subject(s))
            .map(title_case),
        4,
    );
    // Deliberately NOT `first_sentence`. It is not language-tagged and
    // OpenLibrary returns whichever edition it happens to hold first:
    // measured live, "Project Hail Mary" came back as "Was ist zwei plus
    // zwei?" - the German edition's opening line, on an English card.
    // A short factual line is always right, and matches the shape the
    // music provider produces ("Album by Pink Floyd").
    let overview = if author.is_empty() {
        String::new()
    } else {
        format!("Book by {author}")
    };
    let key = best["key"]
        .as_str()
        .unwrap_or(best["title"].as_str().unwrap_or(""));
    let poster_url = best["cover_i"]
        .as_i64()
        .map(|id| format!("https://covers.openlibrary.org/b/id/{id}-L.jpg"))
        .unwrap_or_default();
    Some(TitleMeta {
        tmdb_id: provider_flag_id(key),
        id_src: "openlibrary".into(),
        overview,
        // OpenLibrary rates out of 5; every other provider here (and the
        // IMDb snapshot the card shares a star with) is out of 10.
        rating: best["ratings_average"]
            .as_f64()
            .map(|r| r * 2.0)
            .unwrap_or(0.0),
        genres,
        poster_url,
        backdrop_url: String::new(),
        imdb: String::new(),
        actors: author,
        // Only a year is published, and a bare "YYYY" is deliberate: the
        // column is sorted as a plain string and a year is a correct
        // ISO prefix, so it orders against full dates properly. Padding
        // it to "YYYY-01-01" would invent a day we do not know.
        air_date: best["first_publish_year"]
            .as_i64()
            .filter(|y| (1000..=9999).contains(y))
            .map(|y| y.to_string())
            .unwrap_or_default(),
        credits: Vec::new(),
    })
}

/// OpenLibrary search for a book by author + title.
pub fn openlibrary_lookup(author: &str, title: &str) -> Option<TitleMeta> {
    let mut url = format!(
        "https://openlibrary.org/search.json?title={}&limit=10\
         &fields=title,author_name,first_publish_year,cover_i,subject,\
ratings_average,edition_count,key",
        percent_encode(title)
    );
    if !author.is_empty() {
        let _ = write!(url, "&author={}", percent_encode(author));
    }
    let v = get_json_paced(Provider::OpenLibrary, &url)?;
    parse_openlibrary(&v, title)
}

/// Lowercase scene text ("progressive rock") reads badly next to the
/// other providers' genre lists, which are already capitalised.
fn title_case(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse IMDb's title.ratings TSV (tconst\taverageRating\tnumVotes),
/// keeping rows with ≥ `min_votes` - drops the long tail of 1-vote
/// entries and shrinks 1.5M rows to a few hundred k (tested).
pub fn parse_imdb_ratings(tsv: &str, min_votes: u64) -> Vec<(String, f64, u64)> {
    tsv.lines()
        .skip(1) // header
        .filter_map(|l| {
            let mut f = l.split('\t');
            let t = f.next()?;
            let r: f64 = f.next()?.parse().ok()?;
            let v: u64 = f.next()?.parse().ok()?;
            (v >= min_votes).then(|| (t.to_string(), r, v))
        })
        .collect()
}

/// Download + gunzip the daily IMDb ratings snapshot (keyless; IMDb's
/// official non-commercial datasets - credited in the wall footer).
pub fn imdb_ratings_fetch() -> Option<Vec<(String, f64, u64)>> {
    let resp = crate::netfetch::shared_enrich_agent()
        .get("https://datasets.imdbws.com/title.ratings.tsv.gz")
        .timeout(std::time::Duration::from_secs(120))
        .call()
        .ok()?;
    let mut gz = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(64 * 1024 * 1024)
        .read_to_end(&mut gz)
        .ok()?;
    let mut tsv = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut tsv)
        .ok()?;
    Some(parse_imdb_ratings(&tsv, 100))
}

/// Fetch a poster/backdrop image by full URL (any provider). Routed
/// through the SSRF-guarded agent: metadata providers are public hosts,
/// and a "set poster from URL" value must not become a request into the
/// host's own network (cloud metadata, LAN services).
pub fn fetch_image(url: &str) -> Option<Vec<u8>> {
    fetch_image_res(url).ok()
}

/// Why an image did not arrive - the art half of [`Outcome`].
///
/// The enricher needs the distinction for the same reason the metadata
/// chain does: it writes the card and the `checked` stamp in one call,
/// and that stamp is final. A poster that 504'd for ten seconds used to
/// come back as `None`, indistinguishable from a URL that serves
/// nothing, and the card kept its permanent hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtMiss {
    /// The host answered and there is no usable image here: a 404 or
    /// other definitive 4xx, an empty body, or one past the size cap.
    /// Asking again gets the same answer.
    NoImage,
    /// We could not get an answer: a timeout, a TLS or DNS failure, a
    /// 5xx, a 429. Worth another pass.
    Transient,
}

/// [`fetch_image`] with the reason for a miss kept.
pub fn fetch_image_res(url: &str) -> Result<Vec<u8>, ArtMiss> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ArtMiss::NoImage);
    }
    // 15 s, as when this built its own agent: the shared one's default is
    // longer, and an art fetch should not inherit it.
    let resp = crate::netfetch::shared_enrich_agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .map_err(|e| match &e {
            // Same classification as `note_http_err`, and it has to
            // stay the same: an art host that is briefly broken is not
            // an art host with no art.
            ureq::Error::Status(code, _) if *code < 500 && !matches!(code, 408 | 425 | 429) => {
                ArtMiss::NoImage
            }
            _ => ArtMiss::Transient,
        })?;
    let mut bytes = Vec::new();
    use std::io::Read;
    // cap + 1, and REFUSE anything that fills past the cap: a bare
    // take(cap) silently truncated an oversized original-resolution
    // poster to a torn head-of-file, which passed the only check
    // (non-empty) and was cached in an art dir that never re-fetches -
    // a permanently corrupt image. Truncated JSON self-corrects at the
    // parse; truncated image bytes pass everything.
    const CAP: u64 = 4 * 1024 * 1024;
    // A read that dies mid-body is a connection that dropped, not an
    // answer about the image.
    resp.into_reader()
        .take(CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ArtMiss::Transient)?;
    if bytes.is_empty() || bytes.len() as u64 > CAP {
        return Err(ArtMiss::NoImage);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Filmography: the person page's "not in your index" half.
//
// Two sources because neither is a filmography on its own. TVmaze's
// castcredits endpoint is TV ONLY - measured live, Adam Scott comes back
// with 8 credits, a fraction of his real body of work - and Wikidata's
// reverse cast lookup is the film half. Both are keyless; both are
// on-demand only. In particular Wikidata's SPARQL service is rate-limited
// with a query timeout, which is fine for one person page and wrong for
// any kind of bulk backfill.
// ---------------------------------------------------------------------------

/// One credit on a person's filmography, wherever it came from.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FilmoEntry {
    pub title: String,
    /// ISO date, or a bare "YYYY", or empty - providers give all three.
    pub date: String,
    pub year: u32,
    /// "tv" | "movie".
    pub kind: String,
    pub character: String,
    pub source: String,
}

/// Sort a filmography newest-first with undated credits LAST.
///
/// Not a detail: many Wikidata rows carry no P577 at all, and a plain
/// descending sort on a possibly-empty string puts every one of them at
/// the head of the list, which reads as "these are the newest".
fn sort_filmography(v: &mut [FilmoEntry]) {
    v.sort_by(|a, b| {
        a.date
            .is_empty()
            .cmp(&b.date.is_empty())
            .then_with(|| b.date.cmp(&a.date))
            .then_with(|| a.title.cmp(&b.title))
    });
}

/// Pure parse of a TVmaze `/people/:id/castcredits?embed=show` response
/// (tested).
fn parse_tvmaze_castcredits(v: &serde_json::Value) -> Vec<FilmoEntry> {
    v.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|c| {
                    let show = &c["_embedded"]["show"];
                    let title = show["name"].as_str().filter(|n| !n.is_empty())?;
                    let date = iso_date(show["premiered"].as_str().unwrap_or(""));
                    Some(FilmoEntry {
                        title: title.to_string(),
                        year: date.get(..4).and_then(|y| y.parse().ok()).unwrap_or(0),
                        date,
                        kind: "tv".into(),
                        // The character rides on the link, not the
                        // embed - TVmaze only embeds one relation.
                        character: c["_links"]["character"]["name"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        source: "tvmaze".into(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every TV show a TVmaze person id has acted in. `None` = the service
/// did not answer, which is NOT the same as "they have no TV credits".
pub fn tvmaze_filmography(person_id: i64) -> Option<Vec<FilmoEntry>> {
    get_json(
        Provider::Tvmaze,
        &format!("https://api.tvmaze.com/people/{person_id}/castcredits?embed=show"),
    )
    .map(|v| parse_tvmaze_castcredits(&v))
}

/// Pure parse of a Wikidata SPARQL result set into film credits
/// (tested).
///
/// Two measured hazards, both handled here rather than by the caller:
///
/// - **The result mixes TV in with film.** A Keanu Reeves query really
///   does return "The Fresh Prince of Bel-Air" and "American Chopper" -
///   P161 (cast member) is not film-specific. Rows are kept only when
///   their P31 is one of `FILM_CLASSES`, the same list the movie
///   provider already picks entities with.
/// - **One film yields several rows**, because it has several P31 values
///   and often several P577 dates. Deduped by entity, keeping the
///   earliest date.
pub fn parse_sparql_filmography(v: &serde_json::Value) -> Vec<FilmoEntry> {
    let last = |uri: &str| uri.rsplit('/').next().unwrap_or("").to_string();
    let mut by_entity: HashMap<String, FilmoEntry> = HashMap::new();
    let mut is_film: std::collections::HashSet<String> = std::collections::HashSet::new();
    for row in v["results"]["bindings"].as_array().into_iter().flatten() {
        let Some(qid) = row["film"]["value"].as_str().map(last) else {
            continue;
        };
        if row["class"]["value"]
            .as_str()
            .map(last)
            .is_some_and(|c| FILM_CLASSES.contains(&c.as_str()))
        {
            is_film.insert(qid.clone());
        }
        let title = row["filmLabel"]["value"].as_str().unwrap_or("");
        // An unresolved label comes back as the bare Q-id; a person page
        // listing "Q157443" is worse than one fewer credit.
        if title.is_empty() || title == qid {
            continue;
        }
        let date = wikidata_iso(row["date"]["value"].as_str().unwrap_or(""));
        let e = by_entity.entry(qid).or_insert_with(|| FilmoEntry {
            title: title.to_string(),
            kind: "movie".into(),
            source: "wikidata".into(),
            ..Default::default()
        });
        // A film is released per territory; the one that matters is the
        // first.
        if !date.is_empty() && (e.date.is_empty() || date < e.date) {
            e.year = date.get(..4).and_then(|y| y.parse().ok()).unwrap_or(0);
            e.date = date;
        }
    }
    let mut out: Vec<FilmoEntry> = by_entity
        .into_iter()
        .filter(|(q, _)| is_film.contains(q))
        .map(|(_, e)| e)
        .collect();
    sort_filmography(&mut out);
    out
}

/// Every film a Wikidata Q-id is credited in, via the public SPARQL
/// endpoint. `None` = the service did not answer.
///
/// That distinction earned itself: the endpoint is rate-limited with a
/// query timeout, and it really does refuse one call and serve the next.
/// Collapsing a refusal into an empty list makes the page say "you
/// already have everything" about an actor with fifty films.
///
/// The label language is `"en,mul"`, not `"en"` - see `resolve_labels`
/// for why. Measured on this exact query: `"en"` alone lost 7 of Tom
/// Cruise's 60 credits, including Top Gun: Maverick.
pub fn wikidata_filmography(qid: &str) -> Option<Vec<FilmoEntry>> {
    if !qid.starts_with('Q') || qid.len() < 2 || !qid[1..].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // LIMIT keeps a prolific actor inside the service's query timeout.
    let query = format!(
        "SELECT ?film ?filmLabel ?date ?class WHERE {{ \
           ?film wdt:P161 wd:{qid} . \
           OPTIONAL {{ ?film wdt:P577 ?date }} \
           OPTIONAL {{ ?film wdt:P31 ?class }} \
           SERVICE wikibase:label {{ bd:serviceParam wikibase:language \"en,mul\" }} \
         }} LIMIT 400"
    );
    ratelimit::acquire(Provider::WikidataSparql);
    let resp = crate::netfetch::shared_enrich_agent()
        .get(&format!(
            "https://query.wikidata.org/sparql?query={}",
            percent_encode(&query)
        ))
        .set("User-Agent", WIKI_UA)
        .set("Accept", "application/sparql-results+json")
        // Longer than the metadata calls on purpose: SPARQL is a query
        // engine, not a document fetch, and a busy service is slow before it
        // is unavailable.
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .ok()?;
    let body = resp.into_string().ok()?;
    serde_json::from_str(&body)
        .ok()
        .map(|v: serde_json::Value| parse_sparql_filmography(&v))
}

/// Both halves of a person's filmography, fetched concurrently because
/// they are different services with different limits.
///
/// The bool is "every source we asked actually answered". False means the
/// list is short because a provider declined, not because the person has
/// no more credits - and the page has to say so rather than presenting a
/// partial list as complete.
pub fn person_filmography(tvmaze_id: i64, qid: &str) -> (Vec<FilmoEntry>, bool) {
    let (mut out, complete) = std::thread::scope(|s| {
        let tv = s.spawn(move || (tvmaze_id > 0).then(|| tvmaze_filmography(tvmaze_id)));
        let film = (!qid.is_empty()).then(|| wikidata_filmography(qid));
        let tv = tv.join().unwrap_or(None);
        // `Some(None)` is "asked, and it did not answer"; `None` is "there
        // was no handle to ask with", which is not a failure.
        let complete = !matches!(tv, Some(None)) && !matches!(film, Some(None));
        let mut out = film.flatten().unwrap_or_default();
        out.extend(tv.flatten().unwrap_or_default());
        (out, complete)
    });
    sort_filmography(&mut out);
    (out, complete)
}

/// Art-cache filename for a person's headshot. Shares the art directory
/// with posters, so the name has to be distinguishable from one: the "p"
/// prefix plus digits can never collide with `art_name`'s output, which
/// always starts with a title key's kind letter and its separator
/// underscore ("m_", "t_", "c_").
pub fn person_art_name(id: i64) -> String {
    format!("p{id}.jpg")
}

/// Is this art-directory entry an evictable headshot? Posters and
/// backdrops must never match - they are the wall itself, and nothing
/// re-fetches them on demand.
pub fn is_person_art_name(name: &str) -> bool {
    // The lazy "thumb_" variant counts too: nothing asks for one today,
    // but the /art/ route will make one for any name, and an evictable
    // file whose thumbnail is not evictable is a cache that leaks.
    name.strip_prefix("thumb_")
        .unwrap_or(name)
        .strip_prefix('p')
        .and_then(|r| r.strip_suffix(".jpg"))
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// The widest decoration anything in this repo composes onto an
/// [`art_name`] result, spelled over an EMPTY stem - the house idiom for
/// a stem reserve, so the number and the writers cannot drift.
///
/// It is a BACKDROP's upload staging name,
/// `.{stem}.bd.jpg.new-{pid}-{nanos}` (`serve::api::wall::art_staging_name`),
/// with a `u32` pid at its widest (ten digits) and `subsec_nanos`, which
/// is under a second and so nine. Hence the leading `..`: the first dot
/// is the staging prefix and the second opens `.bd.jpg` onto a stem that
/// is not there.
///
/// The `/art/` route's lazy `thumb_` derivative (`serve::http::route_art`)
/// is six bytes in front of `.bd.jpg`'s seven, so it is not the maximum
/// and does not set this number. It is named here anyway, because a
/// reserve that had forgotten it would be wrong the day the two met.
/// `art_names_leave_room_for_every_decoration` drives the real writers
/// and pins both.
pub(crate) const ART_DECORATION: &str = "..bd.jpg.new-4294967295-999999999";

/// Art-cache filename for a title key (safe, flat, deterministic).
///
/// # Why the length is decided HERE
///
/// Nothing bounds a title key. It is `m:{norm_title}:{year}` /
/// `t:{norm_title}` (`nzbkit::release`), `norm_title` truncates nothing,
/// and an obfuscated post with no recognisable furniture makes the WHOLE
/// release stem the title - and Usenet subjects routinely carry 100-250
/// characters. So this name used to run past what a filesystem takes: at
/// 233..=255 bytes the live poster wrote and the staging decoration
/// above failed, and past 255 neither could be written at all. Both
/// surfaced as `couldn't write the art cache`, or as
/// `republish_title_art` deleting the live art after a failed publish.
///
/// This is an identity key as much as a filename - the index stores it
/// (`nzbkit::index::cards::TitleArt::poster`), `/art/` serves it, and
/// [`drop_art`], [`drop_art_thumbs`], the enrichment lane and the fixer
/// all RECOMPUTE it - so every reader has to get the same string out.
/// They do, because they all come through this function; that is the
/// whole reason the cap is here and not at any write.
///
/// # Why a stem reserve rather than capping the composed name
///
/// The rule for an identity key is normally "cap the COMPOSED name"
/// (`nzbkit::disk::sanitize_filename_capped_for`). It is the wrong one
/// here, for `cap_shared_stem`'s own reason: FOUR names are composed off
/// this one stem - poster, backdrop, and the `thumb_` derivative of
/// each - and the `/art/` route finds a thumbnail's source by STRIPPING
/// the prefix, so the pairing IS the shared stem. Capping each composed
/// name independently hashes different inputs, and `thumb_` + a name
/// already at 255 is unwritable again.
///
/// # Why the `-` is folded to `_`
///
/// `cap_component` joins its hash tag on with a `-`, and a `-` is
/// exactly what `serve::apiutil::art_name_ok` refuses - which is what
/// makes a staging name unservable by construction, and what lets
/// `is_art_staging_name` split on `.new-`. Both are load-bearing, so the
/// character goes rather than the filter. The fold is total (it maps
/// every `-`, not a known position), and it cannot merge two keys that
/// the cap kept apart: the tag is 12 hex digits either side of it.
pub fn art_name(key: &str, backdrop: bool) -> String {
    let safe: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let safe = nzbkit::disk::cap_shared_stem(&safe, [ART_DECORATION]);
    // Deterministic across restarts because `cap_shared_stem` is: a
    // truncation plus a SHA-256 prefix of the whole input, no clock, no
    // process state, no map iteration. Same key in, same name out - which
    // is what the readers above rest on.
    let safe = if safe.contains('-') {
        safe.replace('-', "_")
    } else {
        safe
    };
    format!("{safe}{}.jpg", if backdrop { ".bd" } else { "" })
}

/// Drop the cached THUMBNAILS for one title, keeping the full-size art.
///
/// Every writer of a title's poster has to call this, and forgetting it
/// is invisible in the code that writes the poster. `/art/thumb_<name>`
/// is generated from the full poster on first request and then cached on
/// disk under a name derived from the same title key, so a new poster
/// written over the old one at the same path leaves the grid serving the
/// OLD thumbnail - for good. The card's `?v=<checked>` query busts the
/// browser's cache, not the server's file: the route strips the query
/// before it joins the name.
pub fn drop_art_thumbs(art_dir: &std::path::Path, key: &str) {
    for backdrop in [false, true] {
        let _ = std::fs::remove_file(art_dir.join(format!("thumb_{}", art_name(key, backdrop))));
    }
}

/// Drop everything the art cache holds for one title - poster, backdrop
/// and both thumbnails. For the paths that mean "this title's art is
/// wrong", not the ones that replace it.
pub fn drop_art(art_dir: &std::path::Path, key: &str) {
    drop_art_thumbs(art_dir, key);
    for backdrop in [false, true] {
        let _ = std::fs::remove_file(art_dir.join(art_name(key, backdrop)));
    }
}

// The OMDb and Wikidata clients, moved out bodily (TODO 106) and re-exported
// so every caller still names `wall::omdb_lookup` / `wall::wikidata_movie`.
mod omdb;
pub use omdb::{omdb_lookup, omdb_lookup_imdb, omdb_search, omdb_signup};
// `wall::tests` drives the parsers and the signup form builder directly, and
// a sibling child module is not in scope through its own `use super::*`.
#[cfg(test)]
use omdb::{form_encode, omdb_free_radio, omdb_signup_fields, parse_omdb, parse_omdb_search};
#[cfg(test)]
use wikidata::pick_wikidata_imdb;
mod wikidata;
use wikidata::{FILM_CLASSES, wikidata_iso, wikidata_search};
pub use wikidata::{parse_wikidata_candidates, wikidata_imdb, wikidata_movie};
// The parsers under those three have no production caller of their own - each
// is the inner half of a lookup beside it - but `wall::tests` drives every one
// of them directly against a captured entity body.
#[cfg(test)]
pub use wikidata::{
    PersonFacts, parse_person_facts, parse_wikidata_credits, parse_wikidata_film,
    pick_wikidata_film,
};

#[cfg(test)]
mod tests;
