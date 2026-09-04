//! The Wikidata client: the keyless fallback the wall leans on when no
//! provider key is configured.
//!
//! Entity search and the candidate pick over it, the film/credit/candidate
//! parsers on top, the label cache that keeps repeat QIDs off the wire, and
//! the person facts filled in behind a credit list (TODO 106 code motion
//! out of wall.rs, behaviour unchanged).

use super::*;

/// Entity labels are overwhelmingly repeats - every science-fiction film
/// references the same genre Q-id, and a prolific actor recurs across a
/// whole filmography - so resolving them once per process removes most
/// of the third Wikidata call as the wall fills in.
fn label_cache() -> &'static std::sync::Mutex<HashMap<String, String>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Pure candidate-picking over wbsearchentities + wbgetentities claims:
/// take the first candidate holding an IMDb id (P345) whose publication
/// year (P577) matches ±1 when we know the year (tested).
pub(super) fn pick_wikidata_imdb(
    search: &serde_json::Value,
    entities: &serde_json::Value,
    year: u32,
) -> Option<String> {
    let order: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    let year_of = |ent: &serde_json::Value| -> Option<u32> {
        ent["claims"]["P577"].as_array()?.first()?["mainsnak"]["datavalue"]["value"]["time"]
            .as_str()?
            .get(1..5)?
            .parse()
            .ok()
    };
    for id in order {
        let ent = &entities["entities"][id];
        let Some(tconst) = ent["claims"]["P345"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["mainsnak"]["datavalue"]["value"].as_str())
        else {
            continue;
        };
        if year > 0 {
            match year_of(ent) {
                Some(y) if y.abs_diff(year) <= 1 => return Some(tconst.to_string()),
                Some(_) => continue,
                None => continue,
            }
        }
        return Some(tconst.to_string());
    }
    None
}

/// Wikidata: resolve a movie title(+year) to an IMDb tconst - the join
/// key for the IMDb ratings snapshot. Two keyless calls.
pub fn wikidata_imdb(title: &str, year: u32) -> Option<String> {
    let search = get_json_ua(
        Provider::Wikidata,
        &format!(
            "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json\
         &language=en&type=item&limit=5&search={}",
            percent_encode(title)
        ),
    )?;
    let ids: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    if ids.is_empty() {
        return None;
    }
    let entities = get_json_ua(
        Provider::Wikidata,
        &format!(
            "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json\
         &props=claims&ids={}",
            ids.join("|")
        ),
    )?;
    pick_wikidata_imdb(&search, &entities, year)
}

// ---------------------------------------------------------------------------
// Wikidata as the keyless MOVIE provider.
//
// Apple removed movies from the iTunes Search API: as of 26 Jul 2026
// `media=movie` answers HTTP 200 with `resultCount: 0` for every title
// tried, mainstream or not, in every storefront. That left the keyless
// movie path with no metadata source at all - a live index measured 36
// posters across 3676 movie titles (1.0%) and zero cast, against 59% and
// 48% for TV, which goes to TVmaze.
//
// Wikidata replaces it using the two calls `wikidata_imdb` was already
// making: wbsearchentities to find candidates, wbgetentities to read
// their claims. The claims we were throwing away carry the whole card -
// P345 IMDb id, P577 publication date, P136 genre, P161 cast. The
// poster comes from Wikipedia, not Wikidata - see `parse_wikidata_film`. Only the third call (resolving genre/cast Q-ids to names)
// is new. Plot still comes from Wikipedia, as it did before.
// ---------------------------------------------------------------------------

/// P31 (instance of) values that mean "this entity is a film". Wikidata
/// has no single film class, and the subtypes do not all declare P31 to
/// the parent, so the specific ones have to be listed.
pub(super) const FILM_CLASSES: [&str; 7] = [
    "Q11424",    // film
    "Q24869",    // feature film
    "Q506240",   // television film
    "Q202866",   // animated film
    "Q93204",    // documentary film
    "Q24862",    // short film
    "Q20650540", // adult film
];

/// External-id / string-valued claims (P345 imdb).
fn claim_strs(ent: &serde_json::Value, prop: &str) -> Vec<String> {
    ent["claims"][prop]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["mainsnak"]["datavalue"]["value"].as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Entity-valued claims (P136 genre, P161 cast member) → the Q-ids.
fn claim_entity_ids(ent: &serde_json::Value, prop: &str) -> Vec<String> {
    ent["claims"][prop]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["mainsnak"]["datavalue"]["value"]["id"].as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Wikidata times look like "+2010-07-16T00:00:00Z" - the leading sign
/// is mandatory in the model and breaks `iso_date`'s digit check, so it
/// is stripped here rather than teaching every caller about it.
pub(super) fn wikidata_iso(t: &str) -> String {
    iso_date(t.strip_prefix('+').unwrap_or(t))
}

/// Earliest P577 (publication date). Films carry one per territory, and
/// the release we care about is the first one.
fn earliest_publication(ent: &serde_json::Value) -> String {
    let mut dates: Vec<String> = ent["claims"]["P577"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["mainsnak"]["datavalue"]["value"]["time"].as_str())
                .map(wikidata_iso)
                .filter(|d| !d.is_empty())
                .collect()
        })
        .unwrap_or_default();
    dates.sort();
    dates.into_iter().next().unwrap_or_default()
}

fn is_film_entity(ent: &serde_json::Value) -> bool {
    claim_entity_ids(ent, "P31")
        .iter()
        .any(|q| FILM_CLASSES.contains(&q.as_str()))
}

/// Pick the film entity a title(+year) means, in search-rank order
/// (tested). Two passes: one that insists on an IMDb id, then one that
/// does not - a Wikidata film without P345 still has art, a date, genres
/// and a cast, which beats the bare stem the wall shows otherwise.
///
/// A known year is a hard filter, not a tiebreak: "The Italian Job"
/// resolves to two films, and showing the wrong one's poster is worse
/// than showing none.
pub fn pick_wikidata_film(
    search: &serde_json::Value,
    entities: &serde_json::Value,
    year: u32,
) -> Option<String> {
    let order: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    let year_ok = |ent: &serde_json::Value| -> bool {
        if year == 0 {
            return true;
        }
        earliest_publication(ent)
            .get(..4)
            .and_then(|y| y.parse::<u32>().ok())
            .is_some_and(|y| y.abs_diff(year) <= 1)
    };
    for want_imdb in [true, false] {
        for id in &order {
            let ent = &entities["entities"][*id];
            if !is_film_entity(ent) || !year_ok(ent) {
                continue;
            }
            if want_imdb && claim_strs(ent, "P345").is_empty() {
                continue;
            }
            return Some((*id).to_string());
        }
    }
    None
}

/// A picked film entity + resolved names for its referenced Q-ids → the
/// card (tested). A Q-id missing from `labels` is dropped rather than
/// shown raw, because "Q157443" on a poster card is worse than one
/// fewer genre.
pub fn parse_wikidata_film(ent: &serde_json::Value, labels: &HashMap<String, String>) -> TitleMeta {
    let names = |ids: Vec<String>, cap: usize| -> String {
        ids.iter()
            .filter_map(|q| labels.get(q).cloned())
            .take(cap)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let credits = parse_wikidata_credits(ent, labels);
    TitleMeta {
        // Wikidata is not one of the id namespaces the fix-match flow
        // resolves against, so it contributes no provider id - and
        // therefore no namespace to label either.
        tmdb_id: 0,
        id_src: String::new(),
        // Wikidata holds no synopsis; the caller's Wikipedia fallback
        // fills this, exactly as it did behind iTunes.
        overview: String::new(),
        // No community rating either - the IMDb snapshot overlays one at
        // wall time via the tconst below.
        rating: 0.0,
        genres: names(claim_entity_ids(ent, "P136"), 4),
        // No poster from here. P18 ("image") is NOT a film poster:
        // posters are non-free and cannot live on Commons, so P18 holds
        // whatever freely-licensed picture exists instead - measured
        // against the live API, The Matrix returns a screenshot of the
        // glmatrix screensaver and Inception a photo of the cast at a
        // premiere. Both are worse on a wall than no art at all. The
        // caller pairs this with `wikipedia_page`, whose infobox image
        // IS the poster.
        poster_url: String::new(),
        backdrop_url: String::new(),
        imdb: claim_strs(ent, "P345").first().cloned().unwrap_or_default(),
        // Billing order IS modelled after all - as the P1545 qualifier on
        // each cast claim, which `parse_wikidata_credits` reads. The
        // credit line is rendered from that order rather than from the
        // order the claims happened to be stored in.
        actors: credit_line(&credits, 8),
        air_date: earliest_publication(ent),
        credits,
    }
}

/// Wikidata crew properties worth a credit, and the role each becomes.
/// Deliberately short: these are the four the film community actually
/// looks a film up by, and every one of them is already in the claims
/// response we parse for genre and cast.
const WIKIDATA_CREW: [(&str, &str); 4] = [
    ("P57", "director"),
    ("P58", "writer"),
    ("P86", "composer"),
    ("P162", "producer"),
];

/// Cast and crew from a film entity's claims (tested).
///
/// The cast half is what `parse_wikidata_film` was already reading and
/// flattening to names. Two things were being dropped from claims we had
/// in hand: the **P453 character-role qualifier** (9 of the 19 cast on
/// The Matrix carry one) and **P1545, the series ordinal**, which is
/// Wikidata's billing order - without it the "starring" line is in
/// whatever order the claims happened to be stored in.
pub fn parse_wikidata_credits(
    ent: &serde_json::Value,
    labels: &HashMap<String, String>,
) -> Vec<Credit> {
    let mut out: Vec<Credit> = Vec::new();
    if let Some(list) = ent["claims"]["P161"].as_array() {
        for c in list {
            let Some(qid) = c["mainsnak"]["datavalue"]["value"]["id"].as_str() else {
                continue;
            };
            // A Q-id with no resolved label is dropped rather than shown
            // raw, exactly as the genre list does: "Q157443" is not a
            // name, and a person page titled with one is worse than one
            // fewer credit.
            let Some(name) = labels.get(qid) else {
                continue;
            };
            let qual = |p: &str| -> Option<&serde_json::Value> {
                c["qualifiers"][p].as_array().and_then(|a| a.first())
            };
            out.push(Credit {
                name: name.clone(),
                role: "actor".into(),
                character: qual("P453")
                    .and_then(|q| q["datavalue"]["value"]["id"].as_str())
                    .and_then(|q| labels.get(q))
                    .cloned()
                    .unwrap_or_default(),
                // P1545 is a string in the data model even though it
                // holds a number.
                ord: qual("P1545")
                    .and_then(|q| q["datavalue"]["value"].as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                wikidata_qid: qid.to_string(),
                ..Default::default()
            });
        }
    }
    // Only some of a cast carry P1545 (10 of 19 on The Matrix do not).
    // Sorting on ord alone would float every unranked name above the
    // billed leads, so they keep claim order in a band behind them.
    let mut n = 0;
    for c in out.iter_mut().filter(|c| c.ord == 0) {
        n += 1;
        c.ord = 1000 + n;
    }
    out.sort_by_key(|c| c.ord);
    for (prop, role) in WIKIDATA_CREW {
        for qid in claim_entity_ids(ent, prop) {
            let Some(name) = labels.get(&qid) else {
                continue;
            };
            out.push(Credit {
                name: name.clone(),
                role: role.into(),
                wikidata_qid: qid,
                ..Default::default()
            });
        }
    }
    out
}

/// Search Wikidata for a title and pull the candidates' claims: the two
/// calls every Wikidata path here starts with. `labels` and
/// `descriptions` ride along because the candidate list needs them and
/// they cost nothing extra.
pub(super) fn wikidata_search(title: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    let search = get_json_ua(
        Provider::Wikidata,
        &format!(
            "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json\
         &language=en&type=item&limit=10&search={}",
            percent_encode(title)
        ),
    )?;
    let ids: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    if ids.is_empty() {
        return None;
    }
    let entities = get_json_ua(
        Provider::Wikidata,
        &format!(
            "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json\
         &props=claims|labels|descriptions&languages=en|mul&ids={}",
            ids.join("|")
        ),
    )?;
    Some((search, entities))
}

/// Every film among the candidates → the "did you mean?" list behind the
/// wall's fix-match flow (tested). Year is a filter here too, but a
/// missing date is kept: the user is looking at the list precisely
/// because the automatic pick went wrong.
pub fn parse_wikidata_candidates(
    search: &serde_json::Value,
    entities: &serde_json::Value,
    year: u32,
) -> Vec<Candidate> {
    let Some(order) = search["search"].as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for id in order.iter().filter_map(|c| c["id"].as_str()) {
        let ent = &entities["entities"][id];
        if !is_film_entity(ent) {
            continue;
        }
        let date = earliest_publication(ent);
        let y = date
            .get(..4)
            .and_then(|y| y.parse::<u32>().ok())
            .unwrap_or(0);
        if year > 0 && y > 0 && y.abs_diff(year) > 1 {
            continue;
        }
        // `mul` fallback for the same reason `resolve_labels` needs one.
        let title = ent["labels"]["en"]["value"]
            .as_str()
            .or(ent["labels"]["mul"]["value"].as_str())
            .unwrap_or("");
        if title.is_empty() {
            continue;
        }
        out.push(Candidate {
            id: 0,
            kind: "movie".into(),
            title: title.to_string(),
            year: y,
            // Wikidata's one-line description ("1999 film by the
            // Wachowskis") is exactly the disambiguator this list needs.
            overview: ent["descriptions"]["en"]["value"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            rating: 0.0,
            genres: String::new(),
            // No art: P18 is not a film poster (see
            // `parse_wikidata_film`), and a wrong picture in a
            // "did you mean?" list is worse than none - the title, year
            // and Wikidata's one-line description already disambiguate.
            poster_url: String::new(),
            backdrop_url: String::new(),
            imdb: claim_strs(ent, "P345").first().cloned().unwrap_or_default(),
            provider: "wikidata".into(),
            air_date: date,
        });
    }
    out
}

/// Wikidata: the keyless movie provider. Four calls - search, claims,
/// labels for the genre/cast entities the claims reference (skipped when
/// there are none), and the cast's own IMDb ids and birth dates. The
/// fourth is what stops a credit from being a name with a Q-id attached:
/// without it two same-named people from different providers have
/// nothing to disagree about and merge into one row (see
/// `person_upsert`). Every one of them is cached process-wide, so a wall
/// filling in makes far fewer than four per film.
pub fn wikidata_movie(title: &str, year: u32) -> Option<TitleMeta> {
    let (search, entities) = wikidata_search(title)?;
    let picked = pick_wikidata_film(&search, &entities, year)?;
    let ent = &entities["entities"][&picked];
    // Everything the card and the credits reference, in ONE label call.
    // The cast cap is 16 rather than 8 because the credit line shows 8
    // but the person graph keeps them all, and characters/crew ride in
    // the same 50-id budget `resolve_labels` already spends.
    let mut refs = claim_entity_ids(ent, "P136");
    refs.extend(claim_entity_ids(ent, "P161").into_iter().take(16));
    refs.extend(character_qids(ent).into_iter().take(16));
    for (prop, _) in WIKIDATA_CREW {
        refs.extend(claim_entity_ids(ent, prop).into_iter().take(4));
    }
    refs.sort();
    refs.dedup();
    let mut meta = parse_wikidata_film(ent, &resolve_labels(&refs));
    fill_person_facts(&mut meta.credits);
    Some(meta)
}

/// The P453 (character role) Q-ids qualifying a film's cast claims -
/// resolved in the same label call as the cast themselves.
fn character_qids(ent: &serde_json::Value) -> Vec<String> {
    ent["claims"]["P161"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| {
                    c["qualifiers"]["P453"].as_array()?.first()?["datavalue"]["value"]["id"]
                        .as_str()
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Q-ids → names, serving what the process has already seen from cache
/// and asking Wikidata only for the rest.
///
/// Asks for `en|mul`, not `en`. Wikidata's newer convention is to store a
/// name that is the same in every language ONCE, under the `mul`
/// (multilingual) code, instead of duplicating it per language - and
/// modern film items increasingly do. Measured 26 Jul 2026: Top Gun:
/// Maverick (Q31202708) has NO `en` label at all, only `mul`. Asking for
/// English alone silently drops every such entity, which on a person page
/// meant losing 7 of Tom Cruise's 60 credits without a trace.
fn resolve_labels(ids: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut want: Vec<String> = Vec::new();
    {
        let cache = label_cache().lock_ok();
        for q in ids {
            match cache.get(q) {
                Some(name) => {
                    out.insert(q.clone(), name.clone());
                }
                None => want.push(q.clone()),
            }
        }
    }
    // wbgetentities takes at most 50 ids per call, and one call is all
    // this is worth: a film referencing more than that just gets the
    // first 50 resolved.
    want.truncate(50);
    if want.is_empty() {
        return out;
    }
    let Some(v) = get_json_ua(
        Provider::Wikidata,
        &format!(
            "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json\
         &props=labels&languages=en|mul&ids={}",
            want.join("|")
        ),
    ) else {
        return out;
    };
    let mut cache = label_cache().lock_ok();
    for q in want {
        let l = &v["entities"][&q]["labels"];
        if let Some(name) = l["en"]["value"].as_str().or(l["mul"]["value"].as_str()) {
            cache.insert(q.clone(), name.to_string());
            out.insert(q, name.to_string());
        }
    }
    out
}

/// What Wikidata knows about a credited person beyond their name: the
/// two facts that let `person_upsert` decide whether a same-named credit
/// is the same human.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PersonFacts {
    /// P345, and only when it is an `nm…` id - see `parse_person_facts`.
    pub imdb: String,
    /// P569 at day precision, ISO `YYYY-MM-DD`.
    pub born: String,
}

/// Is this a Q-id we are willing to put in a query? Everything here
/// comes from a provider response, and a Q-id is interpolated into
/// SPARQL rather than bound.
fn is_qid(q: &str) -> bool {
    q.len() >= 2 && q.starts_with('Q') && q[1..].bytes().all(|b| b.is_ascii_digit())
}

/// Pure parse of the person-facts SPARQL result set (tested).
///
/// One measured guard: **P345 is not person-only.** It is "IMDb ID" for
/// every kind of entity, so an entity that turns out to be a film hands
/// back a `tt…` title id - Q3564164, used as an actor in the D2
/// regression test, really returns `tt0034354`. Storing that in
/// `people.imdb` would put a film's id in a person's identity column and
/// let two unrelated people match on it, so anything that is not an
/// `nm…` id is dropped.
///
/// Birth dates arrive already filtered to day precision by the query:
/// Wikidata models "some time in 1962" as `1962-01-01` with a precision
/// of 9, which is indistinguishable from a real New Year's Day birthday
/// once the precision is thrown away - and a fake disagreement is how a
/// disambiguator splits one real person into two.
pub fn parse_person_facts(v: &serde_json::Value) -> HashMap<String, PersonFacts> {
    let mut out: HashMap<String, PersonFacts> = HashMap::new();
    for row in v["results"]["bindings"].as_array().into_iter().flatten() {
        let Some(qid) = row["p"]["value"]
            .as_str()
            .and_then(|u| u.rsplit('/').next())
        else {
            continue;
        };
        if !is_qid(qid) {
            continue;
        }
        let e = out.entry(qid.to_string()).or_default();
        if let Some(id) = row["imdb"]["value"]
            .as_str()
            .filter(|s| s.starts_with("nm"))
        {
            e.imdb = id.to_string();
        }
        let born = wikidata_iso(row["dob"]["value"].as_str().unwrap_or(""));
        if !born.is_empty() {
            e.born = born;
        }
    }
    out
}

/// Facts already asked about are not asked about again: a prolific actor
/// recurs across a whole filmography, exactly like their label does.
/// A Q-id that came back with nothing is cached as nothing, so an actor
/// Wikidata holds no dates for costs one lookup per process, not one per
/// film.
fn facts_cache() -> &'static std::sync::Mutex<HashMap<String, PersonFacts>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, PersonFacts>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Q-ids → `PersonFacts`, in one batched SPARQL call.
///
/// SPARQL rather than `wbgetentities`, because `props=claims` has no
/// property filter: measured 27 Jul 2026, one person's claims are ~190
/// KB (Tom Cruise carries 242 properties), so a film's cast would be
/// several MB per enrichment to read two fields. The same 20 people
/// through the query service is one ~2 KB response in ~0.4 s.
fn person_facts(qids: &[String]) -> HashMap<String, PersonFacts> {
    let mut out = HashMap::new();
    let mut want: Vec<String> = Vec::new();
    {
        let cache = facts_cache().lock_ok();
        for q in qids.iter().filter(|q| is_qid(q)) {
            match cache.get(q) {
                Some(f) => {
                    out.insert(q.clone(), f.clone());
                }
                None => want.push(q.clone()),
            }
        }
    }
    want.sort();
    want.dedup();
    // One call is all this is worth, exactly as `resolve_labels` decided:
    // a cast longer than this just goes unenriched, which costs a
    // disambiguator and never a credit.
    want.truncate(50);
    if want.is_empty() {
        return out;
    }
    let values = want
        .iter()
        .map(|q| format!("wd:{q}"))
        .collect::<Vec<_>>()
        .join(" ");
    let query = format!(
        "SELECT ?p ?imdb ?dob WHERE {{ \
           VALUES ?p {{ {values} }} \
           OPTIONAL {{ ?p wdt:P345 ?imdb }} \
           OPTIONAL {{ \
             ?p p:P569/psv:P569 ?dv . \
             ?dv wikibase:timePrecision ?prec . \
             ?dv wikibase:timeValue ?dob . \
             FILTER(?prec >= 11) }} \
         }}"
    );
    // The query service is a third Wikimedia service with its own
    // bucket, and every other network call in this file is paced.
    ratelimit::acquire(Provider::WikidataSparql);
    let Some(body) = crate::netfetch::shared_enrich_agent()
        .get(&format!(
            "https://query.wikidata.org/sparql?query={}",
            percent_encode(&query)
        ))
        .set("User-Agent", WIKI_UA)
        .set("Accept", "application/sparql-results+json")
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .ok()
        .and_then(|r| r.into_string().ok())
    else {
        // Not marked unreachable: the title's own metadata is complete
        // without this, and the next enrichment of any film this person
        // appears in fills the blanks (`person_upsert` only ever writes
        // into empty columns). The cost of a refusal is that credits
        // landing in this window merge on name alone, as they did
        // before this lane existed.
        return out;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return out;
    };
    let got = parse_person_facts(&v);
    let mut cache = facts_cache().lock_ok();
    for q in want {
        let f = got.get(&q).cloned().unwrap_or_default();
        cache.insert(q.clone(), f.clone());
        out.insert(q, f);
    }
    out
}

/// Stamp the IMDb id and birth date onto Wikidata-sourced credits.
///
/// Kept out of `parse_wikidata_credits` so that stays a pure parse of one
/// response; this is the one part of the credit that needs a second
/// service to answer.
fn fill_person_facts(credits: &mut [Credit]) {
    let qids: Vec<String> = credits
        .iter()
        .map(|c| c.wikidata_qid.clone())
        .filter(|q| !q.is_empty())
        .collect();
    if qids.is_empty() {
        return;
    }
    let facts = person_facts(&qids);
    for c in credits.iter_mut() {
        if let Some(f) = facts.get(&c.wikidata_qid) {
            c.imdb = f.imdb.clone();
            c.born = f.born.clone();
        }
    }
}
