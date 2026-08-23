//! Unit tests for [`super`] - the provider-payload parsers.
//!
//! Split out of wall.rs for the size gate (TODO 106): the module was
//! 1,175 of that file's 3,959 lines, which left no room for a feature
//! to add so much as a provider field - every one paid for the tests of
//! every other. wall.rs is 2,815 lines with this gone, back under the
//! 3,000 ceiling, so its baseline entry went in the same commit.
//! `use super::*;` reaches the private parsers exactly as it did inline.

use super::*;

/// The bare-title Wikipedia fallback is the last thing tried for a
/// movie with no year, and nothing used to check the article was
/// about a film - so an obfuscated stem parsed as "Ambulance" took
/// the road-vehicle article's photo as its poster and its lead
/// paragraph as its plot, then stamped the title checked so nothing
/// ever revisited it.
#[test]
fn only_a_screen_work_may_answer_an_unqualified_title() {
    let page =
        |desc: &str, extract: &str| serde_json::json!({"description": desc, "extract": extract});
    // Real films and TV, by description or by lead sentence.
    assert!(describes_a_screen_work(&page(
        "2022 American film",
        "Ambulance is a 2022 film."
    )));
    assert!(describes_a_screen_work(&page(
        "",
        "Sunlight is a 2019 Irish film directed by …"
    )));
    assert!(describes_a_screen_work(&page(
        "British television series",
        ""
    )));
    assert!(describes_a_screen_work(&page("2021 documentary", "")));
    assert!(describes_a_screen_work(&page(
        "anime television series",
        ""
    )));

    // The articles that were being adopted as posters.
    assert!(!describes_a_screen_work(&page(
        "medical vehicle",
        "An ambulance is a medically equipped vehicle which transports patients."
    )));
    assert!(!describes_a_screen_work(&page(
        "electromagnetic radiation",
        "Sunlight is a portion of the electromagnetic radiation given off by the Sun."
    )));
    assert!(!describes_a_screen_work(&page("", "")));

    // A mention of filming far down the article does not qualify it:
    // only the start of the lead is examined.
    let buried = format!("{} It was later filmed for television.", "x".repeat(400));
    assert!(!describes_a_screen_work(&page("river in Norway", &buried)));
}

#[test]
fn tvmaze_episode_parse() {
    let v: serde_json::Value = serde_json::from_str(
        r#"[
          {"season":1,"number":1,"name":"Good News About Hell","airdate":"2022-02-18"},
          {"season":1,"number":null,"name":"Special","airdate":"2022-03-01"},
          {"season":3,"number":5,"name":"","airdate":""}
        ]"#,
    )
    .unwrap();
    let eps = parse_tvmaze_episodes(&v);
    assert_eq!(eps.len(), 2); // the special (null number) is dropped
    assert_eq!(eps[0].season, 1);
    assert_eq!(eps[0].episode, 1);
    assert_eq!(eps[0].airdate, "2022-02-18");
    assert_eq!(eps[1].season, 3);
    assert_eq!(eps[1].airdate, "");
}

#[test]
fn provider_dates_normalise_to_iso() {
    // ISO, plus the datetime form iTunes sends.
    assert_eq!(iso_date("1999-03-30"), "1999-03-30");
    assert_eq!(iso_date("1999-03-30T08:00:00Z"), "1999-03-30");
    assert_eq!(iso_date("  1999-03-30  "), "1999-03-30");
    // OMDb's human form, zero-padded on the way in.
    assert_eq!(iso_date("30 Mar 1999"), "1999-03-30");
    assert_eq!(iso_date("5 Jan 2026"), "2026-01-05");
    // Anything we can't place is dropped, NOT stored: the column is
    // sorted as a plain string, so one stray format would misorder
    // every card around it.
    for junk in [
        "",
        "N/A",
        "1999",
        "1999-03",
        "March 1999",
        "30 Foo 1999",
        "32 Mar 1999",
        "30 Mar 99",
    ] {
        assert_eq!(iso_date(junk), "", "{junk:?}");
    }
}

#[test]
fn person_facts_parse() {
    // The live shape, probed 27 Jul 2026 against query.wikidata.org
    // with the query `person_facts` sends. Row 3 is the measured
    // hazard: Q3564164 is a FILM, and P345 is "IMDb ID" for any
    // entity, so it answers with a `tt…` title id.
    let v: serde_json::Value = serde_json::from_str(
        r#"{"results":{"bindings":[
             {"p":{"value":"http://www.wikidata.org/entity/Q37079"},
              "imdb":{"value":"nm0000129"},
              "dob":{"value":"1962-07-03T00:00:00Z"}},
             {"p":{"value":"http://www.wikidata.org/entity/Q129429"},
              "imdb":{"value":"nm0000046"}},
             {"p":{"value":"http://www.wikidata.org/entity/Q3564164"},
              "imdb":{"value":"tt0034354"}},
             {"p":{"value":"http://www.wikidata.org/entity/Q23844838"}},
             {"p":{"value":"http://www.wikidata.org/entity/P31"},
              "imdb":{"value":"nm9999999"}}]}}"#,
    )
    .unwrap();
    let f = parse_person_facts(&v);
    assert_eq!(
        f["Q37079"],
        PersonFacts {
            imdb: "nm0000129".into(),
            born: "1962-07-03".into()
        }
    );
    // No date is not a missing person - the row still carries an id.
    assert_eq!(f["Q129429"].imdb, "nm0000046");
    assert_eq!(f["Q129429"].born, "");
    // A title id must never reach `people.imdb`: two unrelated
    // people credited on the same film would then match on it.
    assert_eq!(f["Q3564164"], PersonFacts::default());
    // Asked about, nothing known: still an entry, so the cache does
    // not ask again on every film they appear in.
    assert!(f.contains_key("Q23844838"));
    // Only Q-ids. Nothing else belongs in a people column.
    assert!(!f.contains_key("P31"));
}

#[test]
fn art_names_are_flat_and_safe() {
    assert_eq!(
        art_name("m:the matrix:1999", false),
        "m_the_matrix_1999.jpg"
    );
    assert_eq!(art_name("t:severance", true), "t_severance.bd.jpg");
}

/// The thumbnails are art too, and forgetting them is invisible at the
/// point where a new poster is written.
///
/// `/art/thumb_<name>` is generated from the full poster on first
/// request and cached on disk under a name of its own, so a title whose
/// poster is replaced in place - a fixed identity, a hand-picked
/// upload - keeps serving the OLD picture on the grid until the
/// derivative goes. The card's `?v=<checked>` query is a browser-cache
/// buster; the route strips the query before it joins the filename.
#[test]
fn dropping_a_titles_art_takes_its_thumbnails() {
    let dir = std::env::temp_dir().join(format!("nzbfast-art-drop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let files = |key: &str| -> Vec<String> {
        let mut names: Vec<String> = [false, true]
            .iter()
            .flat_map(|bd| {
                let n = art_name(key, *bd);
                [format!("thumb_{n}"), n]
            })
            .collect();
        names.sort();
        names
    };
    let seed = || {
        for key in ["t:severance", "t:other"] {
            for n in files(key) {
                std::fs::write(dir.join(n), b"jpeg").unwrap();
            }
        }
    };
    let live = |key: &str| -> Vec<String> {
        files(key)
            .into_iter()
            .filter(|n| dir.join(n).is_file())
            .collect()
    };

    // Replacing a poster keeps the full-size files (they are about to be
    // overwritten) and drops only the stale derivatives.
    seed();
    drop_art_thumbs(&dir, "t:severance");
    assert_eq!(
        live("t:severance"),
        ["t_severance.bd.jpg", "t_severance.jpg"]
    );

    // "This title's art is wrong" drops all four.
    drop_art(&dir, "t:severance");
    assert!(live("t:severance").is_empty());
    // And never a neighbour's, whatever the key looked like.
    assert_eq!(live("t:other").len(), 4);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tvmaze_show_payload_yields_a_tvdb_id() {
    let v: serde_json::Value =
        serde_json::from_str(r#"{"id":431,"externals":{"tvrage":null,"thetvdb":407362}}"#).unwrap();
    assert_eq!(tvdb_of_show(&v, 431), Some(407362));
    // Asked, none published: a real answer, and what retires the row
    // from the backfill lane.
    let none: serde_json::Value =
        serde_json::from_str(r#"{"id":431,"externals":{"thetvdb":null}}"#).unwrap();
    assert_eq!(tvdb_of_show(&none, 431), Some(0));
    assert_eq!(tvdb_of_show(&serde_json::json!({"id":431}), 431), Some(0));
    // A merged id redirects to the SURVIVING show, whose TVDB id would
    // point Sonarr at a different series. Not an answer about ours.
    assert_eq!(tvdb_of_show(&v, 9), None);
}

#[test]
fn tvmaze_response_parses() {
    let v: serde_json::Value = serde_json::from_str(
        r#"{"id":431,"name":"Severance","genres":["Drama","Science-Fiction"],
            "rating":{"average":8.3},
            "image":{"medium":"https://static.tvmaze.com/m.jpg",
                     "original":"https://static.tvmaze.com/o.jpg"},
            "summary":"<p>Mark leads a team.</p>"}"#,
    )
    .unwrap();
    let m = parse_tvmaze(&v).unwrap();
    assert_eq!(m.tmdb_id, 431);
    assert_eq!(m.overview, "Mark leads a team.");
    assert_eq!(m.rating, 8.3);
    assert_eq!(m.genres, "Drama, Science-Fiction");
    assert_eq!(m.poster_url, "https://static.tvmaze.com/m.jpg");
    assert_eq!(m.backdrop_url, "https://static.tvmaze.com/o.jpg");
}

#[test]
fn candidate_searches_parse() {
    let tv: serde_json::Value = serde_json::from_str(
        r#"[{"score":0.9,"show":{"id":431,"name":"Severance","premiered":"2022-02-18",
             "genres":["Drama"],"rating":{"average":8.3},
             "image":{"medium":"https://s.tvmaze.com/m.jpg","original":"https://s.tvmaze.com/o.jpg"},
             "summary":"<p>Mark leads.</p>"}},
            {"score":0.5,"show":{"id":99,"name":"Severance (1998)","premiered":null,
             "genres":[],"rating":{},"image":null,"summary":null}}]"#,
    )
    .unwrap();
    let c = parse_tvmaze_search(&tv);
    assert_eq!(c.len(), 2);
    assert_eq!((c[0].id, c[0].year, c[0].kind.as_str()), (431, 2022, "tv"));
    assert_eq!(c[0].overview, "Mark leads.");
    assert_eq!(c[0].provider, "tvmaze");
    assert_eq!(c[1].year, 0);

    let tm: serde_json::Value = serde_json::from_str(
        r#"{"results":[{"id":603,"title":"The Matrix","release_date":"1999-03-30",
             "overview":"Neo.","vote_average":8.2,"genre_ids":[878,28],
             "poster_path":"/p.jpg","backdrop_path":"/b.jpg"}]}"#,
    )
    .unwrap();
    let c = parse_tmdb_search(&tm, &Kind::Movie);
    assert_eq!(c.len(), 1);
    assert_eq!(
        (c[0].id, c[0].year, c[0].kind.as_str()),
        (603, 1999, "movie")
    );
    assert_eq!(c[0].genres, "Sci-Fi, Action");
    assert_eq!(c[0].poster_url, "https://image.tmdb.org/t/p/w342/p.jpg");
    assert_eq!(c[0].provider, "tmdb");
}

#[test]
fn tvmaze_cast_and_externals_parse() {
    // The `_embedded` shape of the ONE call that replaced the old
    // lookup + /cast pair. Fixture fields are the live ones (probed
    // 26 Jul 2026): person id, headshot, character name, voice flag,
    // and crew with a free-text `type`.
    let emb: serde_json::Value = serde_json::from_str(
        r#"{"cast":[
              {"person":{"id":29657,"name":"Adam Scott","birthday":"1973-04-03",
                         "image":{"medium":"https://static.tvmaze.com/a.jpg"}},
               "character":{"name":"Mark Scout"},"voice":false},
              {"person":{"id":1,"name":"Britt Lower","birthday":null},
               "character":{"name":"Helly R"},"voice":true},
              {"person":{"id":2,"name":"Zach Cherry"},"character":{"name":"Dylan G"}},
              {"person":{"name":"   "},"character":{"name":"Nobody"}}],
            "crew":[
              {"type":"Unit Production Manager","person":{"id":90,"name":"U P M"}},
              {"type":"Creator","person":{"id":91,"name":"Dan Erickson",
                                          "birthday":"1980-01-02"}},
              {"type":"","person":{"id":92,"name":"No Role"}}]}"#,
    )
    .unwrap();
    let cr = parse_tvmaze_credits(&emb);
    // The nameless entry is dropped, not credited as "".
    let cast: Vec<&Credit> = cr.iter().filter(|c| c.role == "actor").collect();
    assert_eq!(cast.len(), 3);
    assert_eq!(cast[0].name, "Adam Scott");
    assert_eq!(cast[0].tvmaze_id, 29657);
    assert_eq!(cast[0].character, "Mark Scout");
    assert_eq!(cast[0].photo, "https://static.tvmaze.com/a.jpg");
    // The birthday is the only thing TVmaze publishes that can tell
    // this person apart from a same-named one seen by Wikidata, so
    // it has to survive the parse. `null` and absent both mean
    // "unknown", which must read as empty rather than as a date.
    assert_eq!(cast[0].born, "1973-04-03");
    assert_eq!((cast[1].born.as_str(), cast[2].born.as_str()), ("", ""));
    // Billing order is position, 1-based so 0 still means "unranked".
    assert_eq!((cast[0].ord, cast[2].ord), (1, 3));
    // A voice role stays visible without a schema column for it.
    assert_eq!(cast[1].character, "Helly R (voice)");
    // The credit line is the same string the cards always showed.
    assert_eq!(credit_line(&cr, 8), "Adam Scott, Britt Lower, Zach Cherry");
    // Crew: the role-less entry is dropped and the creator outranks
    // the production manager, so a cap keeps the useful one.
    let crew: Vec<&Credit> = cr.iter().filter(|c| c.role != "actor").collect();
    assert_eq!(crew.len(), 2);
    assert_eq!(
        (crew[0].name.as_str(), crew[0].role.as_str()),
        ("Dan Erickson", "creator")
    );
    assert_eq!(crew[0].born, "1980-01-02", "crew are people too");
    let show: serde_json::Value = serde_json::from_str(
        r#"{"id":431,"externals":{"imdb":"tt11280740"},"summary":"<p>x</p>"}"#,
    )
    .unwrap();
    assert_eq!(parse_tvmaze(&show).unwrap().imdb, "tt11280740");
}

#[test]
fn wikidata_credits_read_the_qualifiers_we_used_to_drop() {
    // Shape taken from the live Matrix entity (Q83495): P453 is the
    // character-role qualifier, P1545 the billing ordinal, and only
    // SOME cast claims carry either.
    let ent: serde_json::Value = serde_json::from_str(
        r#"{"claims":{
             "P161":[
               {"mainsnak":{"datavalue":{"value":{"id":"Q43416"}}},
                "qualifiers":{"P453":[{"datavalue":{"value":{"id":"Q1750842"}}}],
                              "P1545":[{"datavalue":{"value":"2"}}]}},
               {"mainsnak":{"datavalue":{"value":{"id":"Q106508"}}},
                "qualifiers":{"P1545":[{"datavalue":{"value":"1"}}]}},
               {"mainsnak":{"datavalue":{"value":{"id":"Q193048"}}}},
               {"mainsnak":{"datavalue":{"value":{"id":"Q_unlabelled"}}}}],
             "P57":[{"mainsnak":{"datavalue":{"value":{"id":"Q9545711"}}}}],
             "P58":[{"mainsnak":{"datavalue":{"value":{"id":"Q195719"}}}}],
             "P86":[{"mainsnak":{"datavalue":{"value":{"id":"Q207859"}}}}]}}"#,
    )
    .unwrap();
    let labels: HashMap<String, String> = [
        ("Q43416", "Keanu Reeves"),
        ("Q106508", "Laurence Fishburne"),
        ("Q193048", "Carrie-Anne Moss"),
        ("Q1750842", "Neo"),
        ("Q9545711", "Lana Wachowski"),
        ("Q195719", "Lilly Wachowski"),
        ("Q207859", "Don Davis"),
    ]
    .iter()
    .map(|(q, n)| (q.to_string(), n.to_string()))
    .collect();
    let cr = parse_wikidata_credits(&ent, &labels);
    // P1545 IS the billing order, so the ranked pair leads and the
    // unranked one falls in behind rather than jumping the queue.
    let cast: Vec<&str> = cr
        .iter()
        .filter(|c| c.role == "actor")
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(
        cast,
        ["Laurence Fishburne", "Keanu Reeves", "Carrie-Anne Moss"]
    );
    // The character qualifier - 9 of 19 on the real entity carry one.
    let neo = cr.iter().find(|c| c.name == "Keanu Reeves").unwrap();
    assert_eq!(neo.character, "Neo");
    assert_eq!(neo.wikidata_qid, "Q43416");
    // A Q-id with no label is dropped, not shown raw.
    assert!(!cr.iter().any(|c| c.name.starts_with('Q')));
    // Crew from claims that were already in the response.
    let role = |n: &str| cr.iter().find(|c| c.name == n).map(|c| c.role.as_str());
    assert_eq!(role("Lana Wachowski"), Some("director"));
    assert_eq!(role("Lilly Wachowski"), Some("writer"));
    assert_eq!(role("Don Davis"), Some("composer"));
}

#[test]
fn episode_parse_keeps_the_synopsis() {
    let v: serde_json::Value = serde_json::from_str(
        r#"[{"season":1,"number":1,"name":"Good News About Hell",
             "airdate":"2022-02-18","runtime":57,"rating":{"average":8.1},
             "image":{"medium":"https://static.tvmaze.com/e.jpg"},
             "summary":"<p>Mark leads a team of <b>four</b>.</p>"}]"#,
    )
    .unwrap();
    let e = &parse_tvmaze_episodes(&v)[0];
    // Provider HTML is stripped here so nothing downstream has to
    // decide whether to trust it as markup.
    assert_eq!(e.summary, "Mark leads a team of four.");
    assert_eq!(e.image, "https://static.tvmaze.com/e.jpg");
    assert_eq!((e.runtime, e.rating), (57, 8.1));
    // Episode lists are cached as JSON in `kv`. A blob written before
    // these fields existed must still deserialize, or the calendar
    // empties itself on upgrade.
    let old: EpInfo = serde_json::from_str(r#"{"season":2,"episode":3,"name":"x"}"#).unwrap();
    assert_eq!((old.season, old.episode, old.summary.as_str()), (2, 3, ""));
}

#[test]
fn tvmaze_castcredits_parse() {
    let v: serde_json::Value = serde_json::from_str(
        r#"[{"_links":{"character":{"name":"Emily"}},
             "_embedded":{"show":{"name":"The Odd Couple","premiered":"2015-02-19",
                                  "type":"Scripted"}}},
            {"_links":{},"_embedded":{"show":{"name":"Unaired","premiered":null}}},
            {"_embedded":{"show":{"name":""}}}]"#,
    )
    .unwrap();
    let f = parse_tvmaze_castcredits(&v);
    assert_eq!(f.len(), 2, "the nameless show is dropped");
    assert_eq!(
        (f[0].title.as_str(), f[0].year, f[0].kind.as_str()),
        ("The Odd Couple", 2015, "tv")
    );
    assert_eq!(f[0].character, "Emily");
    assert_eq!(f[1].date, "", "a null premiere is not a date");
}

#[test]
fn sparql_filmography_filters_tv_and_sorts_undated_last() {
    let ent = |q: &str, label: &str, date: Option<&str>, class: &str| {
        let mut o = serde_json::json!({
            "film": {"value": format!("http://www.wikidata.org/entity/{q}")},
            "filmLabel": {"value": label},
            "class": {"value": format!("http://www.wikidata.org/entity/{class}")},
        });
        if let Some(d) = date {
            o["date"] = serde_json::json!({"value": d});
        }
        o
    };
    let v = serde_json::json!({"results": {"bindings": [
        // Two rows for one film: a second P31 and a later territory
        // release. Both must collapse to one entry at the EARLIEST date.
        ent("Q83495", "The Matrix", Some("+1999-03-31T00:00:00Z"), "Q11424"),
        ent("Q83495", "The Matrix", Some("+1999-06-11T00:00:00Z"), "Q24869"),
        // The measured noise: P161 is not film-specific, so a real
        // Keanu Reeves query brings back television.
        ent("Q1204", "The Fresh Prince of Bel-Air", Some("+1990-09-10T00:00:00Z"),
            "Q5398426"),
        // Undated, and a film - kept, but it must not head the list.
        ent("Q999", "Untitled Project", None, "Q11424"),
        // An unresolved label comes back as the bare Q-id. This is
        // what a `mul`-only item looked like before the query asked
        // for "en,mul" - see `resolve_labels`. It has to be dropped
        // rather than listed as "Q777", and the LIVE test is what
        // proves the query no longer produces these.
        ent("Q777", "Q777", Some("+2001-01-01T00:00:00Z"), "Q11424"),
    ]}});
    let f = parse_sparql_filmography(&v);
    let titles: Vec<&str> = f.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, ["The Matrix", "Untitled Project"]);
    assert_eq!(f[0].date, "1999-03-31", "kept the later territory release");
    assert_eq!(f[0].year, 1999);
    assert_eq!(f[1].date, "");
}

#[test]
fn person_art_names_are_evictable_and_posters_are_not() {
    assert_eq!(person_art_name(42), "p42.jpg");
    assert!(is_person_art_name("p42.jpg"));
    assert!(is_person_art_name("thumb_p42.jpg"));
    // Posters and backdrops share the directory and must NEVER be
    // evicted - nothing re-fetches them on demand.
    for n in [
        "m_the_matrix_1999.jpg",
        "t_severance.bd.jpg",
        "thumb_m_the_matrix_1999.jpg",
        "p.jpg",
        "pilot.jpg",
        "p42.png",
    ] {
        assert!(!is_person_art_name(n), "{n} must not be evictable");
    }
}

/// Live smoke test for everything the person page needs, against the
/// real TVmaze and Wikidata services:
///   cargo test -p nzbfast --bin nzbfast -- --ignored cast_and_filmography
///
/// Same reasoning as `keyless_movie_chain_answers_live`, and the same
/// failure it exists to catch: the movie provider this replaced died
/// SILENTLY - HTTP 200 with an empty body - so every offline test
/// above kept passing while the wall quietly stopped getting data.
/// Parsing fixtures cannot tell you an endpoint stopped answering.
#[test]
#[ignore]
fn cast_and_filmography_answer_live() {
    // 1. The embed call: one request, show + cast + crew.
    let m = tvmaze_lookup_full("Severance").expect("TVmaze found no show for Severance");
    println!(
        "Severance: id={} cast+crew={} actors={:?}",
        m.tmdb_id,
        m.credits.len(),
        m.actors
    );
    assert!(m.tmdb_id > 0, "no show id");
    let cast: Vec<&Credit> = m.credits.iter().filter(|c| c.role == "actor").collect();
    assert!(
        cast.len() >= 3,
        "embed returned no cast ({} credits)",
        m.credits.len()
    );
    assert!(
        cast.iter().any(|c| c.tvmaze_id > 0),
        "no person ids - filmography is dead"
    );
    assert!(
        cast.iter().any(|c| !c.character.is_empty()),
        "no character names"
    );
    assert!(
        m.credits.iter().any(|c| c.role != "actor"),
        "crew embed returned nothing"
    );
    assert!(!m.actors.is_empty(), "no credit line");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 2. Episode summaries - 19 of 19 on the probe that found this.
    let eps = tvmaze_episodes(m.tmdb_id);
    assert!(!eps.is_empty(), "no episodes");
    let with_summary = eps.iter().filter(|e| !e.summary.is_empty()).count();
    println!("  {} episodes, {with_summary} with a synopsis", eps.len());
    assert!(with_summary > 0, "every episode summary came back empty");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 3. The TV filmography endpoint, on a person id from step 1.
    let pid = cast.iter().find(|c| c.tvmaze_id > 0).unwrap().tvmaze_id;
    let tv = tvmaze_filmography(pid)
        .unwrap_or_else(|| panic!("castcredits did not answer for person {pid}"));
    println!("  person {pid}: {} TV credits", tv.len());
    assert!(
        !tv.is_empty(),
        "castcredits returned nothing for person {pid}"
    );

    // 4. The film half: Wikidata SPARQL. Q43416 is Keanu Reeves -
    // the query whose noise (TV mixed into film results) the parser
    // filters, so a live run also proves the filter still fires.
    let films = wikidata_filmography("Q43416").expect("the SPARQL endpoint did not answer at all");
    println!("  Q43416: {} film credits", films.len());
    assert!(
        films.len() >= 20,
        "SPARQL returned only {} films",
        films.len()
    );
    assert!(
        films.iter().any(|f| f.title == "The Matrix"),
        "the best-known credit is missing - the P31 filter is too strict"
    );
    assert!(
        !films.iter().any(|f| f.title.contains("Fresh Prince")),
        "television leaked through the film filter"
    );

    // A `mul`-only item: Wikidata increasingly stores a film's title
    // ONCE under the multilingual code instead of per-language, and
    // Top Gun: Maverick (Q31202708) has no `en` label at all. Asking
    // for English alone silently dropped it and six others from Tom
    // Cruise's 60 credits - no error, no warning, just a shorter
    // list. Only a live call can catch that class of loss, which is
    // exactly why this test exists.
    let cruise =
        wikidata_filmography("Q37079").expect("the SPARQL endpoint did not answer for Q37079");
    println!("  Q37079: {} film credits", cruise.len());
    assert!(
        cruise.iter().any(|f| f.title.contains("Maverick")),
        "a mul-only title vanished - the label service is being asked for 'en' only"
    );
    assert!(
        !cruise.iter().any(|f| f.title.starts_with('Q')),
        "raw Q-ids leaked as titles"
    );
    // Undated rows exist and must be last, not first.
    if let Some(first_undated) = films.iter().position(|f| f.date.is_empty()) {
        assert!(
            films[first_undated..].iter().all(|f| f.date.is_empty()),
            "undated credits are interleaved rather than sorted last"
        );
    }
}

#[test]
fn omdb_detail_and_search_parse() {
    let v: serde_json::Value = serde_json::from_str(
        r#"{"Title":"The Matrix","Year":"1999","Genre":"Action, Sci-Fi",
            "Actors":"Keanu Reeves, Laurence Fishburne","Plot":"Neo.",
            "Poster":"https://m.media-amazon.com/x.jpg","imdbRating":"8.7",
            "imdbVotes":"2,100,000","imdbID":"tt0133093","Type":"movie",
            "Response":"True"}"#,
    )
    .unwrap();
    let m = parse_omdb(&v).unwrap();
    assert_eq!(m.tmdb_id, 133093);
    assert_eq!(m.imdb, "tt0133093");
    assert_eq!(m.overview, "Neo.");
    assert_eq!(m.rating, 8.7);
    assert_eq!(m.genres, "Action, Sci-Fi");
    assert_eq!(m.actors, "Keanu Reeves, Laurence Fishburne");
    assert_eq!(m.poster_url, "https://m.media-amazon.com/x.jpg");

    // "N/A" padding reads as absent; a miss parses as None.
    let na: serde_json::Value = serde_json::from_str(
        r#"{"Title":"Obscure","Plot":"N/A","Poster":"N/A","imdbRating":"N/A",
            "Genre":"N/A","Actors":"N/A","imdbID":"tt0000123","Response":"True"}"#,
    )
    .unwrap();
    let m = parse_omdb(&na).unwrap();
    assert!(m.overview.is_empty() && m.poster_url.is_empty() && m.actors.is_empty());
    assert_eq!(m.rating, 0.0);
    let miss: serde_json::Value =
        serde_json::from_str(r#"{"Response":"False","Error":"Movie not found!"}"#).unwrap();
    assert!(parse_omdb(&miss).is_none());

    let s: serde_json::Value = serde_json::from_str(
        r#"{"Search":[
            {"Title":"The Matrix","Year":"1999","imdbID":"tt0133093","Type":"movie",
             "Poster":"https://m.media-amazon.com/x.jpg"},
            {"Title":"The Matrix Revisited","Year":"2001–2003","imdbID":"tt0295432",
             "Type":"movie","Poster":"N/A"}],
            "totalResults":"2","Response":"True"}"#,
    )
    .unwrap();
    let c = parse_omdb_search(&s);
    assert_eq!(c.len(), 2);
    assert_eq!(
        (c[0].id, c[0].year, c[0].imdb.as_str()),
        (133093, 1999, "tt0133093")
    );
    assert_eq!(c[0].provider, "omdb");
    assert_eq!(c[1].year, 2001, "year ranges take the first year");
    assert!(c[1].poster_url.is_empty());
}

#[test]
fn omdb_signup_form_scrape() {
    // Shape of the LIVE form (fetched 19 Jul 2026): Patreon radio
    // checked by default, the free radio is an AutoPostBack.
    let step1 = r#"<html><body><form method="post" action="./apikey.aspx">
      <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="VS123" />
      <input type="hidden" name="__EVENTVALIDATION" value="EV456" />
      <input id="patreonAcct" type="radio" name="at" value="patreonAcct" checked="checked" />
      <input id="freeAcct" type="radio" name="at" value="freeAcct" onclick="javascript:setTimeout('__doPostBack(\'freeAcct\',\'\')', 0)" />
      <input name="Email" type="text" id="Email" class="form-control" />
      <input type="submit" name="Submit" value="Submit" id="Submit" />
    </form></body></html>"#;
    let (name, target, value, checked) = omdb_free_radio(step1).unwrap();
    assert_eq!(
        (name.as_str(), target.as_str(), value.as_str()),
        ("at", "freeAcct", "freeAcct")
    );
    assert!(!checked, "live form defaults to the Patreon tier");
    // The radio-select postback carries state + the free radio but
    // must NOT press Submit.
    let f = omdb_signup_fields(step1, "user@example.com", false).unwrap();
    let get = |f: &[(String, String)], k: &str| {
        f.iter()
            .find(|(n, _)| n.contains(k))
            .map(|(_, v)| v.to_string())
    };
    assert_eq!(get(&f, "__VIEWSTATE").as_deref(), Some("VS123"));
    assert_eq!(get(&f, "at").as_deref(), Some("freeAcct"));
    assert_eq!(get(&f, "Email").as_deref(), Some("user@example.com"));
    assert!(get(&f, "Submit").is_none());

    // Step 2: the re-rendered free-tier form (name/use fields).
    let step2 = r#"<form>
      <input type="hidden" name="__VIEWSTATE" value="VS999" />
      <input id="freeAcct" type="radio" name="at" value="freeAcct" checked="checked" />
      <input name="Email" type="text" />
      <input name="FirstName" type="text" />
      <input name="LastName" type="text" />
      <textarea name="Use"></textarea>
      <input type="submit" name="Submit" value="Submit" />
      <input type="submit" name="Other" value="Other" />
    </form>"#;
    assert!(
        omdb_free_radio(step2).unwrap().3,
        "free tier selected after postback"
    );
    let f = omdb_signup_fields(step2, "user@example.com", true).unwrap();
    assert_eq!(get(&f, "__VIEWSTATE").as_deref(), Some("VS999"));
    assert_eq!(get(&f, "Email").as_deref(), Some("user@example.com"));
    assert_eq!(get(&f, "FirstName").as_deref(), Some("nzbfast"));
    assert_eq!(get(&f, "LastName").as_deref(), Some("user"));
    assert!(get(&f, "Use").unwrap().contains("Personal"));
    assert_eq!(get(&f, "Submit").as_deref(), Some("Submit"));
    assert!(get(&f, "Other").is_none(), "only the first submit posts");
    // A page without an email box is not the form we expect.
    assert!(omdb_signup_fields("<html><input name='q'></html>", "e@x", true).is_none());
    // Encoding round-trip stays urlencoded-safe.
    assert!(form_encode(&f).contains("__VIEWSTATE=VS999"));
    assert!(form_encode(&f).contains("user%40example.com"));
}

#[test]
fn wikidata_candidate_picking_honors_year_and_p345() {
    let search: serde_json::Value =
        serde_json::from_str(r#"{"search":[{"id":"Q1"},{"id":"Q2"},{"id":"Q3"}]}"#).unwrap();
    let entities: serde_json::Value = serde_json::from_str(
        r#"{"entities":{
          "Q1":{"claims":{}},
          "Q2":{"claims":{"P345":[{"mainsnak":{"datavalue":{"value":"tt0000002"}}}],
                "P577":[{"mainsnak":{"datavalue":{"value":{"time":"+2021-12-22T00:00:00Z"}}}}]}},
          "Q3":{"claims":{"P345":[{"mainsnak":{"datavalue":{"value":"tt0133093"}}}],
                "P577":[{"mainsnak":{"datavalue":{"value":{"time":"+1999-03-31T00:00:00Z"}}}}]}}
        }}"#,
    )
    .unwrap();
    // Year steers past the wrong-year candidate (Q2) to Q3.
    assert_eq!(
        pick_wikidata_imdb(&search, &entities, 1999).as_deref(),
        Some("tt0133093")
    );
    // No year → first candidate WITH a P345 wins (Q1 has none).
    assert_eq!(
        pick_wikidata_imdb(&search, &entities, 0).as_deref(),
        Some("tt0000002")
    );
}

#[test]
fn anilist_parses_and_rescales_score() {
    let v: serde_json::Value = serde_json::from_str(
        r#"{"data":{"Media":{"id":21,"description":"Pirates<br>adventure",
            "averageScore":86,"genres":["Action","Adventure"],
            "coverImage":{"large":"https://a/l.jpg","extraLarge":"https://a/xl.jpg"},
            "bannerImage":"https://a/b.jpg"}}}"#,
    )
    .unwrap();
    let m = parse_anilist(&v).unwrap();
    assert_eq!(m.tmdb_id, 21);
    assert_eq!(m.rating, 8.6);
    assert_eq!(m.overview, "Piratesadventure");
    assert_eq!(m.poster_url, "https://a/xl.jpg");
    assert_eq!(m.genres, "Action, Adventure");
}

#[test]
fn imdb_ratings_tsv_parses_and_filters() {
    let tsv = "tconst\taverageRating\tnumVotes\n\
               tt0133093\t8.7\t2100000\n\
               tt0000001\t5.7\t42\n\
               ttbroken\tx\ty\n\
               tt0111161\t9.3\t3000000\n";
    let rows = parse_imdb_ratings(tsv, 100);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], ("tt0133093".into(), 8.7, 2_100_000));
    assert_eq!(rows[1], ("tt0111161".into(), 9.3, 3_000_000));
}

// --- Wikidata: the keyless movie provider (iTunes' replacement) ---

/// wbsearchentities ranks these in order; Q3 is not a film, Q1 is
/// the wrong year, Q2 is the film we want, Q4 is a film with no
/// IMDb id.
fn wikidata_fixture() -> (serde_json::Value, serde_json::Value) {
    let search = serde_json::json!({
        "search": [{"id":"Q3"},{"id":"Q1"},{"id":"Q2"},{"id":"Q4"}]
    });
    let film = |q: &str| serde_json::json!([{"mainsnak":{"datavalue":{"value":{"id":q}}}}]);
    let time = |t: &str| serde_json::json!([{"mainsnak":{"datavalue":{"value":{"time":t}}}}]);
    let s = |v: &str| serde_json::json!([{"mainsnak":{"datavalue":{"value":v}}}]);
    let entities = serde_json::json!({"entities":{
        // A video game, not a film - never eligible however well it ranks.
        "Q3": {"claims":{"P31": film("Q7889"), "P345": s("tt9999999")}},
        // Right title, wrong year.
        "Q1": {"claims":{"P31": film("Q11424"), "P577": time("+2021-12-22T00:00:00Z"),
                         "P345": s("tt10838180")}},
        // The match: film, right year, has an IMDb id.
        "Q2": {"labels":{"en":{"value":"The Matrix"}},
               "descriptions":{"en":{"value":"1999 film by the Wachowskis"}},
               "claims":{
                 "P31": film("Q11424"),
                 "P345": s("tt0133093"),
                 "P18": s("The Matrix poster.jpg"),
                 // Deliberately out of order: the earliest wins.
                 "P577": serde_json::json!([
                    {"mainsnak":{"datavalue":{"value":{"time":"+1999-05-07T00:00:00Z"}}}},
                    {"mainsnak":{"datavalue":{"value":{"time":"+1999-03-31T00:00:00Z"}}}}]),
                 "P136": serde_json::json!([
                    {"mainsnak":{"datavalue":{"value":{"id":"Q471839"}}}},
                    {"mainsnak":{"datavalue":{"value":{"id":"Q188473"}}}}]),
                 "P161": serde_json::json!([
                    {"mainsnak":{"datavalue":{"value":{"id":"Q40096"}}}},
                    {"mainsnak":{"datavalue":{"value":{"id":"Q102289"}}}}])}},
        // A film with art and a date but no IMDb id.
        "Q4": {"labels":{"en":{"value":"The Matrix (short)"}},
               "claims":{"P31": film("Q24862"), "P577": time("+1999-08-01T00:00:00Z"),
                         "P18": s("Short.jpg")}},
    }});
    (search, entities)
}

#[test]
fn wikidata_picks_the_right_film_and_builds_the_card() {
    let (search, entities) = wikidata_fixture();
    // Non-films are skipped even though Q3 ranks first, and the
    // wrong-year Q1 is filtered out by the year.
    let picked = pick_wikidata_film(&search, &entities, 1999).unwrap();
    assert_eq!(picked, "Q2");

    // Q188473 deliberately absent - an unresolved id must be
    // dropped, never rendered as a raw "Q188473" genre.
    let labels: HashMap<String, String> = [
        ("Q471839", "Science Fiction"),
        ("Q40096", "Keanu Reeves"),
        ("Q102289", "Laurence Fishburne"),
    ]
    .iter()
    .map(|(q, n)| (q.to_string(), n.to_string()))
    .collect();
    let m = parse_wikidata_film(&entities["entities"]["Q2"], &labels);
    assert_eq!(m.imdb, "tt0133093");
    assert_eq!(m.air_date, "1999-03-31", "earliest P577 wins");
    assert_eq!(m.genres, "Science Fiction");
    assert_eq!(m.actors, "Keanu Reeves, Laurence Fishburne");
    // P18 is never a poster - the caller pairs this with Wikipedia's
    // infobox image instead.
    assert_eq!(m.poster_url, "");
}

#[test]
fn wikidata_falls_back_to_a_film_without_an_imdb_id() {
    let (search, entities) = wikidata_fixture();
    // With no IMDb id anywhere, the second pass still returns a
    // film: art, a date, genres and a cast beat the bare stem the
    // wall would show otherwise.
    let mut e = entities.clone();
    e["entities"]["Q2"]["claims"]["P345"] = serde_json::Value::Null;
    assert_eq!(pick_wikidata_film(&search, &e, 1999).unwrap(), "Q2");
    // And the pass reaches past the top-ranked entity when that one
    // is not a film at all - Q4 is the only 1999 film left here.
    let s = serde_json::json!({"search":[{"id":"Q3"},{"id":"Q1"},{"id":"Q4"}]});
    assert_eq!(pick_wikidata_film(&s, &e, 1999).unwrap(), "Q4");
}

#[test]
fn wikidata_year_mismatch_finds_nothing_rather_than_the_wrong_film() {
    let (search, entities) = wikidata_fixture();
    assert_eq!(pick_wikidata_film(&search, &entities, 1975), None);
}

#[test]
fn wikidata_candidates_filter_by_year_and_carry_the_description() {
    let (search, entities) = wikidata_fixture();
    let c = parse_wikidata_candidates(&search, &entities, 1999);
    // Q3 is not a film; Q1 is the wrong year; Q2 and Q4 survive.
    assert_eq!(c.len(), 2);
    assert_eq!((c[0].title.as_str(), c[0].year), ("The Matrix", 1999));
    assert_eq!(c[0].overview, "1999 film by the Wachowskis");
    assert_eq!(c[0].provider, "wikidata");
    assert_eq!(c[0].imdb, "tt0133093");
    assert_eq!(c[1].title, "The Matrix (short)");
}

/// Live smoke test for the whole keyless movie chain, against the
/// real Wikidata and Wikipedia APIs. `#[ignore]`d so no ordinary
/// test run touches the network:
///   cargo test -p nzbfast keyless_movie_chain -- --ignored --nocapture
///
/// This exists because the provider it replaced died silently: Apple
/// kept answering HTTP 200 with an empty result set, so every test
/// still passed while the wall quietly stopped getting posters. Only
/// a live check catches that class of failure.
#[test]
#[ignore]
fn keyless_movie_chain_answers_live() {
    for (title, year) in [
        ("The Matrix", 1999u32),
        ("Top Gun Maverick", 2022),
        ("Dune Part Two", 2024),
    ] {
        let m = wikidata_movie(title, year)
            .unwrap_or_else(|| panic!("wikidata found no film for {title} ({year})"));
        let w = wikipedia_page(title, year)
            .unwrap_or_else(|| panic!("wikipedia has no page for {title} ({year})"));
        println!(
            "{title}: imdb={} date={} genres={:?} cast={:?} poster={}",
            m.imdb, m.air_date, m.genres, m.actors, w.image
        );
        assert!(m.imdb.starts_with("tt"), "{title}: no imdb id");
        assert!(!m.air_date.is_empty(), "{title}: no release date");
        assert!(!m.actors.is_empty(), "{title}: no cast");
        assert!(
            w.image.contains("upload.wikimedia.org"),
            "{title}: no poster"
        );
        // The person-facts leg fails the same silent way: the query
        // service can answer 200 with an empty result set, and
        // without these two fields every same-named credit merges
        // on the name alone again (see `person_upsert`). Asserted as
        // "most of the cast", not all, because Wikidata genuinely
        // holds no birthday for some people.
        let with_imdb = m
            .credits
            .iter()
            .filter(|c| c.imdb.starts_with("nm"))
            .count();
        let with_born = m.credits.iter().filter(|c| !c.born.is_empty()).count();
        println!(
            "  facts: {with_imdb} imdb / {with_born} born of {}",
            m.credits.len()
        );
        assert!(
            with_imdb * 2 > m.credits.len(),
            "{title}: person IMDb ids did not land ({with_imdb}/{})",
            m.credits.len()
        );
        assert!(
            with_born * 2 > m.credits.len(),
            "{title}: person birth dates did not land ({with_born}/{})",
            m.credits.len()
        );
        // Stay well inside Wikimedia's anonymous rate limit.
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

/// Live pacing benchmark for the movie and TV lanes, in seconds per
/// title against the real providers. `#[ignore]`d - it is a
/// measurement, not an assertion:
///   cargo test -p nzbfast enrichment_pacing -- --ignored --nocapture
///
/// The title list deliberately mixes hits with misses. A miss is the
/// expensive shape (Wikidata answers nothing, then all three
/// Wikipedia title variants are tried), so a benchmark of hits only
/// would flatter any pacing change.
#[test]
#[ignore]
fn enrichment_pacing_benchmark() {
    const MOVIES: [(&str, u32); 10] = [
        ("The Matrix", 1999),
        ("Top Gun Maverick", 2022),
        ("Dune Part Two", 2024),
        ("Inception", 2010),
        ("Jaws", 1975),
        ("Arrival", 2016),
        ("Blade Runner 2049", 2017),
        ("Sicario", 2015),
        ("Qwertzuiop Nonesuch", 2021),
        ("Zzyzx Roadhouse Nowhere", 2019),
    ];
    const SHOWS: [&str; 10] = [
        "Breaking Bad",
        "Severance",
        "Slow Horses",
        "Foundation",
        "Andor",
        "Silo",
        "Shogun",
        "The Bear",
        "Qwertzuiop Nonesuch Show",
        "Zzyzx Roadhouse Nowhere Show",
    ];

    // Mirrors wall_enrich_lane's keyless movie chain: Wikidata, then
    // Wikipedia for whatever it left empty.
    let t0 = std::time::Instant::now();
    let mut movie_hits = 0;
    for (title, year) in MOVIES {
        let paced_from = std::time::Instant::now();
        let m = wikidata_movie(title, year);
        let wd = paced_from.elapsed();
        let need_wiki = match &m {
            Some(meta) => meta.overview.is_empty() || meta.poster_url.is_empty(),
            None => true,
        };
        let w = if need_wiki {
            wikipedia_page(title, year)
        } else {
            None
        };
        println!(
            "  {title}: wikidata {:.2}s, wikipedia {:.2}s",
            wd.as_secs_f64(),
            (paced_from.elapsed() - wd).as_secs_f64()
        );
        if m.is_some() || w.is_some() {
            movie_hits += 1;
        }
    }
    let movie = t0.elapsed();

    let t1 = std::time::Instant::now();
    let mut show_hits = 0;
    for title in SHOWS {
        if tvmaze_lookup_full(title).is_some() {
            show_hits += 1;
        }
    }
    let show = t1.elapsed();

    println!(
        "movie lane: {:?} for {} titles ({:.2} s/title, {movie_hits}/10 matched)",
        movie,
        MOVIES.len(),
        movie.as_secs_f64() / MOVIES.len() as f64
    );
    println!(
        "tv lane:    {:?} for {} titles ({:.2} s/title, {show_hits}/10 matched)",
        show,
        SHOWS.len(),
        show.as_secs_f64() / SHOWS.len() as f64
    );
}

/// The tool the `ratelimit` numbers came out of: fire 24 requests at
/// a fixed spacing and report what the provider does about it.
/// `#[ignore]`d, and it deliberately provokes refusals - run it to
/// re-derive a limit, not as part of a suite.
///
///   PROBE=wikidata SPACING_MS=1000 \
///     cargo test -p nzbfast provider_rate_probe -- --ignored --nocapture
///
/// Reading the output: a provider enforcing a RATE refuses whenever
/// you go too fast and accepts when you slow down. One enforcing a
/// QUOTA lets exactly N through at any spacing and then refuses the
/// rest of the run - which is how Wikidata's 10-per-minute window
/// was found, and it is not a distinction the old
/// sleep-between-titles pacing could have surfaced.
#[test]
#[ignore]
fn provider_rate_probe() {
    let ms: u64 = std::env::var("SPACING_MS")
        .unwrap_or("1000".into())
        .parse()
        .unwrap();
    // Let any standing penalty from an earlier run expire first.
    std::thread::sleep(std::time::Duration::from_secs(60));
    let t0 = std::time::Instant::now();
    let mut ok = 0;
    for i in 0..24 {
        let at = std::time::Instant::now();
        let url = match std::env::var("PROBE").unwrap_or_default().as_str() {
            "tvmaze" => format!(
                "https://api.tvmaze.com/singlesearch/shows?q={}",
                percent_encode(["lost", "friends", "house", "the office"][i % 4])
            ),
            "wikipedia" => format!(
                "https://en.wikipedia.org/api/rest_v1/page/summary/{}",
                percent_encode(["The_Matrix", "Inception", "Jaws_(film)", "Arrival_(film)"][i % 4])
            ),
            _ if i % 2 == 0 => format!(
                "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json\
                 &language=en&type=item&limit=10&search={}",
                percent_encode(&format!("probe{i}"))
            ),
            _ => "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json\
                  &props=claims|labels|descriptions&languages=en|mul&ids=Q83495|Q42|Q1|Q2|Q3"
                .to_string(),
        };
        match crate::serve::shared_enrich_agent()
            .get(&url)
            .set("User-Agent", WIKI_UA)
            .timeout(std::time::Duration::from_secs(10))
            .call()
        {
            Ok(_) => ok += 1,
            Err(ureq::Error::Status(code, r)) => {
                let ra = r.header("Retry-After").unwrap_or("-").to_string();
                let body: String = r
                    .into_string()
                    .unwrap_or_default()
                    .chars()
                    .take(180)
                    .collect();
                println!(
                    "  request {i} at {:.1}s: HTTP {code} retry-after={ra} body={body:?}",
                    t0.elapsed().as_secs_f64()
                );
            }
            Err(e) => println!("  request {i} at {:.1}s: {e}", t0.elapsed().as_secs_f64()),
        }
        std::thread::sleep(std::time::Duration::from_millis(ms).saturating_sub(at.elapsed()));
    }
    println!(
        "spacing {ms}ms: {ok}/24 ok in {:.1}s",
        t0.elapsed().as_secs_f64()
    );
}

// ---- music + books --------------------------------------------------

#[test]
fn openlibrary_reranks_past_its_own_relevance_order() {
    // Measured against the live service: asking for title=Dune,
    // author=Frank Herbert answers with "Children of Dune" first and
    // the actual "Dune" seventh. Taking docs[0] would put the wrong
    // cover on the card for every book in a series, so this fixture
    // is the real ordering, not a convenient one.
    let v = serde_json::json!({"docs": [
        {"title":"Children of Dune","author_name":["Frank Herbert"],
         "first_publish_year":1976,"cover_i":6976407,"edition_count":77,
         "key":"/works/OL893516W","subject":["Science Fiction","Fiction in English"]},
        {"title":"God Emperor of Dune","author_name":["Frank Herbert"],
         "first_publish_year":1981,"cover_i":6711531,"edition_count":47,
         "key":"/works/OL893515W"},
        {"title":"Dune","author_name":["Frank Herbert","Френк Герберт"],
         "first_publish_year":1965,"cover_i":11481354,"edition_count":160,
         "key":"/works/OL893414W","ratings_average":4.2,
         "first_sentence":["A beginning is the time for taking the most delicate care."],
         "subject":["Science Fiction","Reading Level-Grade 7","Fiction",
                    "Dune (Imaginary Place)","New York Times Reviewed"]},
    ]});
    let m = parse_openlibrary(&v, "Dune").expect("no book picked");
    // The Cyrillic entry is the same author transliterated, not a
    // co-author - live OpenLibrary really does return both.
    assert_eq!(m.actors, "Frank Herbert", "author belongs in actors");
    assert_eq!(m.air_date, "1965");
    assert_eq!(
        m.poster_url,
        "https://covers.openlibrary.org/b/id/11481354-L.jpg"
    );
    assert_eq!(m.overview, "Book by Frank Herbert");
    // OpenLibrary rates out of 5, the card's star is out of 10.
    assert!(
        (m.rating - 8.4).abs() < 0.01,
        "rating not rescaled: {}",
        m.rating
    );
    // Shelving noise is not a genre.
    assert_eq!(m.genres, "Science Fiction, Fiction");
    // Nothing resembling the request → no card, rather than a wrong one.
    let other = serde_json::json!({"docs":[{"title":"A Totally Different Book",
        "author_name":["Someone"],"edition_count":5,"key":"/works/X"}]});
    assert!(parse_openlibrary(&other, "Dune").is_none());
}

#[test]
fn musicbrainz_picks_the_titled_release_group() {
    let v = serde_json::json!({"release-groups": [
        {"id":"aaa","title":"The Dark Side of the Moon: Live","score":95,
         "primary-type":"Album","first-release-date":"1974-01-01",
         "artist-credit":[{"name":"Pink Floyd"}]},
        {"id":"f5093c06","title":"The Dark Side of the Moon","score":100,
         "primary-type":"Album","first-release-date":"1973-03-24",
         "artist-credit":[{"name":"Pink Floyd"}]},
    ]});
    let g = pick_release_group(&v, "The Dark Side of the Moon").expect("no group");
    assert_eq!(
        g["id"], "f5093c06",
        "a scored near-miss beat the exact title"
    );
    let m = parse_release_group(&g).unwrap();
    assert_eq!(m.actors, "Pink Floyd", "artist belongs in actors");
    assert_eq!(m.air_date, "1973-03-24");
    assert_eq!(m.overview, "Album by Pink Floyd");
    assert!(m.tmdb_id != 0, "a match must set the found flag");
}

#[test]
fn cover_art_prefers_the_front_thumbnail_over_the_full_scan() {
    // The archive serves http:// in its JSON; artwork must not be
    // fetched in the clear just because it was advertised that way.
    let v = serde_json::json!({"images": [
        {"front": false, "image": "http://coverartarchive.org/release/x/back.jpg",
         "thumbnails": {"500": "http://coverartarchive.org/release/x/back-500.jpg"}},
        {"front": true, "image": "http://coverartarchive.org/release/x/front.jpg",
         "thumbnails": {"500": "http://coverartarchive.org/release/x/front-500.jpg"}},
    ]});
    assert_eq!(
        parse_coverart(&v),
        "https://coverartarchive.org/release/x/front-500.jpg"
    );
    assert_eq!(parse_coverart(&serde_json::json!({"images": []})), "");
}

/// Live check, same reasoning as `keyless_movie_chain_answers_live`:
/// the provider that path replaced (iTunes) died SILENTLY, answering
/// HTTP 200 with an empty result set, so every offline test above
/// kept passing while the wall quietly stopped getting artwork. Only
/// a real call catches that.
///
///     cargo test -p nzbfast --bin nzbfast -- --ignored music_and_book
#[test]
#[ignore]
fn music_and_book_chains_answer_live() {
    let mut any_genres = false;
    for (artist, album) in [
        ("Pink Floyd", "The Dark Side of the Moon"),
        ("Radiohead", "OK Computer"),
    ] {
        let m = musicbrainz_lookup(artist, album)
            .unwrap_or_else(|| panic!("musicbrainz found nothing for {artist} - {album}"));
        println!(
            "{artist} - {album}: date={} genres={:?} artist={:?} cover={}",
            m.air_date, m.genres, m.actors, m.poster_url
        );
        assert!(!m.air_date.is_empty(), "{album}: no first-release date");
        assert!(!m.actors.is_empty(), "{album}: no artist");
        assert!(
            m.poster_url.starts_with("https://"),
            "{album}: no cover art ({})",
            m.poster_url
        );
        any_genres |= !m.genres.is_empty();
    }
    // Genres come from a SECOND MusicBrainz call per album, and that
    // call is optional by design - a throttled response leaves the
    // field empty rather than losing the card. Asserting it per album
    // was stricter than the code's own contract and duly failed on a
    // transient. Requiring it from at least one album still catches
    // the case worth catching: the genre lookup being dead.
    assert!(
        any_genres,
        "no album returned genres - the release-group lookup is dead"
    );
    for (author, title) in [
        ("Frank Herbert", "Dune"),
        ("Andy Weir", "Project Hail Mary"),
    ] {
        let b = openlibrary_lookup(author, title)
            .unwrap_or_else(|| panic!("openlibrary found nothing for {author} - {title}"));
        println!(
            "{author} - {title}: year={} subjects={:?} author={:?} cover={}",
            b.air_date, b.genres, b.actors, b.poster_url
        );
        assert!(!b.air_date.is_empty(), "{title}: no publish year");
        assert!(!b.actors.is_empty(), "{title}: no author");
        assert!(
            b.poster_url.starts_with("https://covers.openlibrary.org/"),
            "{title}: no cover ({})",
            b.poster_url
        );
    }
}

#[test]
fn wikidata_times_are_normalised() {
    // The mandatory leading sign would fail iso_date's digit check.
    assert_eq!(wikidata_iso("+1999-03-31T00:00:00Z"), "1999-03-31");
    assert_eq!(wikidata_iso("-0044-03-15T00:00:00Z"), "");
}

// ---- TODO 26c: found / not-found / could-not-ask ---------------------

/// One refused HTTP reply, built the way ureq hands one to the fetchers -
/// headers and all, so the `Retry-After` under test is a real parsed
/// header rather than a number typed into the assertion.
fn refused_response(status: u16, headers: &str) -> ureq::Response {
    format!("HTTP/1.1 {status} Refused\r\n{headers}Content-Length: 0\r\n\r\n")
        .parse()
        .expect("a well-formed response")
}

/// The same reply as the error `note_http_err` classifies.
fn refusal(status: u16, headers: &str) -> ureq::Error {
    ureq::Error::Status(status, refused_response(status, headers))
}

/// A 429 must leave the row RE-ENRICHABLE, and must not be quietly
/// downgraded to "there is no such film".
///
/// This is the whole of TODO 26c in one assertion. `title_fill` writes
/// the card and `checked` in one statement and every lane query wants
/// `checked = 0`, so the value the lane reads here decides whether a
/// rate-limited minute costs a title its metadata permanently.
#[test]
fn a_429_is_could_not_ask_and_carries_its_retry_after() {
    clear_unreachable();
    // The lane calls this against its own bucket, so use one nothing
    // else in the BINARY touches - see the AniList note below for why
    // "in this file" is the wrong scope for a cooldown assertion.
    let wait = note_refusal(
        Provider::Srrdb,
        &refused_response(429, "Retry-After: 900\r\n"),
        30,
    );
    note_unreachable();
    assert_eq!(wait, 900, "the header the provider sent was not read");
    assert_eq!(
        outcome(false),
        Outcome::Transient {
            retry_after: Some(900)
        },
        "a 429 was recorded as an answer about the title"
    );
    // ...and the provider itself is backed off for as long as it asked,
    // not for the minute the bucket sleeps on. That is what stops the
    // NEXT row in the batch walking into the same refusal.
    let cooling = crate::ratelimit::cooling(Provider::Srrdb);
    assert!(
        cooling > std::time::Duration::from_secs(800),
        "the provider is only cooling for {cooling:?} of the 900 s it asked for"
    );
    // A provider that was NOT refused is untouched - the limits are
    // per-service and a mixed batch must only lose the lane that 429'd.
    //
    // AniList because the cooldown table is process-global and
    // `cargo test --bin nzbfast` runs every module's tests in ONE
    // process, so "a bucket nothing else in this file touches" is not
    // enough: this read has to name a provider no other TEST IN THE
    // BINARY penalises. WikidataQlever stood here until 23 Aug 2026 and
    // `ratelimit::tests::a_long_retry_after_cools_one_provider_and_only_that_one`
    // leaves it cooling for the clamped hour, which is what this
    // assertion read - both tests landed together in 84ae50bd7 and
    // picked the same two providers. See that test for the rule.
    assert_eq!(
        crate::ratelimit::cooling(Provider::AniList),
        std::time::Duration::ZERO,
        "one provider's 429 backed off an unrelated service"
    );
}

/// The other side of the same coin: a 404 is a real answer. Stamping it
/// is CORRECT, and re-asking on every pass would spend a keyless lane's
/// whole allowance being told the same thing.
#[test]
fn a_404_is_a_verdict_and_is_not_retried() {
    clear_unreachable();
    note_http_err(&refusal(404, ""));
    assert_eq!(
        outcome(false),
        Outcome::NotFound,
        "a 404 was treated as an outage"
    );
    assert_eq!(retry_after_hint(), None);
    // 5xx and the transient 4xx are the opposite verdict, on the same
    // helper - 408 and 425 say "not now", not "no such thing".
    for code in [500, 502, 503, 408, 425, 429] {
        clear_unreachable();
        note_http_err(&refusal(code, ""));
        assert_eq!(
            outcome(false),
            Outcome::Transient { retry_after: None },
            "HTTP {code} was counted as a real answer about the title"
        );
    }
}

/// A chain where one provider was refused and another ANSWERED has its
/// card, and must be stamped. Holding the row open for the service that
/// declined would re-fetch a complete record on every pass forever.
#[test]
fn an_answer_outranks_a_refusal_in_the_same_chain() {
    clear_unreachable();
    note_unreachable();
    note_retry_after(60);
    assert_eq!(outcome(true), Outcome::Found);
}

/// A clean chain that simply found nothing is the third state, and the
/// window must reset between rows or one blip blanks nothing and then
/// pins everything.
#[test]
fn the_window_resets_between_titles() {
    clear_unreachable();
    note_unreachable();
    note_retry_after(120);
    assert!(matches!(outcome(false), Outcome::Transient { .. }));
    clear_unreachable();
    assert_eq!(outcome(false), Outcome::NotFound);
    assert_eq!(retry_after_hint(), None);
}

/// The art fetch is on the stamping path too: `title_fill` writes the
/// poster name and `checked` together, so a poster that merely timed out
/// must not read like a URL that serves nothing.
#[test]
fn an_art_host_that_failed_is_told_apart_from_one_with_no_art() {
    // Not a URL at all: nothing to ask, and asking again will not help.
    assert_eq!(fetch_image_res("not a url"), Err(ArtMiss::NoImage));
    assert_eq!(fetch_image("not a url"), None);
}
