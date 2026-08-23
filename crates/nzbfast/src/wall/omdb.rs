//! The OMDb client: title and IMDb-id lookup, search, and the free-key
//! signup flow that gets a user a key without leaving the settings page
//! (TODO 106 code motion out of wall.rs, behaviour unchanged).

use super::*;

/// OMDb pads absent fields with the string "N/A" instead of omitting.
fn omdb_field(v: &serde_json::Value) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty() && *s != "N/A")
}

/// Pure parse of an OMDb detail response (t=/i= lookups; tested).
pub(super) fn parse_omdb(v: &serde_json::Value) -> Option<TitleMeta> {
    if v["Response"].as_str() != Some("True") {
        return None;
    }
    let imdb = omdb_field(&v["imdbID"]).unwrap_or("").to_string();
    // Numeric part of the tconst as the provider id (nonzero = found).
    let id: i64 = imdb.trim_start_matches("tt").parse().unwrap_or(1);
    Some(TitleMeta {
        tmdb_id: id.max(1),
        // NOT a TMDB id, whatever the column is called: it is the
        // numeric half of the IMDb tconst. Radarr's `tmdbid=` resolves
        // against that column, so without this label an OMDb-enriched
        // film answered a TMDB id lookup (Codex sweep 7, H2).
        id_src: "omdb".into(),
        overview: omdb_field(&v["Plot"]).unwrap_or("").to_string(),
        rating: omdb_field(&v["imdbRating"])
            .and_then(|r| r.parse().ok())
            .unwrap_or(0.0),
        genres: omdb_field(&v["Genre"]).unwrap_or("").to_string(),
        poster_url: omdb_field(&v["Poster"]).unwrap_or("").to_string(),
        backdrop_url: String::new(),
        imdb,
        actors: omdb_field(&v["Actors"]).unwrap_or("").to_string(),
        air_date: iso_date(omdb_field(&v["Released"]).unwrap_or("")),
        credits: Vec::new(),
    })
}

/// OMDb: movie metadata by title (+year hint).
pub fn omdb_lookup(key: &str, title: &str, year: u32) -> Option<TitleMeta> {
    let mut url = format!(
        "https://www.omdbapi.com/?apikey={key}&type=movie&t={}",
        percent_encode(title)
    );
    if year > 0 {
        let _ = write!(url, "&y={year}");
    }
    get_json(Provider::Omdb, &url).as_ref().and_then(parse_omdb)
}

/// OMDb: exact lookup by IMDb tconst (Wikidata resolves those keyless,
/// so an OMDb title-miss often still lands via the id).
pub fn omdb_lookup_imdb(key: &str, tconst: &str) -> Option<TitleMeta> {
    get_json(
        Provider::Omdb,
        &format!("https://www.omdbapi.com/?apikey={key}&i={tconst}"),
    )
    .as_ref()
    .and_then(parse_omdb)
}

/// Pure parse of an OMDb `s=` search response → candidates (tested).
/// Year comes as "1999" or a range "1999–2003" - first 4 digits win.
pub(super) fn parse_omdb_search(v: &serde_json::Value) -> Vec<Candidate> {
    v["Search"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .take(10)
                .filter_map(|hit| {
                    let imdb = omdb_field(&hit["imdbID"])?.to_string();
                    Some(Candidate {
                        id: imdb.trim_start_matches("tt").parse().unwrap_or(1),
                        kind: "movie".into(),
                        title: omdb_field(&hit["Title"]).unwrap_or("").to_string(),
                        year: omdb_field(&hit["Year"])
                            .and_then(|y| y.get(..4))
                            .and_then(|y| y.parse().ok())
                            .unwrap_or(0),
                        overview: String::new(),
                        rating: 0.0,
                        genres: String::new(),
                        poster_url: omdb_field(&hit["Poster"]).unwrap_or("").to_string(),
                        backdrop_url: String::new(),
                        imdb,
                        provider: "omdb".into(),
                        // The `s=` list carries Year only - a per-title
                        // Refresh picks the full date up from `t=`/`i=`.
                        air_date: String::new(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// OMDb candidate search for the wall's fix-match UI.
pub fn omdb_search(key: &str, query: &str) -> Vec<Candidate> {
    get_json(
        Provider::Omdb,
        &format!(
            "https://www.omdbapi.com/?apikey={key}&type=movie&s={}",
            percent_encode(query)
        ),
    )
    .map(|v| parse_omdb_search(&v))
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// OMDb signup automation: the free-key form only wants an email, so the
// daemon can submit it for the user (Settings → Indexing → "Request
// key"). It's a classic ASP.NET WebForms page - replay every hidden
// field verbatim, pick the FREE account-type radio, fill the email/name
// boxes, press the submit button. The key then arrives BY EMAIL with an
// activation link, so the last step is always the user's inbox.
// ---------------------------------------------------------------------------

/// One attribute out of a raw HTML tag ("<input name=\"x\" …>").
fn tag_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    for quote in ['"', '\''] {
        let pat = format!("{name}={quote}");
        if let Some(p) = tag.to_ascii_lowercase().find(&pat) {
            let rest = &tag[p + pat.len()..];
            if let Some(end) = rest.find(quote) {
                return Some(&rest[..end]);
            }
        }
    }
    None
}

/// The free-tier account-type radio: (field name, __doPostBack target
/// = the element id, field value, whether it's already selected). The
/// live form defaults to the Patreon tier with an AutoPostBack on the
/// free radio, so selection is a round-trip, not just a field value.
pub(super) fn omdb_free_radio(html: &str) -> Option<(String, String, String, bool)> {
    let mut rest = html;
    while let Some(p) = rest.find("<input") {
        rest = &rest[p..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        rest = &rest[end..];
        if tag_attr(tag, "type")
            .map(str::to_ascii_lowercase)
            .as_deref()
            != Some("radio")
        {
            continue;
        }
        let value = tag_attr(tag, "value").unwrap_or("");
        if !value.to_ascii_lowercase().contains("free") {
            continue;
        }
        let name = tag_attr(tag, "name")?.to_string();
        let target = tag_attr(tag, "id").unwrap_or(value).to_string();
        let checked = tag.to_ascii_lowercase().contains("checked");
        return Some((name, target, value.to_string(), checked));
    }
    None
}

/// Pure form scrape (tested): every field the POST must carry, with the
/// user's email in the email boxes and the free tier selected. None if
/// the page doesn't look like the signup form (no email field). The
/// submit button only rides on the final POST - a WebForms postback
/// that selects the radio must not also "click" Submit.
pub(super) fn omdb_signup_fields(
    html: &str,
    email: &str,
    include_submit: bool,
) -> Option<Vec<(String, String)>> {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut saw_email = false;
    let mut submit_taken = false;
    let mut rest = html;
    while let Some(p) = rest.find("<input") {
        rest = &rest[p..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        rest = &rest[end..];
        let Some(name) = tag_attr(tag, "name") else {
            continue;
        };
        let name = name.to_string();
        let lname = name.to_ascii_lowercase();
        let value = tag_attr(tag, "value").unwrap_or("").to_string();
        let ty = tag_attr(tag, "type").unwrap_or("text").to_ascii_lowercase();
        match ty.as_str() {
            "radio" => {
                // Account type: always post the free-tier option.
                if value.to_ascii_lowercase().contains("free") {
                    fields.push((name, value));
                }
            }
            "submit" => {
                if include_submit && !submit_taken {
                    submit_taken = true;
                    fields.push((name, value));
                }
            }
            "checkbox" => {} // none required on this form
            _ => {
                // text/email/hidden: viewstate rides through verbatim,
                // email boxes (incl. the confirm box) get the address.
                if lname.contains("email") {
                    saw_email = true;
                    fields.push((name, email.to_string()));
                } else if lname.contains("firstname") {
                    fields.push((name, "nzbfast".into()));
                } else if lname.contains("lastname") {
                    fields.push((name, "user".into()));
                } else {
                    fields.push((name, value));
                }
            }
        }
    }
    // The "use" textarea posts too.
    let mut rest = html;
    while let Some(p) = rest.find("<textarea") {
        rest = &rest[p..];
        let end = rest.find('>').unwrap_or(rest.len());
        if let Some(name) = tag_attr(&rest[..end], "name") {
            fields.push((
                name.to_string(),
                "Personal media library (poster wall metadata)".into(),
            ));
        }
        rest = &rest[end..];
    }
    saw_email.then_some(fields)
}

pub(super) fn form_encode(fields: &[(String, String)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Best-effort automated OMDb free-key signup. Ok = the form was
/// accepted (key + activation link arrive by email); Err = fall back to
/// doing it by hand at omdbapi.com/apikey.aspx.
///
/// Two round-trips: the live form defaults to the Patreon tier and the
/// FREE radio is a WebForms AutoPostBack - selecting it re-renders the
/// page with the free-tier fields (name, intended use). So: GET, replay
/// the __doPostBack that picks FREE, then fill + submit that form.
pub fn omdb_signup(email: &str) -> Result<(), String> {
    const URL: &str = "https://www.omdbapi.com/apikey.aspx";
    let post = |fields: &[(String, String)]| -> Result<String, String> {
        // The same shared agent the GET below rides, so the whole
        // three-round-trip WebForms dance reuses one connection rather
        // than handshaking afresh for each postback.
        crate::serve::shared_enrich_agent()
            .post(URL)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .timeout(std::time::Duration::from_secs(15))
            .send_string(&form_encode(fields))
            .map_err(|e| format!("signup submit failed: {e}"))?
            .into_string()
            .map_err(|e| e.to_string())
    };
    let mut page = crate::serve::shared_enrich_agent()
        .get(URL)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .map_err(|e| format!("couldn't load the signup form: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    if let Some((_, target, _, checked)) = omdb_free_radio(&page)
        && !checked
    {
        let mut fields = omdb_signup_fields(&page, email, false)
            .ok_or("the signup form has changed - request a key manually")?;
        fields.push(("__EVENTTARGET".into(), target));
        fields.push(("__EVENTARGUMENT".into(), String::new()));
        page = post(&fields)?;
    }
    let fields = omdb_signup_fields(&page, email, true)
        .ok_or("the signup form has changed - request a key manually")?;
    let body = post(&fields)?.to_ascii_lowercase();
    // WebForms answers 200 either way - look for the confirmation copy.
    if ["sent", "activat", "verification", "shortly", "receive"]
        .iter()
        .any(|m| body.contains(m))
    {
        Ok(())
    } else if body.contains("exist") || body.contains("already") {
        Err("that email already has a key - check your inbox (or spam) for it".into())
    } else {
        Err("the form didn't confirm - request a key manually".into())
    }
}
