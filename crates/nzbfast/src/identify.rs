//! Synthesised naming: work out what an obfuscated film IS from the
//! bytes that already arrived, and rename it only when the answer is
//! beyond doubt.
//!
//! # Why this exists, and where it may run
//!
//! A fully obfuscated post carries no name anywhere: not in the subject,
//! not in the PAR2 file descriptors, not in the archive headers. Every
//! earlier pass in the rename pipeline has already declined by the time
//! this one is asked. What is left is the payload itself, and the
//! measured result is that for RECENT FILMS the container's own facts
//! discriminate: release year plus runtime to the minute plus the
//! original language cuts the field of 2024-2026 films to a median of
//! 4-11 candidates, and a second source agreeing on the exact runtime
//! frequently makes it one.
//!
//! This runs POST-DOWNLOAD, on local bytes, and that is not an
//! implementation detail. Locating an obfuscated post's first article
//! before downloading it was measured as effectively unbounded on the
//! bare-stem posting style, so a pre-download identify ladder never
//! starts. Once the job completes, part 1 is on disk by definition and
//! the whole ladder costs a couple of API calls.
//!
//! # Films only
//!
//! TV is measured DEAD for this and is not attempted. Wikidata holds
//! runtimes for only a few hundred recent episodes and they cluster on
//! 42/60/75/120 minutes, so an episode's runtime discriminates nothing.
//! The caller gates on a movie-like classification; this module gates
//! again on a feature-length runtime.
//!
//! # The gate is the feature
//!
//! A wrong rename is worse than no rename: it puts a confident, false
//! name on a file the user then cannot find by its real one, and *arr
//! clients import it under that name. So the acceptance rule is not
//! "best match" but "no other possibility":
//!
//! 1. Candidates come from a year window and a runtime window (+/-2 min,
//!    the theatrical-vs-file tolerance), narrowed by original language
//!    only when the container asserts exactly one audio language.
//! 2. Survivors are the candidates whose published runtime equals the
//!    file's runtime in whole minutes EXACTLY. The window exists to
//!    bound the query; the equality is what decides.
//! 3. TWO independent catalogues must each return exactly one survivor,
//!    and they must name the same film.
//!
//! Anything else records the facts and the shortlist for the user and
//! leaves the filename alone. Declining is the common outcome by
//! design - see [`Outcome`].
//!
//! # Why rule 3 needs two sources and not one
//!
//! A single catalogue's unique hit was tried first and is NOT safe. It
//! fails on a real file, and the failure was found by running this on
//! one:
//!
//! Buster Keaton's *The General* (1926) measures 78.9 minutes in the
//! transfer that exists, so 79. Wikidata publishes that film at 75, so
//! it is not in the 79-minute set at all - but exactly one 1925-26 film
//! IS, an unrelated Soviet picture called *The Wings of a Serf*. One
//! source, one survivor, total confidence, wrong film.
//!
//! The general shape, which is not about old films: a unique hit means
//! "only one film I KNOW OF has this runtime", and the minutes where
//! that is true are exactly the sparsely-populated ones - measured over
//! 2025-2026 English-original films, the 21 uniquely-occupied minutes
//! are the tails (40-74 and 117-147), not the 90-110 mass. So single
//! source uniqueness concentrates precisely where the catalogue is
//! thinnest and a miss is most likely. Meanwhile the other half of the
//! coin: across three real transfers measured here, the container
//! runtime differed from the published one EVERY time (88.2 vs 90, 54.8
//! vs 53, 78.9 vs 75). The right film is usually absent from the exact
//! minute; a wrong one is sometimes alone in it.
//!
//! Two catalogues with independent editorial processes landing on the
//! same film at the same minute is a far stronger claim, and it is what
//! the measured success case rested on. The cost is recall: an install
//! with no second source configured never renames, and only ever writes
//! the note. Given the above, that is the correct trade - the note is
//! the part that was always going to earn its keep.

use crate::ratelimit::{self, Provider};
use tracing::warn;

/// One film a catalogue offered as a possibility.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub title: String,
    pub year: u32,
    /// Published runtime in whole minutes.
    pub runtime_min: u32,
    /// Which catalogue said so ("wikidata" / "tmdb").
    pub source: &'static str,
    /// The catalogue's own id (a Wikidata Q-number, a TMDB integer), so
    /// a user reading the shortlist can go and look.
    pub id: String,
}

impl std::fmt::Display for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) {} min [{}:{}]",
            self.title, self.year, self.runtime_min, self.source, self.id
        )
    }
}

/// What one catalogue answered. Kept apart from the verdict because the
/// gate needs to know the difference between "asked, nobody matched"
/// and "could not ask" - a source that failed must never be counted as
/// agreeing.
#[derive(Debug, Clone)]
pub struct SourceResult {
    /// Candidates inside the runtime WINDOW, before the exact-minute
    /// rule. This is what the shortlist shows the user.
    pub window: Vec<Candidate>,
    /// The query ran and this is its answer. False means the lookup
    /// itself failed (offline, 5xx, malformed response) and the source
    /// is not evidence either way.
    pub answered: bool,
}

/// Why the ladder stopped. Every arm except [`Verdict::Named`] leaves the
/// filename exactly as posted.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Two independent catalogues each had exactly one survivor and they
    /// named the same film. This is the only arm that renames.
    Named { title: String, year: u32 },
    /// One catalogue had exactly one survivor and nothing corroborated
    /// it - either because no second source is configured, or because
    /// the second one could not be reached.
    ///
    /// Deliberately NOT a rename, and deliberately not folded into
    /// [`Verdict::Ambiguous`] either: it is the single most useful thing
    /// the note can tell a user, and it is exactly the shape that
    /// renamed Buster Keaton's *The General* to an unrelated Soviet film
    /// in testing. Worth showing, never worth acting on.
    Uncorroborated { title: String, year: u32 },
    /// The container gave us no runtime we could search on: not a
    /// feature-length duration, or no duration at all.
    NoRuntime,
    /// No catalogue could be reached, so nothing was ruled out.
    NoSource,
    /// Sources answered, but not with exactly one survivor each, or not
    /// with the same one. The shortlist carries what they did say.
    Ambiguous,
}

/// The whole result of one identification attempt: the verdict, plus
/// everything a user needs to see why.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub verdict: Verdict,
    /// The facts the file itself asserted, already rendered ("108 min,
    /// h264, eac3, audio en, subs en fr"). Shown whatever the verdict.
    pub facts: String,
    /// Candidates inside the runtime window, across every source, best
    /// first. Capped - see [`SHORTLIST_MAX`].
    pub shortlist: Vec<String>,
}

/// How many candidates the note carries. The window can hold dozens; a
/// list that long is not a shortlist and would push everything else out
/// of the drawer. The user has the facts line and can search on it.
const SHORTLIST_MAX: usize = 8;

impl Outcome {
    /// The film name to rename to, or `None` for every declining
    /// verdict. Deliberately the only way out of this type into a
    /// filename, so no caller can accidentally act on an ambiguous
    /// result.
    pub fn accepted_name(&self) -> Option<String> {
        match &self.verdict {
            Verdict::Named { title, year } => Some(format!("{title} {year}")),
            _ => None,
        }
    }

    /// One line for the job log and the history drawer, in English.
    /// Facts first, because they are true regardless of what any
    /// catalogue said, and they are what the user searches with when we
    /// decline.
    pub fn log_line(&self) -> String {
        let head = match &self.verdict {
            Verdict::Named { title, year } => format!("identified as {title} ({year})"),
            Verdict::Uncorroborated { title, year } => format!(
                "possibly {title} ({year}) - the only film one catalogue lists at this \
                 runtime, but nothing confirms it, so the name was left alone"
            ),
            Verdict::NoRuntime => "no usable runtime in the container".to_string(),
            Verdict::NoSource => "no film catalogue could be reached".to_string(),
            Verdict::Ambiguous if self.shortlist.is_empty() => {
                "no film matches these facts".to_string()
            }
            Verdict::Ambiguous => {
                format!("{} possible matches, none certain", self.shortlist.len())
            }
        };
        if self.facts.is_empty() {
            head
        } else {
            format!("{head}; {}", self.facts)
        }
    }
}

/// Runtime tolerance for the QUERY, in minutes. A file's runtime and a
/// catalogue's published one differ by a minute or two routinely -
/// theatrical versus retail cuts, PAL speedup, credits handling - so the
/// window has to be wider than the rule that decides. Widening it does
/// not loosen the gate: the exact-minute equality in [`decide`] is what
/// accepts, and the window only controls what we get to rule OUT.
const RUNTIME_WINDOW_MIN: u32 = 2;

/// Most candidates we will pull back from one source. Well above the
/// measured window sizes (median 27-111 for a +/-1 window, roughly
/// double at +/-2), and there purely so a catalogue bug cannot hand us
/// an unbounded result set.
const MAX_ROWS: usize = 400;

/// Run the whole ladder for one file's facts. Blocking: two HTTP calls
/// at most, each paced by its provider's bucket. Call from a blocking
/// context - the renamer already is one.
///
/// `post_year` is when the release was POSTED, which bounds the film's
/// release year from above: a film cannot be posted before it exists.
/// The window is `{post_year - 1, post_year}` because posts of a film's
/// retail release routinely land the year after its theatrical one.
pub fn identify(
    facts: &nzbkit::media::MediaFacts,
    post_year: u32,
    tmdb_key: Option<&str>,
) -> Outcome {
    let rendered = render_facts(facts);
    let Some(minutes) = facts.runtime_minutes() else {
        return Outcome {
            verdict: Verdict::NoRuntime,
            facts: rendered,
            shortlist: Vec::new(),
        };
    };
    let lang = facts.original_language();
    let years = (post_year.saturating_sub(1), post_year);

    let mut results = vec![wikidata_candidates(years, minutes, lang)];
    if let Some(key) = tmdb_key.filter(|k| !k.is_empty()) {
        results.push(tmdb_candidates(key, years, minutes, lang));
    }
    let verdict = decide(minutes, &results);
    Outcome {
        verdict,
        facts: rendered,
        shortlist: shortlist(minutes, &results),
    }
}

/// The acceptance gate, pure and total over what the sources returned.
/// Every rename decision this feature can make comes through here, which
/// is why it takes no network and no clock: it is the piece worth
/// testing exhaustively.
pub fn decide(minutes: u32, results: &[SourceResult]) -> Verdict {
    let answered: Vec<&SourceResult> = results.iter().filter(|r| r.answered).collect();
    if answered.is_empty() {
        // Nothing was ruled out, so nothing may be concluded. NOT
        // Ambiguous: a source that could not be reached is silence, and
        // silence from the only source consulted must not read as
        // "no match" to a caller deciding whether to try again.
        return Verdict::NoSource;
    }
    let mut agreed: Option<(String, u32)> = None;
    for r in &answered {
        // The window bounded the query; this equality is the rule.
        let mut survivors = r.window.iter().filter(|c| c.runtime_min == minutes);
        let (Some(only), None) = (survivors.next(), survivors.next()) else {
            return Verdict::Ambiguous;
        };
        match &agreed {
            // Two catalogues that name different films have not
            // confirmed each other, however confident each one is.
            Some((title, _)) if !same_title(title, &only.title) => {
                return Verdict::Ambiguous;
            }
            // First source to answer sets the claim; a later one may
            // only confirm it. Its year is kept because the first
            // source is the keyless one every install has.
            None => agreed = Some((only.title.clone(), only.year)),
            _ => {}
        }
    }
    match agreed {
        // Corroboration, not just uniqueness. One catalogue alone
        // saying "only one film I know of has this runtime" is not the
        // same claim as "this is the film", and the module docs record
        // the real file where treating them as the same renamed Buster
        // Keaton's The General to something else entirely.
        Some((title, year)) if answered.len() >= 2 => Verdict::Named { title, year },
        Some((title, year)) => Verdict::Uncorroborated { title, year },
        None => Verdict::Ambiguous,
    }
}

/// Do two catalogues mean the same film? Compared on the normalised
/// form the release parser already uses for title identity, so
/// "WALL-E" and "WALL·E" or "Se7en" and "Se7en " agree, while genuinely
/// different films do not.
fn same_title(a: &str, b: &str) -> bool {
    nzbkit::release::norm_title(a) == nzbkit::release::norm_title(b)
}

/// The union of every source's window, best first, capped. Duplicates
/// across sources are merged on title so a film both catalogues offer
/// does not read as two possibilities.
///
/// "Best" is CLOSEST TO THE FILE'S OWN RUNTIME, and that ordering is the
/// whole value of the note. A +/-2 minute window over two years holds
/// dozens of films; the first eight of them alphabetically are eight
/// arbitrary films, while the first eight by runtime distance are the
/// ones actually worth reading. Title is only the tie-break, so the
/// order stays deterministic and the same file always produces the same
/// note.
fn shortlist(minutes: u32, results: &[SourceResult]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<String> = Vec::new();
    let mut all: Vec<&Candidate> = results.iter().flat_map(|r| r.window.iter()).collect();
    all.sort_by(|a, b| {
        let d = |c: &Candidate| c.runtime_min.abs_diff(minutes);
        d(a).cmp(&d(b))
            .then_with(|| {
                a.title
                    .to_ascii_lowercase()
                    .cmp(&b.title.to_ascii_lowercase())
            })
            .then(a.year.cmp(&b.year))
    });
    for c in all {
        let key = nzbkit::release::norm_title(&c.title);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(c.to_string());
        if out.len() >= SHORTLIST_MAX {
            break;
        }
    }
    out
}

/// The container facts as one human line. Written here rather than in
/// the dashboard because it is evidence, not chrome: it goes in the log
/// as well, and both have to say the same thing.
fn render_facts(f: &nzbkit::media::MediaFacts) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(m) = f.runtime_minutes() {
        parts.push(format!("{m} min"));
    } else if let Some(s) = f.duration_secs {
        parts.push(format!("{:.0}s", s));
    }
    if let (Some(w), Some(h)) = (f.width, f.height) {
        parts.push(nzbkit::mkv::res_bucket(w, h).to_string());
    }
    if let Some(v) = &f.video_codec {
        parts.push(v.clone());
    }
    if !f.audio_codecs.is_empty() {
        parts.push(f.audio_codecs.join("/"));
    }
    if !f.audio_langs.is_empty() {
        parts.push(format!("audio {}", f.audio_langs.join(" ")));
    }
    if !f.sub_langs.is_empty() {
        parts.push(format!("subs {}", f.sub_langs.join(" ")));
    }
    parts.join(", ")
}

// ---------------------------------------------------------------- Wikidata

/// The keyless source every install has. Queried through the QLever
/// mirror rather than query.wikidata.org: WDQS has been returning 502
/// for this class of query, and the mirror answers the same graph in
/// under two seconds.
const QLEVER: &str = "https://qlever.cs.uni-freiburg.de/api/wikidata";

fn wikidata_candidates(years: (u32, u32), minutes: u32, lang: Option<&str>) -> SourceResult {
    let mut out = SourceResult {
        window: Vec::new(),
        answered: false,
    };
    let sparql = wikidata_sparql(years, minutes, lang);
    ratelimit::acquire(Provider::WikidataQlever);
    let url = format!("{QLEVER}?query={}", percent_encode(&sparql));
    let resp = crate::netfetch::shared_enrich_agent()
        .get(&url)
        .set("Accept", "application/sparql-results+json")
        .timeout(std::time::Duration::from_secs(30))
        .call();
    let body = match resp {
        Ok(r) => match r.into_string() {
            Ok(b) => b,
            Err(_) => return out,
        },
        Err(e) => {
            // Same courtesy as the enricher: a 429/503 slows the whole
            // lane, not just this call.
            if let ureq::Error::Status(code @ (429 | 503), r) = &e {
                let wait = r
                    .header("Retry-After")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(if *code == 429 { 30 } else { 5 });
                ratelimit::penalise(Provider::WikidataQlever, wait);
            }
            warn!(target: "identify", "wikidata: {e}");
            return out;
        }
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return out;
    };
    let Some(rows) = v["results"]["bindings"].as_array() else {
        return out;
    };
    // A row count at the query's own LIMIT means the window was cut off:
    // a survivor past the cap was never seen, so this source has not
    // ruled the rest of the window out and must not read as certainty.
    out.answered = rows.len() < MAX_ROWS;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for row in rows.iter().take(MAX_ROWS) {
        let title = row["label"]["value"].as_str().unwrap_or("").trim();
        // A published runtime is a decimal in the graph ("108.0"); a
        // film whose runtime does not round to a whole minute is not a
        // thing, so rounding here loses nothing and lets the equality
        // in `decide` be integer.
        let mins = row["mins"]["value"]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|m| m.round());
        let year = row["y"]["value"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok());
        let (Some(mins), Some(year)) = (mins, year) else {
            continue;
        };
        if title.is_empty() || !(0.0..=1000.0).contains(&mins) {
            continue;
        }
        // ".../entity/Q116921951" -> "Q116921951"
        let id = row["film"]["value"]
            .as_str()
            .and_then(|u| u.rsplit('/').next())
            .unwrap_or("")
            .to_string();
        // One film, two rows: the query accepts an `en` label AND a `mul`
        // one (Wikidata is migrating single-form names to `mul`), and an
        // entity carrying both arrives twice. The uniqueness rule that
        // decides a verdict counts rows, so the duplicate read as two
        // different films and the answer came back Ambiguous.
        if !id.is_empty() && !seen.insert(id.clone()) {
            continue;
        }
        out.window.push(Candidate {
            source: "wikidata",
            title: title.to_string(),
            year,
            runtime_min: mins as u32,
            id,
        });
    }
    out
}

/// The query, built as text because there is no SPARQL builder here and
/// every value interpolated into it is an integer or a two-letter code
/// this module produced - see the assertions in `lang_clause`.
fn wikidata_sparql(years: (u32, u32), minutes: u32, lang: Option<&str>) -> String {
    let (lo_year, hi_year) = years;
    let lo = minutes.saturating_sub(RUNTIME_WINDOW_MIN);
    let hi = minutes + RUNTIME_WINDOW_MIN;
    format!(
        "PREFIX wdt: <http://www.wikidata.org/prop/direct/>\n\
         PREFIX wd: <http://www.wikidata.org/entity/>\n\
         PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n\
         SELECT ?film ?label ?mins ?y WHERE {{\n\
         {{ SELECT ?film (MIN(YEAR(?d)) AS ?y) WHERE {{\n\
         ?film wdt:P31 wd:Q11424 . ?film wdt:P577 ?d .\n\
         }} GROUP BY ?film }}\n\
         FILTER(?y >= {lo_year} && ?y <= {hi_year})\n\
         ?film wdt:P2047 ?mins .\n\
         FILTER(?mins >= {lo}.0 && ?mins <= {hi}.0)\n\
         {lang_clause}\
         ?film rdfs:label ?label . FILTER(LANG(?label) IN (\"en\", \"mul\"))\n\
         }} LIMIT {MAX_ROWS}",
        lang_clause = lang_clause(lang),
    )
}

/// The original-language narrowing, or nothing.
///
/// Two things are load-bearing here. The film's year is taken as the
/// EARLIEST of its publication dates, not any of them: Wikidata records
/// a `P577` per country, so a 2023 film with a 2025 Japanese release
/// would otherwise enter a 2025 window and pollute it. And the label
/// filter accepts `mul` as well as `en`, because Wikidata has been
/// migrating single-form names to the `mul` pseudo-language and a film
/// whose label moved is otherwise invisible to an `en`-only filter.
fn lang_clause(lang: Option<&str>) -> String {
    match lang {
        // P364 original language of work, joined to P218 (ISO 639-1) so
        // the two-letter code the container gave us is what we compare.
        // The code is asserted to be two ASCII letters before it reaches
        // the query text: `normalise_lang` only ever emits that shape,
        // and this is the belt to its braces, because everything else
        // interpolated into the query is an integer.
        Some(l) if l.len() == 2 && l.bytes().all(|b| b.is_ascii_lowercase()) => {
            format!("?film wdt:P364 ?lang . ?lang wdt:P218 \"{l}\" .\n")
        }
        _ => String::new(),
    }
}

// -------------------------------------------------------------------- TMDB

/// The second source, on the user's own key. Its runtimes come from a
/// different editorial process than Wikidata's, which is exactly why
/// agreement between them is worth something: two catalogues that
/// independently publish the same exact minute for the same film are
/// much harder to both be wrong about than one.
fn tmdb_candidates(key: &str, years: (u32, u32), minutes: u32, lang: Option<&str>) -> SourceResult {
    let mut out = SourceResult {
        window: Vec::new(),
        answered: false,
    };
    let lo = minutes.saturating_sub(RUNTIME_WINDOW_MIN);
    let hi = minutes + RUNTIME_WINDOW_MIN;
    let mut any_failed = false;
    let mut answered_any = false;
    // /discover takes one release year at a time, so the two-year window
    // is two calls. Both must be attempted: a source that answered for
    // only half its window has not ruled the other half out.
    for year in [years.0, years.1] {
        let mut url = format!(
            "https://api.themoviedb.org/3/discover/movie?api_key={key}\
             &primary_release_year={year}&with_runtime.gte={lo}&with_runtime.lte={hi}\
             &include_adult=false&page=1"
        );
        if let Some(l) = lang.filter(|l| l.len() == 2 && l.bytes().all(|b| b.is_ascii_lowercase()))
        {
            url.push_str(&format!("&with_original_language={l}"));
        }
        ratelimit::acquire(Provider::Tmdb);
        let body = match crate::netfetch::shared_enrich_agent()
            .get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .call()
        {
            Ok(r) => match r.into_string() {
                Ok(b) => b,
                Err(_) => {
                    any_failed = true;
                    continue;
                }
            },
            Err(e) => {
                if let ureq::Error::Status(code @ (429 | 503), r) = &e {
                    let wait = r
                        .header("Retry-After")
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(if *code == 429 { 30 } else { 5 });
                    ratelimit::penalise(Provider::Tmdb, wait);
                }
                // NEVER format the whole error: the request URL carries
                // `api_key=<the user's key>` in its query string, and
                // ureq's Display prints that URL for both Status and
                // Transport errors. The log ring this lands in is served
                // unscrubbed at mode=log and by JSON-RPC loadlog, and gets
                // pasted into support threads. Rebuilt from the parts that
                // describe the failure, exactly as notify.rs does for
                // webhook URLs - which also keeps this correct if the
                // key's spelling or position in the query ever changes.
                // The trigger is not exotic: the 429/503 branch directly
                // above exists because rate-limiting is expected.
                match &e {
                    ureq::Error::Status(code, _) => {
                        warn!(target: "identify", "tmdb: status code {code}")
                    }
                    ureq::Error::Transport(t) => warn!(
                        target: "identify",
                        "tmdb: {}{}",
                        t.kind(),
                        t.message().map(|m| format!(": {m}")).unwrap_or_default(),
                    ),
                }
                any_failed = true;
                continue;
            }
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
            any_failed = true;
            continue;
        };
        let Some(rows) = v["results"].as_array() else {
            any_failed = true;
            continue;
        };
        answered_any = true;
        // /discover's runtime filter is inclusive but the payload does
        // NOT carry the runtime, so each hit needs its own detail call
        // to be usable by the exact-minute rule. Bounded by
        // DETAIL_BUDGET: the window is small by construction, and an
        // unexpectedly large one is a reason to decline, not to spend a
        // hundred requests.
        for hit in rows.iter().take(DETAIL_BUDGET) {
            let Some(id) = hit["id"].as_i64() else {
                continue;
            };
            let title = hit["title"].as_str().unwrap_or("").trim().to_string();
            if title.is_empty() {
                continue;
            }
            let Some(answer) = tmdb_runtime(key, id) else {
                // The detail ask failed (429 mid-burst, transport, bad
                // body). Dropping the candidate silently would count a
                // failed lookup as evidence - a second exact-minute
                // survivor could vanish and leave a false unique match.
                any_failed = true;
                continue;
            };
            let Some(runtime) = answer else {
                continue; // answered: no runtime published
            };
            if !(lo..=hi).contains(&runtime) {
                continue;
            }
            out.window.push(Candidate {
                title,
                year,
                runtime_min: runtime,
                source: "tmdb",
                id: id.to_string(),
            });
        }
        // More hits than we were willing to price: the window is bigger
        // than we saw, so this source has NOT ruled the rest out. The
        // page carries at most 20 rows (TMDB's fixed page size, equal to
        // DETAIL_BUDGET) and only page 1 is ever fetched, so the row
        // count alone can never exceed the budget - the declared total
        // is the only honest measure of the window.
        let total = v["total_results"].as_i64().unwrap_or(i64::MAX);
        if total as usize > rows.len().min(DETAIL_BUDGET) || rows.len() > DETAIL_BUDGET {
            any_failed = true;
        }
    }
    // Answered only if the whole window was covered. A half-covered
    // window that happens to hold one survivor would otherwise read as
    // certainty.
    out.answered = answered_any && !any_failed;
    out
}

/// How many TMDB detail calls one identification may spend. Two years of
/// a +/-2 minute window is a handful of films in practice; a number far
/// above that means the query went wrong.
const DETAIL_BUDGET: usize = 20;

/// Outer `None` = the ask itself failed (transport, status, bad body):
/// the caller must not treat the window as fully covered. `Some(None)` =
/// TMDB answered and publishes no usable runtime: the candidate is
/// legitimately outside the exact-minute rule and may be dropped without
/// weakening the answer.
fn tmdb_runtime(key: &str, id: i64) -> Option<Option<u32>> {
    ratelimit::acquire(Provider::Tmdb);
    let url = format!("https://api.themoviedb.org/3/movie/{id}?api_key={key}");
    let body = crate::netfetch::shared_enrich_agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .ok()?
        .into_string()
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    Some(v["runtime"].as_i64().filter(|m| *m > 0).map(|m| m as u32))
}

/// Minimal percent-encoding for a SPARQL query in a URL. Everything not
/// unreserved is escaped, so a query containing `#`, `&` or a space
/// cannot be cut short or read as another parameter.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
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

/// This year, in UTC. The post year falls back to it when a job's NZB
/// carries no usable date.
pub fn current_year() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    year_of_unix(secs)
}

/// The civil year a unix timestamp falls in, UTC. Spelled out because
/// there is no chrono in the tree, and both the post year (from an NZB's
/// article dates) and the fallback need it.
pub fn year_of_unix(secs: i64) -> u32 {
    // Clamped because this loop is O(years) and its input is not ours: an
    // NZB's `date` attribute is parsed as a bare i64 with no bounds
    // (nzbkit::nzb), and post_year_of runs on the job-finalize path for
    // every completed download. `date="9223372036854775807"` is ~2.9e11
    // iterations, i.e. minutes of a pinned blocking-pool thread while
    // that job's rename, move and history record all wait behind it - and
    // the `year as u32` below would then truncate to nonsense anyway.
    // Nothing real sits outside 1970..=9999, and a caller handed 9999
    // treats it as the absurd year it is.
    const MAX_DAYS: i64 = (9999 - 1970 + 1) * 366;
    let days = secs.div_euclid(86_400).clamp(0, MAX_DAYS);
    let mut year = 1970i64;
    let mut left = days;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if left < len {
            break;
        }
        left -= len;
        year += 1;
    }
    year as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(source: &'static str, title: &str, year: u32, mins: u32) -> Candidate {
        Candidate {
            title: title.into(),
            year,
            runtime_min: mins,
            source,
            id: format!("{source}-{title}"),
        }
    }

    fn answered(window: Vec<Candidate>) -> SourceResult {
        SourceResult {
            window,
            answered: true,
        }
    }

    #[test]
    fn one_exact_survivor_in_one_source_is_reported_but_never_applied() {
        // The window holds neighbours; only one sits on the exact minute.
        // That is worth telling the user and is NOT worth renaming on -
        // see the module docs for the real file this rule comes from.
        let r = answered(vec![
            cand("wikidata", "Supergirl", 2026, 108),
            cand("wikidata", "Holland", 2025, 110),
            cand("wikidata", "Sunny Dancer", 2026, 106),
        ]);
        let v = decide(108, &[r]);
        assert_eq!(
            v,
            Verdict::Uncorroborated {
                title: "Supergirl".into(),
                year: 2026
            }
        );
        let o = Outcome {
            verdict: v,
            facts: String::new(),
            shortlist: vec![],
        };
        assert_eq!(
            o.accepted_name(),
            None,
            "an uncorroborated hit must not rename"
        );
        assert!(
            o.log_line().contains("Supergirl"),
            "but it must be reported"
        );
    }

    /// The measured false positive that made corroboration mandatory.
    ///
    /// Buster Keaton's The General (1926) measures 78.9 minutes in the
    /// transfer that exists, so 79. Wikidata publishes it at 75, so the
    /// right film is absent from the exact-minute set - and exactly one
    /// 1925-26 film IS in it, an unrelated Soviet picture. One source,
    /// one survivor, total confidence, wrong film.
    #[test]
    fn a_lone_catalogue_hit_on_the_wrong_film_does_not_rename() {
        let wd = answered(vec![
            cand("wikidata", "The Wings of a Serf", 1926, 79),
            cand("wikidata", "The General", 1926, 75),
        ]);
        let v = decide(79, &[wd]);
        assert!(
            !matches!(v, Verdict::Named { .. }),
            "a lone catalogue hit renamed The General to something else: {v:?}"
        );
        assert_eq!(
            Outcome {
                verdict: v,
                facts: String::new(),
                shortlist: vec![]
            }
            .accepted_name(),
            None
        );
    }

    #[test]
    fn two_films_on_the_same_minute_name_neither() {
        // The measured common case: exact runtime alone is not unique.
        // Precision over recall means this declines rather than guesses.
        let r = answered(vec![
            cand("wikidata", "Supergirl", 2026, 108),
            cand("wikidata", "Mountainhead", 2025, 108),
        ]);
        assert_eq!(decide(108, &[r]), Verdict::Ambiguous);
    }

    #[test]
    fn a_window_with_no_exact_match_names_nothing() {
        // Near misses are not matches. A catalogue runtime two minutes
        // off is a different cut, or a different film.
        let r = answered(vec![
            cand("wikidata", "Holland", 2025, 110),
            cand("wikidata", "Papers", 2025, 107),
        ]);
        assert_eq!(decide(108, &[r]), Verdict::Ambiguous);
        // An empty window is the same answer, reached sooner.
        assert_eq!(decide(108, &[answered(vec![])]), Verdict::Ambiguous);
    }

    #[test]
    fn two_sources_that_agree_are_what_accepts() {
        let wd = answered(vec![cand("wikidata", "Supergirl", 2026, 108)]);
        let tm = answered(vec![cand("tmdb", "Supergirl", 2026, 108)]);
        assert_eq!(
            decide(108, &[wd.clone(), tm]),
            Verdict::Named {
                title: "Supergirl".into(),
                year: 2026
            }
        );
        // Each source is certain, and they name different films. That is
        // the most dangerous shape this gate sees, and it must decline.
        let other = answered(vec![cand("tmdb", "Mountainhead", 2025, 108)]);
        assert_eq!(decide(108, &[wd.clone(), other]), Verdict::Ambiguous);
        // A second source that is itself ambiguous also blocks.
        let vague = answered(vec![
            cand("tmdb", "Supergirl", 2026, 108),
            cand("tmdb", "Shelter", 2026, 108),
        ]);
        assert_eq!(decide(108, &[wd, vague]), Verdict::Ambiguous);
    }

    /// A second source that could not be REACHED leaves the first one
    /// uncorroborated, not confirmed. The `answered` flag is what keeps
    /// an outage from reading as agreement.
    #[test]
    fn an_outage_cannot_stand_in_for_corroboration() {
        let wd = answered(vec![cand("wikidata", "Supergirl", 2026, 108)]);
        let dead = SourceResult {
            window: vec![],
            answered: false,
        };
        assert_eq!(
            decide(108, &[wd, dead]),
            Verdict::Uncorroborated {
                title: "Supergirl".into(),
                year: 2026
            }
        );
    }

    #[test]
    fn titles_that_differ_only_in_punctuation_still_agree() {
        let wd = answered(vec![cand("wikidata", "WALL-E", 2008, 98)]);
        let tm = answered(vec![cand("tmdb", "WALL·E", 2008, 98)]);
        assert!(matches!(decide(98, &[wd, tm]), Verdict::Named { .. }));
    }

    #[test]
    fn an_unreachable_source_is_silence_not_evidence() {
        // The whole point of the `answered` flag: a failed lookup must
        // not be counted as "nobody matched", and must not let a second
        // source's single hit stand as confirmed-by-two.
        let dead = SourceResult {
            window: vec![],
            answered: false,
        };
        assert_eq!(decide(108, std::slice::from_ref(&dead)), Verdict::NoSource);
        assert_eq!(decide(108, &[]), Verdict::NoSource);
        // ...and a live source beside a dead one is one source, so its
        // certainty is reported and not applied.
        let live = answered(vec![cand("tmdb", "Supergirl", 2026, 108)]);
        assert!(matches!(
            decide(108, &[dead, live]),
            Verdict::Uncorroborated { .. }
        ));
    }

    #[test]
    fn a_declining_verdict_never_yields_a_name() {
        // The one invariant the renamer depends on: no path out of an
        // ambiguous, sourceless or runtime-less outcome produces a
        // filename.
        for verdict in [
            Verdict::Ambiguous,
            Verdict::NoSource,
            Verdict::NoRuntime,
            Verdict::Uncorroborated {
                title: "Supergirl".into(),
                year: 2026,
            },
        ] {
            let o = Outcome {
                verdict,
                facts: "108 min".into(),
                shortlist: vec![],
            };
            assert_eq!(o.accepted_name(), None);
        }
        let named = Outcome {
            verdict: Verdict::Named {
                title: "Supergirl".into(),
                year: 2026,
            },
            facts: String::new(),
            shortlist: vec![],
        };
        assert_eq!(named.accepted_name().as_deref(), Some("Supergirl 2026"));
    }

    #[test]
    fn the_shortlist_merges_sources_and_is_capped() {
        let wd = answered(
            (0..20)
                .map(|i| cand("wikidata", &format!("Film {i:02}"), 2025, 108))
                .collect(),
        );
        let tm = answered(vec![cand("tmdb", "Film 00", 2025, 108)]);
        let list = shortlist(108, &[wd, tm]);
        assert_eq!(list.len(), SHORTLIST_MAX);
        // "Film 00" came from both catalogues and appears once.
        assert_eq!(list.iter().filter(|s| s.starts_with("Film 00")).count(), 1);
        // Ties on distance fall back to title, not to which source
        // answered first.
        assert!(list[0].starts_with("Film 00"));
    }

    /// The note's whole value is that its first few lines are the films
    /// worth reading. A window two minutes wide over two years holds
    /// dozens; ordered alphabetically the cap shows eight arbitrary
    /// ones, which is what the first real end-to-end run produced.
    #[test]
    fn the_shortlist_leads_with_the_closest_runtimes() {
        let r = answered(vec![
            cand("wikidata", "Aardvark", 2025, 110),
            cand("wikidata", "Zebra", 2025, 108),
            cand("wikidata", "Badger", 2025, 109),
            cand("wikidata", "Yak", 2025, 108),
        ]);
        let list = shortlist(108, &[r]);
        // Both exact matches first (alphabetically among themselves),
        // then one minute out, then two.
        assert!(list[0].starts_with("Yak"), "{list:?}");
        assert!(list[1].starts_with("Zebra"), "{list:?}");
        assert!(list[2].starts_with("Badger"), "{list:?}");
        assert!(list[3].starts_with("Aardvark"), "{list:?}");
    }

    #[test]
    fn a_non_feature_runtime_never_reaches_a_catalogue() {
        // A sample clip must not spend an API call, and must not be
        // renamed off a two-minute "runtime".
        let facts = nzbkit::media::MediaFacts {
            duration_secs: Some(95.0),
            ..nzbkit::media::MediaFacts::default()
        };
        let o = identify(&facts, 2026, None);
        assert_eq!(o.verdict, Verdict::NoRuntime);
        assert_eq!(o.accepted_name(), None);
        assert!(o.shortlist.is_empty());
    }

    #[test]
    fn the_sparql_narrows_by_language_only_when_one_was_asserted() {
        let q = wikidata_sparql((2025, 2026), 108, Some("en"));
        assert!(q.contains("?lang wdt:P218 \"en\""));
        // The window is the query's, +/-2 either side of the file.
        assert!(q.contains("?mins >= 106.0 && ?mins <= 110.0"));
        assert!(q.contains("?y >= 2025 && ?y <= 2026"));
        // The `mul` label migration: an en-only filter loses films whose
        // label moved to the pseudo-language.
        assert!(q.contains("\"en\", \"mul\""));
        // No assertion, no filter - the candidate set stays wider rather
        // than being narrowed by a guess.
        assert!(!wikidata_sparql((2025, 2026), 108, None).contains("P218"));
        // Nothing but a two-letter lowercase code can reach the query
        // text, so no value this module produces can alter its shape.
        for hostile in ["\" . ?x ?y ?z . #", "en\"", "EN", "eng", ""] {
            assert!(
                !wikidata_sparql((2025, 2026), 108, Some(hostile)).contains("P218"),
                "{hostile:?} must not reach the query"
            );
        }
    }

    #[test]
    fn the_facts_line_says_what_the_file_said() {
        let facts = nzbkit::media::MediaFacts {
            container: "mkv",
            duration_secs: Some(6480.0),
            width: Some(1920),
            height: Some(1080),
            // A payload that HAS a container Title never reaches this
            // module - `crate::identity` reads it first and names the
            // release off it, and `nameless_video` then finds nothing to
            // rename. None is the only state this ladder ever sees.
            title: None,
            video_codec: Some("h264".into()),
            audio_codecs: vec!["eac3".into()],
            audio_langs: vec!["en".into()],
            sub_langs: vec!["en".into(), "fr".into()],
        };
        assert_eq!(
            render_facts(&facts),
            "108 min, 1080p, h264, eac3, audio en, subs en fr"
        );
        assert_eq!(render_facts(&nzbkit::media::MediaFacts::default()), "");
    }

    #[test]
    fn the_year_helper_tracks_the_civil_calendar() {
        // The daemon has no chrono, so this arithmetic is ours. Pinned
        // at the boundaries a leap-year bug would move.
        assert_eq!(year_of_unix(0), 1970);
        assert_eq!(year_of_unix(946_684_799), 1999); // 1999-12-31 23:59:59Z
        assert_eq!(year_of_unix(946_684_800), 2000); // 2000-01-01 00:00:00Z
        assert_eq!(year_of_unix(1_709_164_800), 2024); // 2024-02-29, a leap day
        assert_eq!(year_of_unix(1_767_225_599), 2025); // 2025-12-31 23:59:59Z
        assert_eq!(year_of_unix(1_767_225_600), 2026);
        assert!(current_year() >= 2026);
    }

    #[test]
    fn a_query_string_cannot_escape_its_parameter() {
        let e = percent_encode("SELECT ?x WHERE { # &=+/ }");
        assert!(!e.contains(['&', '#', '=', '+', ' ', '?']));
        assert_eq!(percent_encode("aZ09-_.~"), "aZ09-_.~");
    }
}
