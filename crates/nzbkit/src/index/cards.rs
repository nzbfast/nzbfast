//! The card grid (TODO 106 phase 2.2, cut 3): Card/CardSort/AffinityCtx,
//! the card SQL fragments, `browse_cards` and the wall tip. Bodies are
//! verbatim moves from the old index.rs.

use super::query::fts_match;
use super::*;

/// Answer to "has anything landed on the wall since I last looked?".
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TipInfo {
    /// Newest `first_seen` in the index - the client hands this back as
    /// `since` next poll, so the window never drifts against clock skew
    /// between the browser and the daemon.
    pub latest: i64,
    /// Distinct wall-visible titles newer than `since`.
    pub new_keys: u32,
    /// Up to `limit` of those keys, newest first, so arriving cards can
    /// be marked without re-deriving which ones they were.
    pub keys: Vec<String>,
}

/// M28: one poster-grid card - a title_key group's aggregates joined to
/// its cached metadata (titles table), built entirely in SQL so the
/// wall pages instead of materializing the whole index per load.
#[derive(Debug, Clone)]
pub struct Card {
    pub title_key: String,
    /// Representative kind ("movie"/"tv"/…).
    pub kind: String,
    /// Release count grouped under this card.
    pub n_releases: u32,
    pub latest_posted: i64,
    pub any_complete: bool,
    pub max_bytes: u64,
    /// Best resolution seen ("2160p" > "1080p" > …; '' = unknown).
    pub best_res: String,
    /// Newest stem in the group (fallback display name for unmatched
    /// cards; also what the detail sheet parses for title/year).
    pub rep_stem: String,
    /// The newest release's newsgroup - the M29 oracle verdict keys off
    /// its group family.
    pub rep_grp: String,
    // Joined titles metadata ('' / 0 until the enricher lands it).
    pub title: String,
    pub year: u32,
    pub rating: f64,
    pub genres: String,
    pub overview: String,
    pub poster_art: String,
    pub backdrop_art: String,
    pub checked: i64,
    pub actors: String,
    /// Enriched release / first-air date, ISO `YYYY-MM-DD` ('' = unknown).
    pub air_date: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardSort {
    /// Latest upload in the group (the wall default).
    Latest,
    /// Newest to THIS index - when we first saw it, not when it was
    /// uploaded. The two come apart more than they look: a release's
    /// posted time is its FIRST article's, so a set that only finishes
    /// arriving now can be hours old and sorts nowhere near the top
    /// under Latest. Measured on a live scratch index, releases the tip
    /// watcher had just picked up sat past position 400 of 5,718. This
    /// is the order the "new arrivals" pill sends you to, and on its own
    /// it answers "what showed up while I was away".
    Arrived,
    Rating,
    Title,
    /// Group release count (how actively posted).
    Releases,
    Size,
    /// Original release year (enriched year, falling back to the year
    /// baked into a movie parse key) - "original date" vs Latest's
    /// upload date.
    Year,
    /// Full release / first-air date, to the day. Answers "what actually
    /// came out this week", which Year can only answer to the year and
    /// Latest confuses with re-uploads of old titles. Falls back to the
    /// card's year for rows enriched before air_date existed (or whose
    /// provider had no date), so nothing sinks for lack of metadata.
    Aired,
    /// M31b "your wall": rank by a weighted match against the user's
    /// demonstrated taste (see AffinityCtx). Falls back to Releases when
    /// no profile is supplied (cold start).
    Affinity,
}

impl CardSort {
    pub fn parse(s: &str) -> CardSort {
        match s {
            "arrived" => CardSort::Arrived,
            "rating" => CardSort::Rating,
            "title" => CardSort::Title,
            "releases" => CardSort::Releases,
            "size" => CardSort::Size,
            "year" => CardSort::Year,
            "aired" => CardSort::Aired,
            "affinity" => CardSort::Affinity,
            _ => CardSort::Latest,
        }
    }
}

/// M31b: the taste inputs `browse_cards` scores an Affinity sort against.
/// Built daemon-side from the user's completed history + watchlist; the
/// weights are pre-scaled so a strong genre/kind/decade match outranks a
/// weak one and owned titles sink below everything.
#[derive(Debug, Clone, Default)]
pub struct AffinityCtx {
    /// (genre substring, weight) - the profile's top genres, weight
    /// already scaled for the ORDER BY. Matched with a `LIKE '%g%'`
    /// against the enriched `titles.genres` list.
    pub genres: Vec<(String, f32)>,
    /// (favoured kind "tv"/"movie", weight), or None if undetermined.
    pub fav_kind: Option<(String, f32)>,
    /// Weighted-mean release year of the taste set, or None.
    pub decade_center: Option<i32>,
    /// Weight applied when a card's year sits within +/-10 of the centre.
    pub decade_weight: f32,
    /// title_keys the user already owns (completed history + queue).
    /// These sink to the bottom - "more like this, but you have it" -
    /// rather than being hidden.
    pub owned: std::collections::HashSet<String>,
}

impl AffinityCtx {
    /// Nothing to rank by (no genres, kind, or decade) - the caller
    /// should treat this like a cold start.
    pub fn is_empty(&self) -> bool {
        self.genres.is_empty() && self.fav_kind.is_none() && self.decade_center.is_none()
    }
}

/// Resolution as a sortable rank. `res` is TEXT, so ordering the column
/// itself is lexicographic: descending gives 720p, 480p, 2160p, 1080p,
/// putting 720p above 4K. Anything that wants "best encode first" has to
/// rank it. Unknown ('') sorts below every real resolution rather than
/// above it, so a blank never leads a category.
///
/// Used by `browse`'s Category sort. The wall's card query needs the
/// same ranking but wraps it in `MAX(...)` over an aliased row, so it
/// spells it out separately - keep the two in step if the vocabulary
/// ever gains a resolution.
pub(super) const RES_RANK_SQL: &str = "CASE res WHEN '2160p' THEN 4 WHEN '1080p' THEN 3
                                     WHEN '720p' THEN 2 WHEN '' THEN 0 ELSE 1 END";

/// M30: a card's original year in SQL - enriched year first, else the
/// ":YYYY" suffix a movie parse key carries. Shared by the Year sort
/// and the decade-range filter.
const CARD_YEAR_SQL: &str = "COALESCE(NULLIF(t.year,0),
    CASE WHEN r.title_key GLOB 'm:*:[0-9][0-9][0-9][0-9]'
         THEN CAST(substr(r.title_key,-4) AS INTEGER) ELSE 0 END)";

/// Sort key for the to-the-day release-date sort. ISO dates order
/// chronologically as plain strings, so a card with only a year is padded
/// to "YYYY-00-00": it sorts alongside its year but beneath every dated
/// card in it, which is the honest position for "sometime that year".
/// Unknown-year rows become "0000-00-00" and sink (or lead, ascending).
fn card_aired_sql() -> String {
    format!(
        "CASE WHEN COALESCE(t.air_date,'') <> '' THEN t.air_date
              ELSE printf('%04d-00-00', {CARD_YEAR_SQL}) END"
    )
}

impl Index {
    /// M28: the poster grid's data, paged in SQL. Groups releases by
    /// their stored parse key, joins each group to its cached metadata,
    /// and returns (cards, total groups) - the wall no longer
    /// materializes the whole index per load. `matched_only` keeps only
    /// cards whose enrichment landed art (the wall's default toggle).
    pub(super) fn browse_cards_once(
        &self,
        q: &BrowseQuery,
        sort: CardSort,
        matched_only: bool,
        // M30: cluster by kind (tv/movie/apps/other) with `sort` as the
        // within-category sub-sort.
        group_by_kind: bool,
        // M31b: taste inputs for the Affinity sort (ignored by every other
        // sort). None on cold start -> Affinity degrades to Releases.
        affinity: Option<&AffinityCtx>,
    ) -> rusqlite::Result<(Vec<Card>, u64)> {
        // Per-release predicates are written with `{}` where the releases
        // alias goes, the same way browse() does: the page renders them
        // against `r.`, and the representative subqueries at the bottom
        // render the SAME list against their own alias `s.`. A card's
        // rep_stem / rep_grp would otherwise be taken from the title's
        // newest release even when this view excludes it - an obfuscated
        // junk stem driving the parse and the enrichment seed, a "have"
        // badge keyed on the wrong dupe, an oracle verdict computed for a
        // group the page filtered out. Both renderings cite the same ?N,
        // so nothing below has to renumber.
        let mut wheres: Vec<String> = vec!["{}title_key != ''".into()];
        // Title-level predicates (the `titles` join, and the year
        // expression built on it): constant for every release sharing a
        // title_key, so repeating them inside the per-title subquery would
        // buy nothing. They stay out of the aliased list.
        let mut title_wheres: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let bind = |params: &mut Vec<Box<dyn rusqlite::ToSql>>, v: Box<dyn rusqlite::ToSql>| {
            params.push(v);
            format!("?{}", params.len())
        };
        let alias = |wheres: &[String], pfx: &str| {
            wheres
                .iter()
                .map(|w| w.replace("{}", pfx))
                .collect::<Vec<_>>()
                .join(" AND ")
        };
        if let Some(kind) = &q.kind {
            let p = bind(&mut params, Box::new(kind.clone()));
            wheres.push(format!("{{}}kind = {p}"));
        }
        if let Some(res) = &q.res {
            let p = bind(&mut params, Box::new(res.clone()));
            wheres.push(format!("{{}}res = {p}"));
        }
        if q.complete_only {
            wheres.push("{}complete".into());
        }
        if q.min_bytes > 0 {
            let p = bind(&mut params, Box::new(q.min_bytes as i64));
            wheres.push(format!("{{}}total_bytes >= {p}"));
        }
        if q.newer_than > 0 {
            let p = bind(&mut params, Box::new(q.newer_than));
            wheres.push(format!("{{}}first_posted >= {p}"));
        }
        if let Some(max) = q.max_junk {
            let p = bind(&mut params, Box::new(max as i64));
            wheres.push(format!("{{}}junk < {p}"));
        }
        // 24C: exact-card fetch. The Releases surface asks for ONE
        // title's card (hover preview, group-by-title header row) by
        // its stored parse key instead of re-deriving it from a page
        // query - same field browse() already honors.
        if !q.title_keys.is_empty() {
            let ps: Vec<String> = q
                .title_keys
                .iter()
                .map(|tk| bind(&mut params, Box::new(tk.clone())))
                .collect();
            wheres.push(format!("{{}}title_key IN ({})", ps.join(", ")));
        }
        // The people leg. Release stems are all the FTS index covers, so
        // "tom cruise" used to find nothing at all unless a filename
        // happened to say it. A title credited to a matching person is
        // just as much a hit as one whose stem matches, hence OR rather
        // than a separate query - one search box, one result set.
        let people_m = if self.people_fts && q.title_keys.is_empty() {
            fts_match(&q.q)
        } else {
            String::new()
        };
        let people_leg = |params: &mut Vec<Box<dyn rusqlite::ToSql>>| -> String {
            if people_m.is_empty() {
                return String::new();
            }
            params.push(Box::new(people_m.clone()));
            let n = params.len();
            format!(
                " OR {{}}title_key IN (SELECT tp.key FROM title_people tp
                    WHERE tp.person_id IN
                          (SELECT rowid FROM people_fts WHERE people_fts MATCH ?{n}))"
            )
        };
        let fts_m = if self.fts {
            fts_match(&q.q)
        } else {
            String::new()
        };
        if !fts_m.is_empty() {
            let p = bind(&mut params, Box::new(fts_m));
            let leg = people_leg(&mut params);
            wheres.push(format!(
                "({{}}id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH {p}){leg})"
            ));
        } else if !q.q.trim().is_empty() {
            const NS: &str = "REPLACE(REPLACE(REPLACE(LOWER({}stem),'.',' '),'_',' '),'-',' ')";
            // Every term must appear in the stem - but a people match
            // satisfies the whole query at once, so it wraps the lot
            // rather than being ANDed in term by term.
            let mut terms: Vec<String> = Vec::new();
            for term in
                q.q.to_ascii_lowercase()
                    .replace(['.', '_', '-'], " ")
                    .split_whitespace()
            {
                let p = bind(&mut params, Box::new(term.to_string()));
                terms.push(format!("{NS} LIKE '%' || {p} || '%'"));
            }
            if !terms.is_empty() {
                let leg = people_leg(&mut params);
                let joined = terms.join(" AND ");
                wheres.push(format!("(({joined}){leg})"));
            }
        }
        if matched_only {
            // LEFT JOIN NULLs fail both predicates, so unmatched groups
            // drop out here too.
            title_wheres.push("t.checked > 0 AND t.poster != ''".into());
        }
        // M30: genre chip filter - substring over the enriched genre
        // list ("Drama, Comedy"); unenriched cards drop out while a
        // chip is active (their genre is unknown).
        if let Some(g) = q.genre.as_deref().filter(|g| !g.trim().is_empty()) {
            let p = bind(&mut params, Box::new(g.trim().to_string()));
            title_wheres.push(format!("t.genres LIKE '%' || {p} || '%'"));
        }
        // Adult titles, when the caller asked for them to be left out.
        //
        // The vocabulary is deliberately NARROW, and grounded in what the
        // providers actually write rather than in what sounds right. Two
        // tokens are unambiguous wherever they appear ("Hentai",
        // "Erotic"). "Adult" is NOT: TVmaze hands it out alongside
        // ordinary genres, and a bare substring test on it hides
        // `Married With Children` ("Comedy, Family, Adult"), which is a
        // mainstream sitcom. So it only counts when it stands alone -
        // which is exactly how the genuinely adult titles carry it.
        //
        // Errs towards SHOWING: a title tagged "Adult, Romance" slips
        // through. That is the right way round - wrongly hiding a show
        // the user owns is a bug they will report, wrongly showing one
        // is a chip away.
        if q.hide_adult {
            title_wheres.push(ADULT_GENRE_SQL.to_string());
            // The spot-born marker (TODO 131), which is a RELEASE-level
            // fact rather than a title-level one: the poster of this
            // post filed it as adult, and the card may have no enriched
            // title behind it to carry a genre. A card whose releases
            // are all marked drops out entirely (every row fails the
            // predicate, so the title_key never reaches the GROUP BY);
            // one marked release beside unmarked ones only loses that
            // release, which is the same way the curation rules behave
            // and the same "errs towards showing" direction as the
            // genre test above.
            wheres.push(ADULT_MARK_SQL.into());
        }
        // M30: decade chips - original-year range over the same
        // enriched-year-with-parse-key-fallback expression the Year
        // sort uses.
        if q.year_min > 0 {
            let p = bind(&mut params, Box::new(q.year_min as i64));
            title_wheres.push(format!("{CARD_YEAR_SQL} >= {p}"));
        }
        if q.year_max > 0 {
            let p = bind(&mut params, Box::new(q.year_max as i64));
            title_wheres.push(format!("{CARD_YEAR_SQL} <= {p} AND {CARD_YEAR_SQL} > 0"));
        }
        // M30: user curation (hides + rules). Rules filter individual
        // releases pre-GROUP BY, so a card only disappears when every
        // one of its releases is excluded (a German dub next to an
        // English encode never hides the whole title). It already takes
        // the alias as an argument, so the placeholder passes straight
        // through and the rules reach the representative pick too.
        if q.curated {
            self.curation_wheres("{}", &mut wheres, &mut params)?;
        }
        // The representative pick: the same per-release predicates,
        // re-rendered against the subquery's alias. `wheres` is never
        // empty (it is seeded with the title_key test), so the AND always
        // has a left side.
        let rep_where = alias(&wheres, "s.");
        let where_clause = {
            let mut all = alias(&wheres, "r.");
            for w in &title_wheres {
                all.push_str(" AND ");
                all.push_str(w);
            }
            all
        };
        // The COUNT runs on the WHERE params ALONE, so it must happen
        // before the Affinity ORDER BY binds any of its own params (those
        // belong to the paged query only).
        let total: u64 = self
            .db
            .query_row(
                &format!(
                    "SELECT COUNT(DISTINCT r.title_key)
                     FROM releases r LEFT JOIN titles t ON t.key = r.title_key
                     WHERE {where_clause}"
                ),
                rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)?;
        // Fixed vocabulary - never user text. Direction is the caller's
        // call (the API defaults title→asc, everything else→desc).
        let key: String = match sort {
            CardSort::Latest => "latest".into(),
            CardSort::Arrived => "MAX(r.first_seen)".into(),
            CardSort::Rating => "COALESCE(t.rating, 0)".into(),
            CardSort::Title => "COALESCE(NULLIF(t.title,''), r.title_key) COLLATE NOCASE".into(),
            CardSort::Releases => "n".into(),
            CardSort::Size => "max_bytes".into(),
            // Enriched year first; movies without metadata still carry
            // their year in the parse key's ":YYYY" suffix.
            CardSort::Year => CARD_YEAR_SQL.into(),
            CardSort::Aired => card_aired_sql(),
            // M31b: weighted taste match. Cold start (no/empty profile)
            // degrades to Releases ("most posted") so the option is still
            // useful before any signal exists.
            CardSort::Affinity => match affinity.filter(|a| !a.is_empty()) {
                None => "n".into(),
                Some(aff) => {
                    let mut terms: Vec<String> = Vec::new();
                    for (g, w) in &aff.genres {
                        let pg = bind(&mut params, Box::new(g.clone()));
                        // COALESCE: an unmatched card (LEFT JOIN miss) has
                        // NULL genres, and `NULL LIKE .. * w` is NULL, which
                        // would nullify the WHOLE score sum (dropping the
                        // kind/decade signal for that card). Mirror the
                        // COALESCE the SELECT projection already uses.
                        terms.push(format!(
                            "(COALESCE(t.genres,'') LIKE '%' || {pg} || '%') * {w:.5}"
                        ));
                    }
                    if let Some((k, w)) = &aff.fav_kind {
                        let pk = bind(&mut params, Box::new(k.clone()));
                        terms.push(format!("(MAX(r.kind) = {pk}) * {w:.5}"));
                    }
                    if let Some(centre) = aff.decade_center {
                        terms.push(format!(
                            "(CASE WHEN {CARD_YEAR_SQL} BETWEEN {} AND {} \
                             THEN 1 ELSE 0 END) * {:.5}",
                            centre - 10,
                            centre + 10,
                            aff.decade_weight
                        ));
                    }
                    // Sink what you already own beneath every ranked card
                    // (the -1000 swamps the largest possible positive
                    // score) without hiding it.
                    if !aff.owned.is_empty() {
                        // Cap the IN(...) list: each owned key is one bound
                        // parameter and SQLite hard-limits a statement to
                        // 32766 variables - an install with more completed
                        // downloads than that would make prepare() fail and
                        // silently break the whole "For you" sort. The cap
                        // is far above any real library; the demotion is a
                        // soft "you have it" nudge, so dropping a few is
                        // harmless.
                        const OWNED_IN_CAP: usize = 10_000;
                        let ph: Vec<String> = aff
                            .owned
                            .iter()
                            .take(OWNED_IN_CAP)
                            .map(|k| bind(&mut params, Box::new(k.clone())))
                            .collect();
                        terms.push(format!("(r.title_key IN ({})) * -1000.0", ph.join(",")));
                    }
                    format!("({})", terms.join(" + "))
                }
            },
        };
        let dir = if q.desc { "DESC" } else { "ASC" };
        // M30: category grouping - a fixed kind order leads the sort so
        // the grid clusters TV / movies / the rest, and the chosen key
        // becomes the within-category sub-sort. The client draws section
        // headers where the kind changes.
        // Custom categories (any kind that is none of the built-in
        // ones) cluster after music and books, each custom kind
        // contiguous (the MAX(r.kind) tiebreak) so the client's
        // header-on-change rendering draws one section per category.
        let group_prefix = if group_by_kind {
            "CASE MAX(r.kind) WHEN 'tv' THEN 0 WHEN 'movie' THEN 1
                              WHEN 'music' THEN 2 WHEN 'book' THEN 3
                              WHEN 'software' THEN 5
                              WHEN 'other' THEN 6 ELSE 4 END ASC,
             MAX(r.kind) ASC, "
        } else {
            ""
        };
        // The two representative subqueries carry an IDENTICAL predicate
        // list and an identical, fully deterministic ORDER BY (the id
        // tiebreak settles same-second posts), so rep_stem and rep_grp
        // can never come from two different rows.
        let sql = format!(
            "SELECT r.title_key, MAX(r.kind), COUNT(*) AS n,
                    MAX(r.first_posted) AS latest, MAX(r.complete),
                    MAX(r.total_bytes) AS max_bytes,
                    MAX(CASE r.res WHEN '2160p' THEN 4 WHEN '1080p' THEN 3
                                   WHEN '720p' THEN 2 WHEN '' THEN 0 ELSE 1 END),
                    -- The fed name when the pre feed supplied one: the
                    -- representative is what drives the card's parse and
                    -- the enrichment seed, and seeding those from a
                    -- random stem when we hold the real title would
                    -- throw the answer away at the last step.
                    (SELECT COALESCE(NULLIF(s.pre_title,''), s.stem) FROM releases s
                      WHERE s.title_key = r.title_key AND {rep_where}
                      ORDER BY s.first_posted DESC, s.id DESC LIMIT 1),
                    (SELECT s.grp FROM releases s
                      WHERE s.title_key = r.title_key AND {rep_where}
                      ORDER BY s.first_posted DESC, s.id DESC LIMIT 1),
                    COALESCE(t.title,''), COALESCE(t.year,0), COALESCE(t.rating,0),
                    COALESCE(t.genres,''), COALESCE(t.overview,''),
                    COALESCE(t.poster,''), COALESCE(t.backdrop,''),
                    COALESCE(t.checked,0), COALESCE(t.actors,''),
                    COALESCE(t.air_date,'')
             FROM releases r LEFT JOIN titles t ON t.key = r.title_key
             WHERE {where_clause}
             GROUP BY r.title_key
             ORDER BY {group_prefix}{key} {dir}, latest DESC
             LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Box::new(q.limit.min(500)));
        params.push(Box::new(q.offset));
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
            |r| {
                Ok(Card {
                    title_key: r.get(0)?,
                    kind: r.get(1)?,
                    n_releases: r.get(2)?,
                    latest_posted: r.get(3)?,
                    any_complete: r.get(4)?,
                    max_bytes: r.get::<_, i64>(5)? as u64,
                    best_res: match r.get::<_, i64>(6)? {
                        4 => "2160p",
                        3 => "1080p",
                        2 => "720p",
                        _ => "",
                    }
                    .to_string(),
                    rep_stem: r.get(7)?,
                    rep_grp: r.get(8)?,
                    title: r.get(9)?,
                    year: r.get::<_, i64>(10)? as u32,
                    rating: r.get(11)?,
                    genres: r.get(12)?,
                    overview: r.get(13)?,
                    poster_art: r.get(14)?,
                    backdrop_art: r.get(15)?,
                    checked: r.get(16)?,
                    actors: r.get(17)?,
                    air_date: r.get(18)?,
                })
            },
        )?;
        Ok((rows.collect::<rusqlite::Result<_>>()?, total))
    }

    // ---- M30 wall curation: hides, rules, suggestions ----------------

    /// What has landed on the wall since `since` - the poll behind the
    /// "N new" pill. Deliberately cheap: the wall's own query is far too
    /// expensive to run every few seconds just to find out whether
    /// anything changed, so this answers only that question and the real
    /// fetch happens when the answer is yes.
    ///
    /// An arrival is BOTH inserted after the caller's persistent sequence
    /// cursor (`arrival_seq > since`) AND recently posted
    /// (`first_posted > posted_after`).
    /// The cursor cannot be `first_seen`: it has whole-second resolution,
    /// so a release inserted later in the same second as the prior poll
    /// would otherwise be skipped forever. Both halves are load-
    /// bearing, and getting this wrong is what live-testing caught:
    ///
    /// - `first_seen` alone counts the history deepen leg's finds. Those
    ///   are new to the index but they are years-old uploads, so the
    ///   pill cries wolf every backfill pass.
    /// - Worse, it cries wolf *invisibly*: the wall's default sort is by
    ///   posted date, so a decade-old upload the pill just announced sits
    ///   thousands of cards down. Clicking "4 new arrivals" showed a wall
    ///   with nothing new on it. Requiring recent `first_posted` means an
    ///   announced arrival is always near the top where the user is
    ///   looking.
    ///
    /// Curation-aware to the same degree as the default wall: junk and
    /// explicitly-hidden titles never count. Learned `wall_rules` are
    /// NOT applied - they need the browse path's whole filter machinery,
    /// and over-counting a badge by a rule-hidden title is a far smaller
    /// sin than making this poll expensive.
    pub fn wall_tip(&self, since: i64, posted_after: i64, limit: u32) -> rusqlite::Result<TipInfo> {
        // Read the persistent counter, not MAX(releases.arrival_seq).
        // Eviction can empty the table; the next inserted release must
        // still advance beyond a browser's zero/current cursor.
        let latest: i64 = self
            .db
            .query_row(
                "SELECT COALESCE(
                    (SELECT CAST(v AS INTEGER) FROM kv WHERE k='wall_arrival_seq'), 0
                 )",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        // INDEXED BY, because the planner gets this one wrong and the
        // cost is the whole table. `arrival_seq > ?1` is the selective
        // term by orders of magnitude - a poll asks about the handful of
        // releases since the browser's cursor - but both statements
        // below also want DISTINCT/GROUP BY on title_key, and SQLite
        // prefers the index that satisfies THAT to the one that reduces
        // the row count, then filters the arrivals out row by row.
        // Measured 2 Aug on the 32M-release live index: 76s per poll for
        // an answer of zero, against 6ms with the arrival index forced -
        // and still 16x better at `since=0`, where the range matches
        // everything and the forced plan is at its worst. The index has
        // been there since M28 (see `open`); nothing but the hint was
        // missing. It is created unconditionally, so this cannot fail
        // for want of it.
        const VISIBLE: &str = "arrival_seq > ?1 AND first_posted > ?2
             AND junk < 50 AND title_key <> ''
             AND title_key NOT IN (SELECT key FROM wall_hidden)";
        let new_keys: u32 = self.db.query_row(
            &format!(
                "SELECT COUNT(*) FROM (SELECT DISTINCT title_key
                   FROM releases INDEXED BY idx_rel_arrival WHERE {VISIBLE})"
            ),
            [since, posted_after],
            |r| r.get(0),
        )?;
        let mut stmt = self.db.prepare(&format!(
            "SELECT title_key FROM releases INDEXED BY idx_rel_arrival WHERE {VISIBLE}
             GROUP BY title_key ORDER BY MAX(arrival_seq) DESC LIMIT ?3"
        ))?;
        let keys = stmt
            .query_map(rusqlite::params![since, posted_after, limit], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(TipInfo {
            latest,
            new_keys,
            keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{dated_entry, entry, teardown};

    /// The to-the-day release-date sort: dated cards order by their full
    /// date, and a card with only a year sits below every dated card in
    /// that same year rather than sinking to the bottom of the wall.
    #[test]
    fn cards_aired_sort_orders_by_day_then_falls_back_to_year() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-aired-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Undated.Film.2026.1080p.WEB.x264-GRP.mkv", "a@a", "g1"),
                mk("July.Film.2026.1080p.WEB.x264-GRP.mkv", "b@b", "g2"),
                mk("January.Film.2026.1080p.WEB.x264-GRP.mkv", "c@c", "g3"),
                mk("Ancient.Film.1994.1080p.BluRay.x264-GRP.mkv", "d@d", "g4"),
            ],
            1_000,
        )
        .unwrap();
        for (key, title, date) in [
            ("m:july film:2026", "July Film", "2026-07-20"),
            ("m:january film:2026", "January Film", "2026-01-05"),
        ] {
            ix.title_seed(key, "movie", title, 2026).unwrap();
            ix.title_fill(
                key,
                &TitleFill {
                    air_date: date,
                    ..Default::default()
                },
                1,
            )
            .unwrap();
        }
        let q = BrowseQuery {
            desc: true,
            ..Default::default()
        };
        let (cards, _) = ix
            .browse_cards(&q, CardSort::Aired, false, false, None)
            .unwrap();
        let keys: Vec<&str> = cards.iter().map(|c| c.title_key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "m:july film:2026",
                "m:january film:2026",
                "m:undated film:2026",
                "m:ancient film:1994",
            ],
            "{cards:?}"
        );
        // The date rides along on the card so the UI can show it.
        assert_eq!(cards[0].air_date, "2026-07-20");
        assert!(cards[2].air_date.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cards_group_by_kind_year_sort_and_genre_filter() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-grp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Old.Film.1994.1080p.BluRay.x264-GRP.mkv", "a@a", "g1"),
                mk("New.Film.2026.1080p.WEB.x264-GRP.mkv", "b@b", "g2"),
                mk("Some.Show.S01E01.1080p.WEB.x264-GRP.mkv", "c@c", "g3"),
            ],
            1_000,
        )
        .unwrap();
        // Grouped: TV cluster leads, movies follow; Year sub-sort puts
        // the newer film first inside its cluster (parse-key fallback -
        // nothing is enriched here).
        let q = BrowseQuery {
            desc: true,
            ..Default::default()
        };
        let (cards, _) = ix
            .browse_cards(&q, CardSort::Year, false, true, None)
            .unwrap();
        let kinds: Vec<&str> = cards.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["tv", "movie", "movie"], "{cards:?}");
        assert!(cards[1].title_key.contains("2026"), "{cards:?}");
        assert!(cards[2].title_key.contains("1994"), "{cards:?}");
        // Genre filter: nothing enriched → everything drops out.
        let gq = BrowseQuery {
            genre: Some("Drama".into()),
            ..Default::default()
        };
        let (_, total) = ix
            .browse_cards(&gq, CardSort::Latest, false, false, None)
            .unwrap();
        assert_eq!(total, 0);
        // Enrich one row with a genre and it comes back.
        ix.title_seed("m:new film:2026", "movie", "New Film", 2026)
            .unwrap();
        ix.db
            .execute(
                "UPDATE titles SET genres='Drama, Thriller', checked=1
                 WHERE key='m:new film:2026'",
                [],
            )
            .unwrap();
        let (cards, total) = ix
            .browse_cards(&gq, CardSort::Latest, false, false, None)
            .unwrap();
        assert_eq!(total, 1, "{cards:?}");
        assert_eq!(cards[0].title_key, "m:new film:2026");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The adult filter hides what it should and, more importantly,
    /// does NOT hide what it should not.
    ///
    /// "Adult" is a genre TVmaze hands out alongside ordinary ones, so a
    /// bare substring test on it hides `Married With Children`
    /// ("Comedy, Family, Adult") - a mainstream sitcom. It only counts
    /// when it stands alone, which is how the genuinely adult titles in
    /// a real index carry it. An unenriched title has no genres at all
    /// and must survive: an unknown genre is not evidence of anything.
    #[test]
    fn the_adult_filter_spares_a_sitcom_tagged_adult() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-adult-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk(
                    "Married With Children.2001.1080p.WEB.x264-GRP.mkv",
                    "a@a",
                    "a1",
                ),
                mk("All About Sex.2002.1080p.WEB.x264-GRP.mkv", "b@b", "a2"),
                mk("Some Anime.2003.1080p.WEB.x264-GRP.mkv", "c@c", "a3"),
                mk("Unenriched Film.2004.1080p.WEB.x264-GRP.mkv", "d@d", "a4"),
            ],
            1_000,
        )
        .unwrap();
        for (key, genres) in [
            ("m:married with children:2001", "Comedy, Family, Adult"),
            ("m:all about sex:2002", "Adult"),
            ("m:some anime:2003", "Hentai"),
        ] {
            ix.title_seed(key, "movie", "T", 2001).unwrap();
            ix.db
                .execute(
                    "UPDATE titles SET genres=?2, checked=1 WHERE key=?1",
                    rusqlite::params![key, genres],
                )
                .unwrap();
        }
        let titles = |hide_adult: bool| -> Vec<String> {
            let (cards, _) = ix
                .browse_cards(
                    &BrowseQuery {
                        curated: true,
                        hide_adult,
                        limit: 50,
                        ..Default::default()
                    },
                    CardSort::Title,
                    false,
                    false,
                    None,
                )
                .unwrap();
            cards.into_iter().map(|c| c.title_key).collect()
        };
        let off = titles(false);
        assert_eq!(off.len(), 4, "nothing is filtered when it is off: {off:?}");

        let on = titles(true);
        assert!(
            on.iter().any(|k| k == "m:married with children:2001"),
            "a sitcom tagged Adult beside Comedy and Family must survive: {on:?}"
        );
        assert!(
            on.iter().any(|k| k == "m:unenriched film:2004"),
            "an unenriched title has no genres and must survive: {on:?}"
        );
        assert!(
            !on.iter().any(|k| k == "m:all about sex:2002"),
            "Adult standing alone is the real thing: {on:?}"
        );
        assert!(
            !on.iter().any(|k| k == "m:some anime:2003"),
            "Hentai is unambiguous wherever it appears: {on:?}"
        );

        // The SAME expectations through the flat release list. The
        // filter lived only in the card query, so switching
        // group-by-title off was a way round the setting: every
        // Adult/Hentai release came back.
        let flat = |hide_adult: bool| -> Vec<String> {
            let (rows, total) = ix
                .browse(&BrowseQuery {
                    curated: true,
                    hide_adult,
                    limit: 50,
                    ..Default::default()
                })
                .unwrap();
            // `total` drives the pager, so it has to agree with the page.
            assert_eq!(total as usize, rows.len(), "total disagrees with the page");
            rows.into_iter().map(|r| r.stem).collect()
        };
        let has = |v: &[String], needle: &str| v.iter().any(|s| s.to_lowercase().contains(needle));
        let off = flat(false);
        assert_eq!(off.len(), 4, "nothing is filtered when it is off: {off:?}");
        let on = flat(true);
        assert!(
            has(&on, "married with children") && has(&on, "unenriched film"),
            "the flat list must spare the same titles the grid spares: {on:?}"
        );
        assert!(
            !has(&on, "all about sex") && !has(&on, "some anime"),
            "the flat list still shows adult releases: {on:?}"
        );
        teardown(&dir, ix);
    }

    #[test]
    fn affinity_ranks_favoured_genre_and_sinks_owned() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-aff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Drama One.2020.1080p.WEB.x264-GRP.mkv", "a@a", "a1"),
                mk("Drama Two.2019.1080p.WEB.x264-GRP.mkv", "b@b", "a2"),
                mk("Comedy Pick.2021.1080p.WEB.x264-GRP.mkv", "c@c", "a3"),
            ],
            1_000,
        )
        .unwrap();
        // Enrich all three with genres so the affinity join has data.
        for (key, genres) in [
            ("m:drama one:2020", "Drama, Thriller"),
            ("m:drama two:2019", "Drama"),
            ("m:comedy pick:2021", "Comedy"),
        ] {
            ix.title_seed(key, "movie", "T", 2020).unwrap();
            ix.db
                .execute(
                    "UPDATE titles SET genres=?2, checked=1 WHERE key=?1",
                    rusqlite::params![key, genres],
                )
                .unwrap();
        }
        // Taste skewed hard to Drama; user already owns "Drama One".
        let mut owned = std::collections::HashSet::new();
        owned.insert("m:drama one:2020".to_string());
        let aff = AffinityCtx {
            genres: vec![("Drama".into(), 10.0)],
            fav_kind: Some(("movie".into(), 2.0)),
            decade_center: None,
            decade_weight: 1.0,
            owned,
        };
        let q = BrowseQuery {
            desc: true,
            ..Default::default()
        };
        let (cards, _) = ix
            .browse_cards(&q, CardSort::Affinity, false, false, Some(&aff))
            .unwrap();
        let order: Vec<&str> = cards.iter().map(|c| c.title_key.as_str()).collect();
        // Drama (unowned) leads; Comedy in the middle; owned Drama sinks last.
        assert_eq!(
            order,
            ["m:drama two:2019", "m:comedy pick:2021", "m:drama one:2020"],
            "{cards:?}"
        );
        // Cold start (no profile) → Affinity degrades to Releases order,
        // still returning every card rather than erroring.
        let (cards, total) = ix
            .browse_cards(&q, CardSort::Affinity, false, false, None)
            .unwrap();
        assert_eq!(total, 3, "{cards:?}");
        assert_eq!(cards.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wall_tip_counts_arrivals_not_backfill() {
        let dir = std::env::temp_dir().join(format!("nzbfast-tip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Clock: a release is POSTED before it is SEEN (ingest clamps a
        // future Date: header to scan time, so the reverse is not
        // expressible). "Recently posted" here means after t=90_000.
        const RECENT: i64 = 90_000;

        // Posted t=91_000, first seen t=100_000.
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"Old.Show.S01E01.mkv\" yEnc (1/1)",
                "o1",
                91_000,
            )],
            100_000,
        )
        .unwrap();
        assert_eq!(ix.wall_tip(0, RECENT, 10).unwrap().latest, 1);
        // Nothing inserted after release row 1.
        let none = ix.wall_tip(1, RECENT, 10).unwrap();
        assert_eq!((none.new_keys, none.keys.len()), (0, 0));

        // A genuine arrival: newly seen AND recently posted.
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"New.Show.S02E02.mkv\" yEnc (1/1)",
                "n1",
                95_000,
            )],
            101_000,
        )
        .unwrap();
        let tip = ix.wall_tip(1, RECENT, 10).unwrap();
        assert_eq!((tip.new_keys, tip.latest), (1, 2));
        assert!(tip.keys[0].contains("new show"), "got {:?}", tip.keys);

        // A second release arriving in the SAME whole second still moves
        // the row-id cursor. A first_seen cursor used to miss this forever.
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"Other.Show.S03E03.mkv\" yEnc (1/1)",
                "n2",
                95_001,
            )],
            101_000,
        )
        .unwrap();
        let same_second = ix.wall_tip(2, RECENT, 10).unwrap();
        assert_eq!((same_second.new_keys, same_second.latest), (1, 3));

        // Eviction can delete the highest SQLite rowid, which SQLite then
        // reuses. The persistent sequence must still advance past 3.
        let same_key = same_second.keys[0].clone();
        ix.db
            .execute(
                "DELETE FROM files WHERE release_id IN
                   (SELECT id FROM releases WHERE title_key=?1)",
                [&same_key],
            )
            .unwrap();
        ix.db
            .execute("DELETE FROM releases WHERE title_key=?1", [&same_key])
            .unwrap();
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"Replacement.Show.S04E04.mkv\" yEnc (1/1)",
                "n3",
                95_002,
            )],
            101_000,
        )
        .unwrap();
        let reused_id = ix.wall_tip(3, RECENT, 10).unwrap();
        assert_eq!((reused_id.new_keys, reused_id.latest), (1, 4));

        // THE ONE THAT MATTERS. The history deepen leg ingests an
        // ancient upload right now: newly seen, posted long ago. It must
        // NOT be announced as an arrival. Counting it both cried wolf
        // every backfill pass AND sent the user to a wall sorted by
        // posted date, where the thing just announced sat thousands of
        // cards down and could not be found at all.
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"Ancient.Film.2009.mkv\" yEnc (1/1)",
                "a1",
                100,
            )],
            102_000,
        )
        .unwrap();
        let after_backfill = ix.wall_tip(4, RECENT, 10).unwrap();
        assert_eq!(
            (after_backfill.new_keys, after_backfill.keys.len()),
            (0, 0),
            "a backfilled old upload is new to the index but is not an arrival"
        );
        assert_eq!(after_backfill.latest, 5, "the mark still advances");

        // Re-seeing a release we already hold is not an arrival either
        // (first_seen is set on insert only, so the mark does not move).
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"New.Show.S02E02.mkv\" yEnc (1/1)",
                "n1",
                95_000,
            )],
            103_000,
        )
        .unwrap();
        assert_eq!(ix.wall_tip(5, RECENT, 10).unwrap().new_keys, 0);

        // Hiding the title removes it from the count.
        ix.hide_title(&tip.keys[0]).unwrap();
        assert_eq!(ix.wall_tip(1, RECENT, 10).unwrap().new_keys, 1);

        // An empty releases table must not reset the opaque cursor. A
        // wall opened while empty keeps cursor 5, then sees sequence 6.
        ix.db.execute("DELETE FROM files", []).unwrap();
        ix.db.execute("DELETE FROM releases", []).unwrap();
        assert_eq!(ix.wall_tip(5, RECENT, 10).unwrap().latest, 5);
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"After.Empty.S01E01.mkv\" yEnc (1/1)",
                "z1",
                95_003,
            )],
            104_000,
        )
        .unwrap();
        let after_empty = ix.wall_tip(5, RECENT, 10).unwrap();
        assert_eq!((after_empty.new_keys, after_empty.latest), (1, 6));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// N9: a card's representative (rep_stem / rep_grp - what drives the
    /// title parse, the enrichment seed, the "have" dupe key and the
    /// oracle verdict) has to come from a release THIS view accepts. The
    /// title's newest release is the wrong answer when the active filters
    /// exclude it.
    #[test]
    fn card_representative_obeys_the_active_filters() {
        let dir = std::env::temp_dir().join(format!("nzbfast-repfilt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        // Two releases of one title, written straight to SQL so junk /
        // group / post date are exact. The NEWER one is the junk copy
        // from the group a rule will hide.
        let key = "m:rep filter:2020";
        let rel = |id: i64, stem: &str, grp: &str, junk: i64, posted: i64| {
            ix.db
                .execute(
                    "INSERT INTO releases(id, stem, poster, grp, total_bytes, files,
                         has_par2, complete, first_posted, first_seen, kind, res,
                         have_parts, need_parts, title_key, junk, oracle_at, langs)
                     VALUES(?1, ?2, 'p@p', ?3, 4096, 1, 0, 1, ?4, ?4, 'movie',
                            '1080p', 1, 1, ?5, ?6, 0, '')",
                    rusqlite::params![id, stem, grp, posted, key, junk],
                )
                .unwrap();
        };
        rel(
            1,
            "Rep.Filter.2020.1080p.WEB.x264-GOOD",
            "alt.binaries.good",
            0,
            100,
        );
        rel(2, "0a1b2c3d4e5f60718293a4b5", "alt.binaries.junk", 90, 900);

        let cards = |q: BrowseQuery| -> Card {
            let (c, total) = ix
                .browse_cards(&q, CardSort::Latest, false, false, None)
                .unwrap();
            assert_eq!((c.len(), total), (1, 1), "{c:?}");
            c.into_iter().next().unwrap()
        };

        // Unfiltered: the newest release IS the representative.
        let all = cards(BrowseQuery::default());
        assert_eq!(all.n_releases, 2);
        assert_eq!(all.rep_stem, "0a1b2c3d4e5f60718293a4b5");
        assert_eq!(all.rep_grp, "alt.binaries.junk");

        // Junk ceiling: the newest release is excluded, so the card must
        // describe itself with the one release the view kept.
        let clean = cards(BrowseQuery {
            max_junk: Some(50),
            ..Default::default()
        });
        assert_eq!(clean.n_releases, 1);
        assert_eq!(
            clean.rep_stem, "Rep.Filter.2020.1080p.WEB.x264-GOOD",
            "{clean:?}"
        );
        assert_eq!(clean.rep_grp, "alt.binaries.good", "{clean:?}");

        // Same for a per-release curation rule (hide one group).
        ix.rule_add("group", "alt.binaries.junk", false).unwrap();
        let curated = cards(BrowseQuery {
            curated: true,
            ..Default::default()
        });
        assert_eq!(curated.n_releases, 1);
        assert_eq!(
            curated.rep_stem, "Rep.Filter.2020.1080p.WEB.x264-GOOD",
            "{curated:?}"
        );
        assert_eq!(curated.rep_grp, "alt.binaries.good", "{curated:?}");

        // ...and a row-level filter that excludes the OLDER release still
        // leaves the newest one as the representative.
        let big = cards(BrowseQuery {
            newer_than: 500,
            ..Default::default()
        });
        assert_eq!(big.n_releases, 1);
        assert_eq!(big.rep_grp, "alt.binaries.junk", "{big:?}");

        // Title-level filters are constant per card, so they must not
        // strand the representative: an unenriched card is dropped whole
        // by matched_only rather than losing its rep.
        let (none, total) = ix
            .browse_cards(&Default::default(), CardSort::Latest, true, false, None)
            .unwrap();
        assert_eq!((none.len(), total as usize), (0, 0));

        // The flat browse() path is unchanged: it filters and dedupes by
        // stem exactly as before.
        let (rows, total) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!((rows.len(), total), (2, 2));
        let (rows, total) = ix
            .browse(&BrowseQuery {
                max_junk: Some(50),
                ..Default::default()
            })
            .unwrap();
        assert_eq!((rows.len(), total), (1, 1));
        assert_eq!(rows[0].stem, "Rep.Filter.2020.1080p.WEB.x264-GOOD");
        let (rows, _) = ix
            .browse(&BrowseQuery {
                curated: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].grp, "alt.binaries.good");
        teardown(&dir, ix);
    }
}
