//! The browse query surface (TODO 106 phase 2.2, cut 3): BrowseQuery and
//! its filters, the adult-genre predicate, curation (hidden titles, wall
//! rules, hide suggestions) and `browse` itself. Bodies are verbatim moves
//! from the old index.rs; see research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::cards::RES_RANK_SQL;
use super::query::fts_match;
use super::*;

/// Browse-view filter/sort/page request (M25). Defaults: everything,
/// newest-first, first page.
#[derive(Debug, Clone)]
pub struct BrowseQuery {
    /// Substring terms over the stem ('' = all).
    pub q: String,
    /// Exact kind filter ("movie"/"tv"/"software"/"other").
    pub kind: Option<String>,
    /// Exact resolution filter ("2160p", …).
    pub res: Option<String>,
    pub complete_only: bool,
    /// Minimum total_bytes (0 = unbounded).
    pub min_bytes: u64,
    /// first_posted cutoff, unix seconds (0 = unbounded).
    pub newer_than: i64,
    pub sort: BrowseSort,
    /// true = descending (the default direction for every sort).
    pub desc: bool,
    pub limit: u32,
    pub offset: u32,
    /// M28: hide releases whose junk score is >= this (None = show all).
    pub max_junk: Option<u32>,
    /// M28: restrict to the releases of one or more grid cards (exact
    /// parse-key match). Empty = no restriction.
    ///
    /// A SET rather than one key because the newznab facade fills it
    /// from an external id, and an id genuinely resolves to several
    /// keys: one show posted under two spellings parses into two, and a
    /// film is keyed `m:<norm>:<year>` or `m:<norm>` depending on
    /// whether its stem carried the year. Answering with one of them
    /// hid the rest of the title's releases from Sonarr and Radarr, and
    /// `total` agreed with the truncated page so nothing looked wrong
    /// (Codex sweep 7, M4).
    pub title_keys: Vec<String>,
    /// M30: apply the user's wall curation (per-title hides + hide
    /// rules). Wall/list views set this; API facades (newznab, *arrs)
    /// stay uncurated.
    pub curated: bool,
    /// M30: leave adult titles out of the curated views. Off by default
    /// so every uncurated facade (newznab, the *arrs) is untouched, and
    /// so a caller has to ask for it deliberately - see
    /// [`ADULT_GENRE_SQL`].
    pub hide_adult: bool,
    /// M30: genre substring filter over the enriched metadata (cards
    /// only - unenriched cards drop out while it's active).
    pub genre: Option<String>,
    /// M30: original-year range filter (decade chips), inclusive.
    /// 0 = unbounded on that side. Cards only (uses the enriched year
    /// with the movie parse-key fallback).
    pub year_min: u32,
    pub year_max: u32,
    /// M29 3c: when set, keep only releases whose availability verdict is
    /// "ok". Pushed into SQL as a real predicate (so `total` and the page
    /// agree), evaluated by the `oracle` verdict logic - not a page trim.
    pub verdict_ok: Option<VerdictFilter>,
}

/// M29 3c: the availability-verdict filter carried on a [`BrowseQuery`].
/// Bundles the (tiny) ledger snapshot, the user's enabled backbones, and
/// `now`, so `browse` can register a SQL scalar function that reuses the
/// single source of truth in [`crate::oracle::Snapshot::verdict`] - no
/// Wilson math or family-fallback logic is duplicated into SQL.
#[derive(Debug, Clone, Default)]
pub struct VerdictFilter {
    pub snap: crate::oracle::Snapshot,
    pub backbones: Vec<String>,
    pub now: i64,
}

/// The "this is adult" test, as one SQL predicate over `titles.genres`.
///
/// Kept in one place because two views have to agree about it (the
/// poster wall and the release list), and because the shape of it is not
/// obvious: see the call site in `browse_cards` for why "Adult" alone is
/// not a substring match. `NOT (...)` rather than an inverted test so an
/// unenriched title, whose genres are empty, is KEPT - an unknown genre
/// is not evidence of anything, and dropping every unenriched card the
/// moment the filter came on would gut the wall.
/// The alias prefix is a parameter because the SAME text has to appear
/// in three places with two spellings: the two query forms below, which
/// qualify the column as `t.genres`, and the CREATE INDEX in `schema.rs`,
/// whose partial-index predicate may not name an alias at all. A partial
/// index is only reachable when the statement's own WHERE repeats its
/// predicate, so those spellings cannot be allowed to drift - see
/// `plan_tests.rs::the_adult_exclusion_list_reaches_its_partial_index`
/// and the `idx_titles_adult` comment in `schema.rs`.
macro_rules! adult_genre_match_sql {
    ($t:literal) => {
        concat!(
            "(LOWER(COALESCE(",
            $t,
            "genres,'')) LIKE '%hentai%' OR LOWER(COALESCE(",
            $t,
            "genres,'')) LIKE '%erotic%' OR LOWER(TRIM(COALESCE(",
            $t,
            "genres,''))) = 'adult')"
        )
    };
}
pub(crate) use adult_genre_match_sql;

pub const ADULT_GENRE_SQL: &str = concat!("NOT ", adult_genre_match_sql!("t."));

/// The same test the POSITIVE way round, for a query that has to SELECT
/// adult titles rather than exclude them - the flat release list has no
/// `titles` join, so it filters with a `title_key NOT IN (SELECT … WHERE
/// <this>)` subquery instead.
///
/// Both spellings come from one literal on purpose: they are the two
/// halves that have to agree, and they did not - the grouped view
/// carried the filter and the flat one did not, so turning group-by-
/// title off brought every Adult/Hentai/Erotic release straight back.
pub const ADULT_GENRE_MATCH_SQL: &str = adult_genre_match_sql!("t.");

/// The OTHER half of "this is adult", as a per-release predicate in the
/// `{}`-alias form both release-level filter lists use: the release is
/// not marked with the poster's own adult filing.
///
/// The genre test above can only speak for a title that enrichment has
/// reached. A spot-born card is usually not one of those - it is a
/// fresh row named from a signed announcement, with no `titles` row
/// behind it yet and possibly never - and roughly a third of the
/// Spotnet feed is erotica. So the filter that was supposed to cover
/// the wall had nothing at all to read on the one source where it
/// mattered most, and adult spots were kept off the wall by never
/// being promoted at all (which cost the catalogue 31% of the feed).
///
/// `releases.adult` is written at promotion time from the spot's own
/// `d75` subcategory: not an inference from metadata, but the poster's
/// filing of their own post. The two tests are OR'd - a card is hidden
/// if EITHER says adult - so neither has to be complete.
pub const ADULT_MARK_SQL: &str = "{}adult = 0";

impl Default for BrowseQuery {
    fn default() -> Self {
        BrowseQuery {
            q: String::new(),
            kind: None,
            res: None,
            complete_only: false,
            min_bytes: 0,
            newer_than: 0,
            sort: BrowseSort::Posted,
            desc: true,
            limit: 50,
            offset: 0,
            max_junk: None,
            title_keys: Vec::new(),
            curated: false,
            hide_adult: false,
            genre: None,
            year_min: 0,
            year_max: 0,
            verdict_ok: None,
        }
    }
}

/// M30: one hidden title in the Hidden view.
#[derive(Debug, Clone)]
pub struct HiddenTitle {
    pub key: String,
    pub title: String,
    pub poster: String,
    pub kind: String,
    pub at: i64,
    pub n_releases: u32,
}

/// M30: one hide rule (manual or accepted suggestion).
#[derive(Debug, Clone)]
pub struct WallRule {
    pub id: i64,
    pub field: String,
    pub value: String,
    pub added: i64,
    pub auto: bool,
}

/// M30: a suggested rule derived from the user's hides.
#[derive(Debug, Clone)]
pub struct Suggestion {
    pub field: String,
    pub value: String,
    /// How many hidden titles share this signal.
    pub n: u32,
    /// Up to 3 hidden titles that triggered it (for the banner text).
    pub sample: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowseSort {
    /// Upload date (first_posted) - the browse default.
    Posted,
    /// When WE first indexed it (first_seen) - "recently added" as
    /// opposed to Posted's upload date. 24C ships added-vs-posted as a
    /// sort option rather than a second date column.
    Seen,
    Size,
    Name,
    /// File count - the Releases table's Files column.
    Files,
    /// Category column: kind first, resolution as the within-kind order
    /// so one category's rows read best-first.
    Kind,
    /// have_parts/need_parts ratio.
    Completeness,
}

impl BrowseSort {
    /// API-string form ("posted"/"seen"/"size"/"name"/"files"/"kind"/
    /// "completeness").
    pub fn parse(s: &str) -> BrowseSort {
        match s {
            "seen" | "added" => BrowseSort::Seen,
            "size" => BrowseSort::Size,
            "name" => BrowseSort::Name,
            "files" => BrowseSort::Files,
            "kind" | "category" => BrowseSort::Kind,
            "completeness" => BrowseSort::Completeness,
            _ => BrowseSort::Posted,
        }
    }
}

/// M28: 0-100 curation score computed at ingest - how likely this
/// release is wall noise. 0 = clean; the default wall hides >= 50.
/// Recomputed on every ingest touch, so a cluster that starts tiny and
/// grows sheds the size penalty as its parts arrive.
/// SQL predicate: does a `files.filename` look like a Windows executable?
/// Shared by the ingest aggregate and the junk_v5 re-score so the two
/// can never disagree.
pub(crate) const EXE_FILE_SQL: &str = "(LOWER(filename) LIKE '%.exe' \
     OR LOWER(filename) LIKE '%.scr' OR LOWER(filename) LIKE '%.lnk' \
     OR LOWER(filename) LIKE '%.bat' OR LOWER(filename) LIKE '%.cmd' \
     OR LOWER(filename) LIKE '%.com' OR LOWER(filename) LIKE '%.msi' \
     OR LOWER(filename) LIKE '%.vbs' OR LOWER(filename) LIKE '%.pif')";

/// `browse`'s exact `total`, given the page's filter clause WITHOUT the
/// best-copy-per-stem predicate.
///
/// **Why this counts the same rows the page returns.** The page keeps
/// one row per stem: `id = (SELECT d.id FROM releases d WHERE
/// d.stem = releases.stem AND <the same filters> ORDER BY … LIMIT 1)`.
/// The subquery's filters are the page's own (that is the invariant the
/// comment at the call site is about), and `LIMIT 1` over an order that
/// ends in the unique `d.id` picks exactly one row per stem. So a row
/// survives iff it is THE representative of its stem among the rows
/// this query accepts, and the surviving set is one row per distinct
/// stem that has at least one accepted row. Counting those is counting
/// the distinct stems - exactly, not approximately. `stem` is
/// `NOT NULL`, so the one way `COUNT(DISTINCT)` could differ (it skips
/// NULLs) cannot arise; and the correlated `d.stem = releases.stem`
/// groups by the column's own collation, which is what `DISTINCT` uses
/// too.
///
/// **Why it is worth doing.** The correlated form runs the subquery once
/// per candidate row, and the candidate set is whatever the filters
/// leave - which for the uncurated facades is the whole table. Measured
/// 20 Aug 2026 on the 13.2M-release live index
/// (`research/BROWSE-stem-dedup-count-2026-08-20.md`):
///
/// | filter | correlated | this |
/// |---|---:|---:|
/// | `junk < 50` (the wall's list) | 140 ms | 50 ms |
/// | `complete` (an *arr RSS sync) | 2.21 s | 1.98 s |
/// | `kind='movie' AND complete` | 3.25 s | 1.07 s |
/// | none (`all=1`, no card) | **391 s** | **0.89 s** |
///
/// **The `+` is load-bearing.** Written `COUNT(DISTINCT stem)`, SQLite
/// answers the DISTINCT from `idx_rel_stem` - and then pays a rowid
/// table fetch PER ENTRY to test filters the index does not carry. On
/// the live index that turns the 2.21 s *arr shape into **27.5 s**: a
/// regression, from the same statement, chosen by the planner. The
/// unary `+` makes the operand an expression rather than a column
/// reference, so that optimization is off the table while the WHERE
/// clause keeps every index it needs (`idx_rel_visible_posted` for
/// `junk < 50`, `idx_rel_kind` for a category). `plan_tests.rs`'s
/// `browse_total_never_walks_the_whole_stem_index` pins both halves.
///
/// The cost of forgoing it is a temp B-tree of the distinct stems: 57 MB
/// peak RSS for the 1.37M-stem unfiltered case, and `temp_store=MEMORY`
/// means that is RAM. It is bounded by the distinct stems the filters
/// admit, which for every curated surface is thousands.
pub(crate) fn browse_total_sql(count_clause: &str) -> String {
    format!("SELECT COUNT(DISTINCT +stem) FROM releases WHERE {count_clause}")
}

impl Index {
    /// M25 browse view: filtered, sorted, paginated release listing -
    /// what the wall's list mode and the Newznab facade page through.
    /// Returns (rows, total matching rows) so the UI can paginate.
    pub(super) fn browse_once(&self, q: &BrowseQuery) -> rusqlite::Result<(Vec<Release>, u64)> {
        // Every predicate is written with `{}` where the table alias
        // goes: the page filters `releases` unqualified, and the
        // representative-copy subquery at the bottom has to apply the
        // SAME filters to its own alias `d`. One list, two renderings -
        // a hand-written second copy would drift. Both renderings cite
        // the same ?N, so nothing below has to renumber.
        let mut wheres: Vec<String> = Vec::new();
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
        // M28: junk ceiling (curation) - None = no filter.
        if let Some(max) = q.max_junk {
            let p = bind(&mut params, Box::new(max as i64));
            wheres.push(format!("{{}}junk < {p}"));
        }
        // M28: exact card filter (the detail sheet lists one title's
        // releases via its stored parse key). Rendered into the SAME
        // `wheres` list as everything else, so the `IN` propagates
        // identically into the representative-copy subquery and into
        // `total` - which is what keeps a multi-key id search paged
        // honestly in SQL.
        if !q.title_keys.is_empty() {
            let ps: Vec<String> = q
                .title_keys
                .iter()
                .map(|tk| bind(&mut params, Box::new(tk.clone())))
                .collect();
            wheres.push(format!("{{}}title_key IN ({})", ps.join(", ")));
        }
        // M30: user curation (hides + rules). It already takes the alias
        // as an argument, so the placeholder passes straight through.
        if q.curated {
            self.curation_wheres("{}", &mut wheres, &mut params)?;
        }
        // M30: adult titles, when the caller asked for them to be left
        // out. `browse_cards` joins `titles` and can test the genres
        // directly; a flat release row only carries its parse key, so
        // the same test runs as a subquery over the titles that MATCH -
        // which keeps the unenriched-titles-are-kept behaviour the card
        // query gets from its `NOT (...)` (an empty genre list matches
        // nothing here, so the release stays).
        //
        // This whole clause was missing: the setting promises it covers
        // the wall AND the release list, and switching group-by-title
        // off put the adult releases straight back on screen.
        if q.hide_adult {
            wheres.push(format!(
                "{{}}title_key NOT IN (SELECT t.key FROM titles t WHERE {ADULT_GENRE_MATCH_SQL})"
            ));
            // ...and the spot-born marker, which needs no join at all.
            wheres.push(ADULT_MARK_SQL.into());
        }
        // M29 3c: availability verdict as a real SQL predicate. A scalar
        // function backed by the oracle Snapshot keeps ALL verdict logic
        // (Wilson bounds, family fallback, blind-spot demotion) in one
        // place; because the same predicate feeds both the COUNT and the
        // page SELECT below, `total` and the returned rows always agree
        // (the old page-level trim left `total` unfiltered - broken paging).
        let verdict_fn = q.verdict_ok.is_some();
        if let Some(vf) = &q.verdict_ok {
            let snap = vf.snap.clone();
            let bbs = vf.backbones.clone();
            let now = vf.now;
            self.db.create_scalar_function(
                "oracle_ok",
                2,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |ctx| {
                    let grp = ctx.get_raw(0).as_str().unwrap_or("");
                    let first_posted: i64 = ctx.get(1)?;
                    // Undated release (no post date): age is UNKNOWN, not
                    // "20000 days old". Treat as no verdict (not ok) rather
                    // than mis-bucketing it as ancient - matches the write
                    // side, which no longer records undated jobs.
                    if first_posted <= 0 {
                        return Ok(0i64);
                    }
                    let age = ((now - first_posted).max(0) / 86_400) as u32;
                    let fam = crate::oracle::group_family(grp);
                    let ok = matches!(
                        snap.verdict(&bbs, &fam, age),
                        Some(crate::oracle::Verdict::Ok)
                    );
                    Ok(ok as i64)
                },
            )?;
            wheres.push("oracle_ok({}grp, {}first_posted) = 1".into());
        }
        // Same separator-insensitive multi-term AND match as search() -
        // FTS prefix match when available, LIKE full-scan fallback.
        let fts_m = if self.fts {
            fts_match(&q.q)
        } else {
            String::new()
        };
        if !fts_m.is_empty() {
            let p = bind(&mut params, Box::new(fts_m));
            // Posted stem OR pre-feed name - see search() for why the
            // second index exists and is separate.
            let leg = if self.pre_fts {
                format!(" OR {{}}id IN (SELECT rowid FROM pre_fts WHERE pre_fts MATCH {p})")
            } else {
                String::new()
            };
            wheres.push(format!(
                "({{}}id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH {p}){leg})"
            ));
        } else {
            const NS: &str = "REPLACE(REPLACE(REPLACE(LOWER({}stem),'.',' '),'_',' '),'-',' ')";
            const PS: &str =
                "REPLACE(REPLACE(REPLACE(LOWER({}pre_title),'.',' '),'_',' '),'-',' ')";
            for term in
                q.q.to_ascii_lowercase()
                    .replace(['.', '_', '-'], " ")
                    .split_whitespace()
            {
                let p = bind(&mut params, Box::new(term.to_string()));
                wheres.push(format!(
                    "({NS} LIKE '%' || {p} || '%' \
                     OR ({{}}pre_title <> '' AND {PS} LIKE '%' || {p} || '%'))"
                ));
            }
        }
        // Cross-posted releases (same stem in teevee AND moovee, or two
        // posters) are separate index rows; a flat list wants ONE. Keep
        // the best copy per stem: complete beats incomplete, then part
        // ratio, then size (idx_rel_stem makes the correlated lookup
        // cheap). The page's own filters go in here too, so the pick is
        // the best copy AMONG the ones this query accepts: a
        // representative that fails a filter would otherwise satisfy no
        // row at all, dropping the release from the list AND from
        // `total` while the grid still showed its card.
        let rep = alias(&wheres, "d.");
        // The COUNT's own clause: the SAME filters, WITHOUT the
        // representative predicate below. See `browse_total_sql` for why
        // dropping it there is exact rather than approximate, and what
        // the `+` on the column is load-bearing for.
        let count_clause = {
            let c = alias(&wheres, "");
            if c.is_empty() { "1".to_string() } else { c }
        };
        let rep = if rep.is_empty() {
            String::new()
        } else {
            format!(" AND {rep}")
        };
        wheres.push(format!(
            "id = (SELECT d.id FROM releases d WHERE d.stem = releases.stem{rep}
                   ORDER BY d.complete DESC,
                            CAST(d.have_parts AS REAL)/MAX(d.need_parts,1) DESC,
                            d.total_bytes DESC, d.id LIMIT 1)"
        ));
        let where_clause = alias(&wheres, "");
        // Sort key is a fixed vocabulary (never interpolated user text).
        let dir = if q.desc { "DESC" } else { "ASC" };
        // Build the full ORDER BY prefix. SQL applies a direction PER term,
        // so a two-column key like "(ratio), complete" would leave the
        // ratio (the real sort key) at the default ASC while only `complete`
        // took {dir} - inverting "Most complete". Attach {dir} to every
        // completeness column explicitly.
        let order_key = match q.sort {
            BrowseSort::Posted => format!("first_posted {dir}"),
            BrowseSort::Seen => format!("first_seen {dir}"),
            BrowseSort::Size => format!("total_bytes {dir}"),
            BrowseSort::Name => format!("stem COLLATE NOCASE {dir}"),
            BrowseSort::Files => format!("files {dir}"),
            // Kind is TEXT; res gets the same direction so each
            // category's rows lead with the best (or worst) encode.
            // `res` is TEXT, so ordering it directly sorts lexicographically
            // and puts 720p above 2160p - the opposite of "best encode
            // first". Rank it the way the wall's own card query does.
            BrowseSort::Kind => format!("kind {dir}, {RES_RANK_SQL} {dir}"),
            // Completeness ratio; complete flag breaks ties so verified-
            // complete singles sort above 100%-but-unconfirmed rows.
            BrowseSort::Completeness => {
                format!("(CAST(have_parts AS REAL) / MAX(need_parts, 1)) {dir}, complete {dir}")
            }
        };
        let total: u64 = self
            .db
            .query_row(
                &browse_total_sql(&count_clause),
                rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)?;
        let sql = format!(
            "SELECT {REL_COLS} FROM releases WHERE {where_clause}
             ORDER BY {order_key}, id DESC LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        // The belt behind the API layer's own clamp (200 for the
        // curated feed, 2001 for a title-scoped ask). It must admit the
        // wall's Show-all cap PLUS its cut sentinel - at 500 it silently
        // re-cut the expanded list the 2001 ask was raised for.
        params.push(Box::new(q.limit.min(2001)));
        params.push(Box::new(q.offset));
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
            release_from_row,
        )?;
        let out = rows.collect::<rusqlite::Result<_>>()?;
        // Drop the per-request verdict function so a stale snapshot never
        // lingers on the shared connection (no-op if it was never set).
        if verdict_fn {
            let _ = self.db.remove_function("oracle_ok", 2);
        }
        Ok((out, total))
    }

    /// Appends the wall-curation predicates (per-title hides + hide
    /// rules) to a query's WHERE list. `pfx` is the releases alias
    /// ("r." in the card query, "" in the flat browse).
    pub(super) fn curation_wheres(
        &self,
        pfx: &str,
        wheres: &mut Vec<String>,
        params: &mut Vec<Box<dyn rusqlite::ToSql>>,
    ) -> rusqlite::Result<()> {
        wheres.push(format!(
            "{pfx}title_key NOT IN (SELECT key FROM wall_hidden)"
        ));
        let rules: Vec<(String, String)> = {
            let mut stmt = self
                .db
                .prepare_cached("SELECT field, value FROM wall_rules")?;

            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (field, value) in rules {
            let n = params.len() + 1;
            match field.as_str() {
                "lang" => {
                    params.push(Box::new(format!(" {} ", value.to_lowercase())));
                    wheres.push(format!("INSTR(' '||{pfx}langs||' ', ?{n}) = 0"));
                }
                "kind" => {
                    params.push(Box::new(value));
                    wheres.push(format!("{pfx}kind <> ?{n}"));
                }
                "group" => {
                    params.push(Box::new(value));
                    wheres.push(format!("{pfx}grp <> ?{n}"));
                }
                // Whole titles whose enriched genre list carries the
                // value ("reality", "sports", ...) - resolved through
                // `titles` so the flat list filters identically to the
                // card grid.
                //
                // Asked per candidate RELEASE, as a seek on the titles
                // PRIMARY KEY, rather than as an exclusion list built by
                // scanning every title. The value is a bound parameter
                // tested with a leading-`%` LIKE, so unlike the adult
                // filter next door there is no predicate to build a
                // partial index on and no prefix to seek: the scan was
                // unindexable by construction. And it ran FOUR times
                // per release-list request when it was measured: browse
                // renders this list twice (once unqualified, once
                // against the `d.` alias of the best-copy-per-stem
                // subquery) and issues two statements, the exact COUNT
                // and the page. TODO 197 landed in parallel with this
                // and took the representative predicate out of the
                // COUNT, so it is three renderings now, not four - which
                // makes the numbers below the cost BEFORE both fixes and
                // does not change what they say about the shapes.
                // Measured on a synthetic 1M-title corpus (`genre_cost`
                // in this file): 741 ms for one rule and 2.23 s for
                // three, against 3.2 ms with no rule at all; as the
                // seek below, 9.0 ms and 12.9 ms. See
                // research/BROWSE-genre-rule-2026-08-20.md, and
                // `plan_tests.rs::the_genre_hide_rule_seeks_titles`,
                // which fails if either rendering goes back to a scan.
                //
                // `NOT EXISTS` rather than `NOT IN` is also what makes
                // the term immune to a NULL `titles.key` - `NOT IN` over
                // a list containing one NULL is NULL for every row, the
                // trap `wall_hidden`'s schema comment spells out.
                "genre" => {
                    params.push(Box::new(value));
                    wheres.push(format!(
                        "NOT EXISTS (SELECT 1 FROM titles tg
                          WHERE tg.key = {pfx}title_key
                            AND tg.genres LIKE '%' || ?{n} || '%')"
                    ));
                }
                // Exact-token stem match via the FTS index (unicode61
                // already splits ./-/_), LIKE word-boundary fallback on
                // non-FTS builds.
                "word" if self.fts => {
                    params.push(Box::new(format!("\"{}\"", value.replace('"', "\"\""))));
                    wheres.push(format!(
                        "{pfx}id NOT IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?{n})"
                    ));
                }
                "word" => {
                    params.push(Box::new(format!("% {} %", value.to_lowercase())));
                    wheres.push(format!(
                        "' '||REPLACE(REPLACE(REPLACE(LOWER({pfx}stem),'.',' '),'_',' '),'-',' ')||' ' NOT LIKE ?{n}"
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// "Not interested": hide one title (all its releases) from every
    /// curated wall/list view. Idempotent.
    pub fn hide_title(&self, key: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO wall_hidden(key, at) VALUES(?1, strftime('%s','now'))
             ON CONFLICT(key) DO NOTHING",
            [key],
        )?;
        Ok(())
    }

    pub fn unhide_title(&self, key: &str) -> rusqlite::Result<()> {
        self.db
            .execute("DELETE FROM wall_hidden WHERE key = ?1", [key])?;
        Ok(())
    }

    /// The Hidden view: every hidden title with enough display context
    /// to render an unhide row (title falls back to the parse key).
    pub fn hidden_titles(&self) -> rusqlite::Result<Vec<HiddenTitle>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT h.key, COALESCE(NULLIF(t.title,''), h.key), COALESCE(t.poster,''),
                    COALESCE(NULLIF(t.kind,''),
                             CASE WHEN h.key LIKE 't:%' THEN 'tv' ELSE 'movie' END),
                    h.at,
                    (SELECT COUNT(*) FROM releases r WHERE r.title_key = h.key)
             FROM wall_hidden h LEFT JOIN titles t ON t.key = h.key
             ORDER BY h.at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(HiddenTitle {
                key: r.get(0)?,
                title: r.get(1)?,
                poster: r.get(2)?,
                kind: r.get(3)?,
                at: r.get(4)?,
                n_releases: r.get(5)?,
            })
        })?;
        let rows: Vec<HiddenTitle> = rows.collect::<rusqlite::Result<_>>()?;
        // Unenriched titles fall back to the raw parse key - present
        // those readably instead.
        Ok(rows
            .into_iter()
            .map(|mut h| {
                if h.title == h.key {
                    h.title = pretty_key(&h.key);
                }
                h
            })
            .collect())
    }

    pub fn rules_list(&self) -> rusqlite::Result<Vec<WallRule>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT id, field, value, added, auto FROM wall_rules ORDER BY added DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(WallRule {
                id: r.get(0)?,
                field: r.get(1)?,
                value: r.get(2)?,
                added: r.get(3)?,
                auto: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Add a hide rule. `auto` marks rules created from an accepted
    /// suggestion (vs typed by hand). Unknown fields are rejected so a
    /// typo can't create a dead rule that silently filters nothing.
    pub fn rule_add(&self, field: &str, value: &str, auto: bool) -> rusqlite::Result<()> {
        if !matches!(field, "lang" | "word" | "kind" | "group" | "genre") {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "unknown rule field '{field}'"
            )));
        }
        let value = value.trim().to_lowercase();
        if value.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "empty rule value".into(),
            ));
        }
        self.db.execute(
            "INSERT INTO wall_rules(field, value, added, auto)
             VALUES(?1, ?2, strftime('%s','now'), ?3)
             ON CONFLICT(field, value) DO NOTHING",
            rusqlite::params![field, value, auto],
        )?;
        // Accepting a rule supersedes any earlier "no thanks".
        self.db.execute(
            "DELETE FROM wall_dismissed WHERE field=?1 AND value=?2",
            rusqlite::params![field, value],
        )?;
        Ok(())
    }

    pub fn rule_delete(&self, id: i64) -> rusqlite::Result<()> {
        self.db
            .execute("DELETE FROM wall_rules WHERE id = ?1", [id])?;
        Ok(())
    }

    /// "No thanks" on a suggestion - never offer this (field, value)
    /// again.
    pub fn suggestion_dismiss(&self, field: &str, value: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO wall_dismissed(field, value) VALUES(?1, LOWER(?2))
             ON CONFLICT DO NOTHING",
            rusqlite::params![field, value],
        )?;
        Ok(())
    }

    /// Pattern detection over the user's hides: when >= 3 hidden titles
    /// share a language tag, or >= 3 share a rare title word, suggest a
    /// one-click rule. Existing rules and dismissed suggestions are
    /// excluded; strongest (most hides) first, capped at 3.
    pub fn hide_suggestions(&self) -> rusqlite::Result<Vec<Suggestion>> {
        use std::collections::{HashMap, HashSet};
        let taken: HashSet<(String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT field, value FROM wall_rules
                 UNION SELECT field, value FROM wall_dismissed",
            )?;

            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        // One pass over the hidden titles' releases: per-title language
        // tags and display names.
        let mut stmt = self.db.prepare_cached(
            "SELECT h.key, COALESCE(NULLIF(t.title,''), h.key),
                    (SELECT COALESCE(GROUP_CONCAT(DISTINCT r.langs), '')
                     FROM releases r WHERE r.title_key = h.key),
                    COALESCE(t.genres, '')
             FROM wall_hidden h LEFT JOIN titles t ON t.key = h.key",
        )?;
        let hidden: Vec<(String, String, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<Vec<(String, String, String, String)>>>()?
            .into_iter()
            .map(|(key, disp, langs, genres)| {
                let disp = if disp == key { pretty_key(&key) } else { disp };
                (key, disp, langs, genres)
            })
            .collect();
        let mut by_lang: HashMap<String, Vec<&str>> = HashMap::new();
        let mut by_word: HashMap<String, Vec<&str>> = HashMap::new();
        let mut by_genre: HashMap<String, Vec<&str>> = HashMap::new();
        // Title-key words already come normalized (lowercase, separator-
        // collapsed). Generic words never make a good rule.
        const STOP: [&str; 24] = [
            "the", "and", "of", "a", "an", "to", "in", "on", "at", "with", "for", "from", "der",
            "die", "das", "les", "los", "las", "una", "del", "you", "not", "all", "one",
        ];
        for (key, disp, langs, genres) in &hidden {
            let mut seen_l: HashSet<&str> = HashSet::new();
            for l in langs.split([',', ' ']).filter(|l| !l.is_empty()) {
                if seen_l.insert(l) {
                    by_lang.entry(l.to_string()).or_default().push(disp);
                }
            }
            let mut seen_g: HashSet<String> = HashSet::new();
            for g in genres.split(',').map(|g| g.trim().to_lowercase()) {
                if !g.is_empty() && seen_g.insert(g.clone()) {
                    by_genre.entry(g).or_default().push(disp);
                }
            }
            let base = key
                .strip_prefix("t:")
                .or_else(|| key.strip_prefix("m:"))
                .unwrap_or(key);
            let words = match base.rsplit_once(':') {
                Some((w, y)) if y.chars().all(|c| c.is_ascii_digit()) => w,
                _ => base,
            };
            let mut seen_w: HashSet<&str> = HashSet::new();
            for w in words.split_whitespace() {
                if w.len() >= 3 && !STOP.contains(&w) && seen_w.insert(w) {
                    by_word.entry(w.to_string()).or_default().push(disp);
                }
            }
        }
        let mut out: Vec<Suggestion> = Vec::new();
        for (lang, titles) in by_lang {
            if titles.len() >= 3 && !taken.contains(&("lang".into(), lang.clone())) {
                out.push(Suggestion {
                    field: "lang".into(),
                    value: lang,
                    n: titles.len() as u32,
                    sample: titles.iter().take(3).map(|s| s.to_string()).collect(),
                });
            }
        }
        for (genre, titles) in by_genre {
            // Genres are broad (half a wall can be "Drama") - demand a
            // stronger signal than lang/word before suggesting.
            if titles.len() >= 4 && !taken.contains(&("genre".into(), genre.clone())) {
                out.push(Suggestion {
                    field: "genre".into(),
                    value: genre,
                    n: titles.len() as u32,
                    sample: titles.iter().take(3).map(|s| s.to_string()).collect(),
                });
            }
        }
        for (word, titles) in by_word {
            if titles.len() < 3 || taken.contains(&("word".into(), word.clone())) {
                continue;
            }
            // Rarity gate: a word that matches half the index is a
            // stopword we missed, not a taste signal. FTS count of
            // distinct titles carrying the token, capped at 500.
            if self.fts {
                let global: i64 = self
                    .db
                    .query_row(
                        "SELECT COUNT(DISTINCT title_key) FROM releases
                         WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)",
                        [format!("\"{}\"", word.replace('"', "\"\""))],
                        |r| r.get(0),
                    )
                    .unwrap_or(i64::MAX);
                if global > 500 {
                    continue;
                }
            }
            out.push(Suggestion {
                field: "word".into(),
                value: word,
                n: titles.len() as u32,
                sample: titles.iter().take(3).map(|s| s.to_string()).collect(),
            });
        }
        out.sort_by(|a, b| b.n.cmp(&a.n).then(a.value.cmp(&b.value)));
        out.truncate(3);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{dated_entry, entry, teardown};

    #[test]
    fn curation_hides_rules_and_suggestions() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-cur-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Inception.2010.1080p.BluRay.x264-GRP.mkv", "a@a", "c1"),
                // Same title, German dub - lang rule must drop only this
                // release, never the whole card.
                mk(
                    "Inception.2010.German.1080p.BluRay.x264-DEU.mkv",
                    "b@b",
                    "c2",
                ),
                mk("Der.Film.2019.German.1080p.WEB.x264-DEU.mkv", "c@c", "c3"),
                mk(
                    "Anderes.Werk.2021.German.720p.WEB.x264-DEU.mkv",
                    "d@d",
                    "c4",
                ),
                mk(
                    "Drittes.Ding.2022.German.2160p.WEB.x265-DEU.mkv",
                    "e@e",
                    "c5",
                ),
                mk("WWE.Raw.2026.03.01.720p.HDTV.x264-GRP.mkv", "f@f", "c6"),
            ],
            1_000,
        )
        .unwrap();
        let cur = BrowseQuery {
            curated: true,
            ..Default::default()
        };
        let (_, base_total) = ix.browse(&cur).unwrap();
        assert_eq!(base_total, 6);

        // "Not interested" on one title.
        let key = crate::release::parse_release("Der.Film.2019.German.1080p.WEB.x264-DEU").key;
        ix.hide_title(&key).unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 5, "hidden title's releases drop out");
        // Uncurated paths (newznab, *arrs) are untouched.
        let (_, raw) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(raw, 6);
        let hid = ix.hidden_titles().unwrap();
        assert_eq!(hid.len(), 1);
        assert_eq!(hid[0].key, key);

        // Language rule: German releases vanish, but Inception keeps its
        // card via the English encode.
        ix.rule_add("lang", "german", false).unwrap();
        let (rows, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2, "{rows:?}"); // english Inception + WWE
        let (cards, _) = ix
            .browse_cards(&cur, CardSort::Latest, false, false, None)
            .unwrap();
        assert!(
            cards.iter().any(|c| c.title_key.starts_with("m:inception")),
            "mixed-language card survives: {cards:?}"
        );
        assert!(
            cards.iter().all(|c| !c.title_key.contains("anderes")),
            "{cards:?}"
        );

        // Word rule via FTS: exact token, not substring.
        ix.rule_add("word", "wwe", false).unwrap();
        let (rows, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 1, "{rows:?}");
        assert!(rows[0].stem.contains("Inception"), "{rows:?}");

        // Rule management round-trip.
        let rules = ix.rules_list().unwrap();
        assert_eq!(rules.len(), 2);
        ix.rule_delete(rules.iter().find(|r| r.field == "word").unwrap().id)
            .unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2);

        // Suggestions: three hidden German-tagged titles → lang rule
        // suggestion (drop the rule first so it isn't "taken").
        ix.rule_delete(ix.rules_list().unwrap()[0].id).unwrap();
        for stem in [
            "Anderes.Werk.2021.German.720p.WEB.x264-DEU",
            "Drittes.Ding.2022.German.2160p.WEB.x265-DEU",
        ] {
            ix.hide_title(&crate::release::parse_release(stem).key)
                .unwrap();
        }
        let sug = ix.hide_suggestions().unwrap();
        assert!(
            sug.iter()
                .any(|s| s.field == "lang" && s.value == "german" && s.n == 3),
            "{sug:?}"
        );
        // Dismissed → never again.
        ix.suggestion_dismiss("lang", "german").unwrap();
        assert!(
            ix.hide_suggestions()
                .unwrap()
                .iter()
                .all(|s| s.value != "german"),
            "dismissed suggestion must not return"
        );
        // Accepting a rule clears the dismissal and takes effect.
        ix.rule_add("lang", "german", true).unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2);
        // Unhide restores.
        ix.unhide_title(&key).unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(
            total, 2,
            "unhidden title's German release stays rule-hidden"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `genre` rule filters by the title behind the release, in the
    /// flat list and the card grid alike - and the three things about
    /// it that are easy to break.
    ///
    /// The rule used to be an exclusion list built by scanning every
    /// title; it is now a seek onto the release's own title row (see
    /// `curation_wheres`, and `genre_cost` for what that was costing).
    /// The rewrite has to keep all of this:
    ///
    /// * a title whose genres carry the value loses its releases;
    /// * a SUBSTRING still matches, because the value is whatever the
    ///   user typed into the wall's filter box ("real" is a legal way
    ///   to spell the Reality rule, and normalising the column into
    ///   exact tokens would silently stop hiding it);
    /// * a title enrichment has never reached has no genres and is
    ///   KEPT - an unknown genre is not evidence, and the old `NOT IN`
    ///   spelling kept it for the same reason.
    #[test]
    fn a_genre_rule_hides_by_title_and_keeps_the_unenriched() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-genre-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, 4 << 30);
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Big.Brother.S01E01.1080p.WEB.h264-GRP.mkv", "g1"),
                mk("Inception.2010.1080p.BluRay.x264-GRP.mkv", "g2"),
                mk("Unknown.Show.S01E01.1080p.WEB.h264-GRP.mkv", "g3"),
            ],
            1_000,
        )
        .unwrap();
        // Enrich two of the three; the third keeps no `titles` row at all.
        for (stem, genres) in [
            (
                "Big.Brother.S01E01.1080p.WEB.h264-GRP",
                "Reality, Game Show",
            ),
            ("Inception.2010.1080p.BluRay.x264-GRP", "Sci-Fi, Thriller"),
        ] {
            let key = crate::release::parse_release(stem).key;
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, genres, checked)
                     VALUES(?1, 'tv', 'T', ?2, 1)
                     ON CONFLICT(key) DO UPDATE SET genres=excluded.genres",
                    rusqlite::params![key, genres],
                )
                .unwrap();
        }
        let cur = BrowseQuery {
            curated: true,
            ..Default::default()
        };
        let (_, base) = ix.browse(&cur).unwrap();
        assert_eq!(base, 3);

        // A substring of the genre, not the whole token.
        ix.rule_add("genre", "real", false).unwrap();
        let (rows, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2, "the Reality title's release drops out: {rows:?}");
        assert!(
            rows.iter().all(|r| !r.stem.starts_with("Big.Brother")),
            "{rows:?}"
        );
        assert!(
            rows.iter().any(|r| r.stem.starts_with("Unknown.Show")),
            "an unenriched title has no genres and must survive: {rows:?}"
        );
        // The grid agrees with the list - the two renderings of the same
        // rule, which is the half that has silently disagreed before.
        let (cards, ctotal) = ix
            .browse_cards(&cur, CardSort::Latest, false, false, None)
            .unwrap();
        assert_eq!(ctotal, 2, "{cards:?}");
        assert!(
            cards.iter().all(|c| !c.rep_stem.starts_with("Big.Brother")),
            "{cards:?}"
        );
        // Uncurated facades (newznab, the *arrs) stay untouched.
        let (_, raw) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(raw, 3);
        teardown(&dir, ix);
    }

    /// A cross-posted release must not disappear from the list because
    /// the copy the dedupe picks to represent it is the copy a filter
    /// hides. The other copy is right there and passes.
    #[test]
    fn a_filtered_copy_does_not_take_the_whole_release_with_it() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-rep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk =
            |f: &str, id: &str, bytes: u64| entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, bytes);
        // ONE release, cross-posted to two groups. The moovee copy is the
        // fatter one, so it is the copy the representative pick takes.
        let dune = "Dune.Part.Two.2024.1080p.BluRay.x264-GRP.mkv";
        ix.ingest("alt.binaries.moovee", &[mk(dune, "d1", 8 << 30)], 1_000)
            .unwrap();
        ix.ingest("alt.binaries.teevee", &[mk(dune, "d2", 4 << 30)], 1_000)
            .unwrap();
        // ...and a release only the hidden group carries, so the test can
        // tell "the filter works" from "the filter eats everything".
        ix.ingest(
            "alt.binaries.moovee",
            &[mk(
                "Other.Film.2023.1080p.BluRay.x264-GRP.mkv",
                "o1",
                8 << 30,
            )],
            1_000,
        )
        .unwrap();

        let cur = BrowseQuery {
            curated: true,
            ..Default::default()
        };
        let (rows, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2, "the two copies collapse onto one row: {rows:?}");

        // Hide the group the representative copy lives in.
        ix.rule_add("group", "alt.binaries.moovee", false).unwrap();
        let (rows, total) = ix.browse(&cur).unwrap();
        let kept: Vec<&Release> = rows.iter().filter(|r| r.stem.starts_with("Dune")).collect();
        assert_eq!(
            kept.len(),
            1,
            "the cross-posted release keeps its allowed copy: {rows:?}"
        );
        assert_eq!(
            kept[0].grp, "alt.binaries.teevee",
            "and it is that copy: {rows:?}"
        );
        // The rule still rules: a release the hidden group alone carries
        // stays gone, and the count agrees with the page.
        assert!(
            !rows.iter().any(|r| r.stem.starts_with("Other")),
            "a release only the hidden group carries must stay hidden: {rows:?}"
        );
        assert_eq!(total, 1, "{rows:?}");
        assert_eq!(
            rows.len() as u64,
            total,
            "page and total must count the same: {rows:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn browse_verdict_ok_is_a_sql_predicate() {
        // M29 3c: verdict=ok must filter in SQL so `total` and the page
        // agree - the old page-level trim left `total` unfiltered, which
        // broke paging.
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-verdict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, 4 << 30);

        // Two fresh releases (→ age bucket 1) and one ancient (→ bucket 6),
        // all in the teevee family. first_posted = the ingest `now`.
        let base: i64 = 1_700_000_000;
        let now = base + 3 * 86_400; // verdict "now": fresh pair is 3d old
        ix.ingest(
            "alt.binaries.teevee",
            &[
                mk("Fresh.Show.S01E01.1080p-A.mkv", "f1"),
                mk("Fresh.Show.S01E02.1080p-A.mkv", "f2"),
            ],
            base,
        )
        .unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[mk("Ancient.Show.S01E01.1080p-A.mkv", "o1")],
            base - 2_000 * 86_400, // ~5.5y old at `now` → bucket 6
        )
        .unwrap();

        // Ledger: eweka is confidently green for teevee/bucket-1, and
        // has nothing at bucket 6 (so the ancient release is verdict None).
        ix.oracle_ingest(
            &[crate::oracle::Sample {
                host: "news.eweka.nl".into(), // → eweka
                family: "teevee".into(),
                bucket: 1,
                hits: 200,
                misses: 0,
            }],
            now,
        )
        .unwrap();
        let snap = ix.oracle_snapshot().unwrap();
        let filt = |bbs: &[&str]| VerdictFilter {
            snap: snap.clone(),
            backbones: bbs.iter().map(|s| s.to_string()).collect(),
            now,
        };

        // Baseline: all three visible.
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 3);

        // verdict=ok on eweka: only the two fresh (green) releases, and
        // `total` reflects the filter - not the unfiltered 3.
        let q = BrowseQuery {
            verdict_ok: Some(filt(&["eweka"])),
            ..Default::default()
        };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 2, "total counts only ok rows");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.stem.starts_with("Fresh")), "{rows:?}");

        // Paging over the filtered set: page size 1 walks the 2 ok rows,
        // never the ancient one, and `total` stays 2 on every page.
        let mut seen = std::collections::HashSet::new();
        for off in 0..2 {
            let q = BrowseQuery {
                verdict_ok: Some(filt(&["eweka"])),
                limit: 1,
                offset: off,
                ..Default::default()
            };
            let (rows, total) = ix.browse(&q).unwrap();
            assert_eq!(total, 2, "total stable across pages");
            assert_eq!(rows.len(), 1);
            assert!(rows[0].stem.starts_with("Fresh"), "page {off}: {rows:?}");
            seen.insert(rows[0].stem.clone());
        }
        assert_eq!(seen.len(), 2, "both ok rows reachable by paging");

        // No enabled backbones → verdict null for all → nothing is "ok".
        let q = BrowseQuery {
            verdict_ok: Some(filt(&[])),
            ..Default::default()
        };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());

        // A subsequent plain browse (no verdict filter) must be unaffected
        // by the per-request function registration/removal.
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn browse_verdict_ok_treats_undated_as_unknown() {
        // A release with no post date (first_posted <= 0) has UNKNOWN age -
        // it must not be read out of the "ancient" (bucket 6) cell the raw
        // `(now-0)/86400` math would land in. Even with that cell green, an
        // undated release must be excluded from verdict=ok.
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-undated-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, 4 << 30);
        // Ingest with now=0 and undated articles → first_posted = 0.
        ix.ingest(
            "alt.binaries.teevee",
            &[mk("Undated.Show.S01E01-A.mkv", "u1")],
            0,
        )
        .unwrap();
        // Ledger: teevee is confidently GREEN in bucket 6 (3y+) - exactly
        // the bucket the pre-fix `(now-0)/86400` misread would target.
        ix.oracle_ingest(
            &[crate::oracle::Sample {
                host: "news.eweka.nl".into(), // → eweka
                family: "teevee".into(),
                bucket: 6,
                hits: 200,
                misses: 0,
            }],
            1_700_000_000,
        )
        .unwrap();
        let snap = ix.oracle_snapshot().unwrap();
        let q = BrowseQuery {
            verdict_ok: Some(VerdictFilter {
                snap,
                backbones: vec!["eweka".into()],
                now: 1_700_000_000,
            }),
            ..Default::default()
        };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 0, "undated release must not be verdict=ok: {rows:?}");
        assert!(rows.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The property the arrivals pill depends on and that the default
    /// sort does NOT give it: the thing we saw most recently comes
    /// first, even when something else was POSTED more recently. These
    /// two orders really do disagree - a release is posted-dated by its
    /// first article, so a set that only finishes arriving now can be
    /// hours old.
    #[test]
    fn arrived_sort_orders_by_when_we_saw_it_not_when_it_was_posted() {
        let dir = std::env::temp_dir().join(format!("nzbfast-arrsort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Posted LATER (t=95_000) but seen FIRST (t=100_000).
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"Posted.Later.2020.mkv\" yEnc (1/1)",
                "p1",
                95_000,
            )],
            100_000,
        )
        .unwrap();
        // Posted EARLIER (t=91_000) but seen LAST (t=110_000) - the
        // slow-to-complete set that Latest buries.
        ix.ingest(
            "alt.test",
            &[dated_entry(
                "\"Seen.Later.2020.mkv\" yEnc (1/1)",
                "s1",
                91_000,
            )],
            110_000,
        )
        .unwrap();

        let q = BrowseQuery {
            limit: 10,
            ..Default::default()
        };
        let first = |sort| {
            let (cards, _) = ix.browse_cards(&q, sort, false, false, None).unwrap();
            cards[0].title_key.clone()
        };
        assert!(
            first(CardSort::Latest).contains("posted later"),
            "Latest must lead with the newest UPLOAD"
        );
        assert!(
            first(CardSort::Arrived).contains("seen later"),
            "Arrived must lead with the newest thing WE SAW - this is the \
             whole reason the arrivals pill switches to it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn browse_filters_sorts_and_backfills() {
        let dir = std::env::temp_dir().join(format!("nzbfast-browse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        {
            let mut ix = Index::open(&db).unwrap();
            let mk = |subj: &str, id: &str, bytes: u64, date: i64| {
                let mut e = entry(subj, "p@x", id, bytes);
                e.date = date;
                e
            };
            ix.ingest(
                "alt.test",
                &[
                    mk(
                        "\"Big.Film.2020.2160p.WEB.mkv\" yEnc (1/1)",
                        "m1",
                        5000,
                        100,
                    ),
                    mk(
                        "\"Small.Film.2021.1080p.BluRay.mkv\" yEnc (1/1)",
                        "m2",
                        1000,
                        300,
                    ),
                    mk(
                        "\"Show.S01E01.1080p.WEB.part1.rar\" yEnc (1/2)",
                        "t1",
                        800,
                        200,
                    ),
                ],
                1000,
            )
            .unwrap();
            // Ingest stored classification + part tallies.
            let all = ix.search("", 10).unwrap();
            let big = all.iter().find(|r| r.stem.starts_with("Big.Film")).unwrap();
            assert_eq!((big.kind.as_str(), big.res.as_str()), ("movie", "2160p"));
            assert_eq!((big.have_parts, big.need_parts), (1, 1));
            let show = all.iter().find(|r| r.stem.starts_with("Show.")).unwrap();
            assert_eq!(show.kind, "tv");
            assert_eq!((show.have_parts, show.need_parts), (1, 2));

            // Kind + res filters.
            let (movies, total) = ix
                .browse(&BrowseQuery {
                    kind: Some("movie".into()),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!((movies.len(), total), (2, 2));
            let (uhd, _) = ix
                .browse(&BrowseQuery {
                    res: Some("2160p".into()),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(uhd.len(), 1);
            assert!(uhd[0].stem.starts_with("Big.Film"));

            // complete_only drops the half-uploaded show.
            let (done, _) = ix
                .browse(&BrowseQuery {
                    complete_only: true,
                    ..Default::default()
                })
                .unwrap();
            assert!(done.iter().all(|r| r.complete));
            assert_eq!(done.len(), 2);

            // Sorts: posted (default, newest first), size, completeness.
            let (by_date, _) = ix.browse(&BrowseQuery::default()).unwrap();
            assert!(by_date[0].stem.starts_with("Small.Film")); // date 300
            let (by_size, _) = ix
                .browse(&BrowseQuery {
                    sort: BrowseSort::Size,
                    ..Default::default()
                })
                .unwrap();
            assert!(by_size[0].stem.starts_with("Big.Film"));
            let (by_comp, _) = ix
                .browse(&BrowseQuery {
                    sort: BrowseSort::Completeness,
                    desc: false,
                    ..Default::default()
                })
                .unwrap();
            assert!(by_comp[0].stem.starts_with("Show.")); // 50% sorts first ASC
            // "Most complete" (desc, the only direction the wall UI sends):
            // the ratio column must honor DESC, not just the tie-break.
            let (by_comp_desc, _) = ix
                .browse(&BrowseQuery {
                    sort: BrowseSort::Completeness,
                    desc: true,
                    ..Default::default()
                })
                .unwrap();
            assert!(
                !by_comp_desc[0].stem.starts_with("Show."),
                "desc completeness put the 50% release first: {}",
                by_comp_desc[0].stem
            );

            // Pagination: limit 1 pages through, total stays 3.
            let (p1, total) = ix
                .browse(&BrowseQuery {
                    limit: 1,
                    ..Default::default()
                })
                .unwrap();
            let (p2, _) = ix
                .browse(&BrowseQuery {
                    limit: 1,
                    offset: 1,
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(total, 3);
            assert_ne!(p1[0].id, p2[0].id);

            // Substring q composes with filters.
            let (hits, _) = ix
                .browse(&BrowseQuery {
                    q: "big film".into(),
                    kind: Some("movie".into()),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(hits.len(), 1);

            // Simulate a pre-M25 database: blank the columns, clear the
            // migration flag.
            ix.db
                .execute_batch(
                    "UPDATE releases SET kind='', res='', have_parts=0, need_parts=0;
                     DELETE FROM kv WHERE k='browse_cols';",
                )
                .unwrap();
        }
        // Re-open runs the backfill.
        let ix = Index::open(&db).unwrap();
        assert_eq!(ix.kv_get("browse_cols").as_deref(), Some("1"));
        let all = ix.search("", 10).unwrap();
        let big = all.iter().find(|r| r.stem.starts_with("Big.Film")).unwrap();
        assert_eq!((big.kind.as_str(), big.res.as_str()), ("movie", "2160p"));
        let show = all.iter().find(|r| r.stem.starts_with("Show.")).unwrap();
        assert_eq!((show.have_parts, show.need_parts), (1, 2));
        teardown(&dir, ix);
    }

    /// Codec / audio / dynamic range land on ingest, and rows indexed
    /// before those columns existed get them from the quality_v9 re-parse
    /// on the next open - the whole point of bumping the version key.
    #[test]
    fn codec_audio_hdr_stored_and_backfilled() {
        let dir = std::env::temp_dir().join(format!("nzbfast-qual-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let stem = "Dune.Part.Two.2024.2160p.UHD.BluRay.REMUX.DV.HDR.HEVC.TrueHD.Atmos-GRP";
        {
            let mut ix = Index::open(&db).unwrap();
            ix.ingest(
                "alt.binaries.test",
                &[entry(
                    &format!("\"{stem}.mkv\" yEnc (1/1)"),
                    "a@a",
                    "g1",
                    40 << 30,
                )],
                1_000,
            )
            .unwrap();
            let r = &ix.search("", 10).unwrap()[0];
            assert_eq!(
                (
                    r.res.as_str(),
                    r.vcodec.as_str(),
                    r.acodec.as_str(),
                    r.hdr.as_str()
                ),
                ("2160p", "x265", "Atmos", "DV"),
                "ingest should store what the parser already read"
            );
            // Simulate a database written before the columns existed.
            ix.db
                .execute_batch(
                    "UPDATE releases SET vcodec='', acodec='', hdr='';
                     DELETE FROM kv WHERE k='quality_v9';",
                )
                .unwrap();
        }
        let ix = Index::open(&db).unwrap();
        assert_eq!(ix.kv_get("quality_v9").as_deref(), Some("1"));
        let r = &ix.search("", 10).unwrap()[0];
        assert_eq!(
            (r.vcodec.as_str(), r.acodec.as_str(), r.hdr.as_str()),
            ("x265", "Atmos", "DV"),
            "re-open should have backfilled from the stem"
        );
        teardown(&dir, ix);
    }

    /// 24C Releases surface: the added (first_seen), files and kind
    /// sorts, plus browse_cards' exact-key filter (hover preview /
    /// group-by-title fetch one title's card).
    #[test]
    fn browse_seen_files_kind_sorts_and_card_key() {
        let dir = std::env::temp_dir().join(format!("nzbfast-brsort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |subj: &str, id: &str, date: i64| {
            let mut e = entry(subj, "p@x", id, 900);
            e.date = date;
            e
        };
        // Three scans at distinct times: first_seen orders by SCAN time,
        // first_posted by article date - deliberately opposite here so
        // the two sorts cannot pass by accident.
        ix.ingest(
            "alt.test",
            &[
                mk(
                    "\"Alpha.Movie.2020.1080p.WEB.part1.rar\" yEnc (1/1)",
                    "a1",
                    900,
                ),
                mk(
                    "\"Alpha.Movie.2020.1080p.WEB.part2.rar\" yEnc (1/1)",
                    "a2",
                    900,
                ),
            ],
            1000,
        )
        .unwrap();
        ix.ingest(
            "alt.test",
            &[mk(
                "\"Beta.Show.S01E01.720p.HDTV.mkv\" yEnc (1/1)",
                "b1",
                500,
            )],
            2000,
        )
        .unwrap();
        ix.ingest(
            "alt.test",
            &[mk(
                "\"Gamma.Tool.v3.2.x64.Setup.rar\" yEnc (1/1)",
                "g1",
                100,
            )],
            3000,
        )
        .unwrap();

        // Seen desc = most recently INDEXED first (Gamma), even though
        // its post date is the oldest.
        let (by_seen, _) = ix
            .browse(&BrowseQuery {
                sort: BrowseSort::Seen,
                ..Default::default()
            })
            .unwrap();
        assert!(
            by_seen[0].stem.starts_with("Gamma."),
            "{:?}",
            by_seen[0].stem
        );
        assert!(
            by_seen[2].stem.starts_with("Alpha."),
            "{:?}",
            by_seen[2].stem
        );
        // ...and posted desc still leads with Alpha (date 900).
        let (by_posted, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert!(
            by_posted[0].stem.starts_with("Alpha."),
            "{:?}",
            by_posted[0].stem
        );

        // Files desc: the two-part Alpha release carries 2 files.
        let (by_files, _) = ix
            .browse(&BrowseQuery {
                sort: BrowseSort::Files,
                ..Default::default()
            })
            .unwrap();
        assert!(
            by_files[0].stem.starts_with("Alpha."),
            "{:?}",
            by_files[0].stem
        );
        assert_eq!(by_files[0].files, 2);

        // Kind asc groups the category column: movie < software < tv.
        let (by_kind, _) = ix
            .browse(&BrowseQuery {
                sort: BrowseSort::Kind,
                desc: false,
                ..Default::default()
            })
            .unwrap();
        let kinds: Vec<&str> = by_kind.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["movie", "software", "tv"], "{by_kind:?}");

        // browse_cards: no filter = three cards; an exact title_key
        // returns just that card with total agreeing.
        let (cards, total) = ix
            .browse_cards(&Default::default(), CardSort::Latest, false, false, None)
            .unwrap();
        assert_eq!((cards.len(), total), (3, 3), "{cards:?}");
        let alpha = cards
            .iter()
            .find(|c| c.rep_stem.starts_with("Alpha."))
            .unwrap();
        let (one, total) = ix
            .browse_cards(
                &BrowseQuery {
                    title_keys: vec![alpha.title_key.clone()],
                    ..Default::default()
                },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap();
        assert_eq!((one.len(), total), (1, 1), "{one:?}");
        assert_eq!(one[0].title_key, alpha.title_key);
        assert_eq!(one[0].n_releases, 1);
        teardown(&dir, ix);
    }

    #[test]
    fn dates_gate_and_prune() {
        let dir = std::env::temp_dir().join(format!("nzbfast-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // first_posted = earliest article Date, walked back by later
        // batches (backfill scans newest-first); scan time is fallback.
        let mut a = entry("\"Old.Film.1999.part1.rar\" yEnc (1/1)", "p@x", "d1", 500);
        a.date = 2000;
        ix.ingest("alt.test", &[a], 9999).unwrap();
        assert_eq!(ix.search("old film", 10).unwrap()[0].first_posted, 2000);
        let mut b = entry("\"Old.Film.1999.par2\" yEnc (1/1)", "p@x", "d2", 100);
        b.date = 1500;
        ix.ingest("alt.test", &[b], 9999).unwrap();
        assert_eq!(ix.search("old film", 10).unwrap()[0].first_posted, 1500);
        let undated = entry("\"No.Date.2001.mkv\" yEnc (1/1)", "p@x", "d3", 500);
        ix.ingest("alt.test", &[undated], 9999).unwrap();
        assert_eq!(ix.search("no date", 10).unwrap()[0].first_posted, 9999);

        // Gate: clusters whose stem is refused never reach the DB.
        ix.set_gate(Box::new(|stem| {
            !stem.to_ascii_lowercase().contains("blocked")
        }));
        let g = entry("\"Blocked.Thing.2020.mkv\" yEnc (1/1)", "p@x", "g1", 500);
        ix.ingest("alt.test", &[g], 9999).unwrap();
        assert_eq!(ix.search("blocked", 10).unwrap().len(), 0);

        // Prune: oversize goes immediately; undersize goes once fully
        // present (all parts of every seen file) - the spam-single case.
        // A release still missing parts survives even when tiny.
        let big = entry("\"Huge.Rel.2020.part1.rar\" yEnc (1/1)", "p@x", "h1", 9000);
        let partial = entry("\"Grow.Ing.2020.part1.rar\" yEnc (1/9)", "p@x", "h2", 400);
        ix.ingest("alt.test", &[big, partial], 9999).unwrap();
        // Huge.Rel oversize + No.Date a fully-present undersize single.
        assert_eq!(ix.prune_size(600, 5000).unwrap(), 2);
        assert_eq!(ix.search("huge", 10).unwrap().len(), 0);
        assert_eq!(ix.search("no date", 10).unwrap().len(), 0);
        assert_eq!(ix.search("grow ing", 10).unwrap().len(), 1); // mid-upload, spared
        // Old.Film (600 bytes, complete): not < 600, spared - then pruned.
        assert_eq!(ix.search("old film", 10).unwrap().len(), 1);
        assert_eq!(ix.prune_size(601, 0).unwrap(), 1);
        assert_eq!(ix.search("old film", 10).unwrap().len(), 0);
        teardown(&dir, ix);
    }

    // ===== the exact `total` and the page it belongs to =====

    /// `total` must count exactly the rows paging returns - no more, no
    /// fewer - for every filter shape, over a corpus where stems really
    /// are cross-posted.
    ///
    /// This is the invariant the two statements exist to keep. They are
    /// built from ONE filter list but rendered differently: the page
    /// keeps one row per stem with the correlated best-copy predicate,
    /// the count counts distinct stems (`browse_total_sql`). An earlier
    /// version trimmed at page level and left `total` unfiltered, which
    /// broke paging; this asserts the property directly rather than
    /// asserting one spelling of the SQL, so it survives either being
    /// rewritten.
    ///
    /// The filters below are chosen so some of them EXCLUDE the copy the
    /// dedup would otherwise pick (the biggest, most complete one). That
    /// is the case the pushed-down filters in the representative
    /// subquery are for: without them the release would drop out of the
    /// list AND out of `total` while its card still showed.
    #[test]
    fn browse_total_counts_exactly_the_rows_paging_returns() {
        let dir = std::env::temp_dir().join(format!("nzbfast-browse-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        // Three stems, cross-posted 3 / 2 / 1 ways. Same stem, different
        // poster and group is a different row (UNIQUE(stem,poster,grp))
        // and one release to a reader - which is the whole point of the
        // dedup.
        let copy = |subj: &str, from: &str, id: &str, posted: i64, bytes: u64| {
            let mut e = dated_entry(subj, id, posted);
            e.from = from.into();
            e.bytes = bytes;
            e
        };
        const A: &str = "\"Cross.Posted.Film.2021.1080p.WEB.H264-GRP.mkv\" yEnc (1/1)";
        const B: &str = "\"Other.Show.S02E03.2160p.WEB.H265-GRP.mkv\" yEnc (1/1)";
        const C: &str = "\"Lonely.Film.2019.720p.BluRay.x264-GRP.mkv\" yEnc (1/1)";
        for (grp, from, tag, bytes) in [
            ("alt.binaries.moovee", "one@x", "a1", 9_000_000_000u64),
            ("alt.binaries.teevee", "two@x", "a2", 4_000_000_000),
            ("alt.binaries.hdtv", "three@x", "a3", 1_000_000_000),
        ] {
            ix.ingest("x", &[], 0).ok();
            ix.ingest(grp, &[copy(A, from, tag, 1_700_000_000, bytes)], 9_999)
                .unwrap();
        }
        for (grp, from, tag, bytes) in [
            ("alt.binaries.teevee", "one@x", "b1", 8_000_000_000u64),
            ("alt.binaries.hdtv", "two@x", "b2", 2_000_000_000),
        ] {
            ix.ingest(grp, &[copy(B, from, tag, 1_700_000_100, bytes)], 9_999)
                .unwrap();
        }
        ix.ingest(
            "alt.binaries.moovee",
            &[copy(C, "solo@x", "c1", 1_700_000_200, 3_000_000_000)],
            9_999,
        )
        .unwrap();
        // ...and one stem that differs from C in CASE alone. The
        // correlated predicate groups with `d.stem = releases.stem` and
        // the count groups with `DISTINCT`, and the two only agree
        // because `stem` carries no explicit collation. Give the pair
        // something to disagree about, so a later `COLLATE NOCASE` on
        // the column cannot land quietly.
        ix.ingest(
            "alt.binaries.moovee",
            &[copy(
                "\"LONELY.FILM.2019.720p.BluRay.x264-GRP.mkv\" yEnc (1/1)",
                "solo@x",
                "c2",
                1_700_000_300,
                3_000_000_000,
            )],
            9_999,
        )
        .unwrap();
        let rows: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 7, "the corpus must really be cross-posted");
        let stems: i64 = ix
            .db
            .query_row("SELECT COUNT(DISTINCT stem) FROM releases", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stems, 4, "case-only twins must be two stems, not one");

        // Every shape the browse surface actually issues, including ones
        // whose filter cuts the copy the dedup would have picked.
        let shapes: Vec<(&str, BrowseQuery)> = vec![
            ("everything", BrowseQuery::default()),
            (
                "curated",
                BrowseQuery {
                    max_junk: Some(50),
                    ..Default::default()
                },
            ),
            (
                "kind",
                BrowseQuery {
                    kind: Some("movie".into()),
                    ..Default::default()
                },
            ),
            (
                "res cuts the best copy",
                BrowseQuery {
                    res: Some("2160p".into()),
                    ..Default::default()
                },
            ),
            (
                "min_bytes cuts the best copy",
                BrowseQuery {
                    min_bytes: 8_500_000_000,
                    ..Default::default()
                },
            ),
            (
                "min_bytes keeps only the small copies",
                BrowseQuery {
                    min_bytes: 1_500_000_000,
                    ..Default::default()
                },
            ),
            (
                "query term",
                BrowseQuery {
                    q: "film".into(),
                    ..Default::default()
                },
            ),
            (
                "complete only",
                BrowseQuery {
                    complete_only: true,
                    ..Default::default()
                },
            ),
            (
                "nothing matches",
                BrowseQuery {
                    kind: Some("software".into()),
                    min_bytes: 900_000_000_000,
                    ..Default::default()
                },
            ),
        ];
        for (what, q) in shapes {
            let (_, total) = ix.browse(&q).unwrap();
            // Page through one row at a time: the count has to describe
            // THIS list, at every offset, not just the first page.
            let mut seen: Vec<String> = Vec::new();
            for off in 0..(total as u32 + 2) {
                let (page, t2) = ix
                    .browse(&BrowseQuery {
                        limit: 1,
                        offset: off,
                        ..q.clone()
                    })
                    .unwrap();
                assert_eq!(t2, total, "{what}: total moved between pages");
                match page.first() {
                    Some(r) => seen.push(r.stem.clone()),
                    None => break,
                }
            }
            assert_eq!(
                seen.len() as u64,
                total,
                "{what}: total={total} but paging returned {} rows",
                seen.len()
            );
            let mut uniq = seen.clone();
            uniq.sort();
            uniq.dedup();
            assert_eq!(
                uniq.len(),
                seen.len(),
                "{what}: the list handed back the same stem twice"
            );
        }
        teardown(&dir, ix);
    }

    // ===== M32: size cap + eviction =====

    // ===== measurement corpus, shared by the two #[ignore]d benches =====

    /// Build (or reuse) the deterministic synthetic corpus the two
    /// measurement tests below run on.
    ///
    /// Everything is a function of the row number - no `random()` - so a
    /// rebuild is byte-identical and two runs compare. The corpus
    /// persists at `$BROWSE_BENCH_DIR` (default: a temp dir keyed on
    /// every knob), so a second run re-times the same bytes instead of
    /// rebuilding them.
    ///
    /// `copies` is releases per stem: cross-posting is what the
    /// best-copy-per-stem dedup exists for, and at 1 there is nothing
    /// for it to do. Attributes that a re-post shares (junk, kind, res,
    /// the parse key, the post date) hang off the STEM ordinal, so the
    /// copies of one stem stand or fall together under a filter, the
    /// way real cross-posts do; the tie-break columns (size, complete,
    /// poster, group) vary per copy so the pick is a real choice.
    ///
    /// `visible_1_in` is how many releases carry `junk = 0`. The default
    /// 797 is 0.125%, which is the shape of a long-running real index
    /// (measured: 0.25%) - the junk scorer is aggressive by design, and a corpus
    /// built at a plausible-sounding 25% junk is what produced C3's
    /// first, wrong headline.
    fn bench_corpus(
        n_titles: u64,
        n_rel: u64,
        adult_1_in: u64,
        copies: u64,
        visible_1_in: u64,
    ) -> Index {
        let dir = std::env::var("BROWSE_BENCH_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::temp_dir().join(format!(
                    "nzbfast-browse-bench-{n_titles}-{n_rel}-{adult_1_in}-{copies}-{visible_1_in}"
                ))
            });
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let fresh = !db.exists();
        let ix = Index::open(&db).unwrap();
        if !fresh {
            return ix;
        }
        let t0 = std::time::Instant::now();
        // 1/adult_1_in of titles are adult by genre; 40% carry art.
        ix.db
            .execute_batch(&format!(
                "PRAGMA synchronous=OFF;
                 INSERT INTO titles(key,kind,title,year,genres,poster,checked)
                 WITH RECURSIVE s(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM s WHERE i+1 < {n_titles})
                 SELECT 't:show'||i,
                        CASE i%3 WHEN 0 THEN 'movie' ELSE 'tv' END,
                        'Title '||i, 1990+(i%35),
                        CASE WHEN i%{adult_1_in} = 0
                          THEN CASE WHEN i%2 = 0 THEN 'Hentai, Animation'
                                    ELSE 'Erotic' END
                          ELSE 'Drama, Thriller' END,
                        CASE WHEN i%5 < 2 THEN 'http://p/'||i ELSE '' END,
                        CASE WHEN i%5 < 2 THEN 1 ELSE 0 END
                 FROM s;"
            ))
            .unwrap();
        // `j` is the stem ordinal; `i` is the copy. 15% unparsed, 2%
        // adult-marked, and `junk` mostly >= 50 so the visible
        // population stays realistically small.
        let j = format!("(i/{copies})");
        ix.db
            .execute_batch(&format!(
                "INSERT INTO releases(stem,poster,grp,total_bytes,files,complete,
                                      first_posted,first_seen,kind,res,
                                      have_parts,need_parts,title_key,junk,adult)
                 WITH RECURSIVE s(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM s WHERE i+1 < {n_rel})
                 SELECT 'Some.Release.Name.'||{j}||'.1080p.WEB.H264-GRP',
                        'poster'||(i%997),
                        CASE i%4 WHEN 0 THEN 'alt.binaries.moovee' ELSE 'alt.binaries.teevee' END,
                        1000000000+(i%50)*100000000, 20+(i%30),
                        CASE WHEN i%5 < 3 THEN 1 ELSE 0 END,
                        1700000000-({j}%94608000), 1700000000,
                        CASE {j}%3 WHEN 0 THEN 'movie' ELSE 'tv' END,
                        CASE {j}%10 WHEN 0 THEN '2160p' WHEN 1 THEN '720p'
                                  WHEN 2 THEN '' ELSE '1080p' END,
                        100, 100,
                        CASE WHEN {j}%20 = 19 THEN '' ELSE 't:show'||({j}%{n_titles}) END,
                        CASE WHEN {j}%{visible_1_in} = 3 THEN 0 WHEN {j}%7 = 0 THEN 70 ELSE 100 END,
                        CASE WHEN {j}%50 = 11 THEN 1 ELSE 0 END
                 FROM s;
                 ANALYZE;"
            ))
            .unwrap();
        eprintln!("corpus built in {:?}", t0.elapsed());
        ix
    }

    // ===== best-copy-per-stem: what the exact `total` costs =====

    /// Time browse's exact `total` both ways round - the correlated
    /// best-copy-per-stem predicate it used to count through, and the
    /// `COUNT(DISTINCT +stem)` it counts with now - on one corpus, and
    /// assert the two agree at every filter shape.
    ///
    /// ```text
    /// NZBFAST_NO_ENRICH=1 BROWSE_BENCH_COPIES=4 \
    ///   cargo test --release -p nzbkit --lib browse::tests::dedup_cost \
    ///   -- --ignored --nocapture
    /// ```
    ///
    /// The equality assertion is the point as much as the timing: the
    /// rewrite is only allowed because the two count the same thing, and
    /// a corpus is a cheaper place to find out otherwise than an install.
    /// The real numbers this decision was taken on came off the 13.2M-row
    /// live index - see
    /// `research/BROWSE-stem-dedup-count-2026-08-20.md`; this is the
    /// re-runnable version.
    #[test]
    #[ignore]
    fn dedup_cost() {
        let n_titles: u64 = std::env::var("BROWSE_BENCH_TITLES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(200_000);
        let n_rel: u64 = std::env::var("BROWSE_BENCH_RELEASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_000_000);
        let adult_1_in: u64 = std::env::var("BROWSE_BENCH_ADULT_1_IN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(25);
        // Releases per stem. A long-running real index measured 9.65
        // across the whole table and 1.52 inside the visible set.
        let copies: u64 = std::env::var("BROWSE_BENCH_COPIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4);
        let visible_1_in: u64 = std::env::var("BROWSE_BENCH_VISIBLE_1_IN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(797);
        let ix = bench_corpus(n_titles, n_rel, adult_1_in, copies, visible_1_in);
        for (what, sql) in [
            ("releases", "SELECT COUNT(*) FROM releases"),
            (
                "distinct stems",
                "SELECT COUNT(DISTINCT +stem) FROM releases",
            ),
            ("visible", "SELECT COUNT(*) FROM releases WHERE junk < 50"),
        ] {
            let n: i64 = ix.db.query_row(sql, [], |r| r.get(0)).unwrap();
            eprintln!("{what}: {n}");
        }
        // The filter shapes the browse surface actually issues, worst
        // last: the wall's curated list, an *arr RSS sync (newznab sets
        // `complete_only` and no junk ceiling), and the unfiltered
        // `all=1` ask that has no ceiling at all.
        for (what, outer, inner) in [
            ("curated (junk<50)", "junk < 50", "d.junk < 50"),
            ("*arr RSS (complete)", "complete", "d.complete"),
            ("unfiltered (all=1)", "1", "1"),
        ] {
            let correlated = format!(
                "SELECT COUNT(*) FROM releases WHERE {outer}
                   AND id = (SELECT d.id FROM releases d
                             WHERE d.stem = releases.stem AND {inner}
                             ORDER BY d.complete DESC,
                                      CAST(d.have_parts AS REAL)/MAX(d.need_parts,1) DESC,
                                      d.total_bytes DESC, d.id LIMIT 1)"
            );
            let distinct = browse_total_sql(outer);
            let mut answers: Vec<i64> = Vec::new();
            eprintln!("-- {what}");
            for (name, sql) in [("correlated", &correlated), ("distinct", &distinct)] {
                let mut best = std::time::Duration::MAX;
                let mut n = 0i64;
                for _ in 0..3 {
                    let t = std::time::Instant::now();
                    n = ix.db.query_row(sql, [], |r| r.get(0)).unwrap();
                    best = best.min(t.elapsed());
                }
                answers.push(n);
                let plan = {
                    let mut st = ix.db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
                    let rows: Vec<String> = st
                        .query_map([], |r| r.get::<_, String>(3))
                        .unwrap()
                        .collect::<rusqlite::Result<_>>()
                        .unwrap();
                    rows.join(" | ")
                };
                eprintln!("   {name:<11} total={n} best={best:?}   plan: {plan}");
            }
            assert_eq!(
                answers[0], answers[1],
                "{what}: the two count forms disagree - the rewrite is only \
                 exact because they cannot"
            );
        }
    }

    // ===== hide_adult cost against the size of `titles` (measurement) =====

    /// Build (or reuse) a synthetic corpus and time `browse` with and
    /// without `hide_adult`, so the fixed `O(titles)` term the adult
    /// exclusion adds is a measured number rather than a plan reading.
    ///
    /// ```text
    /// NZBFAST_NO_ENRICH=1 BROWSE_BENCH_TITLES=1000000 \
    ///   cargo test --release -p nzbkit --lib browse::tests::adult_cost \
    ///   -- --ignored --nocapture
    /// ```
    ///
    /// The corpus persists at `$BROWSE_BENCH_DIR` (default: a temp dir
    /// keyed on the two sizes), so a second run re-times the same bytes
    /// instead of rebuilding them.
    #[test]
    #[ignore]
    fn adult_cost() {
        let n_titles: u64 = std::env::var("BROWSE_BENCH_TITLES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_000_000);
        let n_rel: u64 = std::env::var("BROWSE_BENCH_RELEASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_000_000);
        // One title in `adult_1_in` is adult by genre. The live index
        // and the C3 corpus are both around 1-4%; the knob is here
        // because after the partial index the residual cost is a
        // function of the adult population, not of `titles`.
        let adult_1_in: u64 = std::env::var("BROWSE_BENCH_ADULT_1_IN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(25);
        let ix = bench_corpus(n_titles, n_rel, adult_1_in, 1, 797);
        let titles: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM titles", [], |r| r.get(0))
            .unwrap();
        let rels: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
            .unwrap();
        let visible: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases WHERE junk < 50", [], |r| {
                r.get(0)
            })
            .unwrap();
        eprintln!("titles={titles} releases={rels} visible(junk<50)={visible}");

        let mut hidden_totals: Vec<u64> = Vec::new();
        let mut plain_total = 0u64;
        // Measure BOTH ways round on the same bytes: the partial index
        // is what schema.rs installs, so the "before" is the drop.
        for indexed in [false, true] {
            if indexed {
                let t = std::time::Instant::now();
                ix.db
                    .execute_batch(&format!(
                        "CREATE INDEX IF NOT EXISTS idx_titles_adult ON titles(key) \
                         WHERE {}",
                        adult_genre_match_sql!("")
                    ))
                    .unwrap();
                eprintln!("-- idx_titles_adult built in {:?}", t.elapsed());
            } else {
                ix.db
                    .execute_batch("DROP INDEX IF EXISTS idx_titles_adult")
                    .unwrap();
                eprintln!("-- no idx_titles_adult");
            }
            // The bare exclusion list, on its own.
            let sub = format!(
                "SELECT COUNT(*) FROM (SELECT t.key FROM titles t \
                 WHERE {ADULT_GENRE_MATCH_SQL})"
            );
            let mut keys = 0i64;
            let mut best = std::time::Duration::MAX;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                keys = ix.db.query_row(&sub, [], |r| r.get(0)).unwrap();
                best = best.min(t.elapsed());
            }
            let plan = {
                let mut st = ix.db.prepare(&format!("EXPLAIN QUERY PLAN {sub}")).unwrap();
                let rows: Vec<String> = st
                    .query_map([], |r| r.get::<_, String>(3))
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                rows.join(" | ")
            };
            eprintln!("   key set: {keys} keys, best {best:?}   plan: {plan}");
            // ...and end to end, which is what a request pays.
            for hide in [false, true] {
                let q = BrowseQuery {
                    max_junk: Some(50),
                    hide_adult: hide,
                    limit: 60,
                    ..Default::default()
                };
                let mut best = std::time::Duration::MAX;
                let mut total = 0u64;
                for _ in 0..3 {
                    let t = std::time::Instant::now();
                    let (_rows, tot) = ix.browse(&q).unwrap();
                    best = best.min(t.elapsed());
                    total = tot;
                }
                if !hide {
                    plain_total = total;
                }
                eprintln!("   browse hide_adult={hide}: total={total} best={best:?}");
                if hide {
                    hidden_totals.push(total);
                }
            }
        }
        // The index must not change the ANSWER, only the plan: a partial
        // index whose predicate has drifted from the query's would show
        // up here as a different count.
        assert_eq!(
            hidden_totals[0], hidden_totals[1],
            "idx_titles_adult changed the answer"
        );
        assert!(
            hidden_totals[0] < plain_total,
            "the corpus must actually have adult releases in the visible set \
             (hidden={}, plain={plain_total}) or this measures nothing",
            hidden_totals[0]
        );
    }

    // ===== genre hide-rule cost against the size of `titles` (measurement) =====

    /// Build (or reuse) a synthetic corpus and time the flat release
    /// list under a `genre` wall rule, once per candidate shape, so the
    /// choice between them is a measured number rather than a plan
    /// reading. Sibling of [`adult_cost`]; its own corpus because the
    /// rows here carry a realistic `overview` (a real `titles` row is
    /// mostly overview text, and the whole question is what a full pass
    /// over that table costs against a narrow index over it).
    ///
    /// ```text
    /// NZBFAST_NO_ENRICH=1 cargo test --release -p nzbkit --lib \
    ///   browse::tests::genre_cost -- --ignored --nocapture
    /// ```
    ///
    /// Knobs: `BROWSE_BENCH_TITLES` (1,000,000), `BROWSE_BENCH_RELEASES`
    /// (2,000,000), `BROWSE_BENCH_OVERVIEW` (400 bytes of overview per
    /// title), `BROWSE_BENCH_DIR`.
    #[test]
    #[ignore]
    fn genre_cost() {
        let n_titles: u64 = env_u64("BROWSE_BENCH_TITLES", 1_000_000);
        let n_rel: u64 = env_u64("BROWSE_BENCH_RELEASES", 2_000_000);
        let overview: u64 = env_u64("BROWSE_BENCH_OVERVIEW", 400);
        let dir = std::env::var("BROWSE_BENCH_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::temp_dir().join(format!(
                    "nzbfast-browse-genre-bench-{n_titles}-{n_rel}-{overview}"
                ))
            });
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let fresh = !db.exists();
        let ix = Index::open(&db).unwrap();
        if fresh {
            let t0 = std::time::Instant::now();
            // Deterministic: every column is a function of the row
            // number. Genres are one of eight lists, so `reality` names
            // 5% of titles and `drama` names 50% - the two ends of how
            // selective a real rule is.
            ix.db
                .execute_batch(&format!(
                    "PRAGMA synchronous=OFF;
                     INSERT INTO titles(key,kind,title,year,genres,overview,poster,backdrop,checked)
                     WITH RECURSIVE s(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM s WHERE i+1 < {n_titles})
                     SELECT 't:show'||i,
                            CASE i%3 WHEN 0 THEN 'movie' ELSE 'tv' END,
                            'Title '||i, 1990+(i%35),
                            CASE i%20
                              WHEN 0 THEN 'Reality'
                              WHEN 1 THEN 'Talk Show, News'
                              WHEN 2 THEN 'Documentary'
                              WHEN 3 THEN 'Animation, Family'
                              WHEN 4 THEN 'Sci-Fi, Action'
                              WHEN 5 THEN 'Horror, Thriller'
                              WHEN 6 THEN 'Horror, Mystery'
                              WHEN 7 THEN 'Comedy, Romance'
                              WHEN 8 THEN 'Comedy, Family'
                              WHEN 9 THEN 'Crime, Mystery'
                              ELSE 'Drama, Thriller' END,
                            SUBSTR(HEX(ZEROBLOB({overview})), 1, {overview}),
                            'http://p/'||i, 'http://b/'||i,
                            CASE WHEN i%5 < 2 THEN 1 ELSE 0 END
                     FROM s;"
                ))
                .unwrap();
            // Releases: the same shape adult_cost uses, so the visible
            // population (junk < 50) stays small and the measurement is
            // about the titles-side term and nothing else.
            ix.db
                .execute_batch(&format!(
                    "INSERT INTO releases(stem,poster,grp,total_bytes,files,complete,
                                          first_posted,first_seen,kind,res,
                                          have_parts,need_parts,title_key,junk,adult)
                     WITH RECURSIVE s(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM s WHERE i+1 < {n_rel})
                     SELECT 'Some.Release.Name.'||i||'.1080p.WEB.H264-GRP',
                            'poster'||(i%997)||'@example.invalid',
                            CASE i%4 WHEN 0 THEN 'alt.binaries.moovee' ELSE 'alt.binaries.teevee' END,
                            1000000000+(i%50)*100000000, 20+(i%30),
                            CASE WHEN i%5 < 3 THEN 1 ELSE 0 END,
                            1700000000-(i%94608000), 1700000000,
                            CASE i%3 WHEN 0 THEN 'movie' ELSE 'tv' END,
                            CASE i%10 WHEN 0 THEN '2160p' WHEN 1 THEN '720p'
                                      WHEN 2 THEN '' ELSE '1080p' END,
                            100, 100,
                            CASE WHEN i%20 = 19 THEN '' ELSE 't:show'||(i%{n_titles}) END,
                            CASE WHEN i%797 = 3 THEN 0 WHEN i%7 = 0 THEN 70 ELSE 100 END,
                            CASE WHEN i%50 = 11 THEN 1 ELSE 0 END
                     FROM s;
                     ANALYZE;"
                ))
                .unwrap();
            eprintln!("corpus built in {:?}", t0.elapsed());
        }
        let count = |sql: &str| -> i64 { ix.db.query_row(sql, [], |r| r.get(0)).unwrap() };
        eprintln!(
            "titles={} releases={} visible(junk<50)={} db={:.1} MB",
            count("SELECT COUNT(*) FROM titles"),
            count("SELECT COUNT(*) FROM releases"),
            count("SELECT COUNT(*) FROM releases WHERE junk < 50"),
            std::fs::metadata(&db).unwrap().len() as f64 / 1e6,
        );

        // ---- the shapes under test -------------------------------------
        // Every one of them renders the SAME rule set two ways (the outer
        // list and the `d.` representative pick) into the SAME two
        // statements browse issues (the exact COUNT and the page), so
        // what is timed is what a request pays.
        #[derive(Clone, Copy, PartialEq)]
        enum Shape {
            /// Today: `NOT IN (SELECT key FROM titles WHERE genres LIKE '%v%')`.
            Today,
            /// Same, hoisted into ONE materialized CTE per statement.
            Cte,
            /// Normalized `title_genres`, exact match on the token.
            NormExact,
            /// Normalized, prefix match (`genre LIKE 'v%'`).
            NormPrefix,
            /// Normalized, correlated `NOT EXISTS` per candidate row.
            NormExists,
            /// No new table at all: a correlated `NOT EXISTS` that seeks
            /// the `titles` PRIMARY KEY and tests the SAME substring.
            ExistsTitles,
        }
        let term = |shape: Shape, pfx: &str, n: usize| -> String {
            match shape {
                Shape::Today => format!(
                    "{pfx}title_key NOT IN (SELECT key FROM titles WHERE genres LIKE '%' || ?{n} || '%')"
                ),
                Shape::Cte => format!("{pfx}title_key NOT IN (SELECT key FROM gk{n})"),
                Shape::NormExact => {
                    format!(
                        "{pfx}title_key NOT IN (SELECT key FROM title_genres WHERE genre = ?{n})"
                    )
                }
                Shape::NormPrefix => format!(
                    "{pfx}title_key NOT IN (SELECT key FROM title_genres WHERE genre LIKE ?{n} || '%')"
                ),
                Shape::NormExists => format!(
                    "NOT EXISTS (SELECT 1 FROM title_genres g \
                     WHERE g.key = {pfx}title_key AND g.genre = ?{n})"
                ),
                Shape::ExistsTitles => format!(
                    "NOT EXISTS (SELECT 1 FROM titles t WHERE t.key = {pfx}title_key \
                     AND t.genres LIKE '%' || ?{n} || '%')"
                ),
            }
        };
        // browse's own two statements, with the rule terms rendered in.
        // The two candidate sets: what the wall's list asks for, and
        // what a request with no junk ceiling asks for - the second is
        // the whole 2M-row table, standing in for a real index whose
        // VISIBLE population is large (the shapes below do not all
        // scale the same way in it).
        const VISIBLE: &str = "junk < 50";
        // ~288k rows: the visible population of a real long-running
        // index (measured at 249k in the C3 round), which is where the
        // two families of shape actually have to be compared - one
        // costs O(titles) per rendering, the other a seek per candidate
        // row, and 2.5k and 2M are the two ends of nothing in between.
        const MID: &str = "junk < 80";
        const ALL: &str = "junk >= 0";
        let build = |shape: Shape, rules: &[&str], cand: &str| -> (String, String) {
            let rendered = |pfx: &str| -> String {
                rules
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!(" AND {}", term(shape, pfx, i + 1)))
                    .collect::<String>()
            };
            let cte = if shape == Shape::Cte {
                let legs: Vec<String> = (1..=rules.len())
                    .map(|n| {
                        format!(
                            "gk{n} AS MATERIALIZED \
                             (SELECT key FROM titles WHERE genres LIKE '%' || ?{n} || '%')"
                        )
                    })
                    .collect();
                format!("WITH {} ", legs.join(", "))
            } else {
                String::new()
            };
            let body = format!(
                "FROM releases WHERE {cand}{outer}
                   AND id = (SELECT d.id FROM releases d
                             WHERE d.stem = releases.stem AND d.{cand}{rep}
                             ORDER BY d.complete DESC,
                                      CAST(d.have_parts AS REAL)/MAX(d.need_parts,1) DESC,
                                      d.total_bytes DESC, d.id LIMIT 1)",
                outer = rendered(""),
                rep = rendered("d."),
            );
            (
                format!("{cte}SELECT COUNT(*) {body}"),
                format!(
                    "{cte}SELECT {REL_COLS} {body} ORDER BY first_posted DESC, id DESC LIMIT 60"
                ),
            )
        };
        // best-of-3 for the pair, plus the COUNT's answer and its plan.
        // The two statements are timed SEPARATELY as well as together:
        // the page stops early on `idx_rel_visible_posted` once it has
        // its 60 rows, while the exact COUNT has to walk every candidate
        // row and pay the per-stem dedup on each - so the split says
        // which of the two any future work should aim at.
        let time3 = |shape: Shape, rules: &[&str], cand: &str| -> Timing {
            let (c, p) = build(shape, rules, cand);
            let vals: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
            let mut both = std::time::Duration::MAX;
            let mut best_c = std::time::Duration::MAX;
            let mut best_p = std::time::Duration::MAX;
            let mut total = 0i64;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                total = ix
                    .db
                    .query_row(&c, rusqlite::params_from_iter(vals.iter()), |r| r.get(0))
                    .unwrap();
                let tc = t.elapsed();
                let t2 = std::time::Instant::now();
                let mut st = ix.db.prepare(&p).unwrap();
                let n = st
                    .query_map(rusqlite::params_from_iter(vals.iter()), |r| {
                        r.get::<_, i64>(0)
                    })
                    .unwrap()
                    .count();
                let tp = t2.elapsed();
                assert!(n <= 60);
                best_c = best_c.min(tc);
                best_p = best_p.min(tp);
                both = both.min(t.elapsed());
            }
            let plan = {
                let mut st = ix.db.prepare(&format!("EXPLAIN QUERY PLAN {c}")).unwrap();
                let rows: Vec<String> = st
                    .query_map(rusqlite::params_from_iter(vals.iter()), |r| {
                        r.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                rows.join(" | ")
            };
            Timing {
                both,
                count: best_c,
                page: best_p,
                total,
                plan,
            }
        };
        // The pair-only shape, for the legs that do not want the split.
        let time = |shape: Shape, rules: &[&str], cand: &str| {
            let t = time3(shape, rules, cand);
            (t.both, t.total, t.plan)
        };

        // The control: the same two statements with no rule at all.
        let (base, base_total, _) = time(Shape::Today, &[], VISIBLE);
        eprintln!("\nno rules: total={base_total} best={base:?}");
        // Fidelity: browse() itself, with the rule really installed,
        // must cost what the replica above says it does.
        ix.db
            .execute(
                "INSERT INTO wall_rules(field, value, added) VALUES('genre','reality',1)",
                [],
            )
            .unwrap();
        let q = BrowseQuery {
            max_junk: Some(50),
            curated: true,
            limit: 60,
            ..Default::default()
        };
        let mut real = std::time::Duration::MAX;
        let mut real_total = 0u64;
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let (_r, tot) = ix.browse(&q).unwrap();
            real = real.min(t.elapsed());
            real_total = tot;
        }
        let (rep, rep_total, _) = time(Shape::Today, &["reality"], VISIBLE);
        eprintln!(
            "browse() with the rule: total={real_total} best={real:?}   \
             replica: total={rep_total} best={rep:?}"
        );
        ix.db.execute("DELETE FROM wall_rules", []).unwrap();

        // ---- leg 1: today's shape, and what a covering index does to it ----
        // The corpus persists between runs, so drop anything an earlier
        // run created before measuring the baseline - `titles(key,
        // genres)` covers the exclusion list too, and leaving it behind
        // silently turns the "no index" leg into an indexed one.
        ix.db
            .execute_batch(
                "DROP INDEX IF EXISTS idx_titles_genres;
                 DROP INDEX IF EXISTS idx_titles_key_genres;
                 DROP TABLE IF EXISTS title_genres;
                 DELETE FROM wall_hidden;",
            )
            .unwrap();
        let sets: [&[&str]; 3] = [
            &["reality"],                          // 5% of titles
            &["reality", "documentary", "horror"], // three rules, as the UI allows
            &["drama"],                            // 50% - the broad end
        ];
        for (label, extra) in [
            (
                "no idx_titles_genres",
                "DROP INDEX IF EXISTS idx_titles_genres",
            ),
            (
                "idx_titles_genres(genres,key)",
                "CREATE INDEX IF NOT EXISTS idx_titles_genres ON titles(genres, key)",
            ),
        ] {
            let t = std::time::Instant::now();
            ix.db.execute_batch(extra).unwrap();
            eprintln!("\n== {label} ({:?})", t.elapsed());
            eprintln!(
                "   db file: {:.1} MB",
                std::fs::metadata(&db).unwrap().len() as f64 / 1e6
            );
            for rules in sets {
                for shape in [Shape::Today, Shape::Cte] {
                    let (d, tot, plan) = time(shape, rules, VISIBLE);
                    let tag = if shape == Shape::Today {
                        "today"
                    } else {
                        "cte  "
                    };
                    eprintln!("   {tag} {rules:?}: total={tot} best={d:?}\n      {plan}");
                }
            }
        }

        // ---- leg 2: the normalized table ------------------------------
        let t = std::time::Instant::now();
        ix.db
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS title_genres(
                    key TEXT NOT NULL, genre TEXT NOT NULL,
                    PRIMARY KEY(genre, key)) WITHOUT ROWID;
                 DELETE FROM title_genres;
                 INSERT INTO title_genres(key, genre)
                 WITH RECURSIVE split(key, one, rest) AS (
                   SELECT key, '', LOWER(genres)||',' FROM titles WHERE genres <> ''
                   UNION ALL
                   SELECT key, TRIM(SUBSTR(rest, 1, INSTR(rest, ',')-1)),
                          SUBSTR(rest, INSTR(rest, ',')+1)
                   FROM split WHERE rest <> '')
                 SELECT DISTINCT key, one FROM split WHERE one <> '';
                 ANALYZE;",
            )
            .unwrap();
        eprintln!(
            "\n== title_genres built in {:?}: {} rows, {} distinct genres",
            t.elapsed(),
            count("SELECT COUNT(*) FROM title_genres"),
            count("SELECT COUNT(DISTINCT genre) FROM title_genres"),
        );
        for rules in sets {
            for shape in [Shape::NormExact, Shape::NormPrefix, Shape::NormExists] {
                let (d, tot, plan) = time(shape, rules, VISIBLE);
                let tag = match shape {
                    Shape::NormExact => "exact ",
                    Shape::NormPrefix => "prefix",
                    _ => "exists",
                };
                eprintln!("   {tag} {rules:?}: total={tot} best={d:?}\n      {plan}");
            }
        }

        // ---- leg 2b: the same correlated shape with NO new table ------
        // `titles.key` is already a PRIMARY KEY, so the substring test
        // can be asked per candidate row instead of per title, with the
        // ORIGINAL predicate and no schema change at all.
        for (label, ddl) in [
            (
                "titles PK seek",
                "DROP INDEX IF EXISTS idx_titles_key_genres",
            ),
            (
                "+ idx_titles_key_genres(key,genres)",
                "CREATE INDEX IF NOT EXISTS idx_titles_key_genres ON titles(key, genres)",
            ),
        ] {
            let t = std::time::Instant::now();
            ix.db.execute_batch(ddl).unwrap();
            eprintln!("\n== NOT EXISTS over titles, {label} ({:?})", t.elapsed());
            for rules in sets {
                let (d, tot, plan) = time(Shape::ExistsTitles, rules, VISIBLE);
                eprintln!("   exists-titles {rules:?}: total={tot} best={d:?}\n      {plan}");
            }
        }

        // ---- leg 2c: how each shape scales with the CANDIDATE rows ----
        // The subquery shapes cost O(titles) per rendering and do not
        // care how many releases the page considers; the correlated
        // ones cost a seek per candidate row and care about nothing
        // else. `junk >= 0` is every release in the table.
        //
        // Two index states, because the correlated shape's per-row cost
        // is a primary-key descent PLUS a table fetch (the PK autoindex
        // carries `key` -> rowid, not `genres`), and a covering index on
        // (key, genres) is the only thing that can remove the fetch. At
        // 2,510 candidate rows it measured SLOWER - a wider b-tree to
        // descend, and no fixed cost to amortise it against - but the
        // tail is the one place the shipped shape is behind the shape it
        // replaced, and the tail is where removing a per-row fetch pays.
        for (label, ddl) in [
            (
                "no extra index",
                "DROP INDEX IF EXISTS idx_titles_genres;
                 DROP INDEX IF EXISTS idx_titles_key_genres;",
            ),
            (
                "+ idx_titles_key_genres(key,genres)",
                "CREATE INDEX IF NOT EXISTS idx_titles_key_genres ON titles(key, genres)",
            ),
        ] {
            let t0 = std::time::Instant::now();
            ix.db.execute_batch(ddl).unwrap();
            eprintln!(
                "\n== candidate-row scaling, rule ['reality'], {label} (ddl {:?}, db {:.1} MB)",
                t0.elapsed(),
                std::fs::metadata(&db).unwrap().len() as f64 / 1e6,
            );
            for (tag, cand) in [
                ("visible junk<50", VISIBLE),
                ("mid     junk<80", MID),
                ("all     2M rows", ALL),
            ] {
                for (name, shape) in [
                    ("today        ", Shape::Today),
                    ("exists-titles", Shape::ExistsTitles),
                ] {
                    let t = time3(shape, &["reality"], cand);
                    eprintln!(
                        "   {tag} {name}: total={} both={:?} (count={:?} page={:?})",
                        t.total, t.both, t.count, t.page
                    );
                }
                // The control is also the DEDUP measurement: with no
                // rule at all, what is left in these two statements is
                // the per-stem best-copy subquery and the walk itself.
                let t = time3(Shape::Today, &[], cand);
                eprintln!(
                    "   {tag} no rules     : total={} both={:?} (count={:?} page={:?})",
                    t.total, t.both, t.count, t.page
                );
                // ...and the same pair with the dedup term REMOVED, so
                // the dedup's own share is a subtraction and not an
                // inference. This is not a shippable query - it lists
                // cross-posted copies twice - it is the floor.
                let bare_count = format!("SELECT COUNT(*) FROM releases WHERE {cand}");
                let bare_page = format!(
                    "SELECT {REL_COLS} FROM releases WHERE {cand} \
                     ORDER BY first_posted DESC, id DESC LIMIT 60"
                );
                let mut bc = std::time::Duration::MAX;
                let mut bp = std::time::Duration::MAX;
                let mut n = 0i64;
                for _ in 0..3 {
                    let t = std::time::Instant::now();
                    n = ix.db.query_row(&bare_count, [], |r| r.get(0)).unwrap();
                    bc = bc.min(t.elapsed());
                    let t = std::time::Instant::now();
                    let mut st = ix.db.prepare(&bare_page).unwrap();
                    let _ = st.query_map([], |r| r.get::<_, i64>(0)).unwrap().count();
                    bp = bp.min(t.elapsed());
                }
                eprintln!(
                    "   {tag} no dedup     : total={n} both={:?} (count={:?} page={:?})",
                    bc + bp,
                    bc,
                    bp
                );
            }
        }

        // ---- leg 3: the other subquery-shaped rules in the same function ----
        ix.db
            .execute_batch(
                "INSERT OR IGNORE INTO wall_hidden(key, at)
                 SELECT key, 1 FROM titles WHERE key LIKE 't:show1%' LIMIT 500;",
            )
            .unwrap();
        eprintln!(
            "\n== wall_hidden: {} rows",
            count("SELECT COUNT(*) FROM wall_hidden")
        );
        for (tag, outer, rep) in [
            (
                "wall_hidden",
                "title_key NOT IN (SELECT key FROM wall_hidden)".to_string(),
                "d.title_key NOT IN (SELECT key FROM wall_hidden)".to_string(),
            ),
            (
                // The designed case: the suggestion path refuses a word
                // carried by more than 500 titles.
                "word rare",
                "id NOT IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)".to_string(),
                "d.id NOT IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)".to_string(),
            ),
            (
                // ...and a hand-typed one that matches every release,
                // which nothing gates.
                "word common",
                "id NOT IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)".to_string(),
                "d.id NOT IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)".to_string(),
            ),
        ] {
            let sql = format!(
                "SELECT COUNT(*) FROM releases WHERE junk < 50 AND {outer}
                   AND id = (SELECT d.id FROM releases d
                             WHERE d.stem = releases.stem AND d.junk < 50 AND {rep}
                             ORDER BY d.complete DESC, d.id LIMIT 1)"
            );
            let vals: Vec<String> = match tag {
                "word rare" => vec!["\"424242\"".into()],
                "word common" => vec!["\"name\"".into()],
                _ => vec![],
            };
            let mut best = std::time::Duration::MAX;
            let mut tot = 0i64;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                tot = ix
                    .db
                    .query_row(&sql, rusqlite::params_from_iter(vals.iter()), |r| r.get(0))
                    .unwrap();
                best = best.min(t.elapsed());
            }
            eprintln!("   {tag}: total={tot} best={best:?}");
        }
    }

    /// One measured request: the pair, and each statement on its own.
    struct Timing {
        both: std::time::Duration,
        count: std::time::Duration,
        page: std::time::Duration,
        total: i64,
        plan: String,
    }

    fn env_u64(k: &str, d: u64) -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(d)
    }
}
