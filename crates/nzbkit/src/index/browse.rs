//! The browse query surface (TODO 106 phase 2.2, cut 3): BrowseQuery and
//! its filters, the adult-genre predicate, curation (hidden titles, wall
//! rules, hide suggestions) and `browse` itself. Bodies are verbatim moves
//! from the old index.rs; see research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::cards::RES_RANK_SQL;
use super::query::{fts_match, stem_fold_arm};
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
            const PS: &str =
                "REPLACE(REPLACE(REPLACE(LOWER({}pre_title),'.',' '),'_',' '),'-',' ')";
            // Unicode fold, not `to_ascii_lowercase`: the stem arm is
            // `stem_fold_arm`, whose second half is written in the same
            // fold, so the query side has to speak it too. See
            // index/fold.rs and TODO 5 phase 2c.
            for term in fold::query(&q.q).split(' ').filter(|t| !t.is_empty()) {
                let p = bind(&mut params, Box::new(term.to_string()));
                let stem_arm = stem_fold_arm("{}", &p);
                wheres.push(format!(
                    "({stem_arm} \
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
                // Both arms, negated: a row is kept only if NEITHER
                // the ASCII expression nor the Unicode fold column
                // holds the word. `value` was already Unicode-lowercased
                // here, which before TODO 5 phase 2c meant a rule
                // spelled in Cyrillic could not hide an uppercase stem
                // it plainly named - `LOWER()` left the stem shouting.
                "word" => {
                    params.push(Box::new(format!("% {} %", fold::query(&value))));
                    wheres.push(format!(
                        "(' '||REPLACE(REPLACE(REPLACE(LOWER({pfx}stem),'.',' '),'_',' '),'-',' ')||' ' \
                            NOT LIKE ?{n} \
                          AND ({pfx}stem_fold = '' OR ' '||{pfx}stem_fold||' ' NOT LIKE ?{n}))"
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
mod tests;
