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
macro_rules! adult_genre_match_sql {
    () => {
        "(\
     LOWER(COALESCE(t.genres,'')) LIKE '%hentai%' \
     OR LOWER(COALESCE(t.genres,'')) LIKE '%erotic%' \
     OR LOWER(TRIM(COALESCE(t.genres,''))) = 'adult')"
    };
}

pub const ADULT_GENRE_SQL: &str = concat!("NOT ", adult_genre_match_sql!());

/// The same test the POSITIVE way round, for a query that has to SELECT
/// adult titles rather than exclude them - the flat release list has no
/// `titles` join, so it filters with a `title_key NOT IN (SELECT … WHERE
/// <this>)` subquery instead.
///
/// Both spellings come from one literal on purpose: they are the two
/// halves that have to agree, and they did not - the grouped view
/// carried the filter and the flat one did not, so turning group-by-
/// title off brought every Adult/Hentai/Erotic release straight back.
pub const ADULT_GENRE_MATCH_SQL: &str = adult_genre_match_sql!();

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
                &format!("SELECT COUNT(*) FROM releases WHERE {where_clause}"),
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
        params.push(Box::new(q.limit.min(500)));
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
                // value ("reality", "sports", ...) - resolved through a
                // titles subquery so the flat list filters identically
                // to the card grid.
                "genre" => {
                    params.push(Box::new(value));
                    wheres.push(format!(
                        "{pfx}title_key NOT IN (SELECT key FROM titles
                          WHERE genres LIKE '%' || ?{n} || '%')"
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

        // Ledger: omicron is confidently green for teevee/bucket-1, and
        // has nothing at bucket 6 (so the ancient release is verdict None).
        ix.oracle_ingest(
            &[crate::oracle::Sample {
                host: "news.eweka.nl".into(), // → omicron
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

        // verdict=ok on omicron: only the two fresh (green) releases, and
        // `total` reflects the filter - not the unfiltered 3.
        let q = BrowseQuery {
            verdict_ok: Some(filt(&["omicron"])),
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
                verdict_ok: Some(filt(&["omicron"])),
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
                host: "news.eweka.nl".into(), // omicron
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
                backbones: vec!["omicron".into()],
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

    // ===== M32: size cap + eviction =====
}
