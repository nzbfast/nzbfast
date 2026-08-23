//! Free-text search (TODO 106 phase 2.2, cut 4): the FTS MATCH builder,
//! `search`, `find_by_header`, and the imdb/tmdb/year title lookups.
//! Bodies are verbatim moves from the old index.rs; see
//! research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;

// ---- Instrument-first: the filename fallback's cost ----
//
// Rung 3 of [`Index::find_by_header_once`] is a full scan of `files`: no
// index covers `filename` alone. Measured on a 16.5M-release /
// 17.7M-file index, a header that matches NOTHING costs 2.4 s warm and
// 4.3 s cold there, all of it holding the single shared read connection
// every other index reader queues behind; a header the indexed rungs
// answer is sub-millisecond.
//
// The fix would be a dedicated filename index, which is large on disk and
// adds a write to every ingested file - a real, permanent cost paid on
// every scan pass. It is only worth that if genuine miss traffic exists,
// which is a question about how people actually use NZBLNK links, not one
// the code can answer. So this counts the rung: how often it runs, how
// often it earns its scan, and the wall time it spends either way. The
// hit time is kept beside the miss time deliberately - the comparison is
// what says whether an index would pay.
//
// Double-counting note: `retry_on_schema_change` re-runs the whole ladder
// when the schema moves under a reader, so such a retry counts its second
// pass too. That is rare and it IS work the process really did.

static FN_FALLBACK_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FN_FALLBACK_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FN_FALLBACK_HIT_NANOS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FN_FALLBACK_MISS_NANOS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A snapshot of the filename-fallback census (see the section note).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilenameFallback {
    /// Times the header ladder fell through to the unindexed filename
    /// scan - both indexed rungs and the FTS rung having answered nothing.
    pub calls: u64,
    /// Of those, the scans that returned at least one release.
    pub hits: u64,
    /// Of those, the scans that returned nothing at all - the case a
    /// dedicated filename index would turn from a scan into a lookup.
    pub misses: u64,
    /// Wall time inside the scan on the hit path.
    pub hit_nanos: u64,
    /// Wall time inside the scan on the miss path.
    pub miss_nanos: u64,
}

/// Record one filename-fallback scan: bump the census and log one
/// greppable line. Cheap by construction - the scan it brackets is
/// measured in seconds, so an `Instant` and four relaxed adds are free,
/// and nothing but this rung ever reaches it.
fn note_filename_fallback(header: &str, hit: bool, took: std::time::Duration) {
    use std::sync::atomic::Ordering;
    let nanos = took.as_nanos().min(u128::from(u64::MAX)) as u64;
    FN_FALLBACK_CALLS.fetch_add(1, Ordering::Relaxed);
    if hit {
        FN_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
        FN_FALLBACK_HIT_NANOS.fetch_add(nanos, Ordering::Relaxed);
    } else {
        FN_FALLBACK_MISS_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    tracing::info!(
        target: "index",
        "filename-fallback: chars={} result={} took={:.3}s",
        header.chars().count(),
        if hit { "hit" } else { "miss" },
        took.as_secs_f64(),
    );
}

/// Current filename-fallback census (process lifetime). Surfaced by the
/// daemon stats API and asserted by the census tests.
pub fn filename_fallback_stats() -> FilenameFallback {
    use std::sync::atomic::Ordering;
    let calls = FN_FALLBACK_CALLS.load(Ordering::Relaxed);
    let hits = FN_FALLBACK_HITS.load(Ordering::Relaxed);
    FilenameFallback {
        calls,
        hits,
        misses: calls.saturating_sub(hits),
        hit_nanos: FN_FALLBACK_HIT_NANOS.load(Ordering::Relaxed),
        miss_nanos: FN_FALLBACK_MISS_NANOS.load(Ordering::Relaxed),
    }
}

/// Reset the census to zero. Test-only: the counters are process-global,
/// so a test that asserts exact counts must isolate itself first.
#[doc(hidden)]
pub fn reset_filename_fallback_stats() {
    use std::sync::atomic::Ordering;
    for c in [
        &FN_FALLBACK_CALLS,
        &FN_FALLBACK_HITS,
        &FN_FALLBACK_HIT_NANOS,
        &FN_FALLBACK_MISS_NANOS,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}

/// FTS5 MATCH string for user query terms: each term quoted (embedded
/// quotes doubled) with a `*` prefix marker - "kill bill" → `"kill"* "bill"*`
/// (space = implicit AND). Empty when the query has no usable terms.
pub(super) fn fts_match(query: &str) -> String {
    query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"*", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The stem half of a normalized substring match, in SQL.
///
/// Two arms, and both are needed: the `REPLACE`/`LOWER` expression is
/// what SQLite can compute for itself, and `stem_fold` is the Unicode
/// fold of the rows whose case `LOWER()` cannot reach - Cyrillic, Greek,
/// and every other script outside `A-Z`. The column is sparse ('' means
/// "the expression on the left is already correct for this row", which
/// is nearly every row), so the fold arm is an ADDITION to the old
/// clause, never a replacement for it, and the `<> ''` test spells that
/// out for the reader as well as skipping a LIKE that cannot match. See
/// index/fold.rs.
///
/// `pfx` is the table-alias placeholder the caller's own SQL uses (`""`
/// where there is none, `"{}"` in browse.rs / cards.rs, whose `alias()`
/// fills it in later); `p` is the already-rendered bind reference.
///
/// The `LOWER(...)` spelling here and [`fold::sql_twin`] are one
/// expression in two languages. Change either and change both, or the
/// two arms of the search start disagreeing about what a stem says.
pub(super) fn stem_fold_arm(pfx: &str, p: &str) -> String {
    format!(
        "(REPLACE(REPLACE(REPLACE(LOWER({pfx}stem),'.',' '),'_',' '),'-',' ') \
           LIKE '%' || {p} || '%' \
         OR ({pfx}stem_fold <> '' AND {pfx}stem_fold LIKE '%' || {p} || '%'))"
    )
}

impl Index {
    /// Search by substring over the stem (case-insensitive), newest first.
    pub(super) fn search_once(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        // Separator-insensitive, multi-term AND search: stems are stored
        // dotted ("Show.Name.S01E02") but *arr clients query with spaces
        // ("show name s01e02"), so normalize both sides to spaces and
        // require every query word to appear. Empty query = everything.
        //
        // The fold is Unicode (index/fold.rs), not `to_ascii_lowercase`
        // as it was until TODO 5 phase 2c: a query typed in lowercase
        // Cyrillic or Greek has to reach the `stem_fold` arm below in
        // the same spelling that column was written in.
        let terms: Vec<String> = fold::query(query)
            .split(' ')
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();
        // M28: FTS path - prefix-match every term against the stem index
        // instead of a triple-REPLACE full scan per request. Gate on the
        // FTS expression itself, not `terms`: a punctuation-only query
        // ("!!!") yields a non-empty `terms` but an EMPTY fts_match, and
        // `rel_fts MATCH ''` is a hard FTS5 error - fall through to the
        // LIKE scan instead (mirrors browse()).
        let m = if self.fts {
            fts_match(query)
        } else {
            String::new()
        };
        if !m.is_empty() {
            // Two indexes, one query: the stem index (what was posted)
            // and the pre-feed name index (what it was called). Without
            // the second leg a release the feed rescued is invisible to
            // every search for its real title - which is the entire
            // point of having rescued it.
            let leg = if self.pre_fts {
                "OR id IN (SELECT rowid FROM pre_fts WHERE pre_fts MATCH ?1)"
            } else {
                ""
            };
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases
                 WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1) {leg}
                 ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            let rows = stmt.query_map(rusqlite::params![m, limit], release_from_row)?;
            return rows.collect();
        }
        // The pre-feed leg's own normalization. It mirrors
        // `fold::sql_twin` as far as SQL can, which is ASCII only - the
        // stem leg gets the rest from `stem_fold_arm`, and a fed name
        // has no fold column of its own (see index/fold.rs).
        const PS: &str = "REPLACE(REPLACE(REPLACE(LOWER(pre_title),'.',' '),'_',' '),'-',' ')";
        let where_clause = if terms.is_empty() {
            "1=1".to_string()
        } else {
            // Same pairing as the FTS path above: match either the
            // posted stem or the name the feed gave it. Both chains cite
            // the same ?N, so the bind list is unchanged.
            let chain = |col: &str| {
                terms
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("{col} LIKE '%' || ?{} || '%'", i + 1))
                    .collect::<Vec<_>>()
                    .join(" AND ")
            };
            let stem_chain = terms
                .iter()
                .enumerate()
                .map(|(i, _)| stem_fold_arm("", &format!("?{}", i + 1)))
                .collect::<Vec<_>>()
                .join(" AND ");
            format!("({stem_chain}) OR (pre_title <> '' AND ({}))", chain(PS))
        };
        let sql = format!(
            "SELECT {REL_COLS} FROM releases WHERE {where_clause}
             ORDER BY first_seen DESC LIMIT ?{}",
            terms.len() + 1
        );
        let mut stmt = self.db.prepare(&sql)?;
        let mut params: Vec<&dyn rusqlite::ToSql> =
            terms.iter().map(|t| t as &dyn rusqlite::ToSql).collect();
        params.push(&limit);
        let rows = stmt.query_map(params.as_slice(), release_from_row)?;
        rows.collect()
    }

    /// Find the release an NZBLNK header names, best candidate first.
    ///
    /// An NZBLNK carries no article ids: `h` is a string distinctive
    /// enough to identify one posting in a raw-header index, which is
    /// exactly what we are. The header is usually the obfuscated release
    /// name itself, so it turns up as a release stem; on posts whose
    /// subject was scrambled per-file it turns up as a FILENAME instead.
    /// Both surfaces are tried, cheapest first:
    ///
    /// 1. `stem` equality, which `idx_rel_stem` answers outright;
    /// 2. the FTS index, verified afterwards by normalized containment
    ///    (FTS matches by token prefix, so an unverified hit would let
    ///    "abc" claim "abcdefgh");
    /// 3. `files.filename`, anchored at the start.
    ///
    /// Rung 3 is a table scan - no index covers `filename` alone - so it
    /// only ever runs when the two indexed rungs missed, and a header
    /// too short to identify anything (< 4 characters) is refused before
    /// it can pay for one.
    ///
    /// Callers get whole [`Release`] rows and decide for themselves;
    /// [`Self::make_nzb`] then emits a complete NZB from the segment
    /// ids the scan already stored.
    pub(super) fn find_by_header_once(
        &self,
        header: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<Release>> {
        let header = header.trim();
        if header.chars().count() < 4 {
            return Ok(Vec::new());
        }
        // Same normalization `search` uses: stems are stored dotted and
        // a header may be spelled with spaces (or the other way round).
        //
        // Unicode, not ASCII, since TODO 5 phase 2c - and here that was
        // a live bug rather than a missing feature. Rung 2 finds a
        // Cyrillic stem perfectly well (FTS5's unicode61 folds the whole
        // range), then handed it to a `contains` test whose own fold was
        // ASCII-only, so `война.и.мир` matched the index and was thrown
        // away by the verification. Measured before the fix: the lowercase
        // header resolved to nothing while the SHOUTED one resolved fine.
        let want = fold::query(header);
        let mut out: Vec<Release> = Vec::new();
        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut push = |rows: Vec<Release>, out: &mut Vec<Release>| {
            for r in rows {
                if seen.insert(r.id) {
                    out.push(r);
                }
            }
        };

        // Every rung below stops the ladder the moment ANYTHING answers.
        // The gates used to be `out.len() >= limit` with the caller passing
        // limit=8, and a distinctive header resolves to exactly one row, so
        // one was never eight and EVERY lookup ran every rung - on a hit as
        // well as a miss. Measured on a 16.5M-release / 17.7M-file index:
        // 1.7 s for a SUCCESSFUL resolution, 2.4 s warm and 4.3 s cold for
        // one that matches nothing, all of it holding the single shared
        // read connection that every other index reader queues behind.
        // A hit is now sub-millisecond on that same index (the indexed
        // equality alone); only a genuine miss pays for the scans.
        //
        // 1a. Exact stem, served from idx_rel_stem.
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE stem = ?1 LIMIT ?2"
        ))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![header, limit], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 1b. Case-insensitively, so a board that SHOUTS the header still
        //     finds the row. Its own statement rather than a UNION ALL arm:
        //     idx_rel_stem is BINARY so this cannot use it, and inside a
        //     UNION ALL under `LIMIT 8` SQLite must evaluate it to look for
        //     the other seven even when the exact arm already matched - so
        //     the full scan ran on every hit. Now it runs only when 1a
        //     found nothing, which is the case the comment always claimed.
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE stem = ?1 COLLATE NOCASE LIMIT ?2"
        ))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![header, limit], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 2. FTS (or the LIKE fallback on a database without it), then
        //    verify: only a stem that really contains the header counts.
        let m = if self.fts {
            fts_match(header)
        } else {
            String::new()
        };
        let cands: Vec<Release> = if !m.is_empty() {
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases
                  WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)
                  ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            stmt.query_map(rusqlite::params![m, FIND_SCAN_CAP], release_from_row)?
                .collect::<Result<_, _>>()?
        } else {
            let arm = stem_fold_arm("", "?1");
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases WHERE {arm}
                  ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            stmt.query_map(rusqlite::params![want, FIND_SCAN_CAP], release_from_row)?
                .collect::<Result<_, _>>()?
        };
        push(
            cands
                .into_iter()
                .filter(|r| fold::query(&r.stem).contains(&want))
                .collect(),
            &mut out,
        );
        // Same reasoning as rung 1: rung 3 is a full scan of `files`, which
        // is the bigger table, so it must run only when nothing at all has
        // answered - not merely when fewer than `limit` things have.
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 3. Filenames, anchored. The header's own LIKE metacharacters
        //    are escaped - an obfuscated name is allowed to contain `_`,
        //    and unescaped that is a single-character wildcard.
        let esc = header
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE id IN (
                 SELECT release_id FROM files
                  WHERE filename LIKE ?1 || '%' ESCAPE '\\' LIMIT ?2)
              ORDER BY first_seen DESC"
        ))?;
        // Instrument-first: this scan is the one an index would replace -
        // time it and record how it went. See `note_filename_fallback`.
        let t0 = std::time::Instant::now();
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![esc, FIND_SCAN_CAP], release_from_row)?
            .collect::<Result<_, _>>()?;
        note_filename_fallback(header, !rows.is_empty(), t0.elapsed());
        push(rows, &mut out);
        out.truncate(limit as usize);
        Ok(out)
    }

    /// Resolve a newznab `imdbid` to the parse-key its releases carry,
    /// so an id-based Radarr search can be answered from the enriched
    /// `titles` table instead of a title substring.
    ///
    /// Newznab carries the bare number (`imdbid=0468569`) while we store
    /// the canonical `tt`-prefixed form, and IMDb widened from 7 digits
    /// to 8 - so both the zero-padded and the as-given widths are tried.
    /// An empty list means "we hold nothing for that id", which the
    /// facade must answer with an empty feed rather than an unfiltered
    /// one.
    ///
    /// EVERY key, not one: a film keyed both `m:<norm>:<year>` and
    /// `m:<norm>` (the parser writes whichever the stem supports, by
    /// design) enriches to one IMDb id on two rows, and the old `LIMIT 1`
    /// then returned one arbitrary half of that film's releases while
    /// `total` agreed with it, so nothing looked wrong (Codex sweep 7,
    /// M4).
    ///
    /// `imdb <> ''` looks redundant next to two equality terms and is
    /// the only thing that makes this a lookup rather than a scan - the
    /// rule every resolver here now follows. `idx_titles_imdb` is
    /// PARTIAL, and SQLite reaches a partial index only when the
    /// statement's own WHERE clause implies its predicate, which an
    /// `imdb=?1` term does not, whatever is bound to it (nor does a
    /// literal `imdb='tt0468569'` - measured both ways). With the guard
    /// the OR folds to an IN over the index and both spellings are still
    /// tried; without it Radarr's primary lookup reads the whole titles
    /// table on every search, 32.6 ms against 0.10 ms at 300 k titles.
    ///
    /// And [`Self::title_keys`]'s `ORDER BY key` tail is what makes that
    /// miss invisible: the plan reads `SCAN titles USING INDEX
    /// sqlite_autoindex_titles_1`, which names an index while scanning
    /// every row of it. plan_tests.rs asserts the pairing per resolver.
    pub fn title_key_for_imdb(&self, imdb: &str) -> rusqlite::Result<Vec<String>> {
        let digits: String = imdb.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return Ok(Vec::new());
        }
        let padded = format!("tt{digits:0>7}");
        let bare = format!("tt{digits}");
        self.title_keys(
            "SELECT key FROM titles WHERE imdb <> '' AND (imdb=?1 OR imdb=?2)",
            rusqlite::params![padded, bare],
        )
    }

    /// The shared tail of the four external-id resolvers: every key the
    /// id names, oldest row first, capped.
    ///
    /// The cap is a bound on the `IN (...)` list `browse` builds from
    /// this, not a policy - a title with more than [`Self::ID_KEY_CAP`]
    /// spellings is a parser fault to fix, not a query to widen. `ORDER
    /// BY key` only so the answer is stable across calls; the caller
    /// filters with a set, so the order carries no meaning of its own.
    fn title_keys(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .db
            .prepare(&format!("{sql} ORDER BY key LIMIT {}", Self::ID_KEY_CAP))?;
        stmt.query_map(params, |r| r.get(0))?.collect()
    }

    /// How many title keys one external id may resolve to. See
    /// [`Self::title_keys`]. Crate-visible so plan_tests.rs can build
    /// the statement in the exact shape `title_keys` runs it - the
    /// `ORDER BY key LIMIT` tail is part of what the planner reads.
    pub(crate) const ID_KEY_CAP: u32 = 32;

    /// Resolve a newznab `tmdbid` to its parse-key - the
    /// [`Self::title_key_for_imdb`] counterpart for the id Radarr sends
    /// when it has no IMDb id for a title.
    ///
    /// MOVIE rows only, and that is the whole point. `titles.tmdb_id`
    /// carries a TMDB movie id on a movie row and a TVmaze SHOW id on a
    /// TV row - two unrelated numbering schemes sharing one column, both
    /// small dense integers, so collisions are not a corner case but the
    /// expected state of a populated index. Unfiltered, a Radarr
    /// `t=movie&tmdbid=N` could resolve a TV series that merely happens
    /// to be TVmaze #N and answer with its episodes.
    ///
    /// `kind` alone was not enough, because the movie half is not one
    /// namespace either: with no TMDB key the keyless chain runs OMDb,
    /// which has no TMDB id to give and writes the bare IMDb NUMBER into
    /// this column instead. So `id_src` names the namespace and this
    /// resolver takes only its own ('' being the legacy, unlabelled
    /// value - Codex sweep 7, H2).
    ///
    /// Returns EVERY movie key filed under the id, not one of them.
    /// Nothing constrains the column to be unique and two shapes make it
    /// genuinely repeat - a remade-title split, and the `m:<norm>:<year>`
    /// / `m:<norm>` pair the parser keys by design - so the old `LIMIT 1`
    /// silently answered with one arbitrary half of a film's releases
    /// (Codex sweep 7, M4). Empty means we hold nothing for that id,
    /// which the caller turns into an empty feed - never a fall-through
    /// to the other namespace.
    ///
    /// `tmdb_id > 0` / `tvdb > 0` earn the partial index the same way
    /// [`Self::title_key_for_imdb`] documents; the early return does not
    /// stand in for it, because the planner reads the statement.
    pub fn title_key_for_tmdb(&self, tmdb: i64) -> rusqlite::Result<Vec<String>> {
        if tmdb <= 0 {
            return Ok(Vec::new());
        }
        self.title_keys(
            "SELECT key FROM titles WHERE tmdb_id=?1 AND tmdb_id > 0 AND kind='movie'
               AND id_src = 'tmdb'",
            rusqlite::params![tmdb],
        )
    }

    /// Resolve a newznab `tvmazeid` to its parse-key - the TV-side
    /// counterpart of [`Self::title_key_for_tmdb`], and the inverse of
    /// [`Self::tv_show_id`].
    ///
    /// The `kind='tv'` filter is not tidiness, it is the same collision
    /// `title_key_for_tmdb` documents from the other side: `tmdb_id`
    /// carries a TMDB MOVIE id on a movie row and a TVmaze SHOW id on a
    /// TV row, two unrelated dense-integer schemes in one column. A
    /// tvsearch that resolved through a movie row would answer with a
    /// film that merely happens to be TMDB #N.
    ///
    /// And `kind='tv'` alone is still not enough, because the TV half is
    /// three namespaces rather than one: TVmaze under the keyless
    /// default, AniList whenever TVmaze missed the title (no key needed
    /// - anime posted under a romaji title is the routine case), and
    /// TMDB when a key is configured. `id_src` is what tells them apart,
    /// so a `tvmazeid=` takes only TVmaze-sourced rows (Codex sweep 7,
    /// H2). Unlabelled legacy rows (`id_src=''`) are NOT admitted: the
    /// AniList fallback was writing its media ids into `tmdb_id` for
    /// three weeks before the `id_src` column existed, so '' names no
    /// namespace at all - answering an id search from one, or handing
    /// one to the TVDB backfill lane, resolves a number in the wrong
    /// numbering and stamps or serves the wrong series permanently
    /// (bug sweep 20 Aug).
    ///
    /// Returns every matching key: one show posted under two spellings
    /// parses into two title keys that enrich to the SAME show id, which
    /// is precisely what the duplicate check's alias oracle relies on,
    /// so answering with one of them arbitrarily hid half a series from
    /// Sonarr (Codex sweep 7, M4). Empty = we hold no TV title for that
    /// id, which the facade turns into an empty feed - never a
    /// fall-through to the whole index (TODO 187).
    ///
    /// `tmdb_id > 0` / `tvdb > 0` earn the partial index the same way
    /// [`Self::title_key_for_imdb`] documents; the early return does not
    /// stand in for it, because the planner reads the statement.
    pub fn title_key_for_tvmaze(&self, id: i64) -> rusqlite::Result<Vec<String>> {
        if id <= 0 {
            return Ok(Vec::new());
        }
        self.title_keys(
            "SELECT key FROM titles WHERE tmdb_id=?1 AND tmdb_id > 0 AND kind='tv'
               AND id_src = 'tvmaze'",
            rusqlite::params![id],
        )
    }

    /// Resolve a newznab `tvdbid` to its parse-key.
    ///
    /// Its own column, unlike the two id lookups above: TheTVDB numbers
    /// nothing but series, so there is no namespace to collide with and
    /// the `kind='tv'` filter is belt only. The id arrives from TVmaze's
    /// `externals.thetvdb` at enrichment, or from the backfill lane for
    /// rows enriched before the column existed.
    ///
    /// `tmdb_id > 0` / `tvdb > 0` earn the partial index the same way
    /// [`Self::title_key_for_imdb`] documents; the early return does not
    /// stand in for it, because the planner reads the statement.
    pub fn title_key_for_tvdb(&self, tvdb: i64) -> rusqlite::Result<Vec<String>> {
        if tvdb <= 0 {
            return Ok(Vec::new());
        }
        self.title_keys(
            "SELECT key FROM titles WHERE tvdb=?1 AND tvdb > 0 AND kind='tv'",
            rusqlite::params![tvdb],
        )
    }

    /// The TheTVDB series id we hold for one title key - the reverse of
    /// [`Self::title_key_for_tvdb`].
    ///
    /// The pull-search's precision id when the user searches third-party
    /// indexers from a card. `kind='tv'` for the reason
    /// [`Self::tv_show_id`] documents in full: the id columns on a title
    /// row are per-kind, and answering with anything but a series id
    /// under a parameter named `tvdbid` asks confidently for the wrong
    /// thing.
    pub fn tvdb_id_for_title(&self, key: &str) -> rusqlite::Result<Option<i64>> {
        if key.is_empty() {
            return Ok(None);
        }
        self.db
            .query_row(
                "SELECT tvdb FROM titles WHERE key=?1 AND kind='tv' AND tvdb > 0",
                rusqlite::params![key],
                |r| r.get(0),
            )
            .optional()
    }

    /// Does this index hold ANY TVDB id at all?
    ///
    /// The newznab caps document is gated on this, and that gate is the
    /// whole ordering story of TODO 187: Sonarr switches to `tvdbid` the
    /// moment caps offers it, so advertising the parameter against an
    /// empty column would answer every series search with nothing and
    /// be read as "this indexer has nothing". One id present means the
    /// backfill lane has run and the promise is real. Cheap by
    /// construction - it is an EXISTS against the partial index, so it
    /// stops at the first row.
    pub fn has_tvdb_ids(&self) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM titles WHERE tvdb > 0)",
            [],
            |r| r.get::<_, i64>(0).map(|n| n != 0),
        )
    }

    /// The TVmaze show id the enricher recorded for a TV title key, or
    /// None when the key is unknown, not a TV row, or not yet enriched.
    ///
    /// This is the duplicate check's alias oracle: a show posted under
    /// two spellings ("Show" vs "Show The Full Subtitle") parses into
    /// two title keys, and the ONLY safe statement that they are one
    /// show is that a provider resolved both to the same id. Filtered
    /// to `kind='tv'` for the reason `title_key_for_tmdb` documents:
    /// this column holds a TMDB movie id on movie rows, an unrelated
    /// numbering scheme that would collide.
    ///
    /// The id therefore comes back WITH its namespace, and the caller
    /// compares the pair. That matters more here than anywhere else,
    /// because two rows are called one show on the strength of one equal
    /// number: an AniList media id that happens to equal another show's
    /// TVmaze id would otherwise make the duplicate check hold a
    /// download as an alias of something unrelated (Codex sweep 7, H2).
    /// Comparing the pair - rather than admitting only TVmaze rows -
    /// also keeps the oracle working for anime, which under the keyless
    /// default is AniList-sourced whenever TVmaze lacked the romaji
    /// title, and that is most of it.
    ///
    /// A legacy '' answers NOTHING. It used to read as 'tvmaze' - the
    /// column's pre-provenance meaning - but the AniList fallback was
    /// writing media ids into the column for three weeks before id_src
    /// existed, so '' names no namespace at all, and an oracle that
    /// guessed one could call an unrelated pair one show and hold a
    /// download as a duplicate of it (bug sweep 20 Aug). Legacy rows
    /// simply stop contributing aliases, which is the recoverable miss.
    pub fn tv_show_id(&self, key: &str) -> rusqlite::Result<Option<(String, i64)>> {
        if key.is_empty() {
            return Ok(None);
        }
        let row = self
            .db
            .query_row(
                "SELECT id_src, tmdb_id FROM titles
                 WHERE key=?1 AND kind='tv' AND tmdb_id > 0",
                rusqlite::params![key],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()?;
        Ok(row.filter(|(src, _)| !src.is_empty()))
    }

    /// The one year the index knows a movie title by - or None when it
    /// knows none, or more than one. The renamer asks this for a
    /// yearless post, and the ambiguity rule is the whole safety story:
    /// a remade title ("The Thing") has two keys with two years, and
    /// guessing between them names the file after the wrong film. Keys
    /// are `m:<norm>` (yearless parse, year filled by enrichment) and
    /// `m:<norm>:<year>`; `norm_title` output is alphanumeric+spaces,
    /// so the LIKE pattern needs no escaping.
    pub fn movie_year(&self, norm: &str) -> rusqlite::Result<Option<u32>> {
        if norm.is_empty() {
            return Ok(None);
        }
        let key = format!("m:{norm}");
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT year FROM titles
              WHERE (key = ?1 OR key LIKE ?1 || ':%')
                AND kind = 'movie' AND year > 0
              LIMIT 2",
        )?;
        let years: Vec<u32> = stmt
            .query_map([&key], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        Ok(match years.as_slice() {
            [y] => Some(*y),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};

    /// The filename-fallback census (`FN_FALLBACK_*`) is process-global
    /// and `cargo test` runs the lib tests as threads in ONE process, so
    /// the two tests that reach the unindexed rung would otherwise
    /// interleave: a sibling's miss landing between the census test's
    /// snapshots filed a hit as a miss, roughly once in three runs.
    /// Every test that calls `find_by_header` takes this first. (Under
    /// nextest each test gets its own process and it costs nothing.)
    static CENSUS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the census lock, ignoring poisoning - a panic in one of
    /// these tests must fail that test, not cascade into the other.
    fn census_lock() -> std::sync::MutexGuard<'static, ()> {
        CENSUS.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `titles.tmdb_id` holds a TMDB movie id on a movie row and a
    /// TVmaze SHOW id on a TV row. Both namespaces are small dense
    /// integers, so a collision is the expected state of a populated
    /// index rather than a corner case - and unfiltered, a Radarr
    /// `t=movie&tmdbid=N` resolved whichever row `LIMIT 1` happened to
    /// reach and could answer a movie search with a TV series.
    #[test]
    fn a_tmdb_lookup_never_crosses_into_the_tv_namespace() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-tmdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        // Labelled rows, as every provider writes them since the id_src
        // column landed: this test is about the KIND filter, and the
        // provenance filter (its own test below) must not mask it.
        let put = |key: &str, kind: &str, id: i64| {
            let src = if kind == "movie" { "tmdb" } else { "tvmaze" };
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year, tmdb_id, id_src)
                     VALUES(?1, ?2, ?3, 0, ?4, ?5)",
                    rusqlite::params![key, kind, "x", id, src],
                )
                .unwrap();
        };
        // The collision: TMDB movie 1399 and TVmaze show 1399 are
        // completely unrelated titles sharing one column.
        put("t:a series", "tv", 1399);
        put("m:a film", "movie", 1399);
        assert_eq!(
            ix.title_key_for_tmdb(1399).unwrap(),
            ["m:a film"],
            "the movie row is the only one a tmdbid may resolve to"
        );

        // An id we hold only a TV row for is NOT a movie we have. The
        // caller turns the empty list into an empty feed; falling
        // through to the TV row would answer a movie search with
        // episodes.
        put("t:another series", "tv", 82856);
        assert!(ix.title_key_for_tmdb(82856).unwrap().is_empty());

        // A movie-only id still resolves, which is the ordinary case.
        put("m:another film", "movie", 603);
        assert_eq!(ix.title_key_for_tmdb(603).unwrap(), ["m:another film"]);

        // The same collision from the TV side (TODO 187): a newznab
        // `tvmazeid` reads the very same column, so it has to refuse the
        // movie row for id 1399 exactly as the movie lookup refuses the
        // series. An id we hold no TV title for is None - which the
        // facade renders as an empty feed, never as the whole index.
        assert_eq!(
            ix.title_key_for_tvmaze(1399).unwrap(),
            ["t:a series"],
            "the tv row is the only one a tvmazeid may resolve to"
        );
        assert!(ix.title_key_for_tvmaze(603).unwrap().is_empty());
        assert!(ix.title_key_for_tvmaze(4242).unwrap().is_empty());
        // A missing param arrives here as 0 (unparsable id, blank
        // value), and must not become "the first TV row we hold".
        put("t:unresolved", "tv", 0);
        assert!(ix.title_key_for_tvmaze(0).unwrap().is_empty());
        assert!(ix.title_key_for_tvmaze(-1).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex sweep 7, H2: `titles.tmdb_id` is FOUR namespaces in one
    /// column, and `kind` names only two of them. On a TV row it holds a
    /// TVmaze show id under the keyless default, an AniList media id
    /// whenever TVmaze missed the title (anime under a romaji title
    /// needs no key to reach this), and a TMDB series id when a key is
    /// configured; on a movie row it holds the bare IMDb NUMBER when the
    /// keyless chain ran OMDb. So each resolver takes its own namespace
    /// and the legacy unlabelled rows, and nothing else.
    #[test]
    fn an_external_id_resolves_only_within_its_own_namespace() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-idsrc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, id: i64, src: &str| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year, tmdb_id, id_src)
                     VALUES(?1, ?2, ?3, 0, ?4, ?5)",
                    rusqlite::params![key, kind, "x", id, src],
                )
                .unwrap();
        };
        // The anime case, which needs no API key and is routine: TVmaze
        // had no romaji title, AniList did, and its MEDIA id landed in
        // the same column a `tvmazeid=` reads.
        put("t:an anime", "tv", 4242, "anilist");
        assert!(
            ix.title_key_for_tvmaze(4242).unwrap().is_empty(),
            "an AniList media id answered a tvmazeid lookup"
        );
        // ...and a TMDB series id, which a configured key writes to the
        // very same place.
        put("t:a series", "tv", 1399, "tmdb");
        assert!(ix.title_key_for_tvmaze(1399).unwrap().is_empty());
        // What a tvmazeid IS for. An unlabelled legacy row does NOT
        // resolve: '' was assumed to mean "written before the column
        // existed, so TVmaze" - but the AniList fallback was writing
        // media ids into this column for three weeks before the column
        // landed, so '' proves nothing about the namespace and answering
        // from it serves the wrong series (bug sweep 20 Aug).
        put("t:a tvmaze show", "tv", 82856, "tvmaze");
        put("t:a legacy show", "tv", 33333, "");
        assert_eq!(ix.title_key_for_tvmaze(82856).unwrap(), ["t:a tvmaze show"]);
        assert!(
            ix.title_key_for_tvmaze(33333).unwrap().is_empty(),
            "an unlabelled id must not answer a tvmazeid lookup"
        );

        // The movie side of the same fault: with no TMDB key the chain
        // runs OMDb, which has no TMDB id and writes the numeric half of
        // the tconst instead - straight into the column Radarr's
        // `tmdbid=` resolves against.
        put("m:an omdb film", "movie", 111_161, "omdb");
        assert!(
            ix.title_key_for_tmdb(111_161).unwrap().is_empty(),
            "an IMDb number answered a tmdbid lookup"
        );
        put("m:a tmdb film", "movie", 603, "tmdb");
        assert_eq!(ix.title_key_for_tmdb(603).unwrap(), ["m:a tmdb film"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex sweep 7, M4: nothing makes an external id unique across
    /// title keys, and two production shapes routinely repeat one - a
    /// film keyed with and without its year, and a show posted under two
    /// spellings. `LIMIT 1` answered with one arbitrary half of the
    /// title.
    #[test]
    fn an_external_id_resolves_every_key_filed_under_it() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-idset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, id: i64, imdb: &str| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year, tmdb_id, imdb, id_src)
                     VALUES(?1, ?2, ?3, 0, ?4, ?5, 'tmdb')",
                    rusqlite::params![key, kind, "x", id, imdb],
                )
                .unwrap();
        };
        // `release.rs` keys a movie `m:<norm>:<year>` when the stem
        // carries a year and `m:<norm>` when it does not, by design, so
        // one film with mixed stems really does hold two keys.
        put("m:a film:2010", "movie", 27205, "tt1375666");
        put("m:a film", "movie", 27205, "tt1375666");
        assert_eq!(
            ix.title_key_for_tmdb(27205).unwrap(),
            ["m:a film", "m:a film:2010"],
            "half the film's releases were unreachable by tmdbid"
        );
        assert_eq!(
            ix.title_key_for_imdb("1375666").unwrap(),
            ["m:a film", "m:a film:2010"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `tv_show_id` is the duplicate check's alias oracle, so what it
    /// refuses matters as much as what it answers: no row, an
    /// unenriched row (tmdb_id=0), and a movie row that happens to hold
    /// the same number all read as "unknown".
    #[test]
    fn a_tv_show_id_answers_only_enriched_tv_rows() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-tvid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, id: i64| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year, tmdb_id)
                     VALUES(?1, ?2, ?3, 0, ?4)",
                    rusqlite::params![key, kind, "x", id],
                )
                .unwrap();
        };
        put("t:a series", "tv", 1399);
        put("t:unresolved", "tv", 0);
        put("m:a film", "movie", 77);
        // A legacy row - no provenance recorded - answers NOTHING: ''
        // was assumed to mean TVmaze, but AniList wrote media ids into
        // this column before id_src existed, so a guessed namespace
        // could alias two unrelated shows (bug sweep 20 Aug).
        assert_eq!(ix.tv_show_id("t:a series").unwrap(), None);
        ix.db
            .execute(
                "UPDATE titles SET id_src='tvmaze' WHERE key='t:a series'",
                [],
            )
            .unwrap();
        assert_eq!(
            ix.tv_show_id("t:a series").unwrap(),
            Some(("tvmaze".into(), 1399))
        );
        assert_eq!(ix.tv_show_id("t:unresolved").unwrap(), None);
        assert_eq!(ix.tv_show_id("t:absent").unwrap(), None);
        assert_eq!(ix.tv_show_id("m:a film").unwrap(), None);
        assert_eq!(ix.tv_show_id("").unwrap(), None);
        // Codex sweep 7, H2: the alias oracle calls two rows one show on
        // the strength of one equal number, so the number alone is not
        // enough - an AniList media id equal to another show's TVmaze id
        // would hold an unrelated download as a duplicate.
        ix.db
            .execute(
                "INSERT INTO titles(key, kind, title, year, tmdb_id, id_src)
                 VALUES('t:an anime', 'tv', 'x', 0, 1399, 'anilist')",
                [],
            )
            .unwrap();
        assert_eq!(
            ix.tv_show_id("t:an anime").unwrap(),
            Some(("anilist".into(), 1399))
        );
        assert_ne!(
            ix.tv_show_id("t:an anime").unwrap(),
            ix.tv_show_id("t:a series").unwrap(),
            "two namespaces' ids collided into one show"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_movie_year_answers_only_when_unambiguous() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-my-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, year: u32| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)",
                    rusqlite::params![key, kind, "x", year],
                )
                .unwrap();
        };
        // One title, one year - via the yearless enriched key.
        put("m:example film", "movie", 2019);
        assert_eq!(ix.movie_year("example film").unwrap(), Some(2019));
        // The yeared key spelling answers too.
        put("m:other film:2007", "movie", 2007);
        assert_eq!(ix.movie_year("other film").unwrap(), Some(2007));
        // A remake means two distinct years: refuse to guess.
        put("m:the remake:1982", "movie", 1982);
        put("m:the remake:2011", "movie", 2011);
        assert_eq!(ix.movie_year("the remake").unwrap(), None);
        // Duplicate keys carrying the SAME year stay unambiguous.
        put("m:same year", "movie", 1999);
        put("m:same year:1999", "movie", 1999);
        assert_eq!(ix.movie_year("same year").unwrap(), Some(1999));
        // Unenriched (year 0) and non-movie rows say nothing.
        put("m:unchecked", "movie", 0);
        assert_eq!(ix.movie_year("unchecked").unwrap(), None);
        put("t:show title", "tv", 2020);
        assert_eq!(ix.movie_year("show title").unwrap(), None);
        // A title that PREFIXES another must not inherit its year:
        // "alien" and "aliens" share no key, and the ':'-anchored LIKE
        // keeps "m:alien" from matching "m:aliens" rows... which it
        // cannot anyway, but the guard worth pinning is the space case.
        put("m:alien nation:1988", "movie", 1988);
        assert_eq!(ix.movie_year("alien").unwrap(), None);
        assert_eq!(ix.movie_year("").unwrap(), None);
    }

    /// TODO 5 phase 2c: SQLite's `LOWER()` folds `A-Z` and nothing else,
    /// so a lowercase Cyrillic or Greek query could never reach an
    /// uppercase stem down any path that was not FTS. `releases.stem_fold`
    /// carries the Unicode fold for exactly those rows; this pins all
    /// three surfaces that read it, in both scripts.
    ///
    /// The FTS legs are here too even though they always worked
    /// (`unicode61` folds the full range): they are what says the fold
    /// column is an ADDITION rather than a replacement, and they are the
    /// arm most of these queries actually take in production.
    #[test]
    fn a_lowercase_cyrillic_or_greek_query_finds_an_uppercase_stem() {
        let _census = census_lock();
        let dir = std::env::temp_dir().join(format!("nzbfast-fold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(ix.fts, "bundled sqlite is expected to ship FTS5");
        let mk = |f: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, 4 << 30);
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("ВОЙНА.И.МИР.S01E01.1080p.WEB.x264-GRP.mkv", "ru1"),
                mk("ΟΔΥΣΣΕΙΑ.2019.1080p.BluRay.x264-GRP.mkv", "el1"),
                mk("Ordinary.Ascii.Release.2019.1080p-GRP.mkv", "as1"),
            ],
            1_000,
        )
        .unwrap();

        // The write side: the two non-ASCII stems earned a stored fold,
        // the ASCII one did not (the column is sparse - see fold.rs).
        let folds: Vec<(String, String)> = ix
            .db
            .prepare("SELECT stem, stem_fold FROM releases ORDER BY stem")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let fold_of = |needle: &str| {
            folds
                .iter()
                .find(|(s, _)| s.starts_with(needle))
                .unwrap_or_else(|| panic!("no stem starting {needle}: {folds:?}"))
                .1
                .clone()
        };
        assert_eq!(fold_of("Ordinary"), "", "an ASCII stem stored a fold");
        assert!(fold_of("ВОЙНА").starts_with("война и мир"), "{folds:?}");
        assert!(fold_of("ΟΔΥΣΣΕΙΑ").starts_with("οδυσσεια"), "{folds:?}");

        // All three read surfaces, on the FTS path they take in
        // production, and then again with FTS switched off so the LIKE
        // fallback - the path the fold column exists for - is the one
        // under test. Both must agree.
        for path in ["fts", "like"] {
            ix.fts = path == "fts";
            ix.pre_fts = ix.fts;
            let n = |q: &str| ix.search(q, 10).unwrap().len();
            assert_eq!(n("война и мир"), 1, "{path}: search ru");
            assert_eq!(n("ВОЙНА"), 1, "{path}: search ru shouted");
            assert_eq!(n("οδυσσεια"), 1, "{path}: search el");
            assert_eq!(n("ΟΔΥΣΣΕΙΑ"), 1, "{path}: search el shouted");
            assert_eq!(
                n("ordinary ascii"),
                1,
                "{path}: the ASCII arm still answers"
            );
            assert_eq!(n("война и рим"), 0, "{path}: a term that is absent");

            let browse = |q: &str| {
                ix.browse(&BrowseQuery {
                    q: q.into(),
                    ..Default::default()
                })
                .unwrap()
                .1
            };
            assert_eq!(browse("война"), 1, "{path}: browse ru");
            assert_eq!(browse("οδυσσεια"), 1, "{path}: browse el");
            assert_eq!(browse("нетакого"), 0, "{path}: browse miss");

            let cards = |q: &str| {
                ix.browse_cards(
                    &BrowseQuery {
                        q: q.into(),
                        ..Default::default()
                    },
                    CardSort::Latest,
                    false,
                    false,
                    None,
                )
                .unwrap()
                .1
            };
            assert_eq!(cards("война"), 1, "{path}: cards ru");
            assert_eq!(cards("οδυσσεια"), 1, "{path}: cards el");
        }
        ix.fts = true;
        ix.pre_fts = true;

        // The NZBLNK ladder, which was a LIVE bug rather than a missing
        // feature: rung 2 found the Cyrillic row through FTS and then
        // threw it away, because the Rust-side `contains` check that
        // verifies an FTS candidate was still ASCII-folded. The SHOUTED
        // spelling resolved (rung 1 is byte equality); the lowercase one
        // did not.
        assert_eq!(
            ix.find_by_header("война.и.мир.s01e01.1080p.web.x264-grp", 10)
                .unwrap()
                .len(),
            1,
            "lowercase Cyrillic header"
        );
        assert_eq!(
            ix.find_by_header("ΟΔΥΣΣΕΙΑ.2019.1080p.BluRay.x264-GRP", 10)
                .unwrap()
                .len(),
            1,
            "exact Greek header"
        );
        assert_eq!(
            ix.find_by_header("οδυσσεια.2019.1080p.bluray.x264-grp", 10)
                .unwrap()
                .len(),
            1,
            "lowercase Greek header"
        );
        teardown(&dir, ix);
    }

    #[test]
    fn fts_search_cards_and_junk() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-m28-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(ix.fts, "bundled sqlite is expected to ship FTS5");

        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                // Same movie from two posters → one card, two releases.
                mk("Inception.2010.1080p.BluRay.x264-GRP.mkv", "a@a", "i1"),
                mk("Inception.2010.2160p.WEB.x265-OTHER.mkv", "b@b", "i2"),
                mk("Breaking.Bad.S01E01.720p.WEB.x264-GRP.mkv", "c@c", "b1"),
                // Obfuscated hash stem → junk >= 50, hidden by default.
                mk("0a1b2c3d4e5f60718293a4b5.mkv", "d@d", "j1"),
            ],
            1_000,
        )
        .unwrap();

        // FTS prefix search, separator-insensitive both ways.
        assert_eq!(ix.search("inception", 10).unwrap().len(), 2);
        assert_eq!(ix.search("breaking bad s01", 10).unwrap().len(), 1);
        assert_eq!(ix.search("nosuchthing", 10).unwrap().len(), 0);

        // Browse with the junk ceiling: the hash stem drops out.
        let q = BrowseQuery {
            max_junk: Some(50),
            ..Default::default()
        };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 3, "junk hidden: {rows:?}");
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 4);

        // Cards: inception's two posters group under one key.
        let (cards, ctotal) = ix
            .browse_cards(
                &BrowseQuery {
                    max_junk: Some(50),
                    ..Default::default()
                },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap();
        assert_eq!(ctotal, 2, "cards: {cards:?}");
        let inception = cards
            .iter()
            .find(|c| c.title_key.starts_with("m:inception"))
            .unwrap();
        assert_eq!(inception.n_releases, 2);
        assert_eq!(inception.best_res, "2160p");
        assert_eq!(inception.kind, "movie");
        // Card-scoped browse (detail sheet) sees both copies.
        let (rows, n) = ix
            .browse(&BrowseQuery {
                title_keys: vec![inception.title_key.clone()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!((rows.len(), n), (2, 2));

        // FTS query text is filtered per-term.
        let (_, n) = ix
            .browse(&BrowseQuery {
                q: "inception \"2010".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(n, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The NZBLNK ladder's first rung: a header the board handed out,
    /// resolved against our own scan data and turned back into an NZB.
    #[test]
    fn find_by_header_resolves_a_link_from_our_own_scan() {
        let _census = census_lock();
        let dir = std::env::temp_dir().join(format!("nzbfast-hdr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // The common shape: the whole posting is named after the header,
        // so the header IS the release stem.
        ix.ingest(
            "alt.binaries.boneless",
            &[
                entry("\"7f3ac91e88.part01.rar\" yEnc (1/2)", "p@x", "s1", 1000),
                entry("\"7f3ac91e88.part01.rar\" yEnc (2/2)", "p@x", "s2", 1000),
                entry("\"7f3ac91e88.part02.rar\" yEnc (1/1)", "p@x", "s3", 800),
                entry("\"7f3ac91e88.par2\" yEnc (1/1)", "p@x", "s4", 200),
            ],
            1000,
        )
        .unwrap();
        // A decoy that shares the header's leading characters: an
        // unverified FTS prefix hit would hand the user this instead.
        ix.ingest(
            "alt.binaries.boneless",
            &[entry(
                "\"7f3ac91e88ff00.mkv\" yEnc (1/1)",
                "q@x",
                "d1",
                4000,
            )],
            1000,
        )
        .unwrap();

        let hits = ix.find_by_header("7f3ac91e88", 10).unwrap();
        assert_eq!(hits[0].stem, "7f3ac91e88", "exact stem must win: {hits:?}");
        assert!(hits[0].complete && hits[0].has_par2);

        // And it emits a whole NZB from the segments the scan stored.
        let nzb = ix.make_nzb(hits[0].id).unwrap();
        let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
        assert_eq!(parsed.files.len(), 3);
        assert_eq!(
            parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            4
        );

        // Case and separator spelling do not matter.
        assert_eq!(
            ix.find_by_header("7F3AC91E88", 10).unwrap()[0].stem,
            "7f3ac91e88"
        );

        // The other shape: per-file obfuscation, where the header names
        // a FILE inside a release whose stem is something else.
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, files, complete, first_posted,
                                      first_seen)
                 VALUES('Die.Hard.Umlaut.German','p2@x','alt.binaries.misc',1,1,50,50)",
                [],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                 VALUES(?1, 'ab_cd%ef-9911.part1.rar', 1, 500, '[[1,\"f1\",500]]', 1)",
                [rid],
            )
            .unwrap();
        // LIKE metacharacters in the header are escaped, not honoured.
        let hits = ix.find_by_header("ab_cd%ef-9911", 10).unwrap();
        assert_eq!(hits.len(), 1, "filename rung missed: {hits:?}");
        assert_eq!(hits[0].stem, "Die.Hard.Umlaut.German");
        assert!(
            ix.find_by_header("ab-cd-ef-9911", 10).unwrap().is_empty(),
            "the wildcards were live"
        );

        // Nothing to resolve, and nothing distinctive enough to try.
        assert!(
            ix.find_by_header("nosuchheaderatall", 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            ix.find_by_header("7f3", 10).unwrap().is_empty(),
            "too short to identify"
        );
        teardown(&dir, ix);
    }

    /// The instrument-first census records the rung it brackets: a
    /// filename-only header pays for the scan and is counted a HIT, a
    /// header nothing holds is counted a MISS with its wall time, and a
    /// header the indexed rungs answer never reaches the scan at all -
    /// which is the whole distinction the counter exists to measure.
    ///
    /// The tally is process-global and the unit suite runs its tests as
    /// threads, so this holds [`CENSUS`] for the duration - within that
    /// lock the deltas below are this test's own, and nothing else in
    /// the crate reaches the rung.
    #[test]
    fn the_filename_fallback_census_records_only_the_unindexed_rung() {
        let _census = census_lock();
        let dir = std::env::temp_dir().join(format!("nzbfast-fnfb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.boneless",
            &[entry(
                "\"5c1d0a77b2.part01.rar\" yEnc (1/1)",
                "p@x",
                "s1",
                900,
            )],
            1000,
        )
        .unwrap();
        // Per-file obfuscation: the header names a FILE, so only the
        // unindexed rung can answer it.
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, files, complete, first_posted,
                                      first_seen)
                 VALUES('Some.Release.Name','p2@x','alt.binaries.misc',1,1,50,50)",
                [],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                 VALUES(?1, 'zz19f4c0d8.part1.rar', 1, 500, '[[1,\"f1\",500]]', 1)",
                [rid],
            )
            .unwrap();

        // An indexed hit: the ladder stops at rung 1, so the census must
        // not move at all.
        let before = filename_fallback_stats();
        assert_eq!(ix.find_by_header("5c1d0a77b2", 10).unwrap().len(), 1);
        let after_indexed = filename_fallback_stats();
        assert_eq!(
            after_indexed.calls, before.calls,
            "an indexed hit reached the unindexed scan"
        );

        // A filename-only hit: the scan runs and earns its keep.
        assert_eq!(ix.find_by_header("zz19f4c0d8", 10).unwrap().len(), 1);
        let after_hit = filename_fallback_stats();
        assert!(
            after_hit.calls > after_indexed.calls && after_hit.hits > after_indexed.hits,
            "filename hit not counted ({after_indexed:?} -> {after_hit:?})"
        );
        assert_eq!(
            after_hit.misses, after_indexed.misses,
            "a hit was filed as a miss"
        );

        // A genuine miss: the case a dedicated filename index would kill.
        assert!(
            ix.find_by_header("nothingholdsthis", 10)
                .unwrap()
                .is_empty()
        );
        let after_miss = filename_fallback_stats();
        assert!(
            after_miss.misses > after_hit.misses,
            "miss not counted ({after_hit:?} -> {after_miss:?})"
        );
        // `misses` is derived as `calls - hits`, so splitting it back
        // out asserts nothing. The wall-time counters are NOT derived,
        // and each path must charge its own: a hit must leave the miss
        // clock alone, and a miss the hit clock.
        assert_eq!(
            after_hit.miss_nanos, after_indexed.miss_nanos,
            "a hit charged its wall time to the miss path"
        );
        assert_eq!(
            after_miss.hit_nanos, after_hit.hit_nanos,
            "a miss charged its wall time to the hit path"
        );
        teardown(&dir, ix);
    }
}
