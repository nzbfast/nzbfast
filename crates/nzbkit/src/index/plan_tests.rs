//! The query-plan gate: statements that run on a user-facing path must
//! never full-scan `releases` - or, for the *arr id lookups at the
//! bottom of this file, `titles`.
//!
//! `releases` is the table that grows without bound - 38 million rows in
//! a 55.9 GB database on a long-running install by 16 Aug 2026 - and
//! several of the statements that touch it are taken under `with_index`,
//! which holds the index write mutex for the whole closure. A scan there is
//! not slow, it is a wedge: on 16 Aug one `SCAN releases` inside the
//! oracle sampler's pick held that mutex for over forty minutes, which
//! stalled the index pass, which meant the download runner waited out
//! its whole `index_pass_gate` bound before starting a watch-folder
//! add, and left a finished job reading "Extracting" at 100% with the
//! rest of the queue stuck behind it.
//!
//! Every one of those has been an INVISIBLE regression: the statement is
//! correct, the tests pass, and the plan only turns pathological once
//! the table is big enough - which is to say on a real install, months
//! later, never in CI. So the plan itself is the assertion. Add the
//! statement here when you write it, in the exact shape the code runs
//! it; if SQLite cannot answer it from an index, this test says so now
//! rather than a user's daemon saying so in August.
//!
//! To fix a failure: give the statement a predicate the existing partial
//! indexes can use (that is what `pre_title=''` does for
//! `idx_rel_stem_lower`), or seek instead of sort (`oracle_pick`), or -
//! last - add an index, remembering that CREATE INDEX on this table
//! scans all 55 GB of it once, at startup, holding the write mutex.

use super::*;

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-index-plan-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The plan SQLite chooses for `sql`, as one line per step.
///
/// Parameters are bound to NULL. The planner's choice of index comes
/// from the statement's SHAPE, not from the values, so a null binding
/// asks the same question the daemon's does - and it lets the SQL below
/// stay a verbatim copy of the call site instead of a re-typed
/// paraphrase that could drift from it.
fn plan(ix: &Index, sql: &str) -> String {
    let mut stmt = ix
        .db
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap_or_else(|e| panic!("prepare {sql}: {e}"));
    let nulls = vec![rusqlite::types::Null; stmt.parameter_count()];
    let rows: Vec<String> = stmt
        .query_map(rusqlite::params_from_iter(nulls), |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    rows.join(" | ")
}

/// Statements whose plan must not contain a full scan of `releases`,
/// named by the function that runs them. The SQL is copied from the
/// call site verbatim, with bound parameters left as `?`.
const INDEXED: &[(&str, &str)] = &[
    (
        "oracle_pick forward seek",
        "SELECT id, grp, first_posted, COALESCE(oracle_at, 0) FROM releases
          WHERE first_posted >= ?1 AND junk < 50 ORDER BY first_posted LIMIT ?2",
    ),
    (
        "oracle_pick backward seek",
        "SELECT id, grp, first_posted, COALESCE(oracle_at, 0) FROM releases
          WHERE first_posted <= ?1 AND junk < 50 ORDER BY first_posted DESC LIMIT ?2",
    ),
    (
        "oracle_pick window low",
        "SELECT COALESCE(MIN(first_posted), 0) FROM releases",
    ),
    (
        "oracle_pick window high",
        "SELECT COALESCE(MAX(first_posted), 0) FROM releases",
    ),
    (
        "release_ids_by_stem exact",
        "SELECT id FROM releases WHERE stem=?1 LIMIT 3",
    ),
    (
        "release_ids_by_stem case-folded, unnamed",
        "SELECT id FROM releases WHERE pre_title='' AND LOWER(stem)=?1 LIMIT 3",
    ),
    (
        "predb_sweep exact match",
        "SELECT id FROM releases WHERE pre_title='' AND LOWER(stem)=?1 LIMIT 200",
    ),
    // The two retention reapers' selections. Both run under `with_index`,
    // on the hourly pass, against the biggest the table ever gets - and
    // both have been the wedge already (15 Aug, 16 Aug). The stale-partial
    // one rides its rowid stride and nothing else, which is what makes the
    // cursor mean anything: if the planner ever prefers `idx_rel_posted`
    // or `idx_rel_seen` here, the stride stops bounding the walk and the
    // cursor stops bounding the work, silently.
    (
        "prune_age selection",
        "SELECT id FROM releases
          WHERE first_posted > 0 AND first_posted < ?1
            AND title_key NOT IN (SELECT key FROM wall_hidden)
          LIMIT 8000",
    ),
    (
        "prune_stale_partials selection",
        "SELECT id FROM releases
          WHERE id > ?1 AND id <= ?2
            AND junk >= 50 AND first_posted > 0 AND first_posted < ?3
            AND first_seen > 0 AND first_seen < ?3
            AND title_key NOT IN (SELECT key FROM wall_hidden)
            AND EXISTS (SELECT 1 FROM files f
                        WHERE f.release_id = releases.id
                          AND (CASE WHEN f.nsegs > 0 THEN f.nsegs
                                               ELSE seg_count(f.segments) END) < f.total_parts)",
    ),
    // The header-encryption stats, all four. `idx_rel_enc` is partial on
    // `enc_class>0` and three of these did not repeat it, so each was a
    // full pass over the table to reach 184 rows. The fourth always had
    // the term - which is the pattern worth noticing: this class ships as
    // three-of-four, never as all-of-four, because the one that is written
    // as a range works and nobody re-reads the ones that are not.
    (
        "encrypted_stats by_kind",
        "SELECT enc_kind, COUNT(*), COALESCE(SUM(total_bytes),0)
           FROM releases WHERE enc_class=?1 AND enc_class>0 GROUP BY enc_kind",
    ),
    (
        "encrypted_stats count",
        "SELECT COUNT(*) FROM releases WHERE enc_class=?1 AND enc_class>0",
    ),
    (
        "encrypted_stats bytes",
        "SELECT COALESCE(SUM(total_bytes),0) FROM releases
           WHERE enc_class=?1 AND enc_class>0",
    ),
    (
        "encrypted_stats stale",
        "SELECT COUNT(*) FROM releases WHERE enc_class>0 AND enc_class<>?1",
    ),
];

/// A `SCAN releases` in any of these is the wedge described at the top
/// of this file. A scan of a small partial index (`idx_rel_pre_named`,
/// 13 k rows against the table's 38 M) is bounded and allowed - only
/// the TABLE and its whole-table indexes are the hazard.
#[test]
fn no_hot_path_statement_full_scans_the_releases_table() {
    let d = dir("noscan");
    let ix = Index::open(&d.join("index.db")).unwrap();
    let mut bad: Vec<String> = Vec::new();
    for (what, sql) in INDEXED {
        let p = plan(&ix, sql);
        // "SCAN releases" (the table) and "SCAN releases USING ... INDEX
        // idx_rel_stem" (an index over every row) are both full passes.
        // The partial indexes are named explicitly where a scan of one
        // is the intended, bounded answer.
        let full = p.contains("SCAN releases")
            && !p.contains("idx_rel_pre_named")
            && !p.contains("idx_rel_stem_lower");
        if full {
            bad.push(format!("{what}: {p}"));
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        bad.is_empty(),
        "these statements full-scan `releases` - see the note at the top of \
         plan_tests.rs for why that is a wedge and not a slowdown:\n  {}",
        bad.join("\n  ")
    );
}

/// The three enricher lane queues must each reach their partial index
/// on `titles`, and the drained-queue probe must not sort at all.
///
/// These are the statements the three lane threads run every 15 s, for
/// the life of the daemon, inside `with_index` - the write connection
/// and the write mutex the note at the top of this file is about. Until
/// N1 nothing indexed `checked`, `air_tried` or `tvdb_tried`, so each
/// tick was a full pass over `titles` PLUS a correlated
/// `MAX(first_posted)` per candidate row PLUS a temp B-tree, to return
/// six to twelve rows - or, on a settled install, none at all. That is
/// the `oracle_pick` shape one table over, and it ran forever rather
/// than once an hour.
///
/// Two different bars, deliberately:
///
/// * The PICK keeps its temp B-tree. Its sort key is a correlated
///   subquery (M28's "newest upload first", which is what stops a fresh
///   post queueing behind the whole historical backlog) and no index
///   can carry that. What the partial index changes is the candidate
///   SET the sort runs over. So the bar here is the index BY NAME, for
///   the reason the *arr test below spells out: a miss names an index
///   too (`sqlite_autoindex_titles_1`), so "no SCAN" is not the bar.
///
/// * The PRE-CHECK must have no temp sort AND no scan of the table.
///   That statement is the one that answers on a drained queue, which
///   on any settled install is every tick from now until the daemon
///   stops. If it ever grows a sort, the fast path has quietly become
///   the slow path again.
///
/// Both are built from the same where-builders the daemon uses, so the
/// shape planned here cannot drift from the shape it runs.
#[test]
fn every_enricher_lane_queue_reaches_its_partial_index() {
    let d = dir("enrichlanes");
    let ix = Index::open(&d.join("index.db")).unwrap();
    let lanes = [Lane::Movies, Lane::Shows, Lane::MusicBooks];
    // (what, the pick, the pre-check, the index both must use)
    let mut cases: Vec<(String, String, String, &str)> = Vec::new();
    for lane in lanes {
        cases.push((
            format!("titles_pending_lane {lane:?}"),
            titles::pending_lane_sql(lane),
            titles::titles_any_sql(&titles::pending_lane_where(lane)),
            "idx_titles_unchecked",
        ));
        cases.push((
            format!("titles_missing_date {lane:?}"),
            titles::missing_date_sql(lane),
            titles::titles_any_sql(&titles::missing_date_where(lane)),
            "idx_titles_air_backfill",
        ));
    }
    cases.push((
        "titles_missing_tvdb".to_string(),
        titles::missing_tvdb_sql(),
        titles::titles_any_sql(&titles::tvdb_queue_where()),
        "idx_titles_tvdb_backfill",
    ));
    let mut bad: Vec<String> = Vec::new();
    for (what, pick, probe, index) in &cases {
        for (leg, sql) in [("pick", pick), ("probe", probe)] {
            let p = plan(&ix, sql);
            // A bare `SCAN t` is the table itself - what all six of
            // these did before the indexes existed. `SCAN t USING INDEX
            // idx_titles_*` is a walk of the PARTIAL, bounded by the
            // queue, and is the intended answer for the lanes whose
            // `kind` term is a NOT IN that no seek can serve.
            if table_scan(&p) || !p.contains(index) {
                bad.push(format!("{what} {leg}: wanted {index}, got {p}"));
            }
        }
        let q = plan(&ix, probe);
        if q.contains("TEMP B-TREE") {
            bad.push(format!(
                "{what} probe sorts - the drained-queue fast path is gone: {q}"
            ));
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        bad.is_empty(),
        "the enricher's idle lanes no longer answer from an index on `titles` - \
         a partial index needs its predicate repeated in the statement, and the \
         where-builders in titles.rs are where it is written:\n  {}",
        bad.join("\n  ")
    );
}

/// The three background release pickers must each reach their partial
/// index on `releases`, with NO temp B-tree - B1, the RELEASES half of
/// the disease N1 fixed one table over.
///
/// probe7z_pick and pesto_pick run every 60 s under `with_index` for
/// the life of the daemon, and once their bands are exhausted (which is
/// the steady state - tries saturate) they return nothing and used to
/// pay a walk of `idx_rel_posted` over the whole table, or an
/// `idx_rel_size` range plus a temp sort, to say so. gapfill_pick runs
/// per scan pass and sorted the ENTIRE incomplete band (temp B-tree
/// over hundreds of thousands of rows) to return four.
///
/// Three assertions per statement, deliberately:
///
/// * The index BY NAME - a miss names an index too (`idx_rel_posted`
///   walks every row and reads like an index lookup in a log), so "no
///   SCAN" is not the bar.
/// * No temp B-tree. The two probe lanes' indexes carry `first_posted`
///   and the gapfill one carries the pick's ORDER BY expressions byte
///   for byte; if either stops matching, the sort comes back silently
///   and only this line says so.
/// * No bare table scan, the file's standing rule.
///
/// All three statements come from the same builders the picks run
/// (`probe7z_pick_sql`, `pesto_pick_sql`, `gapfill_pick_sql`), and the
/// indexes' predicates come from the same band builders those SQL
/// builders embed - so the shape planned here cannot drift from the
/// shape the daemon runs, and neither copy of a band can drift from
/// the other. The band terms are LITERALS in the SQL because a partial
/// index is reachable only when the statement's own WHERE implies its
/// predicate, proven from literal terms, never from a bound parameter.
///
/// Fresh-open databases carry the indexes (under
/// `PICKER_INDEX_INLINE_MAX` they build inline); a large existing
/// index gets them from the daemon's one-per-pass maintenance
/// backfill, and until then simply keeps the old plans.
#[test]
fn every_background_picker_reaches_its_partial_index() {
    let d = dir("pickers");
    let ix = Index::open(&d.join("index.db")).unwrap();
    let cases = [
        ("probe7z_pick", probe::probe7z_pick_sql(), "idx_rel_probe7z"),
        ("pesto_pick", pesto::pesto_pick_sql(), "idx_rel_pesto_tiny"),
        (
            "gapfill_pick",
            crate::index::gapfill_pick_sql(),
            "idx_rel_gapfill",
        ),
    ];
    let mut bad: Vec<String> = Vec::new();
    for (what, sql, index) in &cases {
        let p = plan(&ix, sql);
        if table_scan(&p) || !p.contains(index) {
            bad.push(format!("{what}: wanted {index}, got {p}"));
        }
        if p.contains("TEMP B-TREE") {
            bad.push(format!("{what} sorts - the bounded pick is gone: {p}"));
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        bad.is_empty(),
        "a background picker no longer answers from its partial index on \
         `releases` - the band builders (probe7z_band_sql, pesto_band_sql, \
         GAPFILL_BAND_SQL) are the single source for both the statements and \
         the index predicates in schema.rs:\n  {}",
        bad.join("\n  ")
    );
}

/// Every id an *arr client searches by must reach an index on `titles`.
///
/// These are the whole of Sonarr's and Radarr's primary lookup path: one
/// per search, on the request the user is waiting for. `titles` is
/// smaller than `releases` (tens of thousands of rows, not tens of
/// millions) so a scan here is a slowdown rather than the wedge the note
/// at the top describes - but it is a slowdown on the hottest *arr
/// statement there is, and it hid in plain sight twice over.
///
/// `idx_titles_tvdb` shipped with TODO 187 for one of these queries and
/// answered NOTHING: a partial index is reachable only when the
/// statement's own WHERE implies its predicate, and SQLite does not
/// derive `tvdb>0` from `tvdb=?1`. The guard terms in query.rs are
/// load-bearing and look redundant, which is the combination this test
/// exists to protect.
///
/// And the plan of a miss NAMES an index either way: with the sweep 7
/// `ORDER BY key` tail, the unguarded shapes plan as `SCAN titles USING
/// INDEX sqlite_autoindex_titles_1` - a full pass over the primary key,
/// which reads like an index lookup in a log. So each row below names
/// the index it must actually use, rather than only forbidding "SCAN".
#[test]
fn every_arr_id_lookup_reaches_an_index_on_titles() {
    let d = dir("titleids");
    let ix = Index::open(&d.join("index.db")).unwrap();
    // WHERE clauses copied verbatim from the call sites in query.rs; the
    // tail is the one `title_keys` appends, because the planner sees the
    // whole statement and the ORDER BY is what makes the primary key
    // look attractive.
    let tail = format!(" ORDER BY key LIMIT {}", Index::ID_KEY_CAP);
    let lookups = [
        (
            "title_key_for_imdb",
            "SELECT key FROM titles WHERE imdb <> '' AND (imdb=?1 OR imdb=?2)",
            "idx_titles_imdb",
        ),
        (
            "title_key_for_tvdb",
            "SELECT key FROM titles WHERE tvdb=?1 AND tvdb > 0 AND kind='tv'",
            "idx_titles_tvdb",
        ),
        (
            "title_key_for_tmdb",
            "SELECT key FROM titles WHERE tmdb_id=?1 AND tmdb_id > 0 AND kind='movie'
               AND id_src = 'tmdb'",
            "idx_titles_tmdb",
        ),
        (
            "title_key_for_tvmaze",
            "SELECT key FROM titles WHERE tmdb_id=?1 AND tmdb_id > 0 AND kind='tv'
               AND id_src = 'tvmaze'",
            "idx_titles_tmdb",
        ),
        (
            "tvdb_id_for_title",
            "SELECT tvdb FROM titles WHERE key=?1 AND kind='tv' AND tvdb > 0",
            "sqlite_autoindex_titles_1",
        ),
    ];
    let mut bad: Vec<String> = Vec::new();
    for (what, sql, index) in lookups {
        // The per-key reverse lookup is a primary-key seek and carries no
        // ORDER BY; every resolver goes through `title_keys`.
        let sql = if what == "tvdb_id_for_title" {
            sql.to_string()
        } else {
            format!("{sql}{tail}")
        };
        let p = plan(&ix, &sql);
        if p.contains("SCAN titles") || !p.contains(index) {
            bad.push(format!("{what}: wanted {index}, got {p}"));
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        bad.is_empty(),
        "these *arr id lookups no longer reach their index on `titles` - a partial \
         index needs its predicate repeated in the statement:\n  {}",
        bad.join("\n  ")
    );
}

/// ...and "not a full scan" is too weak a bar for the stale-partial
/// reaper, for the same reason it was too weak for the oracle sampler
/// below: its WHERE also carries `first_posted` and `first_seen` ranges,
/// and `idx_rel_posted` / `idx_rel_seen` both exist. If the planner ever
/// prefers one of those, the plan still reads `SEARCH releases USING
/// INDEX ...` - no scan anywhere - while the walk quietly stops being
/// bounded by the rowid stride at all, and with it the kv cursor, and
/// with it the 1 s slice. So assert the stride's index by name.
#[test]
fn the_stale_partial_reaper_walks_the_rowid_stride() {
    let d = dir("stride");
    let ix = Index::open(&d.join("index.db")).unwrap();
    let (_, sql) = INDEXED
        .iter()
        .find(|(what, _)| *what == "prune_stale_partials selection")
        .expect("the reaper's selection left the list");
    let p = plan(&ix, sql);
    let walks_the_stride = p.contains("SEARCH releases USING INTEGER PRIMARY KEY");
    crate::index::testutil::teardown(&d, ix);
    assert!(
        walks_the_stride,
        "the reaper no longer walks by rowid, so its cursor and its slice \
         bound nothing - one entry can walk the whole table again: {p}"
    );
}

/// Every statement inside every TRIGGER must reach an index.
///
/// This is the blind spot the list at the top of this file cannot cover:
/// a trigger body is DDL in `schema.rs`, nobody writes it at a call site,
/// and it runs on EVERY insert or delete of the table it hangs off -
/// multiplied by the batch. `rel_identity_ad_v2` carried
/// `UPDATE spots SET release_id=-1 WHERE release_id=old.id` from 14 Aug.
/// `idx_spots_rel` is partial on `release_id>0` and the statement did not
/// repeat it, so the plan was `SCAN spots` - a full pass over every spot
/// ever seen, per deleted release, inside the caller's transaction on the
/// index write mutex. Measured 20 Aug 2026 on the real schema with 2.0 M
/// spots: 83-98 ms a row against 0.26-0.42 ms with the term, so one
/// 8000-id `prune_batch` went from about three seconds to eleven minutes.
/// That is Gary's report of a finished job stuck in the tail while the
/// hourly retention reap ran.
///
/// Note what the two guards catch differently. The list above is
/// hand-maintained, so it only sees statements somebody remembered to
/// add. This one enumerates `sqlite_master`, so a trigger added later is
/// covered the day it lands, without anyone thinking of this file.
///
/// A trigger statement is checked in the shape the planner sees it:
/// `old.x` / `new.x` are values the planner cannot look inside, exactly
/// like a bound parameter, so they are rewritten to `?`.
#[test]
fn no_trigger_statement_full_scans_a_table() {
    let d = dir("triggers");
    let ix = Index::open(&d.join("index.db")).unwrap();
    let bodies: Vec<(String, String)> = {
        let mut stmt = ix
            .db
            .prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert!(
        bodies.len() >= 8,
        "sqlite_master lists only {} triggers - the enumeration broke, and a \
         guard that checks nothing passes silently",
        bodies.len()
    );
    let mut bad: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for (name, sql) in &bodies {
        for stmt in trigger_statements(sql) {
            checked += 1;
            let p = plan(&ix, &stmt);
            // "SCAN CONSTANT ROW" is the planner's name for a one-row
            // VALUES/SELECT with no table behind it - the shape every fts
            // sync statement takes, and not a pass over anything.
            let scans: Vec<&str> = p
                .split(" | ")
                .filter(|step| step.contains("SCAN") && !step.contains("SCAN CONSTANT ROW"))
                .collect();
            if !scans.is_empty() {
                bad.push(format!(
                    "{name}: {} <- {}",
                    scans.join(" | "),
                    squash(&stmt)
                ));
            }
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        checked >= bodies.len(),
        "no statement was extracted from some trigger body - the BEGIN/END \
         split stopped matching what schema.rs writes"
    );
    assert!(
        bad.is_empty(),
        "these trigger statements full-scan a table, once per affected row, inside \
         whatever transaction fired them - a partial index needs its predicate \
         repeated in the statement:\n  {}",
        bad.join("\n  ")
    );
}

/// The statements of a `CREATE TRIGGER ... BEGIN a; b; END` body, with
/// `old.`/`new.` column references rewritten to `?` so each one can be
/// planned on its own. Our trigger bodies are plain statement lists with
/// no nested block and no semicolon inside a literal, which is what makes
/// the split safe - the `checked` assertion above is the tripwire for the
/// day that stops being true.
fn trigger_statements(sql: &str) -> Vec<String> {
    let Some(begin) = sql.find(" BEGIN") else {
        return Vec::new();
    };
    let body = &sql[begin + " BEGIN".len()..];
    let body = body.rsplit_once("END").map_or(body, |(head, _)| head);
    body.split(';')
        .map(deref_row_aliases)
        .filter(|s| !s.trim().is_empty())
        .collect()
}

/// `old.stem` -> `?`. The planner treats a trigger's row reference as an
/// opaque value, the same way it treats a bound parameter, so this keeps
/// the shape it sees while making the fragment a statement we can prepare.
fn deref_row_aliases(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    loop {
        let hit = ["old.", "new.", "OLD.", "NEW."]
            .iter()
            .filter_map(|k| rest.find(k).map(|i| (i, k.len())))
            .min();
        let Some((at, klen)) = hit else {
            out.push_str(rest);
            return out;
        };
        // Only a bare `old.` counts - not the tail of an identifier that
        // happens to end in those letters.
        let boundary = rest[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        out.push_str(&rest[..at]);
        if !boundary {
            out.push_str(&rest[at..at + klen]);
            rest = &rest[at + klen..];
            continue;
        }
        out.push('?');
        rest = &rest[at + klen..];
        let end = rest
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        rest = &rest[end..];
    }
}

/// Does this plan read the `titles` table itself, rather than reaching
/// it through an index? The enricher's statements alias it to `t`, so
/// the string "SCAN titles" never appears in their plans - the step to
/// look for is a `SCAN` naming no index at all.
///
/// "SCAN CONSTANT ROW" is not one: it is the planner's name for the
/// one-row outer SELECT that wraps every `SELECT EXISTS(...)` probe,
/// with no table behind it.
fn table_scan(plan: &str) -> bool {
    plan.split(" | ").any(|step| {
        step.starts_with("SCAN ") && !step.contains("USING") && step != "SCAN CONSTANT ROW"
    })
}

/// One line, for a failure message that has to fit in a terminal.
fn squash(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `person_upsert`'s three handle lookups must each reach their partial
/// index on `people`.
///
/// Same trap as the *arr lookups above, one table over and with nothing
/// guarding it until now. Each lookup sits behind a Rust-side `if`
/// (`tvmaze_id > 0`, `!qid.is_empty()`, `!imdb.is_empty()`) - which the
/// PLANNER cannot see, so the statement itself has to repeat the
/// predicate or the partial unique index is unreachable and the lookup
/// becomes a full scan of `people`. Three of them, per credit written,
/// under the index write mutex.
#[test]
fn every_person_handle_lookup_reaches_its_partial_index() {
    let d = dir("peopleids");
    let ix = Index::open(&d.join("index.db")).unwrap();
    // Copied verbatim from person_upsert in titles.rs.
    let lookups = [
        (
            "by tvmaze_id",
            "SELECT id FROM people WHERE tvmaze_id=?1 AND tvmaze_id > 0",
            "idx_people_tvmaze",
        ),
        (
            "by wikidata_qid",
            "SELECT id FROM people WHERE wikidata_qid=?1 AND wikidata_qid <> ''",
            "idx_people_qid",
        ),
        (
            "by imdb",
            "SELECT id FROM people WHERE imdb=?1 AND imdb <> ''",
            "idx_people_imdb",
        ),
    ];
    let mut bad: Vec<String> = Vec::new();
    for (what, sql, index) in lookups {
        let p = plan(&ix, sql);
        if p.contains("SCAN people") || !p.contains(index) {
            bad.push(format!("{what}: wanted {index}, got {p}"));
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        bad.is_empty(),
        "these person handle lookups no longer reach their partial index on \
         `people` - the predicate must be repeated in the statement:\n  {}",
        bad.join("\n  ")
    );
}

/// The case-folded fallback's two arms must stay exactly
/// complementary. They are what let each half use an index, and a stem
/// that falls in the gap between them simply stops resolving - which
/// would be silent, because the caller reads "no rows" as "not indexed
/// here" and moves on.
#[test]
fn the_case_folded_arms_cover_every_row_between_them() {
    let d = dir("arms");
    let ix = Index::open(&d.join("index.db")).unwrap();
    ix.db
        .execute(
            "INSERT INTO releases(stem, poster, grp, first_posted, pre_title)
             VALUES('Unnamed.Release','p','g',1,''),
                   ('Named.Release','p','g',1,'Named.Release.Real.Name')",
            [],
        )
        .unwrap();
    let total: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    let covered: i64 = ix
        .db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM releases WHERE pre_title='')
                  + (SELECT COUNT(*) FROM releases WHERE pre_title<>'')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(covered, total, "the two arms must partition the table");
    // ...and the fallback finds a row through either of them.
    assert_eq!(ix.release_ids_by_stem("unnamed.release").unwrap().len(), 1);
    assert_eq!(ix.release_ids_by_stem("named.release").unwrap().len(), 1);
    crate::index::testutil::teardown(&d, ix);
}

/// L3b: "not a full scan" is too weak a bar for the oracle sampler.
///
/// Its seeks order by `first_posted` and filter `junk < 50`. No index
/// carried `junk` - it arrives by ALTER TABLE - so they planned as a
/// SEARCH on `idx_rel_posted` with a POST-FILTER, doing a rowid table
/// fetch per index entry to test junk, unbounded forwards and with no
/// wall-clock budget in the draw loop. That passes the gate above,
/// which is why it survived: `SCAN releases` never appears.
///
/// The bar that catches it is naming the partial index. If a future
/// edit widens the sampler's WHERE away from `junk < 50`, or drops
/// `idx_rel_visible_posted`, the index silently stops being used and
/// the per-row fetches come back - so assert the pairing directly.
#[test]
fn the_oracle_sampler_uses_the_partial_visible_index() {
    let d = dir("oracle-partial");
    let ix = Index::open(&d.join("index.db")).unwrap();
    for (what, sql) in INDEXED {
        if !what.starts_with("oracle_pick") || !what.contains("seek") {
            continue;
        }
        let p = plan(&ix, sql);
        assert!(
            p.contains("idx_rel_visible_posted"),
            "{what} no longer uses the partial visible index, so it is back to a \
             table fetch per row to test junk: {p}"
        );
    }
}

/// The flat release list's `hide_adult` exclusion list must reach
/// `idx_titles_adult`.
///
/// Without it the subquery plans as `SCAN t` - a full pass over
/// `titles`, aliased, so "SCAN titles" never appears and the naive
/// string test above is blind to it. Browse renders its whole predicate
/// list twice (unqualified, and against the `d.` alias of the
/// best-copy-per-stem subquery) and runs two statements (the COUNT and
/// the page), so that scan ran FOUR times per request: measured on a
/// synthetic 1M-title corpus, 1,235 ms against 3.4 ms for the same
/// query with `hide_adult` off, and unchanged by how selective the rest
/// of the filter was. With the index, 25.7 ms.
///
/// The index is PARTIAL on the genre test, so this is the pairing that
/// has to hold: the statement's WHERE must repeat the index predicate
/// verbatim, which is why both come from `adult_genre_match_sql!` with
/// only the alias prefix differing. Edit one spelling by hand and this
/// test is what says so.
#[test]
fn the_adult_exclusion_list_reaches_its_partial_index() {
    let d = dir("adultlist");
    let ix = Index::open(&d.join("index.db")).unwrap();
    // Verbatim from browse.rs's `hide_adult` arm, with the `{}` alias
    // placeholder rendered both ways round - the outer list and the
    // representative-copy subquery's `d.` - because a partial index that
    // answers one and not the other is still a full scan per request.
    let sub = format!("SELECT t.key FROM titles t WHERE {ADULT_GENRE_MATCH_SQL}");
    let shapes = [
        format!("SELECT id FROM releases WHERE title_key NOT IN ({sub})"),
        format!(
            "SELECT id FROM releases WHERE id = (SELECT d.id FROM releases d
               WHERE d.stem = releases.stem AND d.title_key NOT IN ({sub})
               ORDER BY d.complete DESC, d.id LIMIT 1)"
        ),
    ];
    let mut bad: Vec<String> = Vec::new();
    for sql in &shapes {
        let p = plan(&ix, sql);
        if !p.contains("idx_titles_adult") || table_scan(&p) {
            bad.push(format!("{}: {p}", squash(sql)));
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        bad.is_empty(),
        "the hide_adult exclusion list is back to scanning `titles` - the partial \
         index `idx_titles_adult` needs its predicate repeated verbatim by the \
         statement:\n  {}",
        bad.join("\n  ")
    );
}

/// `browse`'s exact `total` must never answer its DISTINCT out of
/// `idx_rel_stem`, and must still reach the partial index when the
/// filters have one.
///
/// The count is `COUNT(DISTINCT +stem)` and the unary `+` is the whole
/// reason it is fast (`browse_total_sql` carries the measurement).
/// Written without it, SQLite satisfies the DISTINCT by walking
/// `idx_rel_stem` - every row of it, in stem order, with a rowid table
/// fetch per entry to test whatever the index does not carry. On the
/// 13.2M-release live index that turned the 2.21 s `complete` shape (an
/// *arr RSS sync) into 27.5 s. `SCAN releases` never appears in that
/// plan, so the gate at the top of this file cannot see it; the index
/// NAME is the assertion.
///
/// The second half is the other way the `+` could go wrong: a blunter
/// spelling that suppressed index use outright (`NOT INDEXED`) also
/// loses `idx_rel_visible_posted`, which is what keeps the wall's own
/// list at 50 ms on that same index instead of a 13.2M-row table scan.
/// So one shape must NOT name an index and the other MUST.
#[test]
fn browse_total_never_walks_the_whole_stem_index() {
    let d = dir("browsetotal");
    let ix = Index::open(&d.join("index.db")).unwrap();
    let stem_index = plan(&ix, &crate::index::browse::browse_total_sql("complete"));
    let visible = plan(&ix, &crate::index::browse::browse_total_sql("junk < 50"));
    crate::index::testutil::teardown(&d, ix);
    assert!(
        !stem_index.contains("idx_rel_stem"),
        "browse's total is answering its DISTINCT from idx_rel_stem, which \
         costs a table fetch per entry of a whole-table index - see \
         `browse_total_sql`, the `+` on the column is what stops it: {stem_index}"
    );
    assert!(
        visible.contains("idx_rel_visible_posted"),
        "browse's total no longer reaches the partial visible index, so the \
         wall's list now walks every release: {visible}"
    );
}

/// §198: the `complete` browse shapes - every *arr RSS sync - must
/// count out of a partial index rather than off the end of the table.
///
/// `complete` is 1.5% of `releases` and until §198 nothing indexed it,
/// so the newznab facade's `total` (it sets `complete_only`, and no
/// junk ceiling) reached 204k rows only through a full 13.2M-row scan.
/// Measured on the live index: 1.05 s for Radarr's shape, 1.12 s with
/// no cat, 3.65 s once a `maxage` joined in. With the pair below,
/// 0.11 s / 0.16 s / 0.15 s. Full numbers and the two candidates that
/// lost: `research/BROWSE-complete-index-2026-08-20.md`.
///
/// Every *arr query carries a kind - `t=movie` and `t=tvsearch` each
/// set one even when the client sends no `cat` - so the kind-leading
/// index is the one the RSS syncs actually reach; the no-cat shape is
/// Prowlarr's generic search and NZBHydra's. Both are gated here
/// because the pair is what makes the page safe: see
/// `picker_index_ddl` for why shipping the kind-leading one alone
/// regresses the no-cat PAGE 16x.
///
/// **The maxage case asserts only "not a scan", and that is not
/// timidity.** This database is empty, so SQLite plans it with no
/// statistics at all and takes the new index. On the live index, with
/// the sampled statistics `Index::optimize` writes (`analysis_limit=
/// 1000`), `idx_rel_kind(kind, first_posted)` and the new
/// `idx_rel_complete_kind(kind, first_posted, stem)` get the SAME
/// per-value estimate - 1001, the sample size, for a column with six
/// values and 2.2M rows behind the commonest - and the planner takes
/// `idx_rel_kind`, measured at 1.05 s, exactly today's number. So this
/// gate CANNOT see that flip, and asserting the index name here would
/// assert something production does not do. What it can hold is the
/// floor: no shape of an *arr count may reach the table.
#[test]
fn browse_total_over_complete_reaches_a_complete_index() {
    let d = dir("browsecomplete");
    let ix = Index::open(&d.join("index.db")).unwrap();
    let shapes = [
        ("no cat", "complete", "idx_rel_complete_"),
        (
            "t=movie / t=tvsearch",
            "kind = ?1 AND complete",
            "idx_rel_complete_kind",
        ),
        // Any index at all - see the note above on why this one
        // cannot name the index it gets on an empty database.
        (
            "with maxage",
            "kind = ?1 AND complete AND first_posted >= ?2",
            "",
        ),
    ];
    let plans: Vec<(&str, String, &str)> = shapes
        .iter()
        .map(|(what, clause, want)| {
            (
                *what,
                plan(&ix, &crate::index::browse::browse_total_sql(clause)),
                *want,
            )
        })
        .collect();
    crate::index::testutil::teardown(&d, ix);
    let bad: Vec<String> = plans
        .iter()
        .filter(|(_, p, want)| table_scan(p) || !p.contains(want))
        .map(|(what, p, want)| format!("{what}: wanted {want}, got {p}"))
        .collect();
    assert!(
        bad.is_empty(),
        "an *arr's browse total is back to scanning `releases` - the index \
         predicate in `picker_index_ddl` must stay the literal `complete` \
         term browse itself renders, or SQLite cannot prove the statement \
         implies it:\n  {}",
        bad.join("\n  ")
    );
}

/// The deferred builder installs ONE `picker_index_ddl` entry per idle
/// pass, a scan interval apart, so on a migrating database whichever
/// complete-pair member is listed first stands ALONE for at least one
/// interval. Posted-leading alone is only ever an improvement;
/// kind-leading alone is the documented 16x no-cat page regression. So
/// the list order is load-bearing: posted must precede kind.
#[test]
fn the_complete_pair_deploys_posted_first() {
    let names: Vec<&str> = crate::index::schema::picker_index_ddl()
        .iter()
        .map(|(n, _)| *n)
        .collect();
    let posted = names
        .iter()
        .position(|n| *n == "idx_rel_complete_posted")
        .expect("posted member missing from picker_index_ddl");
    let kind = names
        .iter()
        .position(|n| *n == "idx_rel_complete_kind")
        .expect("kind member missing from picker_index_ddl");
    assert!(
        posted < kind,
        "idx_rel_complete_posted must be listed before idx_rel_complete_kind: \
         the one-per-pass deferred builder would otherwise leave the \
         kind-leading index standing alone for a full scan interval, \
         which is the measured 16x no-cat page regression \
         (order found: {names:?})"
    );
}

/// A `genre` wall rule must reach `titles` by SEEK, in BOTH renderings
/// of the release-list predicate - and so must the summary path's copy
/// of the same test.
///
/// This is the `hide_adult` disease one rule over, and it could not
/// take the same cure. `idx_titles_adult` is partial on a predicate
/// fixed when the index is created; a genre rule's value is a bound
/// parameter tested with a leading-`%` LIKE, so there is no predicate
/// to index and no prefix to seek - the exclusion list
/// (`title_key NOT IN (SELECT key FROM titles WHERE genres LIKE …)`)
/// was an unindexable full pass over `titles` by construction, four
/// times per request: browse renders its whole predicate list twice
/// (unqualified, and against the `d.` alias of the best-copy-per-stem
/// subquery) and issues two statements, the COUNT and the page.
/// Measured on a synthetic 1M-title corpus: 741 ms for one rule, 2.23 s
/// for three, against 3.2 ms with no rule at all.
///
/// The fix asks the question per candidate release instead - a seek on
/// the `titles` primary key, carrying the ORIGINAL substring test - so
/// what this gate asserts is a SEARCH of `titles` in each rendering and
/// no scan anywhere. The predicate is taken from `curation_wheres`
/// itself rather than retyped, so the shape planned here is the shape
/// the daemon runs.
///
/// Note the aliasing trap that hid this: these statements alias the
/// table, so the string "SCAN titles" never appears in a plan - the
/// step to look for is a `SCAN` naming no index, which is what
/// `table_scan` tests.
#[test]
fn the_genre_hide_rule_seeks_titles() {
    let d = dir("genrerule");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // The summary tables are installed on demand, not at open.
    ix.rebuild_title_summaries().unwrap();
    ix.rule_add("genre", "reality", false).unwrap();
    let mut wheres: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    ix.curation_wheres("{}", &mut wheres, &mut params).unwrap();
    let render = |pfx: &str| {
        wheres
            .iter()
            .map(|w| w.replace("{}", pfx))
            .collect::<Vec<_>>()
            .join(" AND ")
    };
    // The two renderings browse issues, in its own shape. An index that
    // answers one and not the other is still a full pass per request.
    let shapes = [
        (
            "release list",
            format!("SELECT id FROM releases WHERE {}", render("")),
        ),
        (
            "representative pick",
            format!(
                "SELECT id FROM releases WHERE id = (SELECT d.id FROM releases d
                   WHERE d.stem = releases.stem AND {}
                   ORDER BY d.complete DESC, d.id LIMIT 1)",
                render("d.")
            ),
        ),
        // ...the exact `total`, which TODO 197 rebuilt as
        // `COUNT(DISTINCT +stem)` over these same filters minus the
        // representative predicate. It is a third rendering of this
        // term, on the one statement whose candidate set is the whole
        // table for the uncurated facades, so it gets its own line here
        // rather than being assumed to follow from the page's.
        (
            "exact total (197)",
            crate::index::browse::browse_total_sql(&render("")),
        ),
        // ...and the summary-backed card page, whose copy of the test
        // reads the row it has already joined.
        (
            "summary card page",
            "SELECT m.title_key FROM title_summaries m
               LEFT JOIN titles t ON t.key = m.title_key
              WHERE NOT (COALESCE(t.genres,'') LIKE '%' || ?1 || '%')"
                .to_string(),
        ),
    ];
    // The bar is about the TITLES side only: this term must reach
    // `titles` by seek and must never walk it. Deliberately NOT the
    // file's blanket `table_scan`, because the exact `total` legitimately
    // scans `releases` - TODO 197 made it `COUNT(DISTINCT +stem)`, and
    // with no junk ceiling in the predicate (this test installs a genre
    // rule and nothing else) counting distinct stems IS a pass over the
    // table. What that statement may not do is walk `idx_rel_stem`, and
    // `browse_total_never_walks_the_whole_stem_index` is the gate for it.
    let scans_titles = |plan: &str| {
        plan.split(" | ").any(|step| {
            step.starts_with("SCAN ")
                && !step.contains("USING")
                && matches!(
                    step.trim_start_matches("SCAN ").split_whitespace().next(),
                    Some("titles") | Some("t") | Some("tg")
                )
        })
    };
    let mut bad: Vec<String> = Vec::new();
    for (what, sql) in &shapes {
        let p = plan(&ix, sql);
        let seeks_titles = p.contains("SEARCH tg USING INDEX sqlite_autoindex_titles_1")
            || p.contains("SEARCH t USING INDEX sqlite_autoindex_titles_1")
            // The summary page reads the row it has already joined.
            || p.contains("SEARCH t USING INTEGER PRIMARY KEY");
        if scans_titles(&p) || !seeks_titles {
            bad.push(format!("{what}: {p}\n     {}", squash(sql)));
        }
    }
    crate::index::testutil::teardown(&d, ix);
    assert!(
        bad.is_empty(),
        "a genre wall rule is scanning `titles` again - the test belongs on the \
         candidate row (a seek on the titles primary key), not in an exclusion \
         list built by walking every title:\n  {}",
        bad.join("\n  ")
    );
}
