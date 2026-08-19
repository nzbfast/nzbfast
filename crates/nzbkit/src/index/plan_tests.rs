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
               AND id_src IN ('tmdb','')",
            "idx_titles_tmdb",
        ),
        (
            "title_key_for_tvmaze",
            "SELECT key FROM titles WHERE tmdb_id=?1 AND tmdb_id > 0 AND kind='tv'
               AND id_src IN ('tvmaze','')",
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
