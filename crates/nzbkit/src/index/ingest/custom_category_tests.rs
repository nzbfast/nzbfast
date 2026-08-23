//! Custom-category (re)classification tests, out of `ingest.rs` under
//! the size gate (TODO 106). The subject is one user-defined category
//! from every angle: ingested under it, browsed and carded under it,
//! reconciled onto rows stored before it existed, left alone by the
//! quality backfill, and the stamp that must not declare a half-done
//! reclassify finished. `super` is still `ingest`, so the bodies are
//! verbatim.

use super::*;
use crate::index::testutil::{entry, teardown};

fn f1_cats() -> Vec<crate::categories::CustomCategory> {
    vec![crate::categories::CustomCategory {
        slug: "formula-1".into(),
        name: "Formula 1".into(),
        pattern: r"^formula\.?1\.".into(),
        not_match: String::new(),
        base: crate::categories::BaseBehavior::Movie,
    }]
}

/// 24D end-to-end at the index level: define a category, ingest
/// matching releases, see them under the category's kind in browse
/// AND as separate wall cards (the F1 dedupe lesson).
#[test]
fn custom_category_ingest_browse_and_cards() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cats-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.set_custom(f1_cats());
    ix.ingest(
        "alt.test",
        &[
            entry("\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f1", 900 << 20),
            entry("\"Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f2", 900 << 20),
            entry("\"The.Matrix.1999.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)", "p@x", "m1", 900 << 20),
        ],
        100,
    )
    .unwrap();
    // The category's kind filter finds exactly its releases.
    let (f1, total) = ix
        .browse(&BrowseQuery {
            kind: Some("formula-1".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(total, 2, "{f1:?}");
    assert!(f1.iter().all(|r| r.kind == "formula-1"), "{f1:?}");
    // The two sessions keep DISTINCT dedupe keys (pre-24D both were
    // "m:formula1:2026") → two wall cards, and the movie is untouched.
    let keys: std::collections::HashSet<String> = ix
        .search("formula1", 10)
        .unwrap()
        .iter()
        .map(|r| {
            ix.db
                .query_row(
                    "SELECT title_key FROM releases WHERE id=?1",
                    [r.id],
                    |row| row.get(0),
                )
                .unwrap()
        })
        .collect();
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert!(
        keys.iter().all(|k| k.starts_with("c:formula-1:")),
        "{keys:?}"
    );
    let (cards, _) = ix
        .browse_cards(
            &BrowseQuery {
                kind: Some("formula-1".into()),
                ..Default::default()
            },
            CardSort::Latest,
            false,
            false,
            None,
        )
        .unwrap();
    assert_eq!(cards.len(), 2, "{cards:?}");
    assert!(cards.iter().all(|c| c.kind == "formula-1"));
    let (movie, _) = ix
        .browse(&BrowseQuery {
            kind: Some("movie".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(movie.len(), 1);
    assert_eq!(movie[0].kind, "movie");
    // Custom titles get seeded for the wall (pretty names), and the
    // custom key renders readably.
    assert!(ix.seed_missing_titles(365000, 100).unwrap() >= 2);
    assert_eq!(
        pretty_key("c:formula-1:formula1:2026:round11 hungary qualifying f1tv"),
        "Formula1 2026 Round11 Hungary Qualifying F1tv"
    );
    teardown(&dir, ix);
}

/// 24D reclassification: rows indexed BEFORE a category existed move
/// under it when the config changes, the pass is fingerprint-stamped
/// (unchanged config = no-op), and deleting the category moves them
/// back to their built-in kind.
#[test]
fn reclassify_custom_reconciles_stored_rows() {
    let dir = std::env::temp_dir().join(format!("nzbfast-recat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    // No categories yet: both sessions collapse onto one movie key -
    // the exact pre-24D failure.
    ix.ingest(
        "alt.test",
        &[
            entry(
                "\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)",
                "p@x",
                "f1",
                900 << 20,
            ),
            entry(
                "\"Formula1.2026.Round12.Spa.Race.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)",
                "p@x",
                "f2",
                900 << 20,
            ),
        ],
        100,
    )
    .unwrap();
    let (rows, _) = ix
        .browse(&BrowseQuery {
            kind: Some("movie".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Define the category and reconcile.
    ix.set_custom(f1_cats());
    assert_eq!(ix.reclassify_custom().unwrap(), 2);
    // Same config again: fingerprint no-op.
    assert_eq!(ix.reclassify_custom().unwrap(), 0);
    let (rows, _) = ix
        .browse(&BrowseQuery {
            kind: Some("formula-1".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Delete the category: rows return to the built-in classifier.
    ix.set_custom(Vec::new());
    assert_eq!(ix.reclassify_custom().unwrap(), 2);
    let (rows, _) = ix
        .browse(&BrowseQuery {
            kind: Some("movie".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    teardown(&dir, ix);
}

/// `Index::open`'s quality_v9 backfill re-parses every stem, and it
/// runs BEFORE `set_custom` by construction - the constructor
/// hardcodes an empty category list, so the pass cannot see the
/// user's categories however the caller is written. Left unguarded it
/// rewrote every row a custom category had claimed back to the
/// built-in answer: each F1 session collapsing onto one movie card,
/// out of the category tab, and losing the Custom junk exemption.
///
/// And it did not heal. `reclassify_custom` reads an unchanged
/// fingerprint with no cursor and returns Ok(0) on every later start,
/// so the damage stood until the user happened to edit the category
/// config. Bumping the kv key - which the comment above the pass
/// advertises as the ordinary way to backfill a new column - would
/// re-inflict it on every install.
#[test]
fn the_quality_backfill_leaves_custom_classifications_alone() {
    let dir = std::env::temp_dir().join(format!("nzbfast-qv8-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("index.db");
    {
        let mut ix = Index::open(&path).unwrap();
        ix.ingest(
            "alt.test",
            &[
                entry("\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f1", 900 << 20),
                entry("\"Formula1.2026.Round12.Spa.Race.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f2", 900 << 20),
                entry("\"The.Matrix.1999.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)", "p@x", "m1", 900 << 20),
            ],
            100,
        )
        .unwrap();
        ix.set_custom(f1_cats());
        assert_eq!(ix.reclassify_custom().unwrap(), 2, "both sessions claimed");

        // An install whose backfill has not run yet - either it never
        // did, or the key was bumped to pick up a new column.
        ix.db
            .execute(
                "DELETE FROM kv WHERE k IN ('quality_v9','quality_v9_cursor')",
                [],
            )
            .unwrap();
        // ...and blank a built-in row's resolution, so the pass has
        // something to prove it still does its job.
        ix.db
            .execute("UPDATE releases SET res='' WHERE kind='movie'", [])
            .unwrap();
    }

    // The next open runs the pass with no categories installed, which
    // is the only state `Index::open` can be in.
    let ix = Index::open(&path).unwrap();
    // Scoped: a live `Statement` borrows the connection, so `teardown`
    // could not take the index while this was still in hand - and the
    // statement holds SQLite resources of its own that want releasing
    // before the connection anyway.
    let rows: Vec<(String, String)> = {
        let mut stmt = ix
            .db
            .prepare("SELECT kind, title_key FROM releases WHERE stem LIKE 'Formula1%' ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert_eq!(rows.len(), 2);
    for (kind, key) in &rows {
        assert_eq!(kind, "formula-1", "the backfill unclassified a custom row");
        assert!(
            key.starts_with("c:formula-1:"),
            "the backfill rewrote a custom title key to {key:?} - every session of \
             the season then collapses onto one card"
        );
    }
    // The two sessions must still be SEPARATE cards, which is the
    // whole point of the category.
    assert_ne!(rows[0].1, rows[1].1);

    // ...and the pass still backfilled the built-in row it is for.
    let res: String = ix
        .db
        .query_row("SELECT res FROM releases WHERE kind='movie'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(res, "1080p", "the backfill must still fill built-in rows");

    teardown(&dir, ix);
}

/// The fingerprint and the cursor are ONE state transition, and this
/// is what happens when they are not: an interruption between the two
/// writes leaves the new config stamped with no cursor, which every
/// later call reads as "already finished". Reclassification is then
/// skipped forever - the user's new category never reaches the rows
/// already in the index, and nothing short of hand-editing `kv` gets
/// it back.
///
/// The interruption is a trigger that aborts the cursor write rather
/// than a killed process: same window, made deterministic. What is
/// asserted is the recovery, not the mechanism - after the failure,
/// the next call must still have the work to do.
#[test]
fn an_interrupted_reclassify_stamp_does_not_declare_the_work_done() {
    let dir = std::env::temp_dir().join(format!("nzbfast-recat-crash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.ingest(
        "alt.test",
        &[
            entry(
                "\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)",
                "p@x",
                "f1",
                900 << 20,
            ),
            entry(
                "\"Formula1.2026.Round12.Spa.Race.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)",
                "p@x",
                "f2",
                900 << 20,
            ),
        ],
        100,
    )
    .unwrap();

    // Crash the cursor write, leave the fingerprint write alone.
    ix.db
        .execute_batch(
            "CREATE TRIGGER kv_lose_the_cursor BEFORE INSERT ON kv
               WHEN new.k='custom_cats_cursor'
               BEGIN SELECT RAISE(ABORT, 'interrupted before the cursor landed'); END;",
        )
        .unwrap();
    ix.set_custom(f1_cats());
    assert!(
        ix.reclassify_custom().is_err(),
        "the interrupted pass must report the failure, not swallow it"
    );
    ix.db
        .execute_batch("DROP TRIGGER kv_lose_the_cursor")
        .unwrap();

    // The machine is back. The category config is still new to this
    // index, so its rows must still be reclassified.
    assert_eq!(
        ix.reclassify_custom().unwrap(),
        2,
        "a half-written stamp made the index believe it had already \
         reclassified these rows"
    );
    let (rows, _) = ix
        .browse(&BrowseQuery {
            kind: Some("formula-1".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 2);
    teardown(&dir, ix);
}
