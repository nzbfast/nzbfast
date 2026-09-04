//! The predb feed's own test suite, split out of the old index.rs (its
//! subject lives in predb.rs; inline it would break the 3,000-line file
//! ceiling).
//!
//! What is left here after the TODO 106 cut below is phase 1: the feed
//! itself. Ingest and the arrival watch, naming an obfuscated post at
//! ingest and from a late announcement, the backlog sweep, the update
//! line that fills a filename in, the named count over a partial index,
//! and pruning the feed by age and by row cap. Phase 2 and the red-team
//! round that followed it are the two child modules.

use super::predb::PREDB_RETIRED;
use super::testutil::{WALK, teardown};
use super::*;
use crate::predb::{PreKind, PreLine};

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-index-predb-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn over(subject: &str, from: &str, id: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: from.into(),
        message_id: format!("<{id}>"),
        bytes,
        date: 0,
    }
}

fn pre(title: &str, filename: &str) -> PreLine {
    PreLine {
        kind: PreKind::New,
        title: title.into(),
        filename: filename.into(),
        source: "PRE".into(),
        ..Default::default()
    }
}

// The builders above and below are used by phase 1, by correlation_tests
// and by hardening_tests, so they stay with the parent: a sibling
// cfg(test) module is not in scope through `use super::*`. `overd` and
// `tpre` came up here out of the phase 2 block in the TODO 106 cut.

/// An over entry with a controlled article date, because
/// correlation runs on `first_posted` and the plain helper leaves
/// it unset.
fn overd(subject: &str, id: &str, bytes: u64, date: i64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: "p@x".into(),
        message_id: format!("<{id}>"),
        bytes,
        date,
    }
}

/// A title-only pre (the live public relay shape): a name, a
/// section, a size - no filename, ever.
fn tpre(title: &str, category: &str, size: u64, date: i64) -> PreLine {
    PreLine {
        kind: PreKind::New,
        title: title.into(),
        category: category.into(),
        size,
        date,
        source: "PRE".into(),
        ..Default::default()
    }
}

/// A weak background pre for a correlation window: sizeless, section
/// blank and a title that classifies to nothing, so it scores near the
/// bottom and is vetoed by nothing.
///
/// It exists to make the auto tier's runner-up margin do real work. A
/// window holding exactly ONE candidate has no runner-up, and until
/// 2 Sep 2026 the gate read that as a margin of the raw score and
/// passed every time - so every auto-apply assertion in this suite,
/// and all 76 auto pairs of the calibration corpus, were proving a
/// clause that could not fail. `predb_corr::margin_clears` refuses the
/// empty case now, and the tests carry a field the way a real window
/// does: 14 days at the feed's own rate is 13k-67k pres, and
/// `corr_eval` keeps every SIZELESS one whatever the size band, so a
/// one-candidate window is a test artefact, never production.
fn bgpre(tag: &str, date: i64) -> PreLine {
    PreLine {
        kind: PreKind::New,
        title: format!("Filler.Item.{tag}"),
        category: String::new(),
        size: 0,
        date,
        source: "PRE".into(),
        ..Default::default()
    }
}

// Phase 2 and the hardening round that followed it, out for the size
// gate (TODO 106). Each child resolves to predb_tests/<name>.rs because
// this module is reached by a plain `mod predb_tests;`, not a `#[path]`,
// and each is named for its file so size-gate.py's CFG_TEST_MOD resolver
// still scores it as test code.
#[cfg(test)]
mod correlation_tests;
#[cfg(test)]
mod hardening_tests;

/// §74 hook A: an installed arrival watch hears about the releases
/// it asked for as they are ingested, complete or not, and about
/// nothing else.
#[test]
fn the_arrival_watch_reports_the_names_it_was_given() {
    let d = dir("watch-ingest");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.set_watch_names(Some(Box::new(|n: &str| n.contains("Wanted"))));
    ix.ingest(
        "alt.binaries.teevee",
        &[
            over(
                r#""Wanted.Show.S01E01.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "a1",
                100,
            ),
            over(
                r#""Other.Show.S01E01.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "b1",
                100,
            ),
            // Two parts, one seen: still going up, so still incomplete.
            over(
                r#""Wanted.Show.S01E02.1080p.WEB-GRP.rar" yEnc (1/2)"#,
                "p@x",
                "c1",
                100,
            ),
        ],
        1000,
    )
    .unwrap();
    let (hits, dropped) = ix.take_watch_hits();
    assert_eq!(dropped, 0);
    let mut got: Vec<(String, bool)> = hits.into_iter().map(|h| (h.name, h.complete)).collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("Wanted.Show.S01E01.1080p.WEB-GRP".to_string(), true),
            ("Wanted.Show.S01E02.1080p.WEB-GRP".to_string(), false),
        ],
        "the watch must see its own names and only those, \
         with completeness as the index computed it"
    );
    // Draining empties it: a second ingest of nothing interesting
    // must not re-announce the first batch.
    assert!(ix.take_watch_hits().0.is_empty());
    // Clearing the watch stops the journalling outright.
    ix.set_watch_names(None);
    ix.ingest(
        "alt.binaries.teevee",
        &[over(
            r#""Wanted.Show.S01E03.1080p.WEB-GRP.rar" yEnc (1/1)"#,
            "p@x",
            "d1",
            100,
        )],
        1000,
    )
    .unwrap();
    assert!(ix.take_watch_hits().0.is_empty());
    teardown(&d, ix);
}

/// §74 hook B: a release that GAINS a name is an arrival for anything
/// matching on names - until that moment it was an obfuscated stem no
/// watchlist entry could match. The ingest that stored it under the
/// stem says nothing; the naming leg does.
#[test]
fn naming_an_obfuscated_release_is_itself_an_arrival() {
    let d = dir("watch-named");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.set_watch_names(Some(Box::new(|n: &str| n.contains("Wanted"))));
    ix.ingest(
        "alt.binaries.boneless",
        &[over(
            r#""hH3jK9lM1nP5qR7s.part01.rar" yEnc (1/1)"#,
            "p@x",
            "n1",
            4 << 30,
        )],
        1000,
    )
    .unwrap();
    assert!(
        ix.take_watch_hits().0.is_empty(),
        "an obfuscated stem matches nothing, and must not be announced"
    );
    // The relay names it. Reopened first, because the naming lookup
    // is gated on a flag read at open.
    ix.predb_store(
        &[pre("Wanted.Show.S01E01.1080p.WEB-GRP", "zzz.part01.rar")],
        1000,
    )
    .unwrap();
    let mut ix = {
        drop(ix);
        let mut re = Index::open(&d.join("index.db")).unwrap();
        re.set_watch_names(Some(Box::new(|n: &str| n.contains("Wanted"))));
        re
    };
    let rid: i64 = ix.search("", 10).unwrap()[0].id;
    assert!(ix.pre_assign(rid, 1, 2000).unwrap());
    let (hits, _) = ix.take_watch_hits();
    assert_eq!(
        hits,
        [WatchHit {
            id: rid,
            name: "Wanted.Show.S01E01.1080p.WEB-GRP".into(),
            complete: true,
        }]
    );
    teardown(&d, ix);
}

/// The headline case: a fully obfuscated post is indexed as a random
/// stem, the relay names it, and the release comes out carrying the
/// real title everywhere the wall and the *arr feed read.
#[test]
fn an_obfuscated_post_gets_named_at_ingest() {
    let d = dir("ingest");
    let path = d.join("index.db");
    {
        let mut ix = Index::open(&path).unwrap();
        // The pre line lands FIRST: the relay usually beats the
        // header scan, which is what makes ingest-time naming the
        // main path rather than a special case.
        ix.predb_store(
            &[pre(
                "Some.Film.2026.1080p.WEB-DL.x264-GRP",
                "p5cbKvaDJ1Y0PW6DvKCIfztzZ.part01.rar",
            )],
            1000,
        )
        .unwrap();
    }
    // Re-open: `predb` is sampled at open, so this is also the check
    // that a daemon picks the feed up on its next handle.
    let mut ix = Index::open(&path).unwrap();
    ix.ingest(
        "alt.binaries.boneless",
        &[
            over(
                r#""p5cbKvaDJ1Y0PW6DvKCIfztzZ.part01.rar" yEnc (1/1)"#,
                "poster@x",
                "o1",
                4 << 30,
            ),
            over(
                r#""p5cbKvaDJ1Y0PW6DvKCIfztzZ.part02.rar" yEnc (1/1)"#,
                "poster@x",
                "o2",
                4 << 30,
            ),
        ],
        2000,
    )
    .unwrap();

    let rows = ix.search("", 10).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    // The posted identity is kept - it is half the ingest key, and
    // the evidence that the two names are different things.
    assert_eq!(r.stem, "p5cbKvaDJ1Y0PW6DvKCIfztzZ");
    assert_eq!(r.pre_title, "Some.Film.2026.1080p.WEB-DL.x264-GRP");
    assert_eq!(r.pre_source, "predb/PRE", "the claim is attributed");
    assert_eq!(r.display_name(), "Some.Film.2026.1080p.WEB-DL.x264-GRP");
    // Everything the name determines is re-derived from the REAL
    // name, not the stem it was posted under.
    assert_eq!(r.kind, "movie");
    assert_eq!(r.res, "1080p");
    let (junk, key): (i64, String) = ix
        .db
        .query_row(
            "SELECT junk, title_key FROM releases WHERE id=?1",
            [r.id],
            |x| Ok((x.get(0)?, x.get(1)?)),
        )
        .unwrap();
    assert!(
        junk < 50,
        "a named release is no longer wall junk (junk={junk})"
    );
    assert!(
        key.starts_with("m:some film"),
        "landed on a real card: {key}"
    );
    // And it is findable by the name a person would actually type.
    assert_eq!(ix.search("Some Film 2026", 10).unwrap().len(), 1);
    teardown(&d, ix);
}

/// The other order: the post is indexed first and the relay only
/// announces it later. The sweep has to find it after the fact.
#[test]
fn a_late_announcement_names_an_already_indexed_release() {
    let d = dir("sweep");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.boneless",
        &[over(
            r#""aB9zQ1mK7pR3tX5w.part01.rar" yEnc (1/1)"#,
            "p@x",
            "s1",
            4 << 30,
        )],
        1000,
    )
    .unwrap();
    assert_eq!(ix.search("", 10).unwrap()[0].pre_title, "");

    ix.predb_store(
        &[pre(
            "Late.Show.S01E01.1080p.WEB-GRP",
            "aB9zQ1mK7pR3tX5w.part01.rar",
        )],
        2000,
    )
    .unwrap();
    let (tried, named) = ix.predb_sweep(50, 2000).unwrap();
    assert_eq!((tried, named), (1, 1));

    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "Late.Show.S01E01.1080p.WEB-GRP");
    assert_eq!(r.kind, "tv");
    // A second sweep must not re-count it - the row is already named.
    assert_eq!(ix.predb_sweep(50, 3000).unwrap().1, 0);
    // ... and the retry floor keeps a just-swept row out of the very
    // next tick, so a quiet feed is not re-asking the same questions
    // three times a minute.
    assert_eq!(ix.predb_sweep(50, 2100).unwrap(), (0, 0));

    // Once the retry window closes on a row whose post never
    // appeared, it retires: the sweep's range scan must not reach it
    // again however long the daemon runs.
    ix.predb_store(
        &[pre("Never.Posted-GRP", "neverPostedStem123.part01.rar")],
        2000,
    )
    .unwrap();
    // Both rows are now past their retry window, so this sweep is
    // the last one either of them gets.
    let long_after = 2000 + 30 * 86_400;
    assert_eq!(
        ix.predb_sweep(50, long_after).unwrap().0,
        2,
        "swept once more"
    );
    assert_eq!(
        ix.predb_sweep(50, long_after + 30 * 86_400).unwrap().0,
        0,
        "and never again"
    );
    teardown(&d, ix);
}

/// A re-ingest of the same articles (every later batch touching the
/// release) must not blank a name the sweep already applied.
#[test]
fn re_ingest_does_not_un_name_a_release() {
    let d = dir("reingest");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let art = over(
        r#""kQ8vN2xL4hT6yW1e.part01.rar" yEnc (1/2)"#,
        "p@x",
        "r1",
        4 << 30,
    );
    ix.ingest("alt.binaries.boneless", std::slice::from_ref(&art), 1000)
        .unwrap();
    ix.predb_store(
        &[pre(
            "Kept.Name.2026.1080p-GRP",
            "kQ8vN2xL4hT6yW1e.part01.rar",
        )],
        1000,
    )
    .unwrap();
    ix.predb_sweep(50, 1000).unwrap();
    assert_eq!(
        ix.search("", 10).unwrap()[0].pre_title,
        "Kept.Name.2026.1080p-GRP"
    );

    // The second part of the same file arrives on a later batch.
    ix.ingest(
        "alt.binaries.boneless",
        &[over(
            r#""kQ8vN2xL4hT6yW1e.part01.rar" yEnc (2/2)"#,
            "p@x",
            "r2",
            4 << 30,
        )],
        2000,
    )
    .unwrap();
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(
        r.pre_title, "Kept.Name.2026.1080p-GRP",
        "the name survived a re-ingest"
    );
    assert!(r.complete);
    teardown(&d, ix);
}

/// The backlog leg: releases indexed long before the feed was on.
/// Only obfuscated-looking rows are considered, and the cursor walks
/// once rather than re-reading the newest rows every tick.
#[test]
fn the_backlog_sweep_walks_once_and_only_touches_junk() {
    let d = dir("backlog");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.boneless",
        &[
            over(
                r#""zX4mB8kP2vQ7nR1t.part01.rar" yEnc (1/1)"#,
                "p@x",
                "b1",
                4 << 30,
            ),
            // A perfectly readable scene name: the feed has a row for
            // it too, but this leg must leave it alone - it is not
            // what the feature is for and re-writing it would be
            // churn on rows that already parse.
            over(
                r#""Readable.Show.S01E01.1080p.WEB.x264-GRP.mkv" yEnc (1/1)"#,
                "p@x",
                "b2",
                4 << 30,
            ),
        ],
        1000,
    )
    .unwrap();
    ix.predb_store(
        &[
            pre(
                "Backlog.Film.2026.2160p.WEB-GRP",
                "zX4mB8kP2vQ7nR1t.part01.rar",
            ),
            pre(
                "Something.Else-GRP",
                "Readable.Show.S01E01.1080p.WEB.x264-GRP.mkv",
            ),
        ],
        2000,
    )
    .unwrap();

    let (tried, named) = ix.predb_backlog(100, 0, 2000).unwrap();
    assert_eq!(
        named, 1,
        "only the obfuscated row was named (tried {tried})"
    );
    let hit = ix.search("Backlog Film", 10).unwrap();
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].stem, "zX4mB8kP2vQ7nR1t");
    let readable = ix.search("Readable Show", 10).unwrap();
    assert_eq!(
        readable[0].pre_title, "",
        "a readable name is left as posted"
    );

    // Cursor reached the floor: the leg is finished and costs
    // nothing from here on.
    assert_eq!(ix.predb_backlog(100, 0, 3000).unwrap(), (0, 0));
    teardown(&d, ix);
}

/// Upsert semantics: a NEW line announces, a later UPD supplies the
/// filename, and neither may blank what the other established.
#[test]
fn an_update_line_fills_the_filename_in() {
    let d = dir("upd");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[PreLine {
            title: "Two.Step.Release-GRP".into(),
            category: "X264".into(),
            ..Default::default()
        }],
        1000,
    )
    .unwrap();
    assert_eq!(
        ix.predb_stats().unwrap(),
        (1, 0),
        "a title alone names nothing"
    );

    ix.predb_store(
        &[PreLine {
            kind: PreKind::Upd,
            title: "Two.Step.Release-GRP".into(),
            filename: "hH3jK9lM1nP5qR7s.part01.rar".into(),
            ..Default::default()
        }],
        2000,
    )
    .unwrap();
    assert_eq!(ix.predb_stats().unwrap(), (1, 1), "one row, now nameable");
    let cat: String = ix
        .db
        .query_row("SELECT category FROM predb", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cat, "X264", "the UPD did not blank what NEW established");

    // A nuke afterwards is sticky and does not cost the filename.
    ix.predb_store(
        &[PreLine {
            kind: PreKind::Nuk,
            title: "Two.Step.Release-GRP".into(),
            nuke_reason: "bad.crc".into(),
            ..Default::default()
        }],
        3000,
    )
    .unwrap();
    let (nuked, fname): (bool, String) = ix
        .db
        .query_row("SELECT nuked, filename FROM predb", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert!(nuked);
    assert_eq!(fname, "hH3jK9lM1nP5qR7s.part01.rar");
    teardown(&d, ix);
}

/// The named counter must not walk the releases table: the settings
/// card polls it, and on a multi-million-row index the full scan
/// took seconds per call. First use builds the partial index and
/// the COUNT must come out of it, not a table scan.
#[test]
fn the_named_count_takes_the_partial_index() {
    let d = dir("namedcount");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.boneless",
        &[over(
            r#""qW4eR6tY8uI0oP2a.part01.rar" yEnc (1/1)"#,
            "p@x",
            "nc1",
            4 << 30,
        )],
        1000,
    )
    .unwrap();
    assert_eq!(ix.predb_named_count().unwrap(), 0);
    // The first call built the index...
    let n: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='index' AND name='idx_rel_pre_named'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "first use builds the partial index");
    // ... and the COUNT actually plans onto it. This is the whole
    // point of the index, so pin the plan, not just the schema.
    let plan: String = ix
        .db
        .query_row(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM releases WHERE pre_title<>''",
            [],
            |r| r.get(3),
        )
        .unwrap();
    assert!(
        plan.contains("idx_rel_pre_named"),
        "COUNT must use the partial index, planned: {plan}"
    );
    // Naming and revoking both move the counter - the partial
    // index is maintained through the UPDATE paths, not just
    // correct at build time.
    ix.predb_store(
        &[pre("Counted.Film.2026-GRP", "qW4eR6tY8uI0oP2a.part01.rar")],
        2000,
    )
    .unwrap();
    ix.predb_sweep(50, 2000).unwrap();
    assert_eq!(ix.predb_named_count().unwrap(), 1);
    let rid = ix.search("", 10).unwrap()[0].id;
    assert!(ix.revoke_pre_name(rid).unwrap());
    assert_eq!(ix.predb_named_count().unwrap(), 0);
    teardown(&d, ix);
}

/// The daemon's API polls the count through a READ-ONLY handle,
/// which cannot create the index - the writer has to have built
/// it. The live shape that caught this: a title-only feed, so
/// nothing is `nameable` and the `predb` flag stays false, yet
/// the settings card still asks for the count.
#[test]
fn the_writer_builds_the_named_index_for_the_read_only_handle() {
    let d = dir("namedro");
    let path = d.join("index.db");
    {
        let mut ix = Index::open(&path).unwrap();
        ix.predb_store(
            &[PreLine {
                title: "Title.Only.Line-GRP".into(),
                ..Default::default()
            }],
            1000,
        )
        .unwrap();
        // Simulate a database written before this index existed.
        ix.db.execute("DROP INDEX idx_rel_pre_named", []).unwrap();
    }
    // The next writer open rebuilds it, because the feed has rows.
    let ix = Index::open(&path).unwrap();
    {
        let ro = Index::open_read_only(&path).unwrap();
        assert_eq!(ro.predb_named_count().unwrap(), 0);
        let n: i64 = ro
            .db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='index' AND name='idx_rel_pre_named'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "the writer's open built the index");
    }
    teardown(&d, ix);
}

/// The separator-insensitive fallback, and the fact that it is a
/// fallback: an exact key never has to go looking.
#[test]
fn the_normalized_key_is_the_fallback() {
    let d = dir("norm");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // The relay wrote the name with underscores, the post used dots.
    ix.predb_store(&[pre("Norm.Test.2026-GRP", "ab_12_cd_34.part01.rar")], 1000)
        .unwrap();
    ix.ingest(
        "alt.binaries.boneless",
        &[over(
            r#""ab-12-cd-34.part01.rar" yEnc (1/1)"#,
            "p@x",
            "n1",
            4 << 30,
        )],
        2000,
    )
    .unwrap();
    assert_eq!(
        ix.search("", 10).unwrap()[0].pre_title,
        "Norm.Test.2026-GRP"
    );
    teardown(&d, ix);
}

/// Pruning: the feed is always-on, so it must be bounded both ways.
#[test]
fn the_feed_is_pruned_by_age_and_by_row_cap() {
    let d = dir("prune");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    for i in 0..10 {
        ix.predb_store(
            &[pre(&format!("R{i}-GRP"), &format!("fn{i}.rar"))],
            1000 + i as i64,
        )
        .unwrap();
    }
    assert_eq!(ix.predb_stats().unwrap().0, 10);
    // Age: everything heard before 1005 goes.
    assert_eq!(ix.predb_prune(0, 100, 1105).unwrap(), 5);
    assert_eq!(ix.predb_stats().unwrap().0, 5);
    // Cap: oldest-heard first, down to 2.
    assert_eq!(ix.predb_prune(2, 0, 2000).unwrap(), 3);
    let left: Vec<String> = ix
        .db
        .prepare("SELECT title FROM predb ORDER BY seen_at")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(left, vec!["R8-GRP".to_string(), "R9-GRP".to_string()]);
    teardown(&d, ix);
}

/// A feed that has never heard anything costs the ingest path
/// nothing at all - the lookup is gated on the table having content.
#[test]
fn an_empty_feed_changes_nothing() {
    let d = dir("empty");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    assert!(!ix.predb, "no rows, no lookups");
    ix.ingest(
        "alt.binaries.boneless",
        &[over(
            r#""qQ1wW2eE3rR4tT5y.part01.rar" yEnc (1/1)"#,
            "p@x",
            "e1",
            4 << 30,
        )],
        1000,
    )
    .unwrap();
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "");
    assert_eq!(r.display_name(), r.stem);
    assert_eq!(ix.predb_sweep(50, 1000).unwrap(), (0, 0));
    assert_eq!(ix.predb_backlog(50, 0, 1000).unwrap(), (0, 0));
    teardown(&d, ix);
}
