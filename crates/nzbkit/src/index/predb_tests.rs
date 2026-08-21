//! The predb + correlation test suite, split out of the old index.rs
//! (its subject lives in predb.rs; inline it would break the 3,000-line
//! file ceiling).

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

// ---- phase 2: correlation ---------------------------------------

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

/// The design's own worked example: pre at t=1000, obfuscated post
/// at t=4600 within 3% of the announced size. Suggest-only stores a
/// suggestion and changes nothing on the release; the auto tier
/// applies it with corr provenance.
#[test]
fn a_sized_fast_pair_suggests_then_auto_applies() {
    let d = dir("corr-auto");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // est_content = 5e9 / 1.03 = 4.854e9; announce 4.9e9 -> ratio
    // 0.9906, the top band. Group and section agree on video.
    ix.predb_store(
        &[tpre(
            "Some.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        1000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""aQ3xY7Bm2ZpK4L.part01.rar" yEnc (1/1)"#,
            "c1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;

    // Suggest-only: the walk stores the candidate, the release
    // itself stays untouched.
    let (examined, suggested, applied) = ix.predb_corr_backlog(100, 0, false, 5000).unwrap();
    assert_eq!((examined, suggested, applied), (1, 1, 0));
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "", "suggest-only must not name anything");
    let hints = ix.pre_hints(&[rid]).unwrap();
    assert_eq!(hints.len(), 1);
    let (hid, hname, hscore, hdelta, _ratio, hstatus) = hints[0].clone();
    assert_eq!(hid, rid);
    assert_eq!(hname, "Some.Film.2026.1080p.WEB.H264-GRP");
    assert_eq!(hdelta, 3600);
    assert_eq!(hscore, 34 + 40 + 10, "T(<=2h) + S(top band) + C");
    assert_eq!(hstatus, "suggested");

    // Auto: the same pair clears every gate (unique, sized, tight,
    // mutual-best, no sibling) and gets applied with provenance
    // that says it was inferred.
    let (_, _, applied) = ix.predb_corr_sweep(100, true, 5000).unwrap();
    assert_eq!(applied, 1);
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "Some.Film.2026.1080p.WEB.H264-GRP");
    assert_eq!(r.pre_source, "predb/corr:PRE");
    assert_eq!(r.display_name(), "Some.Film.2026.1080p.WEB.H264-GRP");
    let hints = ix.pre_hints(&[rid]).unwrap();
    assert_eq!(hints[0].5, "applied");
    teardown(&d, ix);
}

/// The confirm lane's pick: STRONG suggestions only, best first, and
/// a stamp retires a row from the pick forever - one suggestion never
/// costs the user's indexer quota twice.
#[test]
fn the_confirm_pick_takes_strong_unchecked_suggestions_best_first() {
    let d = dir("confirm-pick");
    let ix = Index::open(&d.join("index.db")).unwrap();
    ix.db
        .execute(
            "INSERT INTO predb(title, fnstem, fnkey, pt, seen_at)
             VALUES('A.Strong.One-GRP','','',1000,1000),
                   ('A.Stronger.One-GRP','','',1000,1000),
                   ('A.Weak.One-GRP','','',1000,1000)",
            [],
        )
        .unwrap();
    for (rid, pid, score) in [(11, 1, 85), (12, 2, 95), (13, 3, 79)] {
        ix.db
            .execute(
                "INSERT INTO pre_corr(release_id, predb_id, score, delta, status, at)
                 VALUES(?1, ?2, ?3, 0, 'suggested', 1000)",
                rusqlite::params![rid, pid, score],
            )
            .unwrap();
    }
    let picks = ix.corr_confirm_pick(10).unwrap();
    assert_eq!(
        picks
            .iter()
            .map(|(rid, _, s, _)| (*rid, *s))
            .collect::<Vec<_>>(),
        vec![(12, 95), (11, 85)],
        "STRONG floor holds and the best spends first"
    );
    assert_eq!(picks[0].1, "A.Stronger.One-GRP");
    ix.corr_confirm_stamp(12, 2, 2000).unwrap();
    let picks = ix.corr_confirm_pick(10).unwrap();
    assert_eq!(picks.len(), 1, "a stamped suggestion never re-picks");
    assert_eq!(picks[0].0, 11);
    teardown(&d, ix);
}

/// 2 Aug Opus sweep: the applied status update did not re-assert
/// WHICH pre it applied. A stored suggestion pointing at an earlier,
/// higher-scoring pre survives the refresh upsert (score gate), and
/// the release then wore pre X's title while its 'applied' verdict
/// row named pre Y - so confirms, rejects and revokes all ruled on
/// the wrong pairing. The verdict row must end pointing at the pre
/// whose title was actually applied.
#[test]
fn the_applied_verdict_names_the_pre_that_was_applied() {
    let d = dir("corr-applied-id");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[
            tpre(
                "Some.Film.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            // A decoy in another section entirely: never a candidate
            // for this release, but a valid predb row to point at.
            tpre("Other.Album.2026-GRP", "MP3", 100_000_000, 500),
        ],
        1000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""aQ3xY7Bm2ZpK4L.part01.rar" yEnc (1/1)"#,
            "c1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    let decoy: i64 = ix
        .db
        .query_row(
            "SELECT id FROM predb WHERE title='Other.Album.2026-GRP'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // The stale higher-scoring suggestion: the refresh upsert keeps
    // it (excluded.score >= pre_corr.score fails), exactly the state
    // a drifted re-walk runs in.
    ix.db
        .execute(
            "INSERT INTO pre_corr(release_id, predb_id, score, delta, ratio,
                                  runner_up, status, at)
             VALUES(?1, ?2, 999, 0, 1000, 0, 'suggested', 4700)",
            rusqlite::params![rid, decoy],
        )
        .unwrap();
    let (_, _, applied) = ix.predb_corr_sweep(100, true, 5000).unwrap();
    assert_eq!(applied, 1);
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "Some.Film.2026.1080p.WEB.H264-GRP");
    let (row_pre, status): (String, String) = ix
        .db
        .query_row(
            "SELECT p.title, c.status FROM pre_corr c
              JOIN predb p ON p.id=c.predb_id WHERE c.release_id=?1",
            [rid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "applied");
    assert_eq!(
        row_pre, "Some.Film.2026.1080p.WEB.H264-GRP",
        "the verdict row must name the pre whose title the release wears"
    );
    teardown(&d, ix);
}

/// Two same-size pres of the SAME title (REPACK) in the window: the
/// sibling rule caps at SUGGEST categorically - a human picks
/// REPACK vs original.
#[test]
fn a_repack_sibling_blocks_auto() {
    let d = dir("corr-sibling");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[
            tpre(
                "Some.Show.S01E01.1080p.WEB.H264-GRP",
                "TV-WEB-HD-X264",
                4_900_000_000,
                1000,
            ),
            tpre(
                "Some.Show.S01E01.REPACK.1080p.WEB.H264-GRP",
                "TV-WEB-HD-X264",
                4_910_000_000,
                2000,
            ),
        ],
        2000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""zZ9pQm2LxV4.part01.rar" yEnc (1/1)"#,
            "s1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let (_, suggested, applied) = ix.predb_corr_backlog(100, 0, true, 5000).unwrap();
    assert_eq!(applied, 0, "sibling pres must never auto-apply");
    assert_eq!(suggested, 1);
    assert_eq!(ix.search("", 10).unwrap()[0].pre_title, "");
    teardown(&d, ix);
}

/// Two same-size pres of DIFFERENT titles: crowding. The margin
/// gate fails closed into a suggestion.
#[test]
fn a_crowded_window_blocks_auto() {
    let d = dir("corr-crowd");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[
            tpre(
                "First.Film.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            tpre(
                "Other.Film.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_905_000_000,
                1500,
            ),
        ],
        1500,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""kK4mN8rT2wQ.part01.rar" yEnc (1/1)"#,
            "cr1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let (_, suggested, applied) = ix.predb_corr_backlog(100, 0, true, 5000).unwrap();
    assert_eq!(applied, 0, "a crowded window must never auto-apply");
    assert_eq!(suggested, 1);
    teardown(&d, ix);
}

/// A sizeless pre can suggest but can never auto-apply, whatever
/// else agrees - the arithmetic caps it below STRONG.
#[test]
fn a_sizeless_pre_cannot_auto_apply() {
    let d = dir("corr-sizeless");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // Even with file-count agreement (the best a sizeless pair can
    // do: T40 + C10 + F8 = 58) the ceiling sits under STRONG.
    ix.predb_store(
        &[PreLine {
            files: 1,
            ..tpre("Fast.Film.2026.1080p.WEB.H264-GRP", "X264-HD", 0, 4000)
        }],
        4000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""bB7cD3eF9gH.part01.rar" yEnc (1/1)"#,
            "sz1",
            5_000_000_000,
            4300,
        )],
        5000,
    )
    .unwrap();
    let (_, suggested, applied) = ix.predb_corr_backlog(100, 0, true, 5000).unwrap();
    assert_eq!(applied, 0);
    assert_eq!(suggested, 1, "fast + agreeing still suggests");
    teardown(&d, ix);
}

/// The live rotation: a title-only row is re-asked while its
/// forward window is open and retired once it closes. Seed rows are
/// born retired and never enter the rotation at all.
#[test]
fn corr_rotation_retires_and_seeds_are_born_retired() {
    let d = dir("corr-retire");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(&[tpre("Lone.Pre.2026.1080p-GRP", "X264-HD", 0, 1000)], 1000)
        .unwrap();
    // Inside the window: examined, stamped, not retired.
    let (examined, _, _) = ix.predb_corr_sweep(100, false, 2000).unwrap();
    assert_eq!(examined, 1);
    let tried: i64 = ix
        .db
        .query_row("SELECT tried_at FROM predb", [], |r| r.get(0))
        .unwrap();
    assert_eq!(tried, 2000);
    // Window closed: the next look retires it, and after that the
    // rotation never reaches it again.
    let later = 1000 + 14 * 86_400 + 10;
    assert_eq!(ix.predb_corr_sweep(100, false, later).unwrap().0, 1);
    let tried: i64 = ix
        .db
        .query_row("SELECT tried_at FROM predb", [], |r| r.get(0))
        .unwrap();
    assert_eq!(tried, PREDB_RETIRED);
    assert_eq!(ix.predb_corr_sweep(100, false, later + 700).unwrap().0, 0);

    // A seed row: stored retired, invisible to the rotation.
    let n = ix
        .predb_seed_store(
            &[tpre("Seeded.Film.2026.1080p-GRP", "X264-HD", 1 << 30, 500)],
            "seed:predb.net",
            later,
        )
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(ix.predb_corr_sweep(100, false, later + 1400).unwrap().0, 0);
    // ...and a timestampless seed row is refused outright.
    let n = ix
        .predb_seed_store(
            &[tpre("Undated.Film.2026-GRP", "X264-HD", 1 << 30, 0)],
            "seed:predb.net",
            later,
        )
        .unwrap();
    assert_eq!(n, 0, "a pre with no time can do nothing but collide");
    teardown(&d, ix);
}

/// A batch's "one evaluation per release" skip must be earned by an
/// evaluation, not spent by a pair that never got one.
///
/// Sibling pres in a batch share candidates, so the release is
/// marked seen to stop it paying for a full 4000-row evaluation
/// once per pre. Marking it BEFORE the floor test meant a weak pair
/// - a sizeless pre, which by construction can never reach the auto
/// band - consumed the release, and the tight sized pre behind it
/// (rotation order is `tried_at ASC, id DESC`, so the higher id goes
/// first) skipped straight past a match it would have made.
#[test]
fn a_below_floor_pair_does_not_consume_the_release() {
    let d = dir("corr-starve");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // Stored in one call so both share a batch. The WEAK one is
    // second, so it takes the higher id and is probed first.
    ix.predb_store(
        &[
            tpre(
                "Strong.Film.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            // Sizeless and far back in the window: in range, so it
            // is probed, but it cannot clear the floor.
            tpre("Weak.Other.2026-GRP", "X264-HD", 0, 100),
        ],
        1000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""yY6tR3eW8qA.part01.rar" yEnc (1/1)"#,
            "ov1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    let (_, suggested, _) = ix.predb_corr_sweep(100, false, 5000).unwrap();
    assert_eq!(
        suggested, 1,
        "the strong pre must still reach the release the weak one only looked at"
    );
    let stored: String = ix
        .db
        .query_row(
            "SELECT p.title FROM pre_corr c JOIN predb p ON p.id=c.predb_id
              WHERE c.release_id=?1",
            [rid],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        stored.starts_with("Strong."),
        "the wrong pre won the release: {stored}"
    );
    teardown(&d, ix);
}

/// The corr backlog cursor walks once and stops; a seed import
/// (predb_seed_gen bump) is the one event that re-opens it.
#[test]
fn corr_backlog_walks_once_until_a_seed_lands() {
    let d = dir("corr-cursor");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""mM1nB6vC8xZ.part01.rar" yEnc (1/1)"#,
            "cu1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    assert_eq!(ix.predb_corr_backlog(100, 0, false, 5000).unwrap().0, 1);
    assert_eq!(
        ix.predb_corr_backlog(100, 0, false, 5000).unwrap(),
        (0, 0, 0),
        "the cursor must not re-walk a dry backlog"
    );
    // A seed lands: the importer bumps the generation and the walk
    // runs exactly once more.
    ix.predb_seed_store(
        &[tpre(
            "Late.Seed.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        "seed:predb.net",
        6000,
    )
    .unwrap();
    ix.kv_set("predb_seed_gen", "1").unwrap();
    let (examined, suggested, _) = ix.predb_corr_backlog(100, 0, false, 6000).unwrap();
    assert_eq!(examined, 1);
    assert_eq!(suggested, 1, "the seeded pre now names the backlog row");
    assert_eq!(
        ix.predb_corr_backlog(100, 0, false, 6000).unwrap(),
        (0, 0, 0)
    );
    teardown(&d, ix);
}

/// Revocation: a corr-applied name comes back off cleanly - stem
/// classification returns, the FTS entry disappears, the audit row
/// says revoked. And a rejected suggestion is never re-suggested.
#[test]
fn revoke_undoes_and_reject_never_nags() {
    let d = dir("corr-revoke");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[tpre(
            "Named.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        1000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""rR5tY2uI9oP.part01.rar" yEnc (1/1)"#,
            "rv1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    let (_, _, applied) = ix.predb_corr_backlog(100, 0, true, 5000).unwrap();
    assert_eq!(applied, 1);
    assert_eq!(
        ix.search("Named.Film", 10).unwrap().len(),
        1,
        "found via pre_fts"
    );

    assert!(ix.revoke_pre_name(rid).unwrap());
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "");
    assert_eq!(r.pre_source, "");
    assert!(
        ix.search("Named.Film", 10).unwrap().is_empty(),
        "a revoked name must leave the search index"
    );
    let status: String = ix
        .db
        .query_row(
            "SELECT status FROM pre_corr WHERE release_id=?1",
            [rid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "revoked");

    // Reject it: even though the candidate still scores, the legs
    // must never suggest it again.
    ix.pre_reject(rid, 6000).unwrap();
    ix.kv_set("predb_seed_gen", "2").unwrap(); // force a re-walk
    let (_, suggested, applied) = ix.predb_corr_backlog(100, 0, true, 6000).unwrap();
    assert_eq!((suggested, applied), (0, 0), "a rejected row is settled");
    let status: String = ix
        .db
        .query_row(
            "SELECT status FROM pre_corr WHERE release_id=?1",
            [rid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "rejected", "a rejected row must stay rejected");
    assert_eq!(ix.search("", 10).unwrap()[0].pre_title, "");
    teardown(&d, ix);
}

/// THE seed invariant: a seed row whose TITLE happens to equal a
/// release stem must not exact-match it - seeds are correlation
/// evidence only, and fnkey='' pins them out of every exact leg.
#[test]
fn a_seed_title_never_exact_matches() {
    let d = dir("corr-seedinv");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""Readable.Film.2026.1080p.WEB.H264-GRP.part01.rar" yEnc (1/1)"#,
            "si1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    ix.predb_seed_store(
        &[tpre(
            "Readable.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            0,
            1000,
        )],
        "seed:predb.net",
        5000,
    )
    .unwrap();
    assert_eq!(
        ix.predb_sweep(100, 6000).unwrap(),
        (0, 0),
        "nothing to sweep"
    );
    assert_eq!(
        ix.predb_backlog(100, 0, 6000).unwrap().1,
        0,
        "the exact backlog must not see a seed"
    );
    assert_eq!(ix.search("", 10).unwrap()[0].pre_title, "");
    teardown(&d, ix);
}

/// The catch-up pass: a seed import gets covered by walking the
/// SIZED pres once - including rows born retired - and it names
/// the backlog without the release-driven walk's help. Walks once,
/// parks, and re-opens only on the next seed generation.
#[test]
fn catchup_covers_a_seed_import_once_per_generation() {
    let d = dir("corr-catchup");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""tU8vB3nM6kQz.part01.rar" yEnc (1/1)"#,
            "cu9",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    // The seed lands AFTER the release is indexed - the exact
    // shape the live legs cannot reach.
    ix.predb_seed_store(
        &[tpre(
            "Caught.Up.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        "seed:predb.net",
        6000,
    )
    .unwrap();
    ix.kv_set("predb_seed_gen", "1").unwrap();
    let (n, s, a) = ix.predb_corr_catchup(100, true, 6000).unwrap();
    assert_eq!(n, 1, "the retired seed row is walked");
    assert_eq!((s, a), (0, 1), "and the backlog release is auto-named");
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "Caught.Up.2026.1080p.WEB.H264-GRP");
    assert_eq!(r.pre_source, "predb/corr:seed:predb.net");
    // Parked: later ticks cost nothing.
    assert_eq!(ix.predb_corr_catchup(100, true, 6100).unwrap(), (0, 0, 0));
    // A new generation re-opens the walk exactly once.
    ix.kv_set("predb_seed_gen", "2").unwrap();
    assert_eq!(ix.predb_corr_catchup(100, true, 6200).unwrap().0, 1);
    assert_eq!(ix.predb_corr_catchup(100, true, 6300).unwrap(), (0, 0, 0));
    teardown(&d, ix);
}

/// The banded forward query must not lose a true match at the band
/// edges, and must exclude the wildly-mismatched (which could only
/// waste probe budget - the Rust veto would kill them anyway).
#[test]
fn the_size_band_keeps_the_match_and_drops_the_absurd() {
    let d = dir("corr-band");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // Hidden-par2-heavy true match: wire bytes 1.18x the announce.
    ix.ingest(
        "alt.binaries.x264",
        &[
            overd(
                r#""hH2jK9lP4wX.part01.rar" yEnc (1/1)"#,
                "b1",
                5_900_000_000,
                4600,
            ),
            // A 10x-the-size post in the same window: band-excluded.
            overd(
                r#""gG5fD8sA2qE.part01.rar" yEnc (1/1)"#,
                "b2",
                50_000_000_000,
                4600,
            ),
        ],
        5000,
    )
    .unwrap();
    ix.predb_seed_store(
        &[tpre(
            "Banded.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            5_000_000_000,
            1000,
        )],
        "seed:predb.net",
        5000,
    )
    .unwrap();
    ix.kv_set("predb_seed_gen", "1").unwrap();
    let (_, s, a) = ix.predb_corr_catchup(100, false, 6000).unwrap();
    assert_eq!(
        s + a,
        1,
        "exactly the plausible post is probed and suggested"
    );
    let hits = ix.search("", 10).unwrap();
    let big = hits
        .iter()
        .find(|r| r.total_bytes > 10_000_000_000)
        .unwrap();
    assert!(
        ix.pre_hints(&[big.id]).unwrap().is_empty(),
        "no hint on the absurd one"
    );
    teardown(&d, ix);
}

/// The oracle verdict, both directions: agreement confirms and
/// back-feeds the proven filename (arming the exact legs for a
/// repost); contradiction revokes the applied name and records the
/// rejection.
#[test]
fn an_oracle_settles_a_correlation_both_ways() {
    let d = dir("corr-verdict");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[tpre(
            "Oracle.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        1000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""yY6tR3eW8qA.part01.rar" yEnc (1/1)"#,
            "ov1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    assert_eq!(ix.predb_corr_backlog(100, 0, true, 5000).unwrap().2, 1);

    // srrdb answers the SAME name (different separators, canonical
    // case): confirmed, and the pre row now carries the proven
    // posted filename so a repost exact-matches.
    let v = ix
        .pre_corr_verdict(
            "yY6tR3eW8qA.part01.rar",
            "Oracle.Film.2026.1080p.WEB.h264-GRP",
            6000,
        )
        .unwrap();
    assert_eq!(v, Some(true));
    let (fnstem, tried): (String, i64) = ix
        .db
        .query_row("SELECT fnstem, tried_at FROM predb", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(fnstem, "yy6tr3ew8qa", "the proven pairing is fed back");
    assert_eq!(tried, 0, "and queued for the exact sweep");
    let status: String = ix
        .db
        .query_row(
            "SELECT status FROM pre_corr WHERE release_id=?1",
            [rid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "confirmed");

    // A second, contradicted correlation: the applied name comes
    // off and the rejection is recorded.
    let d2 = dir("corr-verdict2");
    let mut ix2 = Index::open(&d2.join("index.db")).unwrap();
    ix2.predb_store(
        &[tpre(
            "Wrong.Guess.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        1000,
    )
    .unwrap();
    ix2.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""zX9cV4bN7mK.part01.rar" yEnc (1/1)"#,
            "ov2",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid2 = ix2.search("", 10).unwrap()[0].id;
    assert_eq!(ix2.predb_corr_backlog(100, 0, true, 5000).unwrap().2, 1);
    let v = ix2
        .pre_corr_verdict(
            "zX9cV4bN7mK.part01.rar",
            "Actually.Other.Film.2026.1080p.WEB.H264-GRP",
            6000,
        )
        .unwrap();
    assert_eq!(v, Some(false));
    let r = &ix2.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "", "the wrong name is gone");
    let status: String = ix2
        .db
        .query_row(
            "SELECT status FROM pre_corr WHERE release_id=?1",
            [rid2],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "rejected");
    // A release with no correlation involvement answers None.
    assert_eq!(
        ix2.pre_corr_verdict("no.such.post.rar", "X-GRP", 6000)
            .unwrap(),
        None
    );
    teardown(&d, ix);
    teardown(&d2, ix2);
}

/// The split-set merge, end to end: legacy fragment rows (indexed
/// before release_stem knew the split shapes) fold into one
/// release with the true size, search follows the stem rewrite,
/// and the re-opened catch-up walk then names the merged set from
/// a seeded pre - the Supergirl acceptance shape.
#[test]
fn split_fragments_merge_and_then_correlate() {
    let d = dir("split-merge");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // Three legacy fragments, the shape old ingest produced: one
    // row per volume, stems still carrying the digit tails.
    for (i, (part, bytes)) in [
        ("008", 2_000_000_000i64),
        ("010", 2_000_000_000),
        ("011", 1_000_000_000),
    ]
    .iter()
    .enumerate()
    {
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                      has_par2, first_posted, first_seen, kind, junk)
                 VALUES(?1, 'p@x', 'alt.binaries.x264', ?2, 1, 1, 0, ?3, 5000,
                        'other', 75)",
                rusqlite::params![format!("aQzXcV7Bn.7z.{part}"), bytes, 4600 + i as i64],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes)
                 VALUES(?1, ?2, 1, ?3)",
                rusqlite::params![rid, format!("aQzXcV7Bn.7z.{part}"), bytes],
            )
            .unwrap();
    }
    assert_eq!(ix.search("aQzXcV7Bn", 10).unwrap().len(), 3, "fragmented");

    let (groups, folded, done) = ix.split_merge(6000, WALK).unwrap();
    assert_eq!((groups, folded), (1, 2));
    assert!(done, "one stride covers a small table");
    let hits = ix.search("aQzXcV7Bn", 10).unwrap();
    assert_eq!(
        hits.len(),
        1,
        "one release now, found via the rewritten stem"
    );
    let r = &hits[0];
    assert_eq!(r.stem, "aQzXcV7Bn.7z");
    assert_eq!(r.total_bytes, 5_000_000_000);
    assert_eq!(r.files, 3);
    assert_eq!(r.first_posted, 4600, "earliest fragment's clock");
    // Parked: the next call is a kv read and nothing else.
    assert_eq!(ix.split_merge(6100, WALK).unwrap(), (0, 0, true));

    // The completion bumped the seed generation, so the catch-up
    // re-walks - and the merged size now matches a seeded pre that
    // no half-GB fragment ever could.
    ix.predb_seed_store(
        &[tpre(
            "Whole.Set.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        "seed:predb.net",
        6000,
    )
    .unwrap();
    let (_, s2, a2) = ix.predb_corr_catchup(100, true, 6200).unwrap();
    assert_eq!(a2 + s2, 1, "the merged set correlates");
    assert_eq!(a2, 1, "and tightly enough to auto-apply");
    let r = &ix.search("Whole.Set", 10).unwrap()[0];
    assert_eq!(r.pre_title, "Whole.Set.2026.1080p.WEB.H264-GRP");
    teardown(&d, ix);
}

/// The shatter fold, end to end through REAL ingest: one file posted
/// under a stable blob name with a randomized poster per article and
/// the group rotated per article (the shape that holds 97% of the
/// live dark band, 13 Aug 2026 census) collapses into one release
/// with the unioned segment list, true size and honest completeness.
/// A duplicate part under yet another poster folds in without
/// double-counting.
#[test]
fn a_shattered_posting_folds_across_posters_and_groups() {
    let d = dir("shatter-fold");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // The wire truth this reproduces, seen live:
    //   [037/209] - "3f2acf....par2" yEnc (2/2745) 1967195216
    let subj = |p: u32| {
        format!(r#"[001/003] - "e3b0c44298fc1c149afbf4c8996fb924.par2" yEnc ({p}/6) 4200000"#)
    };
    let groups = [
        "alt.binaries.movies",
        "alt.binaries.tv",
        "alt.binaries.x264",
    ];
    for p in 1u32..=6 {
        let grp = groups[(p as usize - 1) % 3];
        ix.ingest(
            grp,
            &[over(
                &subj(p),
                &format!("r{p}@h{p}.tld"),
                &format!("m{p}"),
                700_000,
            )],
            5_000 + p as i64,
        )
        .unwrap();
    }
    // A repost of part 3 under a seventh poster: same stem, same
    // total, duplicate part number.
    ix.ingest(
        "alt.binaries.tv",
        &[over(&subj(3), "r7@h7.tld", "m3dup", 700_000)],
        5_010,
    )
    .unwrap();
    let rows: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 7, "the shattered shape really was built");

    let (groups_folded, folded, done) = ix.shatter_fold(6_000, WALK).unwrap();
    assert_eq!((groups_folded, folded), (1, 6));
    assert!(done, "one stride covers a small table");
    let (rows, nsegs, need, complete, total, fp): (i64, i64, i64, bool, i64, i64) = ix
        .db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM releases), f.nsegs, r.need_parts,
                    r.complete, r.total_bytes, r.first_posted
               FROM releases r JOIN files f ON f.release_id=r.id",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(rows, 1, "one posting now");
    assert_eq!(
        nsegs, 6,
        "six distinct parts, the duplicate not double-counted"
    );
    assert_eq!(need, 6);
    assert!(complete, "6/6 parts is complete");
    assert_eq!(total, 6 * 700_000, "size is the union, not one article");
    assert!(fp > 0);
    // Idempotent and parked: the next call re-clamps to the surviving
    // top and finds nothing.
    assert_eq!(ix.shatter_fold(6_100, WALK).unwrap(), (0, 0, true));
    // The session tag rode ingest ("[001/003]") and survived the fold.
    let (si, st): (i64, i64) = ix
        .db
        .query_row("SELECT sess_idx, sess_total FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((si, st), (1, 3), "file 1 of a 3-file posting session");
    teardown(&d, ix);
}

/// The lifetime counters postdate the fold itself (they arrived after
/// v1.1.1, which already shipped the fold and its lap marker), so a
/// database upgraded across that release holds merged rows nothing
/// ever counted. Its census must read as partial instead of a
/// confident zero - and must KEEP reading partial once new folds start
/// writing the counters, because the pre-upgrade total is gone for
/// good. A fresh database, by contrast, really is at zero.
#[test]
fn a_pre_counter_database_census_reads_partial_never_zero() {
    let d = dir("shatter-fold-census");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // Fresh database: no lap marker, no counters - zero is the truth.
    let s = ix.shatter_fold_stats();
    assert_eq!(s["lifetime_known"], true, "a fresh database's zero is real");
    assert_eq!(s["rows_folded"], 0);
    // The v1.1.1 shape: a completed lap, no counter keys.
    ix.kv_set("shatter_fold_lap_v1", "1").unwrap();
    let s = ix.shatter_fold_stats();
    assert_eq!(
        s["lifetime_known"], false,
        "a lap without counters is a pre-counter database"
    );
    assert_eq!(
        s["rows_folded"], 0,
        "the count itself stays honestly at what was counted"
    );
    // The first counted fold writes the counter keys; the partial fact
    // must survive that, or the since-upgrade total would promote
    // itself to a lifetime number.
    let subj = |p: u32| {
        format!(r#"[001/003] - "e3b0c44298fc1c149afbf4c8996fb924.par2" yEnc ({p}/6) 4200000"#)
    };
    for p in 1u32..=6 {
        ix.ingest(
            "alt.binaries.movies",
            &[over(
                &subj(p),
                &format!("r{p}@h{p}.tld"),
                &format!("m{p}"),
                700_000,
            )],
            5_000 + p as i64,
        )
        .unwrap();
    }
    let (_groups, folded, _done) = ix.shatter_fold(6_000, WALK).unwrap();
    assert!(folded > 0, "the fixture really folded");
    let s = ix.shatter_fold_stats();
    assert_eq!(s["rows_folded"], folded as u64);
    assert_eq!(
        s["lifetime_known"], false,
        "counters exist now, but the census stays since-upgrade"
    );
    teardown(&d, ix);
}

/// A first lap completed by counter-aware code has counted every merge
/// it made, so its zero is materialized as real counter keys: a new
/// database that swept and found nothing to fold reads as a true zero,
/// never as "lifetime unknown".
#[test]
fn an_empty_first_lap_reads_as_a_real_zero() {
    let d = dir("shatter-fold-empty-lap");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // One perfectly ordinary named post: nothing shattered, nothing to
    // fold, but the lap has real rows to walk.
    ix.ingest(
        "alt.binaries.movies",
        &[over(
            r#"[001/001] - "Whole.Set.2026.1080p.WEB.H264-GRP.par2" yEnc (1/1) 4200"#,
            "p@h.tld",
            "mid1",
            4_200,
        )],
        5_000,
    )
    .unwrap();
    let (groups, folded, done) = ix.shatter_fold(6_000, WALK).unwrap();
    assert_eq!((groups, folded), (0, 0));
    assert!(done);
    let s = ix.shatter_fold_stats();
    assert_eq!(s["first_lap_done"], true);
    assert_eq!(
        s["lifetime_known"], true,
        "a lap completed under counting code proves its own zero"
    );
    assert_eq!(s["rows_folded"], 0);
    teardown(&d, ix);
}

/// The session tag parses only the real thing: a leading digit-only
/// pair, in either bracket style, never a hex repost tag, a bare year,
/// an inverted pair, or the trailing yEnc part counter.
#[test]
fn the_session_tag_parses_narrowly() {
    use super::ingest::session_tag;
    assert_eq!(
        session_tag(r#"[037/209] - "x.par2" yEnc (2/2745) 196719"#),
        Some((37, 209))
    );
    assert_eq!(session_tag(r#"(3/9) - "x.rar" yEnc (1/5)"#), Some((3, 9)));
    assert_eq!(session_tag(r#"[a1911f7bca]_[newzNZB]_"x.rar""#), None);
    assert_eq!(session_tag(r#"[2026] - "x.rar" yEnc (1/5)"#), None);
    assert_eq!(session_tag(r#"[209/37] - "x.rar""#), None, "inverted");
    assert_eq!(session_tag(r#""x.rar" yEnc (1/5)"#), None, "no leading tag");
    assert_eq!(session_tag(r#"[0/5] - "x.rar""#), None, "zero index");
}

/// The two gates that keep the fold from ever bridging unrelated
/// posts: a readable stem never folds even at junk>=70, and a short
/// generic token ("1917") is excluded before the verdict is even
/// asked. Both posters' rows survive untouched.
#[test]
fn readable_or_short_stems_never_shatter_fold() {
    let d = dir("shatter-gates");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    for (i, name) in [
        "Some.Movie.2026.1080p.WEB.H264-GRP.mkv",
        "Some.Movie.2026.1080p.WEB.H264-GRP.mkv",
        "1917",
        "1917",
    ]
    .iter()
    .enumerate()
    {
        ix.ingest(
            "alt.binaries.movies",
            &[over(
                &format!(r#""{name}" yEnc ({}/2)"#, (i % 2) + 1),
                &format!("p{i}@h.tld"),
                &format!("g{i}"),
                1_000,
            )],
            5_000,
        )
        .unwrap();
    }
    // Force the readable rows into the fold's junk band so ONLY the
    // stem verdict stands between them and a wrong merge.
    ix.db.execute("UPDATE releases SET junk=75", []).unwrap();
    let before: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    let (g, n, _) = ix.shatter_fold(6_000, WALK).unwrap();
    assert_eq!((g, n), (0, 0), "nothing folded");
    let after: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
    teardown(&d, ix);
}

/// Disagreeing subject totals mean two postings reusing one stem: the
/// fold takes the largest agreeing class and leaves the minority
/// alone, so two part universes can never union into one "complete"
/// download that extracts to garbage (the ingest D3 hazard, held at
/// the fold too).
#[test]
fn disagreeing_part_totals_split_the_shatter_fold() {
    let d = dir("shatter-classes");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let subj =
        |p: u32, of: u32| format!(r#""b5bb9d8014a0f9b1d61e21e796d78dcc.par2" yEnc ({p}/{of})"#);
    for p in 1u32..=3 {
        ix.ingest(
            "alt.binaries.tv",
            &[over(
                &subj(p, 6),
                &format!("a{p}@x.tld"),
                &format!("s{p}"),
                100,
            )],
            5_000,
        )
        .unwrap();
    }
    for p in 1u32..=2 {
        ix.ingest(
            "alt.binaries.tv",
            &[over(
                &subj(p, 4),
                &format!("b{p}@y.tld"),
                &format!("t{p}"),
                100,
            )],
            5_001,
        )
        .unwrap();
    }
    let (g, n, _) = ix.shatter_fold(6_000, WALK).unwrap();
    assert_eq!((g, n), (1, 2), "only the 3-member class folded");
    let (rows, folded_need): (i64, i64) = ix
        .db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM releases),
                    (SELECT need_parts FROM releases r JOIN files f
                      ON f.release_id=r.id WHERE f.nsegs=3)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, 3, "folded class + the untouched 2-row minority");
    assert_eq!(folded_need, 6);
    teardown(&d, ix);
}

/// A group already wearing a fed name is not merged - extending a
/// name to bytes it never covered is exactly the wrong-name shape.
#[test]
fn a_named_fragment_blocks_its_groups_merge() {
    let d = dir("split-named");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    for (part, title) in [("001", "Somebody.Named.This-GRP"), ("002", "")] {
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                      has_par2, first_posted, first_seen, kind, junk,
                                      pre_title, pre_source)
                 VALUES(?1, 'p@x', 'alt.binaries.x264', 1000000, 1, 1, 0, 4600, 5000,
                        'other', 75, ?2, CASE WHEN ?2='' THEN '' ELSE 'predb' END)",
                rusqlite::params![format!("zZqWvU5Mk.7z.{part}"), title],
            )
            .unwrap();
    }
    let (groups, folded, _) = ix.split_merge(6000, WALK).unwrap();
    assert_eq!((groups, folded), (0, 0), "a named member freezes the group");
    assert_eq!(
        ix.db
            .query_row(
                "SELECT COUNT(*) FROM releases WHERE stem LIKE 'zZqWvU5Mk%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
    teardown(&d, ix);
}

/// Codex sweep 10 Aug M6: a fold moves the fragments' FILES onto the
/// kept row, so it has to move their message-id identity too. The
/// `rel_identity_ad` delete trigger drops `msgid_map` for every source
/// release, and without an explicit remap the fold silently destroys
/// the §131 substrate: a posted NZB carrying those exact articles would
/// stop resolving to the release that still holds them.
#[test]
fn a_split_fold_carries_every_fragments_message_ids() {
    let d = dir("split-merge-msgid");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let mut ids: Vec<Vec<String>> = Vec::new();
    for (i, part) in ["008", "010", "011"].iter().enumerate() {
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                      has_par2, first_posted, first_seen, kind, junk)
                 VALUES(?1, 'p@x', 'alt.binaries.x264', 1000000, 1, 1, 0, ?2, 5000,
                        'other', 75)",
                rusqlite::params![format!("mSg7XrT4q.7z.{part}"), 4600 + i as i64],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes)
                 VALUES(?1, ?2, 1, 1000000)",
                rusqlite::params![rid, format!("mSg7XrT4q.7z.{part}")],
            )
            .unwrap();
        // Three keys per file, the substrate's own bound - a quorum
        // caller can never ask for more than the row holds.
        let mine: Vec<String> = (0..3).map(|s| format!("frag{part}-{s}@news")).collect();
        claims::msgid_map_insert(&ix.db, rid, mine.iter().map(|s| s.as_str())).unwrap();
        ids.push(mine);
    }
    let (groups, folded, _) = ix.split_merge(6000, WALK).unwrap();
    assert_eq!((groups, folded), (1, 2));
    let kept = ix.search("mSg7XrT4q", 10).unwrap();
    assert_eq!(kept.len(), 1);
    let kept = kept[0].id;
    for (part, mine) in ["008", "010", "011"].iter().zip(&ids) {
        // The NZB form (no angle brackets) on purpose: the map is
        // bracket-normalized, and a fold must not change that either.
        let hits = ix.find_releases_by_msgids(mine).unwrap();
        assert_eq!(
            hits,
            vec![(kept, 3)],
            "fragment {part}'s articles lost their release"
        );
    }
    teardown(&d, ix);
}

/// The same for the par2-sidecar fold: the twin's par2 volumes are
/// still indexed under the container, so the ids that name them must
/// still resolve - a PAR2 sidecar is exactly the object the pesto rung
/// looks up by message-id.
#[test]
fn a_par2_sidecar_fold_carries_the_twins_message_ids() {
    let d = dir("sidecar-fold-msgid");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let cid = sidecar_row(&ix, "wKb51NpZ8.7z", 75, 4700, 3, 1_000_000_000, |i| {
        format!("wKb51NpZ8.7z.{:03}", i + 1)
    });
    let tid = sidecar_row(&ix, "wKb51NpZ8", 75, 4650, 2, 100_000_000, |i| {
        format!("wKb51NpZ8.vol{i:02}+02.par2")
    });
    let twin: Vec<String> = (0..3).map(|s| format!("<par2-{s}@news>")).collect();
    let cont: Vec<String> = (0..3).map(|s| format!("<cont-{s}@news>")).collect();
    claims::msgid_map_insert(&ix.db, tid, twin.iter().map(|s| s.as_str())).unwrap();
    claims::msgid_map_insert(&ix.db, cid, cont.iter().map(|s| s.as_str())).unwrap();
    assert!(ix.split_merge(6000, WALK).unwrap().2);
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (1, 2, true));
    assert_eq!(
        ix.find_releases_by_msgids(&twin).unwrap(),
        vec![(cid, 3)],
        "the twin's par2 articles lost their release"
    );
    assert_eq!(
        ix.find_releases_by_msgids(&cont).unwrap(),
        vec![(cid, 3)],
        "the container's own ids are untouched"
    );
    teardown(&d, ix);
}

/// Insert one release row with `nfiles` files of `each` bytes,
/// named by `namer(i)`. Returns the release id.
fn sidecar_row(
    ix: &Index,
    stem: &str,
    junk: i64,
    first_posted: i64,
    nfiles: usize,
    each: i64,
    namer: impl Fn(usize) -> String,
) -> i64 {
    ix.db
        .execute(
            "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                  has_par2, first_posted, first_seen, kind, junk)
             VALUES(?1, 'p@x', 'alt.binaries.x264', ?2, ?3, 1, 0, ?4, 5000, 'other', ?5)",
            rusqlite::params![
                stem,
                each * nfiles as i64,
                nfiles as i64,
                first_posted,
                junk
            ],
        )
        .unwrap();
    let rid = ix.db.last_insert_rowid();
    for i in 0..nfiles {
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes)
                 VALUES(?1, ?2, 1, ?3)",
                rusqlite::params![rid, namer(i), each],
            )
            .unwrap();
    }
    rid
}

/// The par2-sidecar fold, both halves present: the par2-only twin
/// row disappears into its container, which gains the files, the
/// bytes, the earlier post date and a TRUE has_par2 - the flag
/// that closes the hidden-par2 scoring band for it. Stale
/// correlation rows on either half die with the fold.
#[test]
fn par2_sidecar_folds_into_its_container() {
    let d = dir("sidecar-fold");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let cid = sidecar_row(&ix, "qXv93KpL2.7z", 75, 4700, 3, 1_000_000_000, |i| {
        format!("qXv93KpL2.7z.{:03}", i + 1)
    });
    let tid = sidecar_row(&ix, "qXv93KpL2", 75, 4650, 2, 100_000_000, |i| {
        format!("qXv93KpL2.vol{i:02}+02.par2")
    });
    for rid in [cid, tid] {
        ix.db
            .execute(
                "INSERT INTO pre_corr(release_id, predb_id, score, delta, at)
                 VALUES(?1, 9, 85, 60, 5100)",
                [rid],
            )
            .unwrap();
    }
    // The fold waits for split_merge (its containers may not exist
    // before that walk finishes)...
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (0, 0, false));
    assert!(ix.split_merge(6000, WALK).unwrap().2);
    // ...then folds the pair in one stride.
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (1, 2, true));
    let hits = ix.search("qXv93KpL2", 10).unwrap();
    assert_eq!(hits.len(), 1, "the twin row is gone, from FTS too");
    let r = &hits[0];
    assert_eq!(r.stem, "qXv93KpL2.7z", "the container stem is kept");
    assert!(r.has_par2, "the sidecar's par2 now counts as identified");
    assert_eq!(r.total_bytes, 3_200_000_000);
    assert_eq!(r.files, 5);
    assert_eq!(r.first_posted, 4650, "the earlier half's clock");
    let corr: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM pre_corr", [], |r| r.get(0))
        .unwrap();
    assert_eq!(corr, 0, "both halves' stale correlation rows died");
    // Parked: the next call is two kv reads and a MAX(id).
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (0, 0, true));
    teardown(&d, ix);
}

/// Codex sweep 3 Aug M3: folding deletes the bare twin row, and
/// when that twin held the table's MAXIMUM id, SQLite hands the
/// same id to the next insert. A cursor parked on the deleted id
/// with a strictly-greater scan would never visit the recreated
/// row - the cursor must come to rest on the surviving top.
#[test]
fn a_recreated_twin_at_the_deleted_maximum_id_still_folds() {
    let d = dir("sidecar-fold-reuse");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let cid = sidecar_row(&ix, "zRq77TbN5.7z", 75, 4700, 3, 1_000_000_000, |i| {
        format!("zRq77TbN5.7z.{:03}", i + 1)
    });
    let tid = sidecar_row(&ix, "zRq77TbN5", 75, 4650, 2, 100_000_000, |i| {
        format!("zRq77TbN5.vol{i:02}+02.par2")
    });
    assert!(tid > cid, "the twin must be the maximum for this test");
    assert!(ix.split_merge(6000, WALK).unwrap().2);
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap().0, 1, "first fold");
    let cursor: i64 = ix.kv_get("par2_fold_cursor").unwrap().parse().unwrap();
    assert!(
        cursor < tid,
        "cursor parked on the deleted maximum id {tid}: {cursor}"
    );
    // A late article from the still-uploading recovery twin
    // recreates the row - at exactly the reused maximum id.
    let tid2 = sidecar_row(&ix, "zRq77TbN5", 75, 4800, 1, 50_000_000, |_| {
        "zRq77TbN5.vol07+08.par2".into()
    });
    assert_eq!(tid2, tid, "SQLite reuses the deleted maximum id");
    let (pairs, _, done) = ix.par2_sidecar_fold(WALK).unwrap();
    assert!(done);
    assert_eq!(pairs, 1, "the recreated twin at the reused id folds");
    assert!(
        ix.search("zRq77TbN5", 10)
            .unwrap()
            .iter()
            .all(|r| r.stem == "zRq77TbN5.7z"),
        "no bare twin row survives"
    );
    teardown(&d, ix);
}

/// Codex sweep 3 Aug M2: predb pruning must not leave dangling
/// pre_corr identities - an orphaned SUGGESTED row starves every
/// future lower-scoring valid candidate (the upsert takes only
/// >= scores), and a dangling reference in a settled row can
/// rebind to an unrelated pre once SQLite reuses the rowid.
#[test]
fn pruning_a_pre_releases_its_correlation_identity() {
    let d = dir("prune-precorr");
    let ix = Index::open(&d.join("index.db")).unwrap();
    ix.db
        .execute(
            "INSERT INTO predb(id, title, seen_at) VALUES
               (1, 'Old.Release-GRP', 100), (2, 'Live.Release-GRP', 9000)",
            [],
        )
        .unwrap();
    ix.db
        .execute(
            "INSERT INTO pre_corr(release_id, predb_id, score, delta, status, at) VALUES
               (10, 1, 90, 60, 'suggested', 100),
               (11, 1, 88, 60, 'rejected', 100),
               (12, 2, 70, 60, 'suggested', 100)",
            [],
        )
        .unwrap();
    // Age-prune: cutoff at seen_at < 5000 takes pre 1, keeps pre 2.
    assert_eq!(ix.predb_prune(0, 1000, 6000).unwrap(), 1);
    // The orphaned suggestion is gone - a fresh score-85 candidate
    // for release 10 must not be starved by a ghost score-90...
    let suggested: Vec<(i64, i64)> = ix
        .db
        .prepare("SELECT release_id, predb_id FROM pre_corr WHERE status='suggested'")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        suggested,
        vec![(12, 2)],
        "only the live pre's suggestion survives"
    );
    // ...and the settled audit row keeps its verdict but drops the
    // reference, so a reused rowid can never rebind or be back-fed.
    let (pid, status): (i64, String) = ix
        .db
        .query_row(
            "SELECT predb_id, status FROM pre_corr WHERE release_id=11",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((pid, status.as_str()), (0, "rejected"));
    teardown(&d, ix);
}

/// Codex sweep 2, 3 Aug M5: the orphan repair used to run only when
/// the SAME call had just deleted a pre. A store that already holds
/// dangling rows - left by a crash between the delete and the
/// repair, or by the pre-transaction version failing partway - then
/// healed only if some later prune happened to delete something,
/// and a store inside its retention window with a steady row count
/// never deletes anything again. So the repair has to be
/// unconditional, and this seeds exactly that state: dangling rows,
/// nothing to prune.
#[test]
fn a_prune_that_deletes_nothing_still_heals_dangling_identities() {
    let d = dir("prune-selfheal");
    let ix = Index::open(&d.join("index.db")).unwrap();
    // One live pre, well inside any retention window.
    ix.db
        .execute(
            "INSERT INTO predb(id, title, seen_at) VALUES (7, 'Live.Release-GRP', 9000)",
            [],
        )
        .unwrap();
    // The wreckage: both rows point at pre 4, which does not exist.
    ix.db
        .execute(
            "INSERT INTO pre_corr(release_id, predb_id, score, delta, status, at) VALUES
               (20, 4, 95, 60, 'suggested', 100),
               (21, 4, 88, 60, 'confirmed', 100),
               (22, 7, 70, 60, 'suggested', 100)",
            [],
        )
        .unwrap();
    // Nothing is old enough and the cap is not reached, so this
    // prune deletes zero rows - the exact call that used to skip
    // the repair.
    assert_eq!(ix.predb_prune(1000, 1000, 9500).unwrap(), 0);

    let suggested: Vec<(i64, i64)> = ix
        .db
        .prepare("SELECT release_id, predb_id FROM pre_corr WHERE status='suggested'")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        suggested,
        vec![(22, 7)],
        "the orphaned suggestion is gone and the live one is untouched"
    );
    let (pid, status): (i64, String) = ix
        .db
        .query_row(
            "SELECT predb_id, status FROM pre_corr WHERE release_id=21",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (pid, status.as_str()),
        (0, "confirmed"),
        "the settled row keeps its verdict and drops the reference"
    );
    teardown(&d, ix);
}

/// The two refusals: a twin with any non-par2 content is a real
/// release sharing the base name, and a fed name on either half
/// freezes the pair - extending a name to bytes it never covered
/// is exactly the wrong-name shape.
#[test]
fn an_impure_or_named_twin_blocks_the_sidecar_fold() {
    let d = dir("sidecar-blocked");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // Pair 1: the twin has a content file among the par2s.
    sidecar_row(&ix, "aWk40RzQ7.7z", 75, 4700, 2, 1_000_000_000, |i| {
        format!("aWk40RzQ7.7z.{:03}", i + 1)
    });
    sidecar_row(&ix, "aWk40RzQ7", 75, 4650, 2, 100_000_000, |i| {
        if i == 0 {
            "aWk40RzQ7.nfo".into()
        } else {
            "aWk40RzQ7.vol01+02.par2".into()
        }
    });
    // Pair 2: the container already wears a fed name.
    let named = sidecar_row(&ix, "bTn81LmX4.7z", 75, 4700, 2, 1_000_000_000, |i| {
        format!("bTn81LmX4.7z.{:03}", i + 1)
    });
    ix.db
        .execute(
            "UPDATE releases SET pre_title='Somebody.Named.This-GRP', pre_source='predb'
              WHERE id=?1",
            [named],
        )
        .unwrap();
    sidecar_row(&ix, "bTn81LmX4", 75, 4650, 1, 100_000_000, |_| {
        "bTn81LmX4.vol01+02.par2".into()
    });
    assert!(ix.split_merge(6000, WALK).unwrap().2);
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (0, 0, true));
    let n: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 4, "all four rows survive untouched");
    teardown(&d, ix);
}

/// The rolling walk's reverse arm: the container's stride passes
/// before its twin exists (ingest produces new pairs forever, and
/// article order guarantees nothing). When the twin lands the walk
/// meets it twin-first and still finds the container behind it.
#[test]
fn a_late_twin_still_folds_after_the_walk_parked() {
    let d = dir("sidecar-late");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    assert!(ix.split_merge(6000, WALK).unwrap().2);
    sidecar_row(&ix, "zRq57TvB9.7z", 75, 4700, 2, 1_000_000_000, |i| {
        format!("zRq57TvB9.7z.{:03}", i + 1)
    });
    // The walk parks at the top id with the container unpaired.
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (0, 0, true));
    // The twin arrives above the parked cursor.
    sidecar_row(&ix, "zRq57TvB9", 75, 4650, 1, 100_000_000, |_| {
        "zRq57TvB9.vol03+04.par2".into()
    });
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (1, 1, true));
    let r = &ix.search("zRq57TvB9", 10).unwrap()[0];
    assert_eq!(r.stem, "zRq57TvB9.7z");
    assert!(r.has_par2);
    assert_eq!(r.files, 3);
    teardown(&d, ix);
}

/// pre_assign is the human path: no gates, but full provenance.
#[test]
fn manual_assign_carries_manual_provenance() {
    let d = dir("corr-assign");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_seed_store(
        &[tpre(
            "Picked.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            0,
            1000,
        )],
        "seed:predb.net",
        5000,
    )
    .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""qA2sD4fG6hJ.part01.rar" yEnc (1/1)"#,
            "ma1",
            5_000_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    let pid: i64 = ix
        .db
        .query_row("SELECT id FROM predb", [], |r| r.get(0))
        .unwrap();
    assert!(ix.pre_assign(rid, pid, 6000).unwrap());
    let r = &ix.search("", 10).unwrap()[0];
    assert_eq!(r.pre_title, "Picked.Film.2026.1080p.WEB.H264-GRP");
    assert_eq!(r.pre_source, "predb/manual+corr:seed:predb.net");
    teardown(&d, ix);
}

// ---- suggest-only hardening (red-team 10 Aug 2026) ---------------

/// The naming population gate, negative half: a junk>=70 stem that a
/// human can READ ("misfits-wegedeutschensd" parses as nothing, but it
/// is words) is not obfuscated, and correlation must not guess a name
/// over it - suggestions included.
#[test]
fn the_naming_population_requires_semantic_obfuscation() {
    let d = dir("corr-pop-semantic");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[tpre(
            "Some.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )],
        1000,
    )
    .unwrap();
    // Inserted with the junk score pinned at 75: how a readable stem
    // ENDS UP at junk>=70 is the scorer's business (R6 found real
    // ones); the property under test is that the gate does not trust
    // junk alone.
    ix.db
        .execute(
            "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                  has_par2, first_posted, first_seen, kind, junk)
             VALUES('misfits-wegedeutschensd', 'p@x', 'alt.binaries.x264',
                    5_000_000_000, 1, 1, 0, 4600, 4600, 'other', 75)",
            [],
        )
        .unwrap();
    let (examined, suggested, applied) = ix.predb_corr_backlog(100, 0, true, 5000).unwrap();
    assert_eq!(
        (examined, suggested, applied),
        (1, 0, 0),
        "a readable stem must be walked but never suggested for"
    );
    let n: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM pre_corr", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
    teardown(&d, ix);
}

/// The naming population gate, byte-probe half: shapes whose EXACT
/// name a ~1-article probe reads in-band (single-`.7z`, identified
/// PAR2, the Pesto Message-ID grammar) are excluded from correlation
/// naming entirely; a control row of the plain single-RAR shape still
/// gets its suggestion.
#[test]
fn the_naming_population_excludes_byte_probe_nameable_shapes() {
    let d = dir("corr-pop-probe");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    // Four windows, 20 days apart, one sized pre each.
    for (i, title) in [
        "Control.Film.2026.1080p.WEB.H264-GRP",
        "Sevenz.Film.2026.1080p.WEB.H264-GRP",
        "Partwo.Film.2026.1080p.WEB.H264-GRP",
        "Pesto.Film.2026.1080p.WEB.H264-GRP",
    ]
    .iter()
    .enumerate()
    {
        ix.predb_store(
            &[tpre(
                title,
                "X264-HD",
                4_900_000_000,
                1000 + i as i64 * 1_728_000,
            )],
            1000,
        )
        .unwrap();
    }
    let t = |i: i64| 4600 + i * 1_728_000;
    // Control: single RAR, plain message-id.
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""aQ3xY7Bm2ZpK4L.part01.rar" yEnc (1/1)"#,
            "c1",
            5_000_000_000,
            t(0),
        )],
        t(0),
    )
    .unwrap();
    // The B3 shape: one file, a 7z archive - its own header names it.
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""qQ7wE2rT9uI3oP.7z" yEnc (1/1)"#,
            "c2",
            5_000_000_000,
            t(1),
        )],
        t(1),
    )
    .unwrap();
    // Identified PAR2 alongside: FileDesc carries the real filenames.
    ix.ingest(
        "alt.binaries.x264",
        &[
            overd(
                r#""kK9mN3bV7cX1z.part01.rar" yEnc (1/1)"#,
                "c3",
                5_000_000_000,
                t(2),
            ),
            overd(r#""kK9mN3bV7cX1z.par2" yEnc (1/1)"#, "c4", 1_000_000, t(2)),
        ],
        t(2),
    )
    .unwrap();
    // The Pesto grammar: a real-name tiny PAR2 sits one counter away.
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""zW5xC8vB2nM6k.part01.rar" yEnc (1/1)"#,
            "0123456789abcdef.52b12.fedcba9876543210@wZq",
            5_000_000_000,
            t(3),
        )],
        t(3),
    )
    .unwrap();
    // Suggest-only, the shipped posture.
    let (examined, suggested, applied) = ix.predb_corr_backlog(100, 0, false, t(3) + 400).unwrap();
    assert_eq!(examined, 4, "all four rows are junk>=70 and walked");
    assert_eq!(
        (suggested, applied),
        (1, 0),
        "only the control row may enter the naming population"
    );
    let (rid, n): (i64, i64) = ix
        .db
        .query_row("SELECT MIN(release_id), COUNT(*) FROM pre_corr", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(n, 1);
    let stem: String = ix
        .db
        .query_row("SELECT stem FROM releases WHERE id=?1", [rid], |r| r.get(0))
        .unwrap();
    assert_eq!(stem, "aQ3xY7Bm2ZpK4L");
    // The human picker stays unrestricted: candidates still rank for
    // an excluded row on demand.
    let sevenz: i64 = ix
        .db
        .query_row(
            "SELECT id FROM releases WHERE stem LIKE 'qQ7wE2rT9uI3oP%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        !ix.pre_candidates(sevenz, 8).unwrap().is_empty(),
        "pre_candidates is the human's view and must not be gated"
    );
    teardown(&d, ix);
}

/// The two shape matchers behind the byte-probe exclusion, pinned.
#[test]
fn the_probe_shape_matchers_read_the_right_shapes() {
    for id in [
        "0123456789abcdef.52b12.fedcba9876543210@wZq",
        "<0123456789abcdef.1.fedcba9876543210@x>",
        "DEADBEEFDEADBEEF.ffff.CAFEBABECAFEBABE@host.tld",
    ] {
        assert!(Index::pesto_msgid(id), "{id} must match the Pesto grammar");
    }
    for id in [
        "aQ3xY7Bm2ZpK4L@calib",                                   // no counter triple
        "0123456789abcdef.52b12@x",                               // two parts
        "0123456789abcde.52b12.fedcba9876543210@x",               // 15-hex head
        "0123456789abcdef.z2b12.fedcba9876543210@x",              // non-hex counter
        "0123456789abcdef.52b12.fedcba9876543210",                // no @
        "0123456789abcdef.0123456789abcdef01.fedcba9876543210@x", // counter too long
    ] {
        assert!(!Index::pesto_msgid(id), "{id} must NOT match");
    }
    for n in ["x.7z", "X.7Z", "x.7z.001", "x.7z.042"] {
        assert!(Index::seven_zip_family(n), "{n} is 7z-family");
    }
    for n in ["x.rar", "x.part01.rar", "x.7z.txt", "x.zip", "7z"] {
        assert!(!Index::seven_zip_family(n), "{n} is not 7z-family");
    }
}

/// E1 follow-up 1 (10 Aug 2026): which pre touches a release first
/// within a batch must not matter. Two sized pres fit one release -
/// a weaker floor-clearing one and a tighter one - inserted in both
/// id orders on two fresh indexes; the stored suggestion must name
/// the tighter pre with the same score either way.
#[test]
fn corr_batch_outcome_is_independent_of_pre_order() {
    let strong = tpre(
        "Strong.Film.2026.1080p.WEB.H264-GRP",
        "X264-HD",
        4_900_000_000,
        1000,
    );
    let weak = tpre(
        "Weak.Film.2026.1080p.WEB.H264-GRP",
        "X264-HD",
        4_500_000_000,
        1000,
    );
    let mut results = Vec::new();
    for (tag, order) in [
        ("wf", [weak.clone(), strong.clone()]),
        ("sf", [strong.clone(), weak.clone()]),
    ] {
        let d = dir(&format!("corr-order-{tag}"));
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        // One row per store call so predb ids follow insert order -
        // the catch-up walks ids DESCENDING, so the two runs touch
        // the release in opposite pre order.
        for p in &order {
            ix.predb_store(std::slice::from_ref(p), 1000).unwrap();
        }
        ix.ingest(
            "alt.binaries.x264",
            &[overd(
                r#""aQ3xY7Bm2ZpK4L.part01.rar" yEnc (1/1)"#,
                "c1",
                5_000_000_000,
                4600,
            )],
            5000,
        )
        .unwrap();
        // Seed generation bump opens the catch-up cursor.
        ix.kv_set("predb_seed_gen", "1").unwrap();
        let (_, s, _) = ix.predb_corr_catchup(100, false, 5000).unwrap();
        assert_eq!(s, 1, "one suggestion per run ({tag})");
        let row: (String, i64) = ix
            .db
            .query_row(
                "SELECT p.title, c.score FROM pre_corr c JOIN predb p ON p.id=c.predb_id",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        results.push(row);
        teardown(&d, ix);
    }
    assert_eq!(
        results[0], results[1],
        "batch order changed the stored suggestion"
    );
    assert_eq!(results[0].0, "Strong.Film.2026.1080p.WEB.H264-GRP");
}

/// A future quality_vN bump must not clobber rows named AFTER ingest.
/// `apply_named` (predb sweep, spot promotion, byte probes) derived
/// junk/title_key/kind - and res/langs/codecs - from pre_title, and the
/// row's stem is an obfuscated hash. The retro pass therefore parses
/// the effective name, COALESCE(NULLIF(pre_title,''), stem), same as
/// ingest and the card queries: a re-run reproduces the applied answer
/// instead of reverting the row to the junk>=70 no-card stem answer,
/// which nothing would ever heal (the naming seam refuses rows whose
/// pre_title is already set).
#[test]
fn a_quality_bump_rerun_keeps_names_applied_after_ingest() {
    let d = dir("vbump-named");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.boneless",
        &[over(
            r#""x7Qq0FvGpZk2R9sT.part01.rar" yEnc (1/1)"#,
            "p@x",
            "q1",
            4 << 30,
        )],
        1000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    assert!(
        ix.apply_named(rid, "Some.Film.2026.1080p.WEB-DL.x264-GRP", "spot", 2000)
            .unwrap()
    );

    let snap = |ix: &Index| -> (i64, String, String, String, String) {
        ix.db
            .query_row(
                "SELECT junk, title_key, kind, res, vcodec
                   FROM releases WHERE id=?1",
                [rid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap()
    };
    let before = snap(&ix);
    assert!(
        before.0 < 50,
        "named row starts below the junk bar: {before:?}"
    );
    assert!(
        before.1.starts_with("m:some film"),
        "named row starts on a real card: {before:?}"
    );

    // Simulate the next bump: un-stamp the pass and reopen, so the
    // migration body re-parses every row from scratch.
    ix.db
        .execute(
            "DELETE FROM kv WHERE k IN ('quality_v9','quality_v9_cursor')",
            [],
        )
        .unwrap();
    drop(ix);
    let ix = Index::open(&d.join("index.db")).unwrap();
    let stamped: String = ix
        .db
        .query_row("SELECT v FROM kv WHERE k='quality_v9'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stamped, "1", "the re-run completed");
    assert_eq!(
        snap(&ix),
        before,
        "a retro re-parse must reproduce the applied-name answer, not the stem's"
    );
    teardown(&d, ix);
}

/// Codex probe A: archive volumes share one release stem but remain
/// distinct files, each with its own yEnc part-number universe.
#[test]
fn codex_probe_a_shatter_fold_keeps_distinct_archive_volume_filenames() {
    let d = dir("codex-probe-a");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    const STEM: &str = "e3b0c44298fc1c149afbf4c8996fb924";
    let groups = ["alt.binaries.movies", "alt.binaries.tv"];
    for file in 1u32..=2 {
        for part in 1u32..=2 {
            let subject = format!(r#"[{file}/2] - "{STEM}.part{file:02}.rar" yEnc ({part}/2)"#);
            ix.ingest(
                groups[((file + part) as usize) % groups.len()],
                &[over(
                    &subject,
                    &format!("p{file}{part}@test"),
                    &format!("codex-a-{file}-{part}@test"),
                    1_000,
                )],
                5_000,
            )
            .unwrap();
        }
    }
    let before: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, 4, "real ingest built four one-article fragments");
    ix.shatter_fold(6_000, WALK).unwrap();

    let rows: Vec<(String, i64, bool)> = ix
        .db
        .prepare(
            "SELECT f.filename, f.nsegs, r.complete
               FROM releases r JOIN files f ON f.release_id=r.id
              ORDER BY f.filename",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (format!("{STEM}.part01.rar"), 2, true),
            (format!("{STEM}.part02.rar"), 2, true),
        ],
        "the fold must complete each filename without removing the other volume"
    );
    teardown(&d, ix);
}

/// Codex probe D: a posting bigger than the member cap must still
/// reach one complete row. "It folds on a later lap" was never true -
/// the cursor parks at the top id, so a posting that has stopped
/// arriving is never revisited.
#[test]
fn a_posting_past_the_member_cap_still_folds_to_one_row() {
    const MEMBERS: i64 = 20_001;
    const STEM: &str = "d41d8cd98f00b204e9800998ecf8427e";
    let d = dir("shatter-cap");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    {
        let tx = ix.db.transaction().unwrap();
        {
            let mut rel = tx
                .prepare(
                    "INSERT INTO releases(id, stem, poster, grp, files, complete,
                                          first_posted, first_seen, junk,
                                          have_parts, need_parts)
                     VALUES(?1,?2,?3,'alt.binaries.tv',1,0,4600,5000,70,1,?4)",
                )
                .unwrap();
            let mut file = tx
                .prepare(
                    "INSERT INTO files(release_id, filename, total_parts, bytes,
                                       segments, nsegs)
                     VALUES(?1,?2,?3,100,?4,1)",
                )
                .unwrap();
            for id in 1..=MEMBERS {
                rel.execute(rusqlite::params![id, STEM, format!("p{id}@test"), MEMBERS])
                    .unwrap();
                let segments = format!(r#"[[{id},"<codex-d-{id}@test>",100]]"#);
                file.execute(rusqlite::params![
                    id,
                    format!("{STEM}.bin"),
                    MEMBERS,
                    segments
                ])
                .unwrap();
            }
        }
        tx.commit().unwrap();
    }
    // WALK, not a one-second budget: this test is about the member CAP,
    // not the clock. A second was enough on the machine it was written
    // on and not on the CI runners, which folded 19,999 of 20,000 and
    // failed by one on Linux and on Windows (14 Aug). It costs nothing
    // now that the pass stops when it catches up instead of spinning
    // out its whole budget.
    let first = ix.shatter_fold(6_000, WALK).unwrap();
    let state = |ix: &Index| -> (i64, i64, i64) {
        ix.db
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(f.nsegs),0), COALESCE(SUM(r.complete),0)
                   FROM releases r JOIN files f ON f.release_id=r.id",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    };
    assert_eq!(first.1, (MEMBERS - 1) as usize, "every member folded away");
    // And it KNOWS it is caught up. The fold deletes the rows it folded,
    // so the surviving maximum id collapses far below the `top` the call
    // read at entry; a pass that only tests against that stale top can
    // never reach it, and spins on an empty id range until its budget
    // runs out.
    assert!(
        first.2,
        "the fold folded everything and still reported itself behind"
    );
    assert_eq!(
        state(&ix),
        (1, MEMBERS, 1),
        "one row, every segment, and it is complete"
    );
    assert_eq!(ix.shatter_fold(6_100, WALK).unwrap(), (0, 0, true));
    teardown(&d, ix);
}

/// Codex probe C: a checked marker belongs to ONE suggested pairing,
/// not to every later pairing the same release acquires. A stronger
/// pre replacing the stored one starts a fresh pairing, and the
/// confirm lane has never spent a lookup on it.
#[test]
fn a_replacement_pairing_starts_unchecked() {
    let d = dir("confirm-replace");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    const OLD: &str = "Older.Candidate.2026.1080p.WEB.H264-OLD";
    const NEW: &str = "Newer.Candidate.2026.1080p.WEB.H264-NEW";

    // Score 80: T(<=30m) + S(<=8%) + C. Eligible for the confirm pick
    // but supersedable by a stronger later pre.
    ix.predb_store(&[tpre(OLD, "X264-HD", 4_650_000_000, 3_000)], 5_000)
        .unwrap();
    ix.ingest(
        "alt.binaries.x264",
        &[overd(
            r#""cD3xY7Bm2ZpK4L9q.part01.rar" yEnc (1/1)"#,
            "codex-c1",
            5_000_000_000,
            4_600,
        )],
        5_000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    assert_eq!(ix.predb_corr_backlog(100, 0, false, 5_000).unwrap().1, 1);
    let picks = ix.corr_confirm_pick(10).unwrap();
    assert_eq!(picks[0].1, OLD);
    ix.corr_confirm_stamp(rid, picks[0].3, 5_010).unwrap();
    assert!(ix.corr_confirm_pick(10).unwrap().is_empty(), "OLD retired");

    // Score 90: T(<=30m) + S(top band) + C. The live pre sweep runs
    // the production refresh upsert and replaces OLD with NEW.
    ix.predb_store(&[tpre(NEW, "X264-HD", 4_900_000_000, 4_000)], 5_100)
        .unwrap();
    assert_eq!(ix.predb_corr_sweep(100, false, 5_200).unwrap().1, 1);
    let (stored, checked): (String, i64) = ix
        .db
        .query_row(
            "SELECT p.title, c.checked_at FROM pre_corr c
               JOIN predb p ON p.id=c.predb_id WHERE c.release_id=?1",
            [rid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored, NEW, "the stronger pairing replaced the old one");
    let picks = ix
        .corr_confirm_pick(10)
        .unwrap()
        .into_iter()
        .map(|(_, title, _, _)| title)
        .collect::<Vec<_>>();
    assert_eq!(
        (checked, picks),
        (0, vec![NEW.to_string()]),
        "the replacement pairing must start unchecked and enter the pick"
    );

    // And the stamp a lookup minted before the swap - the OLD pre id -
    // cannot retire the successor when it finally lands.
    let old_pid: i64 = ix
        .db
        .query_row("SELECT id FROM predb WHERE title=?1", [OLD], |r| r.get(0))
        .unwrap();
    ix.corr_confirm_stamp(rid, old_pid, 5_410).unwrap();
    assert_eq!(
        ix.corr_confirm_pick(10).unwrap().len(),
        1,
        "the in-flight stamp belonged to the replaced pairing"
    );
    teardown(&d, ix);
}

/// B4: with the per-pass reader flush gone, the daemon retires its
/// pooled read-only connections only when the schema actually changes -
/// and the one runtime schema change is the named-count index, built by
/// the first feed activity. `predb_store` stamps the connection when it
/// BUILDS the index; the stamp drains once and never re-arms while the
/// index already exists, so steady-state feed batches cost the pool
/// nothing.
#[test]
fn the_named_index_build_is_stamped_once_and_drained() {
    let d = dir("ddl-stamp");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    assert!(!ix.take_schema_ddl(), "a fresh open stamps nothing");
    ix.predb_store(&[pre("Some.Release.2026-GRP", "some.release.r00")], 1000)
        .unwrap();
    assert!(
        ix.take_schema_ddl(),
        "the first feed batch built the named index - the pool must hear"
    );
    assert!(!ix.take_schema_ddl(), "the stamp drains on the first read");
    ix.predb_store(&[pre("Other.Release.2026-GRP", "other.release.r00")], 1001)
        .unwrap();
    assert!(
        !ix.take_schema_ddl(),
        "the index already exists - a later batch is not a schema change"
    );
    // A reopen runs the ladder's own build (feed activity is recorded),
    // so a restarted daemon's first batch stamps nothing either.
    drop(ix);
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(&[pre("Third.Release.2026-GRP", "third.release.r00")], 1002)
        .unwrap();
    assert!(
        !ix.take_schema_ddl(),
        "open's ladder built it before the batch could"
    );
    teardown(&d, ix);
}
