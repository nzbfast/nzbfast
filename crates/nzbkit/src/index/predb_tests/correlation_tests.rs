//! Phase 2: correlation - pairing a predb announcement to an indexed
//! release, and the folds that decide what a release even IS.
//!
//! The suggest and auto tiers and the three things that block auto (a
//! repack sibling, a crowded window, a pre with no size), rotation and
//! retirement, the backlog walk, revoke and reject, the size band, the
//! oracle settling a pair both ways, the shatter fold across posters
//! and groups, the par2 sidecar fold and its twins, and what pruning a
//! pre does to a correlation identity.
//!
//! A child of predb_tests, out here for the size gate (TODO 106): the
//! parent was 2,918 lines against the 3,000-line file ceiling, 81 of
//! them spare. Cut at the file's own `phase 2: correlation` banner,
//! which became this header. The module is named for its file so
//! size-gate.py's CFG_TEST_MOD resolver still reads it as test code,
//! and `use super::*` brings the parent's `dir`, `over`, `pre`, `overd`
//! and `tpre` builders along with everything the parent itself pulls
//! from `index`.

use super::*;

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
        &[
            tpre(
                "Some.Film.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            // The field the margin clause is measured against. Without
            // it there is no runner-up and the clause is vacuous - see
            // `bgpre`.
            bgpre("c1", 100),
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
            // ... and a candidate that IS one, so the margin clause
            // has a runner-up to beat (see `bgpre`).
            bgpre("av1", 100),
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

/// The other end of the crowding range: a window holding exactly ONE
/// candidate must not auto-apply either.
///
/// Until 2 Sep 2026 it always did. `runner_up` was
/// `cands.get(1).map(..).unwrap_or(0)`, so an ABSENT rival read as a
/// rival scoring zero, `best - runner_up` degenerated to the raw
/// score, and the score had already cleared STRONG (80) to reach the
/// clause - a lone candidate was unbeatable by exactly the test meant
/// to catch it. The Python naming prototype carries the same
/// arithmetic and `research/NAMECORR-PRECISION-2026-09-01.md`
/// measured 45-91% of its firings riding it, against 0% precision.
///
/// Two arms, identical but for one weak background pre, because the
/// assertion "it does not auto-apply" is worthless on its own - a
/// corpus that fails some OTHER clause would satisfy it too. Arm B is
/// the control: add a runner-up the true pre beats by 58 and the same
/// pair applies.
#[test]
fn a_lone_candidate_window_never_auto_applies() {
    let build = |tag: &str, field: bool| {
        let d = dir(tag);
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let mut lines = vec![tpre(
            "Lonely.Film.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            4_900_000_000,
            1000,
        )];
        if field {
            lines.push(bgpre("lone", 100));
        }
        ix.predb_store(&lines, 1000).unwrap();
        ix.ingest(
            "alt.binaries.x264",
            &[overd(
                r#""lL3nN8xX2zZ.part01.rar" yEnc (1/1)"#,
                "lo1",
                5_000_000_000,
                4600,
            )],
            5000,
        )
        .unwrap();
        let (_, suggested, applied) = ix.predb_corr_backlog(100, 0, true, 5000).unwrap();
        let runner: i64 = ix
            .db
            .query_row("SELECT runner_up FROM pre_corr", [], |r| r.get(0))
            .unwrap();
        let named = ix.search("", 10).unwrap()[0].pre_title.clone();
        teardown(&d, ix);
        (suggested, applied, runner, named)
    };

    // Arm A: nothing else in the window at all.
    let (suggested, applied, runner, named) = build("corr-lone", false);
    assert_eq!(runner, 0, "the corpus really is a one-candidate window");
    assert_eq!(applied, 0, "a lone candidate must never auto-apply");
    assert_eq!(suggested, 1, "it is still a suggestion - that is the tier");
    assert_eq!(named, "", "and the release keeps its stem");

    // Arm B, the control: the same pair, plus a rival to beat.
    let (suggested, applied, runner, named) = build("corr-lone-ctl", true);
    assert!(runner > 0, "arm B has a real runner-up");
    assert_eq!(suggested, 0);
    assert_eq!(applied, 1, "with a field to beat, the same pair applies");
    assert_eq!(named, "Lonely.Film.2026.1080p.WEB.H264-GRP");
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
        &[
            tpre(
                "Named.Film.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            bgpre("rv1", 100),
        ],
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
        &[
            tpre(
                "Caught.Up.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            // Sizeless, so the catch-up walk (SIZED pres only) never
            // takes it as a driver - it is here to be the release
            // window's runner-up. See `bgpre`.
            bgpre("cu9", 100),
        ],
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
        &[
            tpre(
                "Oracle.Film.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            bgpre("ov1", 100),
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
        &[
            tpre(
                "Wrong.Guess.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            bgpre("ov2", 100),
        ],
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
        &[
            tpre(
                "Whole.Set.2026.1080p.WEB.H264-GRP",
                "X264-HD",
                4_900_000_000,
                1000,
            ),
            bgpre("ws1", 100),
        ],
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

/// The floor's other side: a 15-character random stem - the teevee
/// family's common shape, structurally excluded while the floor sat at
/// 16 - folds now that the measured floor is 12
/// (research/SHATTER-FOLD-STARVATION-2026-09-01.md).
#[test]
fn a_fifteen_char_random_stem_is_inside_the_fold_floor() {
    let d = dir("shatter-floor12");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    for p in 1..=2u32 {
        ix.ingest(
            "alt.binaries.teevee",
            &[over(
                &format!(r#""LgXNckle2TSyKUA" yEnc ({p}/2)"#),
                &format!("q{p}@h.tld"),
                &format!("s{p}"),
                700_000,
            )],
            5_000,
        )
        .unwrap();
    }
    let before: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, 2, "two shattered rows, one per poster");
    let (g, n, _) = ix.shatter_fold(6_000, WALK).unwrap();
    assert_eq!((g, n), (1, 1), "the 15-char stem folds");
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

/// The junk-only half of the same rule (`session_fold_members`'
/// shape): a pass that recomputes `junk` on an existing row scores it
/// against a KIND, so it owes ingest's recoveries even when it never
/// writes the kind column. The par2 sidecar fold rewrites the
/// container's score off a fresh parse of the stem it keeps.
///
/// The shape here is the one this pass actually meets: an obfuscated
/// `.7z` container in a BOOK group. The recovery declines it - the
/// stem wears a plain extension, which the group rule refuses on
/// purpose - so the fold's answer is the fall-through lane, and that
/// is exactly what ingest would have said about the same stem. What
/// this pins is the rule, not a rescue: the container is a junk-70
/// obfuscated row either way, hidden on every wall at any lane.
#[test]
fn a_par2_sidecar_fold_scores_the_way_ingest_scores_it() {
    let d = dir("sidecar-fold-kind");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let grp = "alt.binaries.audiobooks";
    let cstem = "Deliver.Us.From.Evil.gUSbVwIDqhrR.7z";
    let row =
        |stem: &str, posted: i64, nfiles: usize, each: i64, namer: &dyn Fn(usize) -> String| {
            let mut p = crate::categories::classify(stem, &ix.custom);
            crate::release::recover_media_kind(&mut p, stem, stem);
            crate::release::recover_kind_from_group(&mut p, grp, stem);
            let junk = junk_score(stem, &p, (each * nfiles as i64) as u64, false);
            assert!(junk >= 70, "{stem} must be in this pass's band");
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, total_bytes, files, complete,
                                      has_par2, first_posted, first_seen, kind, junk,
                                      title_key)
                 VALUES(?1, 'p@x', ?2, ?3, ?4, 1, 0, ?5, 5000, ?6, ?7, ?8)",
                    rusqlite::params![
                        stem,
                        grp,
                        each * nfiles as i64,
                        nfiles as i64,
                        posted,
                        kind_str(&p.kind),
                        junk,
                        p.key
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
        };
    row(cstem, 4700, 3, 1_000_000_000, &|i| {
        format!("{}.{:03}", "Deliver.Us.From.Evil.gUSbVwIDqhrR.7z", i + 1)
    });
    row(
        "Deliver.Us.From.Evil.gUSbVwIDqhrR",
        4650,
        2,
        100_000_000,
        &|i| format!("Deliver.Us.From.Evil.gUSbVwIDqhrR.vol{i:02}+02.par2"),
    );
    assert!(ix.split_merge(6000, WALK).unwrap().2);
    assert_eq!(ix.par2_sidecar_fold(WALK).unwrap(), (1, 2, true));

    let (stem, kind, junk, bytes, nexe): (String, String, i64, i64, i64) = ix
        .db
        .query_row(
            "SELECT stem, kind, junk, total_bytes, nfiles_exe FROM releases",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(stem, cstem, "the container stem is kept");
    let mut want = crate::categories::classify(&stem, &ix.custom);
    crate::release::recover_media_kind(&mut want, &stem, &stem);
    crate::release::recover_kind_from_group(&mut want, grp, &stem);
    if !crate::index::ingest::stem_obfuscated(&stem, &want) {
        crate::release::recover_episode_from_group(&mut want, grp, &stem);
    }
    assert_eq!(
        junk,
        junk_score(&stem, &want, bytes as u64, nexe > 0),
        "the fold scored junk against a kind ingest would not have used"
    );
    assert_eq!(
        kind, "movie",
        "the fold writes no kind; the row keeps its own"
    );
    assert!(junk >= 70, "an obfuscated container stays dark either way");
    teardown(&d, ix);
}

/// The same for the shatter fold, on the shape it actually meets: a
/// whole-stem blob, posted into a BOOK group, shattered across four
/// posters.
///
/// The recovery cannot fire on this population and the reason is worth
/// having pinned. The walk skips every candidate `stem_is_a_name`
/// accepts, so its members are exactly the stems `looks_obfuscated`
/// damns - which is `stem_obfuscated`'s own first arm. That has two
/// consequences at once: such a stem parses to `Kind::Other`, which
/// both group rules decline on purpose ("an obfuscated stem must not
/// become a book with a hash for a title"), and the 70 it scores is
/// kind-INDEPENDENT, so no recovered lane could move the number even
/// if one fired. Widen the walk's filter or its band, or add a kind
/// branch at or above 70 to `junk_score`, and this reds here instead
/// of on a wall that has quietly hidden a row.
#[test]
fn a_folded_shatter_is_scored_the_way_ingest_scores_it() {
    let d = dir("shatter-fold-kind");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let grp = "alt.binaries.audiobooks";
    let stem = "LgXNckle2TSyKUA";
    assert!(
        !crate::release::stem_is_a_name(stem),
        "the walk skips anything that already shows a name"
    );
    for p in 1u32..=4 {
        ix.ingest(
            grp,
            &[over(
                &format!(r#""{stem}" yEnc ({p}/4)"#),
                &format!("r{p}@h{p}.tld"),
                &format!("m{p}"),
                700_000,
            )],
            5_000 + p as i64,
        )
        .unwrap();
    }
    let (rows, kind, junk): (i64, String, i64) = ix
        .db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM releases), kind, junk FROM releases LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(rows, 4, "the shattered shape really was built");
    assert_eq!(
        kind, "other",
        "precondition: a blob stem parses to Other, which both group \
         rules decline by design"
    );
    assert!(junk >= 70, "and the blob pins the score dark: {junk}");

    let (groups, folded, _) = ix.shatter_fold(6_000, WALK).unwrap();
    assert_eq!((groups, folded), (1, 3));

    let (kind, junk, bytes): (String, i64, i64) = ix
        .db
        .query_row("SELECT kind, junk, total_bytes FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    let mut want = crate::categories::classify(stem, &ix.custom);
    crate::release::recover_media_kind(&mut want, stem, stem);
    crate::release::recover_kind_from_group(&mut want, grp, stem);
    if !crate::index::ingest::stem_obfuscated(stem, &want) {
        crate::release::recover_episode_from_group(&mut want, grp, stem);
    }
    assert_eq!(
        kind, "other",
        "the fold writes no kind; the row keeps ingest's"
    );
    assert_eq!(
        junk,
        junk_score(stem, &want, bytes as u64, false),
        "the fold scored junk against a kind ingest would not have used"
    );
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

/// Revoking a name must put the row back on the lane its own INGEST
/// gave it, not on the one a bare `classify` reads.
///
/// The undo re-derives every column from the stem, and until 2 Sep 2026
/// it did that with `categories::classify` alone - none of the three
/// recoveries ingest runs. An audiobook stem carries no format marker
/// and no video evidence, so it falls through to an evidence-free
/// movie at junk 60, which the wall's default `junk < 50` hides. That
/// makes the undo strictly destructive: the row is less visible after
/// a name is taken off than it was before anybody put one on.
///
/// The human picker is what makes this reachable. `pre_assign` is
/// deliberately ungated ("the human IS the gate"), so it can name a
/// perfectly readable row; the auto lane cannot, because
/// `corr_naming_population` admits only obfuscated stems and both
/// group rules decline those.
#[test]
fn revoking_a_name_restores_the_lane_ingest_gave_the_row() {
    let d = dir("corr-revoke-lane");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_seed_store(
        &[tpre(
            "Some.Wrong.Guess.2026.1080p.WEB.H264-GRP",
            "X264-HD",
            0,
            1000,
        )],
        "seed:predb.net",
        5000,
    )
    .unwrap();
    // A readable audiobook post: no extension, no technical marker,
    // in a group `group_media_kind` speaks for.
    ix.ingest(
        "alt.binaries.audiobooks",
        &[overd(
            r#""David Baldacci - Deliver Us From Evil" yEnc (1/1)"#,
            "ab1",
            700_000_000,
            4600,
        )],
        5000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    let lane = |ix: &Index| -> (String, i64) {
        ix.db
            .query_row("SELECT kind, junk FROM releases WHERE id=?1", [rid], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .unwrap()
    };
    let at_ingest = lane(&ix);
    assert_eq!(
        at_ingest,
        ("book".into(), 0),
        "precondition: ingest's group recovery puts this on the Books lane"
    );

    let pid: i64 = ix
        .db
        .query_row("SELECT id FROM predb", [], |r| r.get(0))
        .unwrap();
    assert!(ix.pre_assign(rid, pid, 6000).unwrap());
    assert!(ix.revoke_pre_name(rid).unwrap());

    assert_eq!(
        lane(&ix),
        at_ingest,
        "the undo must be an undo: same lane and same score the row \
         wore before it was ever named"
    );
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

/// The session fold is the correlation's missing precondition, end to
/// end: five dark complete single files from one session poster are
/// each VETOED on ratio (one 150 MB volume against a 728 MB pre), the
/// fold merges them into one release carrying the true total, its
/// first lap bumps `predb_seed_gen` so the backlog cursor reopens, and
/// the very next walk suggests the pre for the folded row.
#[test]
fn a_folded_session_correlates_by_its_true_size() {
    let d = dir("sess-fold-corr");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.predb_store(
        &[tpre(
            "Some.Show.S01E01.1080p.WEB.H264-GRP",
            "TV-WEB",
            728_000_000,
            1000,
        )],
        1000,
    )
    .unwrap();
    // wire total = 5 files x 3 parts x 50 MB = 750 MB;
    // est_content = 750/1.03 = 728.2 MB against the 728 MB pre.
    let stems = [
        "q7kx9zzp0aa41bb2cc31",
        "m3vd8tty1dd52ee3ff42",
        "z9qa2rrw2gg63hh4ii53",
        "b5nc4uui3jj74kk5ll64",
        "x1pe6oos4mm85nn6oo75",
    ];
    for (i, stem) in stems.iter().enumerate() {
        for p in 1..=3u32 {
            ix.ingest(
                "alt.binaries.tv",
                &[overd(
                    &format!("\"{stem}\" yEnc ({p}/3)"),
                    &format!("{stem}-{p}"),
                    50_000_000,
                    4_600 + i as i64 * 30,
                )],
                4_700,
            )
            .unwrap();
        }
    }
    let (examined, suggested, _) = ix.predb_corr_backlog(100, 0, false, 5_000).unwrap();
    assert_eq!(
        (examined, suggested),
        (5, 0),
        "five lone volumes: examined, and every one vetoed on ratio"
    );
    // now = 30_000 puts the session past the fold's settle margin.
    let (sessions, folded, done) = ix.session_fold(30_000, WALK).unwrap();
    assert_eq!((sessions, folded), (1, 4));
    assert!(done);
    let (examined, suggested, applied) = ix.predb_corr_backlog(100, 0, false, 5_000).unwrap();
    assert_eq!(
        (examined, suggested, applied),
        (1, 1, 0),
        "the gen bump reopened the walk, and the true size clears the band"
    );
    let rid: i64 = ix
        .db
        .query_row("SELECT id FROM releases", [], |r| r.get(0))
        .unwrap();
    let hints = ix.pre_hints(&[rid]).unwrap();
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].1, "Some.Show.S01E01.1080p.WEB.H264-GRP");
    assert_eq!(hints[0].5, "suggested", "suggest-only, per the house rules");
    teardown(&d, ix);
}
