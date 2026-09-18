//! The session fold, end to end through real ingest: the family-S
//! shape (one stable per-session poster, N complete single files under
//! N random stems - the inverse of the shatter shape) and every screen
//! and proof that keeps the merge honest.

use super::testutil::*;
use super::*;

fn fixture(name: &str) -> (std::path::PathBuf, Index) {
    let dir = std::env::temp_dir().join(format!("nzbfast-sessfold-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    (dir, ix)
}

/// One article of one session file: a random extensionless stem quoted
/// in the subject with an ordinary (p/P) counter, a real Date, and a
/// volume-sized payload (family S posts multi-GB sets; a tiny payload
/// would score junk 55 and fall out of the dark band).
fn sess_article(
    ix: &mut Index,
    grp: &str,
    poster: &str,
    stem: &str,
    part: u32,
    total: u32,
    bytes: u64,
    posted: i64,
) {
    let e = OverEntry {
        number: 0,
        subject: format!("\"{stem}\" yEnc ({part}/{total})"),
        from: poster.into(),
        message_id: format!("<{stem}-{part}@sess>"),
        bytes,
        date: posted,
    };
    ix.ingest(grp, &[e], posted).unwrap();
}

/// A whole session file: P uniform articles, complete.
fn sess_file(ix: &mut Index, grp: &str, poster: &str, stem: &str, posted: i64) {
    for p in 1..=3u32 {
        sess_article(ix, grp, poster, stem, p, 3, 50_000_000, posted);
    }
}

/// Five random-looking stems: single mixed-alnum tokens, so
/// `stem_obfuscated` puts every row in the dark band.
const STEMS: [&str; 5] = [
    "q7kx9zzp0aa41bb2cc31",
    "m3vd8tty1dd52ee3ff42",
    "z9qa2rrw2gg63hh4ii53",
    "b5nc4uui3jj74kk5ll64",
    "x1pe6oos4mm85nn6oo75",
];

#[test]
fn a_proven_session_folds_into_one_release_with_true_size() {
    let (dir, mut ix) = fixture("fold");
    for (i, stem) in STEMS.iter().enumerate() {
        sess_file(
            &mut ix,
            "a.b.tv",
            "sess1@h.tld",
            stem,
            5_000_000 + i as i64 * 30,
        );
    }
    let rows: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 5, "the family-S shape really was built");

    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!((sessions, folded), (1, 4));
    assert!(done, "one stride covers a small table");

    let (rows, files, total, need, have, complete, nfc, fp): (
        i64,
        i64,
        i64,
        i64,
        i64,
        bool,
        i64,
        i64,
    ) = ix
        .db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM releases), files, total_bytes,
                    need_parts, have_parts, complete, nfiles_complete,
                    first_posted
               FROM releases",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(rows, 1, "one release now");
    assert_eq!(files, 5);
    assert_eq!(total, 5 * 3 * 50_000_000, "the TRUE size, all volumes");
    assert_eq!((need, have), (15, 15), "N files x P parts, proven held");
    assert!(complete);
    assert_eq!(nfc, 5);
    assert_eq!(fp, 5_000_000, "earliest member's posting time");
    let nfiles: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(nfiles, 5, "every member's file row moved, none lost");

    // Idempotent and parked: the fold's own deletions collapse the id
    // range, so the next call finds nothing and stays caught up.
    assert_eq!(ix.session_fold(6_000_100, WALK).unwrap(), (0, 0, true));
    // Lifetime tallies and the first-lap marker are real.
    assert_eq!(ix.kv_get("session_fold_rows").as_deref(), Some("4"));
    assert_eq!(ix.kv_get("session_fold_sessions").as_deref(), Some("1"));
    assert!(ix.kv_get("session_fold_lap_v1").is_some());
    teardown(&dir, ix);
}

#[test]
fn a_ragged_volume_size_fails_the_uniformity_screen() {
    let (dir, mut ix) = fixture("ragged");
    for (i, stem) in STEMS.iter().enumerate() {
        // The last file's volumes run 10% larger: not one rar set.
        let bytes = if i == 4 { 55_000_000 } else { 50_000_000 };
        for p in 1..=3u32 {
            sess_article(
                &mut ix,
                "a.b.tv",
                "sess2@h.tld",
                stem,
                p,
                3,
                bytes,
                5_000_000,
            );
        }
    }
    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!((sessions, folded, done), (0, 0, true));
    let rows: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 5, "nothing merged");
    teardown(&dir, ix);
}

#[test]
fn a_wrong_part_cover_fails_the_proof_even_when_complete() {
    let (dir, mut ix) = fixture("cover");
    for stem in &STEMS {
        sess_file(&mut ix, "a.b.tv", "sess3@h.tld", stem, 5_000_000);
    }
    // The fifth member is made to hold THREE parts numbered 2..4 under
    // its own claimed total of 3: nsegs >= total so `complete=1`, and
    // the cover is wrong. That is exactly the row the proof exists to
    // refuse - and one bad member refuses the WHOLE candidate, because
    // a session missing a provable member is not a session, it is a
    // guess.
    //
    // THE ROW IS WRITTEN IN SQL, and that is the point rather than a
    // shortcut: since ingest refuses a `(4/3)` article outright
    // (`a_part_over_its_own_total_is_refused_and_never_reads_complete`),
    // nothing on the live ingest path can mint this shape any more, so
    // the proof now stands as a floor under rows OLDER VERSIONS wrote -
    // and an index carrying those rows is the population it still has
    // to refuse. Writing it here is the only way to keep testing that.
    let rid: i64 = ix
        .db
        .query_row("SELECT id FROM releases WHERE stem=?1", [STEMS[4]], |r| {
            r.get(0)
        })
        .unwrap();
    let segs: Vec<segcodec::Seg> = (2..=4u32)
        .map(|p| (p, format!("<{}-{p}@sess>", STEMS[4]), 50_000_000u64))
        .collect();
    let n = ix
        .db
        .execute(
            "UPDATE files SET segments=?2, nsegs=3 WHERE release_id=?1",
            rusqlite::params![rid, segcodec::encode(&segs)],
        )
        .unwrap();
    assert_eq!(n, 1, "the fifth member's one file row was not rewritten");
    let all_complete: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases WHERE complete=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(all_complete, 5, "the bad member really reads complete");
    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!((sessions, folded, done), (0, 0, true));
    teardown(&dir, ix);
}

#[test]
fn a_part_over_its_own_total_is_refused_and_never_reads_complete() {
    let (dir, mut ix) = fixture("overtotal");
    for stem in &STEMS[..4] {
        sess_file(&mut ix, "a.b.tv", "sess9@h.tld", stem, 5_000_000);
    }
    // The fifth member is posted as parts 1, 2 and (4/3) - a garbled or
    // hostile counter claiming a part number past its own total. Before
    // the `part > total` guard the three merged to nsegs=3 >= 3 and the
    // row read COMPLETE with part 3 missing.
    let bad = "v2wf7ppq5qq96rr7ss86";
    for p in [1u32, 2, 4] {
        sess_article(
            &mut ix,
            "a.b.tv",
            "sess9@h.tld",
            bad,
            p,
            3,
            50_000_000,
            5_000_000,
        );
    }
    let (nsegs, total): (i64, i64) = ix
        .db
        .query_row(
            "SELECT f.nsegs, f.total_parts FROM files f
               JOIN releases r ON r.id=f.release_id WHERE r.stem=?1",
            [bad],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (nsegs, total),
        (2, 3),
        "the (4/3) article was stored instead of dropped"
    );
    let complete: i64 = ix
        .db
        .query_row("SELECT complete FROM releases WHERE stem=?1", [bad], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(complete, 0, "2 of 3 parts read as a complete release");
    assert_eq!(
        ix.kv_get("ingest_drop_unparseable").as_deref(),
        Some("1"),
        "the refusal was not counted in the drop census"
    );
    // And the consequence for the fold, which is the half this item was
    // held on: the liar drops out of the fold's `complete=1` population
    // and the four PROVABLE members fold without it. That is the
    // under-merge the module header already licenses ("under-merging,
    // never garbage-union") - the folded release's size and file count
    // are true for the four rows in it, and the incomplete fifth stays
    // its own row, which is what it is.
    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!((sessions, folded, done), (1, 3, true));
    let left: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM releases WHERE stem=?1 AND complete=0",
            [bad],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(left, 1, "the unprovable member was folded in anyway");
    teardown(&dir, ix);
}

#[test]
fn a_slow_posting_span_is_not_a_session() {
    let (dir, mut ix) = fixture("span");
    for (i, stem) in STEMS.iter().enumerate() {
        // Two hours first-to-last: a stable handle, not one upload run.
        sess_file(
            &mut ix,
            "a.b.tv",
            "sess4@h.tld",
            stem,
            5_000_000 + i as i64 * 1_800,
        );
    }
    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!((sessions, folded, done), (0, 0, true));
    teardown(&dir, ix);
}

#[test]
fn posters_never_mix_and_a_named_row_stays_out() {
    let (dir, mut ix) = fixture("mix");
    // Two interleaved sessions from two posters in one group, four
    // files each, same sizes and times.
    let more = [
        "r8gh3aab6tt07uu8vv97",
        "k4jm5ccd7ww18xx9yy08",
        "w6qn7eef8zz29aa0bb19",
    ];
    for i in 0..4usize {
        sess_file(
            &mut ix,
            "a.b.tv",
            "pa@h.tld",
            STEMS[i],
            5_000_000 + i as i64 * 30,
        );
        let stem_b = if i == 0 {
            "t0rr9ggh9cc30dd1ee20"
        } else {
            more[i - 1]
        };
        sess_file(
            &mut ix,
            "a.b.tv",
            "pb@h.tld",
            stem_b,
            5_000_000 + i as i64 * 30 + 5,
        );
    }
    // A ninth row from poster A that something already NAMED: the fold
    // must leave it alone, not eat it into the session.
    sess_file(
        &mut ix,
        "a.b.tv",
        "pa@h.tld",
        "n5ss1iij0ff41gg2hh31",
        5_000_060,
    );
    ix.db
        .execute(
            "UPDATE releases SET pre_title='Some.Release-GRP', pre_source='predb'
              WHERE stem='n5ss1iij0ff41gg2hh31'",
            [],
        )
        .unwrap();
    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!(
        (sessions, folded),
        (2, 6),
        "two sessions of four, separately"
    );
    assert!(done);
    let (rows, named_files): (i64, i64) = ix
        .db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM releases),
                    (SELECT files FROM releases WHERE pre_title<>'')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, 3, "two folded releases plus the named row");
    assert_eq!(named_files, 1, "the named row kept its single file");
    let posters: Vec<String> = {
        let mut stmt = ix
            .db
            .prepare("SELECT poster FROM releases WHERE pre_title='' ORDER BY poster")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap()
    };
    assert_eq!(posters, ["pa@h.tld", "pb@h.tld"], "one release per poster");
    teardown(&dir, ix);
}

#[test]
fn three_files_are_a_coincidence_not_a_session() {
    let (dir, mut ix) = fixture("floor");
    for stem in &STEMS[..3] {
        sess_file(&mut ix, "a.b.tv", "sess5@h.tld", stem, 5_000_000);
    }
    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!((sessions, folded, done), (0, 0, true));
    teardown(&dir, ix);
}

/// A session that STARTS inside a walk window's final overlap strip is
/// deferred whole to the next window instead of having its visible
/// half folded early - the invariant that keeps one posted session
/// from becoming two releases. The lone early row pins the walk's
/// starting window so the session lands in its overlap strip.
#[test]
fn a_session_straddling_a_window_folds_whole() {
    let (dir, mut ix) = fixture("straddle");
    // One lone population row anchors the first window at t0.
    sess_file(
        &mut ix,
        "a.b.tv",
        "lone@h.tld",
        "j8uw2kkl1hh52ii3jj42",
        5_000_000,
    );
    // The session starts 30 minutes before the first window's end and
    // runs 50 minutes - straight across the boundary.
    let t0 = 5_000_000 + 4 * 3_600 - 1_800;
    for (i, stem) in STEMS.iter().enumerate() {
        sess_file(&mut ix, "a.b.tv", "sess7@h.tld", stem, t0 + i as i64 * 750);
    }
    let (sessions, folded, done) = ix.session_fold(6_000_000, WALK).unwrap();
    assert_eq!(
        (sessions, folded),
        (1, 4),
        "one whole session, not two halves"
    );
    assert!(done);
    let files: i64 = ix
        .db
        .query_row(
            "SELECT files FROM releases WHERE poster='sess7@h.tld'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(files, 5, "all five files under one release");
    teardown(&dir, ix);
}

/// A session posted while the walk was already caught up still folds.
/// The catch-up break happens BEFORE the window SELECT, so the span
/// between the cursor and the horizon was never read; parking the
/// cursor on it would jump the walk over that span for good, and since
/// a maintenance lap is far shorter than WINDOW the walk would never
/// scan another window on a live daemon.
#[test]
fn a_session_posted_after_catch_up_still_folds() {
    let (dir, mut ix) = fixture("catchup");
    for (i, stem) in STEMS.iter().enumerate() {
        sess_file(
            &mut ix,
            "a.b.tv",
            "sess8@h.tld",
            stem,
            1_000_000 + i as i64 * 30,
        );
    }
    // Inside the settle margin plus one window: nothing is scannable
    // yet, so the call catches up having read no window at all.
    assert_eq!(ix.session_fold(1_010_000, WALK).unwrap(), (0, 0, true));
    // The unscanned span must not have been parked over.
    let parked: Option<i64> = ix.kv_get("session_fold_at").and_then(|v| v.parse().ok());
    assert!(
        parked.is_none_or(|c| c <= 1_000_000),
        "cursor {parked:?} jumped a span no window ever read"
    );
    // Time passes; the session's window is now clear of the margin.
    let (sessions, folded, done) = ix.session_fold(1_030_000, WALK).unwrap();
    assert_eq!((sessions, folded), (1, 4), "the session folds once seen");
    assert!(done);
    let rows: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1, "one release, not five junk rows forever");
    teardown(&dir, ix);
}

/// The rule the album fold hit live (`album_fold_merge`): a pass that
/// rewrites `kind`, `title_key` or `junk` on an existing row is doing
/// ingest's job and owes ingest's classification recoveries.
/// This fold rewrites `junk` - the merged row is N volumes, not one -
/// so the score it writes must be the score ingest's own
/// classification gives the kept stem, never a bare `classify`'s.
///
/// The stems here are a readable name carrying a scattered-caps hash
/// token, posted to a MUSIC group: the one shape in this fold's dark
/// population where `recover_kind_from_group` fires at all. The token
/// puts the row in the dark band while the words keep the parse off
/// `Kind::Other`, which the recovery refuses on purpose. It fires, and
/// the score does not move, because `stem_obfuscated` already pinned
/// that score at 70 - a measured finding, not a defect reproduction. This test is the guard on it: widen the `junk>=70`
/// screen, or give `junk_score` a kind branch below 70, and it reds
/// here instead of on a wall that has quietly hidden a row.
#[test]
fn a_folded_session_is_scored_the_way_ingest_scores_it() {
    let (dir, mut ix) = fixture("kindrecovery");
    let grp = "alt.binaries.sounds.mp3";
    let stems = [
        "Deliver.Us.From.Evil.gUSbVwIDqhrR",
        "Deliver.Us.From.Evil.kQZmTfjRWpbn",
        "Deliver.Us.From.Evil.xLNbGhqDVrtm",
        "Deliver.Us.From.Evil.pRWkYbnFQjsd",
        "Deliver.Us.From.Evil.vTHcMbrKWnpq",
    ];
    for (i, stem) in stems.iter().enumerate() {
        sess_file(&mut ix, grp, "sess9@h.tld", stem, 5_000_000 + i as i64 * 30);
    }
    let dark: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases WHERE junk>=70", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(dark, 5, "the members really are in this fold's band");
    assert_eq!(ix.session_fold(6_000_000, WALK).unwrap(), (1, 4, true));

    let (stem, kind, junk, bytes): (String, String, i64, i64) = ix
        .db
        .query_row(
            "SELECT stem, kind, junk, total_bytes FROM releases",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    // What ingest would have written for this stem in this group.
    let mut want = crate::categories::classify(&stem, &ix.custom);
    let bare = kind_str(&want.kind).to_string();
    crate::release::recover_media_kind(&mut want, &stem, &stem);
    crate::release::recover_kind_from_group(&mut want, grp, &stem);
    if !crate::index::ingest::stem_obfuscated(&stem, &want) {
        crate::release::recover_episode_from_group(&mut want, grp, &stem);
    }
    assert_ne!(
        bare,
        kind_str(&want.kind),
        "this stem must exercise the recovery, or the test proves nothing"
    );
    assert_eq!(
        junk,
        junk_score(&stem, &want, bytes as u64, false),
        "the fold scored its junk against a kind ingest would not have used"
    );
    // The fold writes no kind, so the column still holds ingest's -
    // which is the lane the score above was computed for.
    assert_eq!(kind, kind_str(&want.kind), "the lane and the score agree");
    teardown(&dir, ix);
}

// The correlation half of the story - a folded session carrying the
// TRUE size the walk needs, where its unfolded members were vetoed on
// ratio - lives in predb_tests/correlation_tests.rs beside the shatter
// fold's own correlation tests, which own the `tpre`/`dir` builders.

/// The session fold's loop really consults the pacer: a slice with a
/// budget for a few sessions folds some and then DECLINES one for want
/// of time, mid-window.
///
/// This is `a_fold_slice_declines_a_unit_it_has_no_time_for`
/// (`predb_tests::correlation_tests`) for this fold. Until 17 Sep 2026
/// only `shatter_fold` had one, and every call to this fold in the suite
/// passes the 60 s `WALK`, which a test-sized index can never spend - so
/// a pacer this loop silently stopped asking would have gone unnoticed.
/// The two assertions are that test's, and they are the ONLY two that
/// survive a shared box: `folds > 0` (the near wall - a budget too small
/// admits nothing past the read) and `take_refusals() > 0` (the pacer
/// said no at least once). There is NO wall-clock assertion on the
/// hold, and that test's doc comment lists the four formulations that
/// were tried and why each one either passes on both rules or reds
/// under load. Do not add one.
///
/// The one thing this asserts beyond the shatter test is that the
/// refusal was the MERGE loop's and not the outer walk's: this fold asks
/// `room()` once more after a window completes, before stepping to the
/// next, and a refusal there records the same count while proving
/// nothing about the loop that does the work. The discriminator is the
/// cursor, which `session_fold` writes only after a whole window
/// survives its merge loop: a slice that declined mid-window leaves it
/// unwritten. That is also what makes a zero-budget call a free read
/// sample (`testutil::probe_fold_cost`).
///
/// SIZING, REDONE FOR THIS FOLD'S OWN UNIT, and the shape of it is
/// different from the shatter test's in one way that decides everything
/// else. A unit here is one SESSION merge (`session_fold_members`), and
/// the walk has no sub-stride: a decline parks the cursor at the window
/// START, the next call re-reads the window, and a folded session
/// rescans to nothing, so a slice spends exactly the sessions it merged
/// and the fixture window is [1, SESSIONS) merges. But the pacer's first
/// unit, the population READ, scans the WHOLE window - every row of
/// every session in the fixture - where the shatter fold's sub-stride
/// read covers three stems. So this read costs `SESSIONS` times what a
/// merge's share of it would, and it cannot be made small relative to a
/// merge by choosing the fixture: measured on the dev Mac 17 Sep 2026,
/// a read of 0.4 ms against 400 rows and 5 ms against 10,000, while a
/// merge's own SQL is under a millisecond in either shape. The near
/// wall is the read dilated past `read + UNITS * merge / 2`, so with a
/// merge no dearer than the read one ordinary scheduler preemption
/// (10-60 ms on this fleet at load 100-230, measured) is the wall: two
/// shapes with the merge at or under the read failed 4 in 64 and 3 in
/// 128, 16 at a time, on exactly that.
///
/// WHAT MAKES A UNIT DEAR HERE, AND IT IS THE FOLD'S REAL UNIT. The
/// fixture is ingested through the real path in one batch per session,
/// 20,000 articles, and the WAL is left as ingest leaves it - past
/// `WAL_AUTOCHECKPOINT_PAGES`. Each merge's `tx.commit()` then carries
/// checkpoint work, which is the unit `foldpace`'s header measured on
/// the live 125 GB index ("50-350 ms of it is `tx.commit()`") and the
/// unit the pacer exists for. Measured 17 Sep 2026, 128 runs 16 at a
/// time at load 85-125: a merge priced between 0.5 ms and 167 ms across
/// runs, p50 12 ms, against a read of 0.4 ms (p90 1.0 ms) - and every
/// run passed, slices of 1 to 12 folds, because the spread is BETWEEN
/// runs and the walls only care about consistency WITHIN one: the probe
/// and the slice see the same regime in a given run. The control with a
/// `PRAGMA wal_checkpoint(TRUNCATE)` after ingest is what showed that:
/// merges fell to 0.5 ms, the read stayed at 0.4 ms, and the same test
/// failed 3 in 128 on both walls and the fixture guard. Nothing here
/// asserts the regime - a guard on WAL size would assert a mechanism
/// this test has measured but not proved - so the record is this
/// comment and section 7 of
/// research/FOLD-BUDGET-DERIVATION-CENSUS-2026-09-17.md, which also says
/// why `album_fold` did NOT get this test: its ingest lands the WAL just
/// under the threshold, the first fold commit past it pays the whole
/// checkpoint at once (0.4-1.9 s, measured, 31 times in 32 runs), and a
/// single unit five hundred times dearer than its neighbours is a
/// spread no window holds.
#[test]
fn a_session_fold_slice_declines_a_session_it_has_no_time_for() {
    /// Foldable units in the fixture, and the WINDOW the budget lands
    /// in. A hundred puts both walls a factor of ten from the geometric
    /// middle. Paid for in ingest only.
    const SESSIONS: usize = 100;
    /// Files per session: the fold's own floor, which keeps the window
    /// read at 400 rows. See the doc comment for why the read, and not
    /// the merge, is what the fixture has to keep small.
    const FILES: usize = 4;
    /// Parts per file. Fifty is what the measured campaign ran and is
    /// kept for that reason; the merge repoints one message-id row per
    /// part, so it is the one lever that moves a merge's own SQL
    /// without moving the read.
    const PARTS: u32 = 50;
    /// Merges' worth of budget on top of the admission floor, and the
    /// only term that buys work: `sqrt(SESSIONS)`, the geometric middle
    /// of the window. DO NOT RAISE IT when this reds - the far wall is
    /// the same failure as the near one. Widen `SESSIONS` and this
    /// follows by square root.
    const UNITS: u32 = 10;
    /// The most sessions ONE slice has been SEEN to take at [`UNITS`] =
    /// 10 - an observation and not a ceiling, and the fixture guard's
    /// number rather than an assertion's. Measured on the dev Mac
    /// 17 Sep 2026 at load 85-125, 16 at a time, 128 runs: p50 4, p90
    /// 11, worst 12; the probe spent at most 6.
    const SLICE_SATURATION: usize = 12;
    /// Every session inside ONE posting window, and that window is the
    /// walk's LAST: `hi - MAX_SPAN + WINDOW > horizon`, so a slice that
    /// completes it catches up rather than reading empty windows until
    /// the pacer stops it there. The sessions sit in the window's first
    /// three hours, clear of the final `MAX_SPAN` strip the fold defers.
    const T0: i64 = 5_000_000;
    const NOW: i64 = 5_027_200;

    let (dir, mut ix) = fixture("pacer");
    let build_t = std::time::Instant::now();
    for s in 0..SESSIONS {
        let poster = format!("sess{s:03}@h.tld");
        let posted = T0 + s as i64 * 30;
        let mut batch = Vec::with_capacity(FILES * PARTS as usize);
        for f in 0..FILES {
            // A 32-char blob stem per file, which is what the dark band
            // wears and what `stem_is_a_name` damns.
            let stem = format!(
                "{:032x}",
                0xe3b0c44298fc1c149afbf4c800000000u128 + (s * FILES + f) as u128
            );
            for p in 1..=PARTS {
                batch.push(OverEntry {
                    number: 0,
                    subject: format!("\"{stem}\" yEnc ({p}/{PARTS})"),
                    from: poster.clone(),
                    message_id: format!("<{stem}-{p}@sess>"),
                    bytes: 50_000_000,
                    date: posted,
                });
            }
        }
        ix.ingest("a.b.tv", &batch, posted).unwrap();
    }
    let built_in = build_t.elapsed();
    // The fold's own population screen, so a fixture that drifted out
    // of the dark band fails HERE and not as a slice that folded
    // nothing.
    let pop: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM releases
              WHERE junk>=70 AND pre_title='' AND complete=1 AND files=1
                AND need_parts>1 AND poster<>''",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        pop,
        (SESSIONS * FILES) as i64,
        "the family-S fixture really was built, every file in the band"
    );

    let probe = probe_fold_cost(built_in, |budget| {
        let (sessions, _, done) = ix.session_fold(NOW, budget).unwrap();
        (sessions, done)
    });
    let left = SESSIONS.saturating_sub(probe.spent);
    assert!(
        left > SLICE_SATURATION,
        "the probe spent {} of {SESSIONS} sessions and left {left}, but one \
         slice has been seen to take {SLICE_SATURATION} - this fixture can \
         no longer answer the question on this box. Raise SESSIONS.",
        probe.spent
    );
    assert!(
        ix.kv_get("session_fold_at").is_none(),
        "the probe completed the window, so its rounds were not the free \
         read samples the derivation prices them as"
    );

    let _ = super::foldpace::take_refusals();
    let budget = probe.budget(UNITS);
    let (folds, _, done) = ix.session_fold(NOW, budget).unwrap();
    let refusals = super::foldpace::take_refusals();
    eprintln!("SLICE budget={budget:?} folds={folds} done={done} refusals={refusals} left={left}");
    assert!(folds > 0, "slice folded nothing at all");
    assert!(
        refusals > 0,
        "slice ended without the pacer declining anything, so it says \
         nothing about whether the fold consults it"
    );
    assert!(
        ix.kv_get("session_fold_at").is_none(),
        "the slice folded all {folds} sessions left and completed the \
         window, so the refusal it recorded was the outer walk's - it \
         says nothing about the merge loop"
    );
    // No upper bound on `folds`, deliberately: the budget is derived
    // and any ceiling is a constant, which is the pairing that held
    // main red for a day on the shatter test. `SLICE_SATURATION` is
    // the fixture guard's number and is never asserted.
    teardown(&dir, ix);
}
