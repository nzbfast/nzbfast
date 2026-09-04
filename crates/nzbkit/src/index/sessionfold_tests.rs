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
    for stem in &STEMS[..4] {
        sess_file(&mut ix, "a.b.tv", "sess3@h.tld", stem, 5_000_000);
    }
    // The fifth member claims 3 parts and holds THREE parts numbered
    // 2..4: nsegs >= total so `complete=1`, and the cover is wrong.
    // That is exactly the row the proof exists to refuse - and one bad
    // member refuses the WHOLE candidate, because a session missing a
    // provable member is not a session, it is a guess.
    for p in 2..=4u32 {
        sess_article(
            &mut ix,
            "a.b.tv",
            "sess3@h.tld",
            "v2wf7ppq5qq96rr7ss86",
            p,
            3,
            50_000_000,
            5_000_000,
        );
    }
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
