//! The album fold, end to end through real ingest: the two arms (a
//! scene mp3 post named by its `00-` furniture, an audiobook named by
//! what its track stems agree on), the guards that refuse a group
//! rather than guess at it, and the shapes the fold must leave alone.

use super::testutil::*;
use super::*;

fn fixture(name: &str) -> (std::path::PathBuf, Index) {
    let dir = std::env::temp_dir().join(format!("nzbfast-albfold-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    (dir, ix)
}

/// One complete single-file post: `parts` articles of one filename,
/// quoted in the subject the way a real poster writes it.
fn post(ix: &mut Index, grp: &str, poster: &str, name: &str, parts: u32, bytes: u64, posted: i64) {
    for p in 1..=parts {
        let e = OverEntry {
            number: 0,
            subject: format!("\"{name}\" yEnc ({p}/{parts})"),
            from: poster.into(),
            message_id: format!("<{name}-{p}@alb>"),
            bytes,
            date: posted,
        };
        ix.ingest(grp, &[e], posted).unwrap();
    }
}

fn rows(ix: &Index) -> i64 {
    ix.db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap()
}

const MUSIC: &str = "alt.binaries.sounds.mp3";
const ALBUM: &str = "gelugugu-masterpiece_cooking-freeweb-2020";

/// The measured shape: six tracks and four furniture rows, one poster,
/// one group, minutes apart.
fn scene_album(ix: &mut Index, poster: &str, album: &str, tracks: &[(u32, &str)], at: i64) {
    for ext in ["jpg", "nfo", "m3u", "sfv"] {
        post(
            ix,
            MUSIC,
            poster,
            &format!("00-{album}.{ext}"),
            1,
            40_000,
            at,
        );
    }
    for (n, title) in tracks {
        post(
            ix,
            MUSIC,
            poster,
            &format!("{n:02}-{title}.mp3"),
            2,
            4_000_000,
            at + i64::from(*n),
        );
    }
}

#[test]
fn a_scene_mp3_post_folds_into_one_album_named_by_its_furniture() {
    let (dir, mut ix) = fixture("scene");
    scene_album(
        &mut ix,
        "up@h.tld",
        ALBUM,
        &[
            (1, "gelugugu-blue_sky"),
            (2, "gelugugu-no_control"),
            (3, "gelugugu-cooking"),
            (4, "gelugugu-last_one"),
        ],
        5_000_000,
    );
    assert_eq!(rows(&ix), 8, "four tracks and four furniture rows");

    let (albums, folded, done) = ix.album_fold(6_000_000, WALK).unwrap();
    assert_eq!((albums, folded, done), (1, 7, true));

    let (stem, files, kind, total, complete): (String, i64, String, i64, bool) = ix
        .db
        .query_row(
            "SELECT stem, files, kind, total_bytes, complete FROM releases",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(rows(&ix), 1, "one album now");
    assert_eq!(stem, ALBUM, "the furniture named it, minus the 00- field");
    assert_eq!(files, 8, "every track AND its furniture came along");
    assert_eq!(kind, "music", "an extensionless scene album is music");
    assert_eq!(total, 4 * 2 * 4_000_000 + 4 * 40_000);
    assert!(complete, "every file we have seen is whole");
    let nfiles: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(nfiles, 8, "no file row lost");

    // The rewritten stem is searchable under its NEW name and not
    // under the track stem it used to wear - which is what the
    // hand-maintained rel_fts write is for, rel_fts having no UPDATE
    // trigger of its own.
    assert_eq!(
        ix.search_once("masterpiece", 10).unwrap().len(),
        1,
        "the album answers a search for its own name"
    );
    assert!(
        ix.search_once("no_control", 10).unwrap().is_empty(),
        "and the folded-away track stem is out of the FTS index"
    );
    // Idempotent, and the tallies are real.
    assert_eq!(ix.album_fold(6_000_100, WALK).unwrap(), (0, 0, true));
    assert_eq!(ix.kv_get("album_fold_rows").as_deref(), Some("7"));
    assert_eq!(ix.kv_get("album_fold_albums").as_deref(), Some("1"));
    teardown(&dir, ix);
}

#[test]
fn a_queue_of_albums_from_one_handle_cuts_at_the_furniture() {
    let (dir, mut ix) = fixture("twoalbums");
    // The measured shape: one scene handle posts album after album for
    // an hour. Each `00-` furniture name opens an album and owns the
    // tracks up to the next one, so both fold, separately.
    scene_album(
        &mut ix,
        "up@h.tld",
        ALBUM,
        &[
            (1, "gelugugu-blue_sky"),
            (2, "gelugugu-no_control"),
            (3, "gelugugu-cooking"),
            (4, "gelugugu-last_one"),
        ],
        5_000_000,
    );
    scene_album(
        &mut ix,
        "up@h.tld",
        "elsa_hewitt-out-freeweb-2021",
        &[
            (1, "elsa_hewitt-reaching_hands"),
            (2, "elsa_hewitt-slow_burn"),
            (3, "elsa_hewitt-eight"),
            (4, "elsa_hewitt-nine"),
        ],
        5_000_600,
    );
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (2, 14, true));
    let mut stems: Vec<String> = ix
        .db
        .prepare("SELECT stem FROM releases ORDER BY stem")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    stems.sort();
    assert_eq!(
        stems,
        vec![
            "elsa_hewitt-out-freeweb-2021".to_string(),
            ALBUM.to_string()
        ]
    );
    teardown(&dir, ix);
}

#[test]
fn interleaved_furniture_refuses_both_albums() {
    let (dir, mut ix) = fixture("interleaved");
    // Two albums posted at the same instant by one handle: their
    // furniture rows fall inside each other's interval, which is the
    // one cut this pass cannot make. Neither folds - a garbage union
    // of two albums is worse than the track cards it would replace.
    for album in [ALBUM, "elsa_hewitt-out-freeweb-2021"] {
        for ext in ["jpg", "nfo", "m3u", "sfv"] {
            post(
                &mut ix,
                MUSIC,
                "up@h.tld",
                &format!("00-{album}.{ext}"),
                1,
                40_000,
                5_000_000,
            );
        }
    }
    for (n, title) in [
        (1, "gelugugu-blue_sky"),
        (2, "gelugugu-no_control"),
        (3, "elsa_hewitt-eight"),
        (4, "elsa_hewitt-nine"),
    ] {
        post(
            &mut ix,
            MUSIC,
            "up@h.tld",
            &format!("{n:02}-{title}.mp3"),
            2,
            4_000_000,
            5_000_000 + i64::from(n),
        );
    }
    let before = rows(&ix);
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (0, 0, true));
    assert_eq!(rows(&ix), before, "nothing merged, nothing lost");
    teardown(&dir, ix);
}

#[test]
fn the_par2_anchor_keeps_its_scene_name_and_the_tracks_join_it() {
    let (dir, mut ix) = fixture("anchor");
    // The measured scene mp3 post in full: furniture, tracks, and the
    // par2 sidecar set that already wears the release name - the
    // furniture name plus the group tag. That row is the album card,
    // so the fold writes no stem at all.
    scene_album(
        &mut ix,
        "up@h.tld",
        ALBUM,
        &[
            (1, "gelugugu-blue_sky"),
            (2, "gelugugu-no_control"),
            (3, "gelugugu-cooking"),
            (4, "gelugugu-last_one"),
        ],
        5_000_000,
    );
    let scene = "Gelugugu-Masterpiece_Cooking-FREEWEB-2020-MFW";
    for v in ["", ".vol00+1", ".vol01+2"] {
        post(
            &mut ix,
            MUSIC,
            "up@h.tld",
            &format!("{scene}{v}.par2"),
            1,
            100_000,
            5_000_030,
        );
    }
    let (albums, folded, done) = ix.album_fold(6_000_000, WALK).unwrap();
    assert_eq!((albums, done), (1, true));
    assert_eq!(folded, 8, "four tracks and four furniture rows joined it");
    let (stem, files, kind, par2): (String, i64, String, bool) = ix
        .db
        .query_row(
            "SELECT stem, files, kind, has_par2 FROM releases",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(rows(&ix), 1);
    assert_eq!(stem, scene, "the anchor's own name, group tag and all");
    assert_eq!(files, 11, "3 par2 + 4 tracks + 4 sidecars");
    assert_eq!(kind, "music");
    assert!(par2, "the album can repair itself");
    teardown(&dir, ix);
}

#[test]
fn a_repeated_track_number_refuses_the_furniture_arm() {
    let (dir, mut ix) = fixture("dupnum");
    // One furniture set, but the window holds a second album's tracks
    // that brought none of its own: the giveaway is a repeated `01-`.
    scene_album(
        &mut ix,
        "up@h.tld",
        ALBUM,
        &[
            (1, "gelugugu-blue_sky"),
            (2, "gelugugu-no_control"),
            (3, "gelugugu-cooking"),
            (4, "gelugugu-last_one"),
        ],
        5_000_000,
    );
    post(
        &mut ix,
        MUSIC,
        "up@h.tld",
        "01-someone_else-a_song.mp3",
        2,
        4_000_000,
        5_000_400,
    );
    let before = rows(&ix);
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (0, 0, true));
    assert_eq!(rows(&ix), before);
    teardown(&dir, ix);
}

#[test]
fn one_track_posted_alone_stays_its_own_row() {
    let (dir, mut ix) = fixture("lone");
    post(
        &mut ix,
        MUSIC,
        "solo@h.tld",
        "01-elsa_hewitt-out-reaching_hands.mp3",
        2,
        4_000_000,
        5_000_000,
    );
    // And a two-track single is still under the floor.
    post(
        &mut ix,
        MUSIC,
        "duo@h.tld",
        "01-band-a_side.mp3",
        2,
        4_000_000,
        5_000_000,
    );
    post(
        &mut ix,
        MUSIC,
        "duo@h.tld",
        "02-band-b_side.mp3",
        2,
        4_000_000,
        5_000_010,
    );
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (0, 0, true));
    assert_eq!(rows(&ix), 3, "a legitimate post is not a broken album");
    teardown(&dir, ix);
}

#[test]
fn an_album_posted_as_one_release_is_never_touched() {
    let (dir, mut ix) = fixture("wholealbum");
    // The shape the fold must not disturb: one post, many files, an
    // already-correct scene name - a lossless album goes up as rar
    // volumes, so `release_stem` collapses all of them onto one stem
    // and the row is multi-FILE. This fold's population is single-file
    // rows, so the album is never even read.
    let name = "Paul_McCartney_And_Wings-Red_Rose_Speedway-32BIT-WAVPACK-1973-REETKEVER";
    for v in 1..=6 {
        post(
            &mut ix,
            MUSIC,
            "scene@h.tld",
            &format!("{name}.part{v:02}.rar"),
            2,
            9_000_000,
            5_000_000,
        );
    }
    assert_eq!(rows(&ix), 1, "one release before");
    let files: i64 = ix
        .db
        .query_row("SELECT files FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(files, 6);
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (0, 0, true));
    assert_eq!(rows(&ix), 1);
    teardown(&dir, ix);
}

#[test]
fn audiobook_tracks_fold_on_the_prefix_their_stems_agree_on() {
    let (dir, mut ix) = fixture("abook");
    let grp = "alt.binaries.audiobooks";
    for d in 94..=99 {
        post(
            &mut ix,
            grp,
            "reader@h.tld",
            &format!("Clive Cussler, Paul Kemprecos - (NUMA Files 8) Medusa - D0{d}.mp3"),
            1,
            7_000_000,
            5_000_000 + i64::from(d),
        );
    }
    // A second book by the same handle in the same window: the prefix
    // IS the separator, so both fold and neither contaminates the
    // other.
    for cd in 13..=16 {
        post(
            &mut ix,
            grp,
            "reader@h.tld",
            &format!("Stephen R. Donaldson-The Runes of the Earth-Unabridged-CD{cd}-07.mp3"),
            1,
            7_000_000,
            5_000_100 + i64::from(cd),
        );
    }
    assert_eq!(rows(&ix), 10);
    let (albums, folded, done) = ix.album_fold(6_000_000, WALK).unwrap();
    assert_eq!((albums, folded, done), (2, 8, true));
    let mut stems: Vec<String> = ix
        .db
        .prepare("SELECT stem FROM releases ORDER BY stem")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    stems.sort();
    assert_eq!(
        stems,
        vec![
            "Clive Cussler, Paul Kemprecos - (NUMA Files 8) Medusa".to_string(),
            "Stephen R. Donaldson-The Runes of the Earth-Unabridged".to_string(),
        ]
    );
    teardown(&dir, ix);
}

#[test]
fn loose_audiobook_files_join_the_par2_set_named_after_the_book() {
    let (dir, mut ix) = fixture("ofcounter");
    let grp = "alt.binaries.audiobooks";
    let book = "Clive Cussler - Trojan Odyssey";
    // The measured shape on the 2 Sep scratch index: `NN of MM` parts
    // beside a par2 set wearing the book's name, with no furniture and
    // no `00-` field anywhere.
    for v in ["", ".vol00+1"] {
        post(
            &mut ix,
            grp,
            "reader@h.tld",
            &format!("{book}{v}.par2"),
            1,
            90_000,
            5_000_000,
        );
    }
    for n in 4..=9 {
        post(
            &mut ix,
            grp,
            "reader@h.tld",
            &format!("{book} 0{n} of 14.mp3"),
            1,
            7_000_000,
            5_000_000 + i64::from(n),
        );
    }
    assert_eq!(rows(&ix), 7);
    let (albums, folded, done) = ix.album_fold(6_000_000, WALK).unwrap();
    assert_eq!((albums, folded, done), (1, 6, true));
    let (stem, files): (String, i64) = ix
        .db
        .query_row("SELECT stem, files FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(stem, book, "the par2 set's own name, unrewritten");
    assert_eq!(files, 8, "2 par2 + 6 parts");
    teardown(&dir, ix);
}

#[test]
fn tracks_that_share_no_prefix_are_left_as_they_are() {
    let (dir, mut ix) = fixture("noprefix");
    // A freeweb compilation with its furniture missing: every track a
    // different artist, so the prefix arm has nothing to agree on and
    // is inert by construction - which is exactly why the furniture is
    // the load-bearing name for music.
    for (n, who) in [
        (1, "elsa_hewitt-reaching_hands"),
        (2, "steve_luck-small_song"),
        (3, "gelugugu-blue_sky"),
        (4, "piero_piccioni-the_light"),
    ] {
        post(
            &mut ix,
            MUSIC,
            "comp@h.tld",
            &format!("{n:02}-{who}.mp3"),
            2,
            4_000_000,
            5_000_000 + i64::from(n),
        );
    }
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (0, 0, true));
    assert_eq!(rows(&ix), 4);
    teardown(&dir, ix);
}

#[test]
fn a_repeated_index_under_one_prefix_refuses_the_prefix_arm() {
    let (dir, mut ix) = fixture("duptail");
    let grp = "alt.binaries.audiobooks";
    for d in 1..=4 {
        post(
            &mut ix,
            grp,
            "reader@h.tld",
            &format!("A Long Book Title Here - D00{d}.mp3"),
            1,
            7_000_000,
            5_000_000 + i64::from(d),
        );
    }
    // The same book posted a second time in another format: a distinct
    // row wearing a REPEATED index under one prefix, which is the one
    // shape a shared prefix cannot tell apart from an album. Refuse the
    // key rather than union two postings into one release.
    post(
        &mut ix,
        grp,
        "reader@h.tld",
        "A Long Book Title Here - D001.flac",
        1,
        7_000_000,
        5_000_050,
    );
    assert_eq!(rows(&ix), 5);
    let (albums, _, _) = ix.album_fold(6_000_000, WALK).unwrap();
    assert_eq!(albums, 0, "ambiguous tails, nothing folded");
    assert_eq!(rows(&ix), 5);
    teardown(&dir, ix);
}

#[test]
fn a_folded_row_is_classified_the_way_ingest_classifies_it() {
    let (dir, mut ix) = fixture("kindrecovery");
    let grp = "alt.binaries.audiobooks";
    let book = "Rachel Amphlett - Scared to Death";
    for v in ["", ".vol00+1"] {
        post(
            &mut ix,
            grp,
            "r@h.tld",
            &format!("{book}{v}.par2"),
            1,
            90_000,
            5_000_000,
        );
    }
    for n in 1..=6 {
        post(
            &mut ix,
            grp,
            "r@h.tld",
            &format!("{book} 0{n} of 06.mp3"),
            1,
            7_000_000,
            5_000_000 + i64::from(n),
        );
    }
    // Before: the anchor is a par2 sidecar the group prior has already
    // recovered to a book.
    let was: String = ix
        .db
        .query_row("SELECT kind FROM releases WHERE stem=?1", [book], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(was, "book");
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (1, 6, true));
    // After: still a book, and still visible. A bare `classify` would
    // have made it an evidence-free movie at junk 60, which the wall
    // hides - strictly worse than the track cards it replaced.
    let (kind, junk): (String, i64) = ix
        .db
        .query_row("SELECT kind, junk FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(kind, "book");
    assert!(junk < 50, "junk {junk} would hide the album");
    teardown(&dir, ix);
}

#[test]
fn history_uncovered_by_backfill_rewinds_a_caught_up_walk() {
    let (dir, mut ix) = fixture("rewind");
    // A fresh install: the walk catches up over a nearly empty table.
    post(
        &mut ix,
        MUSIC,
        "someone@h.tld",
        "a_lone_file.mp3",
        1,
        4_000_000,
        5_900_000,
    );
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (0, 0, true));
    // Then a deepen leg brings in history from BELOW - which is where
    // this fold's whole backlog lives. Parked at the top, the walk
    // would sail over every album of it, forever.
    scene_album(
        &mut ix,
        "up@h.tld",
        ALBUM,
        &[
            (1, "gelugugu-blue_sky"),
            (2, "gelugugu-no_control"),
            (3, "gelugugu-cooking"),
            (4, "gelugugu-last_one"),
        ],
        5_000_000,
    );
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (1, 7, true));
    teardown(&dir, ix);
}

#[test]
fn a_fresh_post_inside_the_settle_margin_waits() {
    let (dir, mut ix) = fixture("settle");
    scene_album(
        &mut ix,
        "up@h.tld",
        ALBUM,
        &[
            (1, "gelugugu-blue_sky"),
            (2, "gelugugu-no_control"),
            (3, "gelugugu-cooking"),
            (4, "gelugugu-last_one"),
        ],
        5_000_000,
    );
    // `now` only minutes past the post: the whole span is inside the
    // two-hour settle margin, so the walk reports caught up and folds
    // nothing. An album still being ingested must not be halved.
    assert_eq!(ix.album_fold(5_000_600, WALK).unwrap(), (0, 0, true));
    assert_eq!(rows(&ix), 8);
    // Time passes; the same call now folds it.
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (1, 7, true));
    teardown(&dir, ix);
}

#[test]
fn the_helpers_read_the_names_the_memo_measured() {
    assert_eq!(
        super::albumfold::furniture_album("00-gelugugu-masterpiece_cooking-freeweb-2020.jpg")
            .as_deref(),
        Some("gelugugu-masterpiece_cooking-freeweb-2020")
    );
    // A two-field body is not the convention and would not parse as
    // music on the far side either.
    assert_eq!(
        super::albumfold::furniture_album("00-artist-album.nfo"),
        None
    );
    // No leading track field: an ordinary sidecar, not an album's.
    assert_eq!(super::albumfold::furniture_album("readme-first.nfo"), None);
    assert_eq!(
        super::albumfold::track_prefix("Clive Cussler - (NUMA Files 8) Medusa - D094.mp3"),
        Some((
            "Clive Cussler - (NUMA Files 8) Medusa".into(),
            " D094".into()
        ))
    );
    assert_eq!(
        super::albumfold::track_prefix("stephen r. donaldson-the runes of the earth-cd15-07.mp3"),
        Some((
            "stephen r. donaldson-the runes of the earth".into(),
            "-cd15-07".into()
        ))
    );
    // Scene music has no numeric tail, which is why the prefix arm
    // cannot fire on it.
    assert_eq!(
        super::albumfold::track_prefix("02-elsa_hewitt-out-reaching_hands.mp3"),
        None
    );
    // A base with no word in it is a numbering scheme, not a title.
    assert_eq!(super::albumfold::track_prefix("12895-1-11.mp3"), None);
    // An explicit "NN of MM" counter is cut whole, so the title's own
    // last word survives it.
    assert_eq!(
        super::albumfold::track_prefix("Clive Cussler - Trojan Odyssey 04 of 14.mp3"),
        Some(("Clive Cussler - Trojan Odyssey".into(), " 04 of 14".into()))
    );
    // The doubled index: cut at the EARLIER copy, so the base is the
    // book and not the book plus one track number.
    assert_eq!(
        super::albumfold::track_prefix(
            "David Baldacci - Deliver Us From Evil - 155 - Deliver Us From Evil - 155.mp3"
        ),
        Some((
            "David Baldacci - Deliver Us From Evil".into(),
            " 155 - Deliver Us From Evil - 155".into()
        ))
    );
    // A number in the title that is NOT the index is left alone.
    assert_eq!(
        super::albumfold::track_prefix("Clive Cussler - (NUMA Files 8) Medusa - D094.mp3"),
        Some((
            "Clive Cussler - (NUMA Files 8) Medusa".into(),
            " D094".into()
        ))
    );
    // "of" without a number in front of it is a title, not a counter.
    assert_eq!(
        super::albumfold::track_prefix("The Fellowship of the Ring.mp3"),
        None
    );
}

/// The third recovery, and the one this fold reaches for real: the
/// population is scoped by EXTENSION, so an audio dump in a group that
/// vouches for video is squarely in it.
///
/// Without `recover_episode_from_group` at the merge site the six
/// visible music cards below become one evidence-free movie at junk 60,
/// which the wall's default hides - the audiobook regression again,
/// with a different group doing the vouching. Delete the call and this
/// test reds on both assertions.
#[test]
fn a_folded_album_in_a_video_group_is_the_episode_ingest_would_have_read() {
    let (dir, mut ix) = fixture("epfromgroup");
    let grp = "alt.binaries.multimedia.anime";
    for n in 1..=6 {
        post(
            &mut ix,
            grp,
            "a@n.tld",
            &format!("Bleach - 187 - Ichigo Rages - 0{n}.mp3"),
            1,
            9_000_000,
            5_000_000 + i64::from(n),
        );
    }
    // Before: each track carries its own `.mp3` marker, so ingest made
    // it music at junk 0 - a visible card.
    let (was, wasj): (String, i64) = ix
        .db
        .query_row(
            "SELECT kind, junk FROM releases WHERE stem LIKE '%- 01.mp3'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((was.as_str(), wasj), ("music", 0));
    assert_eq!(ix.album_fold(6_000_000, WALK).unwrap(), (1, 5, true));
    let (stem, kind, junk): (String, String, i64) = ix
        .db
        .query_row("SELECT stem, kind, junk FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(stem, "Bleach - 187 - Ichigo Rages");
    assert_eq!(kind, "tv");
    assert!(junk < 50, "junk {junk} would hide the album");
    teardown(&dir, ix);
}

/// An anchor may append a GROUP TAG to the album name and nothing else.
///
/// The old rule was `starts_with(name)` plus a `-`, with the remainder
/// unconstrained, so a longer-named neighbour matched. Two audiobooks
/// by one poster about an hour apart is the shape that reaches it: arm
/// B searches anchors an hour either side of the tracks' own span, so
/// the sequel's PAR2 was in range, and the first book's tracks were
/// folded into the sequel's row - wall card and all.
#[test]
fn an_anchor_may_append_a_group_tag_and_not_another_title() {
    // What the fold is FOR, and must keep matching.
    assert!(super::albumfold::anchor_matches(
        "Gelugugu-Masterpiece_Cooking-FREEWEB-2020-MFW",
        "gelugugu-masterpiece_cooking-freeweb-2020"
    ));
    assert!(super::albumfold::anchor_matches(
        "Clive Cussler - Trojan Odyssey",
        "clive cussler - trojan odyssey"
    ));
    // A one-token tag, in any case.
    assert!(super::albumfold::anchor_matches("Album-grp", "album"));

    // And what it must now refuse: a remainder that is another title.
    assert!(
        !super::albumfold::anchor_matches(
            "Author - Short Name-Longer Sequel-GRP",
            "author - short name"
        ),
        "the sequel's PAR2 still claims the first book's tracks"
    );
    assert!(!super::albumfold::anchor_matches(
        "Album-Second Part",
        "album"
    ));
    assert!(!super::albumfold::anchor_matches("Album-a_b", "album"));
    // A bare trailing separator names no group at all.
    assert!(!super::albumfold::anchor_matches("Album-", "album"));
    // A longer name that does not break at a separator was never a
    // match and still is not.
    assert!(!super::albumfold::anchor_matches("Albumen", "album"));
}
