use super::*;
use crate::index::testutil::{dated_entry, entry, teardown};

#[test]
fn split_subject_conventions() {
    // Canonical (n/m).
    assert_eq!(
        split_subject(r#"x - "f.rar" yEnc (5/50)"#),
        Some((r#"x - "f.rar" yEnc"#.to_string(), 5, 50))
    );
    // Trailing parenthesized tag must not shadow the counter.
    assert_eq!(
        split_subject(r#"x - "f.rar" yEnc (5/50) (German)"#).map(|(_, n, m)| (n, m)),
        Some((5, 50))
    );
    assert_eq!(
        split_subject(r#"x - "f.rar" yEnc (5/50) (4.2 GB)"#).map(|(_, n, m)| (n, m)),
        Some((5, 50))
    );
    // Bracketed and "of" counters.
    assert_eq!(
        split_subject("Release.part01.rar yEnc [1/50]").map(|(_, n, m)| (n, m)),
        Some((1, 50))
    );
    assert_eq!(
        split_subject(r#"x - "f.rar" yEnc (1 of 50)"#).map(|(_, n, m)| (n, m)),
        Some((1, 50))
    );
    // No counter at all.
    assert_eq!(split_subject("just a subject (German)"), None);
}

/// A LEADING pair is told from a trailing one by POSITION, never by
/// value: `[1/3] "x.mkv" yEnc (1/3)` carries the same numbers twice,
/// so a value test reads the trailing part counter as the session
/// tag and demotes a real three-part file to one segment.
#[test]
fn a_leading_pair_is_identified_by_position_not_by_value() {
    let at = |s: &str| split_subject_at(s).map(|(_, n, m, open)| (n, m, open));
    // The rightmost pair is taken, and it is NOT the leading one.
    let (n, m, open) = at(r#"[1/3] "x.mkv" yEnc (1/3)"#).unwrap();
    assert_eq!((n, m), (1, 3));
    assert!(
        !pair_is_leading(r#"[1/3] "x.mkv" yEnc (1/3)"#, open),
        "the trailing counter was read as the session tag"
    );
    // With no trailing counter, the leading tag IS what was taken.
    let (_, _, open) = at(r#"[01/15] "track01.mp3" yEnc"#).unwrap();
    assert!(pair_is_leading(r#"[01/15] "track01.mp3" yEnc"#, open));
    // Leading whitespace does not move the answer.
    let s = r#"   [01/15] "track01.mp3" yEnc"#;
    let (_, _, open) = at(s).unwrap();
    assert!(pair_is_leading(s, open));
}

/// `[NN/MM] "file.ext" yEnc` with no per-article counter: MM counts
/// the session's FILES, so each file is a one-segment file.
///
/// Fifteen tracks used to store `total_parts = 15` apiece, so every
/// one of them needed fifteen parts it would never get:
/// `RelAgg::complete` could not go true, and newznab, hunt's local
/// search and the album fold all stopped seeing the post.
#[test]
fn a_leading_file_of_session_tag_is_not_the_part_count() {
    let subjects: Vec<String> = (1..=15)
        .map(|i| format!(r#"[{i:02}/15] "track{i:02}.mp3" yEnc"#))
        .collect();
    let entries: Vec<OverEntry> = subjects
        .iter()
        .enumerate()
        .map(|(i, s)| entry(s, "poster@h.tld", &format!("m{i}"), 1000))
        .collect();
    let files = Index::session_totals_that_count_files(&entries);
    assert!(
        files.contains(&(entries[0].from.as_str(), 15)),
        "fifteen distinct filenames under one poster did not prove 15 counts files"
    );
}

/// THE CONTROL ARM, and the reason the demotion needs evidence at
/// all: a poster who genuinely LEADS with the part counter has ONE
/// filename under many n, which is the opposite shape. Demoting it
/// would store a 50-part file as one complete segment - the garbage
/// `contradicts` exists to refuse.
#[test]
fn a_leading_part_counter_over_one_file_is_left_alone() {
    let subjects: Vec<String> = (1..=50)
        .map(|i| format!(r#"[{i}/50] "movie.mkv" yEnc"#))
        .collect();
    let entries: Vec<OverEntry> = subjects
        .iter()
        .enumerate()
        .map(|(i, s)| entry(s, "poster@h.tld", &format!("m{i}"), 1000))
        .collect();
    let files = Index::session_totals_that_count_files(&entries);
    assert!(
        files.is_empty(),
        "one filename under fifty part numbers was read as a file count"
    );
}

/// TWO UNRELATED RELEASES, ONE POSTER, ONE WINDOW - the shape that
/// made the first cut of the demotion advertise a release complete
/// on a fiftieth of its bytes.
///
/// `[1/50] "Alpha.Movie.mkv"` and `[2/50] "Bravo.Movie.mkv"` are two
/// distinct filenames under one poster at two different `n`, which
/// is everything the first version tested for. Both demoted to
/// (1, 1), landed in two releases (different stems), and each read
/// COMPLETE holding one article. Two files is not a session: the
/// three-filename floor is what refuses it.
#[test]
fn two_lone_articles_under_one_poster_are_not_a_session() {
    let entries = vec![
        entry(r#"[1/50] "Alpha.Movie.mkv" yEnc"#, "p@x", "a1", 1000),
        entry(r#"[2/50] "Bravo.Movie.mkv" yEnc"#, "p@x", "b1", 1000),
    ];
    assert!(
        Index::session_totals_that_count_files(&entries).is_empty(),
        "two unrelated 50-part files were read as a two-file session"
    );

    // And the same shape through the real ingest path, so the
    // verdict under test is `RelAgg::complete` and not the helper's
    // set: neither release may claim to be complete.
    let dir = std::env::temp_dir().join(format!("nzbfast-sessdemote-a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.ingest("alt.test", &entries, 1000).unwrap();
    let hits = ix.search("", 10).unwrap();
    assert_eq!(hits.len(), 2, "expected two releases, one per stem");
    for r in &hits {
        assert!(
            !r.complete,
            "{} read complete holding {} of {} parts",
            r.stem, r.have_parts, r.need_parts
        );
        assert_eq!((r.have_parts, r.need_parts), (1, 50), "{}", r.stem);
    }
    teardown(&dir, ix);
}

/// ARM 1, THE VETO: one filename under two `n` is positive proof
/// that `m` counts the parts of that file, and it holds even when
/// other filenames sit beside it in the batch.
///
/// The first cut kept only the FIRST `n` per filename, so this batch
/// looked like {movie: 1, sample: 3} - two names, differing n - and
/// demoted all three articles onto part 1 of two one-segment files.
#[test]
fn one_filename_at_two_positions_vetoes_the_whole_key() {
    let entries = vec![
        entry(r#"[1/50] "Big.Movie.mkv" yEnc"#, "p@x", "a1", 1000),
        entry(r#"[2/50] "Big.Movie.mkv" yEnc"#, "p@x", "a2", 1000),
        entry(r#"[3/50] "Big.Sample.mkv" yEnc"#, "p@x", "s1", 1000),
    ];
    assert!(
        Index::session_totals_that_count_files(&entries).is_empty(),
        "a filename seen at two session positions did not veto the key"
    );
}

/// THE BACKFILL WINDOW, and the worst of the three: an OVER window
/// that opens mid-file. File A is caught from part 23, file B from
/// part 1, all under `[n/50]` with no trailing counter.
///
/// First-seen-only saw {A: 23, B: 1} - two names, differing n - and
/// demoted all 78 articles to (1, 1), collapsing 28 of A's parts and
/// 50 of B's onto part 1 of a one-segment file apiece. Arm 1 vetoes
/// on A alone. Left un-demoted, the truth survives: A holds 28 of
/// its 50 parts and is incomplete, B holds all 50 and is not.
#[test]
fn a_window_opening_mid_file_does_not_demote_the_poster() {
    let mut entries: Vec<OverEntry> = (23..=50)
        .map(|n| {
            entry(
                &format!(r#"[{n}/50] "Alpha.Movie.mkv" yEnc"#),
                "p@x",
                &format!("a{n}"),
                1000,
            )
        })
        .collect();
    entries.extend((1..=50).map(|n| {
        entry(
            &format!(r#"[{n}/50] "Bravo.Movie.mkv" yEnc"#),
            "p@x",
            &format!("b{n}"),
            1000,
        )
    }));
    assert!(
        Index::session_totals_that_count_files(&entries).is_empty(),
        "a window opening mid-file was read as a two-file session"
    );

    let dir = std::env::temp_dir().join(format!("nzbfast-sessdemote-d-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.ingest("alt.test", &entries, 1000).unwrap();
    let hits = ix.search("", 10).unwrap();
    assert_eq!(hits.len(), 2, "expected two releases, one per stem");
    let a = hits.iter().find(|r| r.stem.contains("Alpha")).unwrap();
    let b = hits.iter().find(|r| r.stem.contains("Bravo")).unwrap();
    assert_eq!((a.have_parts, a.need_parts), (28, 50));
    assert!(!a.complete, "a partly-caught 50-part file read complete");
    assert_eq!((b.have_parts, b.need_parts), (50, 50));
    assert!(b.complete, "a fully-caught 50-part file read incomplete");
    teardown(&dir, ix);
}

/// TWO ALBUMS FROM ONE STANDING HANDLE IN ONE WINDOW - the shape
/// that used to veto the demotion for BOTH of them.
///
/// Twenty-four tracks, two sessions of twelve, so every position
/// from 1 to 12 arrives twice. Plain position-uniqueness read that
/// as "not a session" and left all twenty-four tracks at
/// `total_parts = 12` holding one segment each: permanently
/// incomplete, and unfixable afterwards because D3 drops a later
/// batch that disagrees about the total.
#[test]
fn two_stacked_sessions_in_one_window_still_count_files() {
    let entries: Vec<OverEntry> = (1..=12)
        .flat_map(|n| {
            ["alpha", "bravo"].into_iter().map(move |album| {
                entry(
                    &format!(r#"[{n}/12] "{album}-track{n:02}.mp3" yEnc"#),
                    "p@x",
                    &format!("{album}{n}"),
                    1000,
                )
            })
        })
        .collect();
    assert!(
        Index::session_totals_that_count_files(&entries).contains(&("p@x", 12)),
        "two twelve-track sessions in one window were not read as file counts"
    );
}

/// ...and a RAGGED overlap is not a stack. Twelve positions, one of
/// them doubled and one of them absent, is not two whole sessions
/// and stays refused - the k-fold arm is exact on purpose.
#[test]
fn a_ragged_overlap_is_not_a_stacked_session() {
    let mut entries: Vec<OverEntry> = (1..=12)
        .map(|n| {
            entry(
                &format!(r#"[{n}/12] "alpha-track{n:02}.mp3" yEnc"#),
                "p@x",
                &format!("a{n}"),
                1000,
            )
        })
        .collect();
    entries.push(entry(
        r#"[3/12] "bravo-track03.mp3" yEnc"#,
        "p@x",
        "b3",
        1000,
    ));
    assert!(
        Index::session_totals_that_count_files(&entries).is_empty(),
        "one doubled position was read as two stacked sessions"
    );
}

/// THE FLOOR IS EXACTLY THREE, and a session position is unique.
/// Three tracks at three positions demote; the same three with two
/// of them claiming position 1 are not a session and do not.
#[test]
fn three_files_at_distinct_positions_is_the_smallest_session() {
    let three: Vec<OverEntry> = [1, 2, 3]
        .iter()
        .map(|n| {
            entry(
                &format!(r#"[{n}/12] "track{n:02}.mp3" yEnc"#),
                "p@x",
                &format!("t{n}"),
                1000,
            )
        })
        .collect();
    assert!(
        Index::session_totals_that_count_files(&three).contains(&("p@x", 12)),
        "three tracks at three positions were not read as a session"
    );

    let collided: Vec<OverEntry> = [1, 1, 2]
        .iter()
        .enumerate()
        .map(|(i, n)| {
            entry(
                &format!(r#"[{n}/12] "track{i:02}.mp3" yEnc"#),
                "p@x",
                &format!("c{i}"),
                1000,
            )
        })
        .collect();
    assert!(
        Index::session_totals_that_count_files(&collided).is_empty(),
        "two files sharing session position 1 were read as a session"
    );
}

#[test]
fn quoted_name_conventions() {
    // Quoted, with a decoy quoted run first.
    assert_eq!(
        quoted_name(r#""S01E01" - "Show.part01.rar" yEnc"#),
        Some("Show.part01.rar".to_string())
    );
    // Unquoted convention.
    assert_eq!(
        quoted_name("Release.Name.part01.rar yEnc"),
        Some("Release.Name.part01.rar".to_string())
    );
    assert_eq!(
        quoted_name("Backup.7z.001 yEnc"),
        Some("Backup.7z.001".to_string())
    );
    // Size fragments and version dots are not filenames.
    assert_eq!(quoted_name("Big Release 4.2GB yEnc"), None);
    assert_eq!(quoted_name("Release v1.0 done"), None);
    // T5: this reader calls `nzb::quoted_filename` DIRECTLY, not
    // `NzbFile::filename_hint`, so it inherits the agreeing-run pick
    // only because the rule lives at the pick. A header on the
    // N6-04 ambiguity class - two dotted quoted runs whose kinds
    // disagree, so the subject is `Data` - used to index the row
    // under the recovery-volume name, which is what release
    // grouping and the junk scorer then read. It indexes under the
    // payload name now, and this row is what would go red if the
    // rule were ever moved up to `filename_hint` and forked in two.
    assert_eq!(
        quoted_name(r#""label.vol000+50.par2" - "Movie.mkv" yEnc"#),
        Some("Movie.mkv".to_string())
    );
}

#[test]
fn junk_v6_evidence_free_media_and_lecture_dumps() {
    let score = |stem: &str, bytes: u64| {
        let p = crate::release::parse_release(stem);
        junk_score(stem, &p, bytes, false)
    };
    // Course/lecture dumps (real leaks from a live teevee+moovee
    // index): numbered tracks and bare-words media files.
    assert!(score("003 - Estômago.mp4", 100 << 20) >= 50);
    assert!(score("056 - Ortografia II.mp4", 200 << 20) >= 50);
    assert!(score("aula.mp4", 700 << 20) >= 50);
    assert!(score("Configurando Dsers.mp4", 80 << 20) >= 50);
    assert!(score("misfits-wegedeutschensd", 100 << 20) >= 50);
    // Track prefix wins even when a year parses further in.
    assert!(score("065 - Estatística RLM 2019.mp4", 400 << 20) >= 50);
    // Bracket-hex repost spam - inner name parses real, still junk.
    assert!(
        score(
            "[3b9550c02c]_[newzNZB]_atlanta.s01e10.1080p.hdtv.x264-xpert",
            50 << 20
        ) >= 50
    );
    // Anime subgroup brackets are words, not hex - clean.
    assert!(score("[SubsPlease] Frieren - S01E01 (1080p) [ABCD1234]", 1 << 30) < 50);
    // Real releases with any single marker survive.
    assert!(score("Some.Documentary.2020.mp4", 2 << 30) < 50);
    assert!(
        score(
            "slings.and.arrows.s01e03.proper.dvdrip.xvid-nodlabs",
            300 << 20
        ) < 50
    );
    assert!(
        score(
            "Robin.Hood.2010.Theatrical.Cut.BluRay.1080p.DTS-X.7.1.AVC.HYBRID.REMUX-FraMeSToR.mkv",
            33 << 30
        ) < 50
    );
    // "24.S01E01" style: leading digits but a parsed episode - clean.
    assert!(score("24.S01E01.1080p.WEB.h264-GRP", 2 << 30) < 50);
    // Evidence-free software-ish name is hidden by the same rule.
    assert!(score("Topaz Video AI Pro 8.1.6", 500 << 20) >= 50);
    // Sub-200 MB "HD movie" posts are fakes; a real small movie
    // without an HD claim (old SD rip) survives, and TV stays
    // exempt (short-form episodes are legitimately tiny).
    assert!(score("Dont.Breathe.2016.1080p.WEB-DL.DD5.1.H264-FGT", 180 << 20) >= 50);
    assert!(score("Old.Short.Film.1962.DVDRip.XviD-GRP", 180 << 20) < 50);
    assert!(score("some.show.s01e04.720p.hdtv.x264-grp", 150 << 20) < 50);
}

#[test]
fn dropped_articles_are_counted_not_silent() {
    // Commissioning memo rec 3: an article whose subject carries no
    // filename (the ngPost --obfuscate shape - the subject is a
    // bare token, no quotes, no name.ext) used to vanish without a
    // trace. The drop still happens; the COUNT no longer hides.
    let dir = std::env::temp_dir().join(format!("nzbfast-index-drop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.test",
        &[
            entry("aGVsbG8gb2JmdXNjYXRlZA (1/50)", "a@a", "d1", 700_000),
            entry("bm8gbmFtZSBoZXJlIGVpdGhlcg (2/50)", "b@b", "d2", 700_000),
            entry(
                "\"Kept.Release.2026.1080p-GRP.mkv\" yEnc (1/1)",
                "c@c",
                "d3",
                4 << 30,
            ),
        ],
        1_000,
    )
    .unwrap();
    let rows: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        rows, 1,
        "the named article placed, the obfuscated two did not"
    );
    assert_eq!(
        ix.kv_get("ingest_drop_no_filename").as_deref(),
        Some("2"),
        "both no-filename drops counted"
    );
    assert!(
        ix.kv_get("ingest_drop_unparseable").is_none(),
        "no unparseable drops on this batch"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_drop_census_reads_back_as_two_families_over_a_known_window() {
    // The counters existed for a day before anything read one. This
    // is the read side: the three outright drops in one family, the
    // pass-budget surplus in another (those articles come back on
    // the next scan of the window, so summing the two would be a
    // category error), and a window that says when counting began.
    let dir = std::env::temp_dir().join(format!("nzbfast-index-census-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.test",
        &[
            entry("aGVsbG8gb2JmdXNjYXRlZA (1/50)", "a@a", "d1", 700_000),
            entry("bm8gbmFtZSBoZXJlIGVpdGhlcg (2/50)", "b@b", "d2", 700_000),
            entry(
                "\"Kept.Release.2026.1080p-GRP.mkv\" yEnc (1/1)",
                "c@c",
                "d3",
                4 << 30,
            ),
        ],
        1_000,
    )
    .unwrap();
    let c = ix.ingest_drop_census().unwrap();
    assert_eq!(c["dropped"]["no_filename"], 2, "both no-filename drops");
    assert_eq!(
        c["dropped"]["empty_stem"], 0,
        "a counter that never fired reads as a zero, not as a missing field"
    );
    assert_eq!(c["dropped"]["unparseable"], 0);
    assert_eq!(c["dropped_total"], 2);
    assert_eq!(
        c["over_budget"]["gen_depth"], 0,
        "the surplus family is reported separately and is not in the total"
    );
    assert_eq!(c["unclassified"], serde_json::json!({}));
    assert_eq!(
        c["window_known"], true,
        "this index started counting on its first batch"
    );
    assert!(
        c["since"].as_i64().unwrap_or(0) > 1_700_000_000,
        "the window opens at a real clock, not zero: {}",
        c["since"]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_census_that_was_already_counting_reports_an_unknown_window() {
    // An index that has been scanning for weeks carries millions of
    // drops counted before the window stamp existed (the measured
    // case was 5.8M). Stamping one NOW would date them to this
    // afternoon, so the stamp declines and the readout says so - an
    // unknown window is the honest answer, not a defect.
    //
    // The two decoy keys are the other half: an `ingest_drop_*` name
    // this build does not know must be REPORTED rather than dropped
    // (that is how the next counter avoids being invisible for a day
    // like these four were), and `_` being a LIKE wildcard, a key
    // that only matches with the wildcards live must not be scanned
    // at all.
    let dir = std::env::temp_dir().join(format!("nzbfast-index-census2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.kv_set("ingest_drop_no_filename", "5000000").unwrap();
    ix.kv_set("ingest_drop_future_thing", "7").unwrap();
    ix.kv_set("ingestXdropY_bogus", "9").unwrap();
    ix.ingest(
        "alt.binaries.test",
        &[entry("aGVsbG8gb2JmdXNjYXRlZA (1/50)", "a@a", "d1", 700_000)],
        1_000,
    )
    .unwrap();
    assert!(
        ix.kv_get(super::DROP_SINCE_KEY).is_none(),
        "an index that was already counting is never stamped retroactively"
    );
    let c = ix.ingest_drop_census().unwrap();
    assert_eq!(c["window_known"], false);
    assert_eq!(c["since"], serde_json::Value::Null);
    assert_eq!(
        c["dropped"]["no_filename"], 5_000_001,
        "the batch adds to what was there"
    );
    assert_eq!(
        c["unclassified"]["ingest_drop_future_thing"], "7",
        "a counter this build does not know is reported under its own key, meaning unclaimed"
    );
    assert!(
        c["unclassified"].get("ingestXdropY_bogus").is_none(),
        "the `_` in the prefix is escaped, so the scan is a prefix and not a pattern"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn executable_content_junks_media_releases() {
    // M32 (Prowlarr#2329): an .exe inside a movie/TV-shaped release is
    // flagged past the default-hide line; Software releases keep their
    // normal score (executables are their content).
    let dir = std::env::temp_dir().join(format!("nzbfast-index-exe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    let mk =
        |f: &str, from: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30);
    ix.ingest(
        "alt.binaries.test",
        &[
            mk("Some.Movie.2026.1080p.BluRay.x264-GRP.exe", "a@a", "x1"),
            mk("Clean.Movie.2026.1080p.BluRay.x264-GRP.mkv", "b@b", "x2"),
        ],
        1_000,
    )
    .unwrap();
    // Both rows exist, but the junk ceiling hides the exe-carrying one.
    let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
    assert_eq!(total_all, 2);
    let (rows, total) = ix
        .browse(&BrowseQuery {
            max_junk: Some(50),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(total, 1, "exe-carrying movie must be junk-hidden: {rows:?}");
    assert!(rows[0].stem.contains("Clean.Movie"), "{rows:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sample_token_only_junks_sample_sized_posts() {
    // M32: a full-size release with "sample"
    // in its TITLE is not furniture; a tens-of-MB one is.
    let dir = std::env::temp_dir().join(format!("nzbfast-index-smp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.test",
        &[
            entry(
                "\"The.Free.Sample.2026.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)",
                "a@a",
                "s1",
                4 << 30,
            ),
            entry(
                "\"Other.Movie.2026.1080p-GRP.sample.mkv\" yEnc (1/1)",
                "b@b",
                "s2",
                60 << 20,
            ),
        ],
        1_000,
    )
    .unwrap();
    let (rows, total) = ix
        .browse(&BrowseQuery {
            max_junk: Some(50),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(total, 1, "only the real sample is hidden: {rows:?}");
    assert!(rows[0].stem.contains("Free.Sample"), "{rows:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The arrivals counter lives in `kv`, and three separate code paths
/// do `DELETE FROM kv WHERE k=...`. If that row ever went missing the
/// trigger's `SELECT v FROM kv` yielded NULL, the `UPDATE releases
/// SET arrival_seq=NULL` hit the NOT NULL constraint, and the whole
/// ingest transaction rolled back - one mistyped key away from an
/// index that can never be written to again. The fallback makes the
/// worst case a duplicate cursor value, not a dead database.
#[test]
fn arrival_seq_trigger_survives_a_missing_counter_row() {
    let dir = std::env::temp_dir().join(format!("nzbfast-arrseq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    ix.ingest(
        "alt.test",
        &[dated_entry(
            "\"Before.Wipe.S01E01.mkv\" yEnc (1/1)",
            "b1",
            91_000,
        )],
        100_000,
    )
    .unwrap();

    // Somebody's kv cleanup took the counter with it.
    ix.db
        .execute("DELETE FROM kv WHERE k='wall_arrival_seq'", [])
        .unwrap();

    ix.ingest(
        "alt.test",
        &[dated_entry(
            "\"After.Wipe.S02E02.mkv\" yEnc (1/1)",
            "a1",
            95_000,
        )],
        101_000,
    )
    .expect("a missing kv row must not take the ingest transaction down with it");

    // The release really landed, and it carries a usable cursor
    // value rather than the 0 that means "not yet claimed".
    let (n, seq): (i64, i64) = ix
        .db
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(arrival_seq), 0) FROM releases",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(n, 2, "both releases are in the table");
    assert!(
        seq > 0,
        "the fallback gave the new row a real cursor, got {seq}"
    );

    // An index that predates this fix carries the old trigger, so the
    // upgrade has to replace it - a database still running the
    // original definition is still fail-dead.
    let old: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='trigger' AND name='rel_arrival_seq_ai'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old, 0, "the pre-fix trigger must be dropped on open");

    // And the counter heals itself on the next open, so the id
    // fallback stays a one-insert stopgap rather than the new normal.
    drop(ix);
    let ix = Index::open(&dir.join("index.db")).unwrap();
    let restored: i64 = ix
        .db
        .query_row(
            "SELECT CAST(v AS INTEGER) FROM kv WHERE k='wall_arrival_seq'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        restored, seq,
        "re-open restored the counter from MAX(arrival_seq)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ingest_cluster_search_synthesize() {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    // Two batches split mid-file: merging must complete the release.
    let b1 = vec![
        entry("\"Show.S01E01.part1.rar\" yEnc (1/2)", "p@x", "a1", 1000),
        entry("\"Show.S01E01.part2.rar\" yEnc (1/1)", "p@x", "b1", 900),
        entry("\"Show.S01E01.par2\" yEnc (1/1)", "p@x", "c1", 100),
    ];
    let b2 = vec![entry(
        "\"Show.S01E01.part1.rar\" yEnc (2/2)",
        "p@x",
        "a2",
        1000,
    )];
    assert_eq!(ix.ingest("alt.test", &b1, 1000).unwrap(), 0); // part1 incomplete
    assert_eq!(ix.ingest("alt.test", &b2, 1001).unwrap(), 1); // now complete

    // Separator-insensitive, multi-term AND search: a dotted stem
    // must match a space-separated *arr query (and vice-versa).
    assert_eq!(ix.search("show.s01e01", 10).unwrap().len(), 1);
    assert_eq!(ix.search("show s01e01", 10).unwrap().len(), 1);
    assert_eq!(ix.search("SHOW", 10).unwrap().len(), 1);
    assert_eq!(ix.search("s01e01 show", 10).unwrap().len(), 1); // order-free
    assert_eq!(ix.search("show s09e09", 10).unwrap().len(), 0); // term absent
    assert_eq!(ix.search("", 10).unwrap().len(), 1); // empty = all

    let hits = ix.search("show.s01e01", 10).unwrap();
    assert_eq!(hits.len(), 1);
    let r = &hits[0];
    assert!(r.complete && r.has_par2);
    assert_eq!(r.files, 3);
    assert_eq!(r.total_bytes, 3000);

    // NZB synthesis parses and carries every segment.
    let nzb = ix.make_nzb(r.id).unwrap();
    let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
    assert_eq!(parsed.files.len(), 3);
    assert_eq!(
        parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
        4
    );

    // High-water marks persist, independently per server (A8:
    // article numbers are per-server, message-ids are not).
    ix.set_high_water("alt.test", "News.EXAMPLE.com", 42)
        .unwrap();
    assert_eq!(ix.high_water("alt.test", "news.example.com"), 42);
    assert_eq!(ix.high_water("alt.test", "other.example.com"), 0);
    assert_eq!(ix.stats().unwrap(), (1, 1));
    teardown(&dir, ix);
}
