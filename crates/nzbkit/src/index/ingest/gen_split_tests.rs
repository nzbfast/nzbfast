//! The scanner's generation-split tests, out of `ingest.rs` under the
//! size gate (TODO 106). Every leg here drives the machinery under the
//! `---- the scanner's generation split ----` banner in the parent: the
//! sibling cap on minting, the two ways a saturated family still feeds
//! its own generation row, and the filename probe budget on a wide
//! cluster. `super` is still `ingest`, so the bodies are verbatim.

use super::*;
use crate::index::testutil::{entry, teardown};

/// The generation namespace is bounded: a reinjection flood (same
/// subject and poster, fresh message-ids every repost - observed at
/// 536k mints in 40 hours on a tester's box) mints marked siblings
/// only up to MAX_GEN_SIBLINGS, then drops the batch. Without the
/// cap the seventeenth row is invisible to `gen_candidates` (LIMIT),
/// can never be adopted, and every further repost mints another row
/// without bound (live index: one family reached 2,730 rows).
#[test]
fn generation_minting_stops_at_the_sibling_cap() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gencap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    let rows = |ix: &Index| -> i64 {
        ix.db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
            .unwrap()
    };
    // The same posting reinjected over and over: identical subject
    // and poster, a fresh message-id each time. Every batch
    // contradicts every row the previous ones created (same part
    // number, different id), so each mints one marked sibling -
    // until the cap.
    for i in 0..(MAX_GEN_SIBLINGS as usize + 8) {
        let b = vec![entry(
            "\"Flood.S01E01.mkv\" yEnc (1/1)",
            "bot@flood",
            &format!("reinject-{i}"),
            1000,
        )];
        ix.ingest("alt.test", &b, 1000 + i as i64).unwrap();
    }
    // One plain row plus exactly MAX_GEN_SIBLINGS marked rows; the
    // eight batches past the cap minted nothing.
    assert_eq!(rows(&ix), 1 + MAX_GEN_SIBLINGS);
    let marked: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM releases WHERE poster LIKE '%' || ? || '%'",
            [POSTER_GEN_MARK],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(marked, MAX_GEN_SIBLINGS);
    // A batch that agrees with an existing sibling still adopts it
    // rather than being dropped: re-send the very first reinjection.
    let again = vec![entry(
        "\"Flood.S01E01.mkv\" yEnc (1/1)",
        "bot@flood",
        "reinject-1",
        1000,
    )];
    ix.ingest("alt.test", &again, 5000).unwrap();
    assert_eq!(rows(&ix), 1 + MAX_GEN_SIBLINGS);
    teardown(&dir, ix);
}

/// The cap bounds MINTING, not feeding. A family already past
/// MAX_GEN_SIBLINGS (166k of them on the live index on 14 Aug 2026,
/// plus whatever the uncapped spot minting site pushes over) has
/// siblings the LIMITed candidate window cannot reach. When one of
/// those unreachable rows is the batch's own deterministic home -
/// a second server's scan of the same articles carrying parts the
/// first server's spool missed - the pre-fix code returned
/// Saturated and dropped the cluster on every scan, forever.
#[test]
fn a_saturated_family_still_feeds_its_exact_generation_row() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gensat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    /// One release row plus the single file row that decides whether
    /// it contradicts: part 1 under `part_id`.
    fn add_row(db: &rusqlite::Connection, stem: &str, poster: &str, part_id: &str) {
        db.execute(
            "INSERT INTO releases(stem, poster, grp, first_seen, first_posted)
             VALUES(?1, ?2, 'alt.test', 1000, 1000)",
            rusqlite::params![stem, poster],
        )
        .unwrap();
        let rid = db.last_insert_rowid();
        db.execute(
            "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
             VALUES(?1, 'Pin.S01E01.mkv', 2, 1000, ?2, 1)",
            rusqlite::params![rid, format!("[[1,\"{part_id}\",1000]]")],
        )
        .unwrap();
    }
    let rows = |ix: &Index| -> i64 {
        ix.db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
            .unwrap()
    };

    // The plain row, holding a DIFFERENT posting of the same name:
    // part 1 under another message-id, so it contradicts below.
    ix.ingest(
        "alt.test",
        &[entry(
            "\"Pin.S01E01.mkv\" yEnc (1/2)",
            "pin@x",
            "other-1",
            1000,
        )],
        1000,
    )
    .unwrap();
    let (stem, poster): (String, String) = ix
        .db
        .query_row("SELECT stem, poster FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();

    // The key is MD5 over the lowest part's message-id, so it is the
    // same value on every re-arrival of this article set - which is
    // what makes an existing row the batch's exact home.
    let key = msgid_set_key(["<pin-1@x>"])[..GEN_HEX].to_string();
    let fillers: Vec<String> = (0..MAX_GEN_SIBLINGS).map(|i| format!("{i:012x}")).collect();
    assert!(
        key.as_str() > fillers.last().unwrap().as_str(),
        "this pin needs the exact-home row to sort PAST the whole \
         candidate window, and MD5 fixed the key at {key}"
    );
    for (i, suffix) in fillers.iter().enumerate() {
        add_row(
            &ix.db,
            &stem,
            &format!("{poster}{POSTER_GEN_MARK}{suffix}"),
            &format!("<filler-{i}@x>"),
        );
    }
    add_row(
        &ix.db,
        &stem,
        &format!("{poster}{POSTER_GEN_MARK}{key}"),
        "<pin-1@x>",
    );
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS);

    // The same articles arrive again, this time with part 2 as well.
    // Every row the window can see contradicts them; only the row it
    // cannot see agrees.
    ix.ingest(
        "alt.test",
        &[
            entry("\"Pin.S01E01.mkv\" yEnc (1/2)", "pin@x", "pin-1@x", 1000),
            entry("\"Pin.S01E01.mkv\" yEnc (2/2)", "pin@x", "pin-2@x", 900),
        ],
        2000,
    )
    .unwrap();

    // Nothing minted (the cap still holds) and part 2 landed in the
    // exact-home row rather than being dropped.
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS);
    let parts = ix
        .db
        .query_row(
            "SELECT f.segments FROM files f
               JOIN releases r ON r.id = f.release_id
              WHERE r.poster = ?1",
            [format!("{poster}{POSTER_GEN_MARK}{key}")],
            |r| r.get::<_, crate::index::SegList>(0),
        )
        .unwrap()
        .0;
    assert_eq!(
        parts.len(),
        2,
        "the batch must have been merged into its exact home, got {parts:?}"
    );
    teardown(&dir, ix);
}

/// The exact-home key is a function of the batch's OWN coverage: it
/// hashes the lowest part number PRESENT of each file PRESENT. But
/// coverage GROWS - a second server's spool carries part 1 where the
/// first only had part 2, or carries a file the first never saw -
/// and the key the later batch computes is then not the key the row
/// was minted under. The point lookup missed, the LIMITed window
/// could not reach the row either, and the cluster was dropped on
/// every scan forever: the newly available parts could never be
/// added to the generation that was waiting for them.
///
/// The reverse `msgid_map` is the invariant evidence - an article id
/// does not change when its neighbours arrive - and the two
/// directions below are BOTH the point: the growing batch must land
/// in the row that already holds one of its articles, and a batch
/// that merely SHARES an article while disagreeing elsewhere must
/// still be kept out of it.
#[test]
fn a_saturated_family_feeds_its_row_when_coverage_grows() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gengrow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    /// One release row plus its file row, keyed into the reverse
    /// message-id map exactly as `ingest` keys its own writes.
    fn add_row(db: &rusqlite::Connection, stem: &str, poster: &str, parts: &[(u32, &str)]) -> i64 {
        db.execute(
            "INSERT INTO releases(stem, poster, grp, first_seen, first_posted)
             VALUES(?1, ?2, 'alt.test', 1000, 1000)",
            rusqlite::params![stem, poster],
        )
        .unwrap();
        let rid = db.last_insert_rowid();
        let segs: Vec<(u32, String, u64)> = parts
            .iter()
            .map(|(n, id)| (*n, (*id).into(), 1000))
            .collect();
        db.execute(
            "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
             VALUES(?1, 'Grow.S01E01.part01.rar', 2, 1000, ?2, ?3)",
            rusqlite::params![
                rid,
                serde_json::to_string(&segs).unwrap(),
                segs.len() as i64
            ],
        )
        .unwrap();
        claims::msgid_map_insert(db, rid, parts.iter().map(|(_, id)| *id)).unwrap();
        rid
    }
    let rows = |ix: &Index| -> i64 {
        ix.db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
            .unwrap()
    };
    let segs_of = |ix: &Index, rid: i64, fname: &str| -> Vec<(u32, String, u64)> {
        ix.db
            .query_row(
                "SELECT segments FROM files WHERE release_id=?1 AND filename=?2",
                rusqlite::params![rid, fname],
                |r| r.get::<_, crate::index::SegList>(0),
            )
            .unwrap()
            .0
    };

    // The plain row, holding a DIFFERENT posting of the same name.
    ix.ingest(
        "alt.test",
        &[entry(
            "\"Grow.S01E01.part01.rar\" yEnc (1/2)",
            "grow@x",
            "other-1@x",
            1000,
        )],
        1000,
    )
    .unwrap();
    let (stem, poster): (String, String) = ix
        .db
        .query_row("SELECT stem, poster FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();

    // The hidden row was minted when only PART 2 had been seen, so
    // its key hashes part 2's id. Sixteen fillers sort ahead of it,
    // which is what puts it past the candidate window.
    let key = msgid_set_key(["<grow-2@x>"])[..GEN_HEX].to_string();
    let fillers: Vec<String> = (0..MAX_GEN_SIBLINGS).map(|i| format!("{i:012x}")).collect();
    assert!(
        key.as_str() > fillers.last().unwrap().as_str(),
        "this pin needs the hidden row to sort PAST the whole candidate \
         window, and MD5 fixed the key at {key}"
    );
    for (i, suffix) in fillers.iter().enumerate() {
        add_row(
            &ix.db,
            &stem,
            &format!("{poster}{POSTER_GEN_MARK}{suffix}"),
            &[(1, &format!("<filler-{i}@x>"))],
        );
    }
    let hidden = add_row(
        &ix.db,
        &stem,
        &format!("{poster}{POSTER_GEN_MARK}{key}"),
        &[(2, "<grow-2@x>")],
    );
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS);

    // Coverage grows: another server's spool has part 1 as well, so
    // the batch's own key is now key(part 1) - not the key the row
    // carries. Every row the window can see contradicts it; the row
    // it cannot see shares part 2's article and contradicts nothing.
    ix.ingest(
        "alt.test",
        &[
            entry(
                "\"Grow.S01E01.part01.rar\" yEnc (1/2)",
                "grow@x",
                "grow-1@x",
                1000,
            ),
            entry(
                "\"Grow.S01E01.part01.rar\" yEnc (2/2)",
                "grow@x",
                "grow-2@x",
                900,
            ),
        ],
        2000,
    )
    .unwrap();
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS, "the cap still holds");
    let got = segs_of(&ix, hidden, "Grow.S01E01.part01.rar");
    assert_eq!(
        got.len(),
        2,
        "part 1 must have landed in the generation that was waiting for it, got {got:?}"
    );
    assert_eq!(got[0].1, "<grow-1@x>", "{got:?}");

    // The other half of the same trigger: a file the row has never
    // held moves the key just as surely as a lower part does.
    ix.ingest(
        "alt.test",
        &[
            entry(
                "\"Grow.S01E01.part01.rar\" yEnc (1/2)",
                "grow@x",
                "grow-1@x",
                1000,
            ),
            entry(
                "\"Grow.S01E01.part02.rar\" yEnc (1/2)",
                "grow@x",
                "vol2-1@x",
                1000,
            ),
        ],
        2500,
    )
    .unwrap();
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS, "the cap still holds");
    assert_eq!(
        segs_of(&ix, hidden, "Grow.S01E01.part02.rar").len(),
        1,
        "the new file belongs to the generation that already holds this posting"
    );

    // The other direction, and the one a too-permissive key would
    // break: a batch that SHARES part 1's article but disagrees on
    // part 2 is a different posting, and must stay out of the row it
    // just matched on. Dropped, not unioned.
    ix.ingest(
        "alt.test",
        &[
            entry(
                "\"Grow.S01E01.part01.rar\" yEnc (1/2)",
                "grow@x",
                "grow-1@x",
                1000,
            ),
            entry(
                "\"Grow.S01E01.part01.rar\" yEnc (2/2)",
                "grow@x",
                "mix-2@x",
                900,
            ),
        ],
        3000,
    )
    .unwrap();
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS, "the cap still holds");
    let got = segs_of(&ix, hidden, "Grow.S01E01.part01.rar");
    assert_eq!(
        got.iter()
            .map(|(n, id, _)| (*n, id.as_str()))
            .collect::<Vec<_>>(),
        vec![(1, "<grow-1@x>"), (2, "<grow-2@x>")],
        "a contradicting batch must not be unioned into the row it shares an article with"
    );

    // And a generation sharing NO article with anything reaches no
    // row at all - the reverse lookup is evidence, not a guess.
    ix.ingest(
        "alt.test",
        &[
            entry(
                "\"Grow.S01E01.part01.rar\" yEnc (1/2)",
                "grow@x",
                "flood-1@x",
                1000,
            ),
            entry(
                "\"Grow.S01E01.part01.rar\" yEnc (2/2)",
                "grow@x",
                "flood-2@x",
                900,
            ),
        ],
        4000,
    )
    .unwrap();
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS, "the cap still holds");
    assert_eq!(
        segs_of(&ix, hidden, "Grow.S01E01.part01.rar").len(),
        2,
        "untouched by a stranger"
    );
    teardown(&dir, ix);
}

/// M10 (read-only sweep 3): a WIDE cluster whose only shared article
/// sits in a late filename still finds its hidden home.
///
/// The probe budget is 32 ids and `msgid_map` keys 3 segments per
/// file, so spending it depth-first in sorted filename order ran out
/// after ~11 names. A cluster of 12 files whose out-of-window
/// generation shares an article only with the LAST one was therefore
/// never probed, `hidden_home` answered None, and the cluster was
/// dropped as Saturated - deterministically, on every rescan, so the
/// files that had just become available stayed out of the index for
/// good. Breadth-first spending covers every filename first.
#[test]
fn a_wide_cluster_probes_every_filename_not_just_the_first_eleven() {
    let dir = std::env::temp_dir().join(format!("nzbfast-genwide-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    // 12 files x 3 parts: more than the 11 filenames a depth-first
    // budget could reach.
    const FILES: u32 = 12;
    const PARTS: u32 = 3;
    let fname = |f: u32| format!("Wide.S01E01.part{f:02}.rar");
    let batch: Vec<crate::nntp::OverEntry> = (1..=FILES)
        .flat_map(|f| {
            (1..=PARTS).map(move |p| {
                entry(
                    &format!("\"{}\" yEnc ({p}/{PARTS})", fname(f)),
                    "wide@x",
                    &format!("wide-{f}-{p}@x"),
                    1000,
                )
            })
        })
        .collect();

    // The plain row: a DIFFERENT posting of the same name, so the
    // batch contradicts it.
    ix.ingest(
        "alt.test",
        &[entry(
            &format!("\"{}\" yEnc (1/{PARTS})", fname(1)),
            "wide@x",
            "other-1@x",
            1000,
        )],
        1000,
    )
    .unwrap();
    let (stem, poster): (String, String) = ix
        .db
        .query_row("SELECT stem, poster FROM releases", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();

    /// One release row plus one file row, keyed into the reverse
    /// message-id map exactly as `ingest` keys its own writes.
    fn add_row(
        db: &rusqlite::Connection,
        stem: &str,
        poster: &str,
        filename: &str,
        parts: &[(u32, &str)],
    ) -> i64 {
        db.execute(
            "INSERT INTO releases(stem, poster, grp, first_seen, first_posted)
             VALUES(?1, ?2, 'alt.test', 1000, 1000)",
            rusqlite::params![stem, poster],
        )
        .unwrap();
        let rid = db.last_insert_rowid();
        let segs: Vec<(u32, String, u64)> = parts
            .iter()
            .map(|(n, id)| (*n, (*id).into(), 1000))
            .collect();
        db.execute(
            "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
             VALUES(?1, ?2, ?3, 1000, ?4, ?5)",
            rusqlite::params![
                rid,
                filename,
                PARTS,
                serde_json::to_string(&segs).unwrap(),
                segs.len() as i64
            ],
        )
        .unwrap();
        claims::msgid_map_insert(db, rid, parts.iter().map(|(_, id)| *id)).unwrap();
        rid
    }
    let rows = |ix: &Index| -> i64 {
        ix.db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
            .unwrap()
    };

    // Sixteen contradicting siblings fill the candidate window; the
    // hidden row sorts past all of them, so only the reverse probe
    // can reach it. Its suffix is a literal rather than a real key
    // for the same reason the batch cannot find it by key: the key
    // is a function of coverage and this row was minted under
    // different coverage.
    for (i, suffix) in (0..MAX_GEN_SIBLINGS)
        .map(|i| format!("{i:012x}"))
        .enumerate()
    {
        add_row(
            &ix.db,
            &stem,
            &format!("{poster}{POSTER_GEN_MARK}{suffix}"),
            &fname(1),
            &[(1, &format!("<filler-{i}@x>"))],
        );
    }
    let hidden = add_row(
        &ix.db,
        &stem,
        &format!("{poster}{POSTER_GEN_MARK}ffffffffffff"),
        &fname(FILES),
        &[(1, &format!("<wide-{FILES}-1@x>"))],
    );
    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS);

    ix.ingest("alt.test", &batch, 2000).unwrap();

    assert_eq!(rows(&ix), 2 + MAX_GEN_SIBLINGS, "the cap still holds");
    let held: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM files WHERE release_id=?1",
            [hidden],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        held, FILES as i64,
        "every file of the batch must land in the generation that was \
         waiting for it - {held} of {FILES} did, so the cluster was dropped"
    );
    teardown(&dir, ix);
}

/// The same flood inside ONE OVER window, which is the pass loop's
/// half rather than the sibling cap's. Measured on live teevee traffic
/// 1 Sep 2026: 194 (poster, file, part) slots carrying 133-134 distinct
/// message-ids inside one 25,000-header window, so 91% of the window
/// deferred on the first pass and the leftover shrank by only the slot
/// count per pass - `[25000, 23257, 23058, 22862, 22668]`.
///
/// A pass places exactly one article per slot, so a batch can never
/// contribute more than `MAX_GEN_PASSES` generations however deep the
/// slot is. This pins BOTH halves of that: the rows are exactly the
/// ones the four-pass loop produced before the surplus was dropped
/// early (unchanged outcome), and the surplus is counted in the drop
/// census rather than carried through three more full passes to be
/// dropped at the end.
#[test]
fn a_flood_inside_one_window_places_one_generation_per_pass_and_counts_the_rest() {
    let dir = std::env::temp_dir().join(format!("nzbfast-genflood-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    // One slot, twelve reinjections - three times what the loop can
    // place, and a fortieth of what teevee really posts.
    const DEPTH: usize = 12;
    let batch: Vec<_> = (0..DEPTH)
        .map(|i| {
            entry(
                "\"Flood.S01E01.mkv\" yEnc (1/1)",
                "bot@flood",
                &format!("window-{i}"),
                1000,
            )
        })
        .collect();
    ix.ingest("alt.test", &batch, 1000).unwrap();

    let rows: i64 = ix
        .db
        .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        rows, MAX_GEN_PASSES as i64,
        "one window should contribute exactly MAX_GEN_PASSES generations"
    );
    assert_eq!(
        ix.kv_get("ingest_drop_gen_depth").as_deref(),
        Some((DEPTH - MAX_GEN_PASSES as usize).to_string().as_str()),
        "the surplus past the pass budget was not counted"
    );
    // And the ones that DID land are the first four ids, in arrival
    // order - the same four the old loop placed, one per pass.
    let mut placed: Vec<String> = ix
        .db
        .prepare("SELECT id FROM releases")
        .unwrap()
        .query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .map(|r| ix.make_nzb(r.unwrap()).unwrap())
        .collect();
    placed.sort();
    for i in 0..MAX_GEN_PASSES as usize {
        assert!(
            placed.iter().any(|n| n.contains(&format!("window-{i}"))),
            "window-{i} did not reach a row"
        );
    }
    for i in MAX_GEN_PASSES as usize..DEPTH {
        assert!(
            !placed.iter().any(|n| n.contains(&format!("window-{i}"))),
            "window-{i} reached a row past the pass budget"
        );
    }
    teardown(&dir, ix);
}

/// Stage 1 of the generation-row policy (1 Sep 2026): the per-group
/// slot-depth census that a depth-N cutoff has to be costed against.
/// It cannot be answered from stored rows - `MAX_GEN_SIBLINGS` truncates
/// stored family depth at exactly 17, so the 133-850 a live flood
/// reaches is nowhere in the index - which is why this counts forward
/// traffic at ingest instead.
///
/// Two quantities, and this pins the difference between them, because
/// whoever picks the cutoff reads `rows` and would otherwise read it as
/// slots. `slots` files each clashing slot at its own depth; `rows`
/// files a minted generation row at the depth of the SHALLOWEST
/// clashing slot in its cluster, because a cutoff at N only stops a
/// cluster reaching pass 2 when every one of its slots is at or past N.
/// The mixed cluster below is exactly that case: one slot 12 deep, one
/// 2 deep, and a cutoff at 9 would decline none of its three rows.
#[test]
fn the_depth_census_files_slots_by_depth_and_rows_by_their_cluster_floor() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gencensus-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    // One slot, twelve reinjections - the shape teevee posts, at a
    // fortieth of the depth. Every generation it mints is one a cutoff
    // at any N <= 12 would decline.
    const DEEP: usize = 12;
    let flood: Vec<_> = (0..DEEP)
        .map(|i| {
            entry(
                "\"Flood.S01E01.mkv\" yEnc (1/1)",
                "bot@flood",
                &format!("deep-{i}"),
                1000,
            )
        })
        .collect();
    ix.ingest("alt.test.deep", &flood, 1000).unwrap();

    // The same cluster carrying a 12-deep slot AND a 2-deep one. Part 2
    // is an ordinary two-generation part; part 1 is a flood. Silencing
    // part 1 at a cutoff of 9 leaves part 2 still deferring, so the
    // cluster still reaches passes 2-4 and mints the same three rows.
    let mut mixed: Vec<_> = (0..DEEP)
        .map(|i| {
            entry(
                "\"Mixed.S01E01.mkv\" yEnc (1/2)",
                "bot@mix",
                &format!("mix-a{i}"),
                1000,
            )
        })
        .collect();
    mixed.extend((0..2).map(|i| {
        entry(
            "\"Mixed.S01E01.mkv\" yEnc (2/2)",
            "bot@mix",
            &format!("mix-b{i}"),
            1000,
        )
    }));
    ix.ingest("alt.test.mixed", &mixed, 2000).unwrap();

    let n = |k: &str| -> u64 {
        ix.kv_get(k)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    // Per GROUP, not globally: teevee against everything else is the
    // whole discriminator, and a global total cannot show separation.
    assert_eq!(
        n("ingest_gen_depth_census_slots:alt.test.deep:0009_0012"),
        1,
        "the flood's one slot was not filed at its true depth"
    );
    assert_eq!(
        n("ingest_gen_depth_census_rows:alt.test.deep:0009_0012"),
        MAX_GEN_PASSES as u64 - 1,
        "a 12-deep cluster mints one generation per pass past the first"
    );
    assert_eq!(
        n("ingest_gen_depth_census_slots:alt.test.mixed:0009_0012"),
        1
    );
    assert_eq!(n("ingest_gen_depth_census_slots:alt.test.mixed:0002"), 1);
    assert_eq!(
        n("ingest_gen_depth_census_rows:alt.test.mixed:0002"),
        MAX_GEN_PASSES as u64 - 1,
        "a mixed cluster's rows belong to its SHALLOWEST slot - a cutoff \
         above 2 would not decline one of them"
    );
    assert_eq!(
        n("ingest_gen_depth_census_rows:alt.test.mixed:0009_0012"),
        0,
        "filing a mixed cluster's rows under its deepest slot overstates \
         what a cutoff there would reclaim"
    );
    // Nothing leaked across the group boundary.
    assert_eq!(n("ingest_gen_depth_census_slots:alt.test.deep:0002"), 0);
    // Cumulative counters with no window are a rate nobody can read, so
    // the first batch to count anything dates them. It is stamped once
    // and never moved: the second ingest's clock does not appear.
    assert_eq!(
        ix.kv_get("ingest_gen_depth_census_since").as_deref(),
        Some("1000")
    );
    teardown(&dir, ix);
}

/// The census reads back nested for a human: metric -> group -> bucket,
/// with the bucket vocabulary IN ORDER beside it. The order is the half
/// a reader cannot reconstruct - the cutoff question is "sum this bucket
/// and every deeper one" - and it must list buckets no group reached,
/// or a cutoff at an empty bucket looks unanswerable rather than free.
///
/// Also pins the two ways a prefix scan goes wrong. `_` is a LIKE
/// wildcard and this prefix carries five, so an unescaped scan would
/// report a stranger's `ingestXgen...` key as its own; and a key this
/// build does not understand is REPORTED under `unclassified`, not
/// silently dropped - the founding defect of the drop census next door.
#[test]
fn the_depth_census_reads_back_nested_and_reports_keys_it_does_not_know() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gencread-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();

    let flood: Vec<_> = (0..12)
        .map(|i| {
            entry(
                "\"Flood.S01E01.mkv\" yEnc (1/1)",
                "bot@flood",
                &format!("deep-{i}"),
                1000,
            )
        })
        .collect();
    ix.ingest("alt.binaries.teevee", &flood, 1_700_000_000)
        .unwrap();

    // A key one character off the prefix - `X` where the scan expects a
    // literal `_`. It must not appear anywhere in the answer.
    ix.kv_set("ingestXgen_depth_census_slots:alt.decoy:0002", "999")
        .unwrap();
    // A well-formed key naming a bucket this build has no label for.
    ix.kv_set("ingest_gen_depth_census_slots:alt.test:0009_0011", "7")
        .unwrap();

    let c = ix.gen_depth_census().unwrap();
    assert_eq!(c["slots"]["alt.binaries.teevee"]["0009_0012"], 1, "{c}");
    assert_eq!(c["rows"]["alt.binaries.teevee"]["0009_0012"], 3, "{c}");
    assert_eq!(c["since"], 1_700_000_000i64, "{c}");
    assert_eq!(c["window_known"], true, "{c}");
    assert_eq!(
        c["buckets"].as_array().unwrap().len(),
        GEN_DEPTH_BUCKETS.len(),
        "the whole bucket vocabulary is listed, reached or not: {c}"
    );
    assert_eq!(c["buckets"][0], "0002", "{c}");
    assert_eq!(
        c["unclassified"]["ingest_gen_depth_census_slots:alt.test:0009_0011"], "7",
        "an unknown bucket label is reported with its raw value, not dropped: {c}"
    );
    assert!(
        !c.to_string().contains("alt.decoy"),
        "the LIKE wildcards in the prefix were not escaped: {c}"
    );
    teardown(&dir, ix);
}
