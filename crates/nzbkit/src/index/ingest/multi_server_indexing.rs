use crate::index::testutil::teardown;
use crate::index::{BrowseQuery, Index};
use crate::nntp::OverEntry;

fn entry(subject: &str, from: &str, id: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: from.into(),
        message_id: format!("<{id}>"),
        bytes,
        date: 0,
    }
}

/// A8: a single-server-era marks table (PRIMARY KEY on grp alone)
/// migrates to the (grp, server) shape with its coverage intact, and
/// adopt_legacy_marks hands the '' rows to the historical primary
/// without ever clobbering a row that server has since written.
#[test]
fn marks_migrate_to_per_server_and_adoption_never_clobbers() {
    let dir = std::env::temp_dir().join(format!("nzbfast-marksmig-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("index.db");
    {
        // Build the old shape by hand, exactly as v1.0.10 left it.
        let db = rusqlite::Connection::open(&db_path).unwrap();
        db.execute_batch(
            "CREATE TABLE marks(grp TEXT PRIMARY KEY, high INTEGER NOT NULL);
                 ALTER TABLE marks ADD COLUMN low INTEGER NOT NULL DEFAULT 0;
                 INSERT INTO marks(grp, high, low) VALUES('alt.old', 500, 100);
                 INSERT INTO marks(grp, high, low) VALUES('spots:free.pt', 77, 0);",
        )
        .unwrap();
    }
    let ix = Index::open(&db_path).unwrap();
    // Migrated rows are visible to no server until adopted.
    assert_eq!(ix.high_water("alt.old", "news.first.example"), 0);
    ix.adopt_legacy_marks("News.FIRST.Example").unwrap();
    assert_eq!(ix.high_water("alt.old", "news.first.example"), 500);
    assert_eq!(ix.low_water("alt.old", "news.first.example"), 100);
    // Spot marks migrate the same way (they share the table).
    assert_eq!(ix.high_water("spots:free.pt", "news.first.example"), 77);
    // Adoption never clobbers what the server has since written: a
    // straggling legacy row for an already-claimed group is dropped.
    ix.set_high_water("alt.old", "news.first.example", 900)
        .unwrap();
    ix.db
        .execute(
            "INSERT INTO marks(grp, server, high, low) VALUES('alt.old', '', 1, 1)",
            [],
        )
        .unwrap();
    ix.adopt_legacy_marks("news.first.example").unwrap();
    assert_eq!(ix.high_water("alt.old", "news.first.example"), 900);
    // Idempotent: nothing legacy left.
    ix.adopt_legacy_marks("news.first.example").unwrap();
    // Per-server independence - the whole point of the migration.
    ix.set_high_water("alt.old", "other.example", 42).unwrap();
    assert_eq!(ix.high_water("alt.old", "other.example"), 42);
    assert_eq!(ix.high_water("alt.old", "news.first.example"), 900);
    // A fresh database gets the new shape directly (no rebuild): the
    // reopen must not have bumped anything - just prove reads work.
    drop(ix);
    let ix2 = Index::open(&db_path).unwrap();
    assert_eq!(ix2.high_water("alt.old", "news.first.example"), 900);
    teardown(&dir, ix2);
}

/// A8: two servers scanning the same group merge into one release -
/// message-ids are portable, so a part the first server's spool
/// never received completes the release when another backbone's
/// headers land. Overlap must not double-count.
#[test]
fn coverage_scans_from_two_servers_merge_and_complete() {
    let dir = std::env::temp_dir().join(format!("nzbfast-covmerge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    let grp = "alt.binaries.teevee";
    // Server A saw parts 1 and 2 of 3 (a propagation hole ate #3).
    let a = [
        entry(
            r#""Show.S01E02.720p-GRP.mkv" yEnc (1/3)"#,
            "p@x",
            "s1e2.p1",
            700_000,
        ),
        entry(
            r#""Show.S01E02.720p-GRP.mkv" yEnc (2/3)"#,
            "p@x",
            "s1e2.p2",
            700_000,
        ),
    ];
    ix.ingest(grp, &a, 1_000).unwrap();
    let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
    assert_eq!(r.len(), 1);
    assert!(!r[0].complete, "two of three parts is incomplete");
    // Server B carries parts 2 and 3 - same message-ids for the
    // overlap, which must merge rather than duplicate.
    let b = [
        entry(
            r#""Show.S01E02.720p-GRP.mkv" yEnc (2/3)"#,
            "p@x",
            "s1e2.p2",
            700_000,
        ),
        entry(
            r#""Show.S01E02.720p-GRP.mkv" yEnc (3/3)"#,
            "p@x",
            "s1e2.p3",
            700_000,
        ),
    ];
    let flipped = ix.ingest(grp, &b, 1_000).unwrap();
    assert_eq!(flipped, 1, "the merge is what completes the release");
    let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
    assert_eq!(r.len(), 1, "still one release, not one per server");
    assert!(r[0].complete);
    let nzb = ix.make_nzb(r[0].id).unwrap();
    let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
    assert_eq!(
        parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
        3,
        "the overlapping part must not be emitted twice"
    );
    teardown(&dir, ix);
}

/// A re-scan on a second provider must not revise the byte count of
/// a part already held down to that provider's own convention.
///
/// `:bytes` is a per-server approximation of one article, and two
/// backbones measurably state it two ways - the same article's line
/// terminators counted as CRLF or as LF, ~0.77% apart (measured 31
/// Aug 2026 across five providers; the body they deliver is
/// byte-identical). `gapfill` re-scans an incomplete release on the
/// SECONDARY provider by design, so a plain overwrite made
/// `total_bytes` track whichever server was asked last: 28% of a
/// banked 35,535-release census had moved three days later, 97.5% of
/// them downward, and 27 of them across a `junk_score` size
/// threshold. Both directions are pinned - the smaller count must
/// not win, and it must not be able to win by arriving first either.
#[test]
fn a_second_provider_never_shrinks_a_part_it_already_shares() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bytesconv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    let grp = "alt.binaries.teevee";
    let subj = |n: u32| format!(r#""Show.S01E03.720p-GRP.mkv" yEnc ({n}/2)"#);
    // The measured pair, from one real article on two backbones.
    const CRLF: u64 = 740_327;
    const LF: u64 = 734_624;
    // Primary states the CRLF convention and holds part 1 only.
    ix.ingest(grp, &[entry(&subj(1), "p@x", "s1e3.p1", CRLF)], 1_000)
        .unwrap();
    // Gapfill on the secondary re-states part 1 lower, and carries
    // the part the primary never saw with an OVER byte field it
    // could not parse - which reaches `ingest` as 0.
    ix.ingest(
        grp,
        &[
            entry(&subj(1), "p@x", "s1e3.p1", LF),
            entry(&subj(2), "p@x", "s1e3.p2", 0),
        ],
        1_000,
    )
    .unwrap();
    let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
    assert_eq!(r.len(), 1, "one release, not one per server");
    assert_eq!(
        r[0].total_bytes, CRLF,
        "the shared part keeps the larger count - this is the \
             assertion a plain overwrite fails"
    );
    // A stored 0 is healed by the next real count rather than
    // pinned. This is the assertion first-writer-wins fails, and it
    // is why the merge takes the larger count rather than the first.
    ix.ingest(grp, &[entry(&subj(2), "p@x", "s1e3.p2", LF)], 1_000)
        .unwrap();
    let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
    assert_eq!(
        r[0].total_bytes,
        CRLF + LF,
        "a zero count is not a floor the row can never leave"
    );
    // Monotone, so the stored number converges: re-stating either
    // count in either order changes nothing. The value must not
    // depend on which provider was asked last - which is the whole
    // defect - nor on which was asked first.
    ix.ingest(
        grp,
        &[
            entry(&subj(1), "p@x", "s1e3.p1", CRLF),
            entry(&subj(2), "p@x", "s1e3.p2", LF),
        ],
        1_000,
    )
    .unwrap();
    let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
    assert_eq!(
        r[0].total_bytes,
        CRLF + LF,
        "monotone: re-stating what is already stored changes nothing"
    );
    teardown(&dir, ix);
}

/// A8 gap-fill pick: only incomplete, junk-gated, settled releases
/// are worth re-hunting, and the stamp rotates the pick.
#[test]
fn gapfill_pick_gates_and_rotates() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gapfill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    let grp = "alt.binaries.teevee";
    let now = 1_000_000i64;
    let old = now - 100_000;
    // Eligible: incomplete, seen long ago.
    ix.ingest(
        grp,
        &[entry(
            r#""Old.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
            "p@x",
            "old.p1",
            300_000_000,
        )],
        old,
    )
    .unwrap();
    // Complete: nothing to hunt.
    ix.ingest(
        grp,
        &[entry(
            r#""Done.Show.S01E01.720p-GRP.mkv" yEnc (1/1)"#,
            "p@x",
            "done.p1",
            300_000_000,
        )],
        old,
    )
    .unwrap();
    // Too fresh: parts are usually still propagating.
    ix.ingest(
        grp,
        &[entry(
            r#""New.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
            "p@x",
            "new.p1",
            300_000_000,
        )],
        now - 60,
    )
    .unwrap();
    // Junk-hidden: must not eat the budget.
    ix.ingest(
        grp,
        &[entry(
            r#""Junky.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
            "p@x",
            "junk.p1",
            300_000_000,
        )],
        old,
    )
    .unwrap();
    ix.db
        .execute("UPDATE releases SET junk=90 WHERE stem LIKE 'Junky%'", [])
        .unwrap();
    let picks = ix.gapfill_pick(10, now).unwrap();
    assert_eq!(
        picks.len(),
        1,
        "only the settled incomplete release qualifies"
    );
    let (id, g, posted) = &picks[0];
    assert_eq!(g, grp);
    assert_eq!(*posted, old);
    assert!(!ix.is_complete(*id));
    // The stamp rotates: a marked release yields to unmarked ones.
    ix.ingest(
        grp,
        &[entry(
            r#""Also.Old.S01E01.720p-GRP.mkv" yEnc (1/2)"#,
            "p@x",
            "also.p1",
            300_000_000,
        )],
        old,
    )
    .unwrap();
    ix.gapfill_mark(*id, now).unwrap();
    let picks2 = ix.gapfill_pick(1, now).unwrap();
    assert_eq!(picks2.len(), 1);
    assert_ne!(picks2[0].0, *id, "the stamped release rotates to the back");
    teardown(&dir, ix);
}
