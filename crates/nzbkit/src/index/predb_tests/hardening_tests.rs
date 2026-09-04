//! Suggest-only hardening: the red-team round of 10 Aug 2026.
//!
//! What that adversarial pass went after, and what holds it now - the
//! naming population gates (a stem a human can READ is not obfuscated,
//! and a shape the byte probe can name is not correlation's to guess),
//! the probe shape matchers, a batch outcome that does not depend on
//! the order the pres arrived in, a quality bump rerun that keeps names
//! applied, the two fold shapes the round broke (distinct archive
//! volume filenames, a posting past the member cap), a replacement
//! pairing that starts unchecked, and the named-index build stamped
//! once and drained.
//!
//! A sibling of correlation_tests under predb_tests, cut at its own
//! banner and out here for the same ceiling (TODO 106). `overd` and
//! `tpre` stayed with the parent rather than travelling with phase 2:
//! both children build pres with them, and a sibling cfg(test) module
//! is not in scope through `use super::*`.

use super::*;

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
            "DELETE FROM kv WHERE k IN ('quality_v10','quality_v10_cursor')",
            [],
        )
        .unwrap();
    drop(ix);
    let ix = Index::open(&d.join("index.db")).unwrap();
    let stamped: String = ix
        .db
        .query_row("SELECT v FROM kv WHERE k='quality_v10'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stamped, "1", "the re-run completed");
    assert_eq!(
        snap(&ix),
        before,
        "a retro re-parse must reproduce the applied-name answer, not the stem's"
    );
    teardown(&d, ix);
}

/// The other half of the seam's contract, and the one it was breaking:
/// a release named HERE must be indistinguishable from one named at
/// ingest, so the naming pass owes ingest's whole classification chain
/// and not two thirds of it.
///
/// A spot title names the WORK and drops the file's format marker, so
/// an audiobook arrives here as an evidence-free movie. Ingest answers
/// that with the group prior (2 Sep 2026) and files it as a book at
/// junk 0; this seam did not, and wrote junk 60 - hidden by the wall's
/// default - over a row that had just gained a real name. It is
/// one-way, too: `pre_title=''` is in both the SELECT and the UPDATE's
/// WHERE, so a row named wrongly here is never re-judged here again.
///
/// The bump re-run at the end is the actual invariant: the retro pass
/// and the naming seam must agree, whichever ran first.
#[test]
fn the_naming_seam_owes_ingests_group_recovery_too() {
    let d = dir("vbump-namedgrp");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    ix.ingest(
        "alt.binaries.mp3.audiobooks",
        &[over(
            r#""b6V2qR8mL4pC7xN9zH3k.part01.rar" yEnc (1/1)"#,
            "p@x",
            "ab1",
            231 << 20,
        )],
        1000,
    )
    .unwrap();
    let rid = ix.search("", 10).unwrap()[0].id;
    assert!(
        ix.apply_named(
            rid,
            "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)",
            "spot",
            2000,
        )
        .unwrap()
    );
    let snap = |ix: &Index| -> (i64, String, String) {
        ix.db
            .query_row(
                "SELECT junk, title_key, kind FROM releases WHERE id=?1",
                [rid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    };
    let named = snap(&ix);
    assert_eq!(named.2, "book", "the group says book: {named:?}");
    assert!(named.0 < 50, "and a book in a book group shows: {named:?}");
    assert!(named.1.starts_with("bk:perry rhodan"), "{named:?}");

    // And the retro pass reaches the same answer from the same row.
    ix.db
        .execute(
            "DELETE FROM kv WHERE k IN ('quality_v10','quality_v10_cursor')",
            [],
        )
        .unwrap();
    drop(ix);
    let ix = Index::open(&d.join("index.db")).unwrap();
    assert_eq!(
        snap(&ix),
        named,
        "the naming seam and the quality backfill must not disagree"
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
