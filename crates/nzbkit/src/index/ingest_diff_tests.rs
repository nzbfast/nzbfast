//! Differential ingest tests (N8): the same article stream ingested in
//! one chunk vs many chunks must produce identical release rows - the
//! completeness accounting is the D3 backstop, so the incremental
//! aggregate path is held to the full-recompute answer bit for bit.

use super::*;
use crate::index::testutil::{entry, teardown};

/// A deep-backfill shaped stream: `nfiles` files of `nparts` parts each,
/// delivered as OVER entries. `chunk` slices it into per-part waves (one
/// part of every file per wave), which is how a backfill walks article
/// ranges - every chunk touches every file of the release.
fn corpus(nfiles: usize, nparts: usize) -> Vec<OverEntry> {
    let mut out = Vec::new();
    for p in 1..=nparts {
        for f in 0..nfiles {
            out.push(OverEntry {
                number: 0,
                subject: format!("\"Deep.Backfill.Release.part{f:03}.rar\" yEnc ({p}/{nparts})"),
                from: "poster@example".into(),
                message_id: format!("<seg-{f}-{p}@news>"),
                bytes: 750_000,
                date: 1_700_000_000,
            });
        }
    }
    out
}

fn open_ix(tag: &str) -> (std::path::PathBuf, Index) {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-ingest-diff-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    (dir, ix)
}

/// Every release-row column the aggregate path writes, keyed by stem so
/// the two databases can be compared without depending on rowids.
fn release_rows(ix: &Index) -> Vec<(String, i64, i64, i64, i64, i64, i64, i64, i64)> {
    let mut q = ix
        .db
        .prepare(
            "SELECT stem, files, total_bytes, has_par2, complete,
                    have_parts, need_parts, nfiles_complete, nfiles_exe
               FROM releases ORDER BY stem",
        )
        .unwrap();
    q.query_map([], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
            r.get(8)?,
        ))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

/// The oracle: recompute every aggregate from the files table with the
/// full-scan formula and demand the stored row agrees. `-1` counters
/// (unknown) are only legal on rows ingest has never touched, and no row
/// in these fixtures qualifies.
fn assert_rows_match_recompute(ix: &Index) {
    for (stem, files, tbytes, has_par2, complete, have, need, ncomp, nexe) in release_rows(ix) {
        let rid: i64 = ix
            .db
            .query_row("SELECT id FROM releases WHERE stem=?1", [&stem], |r| {
                r.get(0)
            })
            .unwrap();
        let (rf, rb, rc, rp, rh, rn, re): (i64, i64, i64, i64, i64, i64, i64) = ix
            .db
            .query_row(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(bytes),0),
                            COALESCE(SUM(CASE WHEN nsegs > 0 THEN nsegs
                                     ELSE seg_count(segments) END >= total_parts),0),
                            COALESCE(SUM(LOWER(filename) LIKE '%.par2'),0),
                            COALESCE(SUM(CASE WHEN nsegs > 0 THEN nsegs
                                              ELSE seg_count(segments) END),0),
                            COALESCE(SUM(total_parts),0),
                            COALESCE(SUM({}),0)
                       FROM files WHERE release_id=?1",
                    crate::index::browse::EXE_FILE_SQL
                ),
                [rid],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            (files, tbytes, have, need),
            (rf, rb, rh, rn),
            "{stem}: stored aggregates drifted from the files table"
        );
        assert_eq!(
            (has_par2 > 0, complete > 0),
            (rp > 0, rf >= 1 && rc == rf),
            "{stem}: flags drifted"
        );
        assert_eq!((ncomp, nexe), (rc, re), "{stem}: counters drifted");
    }
}

/// The N8 differential proper: one chunk vs many chunks, identical rows.
#[test]
fn chunked_ingest_matches_single_chunk_ingest() {
    for env in [("one", 1usize), ("many", 7)] {
        let (tag, chunks) = env;
        let (dir, mut ix) = open_ix(&format!("diff-{tag}"));
        let all = corpus(6, 21);
        let per = all.len().div_ceil(chunks);
        for c in all.chunks(per) {
            ix.ingest("alt.binaries.test", c, 1_700_000_100).unwrap();
        }
        assert_rows_match_recompute(&ix);
        if tag == "one" {
            teardown(&dir, ix);
            continue;
        }
        // Rebuild the single-chunk twin and compare row for row.
        let (dir1, mut ix1) = open_ix("diff-one-cmp");
        ix1.ingest("alt.binaries.test", &all, 1_700_000_100)
            .unwrap();
        assert_eq!(release_rows(&ix), release_rows(&ix1));
        teardown(&dir1, ix1);
        teardown(&dir, ix);
    }
}

/// Deep-backfill measurement rig (N8): wall time plus WAL bytes for a
/// release-heavy chunked ingest, incremental vs the old per-chunk full
/// recompute (simulated by poisoning the counters to -1 between chunks,
/// which routes every chunk through the fallback scan - the exact work
/// the old code did every time). Ignored in the suites - run by hand
/// with `--ignored --nocapture`.
#[test]
#[ignore = "measurement rig, run by hand"]
fn deep_backfill_wal_and_wall_measurement() {
    const NFILES: usize = 2000;
    const NPARTS: usize = 12;
    for (tag, poison) in [("full-recompute-per-chunk", true), ("incremental", false)] {
        let (dir, mut ix) = open_ix(&format!("wal-{tag}"));
        // WAL must only grow for the duration of the measurement, or
        // the file length stops being "bytes written".
        ix.db.execute_batch("PRAGMA wal_autocheckpoint=0;").unwrap();
        let _ = ix
            .db
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_r| Ok(()));
        let all = corpus(NFILES, NPARTS);
        let t0 = std::time::Instant::now();
        for c in all.chunks(NFILES) {
            // One part of every file per chunk: NPARTS chunks.
            ix.ingest("alt.binaries.test", c, 1_700_000_100).unwrap();
            if poison {
                ix.db
                    .execute("UPDATE releases SET nfiles_complete=-1, nfiles_exe=-1", [])
                    .unwrap();
            }
        }
        let took = t0.elapsed();
        let wal = std::fs::metadata(dir.join("index.db-wal"))
            .map(|m| m.len())
            .unwrap_or(0);
        println!(
            "deep backfill [{tag}]: {NFILES} files x {NPARTS} parts in {NPARTS} chunks: \
             {took:?}, WAL {wal} bytes ({:.1} MB)",
            wal as f64 / 1e6
        );
        if !poison {
            assert_rows_match_recompute(&ix);
        }
        teardown(&dir, ix);
    }
}

/// `nsegs` caches what `json_array_length(segments)` used to
/// recompute on every touch. Two things must hold: it tracks the
/// merged part set exactly, and completeness stays right for rows
/// the backfill has not reached yet (an unfilled row reads 0, which
/// would otherwise flip a complete release to incomplete).
#[test]
fn nsegs_tracks_segments_and_survives_a_half_done_backfill() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nsegs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("index.db");
    let mut ix = Index::open(&path).unwrap();

    // Split across batches so the merge path runs: part 2 arrives
    // after part 1, and nsegs has to end at 2, not 1.
    ix.ingest(
        "alt.test",
        &[entry(
            "\"Film.2020.part1.rar\" yEnc (1/2)",
            "p@x",
            "a1",
            900,
        )],
        1000,
    )
    .unwrap();
    let count = |ix: &Index| -> i64 {
        ix.db
            .query_row(
                "SELECT nsegs FROM files WHERE filename LIKE 'Film%'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(count(&ix), 1, "first batch: one part seen");
    assert_eq!(
        ix.ingest(
            "alt.test",
            &[entry(
                "\"Film.2020.part1.rar\" yEnc (2/2)",
                "p@x",
                "a2",
                900
            )],
            1001
        )
        .unwrap(),
        1,
        "merging the second part completes the release"
    );
    assert_eq!(count(&ix), 2, "nsegs follows the MERGED set, not the batch");
    assert!(
        ix.db
            .query_row("SELECT complete FROM releases LIMIT 1", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );

    // Simulate a row the chunked backfill has not reached: nsegs
    // back to 0 with the JSON intact, which is exactly the state
    // every pre-existing row is in on first open after upgrading.
    ix.db.execute("UPDATE files SET nsegs = 0", []).unwrap();
    ix.db
        .execute("UPDATE kv SET v='0' WHERE k='nsegs_fill'", [])
        .ok();
    ix.ingest(
        "alt.test",
        &[entry("\"Other.2020.mkv\" yEnc (1/1)", "p@y", "b1", 900)],
        1002,
    )
    .unwrap();
    let still_complete: bool = ix
        .db
        .query_row(
            "SELECT complete FROM releases WHERE stem LIKE 'Film%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        still_complete,
        "a release whose files the backfill has not reached must not \
         be flipped to incomplete by the cached count reading 0"
    );

    // Re-opening runs the backfill and fills them in.
    drop(ix);
    let ix = Index::open(&path).unwrap();
    assert_eq!(count(&ix), 2, "backfill restored the cached count");
    let done: String = ix
        .db
        .query_row("SELECT v FROM kv WHERE k='nsegs_fill'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(done, "1", "backfill stamped itself complete");

    let _ = std::fs::remove_dir_all(&dir);
}
