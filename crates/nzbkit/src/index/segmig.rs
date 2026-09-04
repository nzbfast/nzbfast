//! §26c A5: the online, resumable rebuild of `files` into its compact
//! layout - `segments` as [`segcodec`] bytes, and `nsegs` ahead of the
//! blob in the row.
//!
//! Two things about a row make the old layout expensive. A JSON segment
//! list is 2x the bytes it needs to be (see segcodec). And `nsegs`, the
//! one column the completeness aggregate reads on every chunk of every
//! release, sat BEHIND the blob: for the 3.6% of rows whose list
//! overflows the page - which is where 80% of the table's bytes live -
//! reading `nsegs` meant walking the overflow chain to its end first.
//! SQLite cannot reorder columns in place, so the fix is a rebuild, and
//! a rebuild of a 14 M-row (live: 48 M-row) table has to run beside a
//! daemon that is ingesting into that table the whole time.
//!
//! Shape, and why each part is the way it is:
//!
//! - **Slices, on the maintenance clock.** The copy runs in the scan
//!   loop's post-pass section like the retention reap: one hold of the
//!   index write mutex per slice, a pass budget, and the daemon's
//!   stand-down asked between slices, so a download that starts
//!   mid-copy gets the mutex at the next chunk boundary. Each chunk is
//!   one transaction of [`CHUNK`] rows; the WAL never sees more than
//!   that at once, where `INSERT INTO new SELECT * FROM files` would
//!   put the whole table through it (the 14 Aug 28 GiB fossil).
//! - **A rowid cursor in `kv`, committed WITH the rows it covers.** A
//!   kill at any point rolls back to a chunk boundary and the next
//!   slice resumes there. Rowids are PRESERVED across the rebuild
//!   (`INSERT ... (rowid, ...)`), because three other maintenance
//!   passes keep rowid cursors over `files` in `kv` and every one of
//!   them would have been silently rewound or skipped otherwise.
//! - **Mirror triggers carry live writes across.** From the moment the
//!   staging table exists, every INSERT, UPDATE and DELETE on `files`
//!   is replayed into it by trigger, so a row ingested, folded or
//!   pruned during the hours the copy takes is in the new table
//!   whichever side of the cursor it fell on. The copy itself is
//!   `INSERT OR REPLACE`, so a row the trigger already carried is
//!   simply rewritten. Readers keep using `files` - the old table,
//!   complete and untouched - until the swap.
//! - **The swap is one transaction and instant.** Drop the triggers,
//!   rename `files` to `files_old` and the staging table to `files`.
//!   No DROP of a 14 GB table with the write mutex held: the old table
//!   is deleted in slices afterwards (`reclaim`), and its pages go to
//!   the free list, where the existing idle compaction
//!   (`compact_chunk`) hands them back to the filesystem in bounded
//!   pieces. A crash between the rename and the drop leaves both
//!   tables and a readable index; the next pass carries on deleting.
//! - **Verified before swapping.** Row counts of the two tables are
//!   compared in the swap transaction; a mismatch refuses to swap and
//!   says so, leaving everything for a human. With the triggers in
//!   place the counts cannot differ unless something is wrong, which is
//!   exactly when a verdict is worth having.
//! - **Every reader accepts both forms throughout**, so nothing in the
//!   daemon has to know which stage the table is at. The one moment a
//!   reader can be surprised is the swap itself - a pooled statement
//!   prepared against the old `files` - and that is the `ddl` stamp:
//!   the daemon retires its read-only pool when it sees it, the same
//!   seam the named-feed index uses.
//!
//! Disk: the staging table grows the file by roughly half the old
//! table's size before the swap frees the old one, so the daemon checks
//! free space against [`Index::segmig_estimate_bytes`] before every
//! slice and stands down rather than fill the volume.
//!
//! Measured on an APFS clone of a real 26.2 GB / 14.47 M-row index
//! (22 Aug 2026): see the §26c A5 close in TODO.md for the numbers.

use super::segcodec::{self, SegRaw};
use super::*;
use rusqlite::TransactionBehavior;

/// Staging table name. Plain enough that a human finding it in
/// `sqlite_master` knows what it is and that dropping it costs only
/// the copying done so far.
pub const SEGMIG_STAGING: &str = "files_v2";
/// Where the old table waits to be deleted after the swap.
pub const SEGMIG_OLD: &str = "files_old";
/// kv: rowid of the last row copied.
const CURSOR_KEY: &str = "segs_v2_at";
/// kv: '1' once the copy reached the end of the table.
const COPIED_KEY: &str = "segs_v2_copied";
/// Rows per copy transaction. ~1 KB a row on the measured index, so a
/// chunk is a few MB of WAL; the heavy tail (p99.9 58 KB, max 4 MB) can
/// make one chunk tens of MB, which is still well inside the 64 MiB
/// `journal_size_limit`'s truncate-after.
pub const CHUNK: usize = 2_000;
/// Rows per reclaim DELETE.
const RECLAIM_CHUNK: usize = 2_000;

/// Where the rebuild stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegMigState {
    /// `files` already has the compact layout and nothing is left over.
    Done,
    /// Rows still to copy into the staging table. `copied` is the
    /// cursor; `total` the current highest rowid (an upper bound on the
    /// rows, not a count - the table has gaps).
    Copying { copied: i64, total: i64 },
    /// The copy reached the end of the table; the swap is next.
    Swappable,
    /// Swapped; `files_old` still holds rows to delete.
    Reclaiming,
}

/// What one copy slice did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegMigCopy {
    pub rows: u64,
    pub chunks: u64,
    /// The slice ran out of rows: the copy is complete.
    pub finished: bool,
}

fn table_exists(db: &Connection, name: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

/// Column position of `col` in `table`, or None if absent.
fn column_cid(db: &Connection, table: &str, col: &str) -> Option<i64> {
    db.query_row(
        &format!("SELECT cid FROM pragma_table_info('{table}') WHERE name=?1"),
        [col],
        |r| r.get(0),
    )
    .ok()
}

/// True when `files` carries the compact layout: `nsegs` ahead of
/// `segments`. A database created by this version has it from birth;
/// an older one gets it from the swap.
pub(crate) fn files_has_compact_layout(db: &Connection) -> bool {
    match (
        column_cid(db, "files", "nsegs"),
        column_cid(db, "files", "segments"),
    ) {
        (Some(n), Some(s)) => n < s,
        _ => false,
    }
}

fn kv_get(db: &Connection, k: &str) -> Option<String> {
    db.query_row("SELECT v FROM kv WHERE k=?1", [k], |r| r.get(0))
        .ok()
}

fn kv_set(db: &Connection, k: &str, v: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO kv(k, v) VALUES(?1, ?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        [k, v],
    )?;
    Ok(())
}

impl Index {
    /// Where the rebuild stands on this database.
    pub fn segmig_state(&self) -> SegMigState {
        let db = &self.db;
        if files_has_compact_layout(db) {
            return if table_exists(db, SEGMIG_OLD) {
                SegMigState::Reclaiming
            } else {
                SegMigState::Done
            };
        }
        if kv_get(db, COPIED_KEY).as_deref() == Some("1") && table_exists(db, SEGMIG_STAGING) {
            return SegMigState::Swappable;
        }
        let copied: i64 = kv_get(db, CURSOR_KEY)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let total: i64 = db
            .query_row("SELECT COALESCE(MAX(rowid), 0) FROM files", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        SegMigState::Copying { copied, total }
    }

    /// Roughly how many more bytes the staging table will take before
    /// the swap frees the old one - what the daemon holds free space
    /// against. A bounded sample past the cursor, never a scan: the
    /// question only gates a comparison.
    pub fn segmig_estimate_bytes(&self) -> rusqlite::Result<u64> {
        let SegMigState::Copying { copied, total } = self.segmig_state() else {
            return Ok(0);
        };
        let remaining = (total - copied).max(0) as f64;
        // Segments halve (measured 2.04x); a row already in the compact
        // form is copied at its size.
        let per: f64 = self
            .db
            .query_row(
                "SELECT AVG(CASE WHEN typeof(segments)='text' THEN LENGTH(segments)/2
                                 ELSE LENGTH(segments) END + LENGTH(filename) + 40)
                   FROM (SELECT segments, filename FROM files
                          WHERE rowid > ?1 ORDER BY rowid LIMIT 20000)",
                [copied],
                |r| r.get::<_, Option<f64>>(0),
            )?
            .unwrap_or(300.0);
        // 1.15 for interior pages and fill the sample cannot see.
        Ok((per * remaining * 1.15) as u64)
    }

    /// Create the staging table and the mirror triggers, once. Its own
    /// transaction: the three triggers and the table have to appear
    /// together or a write between them is lost.
    fn segmig_stage(&self) -> rusqlite::Result<()> {
        if table_exists(&self.db, SEGMIG_STAGING) {
            return Ok(());
        }
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        tx.execute_batch(&format!(
            "CREATE TABLE {SEGMIG_STAGING}(
                release_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                total_parts INTEGER NOT NULL,
                bytes INTEGER NOT NULL DEFAULT 0,
                nsegs INTEGER NOT NULL DEFAULT 0,
                segments BLOB NOT NULL DEFAULT '[]',
                UNIQUE(release_id, filename));
             CREATE TRIGGER {SEGMIG_STAGING}_mi AFTER INSERT ON files BEGIN
               INSERT OR REPLACE INTO {SEGMIG_STAGING}
                 (rowid, release_id, filename, total_parts, bytes, nsegs, segments)
                 VALUES(new.rowid, new.release_id, new.filename, new.total_parts,
                        new.bytes, new.nsegs, new.segments);
             END;
             CREATE TRIGGER {SEGMIG_STAGING}_mu AFTER UPDATE ON files BEGIN
               DELETE FROM {SEGMIG_STAGING} WHERE rowid=old.rowid;
               INSERT OR REPLACE INTO {SEGMIG_STAGING}
                 (rowid, release_id, filename, total_parts, bytes, nsegs, segments)
                 VALUES(new.rowid, new.release_id, new.filename, new.total_parts,
                        new.bytes, new.nsegs, new.segments);
             END;
             CREATE TRIGGER {SEGMIG_STAGING}_md AFTER DELETE ON files BEGIN
               DELETE FROM {SEGMIG_STAGING} WHERE rowid=old.rowid;
             END;
             DELETE FROM kv WHERE k IN ('{CURSOR_KEY}', '{COPIED_KEY}');"
        ))?;
        tx.commit()?;
        // Triggers are schema: pooled readers' statements on `files`
        // still plan the same way, but say so like every other DDL.
        self.ddl.set(true);
        Ok(())
    }

    /// Copy rows into the staging table until `deadline`, one chunk
    /// per transaction, advancing the kv cursor with each. Safe to call
    /// in any state: Done/Swappable/Reclaiming report `finished` at
    /// once and copy nothing.
    pub fn segmig_copy_slice(&self, deadline: std::time::Instant) -> rusqlite::Result<SegMigCopy> {
        let mut out = SegMigCopy::default();
        match self.segmig_state() {
            SegMigState::Copying { .. } => {}
            _ => {
                out.finished = true;
                return Ok(out);
            }
        }
        self.segmig_stage()?;
        loop {
            let tx =
                rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
            // Read the cursor INSIDE the write reservation - the
            // nsegs backfill learned that two openers reading it under a
            // deferred transaction could commit a stale lower value.
            let cursor: i64 = kv_get(&tx, CURSOR_KEY)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let rows: Vec<(i64, i64, String, i64, i64, i64, SegRaw)> = {
                let mut sel = tx.prepare_cached(
                    "SELECT rowid, release_id, filename, total_parts, bytes, nsegs, segments
                       FROM files WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
                )?;
                sel.query_map(rusqlite::params![cursor, CHUNK as i64], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            let Some(&(last, ..)) = rows.last() else {
                kv_set(&tx, COPIED_KEY, "1")?;
                tx.commit()?;
                out.finished = true;
                return Ok(out);
            };
            {
                let mut ins = tx.prepare_cached(&format!(
                    "INSERT OR REPLACE INTO {SEGMIG_STAGING}
                       (rowid, release_id, filename, total_parts, bytes, nsegs, segments)
                       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                ))?;
                for (rowid, rid, fname, total, bytes, nsegs, raw) in &rows {
                    // Re-encode what parses; a row that does not (which
                    // nothing writes today) is carried verbatim rather
                    // than replaced with an empty list, and keeps its
                    // stored nsegs. A parsed row gets its count stamped
                    // - the nsegs-or-count shape every reader uses
                    // tolerates 0, but after a full rewrite no row needs
                    // the fallback.
                    let (blob, n): (Vec<u8>, i64) = if segcodec::is_encoded(&raw.0) {
                        (raw.0.clone(), *nsegs)
                    } else {
                        match serde_json::from_slice::<Vec<Seg>>(&raw.0) {
                            Ok(segs) => (segcodec::encode(&segs), segs.len() as i64),
                            Err(_) => (raw.0.clone(), *nsegs),
                        }
                    };
                    ins.execute(rusqlite::params![rowid, rid, fname, total, bytes, n, blob])?;
                }
            }
            kv_set(&tx, CURSOR_KEY, &last.to_string())?;
            tx.commit()?;
            out.rows += rows.len() as u64;
            out.chunks += 1;
            if std::time::Instant::now() >= deadline {
                return Ok(out);
            }
        }
    }

    /// Verify and swap: `files` becomes `files_old`, the staging table
    /// becomes `files`. One transaction, instant apart from the two
    /// counts. `Ok(Some(rows))` swapped; `Ok(None)` when there is
    /// nothing to swap (not Swappable). A count mismatch is an error
    /// that leaves both tables in place.
    pub fn segmig_swap(&self) -> rusqlite::Result<Option<u64>> {
        if self.segmig_state() != SegMigState::Swappable {
            return Ok(None);
        }
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let old: i64 = tx.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))?;
        let new: i64 =
            tx.query_row(&format!("SELECT COUNT(*) FROM {SEGMIG_STAGING}"), [], |r| {
                r.get(0)
            })?;
        if old != new {
            // Say it through the error so the caller's log carries the
            // numbers; nothing is dropped.
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
                Some(format!(
                    "segments rebuild: files has {old} rows, {SEGMIG_STAGING} has {new} - not swapping"
                )),
            ));
        }
        let seed_schema_present = Index::nzb_seed_schema_present_on(&tx)?;
        // Remove both generations before SQLite can retarget their SQL to
        // `files_old`. The reinstall below remains conditional on the
        // optional seed tables being present.
        if seed_schema_present {
            Index::drop_nzb_seed_file_cleanup_triggers_on(&tx)?;
        }
        tx.execute_batch(&format!(
            "DROP TRIGGER {SEGMIG_STAGING}_mi;
             DROP TRIGGER {SEGMIG_STAGING}_mu;
             DROP TRIGGER {SEGMIG_STAGING}_md;
             ALTER TABLE files RENAME TO {SEGMIG_OLD};
             ALTER TABLE {SEGMIG_STAGING} RENAME TO files;
             DELETE FROM kv WHERE k IN ('{CURSOR_KEY}', '{COPIED_KEY}');"
        ))?;
        // Keep the optional trigger reinstall and its tbl_name validation
        // inside this swap, before files_old can be reclaimed.
        if seed_schema_present {
            Index::reinstall_nzb_seed_file_cleanup_triggers_on(&tx)?;
        }
        tx.commit()?;
        // The one schema change a pooled reader's prepared statement
        // can predate: the daemon retires its read-only pool on this.
        self.ddl.set(true);
        Ok(Some(new as u64))
    }

    /// Delete the old table's rows in chunks until `deadline`, and
    /// drop it once empty. Returns `(rows deleted, finished)`.
    pub fn segmig_reclaim_slice(
        &self,
        deadline: std::time::Instant,
    ) -> rusqlite::Result<(u64, bool)> {
        if self.segmig_state() != SegMigState::Reclaiming {
            return Ok((0, true));
        }
        let mut deleted = 0u64;
        loop {
            let n = self.db.execute(
                &format!(
                    "DELETE FROM {SEGMIG_OLD} WHERE rowid IN
                       (SELECT rowid FROM {SEGMIG_OLD} LIMIT {RECLAIM_CHUNK})"
                ),
                [],
            )?;
            deleted += n as u64;
            if n == 0 {
                self.db
                    .execute_batch(&format!("DROP TABLE IF EXISTS {SEGMIG_OLD}"))?;
                self.ddl.set(true);
                return Ok((deleted, true));
            }
            if std::time::Instant::now() >= deadline {
                return Ok((deleted, false));
            }
        }
    }

    /// Test and bench hook: build a database in the PRE-A5 layout so
    /// the rebuild has something to do. Only meaningful on an empty
    /// `files`; rewrites the table in place.
    #[doc(hidden)]
    pub fn segmig_debug_install_legacy_layout(&self) -> rusqlite::Result<()> {
        self.db.execute_batch(
            "DROP TABLE files;
             CREATE TABLE files(
                release_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                total_parts INTEGER NOT NULL,
                bytes INTEGER NOT NULL DEFAULT 0,
                segments TEXT NOT NULL DEFAULT '[]',
                nsegs INTEGER NOT NULL DEFAULT 0,
                UNIQUE(release_id, filename));",
        )?;
        self.ddl.set(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn tempdb(tag: &str) -> (std::path::PathBuf, Index) {
        let dir = std::env::temp_dir().join(format!("nzbfast-segmig-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        (dir, ix)
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn segs(rid: i64, n: u32) -> Vec<Seg> {
        (1..=n)
            .map(|i| {
                (
                    i,
                    format!("<part{i}of{n}.{rid:08x}@nyuu>"),
                    700_000 + u64::from(i),
                )
            })
            .collect()
    }

    /// A legacy-layout database holding `n` releases with one JSON
    /// file row each (and a `nsegs` of 0 on every third, as a row from
    /// before that column existed would carry).
    fn legacy(tag: &str, n: i64) -> (std::path::PathBuf, Index) {
        let (dir, ix) = tempdb(tag);
        ix.segmig_debug_install_legacy_layout().unwrap();
        assert!(!files_has_compact_layout(&ix.db));
        // One transaction for the whole seed: two autocommit inserts a row
        // is two journal flushes a row, and the subject is the migration
        // that runs AFTER this.
        ix.db.execute_batch("BEGIN").unwrap();
        for rid in 1..=n {
            ix.db
                .execute(
                    "INSERT INTO releases(id, stem, poster, grp) VALUES(?1, ?2, 'p', 'g')",
                    rusqlite::params![rid, format!("stem{rid}")],
                )
                .unwrap();
            let s = segs(rid, (rid % 5) as u32 + 1);
            ix.db
                .execute(
                    "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        rid,
                        format!("f{rid}.rar"),
                        s.len() as i64,
                        7,
                        serde_json::to_string(&s).unwrap(),
                        if rid % 3 == 0 { 0 } else { s.len() as i64 }
                    ],
                )
                .unwrap();
        }
        ix.db.execute_batch("COMMIT").unwrap();
        (dir, ix)
    }

    fn snapshot(ix: &Index, table: &str) -> Vec<(i64, i64, String, i64, i64, Vec<Seg>)> {
        ix.db
            .prepare(&format!(
                "SELECT rowid, release_id, filename, total_parts, bytes, segments
                   FROM {table} ORDER BY rowid"
            ))
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get::<_, SegList>(5)?.0,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn run_to_done(ix: &Index) {
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 1000, "migration did not converge");
            match ix.segmig_state() {
                SegMigState::Done => return,
                SegMigState::Copying { .. } => {
                    ix.segmig_copy_slice(far()).unwrap();
                }
                SegMigState::Swappable => {
                    ix.segmig_swap().unwrap().unwrap();
                }
                SegMigState::Reclaiming => {
                    ix.segmig_reclaim_slice(far()).unwrap();
                }
            }
        }
    }

    #[test]
    fn a_fresh_database_is_born_done() {
        let (dir, ix) = tempdb("fresh");
        assert!(files_has_compact_layout(&ix.db));
        assert_eq!(ix.segmig_state(), SegMigState::Done);
        assert!(ix.segmig_copy_slice(far()).unwrap().finished);
        assert_eq!(ix.segmig_swap().unwrap(), None);
        assert_eq!(ix.segmig_reclaim_slice(far()).unwrap(), (0, true));
        drop(ix);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_rebuild_keeps_every_row_its_rowid_and_its_segments() {
        let (dir, ix) = legacy("whole", 50);
        assert!(!ix.nzb_seed_schema_present().unwrap());
        let before = snapshot(&ix, "files");
        assert!(matches!(
            ix.segmig_state(),
            SegMigState::Copying { copied: 0, .. }
        ));
        run_to_done(&ix);
        assert!(
            !ix.nzb_seed_schema_present().unwrap(),
            "a seedless rebuild must not install the optional seed catalog"
        );
        assert!(files_has_compact_layout(&ix.db));
        assert_eq!(snapshot(&ix, "files"), before);
        // Every row is now the compact form, with nsegs stamped.
        let (text, zero): (i64, i64) = ix
            .db
            .query_row(
                "SELECT SUM(typeof(segments)='text'), SUM(nsegs=0) FROM files",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((text, zero), (0, 0));
        // No staging residue, no cursor, no triggers.
        let leftovers: i64 = ix
            .db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'files_v2%' OR name='files_old'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leftovers, 0);
        assert!(kv_get(&ix.db, CURSOR_KEY).is_none());
        // The UNIQUE still holds on the new table.
        let dup = ix.db.execute(
            "INSERT INTO files(release_id, filename, total_parts) VALUES(1, 'f1.rar', 1)",
            [],
        );
        assert!(
            dup.is_err(),
            "UNIQUE(release_id, filename) must survive the rebuild"
        );
        drop(ix);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_slice_stops_at_its_deadline_and_the_next_resumes_at_the_cursor() {
        let (dir, ix) = legacy("slices", 5 * CHUNK as i64 + 7);
        let before = snapshot(&ix, "files");
        // A deadline already past: exactly one chunk per call.
        let first = ix.segmig_copy_slice(Instant::now()).unwrap();
        assert_eq!(
            (first.rows, first.chunks, first.finished),
            (CHUNK as u64, 1, false)
        );
        let SegMigState::Copying { copied, .. } = ix.segmig_state() else {
            panic!("should still be copying");
        };
        assert_eq!(copied, CHUNK as i64);
        // A reopen (a crash, a restart) picks up at the cursor.
        drop(ix);
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let second = ix.segmig_copy_slice(Instant::now()).unwrap();
        assert_eq!(second.rows, CHUNK as u64);
        let SegMigState::Copying { copied, .. } = ix.segmig_state() else {
            panic!("should still be copying");
        };
        assert_eq!(copied, 2 * CHUNK as i64);
        run_to_done(&ix);
        assert_eq!(snapshot(&ix, "files"), before);
        drop(ix);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn writes_during_the_copy_land_in_the_new_table() {
        let (dir, ix) = legacy("live", 3 * CHUNK as i64);
        // One chunk in, then the daemon keeps ingesting: a new row
        // above the cursor, an upsert of a row below it, a fold-style
        // repoint, and a delete - on both sides of the cursor.
        ix.segmig_copy_slice(Instant::now()).unwrap();
        let new_segs = segs(999_999, 3);
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                 VALUES(1, 'late.rar', 3, 9, ?1, 3)",
                [segcodec::encode(&new_segs)],
            )
            .unwrap();
        let upd = segs(5, 4);
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                 VALUES(5, 'f5.rar', 4, 11, ?1, 4)
                 ON CONFLICT(release_id, filename) DO UPDATE SET
                   total_parts=excluded.total_parts, bytes=excluded.bytes,
                   segments=excluded.segments, nsegs=excluded.nsegs",
                [segcodec::encode(&upd)],
            )
            .unwrap();
        ix.db
            .execute(
                "UPDATE OR IGNORE files SET release_id=7 WHERE release_id=8",
                [],
            )
            .unwrap();
        ix.db
            .execute("DELETE FROM files WHERE release_id IN (2, 5000)", [])
            .unwrap();
        let before = snapshot(&ix, "files");
        run_to_done(&ix);
        let after = snapshot(&ix, "files");
        assert_eq!(after, before);
        assert!(after.iter().any(|r| r.2 == "late.rar" && r.5 == new_segs));
        assert!(after.iter().any(|r| r.1 == 5 && r.5 == upd));
        assert!(after.iter().any(|r| r.1 == 7 && r.2 == "f8.rar"));
        assert!(!after.iter().any(|r| r.1 == 2 || r.1 == 5000));
        drop(ix);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_reopen_between_the_swap_and_the_reclaim_finishes_the_job() {
        let (dir, ix) = legacy("midswap", 20);
        while !ix.segmig_copy_slice(far()).unwrap().finished {}
        assert_eq!(ix.segmig_state(), SegMigState::Swappable);
        assert_eq!(ix.segmig_swap().unwrap(), Some(20));
        assert_eq!(ix.segmig_state(), SegMigState::Reclaiming);
        drop(ix);
        let ix = Index::open(&dir.join("index.db")).unwrap();
        // Readers already see the new table; the old one is just disk.
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 20);
        assert_eq!(ix.segmig_state(), SegMigState::Reclaiming);
        let (deleted, done) = ix.segmig_reclaim_slice(far()).unwrap();
        assert_eq!((deleted, done), (20, true));
        assert_eq!(ix.segmig_state(), SegMigState::Done);
        drop(ix);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_count_mismatch_refuses_to_swap() {
        let (dir, ix) = legacy("mismatch", 10);
        while !ix.segmig_copy_slice(far()).unwrap().finished {}
        // Damage the staging table behind the triggers' back.
        ix.db
            .execute(&format!("DELETE FROM {SEGMIG_STAGING} WHERE rowid=3"), [])
            .unwrap();
        let err = ix.segmig_swap().unwrap_err().to_string();
        assert!(err.contains("not swapping"), "{err}");
        assert!(!files_has_compact_layout(&ix.db));
        assert_eq!(ix.segmig_state(), SegMigState::Swappable);
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 10, "the old table is untouched");
        drop(ix);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_index_reads_and_writes_normally_at_every_stage() {
        // The real entry points - ingest-side aggregate, make_nzb, the
        // completeness count - against a half-migrated table.
        let (dir, ix) = legacy("stages", 2 * CHUNK as i64 + 5);
        let check = |ix: &Index, stage: &str| {
            let nzb = ix.make_nzb(3).unwrap();
            assert!(nzb.contains("part1of4.00000003@nyuu"), "{stage}: {nzb}");
            let agg = super::super::aggregates::RelAgg::recompute(&ix.db, 3).unwrap();
            assert_eq!((agg.nfiles, agg.have, agg.need), (1, 4, 4), "{stage}");
            let c: i64 = ix
                .db
                .query_row(
                    "SELECT COUNT(*) FROM files WHERE seg_count(segments) < total_parts",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(c, 0, "{stage}");
        };
        check(&ix, "legacy");
        ix.segmig_copy_slice(Instant::now()).unwrap();
        check(&ix, "copying");
        while !ix.segmig_copy_slice(far()).unwrap().finished {}
        check(&ix, "swappable");
        ix.segmig_swap().unwrap();
        check(&ix, "reclaiming");
        ix.segmig_reclaim_slice(far()).unwrap();
        check(&ix, "done");
        drop(ix);
        let _ = std::fs::remove_dir_all(dir);
    }
    /// The measurement rig behind the §26c A5 close: runs the whole
    /// rebuild against a REAL index and times the queries before and
    /// after. Never against the live file - `cp -c` an APFS clone first
    /// (free until written) and point `NZBFAST_SEGMIG_BENCH_DB` at it:
    ///
    /// ```sh
    /// NZBFAST_SEGMIG_BENCH_DB=/path/clone.db NZBFAST_NO_ENRICH=1 \
    ///   cargo test --release -p nzbkit --lib segmig_bench -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn segmig_bench_on_a_real_clone() {
        let Ok(path) = std::env::var("NZBFAST_SEGMIG_BENCH_DB") else {
            eprintln!("NZBFAST_SEGMIG_BENCH_DB not set - skipping");
            return;
        };
        let path = std::path::PathBuf::from(path);
        let wal = path.with_extension("db-wal");
        let ix = Index::open(&path).unwrap();
        let bytes = |ix: &Index| -> (u64, u64) {
            let pages: i64 = ix
                .db
                .query_row("PRAGMA page_count", [], |r| r.get(0))
                .unwrap();
            let free: i64 = ix
                .db
                .query_row("PRAGMA freelist_count", [], |r| r.get(0))
                .unwrap();
            (pages as u64 * 4096, free as u64 * 4096)
        };
        let file_len = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let (max_id, max_rowid): (i64, i64) = ix
            .db
            .query_row(
                "SELECT (SELECT MAX(id) FROM releases), (SELECT MAX(rowid) FROM files)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // Fixed pseudo-random release sample, the same before and after.
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut sample = Vec::new();
        while sample.len() < 3000 {
            let id = (next() % max_id as u64) as i64 + 1;
            if ix
                .db
                .query_row("SELECT 1 FROM releases WHERE id=?1", [id], |_| Ok(()))
                .is_ok()
            {
                sample.push(id);
            }
        }
        let biggest: Vec<i64> = ix
            .db
            .prepare("SELECT id FROM releases ORDER BY total_bytes DESC LIMIT 50")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let queries = |ix: &Index, tag: &str| {
            let t = |name: &str, f: &dyn Fn()| {
                // Twice: the first is whatever the cache holds, the
                // second is warm. Both are reported.
                let a = Instant::now();
                f();
                let a = a.elapsed();
                let b = Instant::now();
                f();
                let b = b.elapsed();
                eprintln!(
                    "  [{tag}] {name:<44} {:>9.1} ms  warm {:>9.1} ms",
                    a.as_secs_f64() * 1e3,
                    b.as_secs_f64() * 1e3
                );
            };
            t("browse: default page (posted desc, 50)", &|| {
                let q = BrowseQuery::default();
                ix.browse(&q).unwrap();
            });
            t("browse: tv, complete only (RSS shape)", &|| {
                let q = BrowseQuery {
                    kind: Some("tv".into()),
                    complete_only: true,
                    ..Default::default()
                };
                ix.browse(&q).unwrap();
            });
            t("wall: browse_cards default grid", &|| {
                let q = BrowseQuery {
                    curated: true,
                    ..Default::default()
                };
                ix.browse_cards(&q, CardSort::parse("recent"), false, true, None)
                    .unwrap();
            });
            t("wall: wall_tip (last 50 arrivals)", &|| {
                let since: i64 = ix
                    .db
                    .query_row("SELECT MAX(arrival_seq) - 1000 FROM releases", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
                ix.wall_tip(since, 0, 50).unwrap();
            });
            t("files: RelAgg::recompute x3000 random", &|| {
                for id in &sample {
                    super::super::aggregates::RelAgg::recompute(&ix.db, *id).unwrap();
                }
            });
            t("files: RelAgg::recompute x50 biggest", &|| {
                for id in &biggest {
                    super::super::aggregates::RelAgg::recompute(&ix.db, *id).unwrap();
                }
            });
            t("files: make_nzb x300 random", &|| {
                for id in &sample[..300] {
                    ix.make_nzb(*id).unwrap();
                }
            });
            t("files: make_nzb x50 biggest", &|| {
                for id in &biggest {
                    ix.make_nzb(*id).unwrap();
                }
            });
            t("files: stale-partial EXISTS over 200k ids", &|| {
                let lo = max_id / 2;
                ix.db
                    .query_row(
                        "SELECT COUNT(*) FROM releases
                          WHERE id > ?1 AND id <= ?1 + 200000 AND junk >= 50
                            AND EXISTS (SELECT 1 FROM files f WHERE f.release_id = releases.id
                                        AND (CASE WHEN f.nsegs > 0 THEN f.nsegs
                                             ELSE seg_count(f.segments) END) < f.total_parts)",
                        [lo],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap();
            });
        };
        let (db0, free0) = bytes(&ix);
        eprintln!(
            "before: file {} B, pages {} B, freelist {} B, max rowid {max_rowid}",
            file_len(&path),
            db0,
            free0
        );
        queries(&ix, "before");
        eprintln!("state: {:?}", ix.segmig_state());
        // Copy, in the daemon's 1 s slices, with the WAL high-water watched.
        let t0 = Instant::now();
        let mut rows = 0u64;
        let mut wal_hw = 0u64;
        loop {
            let r = ix
                .segmig_copy_slice(Instant::now() + Duration::from_secs(1))
                .unwrap();
            rows += r.rows;
            wal_hw = wal_hw.max(file_len(&wal));
            if r.finished {
                break;
            }
            if rows % 200_000 < CHUNK as u64 {
                eprintln!(
                    "  copied {rows} rows, {:.0} rows/s, wal hw {} MB",
                    rows as f64 / t0.elapsed().as_secs_f64(),
                    wal_hw >> 20
                );
            }
        }
        let copy = t0.elapsed();
        eprintln!(
            "copy: {rows} rows in {:.1} s = {:.0} rows/s = {:.1} s per million; wal high-water {} MB",
            copy.as_secs_f64(),
            rows as f64 / copy.as_secs_f64(),
            copy.as_secs_f64() / (rows as f64 / 1e6),
            wal_hw >> 20
        );
        let (db1, free1) = bytes(&ix);
        eprintln!(
            "after copy (both tables): pages {} B, freelist {} B",
            db1, free1
        );
        let t1 = Instant::now();
        let swapped = ix.segmig_swap().unwrap();
        eprintln!(
            "swap: {swapped:?} rows in {:.2} s",
            t1.elapsed().as_secs_f64()
        );
        let t2 = Instant::now();
        let mut reclaimed = 0u64;
        loop {
            let (n, done) = ix
                .segmig_reclaim_slice(Instant::now() + Duration::from_secs(1))
                .unwrap();
            reclaimed += n;
            wal_hw = wal_hw.max(file_len(&wal));
            if done {
                break;
            }
        }
        let reclaim = t2.elapsed();
        eprintln!(
            "reclaim: {reclaimed} rows in {:.1} s = {:.1} s per million; wal high-water {} MB",
            reclaim.as_secs_f64(),
            reclaim.as_secs_f64() / (reclaimed as f64 / 1e6),
            wal_hw >> 20
        );
        let (db2, free2) = bytes(&ix);
        eprintln!(
            "after reclaim: pages {} B, freelist {} B (live {} B)",
            db2,
            free2,
            db2 - free2
        );
        // Hand the free list back the way the daemon does, in chunks.
        let t3 = Instant::now();
        let mut left = ix.freelist_pages().unwrap();
        while left > 0 {
            left = ix.compact_chunk(2048).unwrap();
            wal_hw = wal_hw.max(file_len(&wal));
        }
        ix.checkpoint_truncate(Duration::from_secs(30)).unwrap();
        eprintln!(
            "incremental vacuum: {:.1} s; wal high-water {} MB",
            t3.elapsed().as_secs_f64(),
            wal_hw >> 20
        );
        let (db3, free3) = bytes(&ix);
        eprintln!(
            "after: file {} B, pages {} B, freelist {} B",
            file_len(&path),
            db3,
            free3
        );
        let (text, blob): (i64, i64) = ix
            .db
            .query_row(
                "SELECT SUM(typeof(segments)='text'), SUM(typeof(segments)='blob') FROM files",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        eprintln!("files rows: {text} json, {blob} compact");
        queries(&ix, "after");
        eprintln!("state: {:?}", ix.segmig_state());
    }
}
