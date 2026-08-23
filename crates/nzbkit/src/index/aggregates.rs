//! Release-level aggregates over the `files` table (N8).
//!
//! Seven values ride on every release row: file count, total bytes,
//! complete-file count, par2 presence, have/need part sums, and the
//! executable-file count that feeds the junk score. Ingest used to
//! re-derive all seven with a full scan of the release's file rows on
//! every chunk that touched it - O(files) row visits plus LIKE chains
//! per chunk, per cluster, across a whole backfill. They are now
//! maintained incrementally from the in-memory merge delta
//! ([`RelAgg::apply_file`]), with [`RelAgg::recompute`] kept as the
//! single copy of the full-scan formula: the fallback that heals a row
//! whose counters are unknown (-1: pre-migration rows, or a maintenance
//! path that rewrote `files` without recomputing), and the oracle the
//! differential tests hold the incremental path to.

use rusqlite::Connection;

use super::browse::EXE_FILE_SQL;

/// The seven aggregates of one release row, in their stored shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelAgg {
    pub(crate) nfiles: i64,
    pub(crate) tbytes: i64,
    /// Files with every part seen. Stored (`nfiles_complete`), because
    /// the boolean `complete` cannot be maintained incrementally: a
    /// file's own completeness flips false when a later batch reveals a
    /// real `(x/y)` total, and only the count says whether the release
    /// still qualifies.
    pub(crate) ncomplete: i64,
    pub(crate) has_par2: bool,
    pub(crate) have: i64,
    pub(crate) need: i64,
    /// Executable-looking files (stored as `nfiles_exe`); the junk
    /// score only asks `> 0`, but the count survives merges better.
    pub(crate) nexe: i64,
}

impl RelAgg {
    /// The release-complete verdict: every file we have seen has all
    /// its parts. Single-file posts are legitimate (see ingest).
    pub(crate) fn complete(&self) -> bool {
        self.nfiles >= 1 && self.ncomplete == self.nfiles
    }

    /// The full-scan formula, verbatim from the old ingest aggregate:
    /// `nsegs` when stamped, `json_array_length(segments)` for
    /// pre-migration rows still carrying 0.
    pub(crate) fn recompute(db: &Connection, rid: i64) -> rusqlite::Result<Self> {
        db.prepare_cached(&format!(
            "SELECT COUNT(*), COALESCE(SUM(bytes),0),
                    COALESCE(SUM(CASE WHEN nsegs > 0 THEN nsegs
                             ELSE seg_count(segments) END >= total_parts),0),
                    COALESCE(SUM(LOWER(filename) LIKE '%.par2'),0),
                    COALESCE(SUM(CASE WHEN nsegs > 0 THEN nsegs
                                      ELSE seg_count(segments) END),0),
                    COALESCE(SUM(total_parts),0),
                    COALESCE(SUM({EXE_FILE_SQL}),0)
             FROM files WHERE release_id=?1"
        ))?
        .query_row([rid], |r| {
            Ok(RelAgg {
                nfiles: r.get(0)?,
                tbytes: r.get(1)?,
                ncomplete: r.get(2)?,
                has_par2: r.get::<_, i64>(3)? > 0,
                have: r.get(4)?,
                need: r.get(5)?,
                nexe: r.get(6)?,
            })
        })
    }

    /// Fold one merged file write into the running aggregates. `old` is
    /// the row's previous contribution - (effective part count, total,
    /// bytes) - and None when this write inserts the file. The new
    /// values must be EXACTLY what the UPSERT stores, so the result
    /// stays bit-identical to a recompute after the write.
    pub(crate) fn apply_file(
        &mut self,
        fname: &str,
        old: Option<(i64, u32, i64)>,
        new_segs: i64,
        new_total: u32,
        new_bytes: i64,
    ) {
        if let Some((segs, total, bytes)) = old {
            self.tbytes -= bytes;
            self.have -= segs;
            self.need -= i64::from(total);
            self.ncomplete -= i64::from(segs >= i64::from(total));
        } else {
            self.nfiles += 1;
            // Filenames are immutable under UNIQUE(release_id,
            // filename), so the name-derived flags are decided once, at
            // insert - never re-tested on a later touch.
            self.has_par2 |= is_par2_file(fname);
            self.nexe += i64::from(is_exe_file(fname));
        }
        self.tbytes += new_bytes;
        self.have += new_segs;
        self.need += i64::from(new_total);
        self.ncomplete += i64::from(new_segs >= i64::from(new_total));
    }
}

/// ASCII-case-insensitive suffix test on BYTES: exactly what
/// `LOWER(filename) LIKE '%.ext'` answers (SQLite's LOWER and LIKE both
/// fold ASCII only), and safe on a name whose tail is mid-multibyte -
/// such a tail can never equal an ASCII extension.
fn has_suffix(name: &str, ext: &[u8]) -> bool {
    let b = name.as_bytes();
    b.len() >= ext.len() && b[b.len() - ext.len()..].eq_ignore_ascii_case(ext)
}

/// Rust twin of the SQL `LOWER(filename) LIKE '%.par2'`.
pub(crate) fn is_par2_file(name: &str) -> bool {
    has_suffix(name, b".par2")
}

/// Rust twin of [`EXE_FILE_SQL`]. The two live one import apart and the
/// differential test below holds them together.
pub(crate) fn is_exe_file(name: &str) -> bool {
    [
        b".exe", b".scr", b".lnk", b".bat", b".cmd", b".com", b".msi", b".vbs", b".pif",
    ]
    .iter()
    .any(|ext| has_suffix(name, *ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust predicates must agree with their SQL twins on every
    /// name shape the index sees, or the incremental counts drift from
    /// what a recompute would say.
    #[test]
    fn predicates_agree_with_their_sql_twins() {
        let db = Connection::open_in_memory().unwrap();
        for name in [
            "Show.S01E01.part01.rar",
            "set.par2",
            "set.PAR2",
            "set.vol00+01.PaR2",
            "par2",
            ".par2",
            "notpar2",
            "x.par23",
            "keygen.exe",
            "KEYGEN.EXE",
            "run.bat",
            "a.cmd",
            "a.com",
            "a.msi",
            "a.vbs",
            "a.pif",
            "a.scr",
            "a.lnk",
            "a.exe.rar",
            "exe",
            "noext",
            "Ünïcode.Exe",
            "Ünïcode.pär2",
            "a.b.par2",
            "trailingdot.",
        ] {
            let (sql_par2, sql_exe): (bool, bool) = db
                .query_row(
                    &format!("SELECT LOWER(?1) LIKE '%.par2', {}", {
                        // EXE_FILE_SQL tests a `filename` column; bind it.
                        EXE_FILE_SQL.replace("filename", "?1")
                    }),
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(is_par2_file(name), sql_par2, "par2 twin split on {name:?}");
            assert_eq!(is_exe_file(name), sql_exe, "exe twin split on {name:?}");
        }
    }

    /// Folding deltas file by file lands on the same answer as a
    /// recompute, through inserts, updates, and a total that a later
    /// batch reveals (completeness flipping true -> false).
    #[test]
    fn apply_file_tracks_recompute() {
        let db = Connection::open_in_memory().unwrap();
        crate::index::segcodec::register(&db).unwrap();
        db.execute_batch(
            "CREATE TABLE files(release_id INTEGER, filename TEXT,
                total_parts INTEGER NOT NULL, bytes INTEGER NOT NULL DEFAULT 0,
                segments TEXT NOT NULL DEFAULT '[]',
                nsegs INTEGER NOT NULL DEFAULT 0,
                UNIQUE(release_id, filename));",
        )
        .unwrap();
        let mut agg = RelAgg::recompute(&db, 1).unwrap();
        // (name, old contribution, new segs/total/bytes) - a file that
        // appears with an unknown total, gains one, and a par2 sidecar.
        let steps: [(&str, Option<(i64, u32, i64)>, i64, u32, i64); 4] = [
            ("a.rar", None, 3, 0, 300),
            ("a.rar", Some((3, 0, 300)), 5, 10, 500),
            ("s.par2", None, 1, 1, 40),
            ("a.rar", Some((5, 10, 500)), 10, 10, 1000),
        ];
        for (name, old, segs, total, bytes) in steps {
            let seg_blob = crate::index::segcodec::encode(
                &(1..=segs)
                    .map(|n| (n as u32, format!("<{n}@x>"), (bytes / segs) as u64))
                    .collect::<Vec<_>>(),
            );
            db.execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                 VALUES(1, ?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(release_id, filename) DO UPDATE SET
                   total_parts=excluded.total_parts, bytes=excluded.bytes,
                   segments=excluded.segments, nsegs=excluded.nsegs",
                rusqlite::params![name, total, bytes, seg_blob, segs],
            )
            .unwrap();
            agg.apply_file(name, old, segs, total, bytes);
            assert_eq!(
                agg,
                RelAgg::recompute(&db, 1).unwrap(),
                "after {name} {old:?}"
            );
        }
        // Both files end with every part: the mid-run states exercised
        // incomplete (unknown total revealed, parts missing), the final
        // state exercises the complete verdict.
        assert!(agg.has_par2 && agg.complete() && agg.nfiles == 2);
    }
}
