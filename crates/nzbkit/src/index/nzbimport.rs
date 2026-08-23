//! Index side of posted-NZB ingestion (REDTEAM 5c / build-order #6):
//! candidate selection (one-file `*.nzb` rows) and the payload
//! message-id join.
//!
//! The join here is the INTERIM implementation: one pass over
//! `files.segments` probing a temp table of candidate ids. The identity
//! substrate's persistent reverse message-id table replaces it when it
//! lands (same call shape, O(ids) instead of O(index)); everything else
//! - candidates, quorum, claims - is unchanged by that swap.

use super::*;

/// Where the posted-NZB walk's durable position lives (index kv). It
/// survives restarts and dies with the file on an index wipe - which is
/// right, because a wiped index renumbers from 1.
///
/// The value is an `arrival_seq`, NOT a release id: see
/// [`Index::posted_nzb_candidates`].
pub const NZBIMPORT_CURSOR: &str = "nzbimport_arrival_cursor";

/// The pre-arrival_seq cursor key, a release id. Read once to seed
/// [`NZBIMPORT_CURSOR`] on an upgrade, then never written again.
const NZBIMPORT_CURSOR_LEGACY_ID: &str = "nzbimport_cursor";

/// A one-file `*.nzb` index row worth fetching: the posted object IS a
/// small NZB, and its payload message-ids can name dark rows exactly.
#[derive(Debug, Clone)]
pub struct PostedNzbCandidate {
    pub release_id: i64,
    /// This row's wall-arrival ordinal - the walker's cursor value.
    /// `release_id` is not: SQLite hands a deleted row's id to the next
    /// insert, and this ordinal is the identity that survives that.
    pub arrival_seq: i64,
    /// The stem the `.nzb` was posted under - the primary name claim.
    pub stem: String,
    pub grp: String,
    pub junk: i64,
    /// `(part_no, message_id)` in stored (bracketed) form, part order.
    pub segs: Vec<(u32, String)>,
    pub bytes: u64,
}

/// Where one payload message-id lives in the index. A message-id can
/// land in MORE than one release row: a crossposted article is scanned
/// into every group it rode, and each (stem, poster, grp) is its own
/// row - so the lookup returns rows, not a unique hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgidRow {
    pub(crate) msgid: String,
    pub(crate) release_id: i64,
    pub(crate) stem: String,
    /// Segments the whole RELEASE holds (`releases.have_parts`) - the
    /// quorum denominator. The release total, not the matched file's,
    /// so a claim must cover the release it would rename.
    pub(crate) row_nsegs: u32,
}

/// A per-NZB, per-release join summary (built by
/// [`crate::nzbimport::group_hits`] from [`MsgidRow`]s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgidHit {
    pub release_id: i64,
    pub stem: String,
    /// Distinct message-ids of THIS NZB found in the row.
    pub matched: usize,
    /// Segments the row holds (quorum denominator).
    pub row_nsegs: u32,
    /// The matched ids themselves - what [`msgid_set_key`] must be fed
    /// (the canonical MsgidSet claim key is over the MATCHED set, so
    /// two lanes proving the same join corroborate instead of reading
    /// as independent evidence).
    pub ids: Vec<String>,
}

impl Index {
    /// One-file releases whose sole file is a complete `*.nzb`,
    /// `arrival_seq` ascending from `after` - the cursor lets a periodic
    /// rung walk the index once instead of re-fetching the same objects.
    /// Junk score is deliberately NOT filtered: an obfuscated-name `.nzb`
    /// post is still a real NZB whose payload ids join exactly.
    ///
    /// The cursor walks `arrival_seq`, not `releases.id`. `id` is an
    /// `INTEGER PRIMARY KEY` with no `AUTOINCREMENT`, so SQLite reuses
    /// the top id as soon as that row is deleted - and maintenance folds
    /// and eviction both delete releases. A posted NZB that landed on a
    /// recycled id below the cursor was excluded FOREVER (10 Aug 2026
    /// Codex sweep, M6: id 2 reused, `WHERE id > 2` returned zero).
    /// `arrival_seq` is the monotonic counter that exists for exactly
    /// this hazard on the wall's side, it is never reused, and
    /// `idx_rel_arrival` makes it the same shape of range scan the id
    /// cursor was.
    pub fn posted_nzb_candidates(
        &self,
        after: i64,
        limit: usize,
    ) -> rusqlite::Result<Vec<PostedNzbCandidate>> {
        // The completeness test uses the nsegs-or-count shape every other
        // site uses: pre-migration rows carry nsegs=0 until the backfill
        // converges, and the daemon's durable nzbimport_cursor advances
        // past them - a raw `nsegs >= total_parts` skipped those rows
        // here, and once backfilled they sat behind the cursor forever.
        let mut stmt = self.db.prepare_cached(
            "SELECT r.id, r.arrival_seq, r.stem, r.grp, r.junk, f.segments, f.bytes
               FROM releases r JOIN files f ON f.release_id = r.id
              WHERE r.arrival_seq > ?1
                AND r.files = 1
                AND lower(f.filename) LIKE '%.nzb'
                AND (CASE WHEN f.nsegs > 0 THEN f.nsegs
                          ELSE seg_count(f.segments) END) >= f.total_parts
              ORDER BY r.arrival_seq LIMIT ?2",
        )?;
        let rows: Vec<(i64, i64, String, String, i64, SegRaw, i64)> = stmt
            .query_map(rusqlite::params![after, limit as i64], |r| {
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
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(id, seq, stem, grp, junk, segraw, bytes)| {
                // Stored as segcodec's compact form, or the older
                // [[part, "<msgid>", bytes], ...] JSON. A row that fails
                // both shapes is dropped AFTER the SQL LIMIT, and the
                // caller reads an empty batch as "caught up" - so a
                // silent drop right after the cursor is a silent
                // permanent stall. Unreachable today (both writers
                // serialize exactly this tuple); if schema drift ever
                // makes it reachable, it must say so.
                let segs: Vec<(u32, String, u64)> = if segcodec::is_encoded(&segraw.0) {
                    segcodec::decode(&segraw.0)
                } else {
                    serde_json::from_slice(&segraw.0).ok()
                }
                .or_else(|| {
                    tracing::warn!(
                        target: "nzbimport",
                        "release {id}: undecodable segments value - candidate skipped"
                    );
                    None
                })?;
                let mut segs: Vec<(u32, String)> =
                    segs.into_iter().map(|(n, id, _)| (n, id)).collect();
                segs.sort_unstable_by_key(|(n, _)| *n);
                Some(PostedNzbCandidate {
                    release_id: id,
                    arrival_seq: seq,
                    stem,
                    grp,
                    junk,
                    segs,
                    bytes: bytes.max(0) as u64,
                })
            })
            .collect())
    }

    /// The walk's durable position, as an `arrival_seq`.
    ///
    /// On the first read after an upgrade there is no arrival cursor,
    /// only the retired release-id one - so seed the new key from it,
    /// once, and never consult the old key again.
    ///
    /// The seed is the id value VERBATIM, and that is the whole trap in
    /// this fix. Every release that existed when `arrival_seq` was added
    /// took `arrival_seq = id` (see `arrival_counter_and_indexes`), so a
    /// cursor of `id > N` and one of `arrival_seq > N` exclude the same
    /// prefix: the upgrade resumes where the walk stood instead of
    /// re-fetching a whole index worth of posted NZBs from the user's
    /// provider (~270 objects on the 15.9M-row live index, and every
    /// install pays in proportion). Anything cleverer - deriving the
    /// seed from the arrival_seq of the rows ABOVE the old cursor, say -
    /// can be dragged arbitrarily low by one recycled row and turns into
    /// exactly that fetch storm.
    ///
    /// What the verbatim seed does NOT recover: rows already lost to the
    /// old cursor, i.e. recycled into an id below it before this fix.
    /// They are indistinguishable from settled rows by arrival_seq alone
    /// and re-walking on suspicion is the storm again, so the fix is
    /// forward-looking - no row can be skipped from here on.
    pub fn nzbimport_cursor(&self) -> i64 {
        if let Some(v) = self
            .kv_get(NZBIMPORT_CURSOR)
            .and_then(|v| v.parse::<i64>().ok())
        {
            return v;
        }
        let seed = self
            .kv_get(NZBIMPORT_CURSOR_LEGACY_ID)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        // A failed write (busy index) just means the next tick seeds it
        // again from the same value - the seed is idempotent, and the
        // legacy key is left in place so a downgrade still resumes.
        let _ = self.nzbimport_cursor_set(seed);
        seed
    }

    /// Persist the walk's position. Called per settled object, so a
    /// restart mid-tick never re-fetches what this one already settled.
    pub fn nzbimport_cursor_set(&self, seq: i64) -> rusqlite::Result<()> {
        self.kv_set(NZBIMPORT_CURSOR, &seq.to_string())
    }

    /// The posted stem of one release (None = evicted/unknown id).
    /// What the MsgidSet lanes gate their apply decision on: naming a
    /// row requires knowing what it is called NOW.
    pub fn stem_of(&self, rid: i64) -> Option<String> {
        self.db
            .prepare_cached("SELECT stem FROM releases WHERE id=?1")
            .ok()?
            .query_row([rid], |r| r.get(0))
            .ok()
    }

    /// Reverse message-id lookup over the whole index for a batch of
    /// payload message-ids (stored/bracketed form). One full pass over
    /// `files` via `json_each` probing a temp table - minutes on a
    /// 13 GB index, so batch EVERY parsed NZB's ids into one call and
    /// group per NZB afterwards ([`crate::nzbimport::group_hits`]).
    ///
    /// INTERIM: the identity substrate's persistent reverse table
    /// replaces the scan with an indexed probe; the return shape is
    /// designed to survive that swap.
    pub fn msgid_lookup(&self, msgids: &[String]) -> rusqlite::Result<Vec<MsgidRow>> {
        self.db.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS nzbimport_ids(msgid TEXT PRIMARY KEY);
             DELETE FROM nzbimport_ids;",
        )?;
        {
            let mut ins = self
                .db
                .prepare_cached("INSERT OR IGNORE INTO nzbimport_ids(msgid) VALUES(?1)")?;
            for id in msgids {
                ins.execute([id])?;
            }
        }
        // The join used to be `json_each(f.segments)` in SQL; the
        // compact form (segcodec) has no table-valued reader, so the
        // walk decodes each row here instead. Same full scan of `files`
        // as before - the statement was never indexed - and one row's
        // list in memory at a time.
        let wanted: std::collections::HashSet<&str> = msgids.iter().map(|s| s.as_str()).collect();
        let mut stmt = self.db.prepare(
            "SELECT f.segments, f.release_id, r.stem, r.have_parts
               FROM files f JOIN releases r ON r.id = f.release_id",
        )?;
        let mut rows = Vec::new();
        let mut q = stmt.query([])?;
        while let Some(r) = q.next()? {
            let segs = r.get::<_, SegList>(0)?.0;
            let mut hit = false;
            for (_, id, _) in &segs {
                if wanted.contains(id.as_str()) {
                    hit = true;
                    break;
                }
            }
            if !hit {
                continue;
            }
            let release_id: i64 = r.get(1)?;
            let stem: String = r.get(2)?;
            let row_nsegs = r.get::<_, i64>(3)?.max(0) as u32;
            for (_, id, _) in segs {
                if wanted.contains(id.as_str()) {
                    rows.push(MsgidRow {
                        msgid: id,
                        release_id,
                        stem: stem.clone(),
                        row_nsegs,
                    });
                }
            }
        }
        let _ = self.db.execute("DELETE FROM nzbimport_ids", []);
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::entry;

    fn open_scratch(name: &str) -> (std::path::PathBuf, Index) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-nzbimport-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        (dir.clone(), Index::open(&db).unwrap())
    }

    #[test]
    fn candidates_select_complete_one_file_nzb_rows_only() {
        let (dir, mut ix) = open_scratch("cand");
        // A one-file complete .nzb post (the candidate).
        ix.ingest(
            "a.b.test",
            &[entry(r#""Some.Release.nzb" yEnc (1/1)"#, "p@x", "n1", 900)],
            1000,
        )
        .unwrap();
        // A one-file INCOMPLETE .nzb post (2 parts, 1 held) - excluded.
        ix.ingest(
            "a.b.test",
            &[entry(r#""Other.Release.nzb" yEnc (1/2)"#, "p@x", "n2", 900)],
            1000,
        )
        .unwrap();
        // A multi-file release that happens to contain a .nzb - excluded.
        // (Both names must reduce to ONE stem to cluster: .par2 strips,
        // so "Two.Files.nzb" + "Two.Files.nzb.par2" share a release. A
        // .nzb posted BESIDE content never clusters with it - the .nzb
        // suffix survives release_stem - which is exactly why the
        // one-file shape is the candidate population.)
        ix.ingest(
            "a.b.test",
            &[
                entry(r#""Two.Files.nzb" yEnc (1/1)"#, "q@x", "n3", 900),
                entry(r#""Two.Files.nzb.par2" yEnc (1/1)"#, "q@x", "n4", 900),
            ],
            1000,
        )
        .unwrap();
        // A plain one-file post - excluded by name.
        ix.ingest(
            "a.b.test",
            &[entry(r#""Not.An.Nzb.rar" yEnc (1/1)"#, "p@x", "n5", 900)],
            1000,
        )
        .unwrap();
        let cands = ix.posted_nzb_candidates(0, 100).unwrap();
        assert_eq!(cands.len(), 1, "{cands:?}");
        assert_eq!(cands[0].stem, "Some.Release.nzb");
        assert_eq!(cands[0].segs, vec![(1, "<n1>".to_string())]);
        // The cursor excludes already-walked rows.
        assert!(
            ix.posted_nzb_candidates(cands[0].arrival_seq, 100)
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M6 (10 Aug 2026 Codex sweep): `releases.id` has no AUTOINCREMENT,
    /// so deleting the top row hands its id to the next insert - and
    /// maintenance folds and eviction do delete releases. Under the old
    /// `id > cursor` walk the recycled row was excluded forever.
    #[test]
    fn a_posted_nzb_on_a_recycled_release_id_is_still_walked() {
        let (dir, mut ix) = open_scratch("recycle");
        ix.ingest(
            "a.b.test",
            &[entry(r#""First.Release.nzb" yEnc (1/1)"#, "p@x", "n1", 900)],
            1000,
        )
        .unwrap();
        ix.ingest(
            "a.b.test",
            &[entry(
                r#""Second.Release.nzb" yEnc (1/1)"#,
                "q@x",
                "n2",
                900,
            )],
            1000,
        )
        .unwrap();
        // Walk both, exactly as the daemon rung does.
        let mut cursor = 0i64;
        for c in ix.posted_nzb_candidates(cursor, 100).unwrap() {
            cursor = c.arrival_seq;
        }
        assert!(cursor > 0);
        // Maintenance deletes the TOP row - the one whose id SQLite
        // reuses next.
        let top: i64 = ix
            .db
            .query_row("SELECT MAX(id) FROM releases", [], |r| r.get(0))
            .unwrap();
        ix.db
            .execute("DELETE FROM files WHERE release_id=?1", [top])
            .unwrap();
        ix.db
            .execute("DELETE FROM releases WHERE id=?1", [top])
            .unwrap();
        // A brand new posted NZB arrives and lands on the freed id.
        ix.ingest(
            "a.b.test",
            &[entry(r#""Third.Release.nzb" yEnc (1/1)"#, "r@x", "n3", 900)],
            1000,
        )
        .unwrap();
        let fresh = ix.posted_nzb_candidates(cursor, 100).unwrap();
        assert_eq!(
            fresh.iter().map(|c| c.stem.as_str()).collect::<Vec<_>>(),
            vec!["Third.Release.nzb"],
            "the recycled-id row must still be walked (cursor {cursor})"
        );
        assert_eq!(
            fresh[0].release_id, top,
            "test is only meaningful if SQLite really reused the id"
        );
        assert!(
            fresh[0].release_id <= cursor,
            "and only if the reused id sits at or below the old id cursor"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The upgrade path: a database carrying only the retired release-id
    /// cursor must resume from it, not re-fetch every posted NZB it has
    /// already imported.
    #[test]
    fn the_retired_id_cursor_seeds_the_arrival_cursor_once() {
        let (dir, mut ix) = open_scratch("seed");
        for (n, stem) in [(1, "One"), (2, "Two"), (3, "Three")] {
            ix.ingest(
                "a.b.test",
                &[entry(
                    &format!(r#""{stem}.Release.nzb" yEnc (1/1)"#),
                    "p@x",
                    &format!("n{n}"),
                    900,
                )],
                1000,
            )
            .unwrap();
        }
        // A fresh index has neither key: start from the beginning.
        assert_eq!(ix.nzbimport_cursor(), 0);
        ix.db
            .execute("DELETE FROM kv WHERE k=?1", [NZBIMPORT_CURSOR])
            .unwrap();

        // Now the pre-fix state: the walk stopped after the second row,
        // recorded as a release id.
        let walked: i64 = ix
            .db
            .query_row(
                "SELECT id FROM releases WHERE stem='Two.Release.nzb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        ix.kv_set(NZBIMPORT_CURSOR_LEGACY_ID, &walked.to_string())
            .unwrap();
        assert_eq!(ix.nzbimport_cursor(), walked, "seeded from the id cursor");
        assert_eq!(
            ix.posted_nzb_candidates(ix.nzbimport_cursor(), 100)
                .unwrap()
                .iter()
                .map(|c| c.stem.clone())
                .collect::<Vec<_>>(),
            vec!["Three.Release.nzb".to_string()],
            "the upgrade resumes at the third row - the first two are \
             already imported and must not be re-fetched"
        );
        // Seeded once: later reads take the arrival key, and a stale
        // legacy key (a downgrade that walked on) cannot drag it back.
        ix.nzbimport_cursor_set(9_000).unwrap();
        ix.kv_set(NZBIMPORT_CURSOR_LEGACY_ID, "1").unwrap();
        assert_eq!(ix.nzbimport_cursor(), 9_000);
        assert!(
            ix.posted_nzb_candidates(ix.nzbimport_cursor(), 100)
                .unwrap()
                .is_empty(),
            "a cursor past every row selects nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn msgid_join_counts_matches_per_release() {
        let (dir, mut ix) = open_scratch("join");
        // A dark row holding 3 segments.
        ix.ingest(
            "a.b.test",
            &[
                entry(r#""abc123xyz.part1.rar" yEnc (1/2)"#, "p@x", "d1", 900),
                entry(r#""abc123xyz.part1.rar" yEnc (2/2)"#, "p@x", "d2", 900),
                entry(r#""abc123xyz.part2.rar" yEnc (1/1)"#, "p@x", "d3", 900),
            ],
            1000,
        )
        .unwrap();
        // Another row sharing nothing.
        ix.ingest(
            "a.b.test",
            &[entry(r#""unrelated.rar" yEnc (1/1)"#, "p@x", "u1", 900)],
            1000,
        )
        .unwrap();
        // NZB claims d1..d3 plus one unknown id.
        let ids: Vec<String> = ["<d1>", "<d2>", "<d3>", "<nowhere@x>"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rows = ix.msgid_lookup(&ids).unwrap();
        assert_eq!(rows.len(), 3, "{rows:?}");
        let hits = crate::nzbimport::group_hits(&ids, &rows);
        assert_eq!(hits.len(), 1, "{hits:?}");
        let h = &hits[0];
        assert_eq!(h.stem, "abc123xyz");
        assert_eq!(h.matched, 3);
        assert_eq!(h.row_nsegs, 3, "quorum denominator is the RELEASE total");
        assert!(crate::nzbimport::quorum(h.matched, h.row_nsegs));

        // A second NZB sharing the batch but holding only d1 must see
        // its own count (1), not the batch's (3) - per-NZB attribution.
        let ids2: Vec<String> = vec!["<d1>".into()];
        let hits2 = crate::nzbimport::group_hits(&ids2, &rows);
        assert_eq!(hits2[0].matched, 1);
        assert!(!crate::nzbimport::quorum(
            hits2[0].matched,
            hits2[0].row_nsegs
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
