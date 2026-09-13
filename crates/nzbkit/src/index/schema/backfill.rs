//! The one-shot DATA migrations the schema ladder runs at open: the
//! backfills that fill a newly-added column on rows written before it
//! existed, the one table rebuild SQLite cannot express as an ALTER, and
//! the budgeted quality re-classification slice the indexer lap
//! finishes. `schema.rs` keeps the DDL - the CREATEs, the ALTERs, the
//! indexes and triggers; this file keeps everything that MOVES ROWS.
//!
//! Cut out of `schema.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,469 of the size gate's 4,000-line file ceiling, before a feature
//! lane met it. Every line here is a verbatim move: the call order in
//! [`super::Index::open`] is unchanged and load-bearing, each step keeps
//! its own error handling (a non-fatal `let _ =` migration STAYS
//! non-fatal - a failed step is retried by the next open), and the only
//! rewrite is `fn` -> `pub(super) fn` so `schema.rs` can still call them.

use super::*;

/// Step 3: the predb.pt index and its one-shot backfill.
///
/// Last, and after [`additive_columns`] has guaranteed `pt` on every
/// install. The kv flag is what keeps the UPDATE from re-running on
/// every open of a large feed table.
pub(super) fn predb_pt_backfill(db: &Connection) {
    // The pt index and its one-shot backfill live here, after the
    // ALTER above has guaranteed the column on every install. The
    // kv flag keeps the UPDATE from re-running on every open of a
    // large feed table; it runs BEFORE anything samples predb.
    let _ = db.execute("CREATE INDEX IF NOT EXISTS idx_predb_pt ON predb(pt)", []);
    let pt_done: bool = db
        .query_row(
            "SELECT 1 FROM kv WHERE k='predb_pt_backfill_v1'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if !pt_done {
        let done = db
            .execute(
                "UPDATE predb SET pt=CASE WHEN pre_at>0 THEN pre_at ELSE seen_at END
                  WHERE pt=0",
                [],
            )
            .is_ok();
        if done {
            let _ = db.execute(
                "INSERT OR REPLACE INTO kv(k,v) VALUES('predb_pt_backfill_v1','1')",
                [],
            );
        }
    }
}

/// A8: rebuild a single-server-era marks table to (grp, server).
pub(super) fn rebuild_marks_if_needed(db: &Connection) {
    // A8: rebuild a single-server-era marks table (PRIMARY KEY(grp))
    // to the (grp, server) shape. SQLite cannot ALTER a primary key,
    // so this is the standard rebuild - one-time; the PRAGMA guard
    // keeps every later open from bumping the schema version. Rows
    // keep server='' until adopt_legacy_marks assigns them to the
    // server that actually built them. Non-fatal like the other
    // migrations: on failure the next open retries, and the worst a
    // lost marks table costs is a rescan (ingest is idempotent).
    let has_server_col = db
        .prepare("SELECT 1 FROM pragma_table_info('marks') WHERE name='server'")
        .and_then(|mut s| s.exists([]))
        .unwrap_or(false);
    if !has_server_col {
        // A real Transaction object, not a BEGIN/COMMIT batch: a
        // mid-batch failure would otherwise leave the transaction
        // open on this connection, and every later statement in this
        // open() would silently run (and hold the write lock) inside
        // it. The drop of an uncommitted Transaction rolls back.
        let rebuild = db.unchecked_transaction().and_then(|tx| {
            tx.execute_batch(
                "DROP TABLE IF EXISTS marks_v2;
                 CREATE TABLE marks_v2(
                    grp TEXT NOT NULL,
                    server TEXT NOT NULL DEFAULT '',
                    high INTEGER NOT NULL,
                    low INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(grp, server));
                 INSERT INTO marks_v2(grp, server, high, low)
                   SELECT grp, '', high, low FROM marks;
                 DROP TABLE marks;
                 ALTER TABLE marks_v2 RENAME TO marks;",
            )?;
            tx.commit()
        });
        let _ = rebuild;
    }
}

/// TODO 5 phase 2c: fill `releases.stem_fold` for rows written before
/// the column existed.
///
/// Chunked with a kv rowid cursor and time-bounded, the `nsegs_fill`
/// shape and for the same two reasons: a single UPDATE over the whole
/// releases table (16.5 M rows on the live index) loses the write lock
/// to a running scanner and is silently discarded, and an unbounded
/// loop here blocks daemon startup, since every scan task opens its own
/// Index. Whatever is left resumes on the next open, and the read side
/// is correct throughout - an unfilled row is findable exactly as it
/// was before the column existed.
///
/// The `GLOB '*[^ -~]*'` term is what keeps this cheap: it is SQLite's
/// way of asking "does this stem hold a byte outside printable ASCII",
/// so the chunk hands Rust only the handful of rows that could possibly
/// earn a fold instead of marshalling 16.5 M stems across the boundary
/// to discover they are all ASCII. It is a filter, not a correctness
/// term - [`fold::stored`] re-decides for itself, and returns '' for
/// every non-ASCII stem `LOWER()` was already folding correctly.
///
/// This generation only ever ADDS a fold, which is all a never-filled
/// column needs. Clearing a fold that has gone stale is the second
/// generation's job, in [`fold_reconcile`].
pub(super) fn fold_backfill(db: &mut Connection) {
    fold_pass(db, "fold_v1", "fold_at", "stem GLOB '*[^ -~]*'");
}

/// TODO 5 phase 2c, corrective generation: reconcile `stem_fold` with
/// what [`fold::stored`] says the row's stem folds to, on databases
/// carrying a fold left behind by a stem rewrite.
///
/// `Index::split_merge_group` in `maintenance.rs` collapses a split
/// release's volumes into one row and rewrites `stem` to the common
/// prefix. Until 886785fd7 (23 Aug 2026) it left `stem_fold` holding
/// the fold of the stem it had just replaced - so a merged Cyrillic
/// group keeps a fold ending in the volume suffix the merge removed,
/// ` 001`. Both non-FTS readers match on that column and so answer for
/// a stem that no longer exists: [`query::stem_fold_arm`], which is the
/// whole search path on a build without FTS, and the browse hide rule
/// that spells the same expression by hand. The FTS arm never saw it -
/// it tokenizes `stem`.
///
/// 886785fd7 stopped new ones being written; it could not repair the
/// ones already on disk, and [`fold_backfill`] above cannot either. Its
/// flag is long since stamped on every live index, and even re-armed it
/// only ever writes a NON-empty fold, so a row whose replacement stem
/// is ASCII would keep the stale one. Hence a second generation with
/// its own flag rather than a rearm of the first.
///
/// Two things follow from that, both in the prefilter:
///
/// * `stem_fold <> ''` is a correctness term here, not just a cost one.
///   A merge that shortens `ВОЙНА.001` to an ASCII stem leaves a fold
///   the GLOB above would never look at.
/// * The sparse rule survives: this writes back exactly what
///   [`fold::stored`] returns, which is `''` for an ASCII stem and for
///   any stem `LOWER()` already folds correctly, so a corrected row
///   costs a record-header byte rather than a second copy of the stem.
///
/// There is no `WHERE stem_fold <> fold(stem)` to write instead of the
/// walk: the fold is Rust, and the daemon's SQLite carries no function
/// for it.
pub(super) fn fold_reconcile(db: &mut Connection) {
    fold_pass(
        db,
        "fold_v2",
        "fold_v2_at",
        "(stem GLOB '*[^ -~]*' OR stem_fold <> '')",
    );
}

/// The chunked rowid walk both `stem_fold` generations above are: read
/// the cursor, re-judge every row in the next stride that `prefilter`
/// admits, write back the ones [`fold::stored`] disagrees with, move
/// the cursor. `done_key` is stamped when the walk runs off the end of
/// the table; until then each open resumes where the last one stopped.
///
/// A generation is identified by its two kv keys, and nothing else -
/// the prefilter may be widened for a later one without disturbing an
/// earlier one's flag.
pub(super) fn fold_pass(db: &mut Connection, done_key: &str, at_key: &str, prefilter: &str) {
    /// Rowids per chunk. Twenty times `nsegs_fill`'s because the
    /// prefilter turns almost every row into a rejected comparison
    /// rather than a row read plus an UPDATE.
    const CHUNK: i64 = 20_000;
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k=?1", [done_key], |r| r.get(0))
        .ok();
    if done.as_deref() == Some("1") {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let sel_sql = format!(
        "SELECT id, stem, stem_fold FROM releases
          WHERE rowid > ?1 AND rowid <= ?2 AND {prefilter}"
    );
    let _ = (|| -> rusqlite::Result<()> {
        loop {
            // Immediate, and the cursor read INSIDE it: several scan
            // connections open the index at once, and a deferred
            // transaction let two of them read the same cursor and the
            // slower one write back a stale lower value.
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let cursor: i64 = tx
                .query_row("SELECT v FROM kv WHERE k=?1", [at_key], |r| {
                    r.get::<_, String>(0)
                })
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            // Advance by rowid, never by "stem_fold = ''": that is the
            // steady state of nearly every row, so it would re-select
            // the same chunk forever.
            let next: Option<i64> = tx.query_row(
                "SELECT MAX(rowid) FROM
                   (SELECT rowid FROM releases WHERE rowid > ?1 ORDER BY rowid LIMIT ?2)",
                [cursor, CHUNK],
                |r| r.get(0),
            )?;
            let Some(next) = next else {
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES(?1,'1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [done_key],
                )?;
                tx.commit()?;
                return Ok(());
            };
            {
                let mut sel = tx.prepare(&sel_sql)?;
                let mut upd = tx.prepare("UPDATE releases SET stem_fold=?2 WHERE id=?1")?;
                let rows: Vec<(i64, String, String)> = sel
                    .query_map([cursor, next], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem, held) in rows {
                    let f = super::fold::stored(&stem);
                    // Compared, not written unconditionally: on a
                    // healthy index every admitted row already agrees,
                    // so the pass reads and writes nothing.
                    if f != held {
                        upd.execute(rusqlite::params![id, f])?;
                    }
                }
            }
            // Cursor moves with the rows, in the same transaction: a
            // busy failure rolls back both and the chunk is redone.
            tx.execute(
                "INSERT INTO kv(k, v) VALUES(?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                rusqlite::params![at_key, next.to_string()],
            )?;
            tx.commit()?;
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
        }
    })();
}

/// The one-shot, kv-stamped retroactive backfills (completeness rule,
/// nsegs, M25 kind/res, M28 FTS + title_key/junk, stem_fold in its two
/// generations, quality_v10).
pub(super) fn retroactive_backfills(db: &mut Connection, fts: bool) {
    // One-time retroactive recompute after the completeness-rule
    // change (nfiles >= 2 → >= 1): existing rows only re-evaluate
    // when a scan touches them, which for finished uploads is never.
    let rule: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='complete_rule'", [], |r| r.get(0))
        .ok();
    if rule.as_deref() != Some("2") {
        // One transaction, and the done-flag only lands if the
        // recompute did: as two autocommit statements, a SQLITE_BUSY
        // on the big UPDATE (discarded) with the tiny insert
        // succeeding stamped the migration done while every
        // completeness flag stayed stale - permanently.
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute(
                "UPDATE releases SET complete =
                   EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id)
                   AND NOT EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id
                                  AND (CASE WHEN f.nsegs > 0 THEN f.nsegs
                                               ELSE seg_count(f.segments) END) < f.total_parts)",
                [],
            )?;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('complete_rule','2')
                 ON CONFLICT(k) DO UPDATE SET v='2'",
                [],
            )?;
            tx.commit()
        })();
    }
    // Retroactive fill of `nsegs` for rows written before the column
    // existed. Finished uploads are never re-ingested, so without
    // this they would take the JSON-parsing fallback above forever.
    //
    // Chunked with a kv rowid cursor, and time-bounded, for two
    // reasons learned the hard way. A single UPDATE over the whole
    // files table (1.6 M rows on the live index) loses the write
    // lock to a running scanner and is silently discarded - the
    // junk_v6 re-score did exactly that. And an unbounded loop here
    // would block daemon startup for minutes, since every scan task
    // opens its own Index. Whatever is left resumes on the next
    // open; the read side is correct throughout either way.
    let filled: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='nsegs_fill'", [], |r| r.get(0))
        .ok();
    if filled.as_deref() != Some("1") {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let _ = (|| -> rusqlite::Result<()> {
            loop {
                // Acquire the writer reservation BEFORE reading the
                // cursor. Several scan connections open the index at
                // once; a deferred transaction let two of them read
                // the same cursor, then a delayed one could overwrite
                // a later cursor with its stale lower value.
                let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let cursor: i64 = tx
                    .query_row("SELECT v FROM kv WHERE k='nsegs_at'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                // Advance by rowid, never by "nsegs = 0": a row whose
                // segments JSON will not parse stays 0 forever and
                // would be re-selected every pass, spinning here.
                let next: Option<i64> = tx.query_row(
                    "SELECT MAX(rowid) FROM
                       (SELECT rowid FROM files WHERE rowid > ?1 ORDER BY rowid LIMIT 5000)",
                    [cursor],
                    |r| r.get(0),
                )?;
                let Some(next) = next else {
                    tx.execute(
                        "INSERT INTO kv(k, v) VALUES('nsegs_fill','1')
                         ON CONFLICT(k) DO UPDATE SET v='1'",
                        [],
                    )?;
                    tx.commit()?;
                    return Ok(());
                };
                tx.execute(
                    "UPDATE files SET nsegs = COALESCE(seg_count(segments), 0)
                     WHERE rowid > ?1 AND rowid <= ?2",
                    [cursor, next],
                )?;
                // Cursor moves with the rows, in the same
                // transaction: a busy failure rolls back both and
                // the chunk is simply redone.
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('nsegs_at', ?1)
                     ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    [next.to_string()],
                )?;
                tx.commit()?;
                if std::time::Instant::now() >= deadline {
                    return Ok(());
                }
            }
        })();
    }
    fold_backfill(db);
    fold_reconcile(db);
    // M25 browse view: retroactive fill of the new kind/res/part
    // columns for rows indexed before they existed. Same shape as
    // the complete_rule migration: one transaction, flag stamped
    // only if the fill landed, so SQLITE_BUSY just retries next open.
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='browse_cols'", [], |r| r.get(0))
        .ok();
    if done.as_deref() != Some("1") {
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute(
                "UPDATE releases SET
                   have_parts = COALESCE((SELECT SUM(seg_count(segments))
                                          FROM files WHERE release_id=releases.id), 0),
                   need_parts = COALESCE((SELECT SUM(total_parts)
                                          FROM files WHERE release_id=releases.id), 0)",
                [],
            )?;
            {
                let mut sel = tx.prepare("SELECT id, stem FROM releases WHERE kind=''")?;
                let mut upd = tx.prepare("UPDATE releases SET kind=?2, res=?3 WHERE id=?1")?;
                let rows: Vec<(i64, String)> = sel
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem) in rows {
                    let p = crate::release::parse_release(&stem);
                    upd.execute(rusqlite::params![
                        id,
                        kind_str(&p.kind),
                        p.res.unwrap_or_default()
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('browse_cols','1')
                 ON CONFLICT(k) DO UPDATE SET v='1'",
                [],
            )?;
            tx.commit()
        })();
    }
    // M28: one-time FTS backfill for rows inserted before the
    // triggers existed - 'rebuild' re-reads the whole content table.
    // Same stamped-in-transaction shape as the migrations above.
    if fts {
        let done: Option<String> = db
            .query_row("SELECT v FROM kv WHERE k='fts_v1'", [], |r| r.get(0))
            .ok();
        if done.as_deref() != Some("1") {
            let _ = (|| -> rusqlite::Result<()> {
                let tx = db.unchecked_transaction()?;
                tx.execute("INSERT INTO rel_fts(rel_fts) VALUES('rebuild')", [])?;
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('fts_v1','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()
            })();
        }
    }
    // M28: retroactive title_key + junk fill (rows only re-parse when
    // a scan touches them, which for finished uploads is never).
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='browse2'", [], |r| r.get(0))
        .ok();
    if done.as_deref() != Some("1") {
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            {
                let mut sel =
                    tx.prepare("SELECT id, stem, total_bytes FROM releases WHERE title_key=''")?;
                let mut upd =
                    tx.prepare("UPDATE releases SET title_key=?2, junk=?3 WHERE id=?1")?;
                let rows: Vec<(i64, String, i64)> = sel
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem, bytes) in rows {
                    let p = crate::release::parse_release(&stem);
                    upd.execute(rusqlite::params![
                        id,
                        p.key,
                        junk_score(&stem, &p, bytes as u64, false)
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('browse2','1')
                 ON CONFLICT(k) DO UPDATE SET v='1'",
                [],
            )?;
            tx.commit()
        })();
    }
    // §131 identity substrate: key existing files rows into msgid_map
    // (rows only pass through ingest when a scan touches them, which
    // for finished uploads is never). Same chunked, time-bounded,
    // cursor-resumed shape as the nsegs fill above, for the same
    // reasons: the live table is millions of rows, a single UPDATE
    // loses the write lock to a running scanner, and an unbounded
    // loop would stall daemon startup. Resumes on the next open.
    super::claims::msgid_map_backfill(db);
    // Pesto counter/clock fill for rows scanned before the columns
    // existed - same chunked, time-bounded, cursor-resumed shape, for
    // the same reasons.
    super::pesto::pesto_backfill(db);
    quality_backfill(db);
}

/// quality_v10 (2 Sep 2026, was quality_v9 on 16 Aug, quality_v8
/// before that, junk_v7 before that): the bump re-files the book,
/// music and anime lanes. Six classifier fixes landed on 2 Sep and
/// NONE of them could reach a row already stored - the `pdf`/`max`/
/// edition-number reads (d94b4735c), the group prior (e2f399a57),
/// the rot13 music and book rescue (633b7baf8), the fansub episode
/// read (ea2229aa2), the dashed `Show - NNN - Title` episode read
/// (3f52c0ca4) and the masthead date reading (4724a8f0b). An
/// audiobook folder in alt.binaries.mp3.audiobooks carries
/// `kind=movie, junk=60`, the naming seam refuses a row whose
/// pre_title is set, and the custom-category sweep only runs when
/// the category config changes. Without the bump every one of those
/// fixes would apply to new posts only.
///
/// Two of the six are GROUP-aware, which is what v10 costs over a
/// free re-run of v9: the SELECT carries `grp` and the pass runs the
/// group half of ingest's chain as well as the name half it already
/// ran.
///
/// v9's own reason, kept because the bump inherits it: the book lane
/// re-file, junk_v6's rules plus a full
/// re-parse - title_key/kind/res so ROT13 rescues that the parser
/// newly decodes regroup under their real titles, and now
/// vcodec/acodec/hdr, which rows indexed before those columns
/// existed have never carried. The kv key names the CURRENT
/// version; bumping it re-parses every row exactly once, which is
/// what backfills the new columns - free, because this pass
/// already parses every row's effective name. CHUNKED with a
/// persisted id cursor - the
/// one-big-tx shape could never win the write lock against
/// parallel scanners on a live daemon (SQLITE_BUSY → silently
/// skipped forever). 10k rows per transaction interleaves with
/// scan ingest; a partial pass resumes from the cursor on the
/// next open.
///
/// TIME-BOUNDED, unlike v9's inline loop, and that is the other half of
/// what makes a bump safe to take again. This runs inside
/// `Index::open`, so an unbounded loop re-parses the whole table before
/// the daemon serves its first request - and v9's loop was unbounded.
/// MEASURED, release build, 400k synthetic rows with two `files` rows
/// each so the SELECT's EXISTS probe does real work (the rig is
/// `qual_bench::time_the_quality_pass`, `--ignored`). Twice, because
/// the first run was on a box carrying five other worktree builds and
/// the spread is the interesting part:
///
///     load ~39   30.8 s / 400k   =  77.1 s per million rows
///     load ~23   16.6 s / 400k   =  41.6 s per million rows
///
/// So a 67M-row index, which the largest live ones are, is somewhere
/// between 46 and 86 minutes, and it is CPU that a busy box makes
/// worse. Stated limits in
/// both directions: a loaded box inflates the rate, and a 400k-row
/// scratch index sits entirely in page cache while a live 67M-row one
/// does not, which deflates it. Neither matters to the decision. What
/// this is not is borderline: the conclusion survives being wrong by
/// 4x either way.
///
/// So the pass takes the shape of the two backfills above it instead: a
/// budget per call, the persisted cursor doing the resuming, and a
/// maintenance leg in the indexer lap
/// (`passes::quality_backfill_pass`) finishing what the 2 s at open
/// could not. The heal is therefore gradual rather than instant, which
/// is the right trade for a re-file of rows that have been mis-filed
/// since they were indexed: nothing downstream has a deadline on it.
pub(super) fn quality_backfill(db: &mut Connection) {
    quality_backfill_slice(db, std::time::Duration::from_secs(2));
}

/// One budgeted slice of [`quality_backfill`]. Returns true when the
/// pass is COMPLETE, so a caller's slice loop can stop early - the same
/// caught-up contract as `msgid_map_backfill_slice`.
pub(super) fn quality_backfill_slice(db: &mut Connection, budget: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    let mut complete = false;
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='quality_v10'", [], |r| r.get(0))
        .ok();
    if done.as_deref() == Some("1") {
        return true;
    }
    let _ = (|| -> rusqlite::Result<()> {
        let mut cursor: i64 = db
            .query_row("SELECT v FROM kv WHERE k='quality_v10_cursor'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        loop {
            // IMMEDIATE, like the nsegs, reclassify and ingest
            // transactions: this reads a cursor and writes it
            // back, and a deferred lock upgrade does NOT get the
            // busy timeout - it returns SQLITE_BUSY at once. A
            // deferred wrapper here meant a contended pass
            // abandoned mid-chunk and left the cursor parked.
            let tx =
                rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
            // The effective name, NOT the raw stem: a row named
            // after ingest (`apply_named` - predb sweep, spot
            // promotion, byte probes) derived every classification
            // column from pre_title, and its stem is an obfuscated
            // hash. Re-parsing the stem here would clobber the row
            // back to the junk>=70 no-card answer, and nothing
            // would ever heal it - the naming seam refuses rows
            // whose pre_title is already set. Same COALESCE the
            // ingest and card paths use.
            // `grp` is the sixth column and the reason this key
            // is v10: two of the six classifier fixes it heals are
            // GROUP-aware (`recover_kind_from_group` and
            // `recover_episode_from_group`), and v9's SELECT could
            // not feed them. `releases.grp` is NOT NULL in the
            // original CREATE TABLE and part of the row's UNIQUE
            // identity, so every row ever written carries it - there
            // is no era of blank groups for this to no-op over.
            let rows: Vec<(i64, String, i64, bool, String, String)> = {
                let mut sel = tx.prepare_cached(&format!(
                    "SELECT id, COALESCE(NULLIF(pre_title,''), stem),
                                total_bytes,
                                EXISTS(SELECT 1 FROM files
                                       WHERE release_id=releases.id AND {EXE_FILE_SQL}),
                                stem, grp
                         FROM releases WHERE id > ?1 ORDER BY id LIMIT 10000"
                ))?;
                sel.query_map([cursor], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            if rows.is_empty() {
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('quality_v10','1')
                         ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()?;
                complete = true;
                return Ok(());
            }
            {
                // `parse_release` is CUSTOM-BLIND: `Index::open`
                // runs before `set_custom`, by construction (the
                // constructor hardcodes an empty category list),
                // so this pass cannot know the user's categories.
                // Re-parsing a row that `reclassify_custom`
                // classified would therefore rewrite kind and
                // title_key back to the built-in answer - every
                // session of an F1 season collapsing onto one
                // movie card, out of the category tab, and losing
                // the Custom junk exemption. Worse, it does not
                // heal: `reclassify_custom` sees an unchanged
                // fingerprint and no cursor and returns Ok(0) on
                // every later start.
                //
                // So the classification columns are written only
                // for rows still carrying a built-in kind. The
                // rest - the codec/resolution/language backfill
                // this pass exists for - is unconditional, and is
                // correct for custom rows too, because
                // `apply_custom` mutates ONLY kind and key.
                // '' is in the list deliberately: a row that has
                // never been classified still needs its first
                // parse.
                let mut upd = tx.prepare_cached(
                    "UPDATE releases SET langs=?2, res=?3,
                                vcodec=?4, acodec=?5, hdr=?6
                         WHERE id=?1 AND (langs<>?2 OR res<>?3
                                OR vcodec<>?4 OR acodec<>?5 OR hdr<>?6)",
                )?;
                let mut upd_class = tx.prepare_cached(
                    "UPDATE releases SET junk=?2, title_key=?3, kind=?4
                         WHERE id=?1
                           AND kind IN ('movie','tv','music','book',
                                        'software','other','')
                           AND (junk<>?2 OR title_key<>?3 OR kind<>?4)",
                )?;
                for (id, name, bytes, has_exe, stem, grp) in &rows {
                    let mut p = crate::release::parse_release(name);
                    // A fed name names the work; the stem names the
                    // file. Only the file says "book".
                    crate::release::recover_media_kind(&mut p, name, stem);
                    // THE SAME CHAIN AS `ingest_pass`, IN THE SAME
                    // ORDER (custom categories excepted, for the
                    // reason written below), because a backfill that
                    // classifies differently from ingest is a second
                    // classifier: rows would flap between the two
                    // answers on every scan touch. The group prior
                    // first (it
                    // returns early on an episode, so an episode
                    // invented ahead of it disarms the book/music
                    // rescue), then the episode read, gated on the
                    // same obfuscation test for the same reason -
                    // the season it records would make the blob test
                    // more lenient than it was.
                    crate::release::recover_kind_from_group(&mut p, grp, stem);
                    if !stem_obfuscated(stem, &p) {
                        crate::release::recover_episode_from_group(&mut p, grp, name);
                    }
                    upd.execute(rusqlite::params![
                        id,
                        p.langs.join(" "),
                        p.res.as_deref().unwrap_or_default(),
                        p.vcodec.as_deref().unwrap_or_default(),
                        p.acodec.as_deref().unwrap_or_default(),
                        p.hdr.as_deref().unwrap_or_default()
                    ])?;
                    upd_class.execute(rusqlite::params![
                        id,
                        junk_score(name, &p, *bytes as u64, *has_exe),
                        p.key,
                        kind_str(&p.kind)
                    ])?;
                }
            }
            cursor = rows.last().unwrap().0;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('quality_v10_cursor', ?1)
                     ON CONFLICT(k) DO UPDATE SET v=?1",
                [cursor.to_string()],
            )?;
            tx.commit()?;
            // The budget is spent BETWEEN chunks, never inside one:
            // the cursor and the rows it covers are one transaction,
            // and a slice that stopped mid-chunk would either park
            // the cursor behind work it had already done or roll the
            // work back. Same place `msgid_map_backfill_slice`
            // checks its own deadline, for the same reason.
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
        }
    })();
    complete
}
