//! Predb naming and pre/release correlation (TODO 106 phase 2.2, cut 2):
//! the predb store/prune/sweep, the correlation engine (corr_*), manual
//! pre assignment, and the seed store. Bodies are verbatim moves from the
//! old index.rs; see research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;

/// How many candidate releases one pre's forward window may return.
///
/// A cost bound that is also a correctness bound. `corr_mutual_best`
/// asks whether OUR candidate beats the best competitor by the auto
/// margin, and a competitor the query truncated away makes `best_other`
/// understated - which loosens the gate in the direction that renames
/// a release wrongly. So the cap is generous, and hitting it is treated
/// as "this window cannot answer the question" rather than as an
/// answer. Was 50, unordered, over a size-banded window.
const CORR_WINDOW: usize = 200;

/// Per-release inputs to the correlation scorer, computed once per
/// release per evaluation.
#[derive(Debug, Clone)]
struct CorrRelFacts {
    #[allow(dead_code)]
    stem: String,
    first_posted: i64,
    grp_kind: crate::predb_corr::GroupKind,
    est_content: u64,
    par2_identified: bool,
    rel_files: u32,
}

/// One predb row as the correlation legs read it.
#[derive(Debug, Clone)]
struct CorrPreRow {
    id: i64,
    title: String,
    category: String,
    source: String,
    size: u64,
    files: u32,
    nuked: bool,
    pt: i64,
    /// Carries a posted filename - such a row belongs to the exact
    /// legs, which outrank correlation by construction.
    has_fn: bool,
}

/// A scored (pre, release) candidate.
#[derive(Debug, Clone)]
struct CorrCand {
    pre: CorrPreRow,
    score: crate::predb_corr::CorrScore,
}

/// What `corr_consider` did with a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorrOutcome {
    Nothing,
    Suggested,
    Applied,
}

/// The provenance base for a correlated name: the pre row's own source
/// when it has one, "relay" otherwise, so `pre_source_label` renders
/// `predb/corr:<where the pre came from>`.
fn corr_source_base(source: &str) -> &str {
    let s = source.trim();
    if s.is_empty() { "relay" } else { s }
}

/// `predb.tried_at` value meaning "swept, and its post never turned up".
/// A timestamp far outside any real clock, so retired rows sort to the
/// end of `idx_predb_tried` and the sweep's range scan stops before
/// them. Deliberately not a separate column: one index, one scan.
pub(super) const PREDB_RETIRED: i64 = 1 << 40;

/// Ask the pre feed what a posted stem was really called.
///
/// Exact key first, then the separator-insensitive one - both indexed on
/// the `predb` side, which is why the lookup is cheap enough to sit in
/// the ingest path. `ORDER BY id DESC` picks the most recently learned
/// title when a filename has (unusually) been announced twice.
///
/// Returns `(title, source label)`. The label is never empty: a name
/// nobody can attribute is a name we should not be showing.
pub(super) fn predb_lookup(db: &Connection, stem: &str) -> Option<(String, String)> {
    if stem.is_empty() {
        return None;
    }
    let lower = stem.to_ascii_lowercase();
    // prepare_cached, not prepare: this sits in the ingest loop and runs
    // once per clustered release, so re-planning the statement per call
    // would be the whole cost of the feature.
    let one = |sql: &str, arg: &String| -> Option<(String, String)> {
        db.prepare_cached(sql)
            .ok()?
            .query_row([arg], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .optional()
            .ok()
            .flatten()
    };
    let hit = one(
        "SELECT title, source FROM predb WHERE fnstem=?1 ORDER BY id DESC LIMIT 1",
        &lower,
    );
    let hit = match hit {
        Some(h) => Some(h),
        None => {
            let key = crate::predb::match_key(&lower);
            if key.is_empty() {
                return None;
            }
            one(
                "SELECT title, source FROM predb WHERE fnkey=?1 ORDER BY id DESC LIMIT 1",
                &key,
            )
        }
    }?;
    let (title, source) = hit;
    if title.trim().is_empty() {
        return None;
    }
    Some((title, pre_source_label(&source)))
}

/// The provenance string stored on a named release.
///
/// Always says "predb" so the origin of the name is legible without
/// knowing the relay's own vocabulary, and appends the relay's source
/// tag when it sent one. This is what a UI badge would render, and what
/// makes the difference between "the post said so" and "somebody told
/// us" visible rather than implied.
/// Idempotent: the two callers reach it by different routes (one via
/// `predb_lookup`, which has already labelled) and double-prefixing
/// would produce `predb/predb/PRE`.
fn pre_source_label(source: &str) -> String {
    let s = source.trim();
    if s == "predb" || s.starts_with("predb/") {
        return s.to_string();
    }
    // §131: a byte-proven name (the claims layer) is not a predb fact
    // and must not be dressed as one - its label passes through.
    if s.starts_with("proven:") {
        return s.to_string();
    }
    if s.is_empty() {
        "predb".to_string()
    } else {
        format!("predb/{s}")
    }
}

impl Index {
    /// Fold a batch of relay lines into `predb`.
    ///
    /// Upsert semantics mirror the wire: a NEW line announces a title, a
    /// later UPD fills fields in, and a field only ever overwrites when
    /// the new value is non-empty. That last rule is the whole reason
    /// this is not a plain REPLACE - the filename usually arrives on the
    /// second line about a release, and a REPLACE would blank it on the
    /// third.
    ///
    /// Returns how many rows now carry a usable filename, which is the
    /// only count worth reporting: a title with no filename cannot name
    /// an obfuscated post.
    pub fn predb_store(
        &mut self,
        lines: &[crate::predb::PreLine],
        now: i64,
    ) -> rusqlite::Result<usize> {
        if lines.is_empty() {
            return Ok(0);
        }
        // Feed activity is what makes the named count worth indexing;
        // this is the first-session path, before the next `open` gets
        // to build it (no-op once it exists).
        self.ensure_named_index_stamped();
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut nameable = 0usize;
        for l in lines {
            if l.title.trim().is_empty() {
                continue;
            }
            // The join keys are derived here, once, rather than at match
            // time: the release side already stores a `release_stem` of
            // the posted filename, so reducing the relay's filename the
            // same way is what makes the two comparable at all.
            let fnstem = if l.filename.is_empty() {
                String::new()
            } else {
                crate::extract::release_stem(&l.filename).to_ascii_lowercase()
            };
            let fnkey = crate::predb::match_key(&fnstem);
            if !fnkey.is_empty() {
                nameable += 1;
            }
            tx.prepare_cached(
                "INSERT INTO predb(title, filename, fnstem, fnkey, size, files, category,
                                   source, requestid, grp, nuked, nuke_reason, pre_at, seen_at,
                                   pt)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,
                        CASE WHEN ?13<>0 THEN ?13 ELSE ?14 END)
                 ON CONFLICT(title) DO UPDATE SET
                   filename=CASE WHEN excluded.filename<>'' THEN excluded.filename ELSE filename END,
                   fnstem  =CASE WHEN excluded.fnstem  <>'' THEN excluded.fnstem   ELSE fnstem   END,
                   fnkey   =CASE WHEN excluded.fnkey   <>'' THEN excluded.fnkey    ELSE fnkey    END,
                   size    =CASE WHEN excluded.size    <>0  THEN excluded.size     ELSE size     END,
                   files   =CASE WHEN excluded.files   <>0  THEN excluded.files    ELSE files    END,
                   category=CASE WHEN excluded.category<>'' THEN excluded.category ELSE category END,
                   source  =CASE WHEN excluded.source  <>'' THEN excluded.source   ELSE source   END,
                   requestid=CASE WHEN excluded.requestid<>'' THEN excluded.requestid ELSE requestid END,
                   grp     =CASE WHEN excluded.grp     <>'' THEN excluded.grp      ELSE grp      END,
                   -- A nuke is sticky: an UPD after one does not un-nuke.
                   nuked   =MAX(nuked, excluded.nuked),
                   nuke_reason=CASE WHEN excluded.nuke_reason<>'' THEN excluded.nuke_reason
                                    ELSE nuke_reason END,
                   pre_at  =CASE WHEN excluded.pre_at  <>0  THEN excluded.pre_at   ELSE pre_at   END,
                   -- An announced time is better evidence than our
                   -- first-arrival clock; otherwise pt keeps the
                   -- EARLIEST sighting, which is the honest pre time.
                   pt      =CASE WHEN excluded.pre_at  <>0  THEN excluded.pre_at   ELSE pt       END,
                   -- A row that gained a filename is worth re-sweeping
                   -- against the index, so clear its attempt stamp.
                   tried_at=CASE WHEN excluded.fnkey<>'' AND fnkey='' THEN 0 ELSE tried_at END",
            )?
            .execute(rusqlite::params![
                l.title.trim(),
                l.filename,
                fnstem,
                fnkey,
                l.size as i64,
                l.files,
                l.category,
                l.source,
                l.requestid,
                l.group,
                matches!(l.kind, crate::predb::PreKind::Nuk),
                l.nuke_reason,
                l.date,
                now
            ])?;
        }
        tx.commit()?;
        if nameable > 0 {
            self.predb = true;
        }
        Ok(nameable)
    }

    /// Rows held, and how many of those carry a posted filename.
    pub fn predb_stats(&self) -> rusqlite::Result<(u64, u64)> {
        self.db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(fnkey<>''),0) FROM predb",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
    }

    /// Build the partial index behind `predb_named_count`. Tiny (only
    /// named rows live in it) but load-bearing: without it that COUNT
    /// walks the whole releases table - seconds per call on a large
    /// index - and the settings card polls it. Deliberately not part
    /// of `open`'s unconditional migrations: callers gate on feed
    /// activity, so an install that never ran the feed never pays the
    /// one-time build. On a read-only handle the CREATE fails and is
    /// ignored, the same way the open-time migrations ignore it.
    ///
    /// Returns whether this call actually BUILT the index - the one
    /// runtime schema change in the system, which is what the daemon
    /// retires its pooled readers on now that the per-pass flush is
    /// gone (B4). The existence probe first keeps the steady state (it
    /// already exists) a single sqlite_master row read.
    pub(super) fn ensure_named_index(db: &Connection) -> bool {
        let had = db
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_rel_pre_named'",
                [],
                |_| Ok(()),
            )
            .is_ok();
        if had {
            return false;
        }
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_rel_pre_named
               ON releases(pre_title) WHERE pre_title<>''",
            [],
        )
        .is_ok()
    }

    /// [`Self::ensure_named_index`] for the runtime write paths: stamps
    /// the connection's `ddl` flag when the index was built just now,
    /// so [`Index::take_schema_ddl`] reports it.
    fn ensure_named_index_stamped(&self) {
        if Self::ensure_named_index(&self.db) {
            self.ddl.set(true);
        }
    }

    /// How many releases carry a name the feed gave them.
    pub fn predb_named_count(&self) -> rusqlite::Result<u64> {
        // Self-heal for a writable handle (tests, CLI): the daemon's
        // API polls this through a read-only connection, where the
        // CREATE is a silent no-op and the index has to have been
        // built by the writer - `open` and the store paths do that.
        // With the index present the COUNT is an index-only scan of
        // exactly the rows it counts; without it the scan below is
        // slow but correct.
        self.ensure_named_index_stamped();
        self.db
            .query_row(
                "SELECT COUNT(*) FROM releases WHERE pre_title<>''",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
    }

    /// Cap the feed's size. Age first (a pre line's naming value decays
    /// with the post's retention), then a hard row cap, oldest-heard
    /// first - the same shape as the release retention prune, and for
    /// the same reason: an always-on feed is otherwise unbounded.
    /// Returns rows deleted.
    pub fn predb_prune(
        &self,
        max_rows: u64,
        max_age_secs: i64,
        now: i64,
    ) -> rusqlite::Result<usize> {
        // One transaction over the whole prune (Codex sweep 2, 3 Aug
        // M5). The two deletes and the orphan repair below used to
        // autocommit separately, so a crash - or a failure in the
        // second statement after the first had committed - left
        // pre_corr rows pointing at predb ids that no longer exist,
        // which is precisely the state the repair exists to prevent.
        let tx = self.db.unchecked_transaction()?;
        let mut removed = 0usize;
        if max_age_secs > 0 {
            removed += tx.execute(
                "DELETE FROM predb WHERE seen_at > 0 AND seen_at < ?1",
                [now - max_age_secs],
            )?;
        }
        if max_rows > 0 {
            let n: i64 = tx.query_row("SELECT COUNT(*) FROM predb", [], |r| r.get(0))?;
            let over = n - max_rows as i64;
            if over > 0 {
                removed += tx.execute(
                    "DELETE FROM predb WHERE id IN
                       (SELECT id FROM predb ORDER BY seen_at ASC, id ASC LIMIT ?1)",
                    [over],
                )?;
            }
        }
        // pre_corr has no FK onto predb, and predb ids are plain rowids
        // SQLite reuses after the maximum is deleted (Codex sweep 3 Aug
        // M2). Dangling references are not inert:
        //  - an orphaned SUGGESTED row wedges out every future valid
        //    candidate scoring below it (the upsert takes only
        //    excluded.score >= pre_corr.score, and the probe shortcut
        //    skips lower scores), while its own hint joins to nothing;
        //  - a dangling reference in ANY row can silently rebind to an
        //    unrelated pre once the rowid is reused, and the confirm
        //    back-feed then writes the old release's stem into that
        //    unrelated predb row, poisoning later exact matches.
        // Suggested orphans are deleted outright; settled rows keep
        // their status (rejected must never nag again) but drop the
        // reference to 0, the same "pre gone" shape a pruned hint
        // already presents through its INNER JOIN.
        //
        // UNCONDITIONAL, not `if removed > 0` (Codex sweep 2, 3 Aug
        // M5). Gating the repair on this call's own delete count meant
        // a store that already held dangling rows - left by a crash, or
        // by the pre-transaction version failing between its two
        // statements - only healed if some LATER prune happened to
        // delete something, and a store past its retention window with
        // a steady row count never prunes again. The repair is the
        // invariant, so it runs every time and costs an indexed lookup
        // per pre_corr row once an hour.
        tx.execute(
            "DELETE FROM pre_corr WHERE status='suggested'
               AND predb_id>0
               AND NOT EXISTS (SELECT 1 FROM predb p WHERE p.id=pre_corr.predb_id)",
            [],
        )?;
        tx.execute(
            "UPDATE pre_corr SET predb_id=0
              WHERE predb_id>0
                AND NOT EXISTS (SELECT 1 FROM predb p WHERE p.id=pre_corr.predb_id)",
            [],
        )?;
        tx.commit()?;
        Ok(removed)
    }

    /// Sweep freshly-heard pre lines against releases that are ALREADY
    /// indexed - the "the post came first, the announcement came second"
    /// direction. Budgeted: `budget` rows per call, oldest attempt first.
    ///
    /// Driven from the feed rather than from the index on purpose. The
    /// feed is small and its join keys are indexed, while `releases` is
    /// millions of rows with no index on a normalized stem, so the same
    /// work driven the other way would be a full table scan per tick.
    /// Returns (rows examined, releases named).
    pub fn predb_sweep(&mut self, budget: u32, now: i64) -> rusqlite::Result<(usize, usize)> {
        if budget == 0 || !self.predb {
            return Ok((0, 0));
        }
        // Only rows still worth asking about. `tried_at` doubles as the
        // rotation key and the retirement marker:
        //   0            never swept - always first
        //   a timestamp  swept, still inside its retry window
        //   RETIRED      the post never turned up; parked at the far end
        //                of idx_predb_tried, so the range scan below
        //                never even reaches it.
        // Without retirement this query walks every row in the feed
        // forever, re-asking about announcements whose posts arrived
        // (and were named at ingest) months ago. The RETRY_FLOOR keeps a
        // live row from being re-asked on every 20-second tick.
        const RETRY_FLOOR: i64 = 600;
        let rows: Vec<(i64, String, String, String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id, title, fnstem, fnkey, source FROM predb
                  WHERE fnkey<>'' AND tried_at < ?1
                  ORDER BY tried_at ASC, id DESC LIMIT ?2",
            )?;
            stmt.query_map(rusqlite::params![now - RETRY_FLOOR, budget], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        if rows.is_empty() {
            return Ok((0, 0));
        }
        let mut named = 0usize;
        for (id, title, fnstem, _fnkey, source) in &rows {
            // Exact match only, and deliberately so. This leg is driven
            // from the feed, so it looks releases up BY STEM - and the
            // only index on that column is the plain one, which a
            // normalized comparison cannot use. Adding the fallback here
            // would turn each budgeted row into a full scan of millions.
            // Nothing is lost: the normalized fallback lives on the two
            // legs that look the other way (ingest and the backlog
            // sweep), where both predb keys ARE indexed.
            //
            // `LIMIT 200` bounds the pathological case of a pre line
            // whose filename matches a great many releases. A stem that
            // generic is not evidence of anything, and re-naming
            // thousands of unrelated releases off one line is the worst
            // thing this feature could do.
            let ids: Vec<i64> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT id FROM releases
                      WHERE pre_title='' AND LOWER(stem)=?1 LIMIT 200",
                )?;
                stmt.query_map([fnstem], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for rid in ids {
                if self.apply_pre_name(rid, title, source, now)? {
                    named += 1;
                }
            }
            // Keep asking while the post could still show up, then
            // retire the row. RETRY_WINDOW is generous because a pre can
            // precede the actual upload by days.
            const RETRY_WINDOW: i64 = 14 * 86_400;
            self.db.execute(
                "UPDATE predb
                    SET tried_at = CASE WHEN seen_at > ?2 THEN ?3 ELSE ?4 END
                  WHERE id=?1",
                rusqlite::params![id, now - RETRY_WINDOW, now, PREDB_RETIRED],
            )?;
        }
        Ok((rows.len(), named))
    }

    /// The other direction, and the one that only matters once: releases
    /// that were indexed BEFORE the feed was switched on. Walks the
    /// index downward from a stored cursor, one bounded slice per call,
    /// asking the feed about each obfuscated-looking release.
    ///
    /// A cursor rather than a "not yet tried" flag because the flag
    /// version degenerates: once the backlog is exhausted, every tick
    /// re-scans the whole table to find the nothing that is left. The
    /// cursor walks once, in id order, and stops. `window_secs` bounds
    /// how far back it bothers to go (0 = the whole index).
    ///
    /// Returns (rows examined, releases named).
    pub fn predb_backlog(
        &mut self,
        budget: u32,
        window_secs: i64,
        now: i64,
    ) -> rusqlite::Result<(usize, usize)> {
        if budget == 0 || !self.predb {
            return Ok((0, 0));
        }
        // The oldest id still inside the window - the floor the walk
        // stops at. Computed from `first_seen` (idx_rel_seen) once per
        // call rather than filtered per row, so the walk itself can stay
        // a plain primary-key range.
        //
        // Both ends are EXCLUSIVE-below (`id > floor`), so the floor is
        // one below the oldest in-window row and the walk still reaches
        // it. The cursor starts at the top of the table rather than
        // i64::MAX, or the first hundred passes would sweep empty id
        // space and never reach a row.
        let cutoff = if window_secs > 0 {
            now - window_secs
        } else {
            0
        };
        let floor: i64 = self.db.query_row(
            "SELECT COALESCE(MIN(id),0) FROM releases WHERE first_seen>=?1",
            [cutoff],
            |r| r.get::<_, i64>(0).map(|v| v - 1),
        )?;
        let cursor: i64 = match self
            .kv_get("predb_backlog_cursor")
            .and_then(|v| v.parse().ok())
        {
            Some(v) => v,
            None => self
                .db
                .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?,
        };
        if cursor <= floor {
            // Walked the window already. New arrivals are named at
            // ingest and late announcements by predb_sweep, so there is
            // nothing left for this leg to do.
            return Ok((0, 0));
        }
        // Bounded per call in ID SPACE, not just in rows returned: a
        // slice with no matches must still cost a fixed amount of scan.
        const STRIDE: i64 = 100_000;
        let lo = cursor.saturating_sub(STRIDE).max(floor);
        let rows: Vec<(i64, String)> = {
            let mut stmt = self.db.prepare_cached(
                // junk>=70 is the obfuscation band (junk_score pins an
                // unparseable or blob-shaped stem there), so this looks
                // only at releases the feed can actually help and leaves
                // the ones already carrying a readable name alone.
                "SELECT id, stem FROM releases
                  WHERE id>?1 AND id<=?2 AND pre_title='' AND junk>=70
                  ORDER BY id DESC LIMIT ?3",
            )?;
            stmt.query_map(rusqlite::params![lo, cursor, budget], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        // A full batch means the slice was cut short by the budget -
        // resume just below the last row examined so nothing is skipped.
        let next = if rows.len() as u32 >= budget {
            rows.last().map(|(id, _)| id - 1).unwrap_or(lo)
        } else {
            lo
        };
        let mut named = 0usize;
        for (rid, stem) in &rows {
            if let Some((title, source)) = predb_lookup(&self.db, stem) {
                if self.apply_pre_name(*rid, &title, &source, now)? {
                    named += 1;
                }
            } else {
                self.db.execute(
                    "UPDATE releases SET pre_at=?2 WHERE id=?1",
                    rusqlite::params![rid, now],
                )?;
            }
        }
        self.kv_set("predb_backlog_cursor", &next.to_string())?;
        Ok((rows.len(), named))
    }

    /// Attach a fed name to one release and re-derive everything the old
    /// name determined. Returns false when the row was already named or
    /// has since vanished.
    pub(super) fn apply_pre_name(
        &self,
        rid: i64,
        title: &str,
        source: &str,
        now: i64,
    ) -> rusqlite::Result<bool> {
        self.apply_named(rid, title, &pre_source_label(source), now)
    }

    /// The seam every out-of-band naming source funnels through: attach
    /// `title` to one release with `label` written to `pre_source`
    /// VERBATIM, and re-derive everything the old name determined
    /// (kind, res, title_key, junk, langs, codecs), so a release named
    /// here is indistinguishable from one named at ingest. The predb
    /// paths reach it via `apply_pre_name` (which stamps their
    /// `predb/...` label); spot promotion and the byte probes pass their
    /// own label (`spot`, `body/7z`). Returns false when the row was
    /// already named or has vanished - an existing name is never
    /// overwritten.
    pub(crate) fn apply_named(
        &self,
        rid: i64,
        title: &str,
        label: &str,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let title = title.trim();
        if title.is_empty() {
            return Ok(false);
        }
        let Some((bytes, nexe, complete, stem)): Option<(i64, i64, bool, String)> = self
            .db
            .prepare_cached(&format!(
                "SELECT total_bytes,
                        (SELECT COALESCE(SUM({EXE_FILE_SQL}),0) FROM files
                          WHERE release_id=releases.id),
                        complete, stem
                   FROM releases WHERE id=?1 AND pre_title=''"
            ))?
            .query_row([rid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .optional()?
        else {
            return Ok(false);
        };
        let mut p = crate::categories::classify(title, &self.custom);
        // A spot or pre title names the work and drops the file's own
        // format marker, which for a book is the ONLY evidence there is.
        crate::release::recover_media_kind(&mut p, title, &stem);
        // Same column set the ingest path writes, from the same parse -
        // a release named here must be indistinguishable from one that
        // was named at ingest, or the wall would file the two copies of
        // the same show differently.
        let n = self.db.execute(
            "UPDATE releases
                SET pre_title=?2, pre_source=?3, pre_at=?4,
                    kind=?5, res=?6, title_key=?7, junk=?8, langs=?9,
                    vcodec=?10, acodec=?11, hdr=?12
              WHERE id=?1 AND pre_title=''",
            rusqlite::params![
                rid,
                title,
                label,
                now,
                kind_str(&p.kind),
                p.res.as_deref().unwrap_or_default(),
                p.key,
                junk_score(title, &p, bytes as u64, nexe > 0),
                p.langs.join(" "),
                p.vcodec.as_deref().unwrap_or_default(),
                p.acodec.as_deref().unwrap_or_default(),
                p.hdr.as_deref().unwrap_or_default()
            ],
        )?;
        // A release that has just GAINED a name is an arrival as far as
        // anything matching on names is concerned: until this moment it
        // was an obfuscated stem no watchlist entry could ever match.
        // Every naming leg - the exact predb legs, correlation auto-apply
        // and a human picking from the candidate list - funnels through
        // here, so this one line covers all of them.
        if n > 0 {
            self.note_watch(rid, title, complete);
        }
        Ok(n > 0)
    }

    // ---- Phase 2: time+size correlation ------------------------------
    //
    // The live public relays carry no filenames, so the exact legs
    // above can never fire from them. What a pre does pin down is WHEN
    // a release existed and (sometimes) how big it is; these legs turn
    // that into scored candidates. The arithmetic lives in
    // `crate::predb_corr`; everything here is queries, cursors and the
    // gates that keep "probably" from ever silently becoming "is".

    /// Per-release facts the scorer needs, gathered once per release.
    fn corr_release_facts(&self, rid: i64) -> rusqlite::Result<Option<CorrRelFacts>> {
        let row = self
            .db
            .prepare_cached(
                "SELECT stem, grp, total_bytes, has_par2, first_posted,
                        (SELECT COALESCE(SUM(bytes),0) FROM files
                          WHERE release_id=releases.id
                            AND LOWER(filename) LIKE '%.par2'),
                        (SELECT COUNT(*) FROM files
                          WHERE release_id=releases.id
                            AND LOWER(filename) NOT LIKE '%.par2')
                   FROM releases WHERE id=?1 AND pre_title='' AND first_posted>0",
            )?
            .query_row([rid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })
            .optional()?;
        let Some((stem, grp, total, has_par2, fp, par2_bytes, rel_files)) = row else {
            return Ok(None);
        };
        // total_bytes is OVER-WIRE bytes, par2 included. The estimate
        // models out identified par2 and the yEnc factor; disguised
        // par2 (no .par2 extension - the common obfuscated shape) stays
        // IN the estimate, which is what the scorer's asymmetric
        // hidden-par2 band exists for.
        let par2_identified = par2_bytes > 0 || has_par2;
        let content_wire = (total - par2_bytes).max(0) as f64;
        Ok(Some(CorrRelFacts {
            stem,
            first_posted: fp,
            grp_kind: crate::predb_corr::group_kind(&grp),
            est_content: (content_wire / crate::predb_corr::YENC_FACTOR) as u64,
            par2_identified,
            rel_files: rel_files.max(0) as u32,
        }))
    }

    /// Score one pre row against one release's facts. `classify` is
    /// only paid when the cheap fields cannot answer.
    fn corr_score_pair(
        &self,
        f: &CorrRelFacts,
        p: &CorrPreRow,
    ) -> Option<crate::predb_corr::CorrScore> {
        use crate::predb_corr as pc;
        let mut kind_pre = pc::section_class(&p.category);
        let mut kind_title = crate::release::Kind::Other;
        let mut res_pre = None;
        // The plausibility prior only matters sizeless, and the
        // section usually answers the class question - classify only
        // when one of them still needs the title read.
        if kind_pre == pc::GroupKind::Unknown || p.size == 0 {
            let parsed = crate::categories::classify(&p.title, &self.custom);
            if kind_pre == pc::GroupKind::Unknown {
                kind_pre = pc::kind_class(&parsed.kind);
            }
            res_pre = parsed.res.clone();
            kind_title = parsed.kind;
        }
        pc::corr_score(&pc::CorrFeatures {
            delta: f.first_posted - p.pt,
            sz: p.size,
            est_content: f.est_content,
            par2_identified: f.par2_identified,
            kind_pre,
            grp_kind: f.grp_kind,
            fl: p.files,
            rel_files: f.rel_files,
            kind_title,
            res_pre,
        })
    }

    /// The candidate pres for one release, scored and ranked (best
    /// first). Uses idx_predb_pt for the window; the LIMIT truncates
    /// pathological windows newest-first, which is also the time-score
    /// order.
    ///
    /// The third value is SATURATION: the window held at least as many
    /// pres as the limit, so candidates were dropped. At the feed's own
    /// documented rate (40-200 pres/hour) a 14-day window is routinely
    /// 13k-67k rows, so this is the ordinary case, not a pathological
    /// one - and the dropped OLDER candidates are invisible to the
    /// runner-up margin and the sibling gate, which makes auto-apply
    /// EASIER to clear, the failure direction that renames a release
    /// wrongly. Same principle as `corr_window_saturated`: a sample
    /// cannot prove a maximum, so a saturated window suggests but never
    /// auto-applies.
    fn corr_eval(&self, rid: i64) -> rusqlite::Result<Option<(CorrRelFacts, Vec<CorrCand>, bool)>> {
        const CAND_LIMIT: usize = 4000;
        let Some(facts) = self.corr_release_facts(rid)? else {
            return Ok(None);
        };
        let lo = facts.first_posted - crate::predb_corr::DELTA_MAX;
        let hi = facts.first_posted - crate::predb_corr::DELTA_MIN;
        // Size-band the candidate window when the release has a usable
        // size estimate (E1's separable prefilter, adopted suggest-only
        // per the 10 Aug red-team). Without this the window is EVERY
        // pre in a 14-day span; once a sized seed lands that is 3k-23k
        // rows (measured), always over CAND_LIMIT, so `saturated` reads
        // true for every release regardless of how crowded its actual
        // size neighbourhood is. A sized pre outside
        // [est/RATIO_MAX, est/RATIO_MIN] is vetoed by `corr_score`
        // anyway (it scores None and is filtered below), so banding the
        // SQL changes no best/runner-up/sibling outcome - it stops
        // size-IMPLAUSIBLE pres from filling the cap ahead of the
        // plausible ones, i.e. it is a false-saturation and cost fix.
        // Sizeless pres (size=0) are always kept: they carry the
        // suggestion tail and the sibling gate's population.
        //
        // Honesty note (red-team §1a): lifting false saturation is NOT
        // "removing candidates only" - `saturated` fails closed in the
        // auto gate, so this change would ENABLE auto-applies the old
        // window blocked. That is exactly why auto ships OFF: see the
        // module docs in `predb_corr.rs` for the evidence bar an auto
        // flip requires. No naming-yield claim is made for this change.
        let est = facts.est_content;
        let pres: Vec<CorrPreRow> = if est > 0 {
            let blo = (est as f64 / crate::predb_corr::RATIO_MAX) as i64;
            let bhi = (est as f64 / crate::predb_corr::RATIO_MIN) as i64;
            let mut stmt = self.db.prepare_cached(
                "SELECT id, title, category, source, size, files, nuked, pt, fnkey<>''
                   FROM predb WHERE pt BETWEEN ?1 AND ?2
                    AND (size=0 OR size BETWEEN ?3 AND ?4)
                  ORDER BY pt DESC LIMIT 4000",
            )?;
            stmt.query_map(rusqlite::params![lo, hi, blo, bhi], |r| {
                Ok(CorrPreRow {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    category: r.get(2)?,
                    source: r.get(3)?,
                    size: r.get::<_, i64>(4)?.max(0) as u64,
                    files: r.get::<_, i64>(5)?.max(0) as u32,
                    nuked: r.get(6)?,
                    pt: r.get(7)?,
                    has_fn: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?
        } else {
            let mut stmt = self.db.prepare_cached(
                "SELECT id, title, category, source, size, files, nuked, pt, fnkey<>''
                   FROM predb WHERE pt BETWEEN ?1 AND ?2
                  ORDER BY pt DESC LIMIT 4000",
            )?;
            stmt.query_map([lo, hi], |r| {
                Ok(CorrPreRow {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    category: r.get(2)?,
                    source: r.get(3)?,
                    size: r.get::<_, i64>(4)?.max(0) as u64,
                    files: r.get::<_, i64>(5)?.max(0) as u32,
                    nuked: r.get(6)?,
                    pt: r.get(7)?,
                    has_fn: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let saturated = pres.len() >= CAND_LIMIT;
        let mut cands: Vec<CorrCand> = pres
            .into_iter()
            .filter_map(|p| {
                self.corr_score_pair(&facts, &p)
                    .map(|score| CorrCand { pre: p, score })
            })
            .collect();
        cands.sort_by_key(|c| std::cmp::Reverse(c.score.total));
        Ok(Some((facts, cands, saturated)))
    }

    /// The Pesto poster-tool Message-ID grammar:
    /// `<16-hex>.<hex counter>.<16-hex>@host` (10 Aug 2026 census:
    /// 8,947 moovee/teevee releases match, counters monotonic per
    /// session). A matching release has a tiny real-name PAR2 posted
    /// adjacent under the same counter grammar, so a ~kilobyte byte
    /// probe reads its EXACT name in-band. Stored ids keep their angle
    /// brackets; accept both shapes.
    pub(super) fn pesto_msgid(id: &str) -> bool {
        let id = id.trim().trim_start_matches('<');
        let Some((local, _host)) = id.split_once('@') else {
            return false;
        };
        let mut parts = local.split('.');
        let (Some(a), Some(b), Some(c), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        let hex = |s: &str| !s.is_empty() && s.chars().all(|ch| ch.is_ascii_hexdigit());
        a.len() == 16 && c.len() == 16 && hex(a) && hex(c) && b.len() <= 16 && hex(b)
    }

    /// Is `name` a 7-Zip archive file (`x.7z`, `x.7z.001`, …)? The
    /// single-file 7z shape is the B3 lane: the archive's own header
    /// carries the real inner filename, readable by a ~1 MB byte probe.
    pub(super) fn seven_zip_family(name: &str) -> bool {
        let n = name.trim().to_ascii_lowercase();
        if n.ends_with(".7z") {
            return true;
        }
        // "x.7z.001" - a numeric split suffix after the .7z.
        if let Some((head, tail)) = n.rsplit_once('.') {
            return head.ends_with(".7z")
                && !tail.is_empty()
                && tail.chars().all(|c| c.is_ascii_digit());
        }
        false
    }

    /// Does this release belong to the correlation NAMING population?
    ///
    /// Two requirements, both from the 10 Aug 2026 red-team of the
    /// indexer-competitive bundle:
    ///
    /// 1. The stem must be actually OBFUSCATED, not merely junk>=70 -
    ///    Kind::Other scores 70 for unparseable-but-readable names, and
    ///    correlation must not guess over a name a human can read.
    /// 2. No in-band byte probe may be able to read the EXACT name:
    ///    identified PAR2 (FileDesc packets carry real filenames), the
    ///    single-`.7z` shape (B3: the archive header carries it), and
    ///    the Pesto Message-ID grammar (a real-name tiny PAR2 sits one
    ///    counter away). Codex's audit showed those lanes DOMINATED the
    ///    suggestion pool while byte probes of the same rows prove the
    ///    correlated guesses are exact-wrong - a guess is strictly
    ///    worse than the probe, so those rows are not correlation's.
    ///
    /// Scope: this gates what correlation may NAME (suggestions
    /// included). Excluded rows still count as mutual-best COMPETITORS
    /// - removing a rival from the margin arithmetic would make auto
    /// MORE permissive, the failure direction that renames wrongly -
    /// and the human `pre_candidates` picker stays unrestricted.
    fn corr_naming_population(&self, rid: i64) -> rusqlite::Result<bool> {
        let stem: Option<String> = self
            .db
            .prepare_cached("SELECT stem FROM releases WHERE id=?1")?
            .query_row([rid], |r| r.get(0))
            .optional()?;
        let Some(stem) = stem else {
            return Ok(false);
        };
        let parsed = crate::categories::classify(&stem, &self.custom);
        if !super::ingest::stem_obfuscated(&stem, &parsed) {
            return Ok(false);
        }
        // In-band PAR2: the releases flag or an identified .par2 file.
        let par2: bool = self
            .db
            .prepare_cached(
                "SELECT has_par2 OR EXISTS(SELECT 1 FROM files
                    WHERE release_id=?1 AND LOWER(filename) LIKE '%.par2')
                   FROM releases WHERE id=?1",
            )?
            .query_row([rid], |r| r.get(0))?;
        if par2 {
            return Ok(false);
        }
        // File shapes: a handful of rows answers both remaining
        // questions - the single-7z test needs to see there is exactly
        // one file, and the Pesto grammar shows on any file's first
        // segment id.
        let rows: Vec<(String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT filename, COALESCE(json_extract(segments,'$[0][1]'),'')
                   FROM files WHERE release_id=?1 LIMIT 4",
            )?;
            stmt.query_map([rid], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        if rows.len() == 1 && Self::seven_zip_family(&rows[0].0) {
            return Ok(false);
        }
        if rows.iter().any(|(_, id)| Self::pesto_msgid(id)) {
            return Ok(false);
        }
        Ok(true)
    }

    /// Evaluate one release and act on the outcome: store/refresh the
    /// suggestion, and auto-apply when every gate agrees. Returns what
    /// happened.
    fn corr_consider(&mut self, rid: i64, auto: bool, now: i64) -> rusqlite::Result<CorrOutcome> {
        use crate::predb_corr::{FLOOR, MARGIN};
        // A row a human or an oracle has ruled on is settled: rejected
        // must never nag again (in ANY form - suggestion or auto),
        // applied/confirmed have nothing left to decide, and revoked
        // means the correlation already guessed wrong here once.
        let settled: Option<String> = self
            .db
            .prepare_cached("SELECT status FROM pre_corr WHERE release_id=?1")?
            .query_row([rid], |r| r.get(0))
            .optional()?;
        if matches!(settled.as_deref(), Some(s) if s != "suggested") {
            return Ok(CorrOutcome::Nothing);
        }
        // Every naming path - backlog, live sweep, catch-up - funnels
        // through here, so the population gate sits here too.
        if !self.corr_naming_population(rid)? {
            return Ok(CorrOutcome::Nothing);
        }
        let Some((facts, cands, saturated)) = self.corr_eval(rid)? else {
            return Ok(CorrOutcome::Nothing);
        };
        let Some(best) = cands.first().cloned() else {
            return Ok(CorrOutcome::Nothing);
        };
        if best.score.total < FLOOR {
            return Ok(CorrOutcome::Nothing);
        }
        let delta = facts.first_posted - best.pre.pt;
        let runner_up = cands.get(1).map(|c| c.score.total).unwrap_or(0);
        // Store/refresh the suggestion - but never touch a row a human
        // or an oracle has already ruled on ('rejected' must not nag,
        // 'applied'/'confirmed' must not wander).
        self.db.execute(
            "INSERT INTO pre_corr(release_id, predb_id, score, delta, ratio, runner_up,
                                  status, at)
             VALUES(?1,?2,?3,?4,?5,?6,'suggested',?7)
             ON CONFLICT(release_id) DO UPDATE SET
               predb_id=excluded.predb_id, score=excluded.score, delta=excluded.delta,
               ratio=excluded.ratio, runner_up=excluded.runner_up, at=excluded.at,
               -- A different pre is a DIFFERENT pairing: the confirm
               -- lane has never spent a lookup on it, so the old
               -- pairing's retirement marker must not retire it too.
               checked_at=CASE WHEN excluded.predb_id<>pre_corr.predb_id
                               THEN 0 ELSE pre_corr.checked_at END
             WHERE pre_corr.status='suggested' AND excluded.score>=pre_corr.score",
            rusqlite::params![
                rid,
                best.pre.id,
                best.score.total,
                delta,
                best.score.ratio_milli as i64,
                runner_up,
                now
            ],
        )?;
        if !auto {
            return Ok(CorrOutcome::Suggested);
        }
        // The auto gate, every clause of it. Failing any clause is not
        // an error: crowded, nuked, filename-bearing or sibling-shaped
        // candidates are exactly what SUGGEST exists for. A saturated
        // candidate window fails closed too: the runner-up and sibling
        // clauses below are proofs about a MAXIMUM over the whole
        // window, and a truncated sample cannot give them (Codex sweep
        // 3 Aug M1).
        if saturated
            || !best.score.strong()
            || best.score.total - runner_up <= MARGIN
            || best.pre.nuked
            || best.pre.has_fn
        {
            return Ok(CorrOutcome::Suggested);
        }
        // Sibling rule: another above-floor pre with the same title_key
        // is the REPACK/PROPER/other-group shape - a human picks those.
        let best_key = crate::categories::classify(&best.pre.title, &self.custom).key;
        let sibling = cands.iter().skip(1).any(|c| {
            c.score.total >= FLOOR
                && crate::categories::classify(&c.pre.title, &self.custom).key == best_key
        });
        if sibling {
            return Ok(CorrOutcome::Suggested);
        }
        // Mutual best: the pre must also pick THIS release from its own
        // forward window, by the same margin. Busy hours are asymmetric
        // in both directions; this closes the second one.
        if !self.corr_mutual_best(&best.pre, rid)? {
            return Ok(CorrOutcome::Suggested);
        }
        let source = format!("corr:{}", corr_source_base(&best.pre.source));
        // The apply is three statements and they have to be ONE
        // transaction, re-checked at its head. Two holes otherwise
        // (both walked on the 2 Aug Opus sweep):
        //
        //   1. The old status update set 'applied' WITHOUT re-asserting
        //      predb_id - so when the stored suggestion still pointed
        //      at an earlier, higher-scoring pre Y (the upsert above
        //      keeps the best row), the release wore pre X's title
        //      while the 'applied' row named Y. Every joined read -
        //      the suggestion list, a human confirm, a later revoke -
        //      then ruled on the wrong pairing. The upsert below
        //      carries the pre that was ACTUALLY applied, the same
        //      shape `pre_assign` uses.
        //   2. The settled check at the top of this fn is stale by
        //      now: a human pre_reject/pre_assign landing mid-walk
        //      (another handle, the CLI importer) must not be stomped
        //      by an unguarded write. Re-checked inside the savepoint.
        self.db.execute_batch("SAVEPOINT corr_apply")?;
        let out = (|| -> rusqlite::Result<CorrOutcome> {
            let settled: Option<String> = self
                .db
                .prepare_cached("SELECT status FROM pre_corr WHERE release_id=?1")?
                .query_row([rid], |r| r.get(0))
                .optional()?;
            if matches!(settled.as_deref(), Some(s) if s != "suggested") {
                return Ok(CorrOutcome::Nothing);
            }
            if self.apply_pre_name(rid, &best.pre.title, &source, now)? {
                self.db.execute(
                    "INSERT INTO pre_corr(release_id, predb_id, score, delta, ratio,
                                          runner_up, status, at)
                     VALUES(?1,?2,?3,?4,?5,?6,'applied',?7)
                     ON CONFLICT(release_id) DO UPDATE SET
                       predb_id=excluded.predb_id, score=excluded.score,
                       delta=excluded.delta, ratio=excluded.ratio,
                       runner_up=excluded.runner_up, status='applied', at=excluded.at
                     WHERE pre_corr.status='suggested'",
                    rusqlite::params![
                        rid,
                        best.pre.id,
                        best.score.total,
                        delta,
                        best.score.ratio_milli as i64,
                        runner_up,
                        now
                    ],
                )?;
                return Ok(CorrOutcome::Applied);
            }
            Ok(CorrOutcome::Suggested)
        })();
        match &out {
            Ok(_) => self.db.execute_batch("RELEASE corr_apply")?,
            Err(_) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO corr_apply; RELEASE corr_apply");
            }
        }
        out
    }

    /// Does this pre, scanning its own forward window, pick `rid` and
    /// by the auto margin?
    /// The forward window's candidate releases for one pre. Sized pres
    /// use the time+size-banded shape, which the partial index below
    /// serves precisely; that matters twice over. First, cost: a plain
    /// 14-day window over a large index holds millions of junk rows and
    /// `LIMIT 50` would take an ARBITRARY 50 of them - the true match
    /// mostly would not be in the sample. Second, the mutual-best gate:
    /// missing a real competitor makes auto MORE permissive, so the
    /// competitor set must actually be the size-plausible one. The
    /// band is generous (the exact veto stays in Rust): wire bytes run
    /// a few percent over content, and hidden par2 up to ~18% more.
    fn corr_forward_ids(&self, pre: &CorrPreRow) -> rusqlite::Result<Vec<i64>> {
        const WINDOW: i64 = CORR_WINDOW as i64;
        let lo = pre.pt + crate::predb_corr::DELTA_MIN;
        let hi = pre.pt + crate::predb_corr::DELTA_MAX;
        if pre.size > 0 {
            let blo = (pre.size as f64 * 0.68) as i64;
            let bhi = (pre.size as f64 * 1.60) as i64;
            let mut stmt = self.db.prepare_cached(
                // The WHERE terms repeat the partial index's predicate
                // verbatim so the planner may use idx_rel_corr.
                "SELECT id FROM releases
                  WHERE junk>=70 AND pre_title=''
                    AND first_posted BETWEEN ?1 AND ?2
                    AND total_bytes BETWEEN ?3 AND ?4 LIMIT ?5",
            )?;
            return stmt
                .query_map(rusqlite::params![lo, hi, blo, bhi, WINDOW], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>();
        }
        let mut stmt = self.db.prepare_cached(
            "SELECT id FROM releases
              WHERE pre_title='' AND junk>=70
                AND first_posted BETWEEN ?1 AND ?2 LIMIT ?3",
        )?;
        stmt.query_map(rusqlite::params![lo, hi, WINDOW], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()
    }

    /// Did [`corr_forward_ids`] return everything in the window, or did
    /// it stop at the cap?
    ///
    /// The distinction is a correctness one, not a cosmetic one. The
    /// mutual-best gate compares our score against the best COMPETITOR,
    /// so a competitor the query never returned makes `best_other`
    /// understated and the auto margin easier to clear - the failure
    /// direction that renames a release wrongly. An arbitrary sample
    /// cannot answer a question about a maximum, so a saturated window
    /// means the gate does not know.
    fn corr_window_saturated(ids: &[i64]) -> bool {
        ids.len() >= CORR_WINDOW
    }

    /// The index `corr_forward_ids` leans on, built lazily on the first
    /// correlation pass rather than at open - an install that never
    /// turns the feature on must not pay an index over its junk rows.
    /// kv-flagged so the CREATE (a table scan on a large index) runs
    /// its check once, not every tick.
    fn ensure_corr_index(&mut self) -> rusqlite::Result<()> {
        if self.kv_get("predb_corr_idx_v1").is_some() {
            return Ok(());
        }
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_rel_corr
               ON releases(first_posted, total_bytes)
             WHERE junk>=70 AND pre_title=''",
            [],
        )?;
        self.kv_set("predb_corr_idx_v1", "1")
    }

    /// One batch of pres against their forward windows, in two phases:
    /// phase 1 scores every (pre, release) edge cheaply and keeps the
    /// BEST touching pair per release; phase 2 runs the full
    /// release-driven evaluation once per release, strongest pairing
    /// first. Shared by the live rotation and the catch-up pass.
    ///
    /// Why two phases and not pre-by-pre with a `seen` set (the shape
    /// this replaces): dense windows are the whole cost story -
    /// sibling pres in one batch share most of their candidates, and
    /// the full evaluation each one triggers scans a 4000-row window
    /// (measured live 2 Aug: unthrottled, a 150-pre tick held the
    /// write lock ~40 s). The `seen` set kept the one-evaluation-per-
    /// release bound but made the FIRST floor-clearing pre in batch
    /// order the trigger, so which releases got evaluated - and the
    /// order auto-applies landed in, each apply removing its release
    /// from every later mutual-best competitor set - depended on batch
    /// order and boundaries (E1 follow-up 1, 10 Aug 2026). Driving
    /// phase 2 off the best pair per release keeps the cost bound and
    /// removes the order dependence at the root.
    fn corr_probe_batch(
        &mut self,
        pres: &[CorrPreRow],
        auto: bool,
        now: i64,
    ) -> rusqlite::Result<(usize, usize)> {
        use std::collections::HashMap;
        // Phase 1: cheap pair scores only. Release facts are cached
        // per batch - the old shape re-read them once per touching pre.
        let mut facts: HashMap<i64, Option<CorrRelFacts>> = HashMap::new();
        let mut best: HashMap<i64, i32> = HashMap::new();
        for p in pres {
            for rid in self.corr_forward_ids(p)? {
                let cached = match facts.entry(rid) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(v) => {
                        let f = self.corr_release_facts(rid)?;
                        v.insert(f)
                    }
                };
                let Some(f) = cached.as_ref() else {
                    continue;
                };
                let Some(pair) = self.corr_score_pair(f, p) else {
                    continue;
                };
                if pair.total < crate::predb_corr::FLOOR {
                    continue;
                }
                let e = best.entry(rid).or_insert(0);
                *e = (*e).max(pair.total);
            }
        }
        // Phase 2: strongest pairing first (id as the deterministic
        // tie-break), one full evaluation per release.
        let mut order: Vec<(i64, i32)> = best.into_iter().collect();
        order.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let (mut suggested, mut applied) = (0usize, 0usize);
        for (rid, top) in order {
            // A stored suggestion is already the best of a FULL
            // evaluation. A batch whose best pair cannot beat it cannot
            // change the stored row - and a settled row (applied/
            // rejected/...) is not ours to reopen. The auto caveat: a
            // stored STRONG-range suggestion may only be sitting
            // unapplied because auto was off (or a gate has since
            // cleared), so with auto on those few rows keep earning a
            // fresh look until they settle one way or the other.
            let stored: Option<(String, i64)> = self
                .db
                .prepare_cached("SELECT status, score FROM pre_corr WHERE release_id=?1")?
                .query_row([rid], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            match &stored {
                Some((st, _)) if st != "suggested" => continue,
                Some((_, sc))
                    if *sc >= i64::from(top)
                        && (!auto || *sc < i64::from(crate::predb_corr::STRONG)) =>
                {
                    continue;
                }
                _ => {}
            }
            match self.corr_consider(rid, auto, now)? {
                CorrOutcome::Suggested => suggested += 1,
                CorrOutcome::Applied => applied += 1,
                CorrOutcome::Nothing => {}
            }
        }
        Ok((suggested, applied))
    }

    fn corr_mutual_best(&self, pre: &CorrPreRow, rid: i64) -> rusqlite::Result<bool> {
        let ids = self.corr_forward_ids(pre)?;
        // The window filled: somewhere past the cap there may be a
        // stronger candidate this never scored, and not knowing means
        // not auto-applying. The suggestion still stands for a human.
        if Self::corr_window_saturated(&ids) {
            return Ok(false);
        }
        let mut ours = None;
        let mut best_other = 0i32;
        for id in ids {
            let Some(f) = self.corr_release_facts(id)? else {
                continue;
            };
            let Some(s) = self.corr_score_pair(&f, pre) else {
                continue;
            };
            if id == rid {
                ours = Some(s.total);
            } else {
                best_other = best_other.max(s.total);
            }
        }
        let Some(ours) = ours else { return Ok(false) };
        Ok(ours - best_other > crate::predb_corr::MARGIN)
    }

    /// Release-driven correlation backlog: walks already-indexed
    /// obfuscated releases once, same cursor discipline as
    /// `predb_backlog` (stride-bounded, walks once, stops). The cursor
    /// resets exactly when a seed import lands (`predb_seed_gen`
    /// bumps) - a bigger pre corpus is the only event that makes
    /// re-walking worth anything.
    /// Returns (examined, suggested, applied).
    pub fn predb_corr_backlog(
        &mut self,
        budget: u32,
        window_secs: i64,
        auto: bool,
        now: i64,
    ) -> rusqlite::Result<(usize, usize, usize)> {
        if budget == 0 {
            return Ok((0, 0, 0));
        }
        let seed_gen = self.kv_get("predb_seed_gen").unwrap_or_default();
        if self.kv_get("predb_corr_seed_gen").unwrap_or_default() != seed_gen {
            self.db
                .execute("DELETE FROM kv WHERE k='predb_corr_cursor'", [])?;
            self.kv_set("predb_corr_seed_gen", &seed_gen)?;
        }
        let cutoff = if window_secs > 0 {
            now - window_secs
        } else {
            0
        };
        let floor: i64 = self.db.query_row(
            "SELECT COALESCE(MIN(id),0) FROM releases WHERE first_seen>=?1",
            [cutoff],
            |r| r.get::<_, i64>(0).map(|v| v - 1),
        )?;
        let cursor: i64 = match self
            .kv_get("predb_corr_cursor")
            .and_then(|v| v.parse().ok())
        {
            Some(v) => v,
            None => self
                .db
                .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?,
        };
        if cursor <= floor {
            return Ok((0, 0, 0));
        }
        const STRIDE: i64 = 100_000;
        let lo = cursor.saturating_sub(STRIDE).max(floor);
        let ids: Vec<i64> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id FROM releases
                  WHERE id>?1 AND id<=?2 AND pre_title='' AND junk>=70
                    AND first_posted>0
                  ORDER BY id DESC LIMIT ?3",
            )?;
            stmt.query_map(rusqlite::params![lo, cursor, budget], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let next = if ids.len() as u32 >= budget {
            ids.last().map(|id| id - 1).unwrap_or(lo)
        } else {
            lo
        };
        let (mut suggested, mut applied) = (0usize, 0usize);
        for rid in &ids {
            match self.corr_consider(*rid, auto, now)? {
                CorrOutcome::Suggested => suggested += 1,
                CorrOutcome::Applied => applied += 1,
                CorrOutcome::Nothing => {}
            }
        }
        self.kv_set("predb_corr_cursor", &next.to_string())?;
        Ok((ids.len(), suggested, applied))
    }

    /// Live pre-driven correlation: fresh title-only rows open a
    /// forward window over arriving posts. Population provably disjoint
    /// from `predb_sweep` (this filters `fnkey=''`, that filters
    /// `fnkey<>''`), so the shared `tried_at` rotation cannot fight.
    /// Seed rows are born RETIRED and never enter this rotation.
    /// Returns (pre rows examined, suggested, applied).
    pub fn predb_corr_sweep(
        &mut self,
        budget: u32,
        auto: bool,
        now: i64,
    ) -> rusqlite::Result<(usize, usize, usize)> {
        if budget == 0 {
            return Ok((0, 0, 0));
        }
        const RETRY_FLOOR: i64 = 600;
        let pres: Vec<CorrPreRow> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id, title, category, source, size, files, nuked, pt, fnkey<>''
                   FROM predb WHERE fnkey='' AND tried_at < ?1
                  ORDER BY tried_at ASC, id DESC LIMIT ?2",
            )?;
            stmt.query_map(rusqlite::params![now - RETRY_FLOOR, budget], |r| {
                Ok(CorrPreRow {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    category: r.get(2)?,
                    source: r.get(3)?,
                    size: r.get::<_, i64>(4)?.max(0) as u64,
                    files: r.get::<_, i64>(5)?.max(0) as u32,
                    nuked: r.get(6)?,
                    pt: r.get(7)?,
                    has_fn: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        if pres.is_empty() {
            return Ok((0, 0, 0));
        }
        self.ensure_corr_index()?;
        let (suggested, applied) = self.corr_probe_batch(&pres, auto, now)?;
        for p in &pres {
            // Keep asking while the window is open, then retire.
            self.db.execute(
                "UPDATE predb SET tried_at=CASE WHEN ?2 < pt + ?3 THEN ?2 ELSE ?4 END
                  WHERE id=?1",
                rusqlite::params![p.id, now, crate::predb_corr::DELTA_MAX, PREDB_RETIRED],
            )?;
        }
        Ok((pres.len(), suggested, applied))
    }

    /// The catch-up pass: one walk over EVERY sized pre in the table -
    /// retired seeds included - probing each one's forward window. This
    /// is the historical mechanism: driving from the ~tens of thousands
    /// of sized pres costs an hour; driving from the tens of MILLIONS
    /// of obfuscated releases (the release-driven walk) costs months.
    /// The release-driven backlog stays for the sizeless-suggestion
    /// tail; this pass is what actually covers a seed import.
    ///
    /// Cursor discipline as everywhere: walks predb ids downward once,
    /// parks at 0 when done, and re-opens exactly when a seed import
    /// bumps `predb_seed_gen`. Does not touch `tried_at` - seeds stay
    /// retired, and the live rotation's clock is not this pass's to
    /// wind. Returns (pres examined, suggested, applied).
    pub fn predb_corr_catchup(
        &mut self,
        budget: u32,
        auto: bool,
        now: i64,
    ) -> rusqlite::Result<(usize, usize, usize)> {
        if budget == 0 {
            return Ok((0, 0, 0));
        }
        let seed_gen = self.kv_get("predb_seed_gen").unwrap_or_default();
        if self.kv_get("predb_catchup_seed_gen").unwrap_or_default() != seed_gen {
            self.db
                .execute("DELETE FROM kv WHERE k='predb_catchup_cursor'", [])?;
            self.kv_set("predb_catchup_seed_gen", &seed_gen)?;
        }
        let cursor: i64 = match self
            .kv_get("predb_catchup_cursor")
            .and_then(|v| v.parse().ok())
        {
            Some(v) => v,
            None => self
                .db
                .query_row("SELECT COALESCE(MAX(id),0)+1 FROM predb", [], |r| r.get(0))?,
        };
        if cursor <= 0 {
            return Ok((0, 0, 0));
        }
        self.ensure_corr_index()?;
        let pres: Vec<CorrPreRow> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id, title, category, source, size, files, nuked, pt, fnkey<>''
                   FROM predb WHERE id<?1 AND fnkey='' AND size>0
                  ORDER BY id DESC LIMIT ?2",
            )?;
            stmt.query_map(rusqlite::params![cursor, budget], |r| {
                Ok(CorrPreRow {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    category: r.get(2)?,
                    source: r.get(3)?,
                    size: r.get::<_, i64>(4)?.max(0) as u64,
                    files: r.get::<_, i64>(5)?.max(0) as u32,
                    nuked: r.get(6)?,
                    pt: r.get(7)?,
                    has_fn: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let (suggested, applied) = self.corr_probe_batch(&pres, auto, now)?;
        // Fewer rows than asked for = the walk fell off the bottom of
        // the table; park at 0 so later ticks cost one kv read.
        let next = if pres.len() as u32 >= budget {
            pres.last().map(|p| p.id).unwrap_or(0)
        } else {
            0
        };
        self.kv_set("predb_catchup_cursor", &next.to_string())?;
        Ok((pres.len(), suggested, applied))
    }

    /// On-demand ranked candidate list for one release (the UI's
    /// pick-a-name view). Top `n`, floor NOT applied - a human scanning
    /// twenty names spots the right one below the floor too.
    pub fn pre_candidates(
        &self,
        rid: i64,
        n: usize,
    ) -> rusqlite::Result<Vec<(i64, String, i32, i64, u32, bool, String)>> {
        let Some((facts, cands, _saturated)) = self.corr_eval(rid)? else {
            return Ok(Vec::new());
        };
        Ok(cands
            .into_iter()
            .take(n)
            .map(|c| {
                (
                    c.pre.id,
                    c.pre.title.clone(),
                    c.score.total,
                    facts.first_posted - c.pre.pt,
                    c.score.ratio_milli,
                    c.pre.nuked,
                    c.pre.source.clone(),
                )
            })
            .collect())
    }

    /// Manual assignment from the candidate list. The human IS the
    /// gate, so none of the auto clauses apply; provenance says a human
    /// picked a correlated name.
    pub fn pre_assign(&mut self, rid: i64, predb_id: i64, now: i64) -> rusqlite::Result<bool> {
        let Some((title, source)) = self
            .db
            .prepare_cached("SELECT title, source FROM predb WHERE id=?1")?
            .query_row([predb_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .optional()?
        else {
            return Ok(false);
        };
        let label = format!("manual+corr:{}", corr_source_base(&source));
        if !self.apply_pre_name(rid, &title, &label, now)? {
            return Ok(false);
        }
        self.db.execute(
            "INSERT INTO pre_corr(release_id, predb_id, score, delta, ratio, runner_up,
                                  status, at)
             VALUES(?1,?2,0,0,0,0,'applied',?3)
             ON CONFLICT(release_id) DO UPDATE SET
               predb_id=excluded.predb_id, status='applied', at=excluded.at",
            rusqlite::params![rid, predb_id, now],
        )?;
        Ok(true)
    }

    /// Reject a suggestion. A rejected row is never re-suggested (the
    /// wall_dismissed lesson: a declined suggestion must not nag). If
    /// the rejected name had been correlation-applied, it is revoked
    /// too - rejection means "that name is wrong", not "stop showing
    /// the hint".
    pub fn pre_reject(&mut self, rid: i64, now: i64) -> rusqlite::Result<()> {
        let applied: Option<String> = self
            .db
            .prepare_cached("SELECT pre_source FROM releases WHERE id=?1")?
            .query_row([rid], |r| r.get(0))
            .optional()?;
        if let Some(src) = applied
            && (src.starts_with("predb/corr:") || src.starts_with("predb/manual+corr:"))
        {
            self.revoke_pre_name(rid)?;
        }
        self.db.execute(
            "INSERT INTO pre_corr(release_id, predb_id, score, delta, ratio, runner_up,
                                  status, at)
             VALUES(?1,0,0,0,0,0,'rejected',?2)
             ON CONFLICT(release_id) DO UPDATE SET status='rejected', at=excluded.at",
            rusqlite::params![rid, now],
        )?;
        Ok(())
    }

    /// Take a correlation-applied name back off: pre_title clears (the
    /// pre_fts UPDATE trigger removes the search entry) and everything
    /// the name determined is re-derived from the stem, exactly the way
    /// ingest would. Exists ONLY for corr-applied rows; exact-leg names
    /// are relay facts and are not touched by correlation code.
    pub fn revoke_pre_name(&mut self, rid: i64) -> rusqlite::Result<bool> {
        let row = self
            .db
            .prepare_cached(&format!(
                "SELECT stem, total_bytes,
                        (SELECT COALESCE(SUM({EXE_FILE_SQL}),0) FROM files
                          WHERE release_id=releases.id)
                   FROM releases WHERE id=?1 AND pre_title<>''"
            ))?
            .query_row([rid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .optional()?;
        let Some((stem, bytes, nexe)) = row else {
            return Ok(false);
        };
        let p = crate::categories::classify(&stem, &self.custom);
        let n = self.db.execute(
            "UPDATE releases
                SET pre_title='', pre_source='',
                    kind=?2, res=?3, title_key=?4, junk=?5, langs=?6,
                    vcodec=?7, acodec=?8, hdr=?9
              WHERE id=?1",
            rusqlite::params![
                rid,
                kind_str(&p.kind),
                p.res.as_deref().unwrap_or_default(),
                p.key,
                junk_score(&stem, &p, bytes as u64, nexe > 0),
                p.langs.join(" "),
                p.vcodec.as_deref().unwrap_or_default(),
                p.acodec.as_deref().unwrap_or_default(),
                p.hdr.as_deref().unwrap_or_default()
            ],
        )?;
        if n > 0 {
            self.db.execute(
                "UPDATE pre_corr SET status='revoked' WHERE release_id=?1",
                [rid],
            )?;
        }
        Ok(n > 0)
    }

    /// Suggestions worth spending an external indexer lookup on: STRONG
    /// score, still 'suggested', never checked before. The
    /// indexer-confirm lane searches the user's own newznab account for
    /// each returned title and message-id-joins the answer - the only
    /// scalable ground truth for a band no byte probe can reach (its
    /// population rule deliberately excludes probe-reachable rows).
    /// Ordered best-first so a small daily budget spends itself on the
    /// pairs most likely to be real.
    ///
    /// Returns (release id, title, score, PREDB ID). The pre id is the
    /// half that makes a stamp specific: see `corr_confirm_stamp`.
    pub fn corr_confirm_pick(
        &self,
        limit: usize,
    ) -> rusqlite::Result<Vec<(i64, String, i32, i64)>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT c.release_id, p.title, c.score, c.predb_id
               FROM pre_corr c JOIN predb p ON p.id=c.predb_id
              WHERE c.status='suggested' AND c.checked_at=0 AND c.score>=?1
              ORDER BY c.score DESC, c.release_id LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(
                rusqlite::params![crate::predb_corr::STRONG, limit as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Retire a suggestion from the confirm lane's pick, win or lose.
    /// One suggestion never costs the user's indexer quota twice; the
    /// verdict itself (confirmed/rejected) is `apply_proven_name`'s to
    /// settle if the fetched NZB joined.
    /// The stamp names the PAIRING it was minted for, not just the
    /// release: a sweep can replace the stored pre while the lookup is
    /// in flight, and a release-only stamp would then retire a
    /// successor nobody has checked.
    pub fn corr_confirm_stamp(
        &self,
        release_id: i64,
        predb_id: i64,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.db
            .prepare_cached(
                "UPDATE pre_corr SET checked_at=?3
                  WHERE release_id=?1 AND predb_id=?2",
            )?
            .execute(rusqlite::params![release_id, predb_id, now])?;
        Ok(())
    }

    /// The download-time verdict: a byte-level oracle (srrdb CRC /
    /// PAR2 hash16k) has just named the post `posted_stem` as
    /// `oracle_name`. If a correlation had claimed (or suggested) a
    /// name for that release, the oracle settles it: agreement is
    /// 'confirmed' (and the now-PROVEN pairing is back-fed into the
    /// predb row's filename, arming the exact legs for any repost);
    /// disagreement is 'rejected', and an applied correlation name is
    /// revoked on the spot. Exact-leg names (relay-paired filenames)
    /// are never touched - the oracle vs relay fight, if it ever
    /// happens, is not correlation's to referee.
    ///
    /// Returns Some(true)=confirmed, Some(false)=rejected, None when
    /// no correlation row was involved. This is the mechanism behind
    /// the confirmed:rejected precision meter.
    pub fn pre_corr_verdict(
        &mut self,
        posted: &str,
        oracle_name: &str,
        now: i64,
    ) -> rusqlite::Result<Option<bool>> {
        let stem = crate::extract::release_stem(posted).to_ascii_lowercase();
        let oracle_key = crate::predb::match_key(oracle_name);
        if stem.is_empty() || oracle_key.is_empty() {
            return Ok(None);
        }
        // Release identity is UNIQUE(stem, poster, grp), so a stem alone
        // can name several rows - a crosspost is exactly that, the same
        // release posted to two groups. The download tail knows only the
        // posted name, so when more than one row carries a live
        // correlation claim under this stem there is no way to tell
        // which one the bytes belong to, and picking an arbitrary
        // `LIMIT 1` let an oracle result for B confirm, reject or revoke
        // A - and, on a confirm, back-feed B's filename into A's predb
        // candidate, arming future exact matches on a pairing nothing
        // ever proved. A verdict that cannot be aimed is not applied.
        let ambiguous: i64 = self
            .db
            .prepare_cached(
                "SELECT COUNT(*) FROM releases r
                   JOIN pre_corr c ON c.release_id=r.id
                  WHERE LOWER(r.stem)=?1 AND c.status IN ('suggested','applied')",
            )?
            .query_row([&stem], |r| r.get(0))?;
        if ambiguous > 1 {
            return Ok(None);
        }
        let row = self
            .db
            .prepare_cached(
                "SELECT r.id, r.pre_title, r.pre_source, c.predb_id, c.status,
                        COALESCE(p.title,''), COALESCE(p.filename,'')
                   FROM releases r
                   JOIN pre_corr c ON c.release_id=r.id
                   LEFT JOIN predb p ON p.id=c.predb_id
                  WHERE LOWER(r.stem)=?1 AND c.status IN ('suggested','applied')
                  LIMIT 1",
            )?
            .query_row([&stem], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })
            .optional()?;
        let Some((rid, pre_title, pre_source, predb_id, status, cand_title, cand_fn)) = row else {
            return Ok(None);
        };
        // What did correlation claim? The applied name for 'applied',
        // the candidate's own title for 'suggested'.
        let claimed = if status == "applied" {
            &pre_title
        } else {
            &cand_title
        };
        if claimed.trim().is_empty() {
            return Ok(None);
        }
        let corr_applied =
            pre_source.starts_with("predb/corr:") || pre_source.starts_with("predb/manual+corr:");
        if status == "applied" && !corr_applied {
            // The applied name is an exact-leg fact, not ours.
            return Ok(None);
        }
        if crate::predb::match_key(claimed) == oracle_key {
            self.db.execute(
                "UPDATE pre_corr SET status='confirmed', at=?2 WHERE release_id=?1",
                rusqlite::params![rid, now],
            )?;
            // Back-feed the proven pairing: the posted stem IS this
            // pre's filename now, which is exactly what the exact legs
            // key on. Non-empty-wins as everywhere; the cleared
            // tried_at puts the row at the front of the exact sweep.
            if cand_fn.is_empty() && predb_id > 0 {
                let fnkey = crate::predb::match_key(&stem);
                self.db.execute(
                    "UPDATE predb SET filename=?2, fnstem=?3, fnkey=?4, tried_at=0
                      WHERE id=?1 AND filename=''",
                    rusqlite::params![predb_id, posted, stem, fnkey],
                )?;
                self.predb = true;
            }
            return Ok(Some(true));
        }
        // The oracle says otherwise. Take an applied name back off
        // before recording the verdict - revoke_pre_name flips the
        // status to 'revoked', so 'rejected' is written after it.
        if status == "applied" && corr_applied {
            self.revoke_pre_name(rid)?;
        }
        self.db.execute(
            "UPDATE pre_corr SET status='rejected', at=?2 WHERE release_id=?1",
            rusqlite::params![rid, now],
        )?;
        Ok(Some(false))
    }

    /// Correlation hints for a page of browse rows: release_id ->
    /// (name, score, delta, ratio_milli, status). One prepared lookup
    /// per page; INNER JOIN so a pruned pre row simply drops its hint.
    pub fn pre_hints(
        &self,
        ids: &[i64],
    ) -> rusqlite::Result<Vec<(i64, String, i32, i64, u32, String)>> {
        let mut out = Vec::new();
        let mut stmt = self.db.prepare_cached(
            "SELECT c.release_id, p.title, c.score, c.delta, c.ratio, c.status
               FROM pre_corr c JOIN predb p ON p.id=c.predb_id
              WHERE c.release_id=?1 AND c.status IN ('suggested','applied','confirmed')",
        )?;
        for id in ids {
            if let Some(row) = stmt
                .query_row([id], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get::<_, i64>(4)?.max(0) as u32,
                        r.get(5)?,
                    ))
                })
                .optional()?
            {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// The correlation precision meter: counts by status. The
    /// confirmed:rejected ratio is the number that earns (or loses) the
    /// auto tier.
    pub fn predb_corr_stats(&self) -> rusqlite::Result<Vec<(String, u64)>> {
        let mut stmt = self
            .db
            .prepare_cached("SELECT status, COUNT(*) FROM pre_corr GROUP BY status")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)?.max(0) as u64)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Store a batch of HISTORICAL pres from an aggregator. Differs
    /// from `predb_store` in exactly the ways the seed design demands:
    /// a row without a timestamp is skipped entirely (it can feed
    /// neither correlation nor exact matching - it could only collide),
    /// rows are born RETIRED (the backlog walk reaches them by pt range;
    /// they never enter the live rotation), and an existing row's
    /// `source` is KEPT when non-empty - live provenance outranks seed
    /// provenance for the same title. Returns rows stored or updated.
    pub fn predb_seed_store(
        &mut self,
        lines: &[crate::predb::PreLine],
        source: &str,
        now: i64,
    ) -> rusqlite::Result<usize> {
        // Same reason as predb_store: seed rows are feed activity, and
        // the named count needs its index before the read-only API
        // handle starts asking.
        self.ensure_named_index_stamped();
        let tx = self.db.transaction()?;
        let mut stored = 0usize;
        for l in lines {
            if l.title.trim().is_empty() || l.date <= 0 {
                continue;
            }
            let n = tx
                .prepare_cached(
                    "INSERT INTO predb(title, filename, fnstem, fnkey, size, files,
                                       category, source, requestid, grp, nuked,
                                       nuke_reason, pre_at, seen_at, pt, tried_at)
                     VALUES(?1,'','','',?2,?3,?4,?5,'','',?6,?7,?8,?9,?8,?10)
                     ON CONFLICT(title) DO UPDATE SET
                       size    =CASE WHEN excluded.size <>0 THEN excluded.size  ELSE size  END,
                       files   =CASE WHEN excluded.files<>0 THEN excluded.files ELSE files END,
                       category=CASE WHEN excluded.category<>'' THEN excluded.category
                                     ELSE category END,
                       source  =CASE WHEN source='' THEN excluded.source ELSE source END,
                       nuked   =MAX(nuked, excluded.nuked),
                       nuke_reason=CASE WHEN excluded.nuke_reason<>'' THEN excluded.nuke_reason
                                        ELSE nuke_reason END,
                       pre_at  =CASE WHEN excluded.pre_at<>0 THEN excluded.pre_at ELSE pre_at END,
                       pt      =CASE WHEN excluded.pre_at<>0 THEN excluded.pre_at ELSE pt END",
                )?
                .execute(rusqlite::params![
                    l.title.trim(),
                    l.size as i64,
                    l.files,
                    l.category,
                    source,
                    matches!(l.kind, crate::predb::PreKind::Nuk),
                    l.nuke_reason,
                    l.date,
                    now,
                    PREDB_RETIRED
                ])?;
            stored += n;
        }
        tx.commit()?;
        Ok(stored)
    }
}
