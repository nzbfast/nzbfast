//! C3 prototype: one-row-per-title materialized wall summaries.
//! MEASURED, DELIBERATELY OFF - read the second paragraph before
//! switching it on.
//!
//! The card wall counts `COUNT(DISTINCT title_key)` over the qualifying
//! population and then groups/sorts that same population to hand back
//! sixty cards ([`super::cards`]). Both halves are proportional to the
//! WALL-VISIBLE release count and neither is bounded by the page. This
//! module keeps one row per wall-visible title, so the count reads
//! O(visible titles) and the page reads O(offset+limit).
//!
//! **It is off by default because the wall is not slow yet, and the
//! reason is worth knowing.** `junk < 50` is the wall's release-level
//! predicate and `idx_rel_visible_posted` is a PARTIAL index on exactly
//! it. Measured 20 Aug 2026 on the live 13.2M-release index: 33,662
//! rows pass that gate - 0.25% - so the planner walks 33k index entries
//! and the whole page costs 190 ms. The audit item that asked for this
//! module read the SQL rather than the plan. The crossover is written
//! down in `research/C3-title-summaries-prototype-2026-08-20.md`: the
//! exact query passes one second per page at roughly 100k visible
//! releases, and this module is a 15-100x win above that and nothing a
//! user can feel below it. Turn it on when the visible population grows,
//! not because the release count did.
//!
//! Two things make it sound rather than merely fast:
//!
//! 1. **The canonical predicate is baked in and nothing else is.** A
//!    summary row aggregates exactly the releases matching
//!    [`CANON_SQL`] - `title_key <> '' AND junk < 50 AND adult = 0`,
//!    which is what the default wall asks for and what no request can
//!    vary except by turning curation off. Every OTHER filter the wall
//!    offers is either title-level (the `titles` join: matched, genre,
//!    decade, adult genre, hides) and therefore still a read-time
//!    predicate against the summary, or release-level (kind, res,
//!    complete, min size, newer-than, the search text, hide rules) and
//!    therefore NOT answerable from a summary at all - those requests
//!    fall back to the exact query. [`cards_summary_eligible`] is the
//!    single place that decides, and the differential tests hold the
//!    two paths to the same answer across the whole matrix.
//!
//! 2. **No writer can escape maintenance.** `releases` has ~40
//!    production write sites (ingest, spots, predb, the fold/prune/
//!    rekey/evict passes, migrations), several of them unbounded bulk
//!    statements. Rather than teach each one to fold - the N8 shape,
//!    which works there because `files` has five writers - the touched
//!    keys are collected by SQL triggers into the `title_dirty` table,
//!    and [`Index::drain_title_dirty`] recomputes them. A key nobody
//!    drained is a key the read path refuses to serve from the summary
//!    (see [`Index::summaries_fresh`]), so staleness costs latency,
//!    never a wrong answer.
//!
//! [`TitleSummary::recompute`] is the single copy of the full-scan
//! formula: the drain's worker AND the oracle the differential tests
//! hold the whole arrangement to. [`TitleSummary::apply_release`] is
//! the incremental fold for the one shape that can be folded (a release
//! joining or growing under a key), kept beside it and held to
//! `recompute` by the same test.

use rusqlite::Connection;

use super::cards::{Card, CardSort};
use super::{BrowseQuery, Index};

/// The releases a summary row aggregates, with `{}` where the alias
/// goes - the same convention `browse`/`browse_cards` use for their
/// predicate lists.
///
/// This is exactly the default wall's release-level predicate list:
/// `title_key != ''` (seeded by the card query), `junk < 50` (the
/// curation ceiling, from `max_junk`) and `adult = 0` (the spot-born
/// marker, from `hide_adult`). A request that varies any of the three
/// cannot be served from these rows.
pub(crate) const CANON_SQL: &str = "{}title_key <> '' AND {}junk < 50 AND {}adult = 0";

/// The junk ceiling the summary is built under. `max_junk` is an
/// `Option<u32>` on the query, and the daemon only ever sends this
/// value or `None`; anything else falls back.
pub(crate) const CANON_JUNK: u32 = 50;

/// Resolution rank, spelled the way the card query spells it inside its
/// `MAX(...)`. Kept here as well as there because the two have to agree
/// exactly and a differential test compares their answers.
const RES_RANK: &str = "CASE {}res WHEN '2160p' THEN 4 WHEN '1080p' THEN 3
                        WHEN '720p' THEN 2 WHEN '' THEN 0 ELSE 1 END";

/// Render a `{}`-placeholder fragment against one alias.
fn at(sql: &str, alias: &str) -> String {
    sql.replace("{}", alias)
}

/// How many dirty keys one ingest batch retires. A scan chunk touches
/// hundreds of clusters, not thousands of titles, so this clears the
/// ordinary batch outright; the cap only bites behind a bulk statement
/// (an eviction sweep, a rekey merge, a migration), which is exactly
/// where a bounded slice per call is what you want.
pub(crate) const DRAIN_PER_BATCH: usize = 4096;

/// One title's wall aggregates, in their stored shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TitleSummary {
    /// Qualifying releases under this key (the card's release count).
    pub(crate) n: i64,
    /// `MAX(first_posted)` - the wall's default sort key.
    pub(crate) latest: i64,
    /// `MAX(first_seen)` - the Arrived sort.
    pub(crate) latest_seen: i64,
    /// `MAX(complete)`: any qualifying release complete.
    pub(crate) any_complete: bool,
    pub(crate) max_bytes: i64,
    /// `MAX(<res rank>)`, 0..4 - see [`RES_RANK`].
    pub(crate) best_res: i64,
    /// `MAX(kind)`, which is what the card query projects and what the
    /// category grouping clusters on.
    pub(crate) rep_kind: String,
    /// The representative release: newest posted, id breaking the tie -
    /// the identical, fully deterministic pick the card query's two
    /// correlated subqueries make.
    pub(crate) rep_id: i64,
    /// `COALESCE(NULLIF(pre_title,''), stem)` of the representative.
    pub(crate) rep_stem: String,
    pub(crate) rep_grp: String,
}

/// The release-level facts a summary reads off one row. What
/// [`TitleSummary::apply_release`] folds.
///
/// Carried by the prototype but not yet by any writer: the drain
/// recomputes, and the fold is the measured next step (see the C3
/// writeup). Tested against `recompute` so the step is a wiring change
/// and not a design one.
// Not #[expect]: the unit tests exercise it, so the expectation is
// unfulfilled under cfg(test).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelFacts {
    pub(crate) id: i64,
    pub(crate) first_posted: i64,
    pub(crate) first_seen: i64,
    pub(crate) complete: bool,
    pub(crate) total_bytes: i64,
    /// Already ranked - see [`res_rank`].
    pub(crate) res_rank: i64,
    pub(crate) kind: String,
    /// The representative's display name, already collapsed:
    /// `COALESCE(NULLIF(pre_title,''), stem)`.
    pub(crate) name: String,
    pub(crate) grp: String,
}

/// Rust twin of [`RES_RANK`], held to it by a differential test.
// Not #[expect]: the unit tests exercise it, so the expectation is
// unfulfilled under cfg(test).
#[allow(dead_code)] // see RelFacts: the fold half is not wired yet.
pub(crate) fn res_rank(res: &str) -> i64 {
    match res {
        "2160p" => 4,
        "1080p" => 3,
        "720p" => 2,
        "" => 0,
        _ => 1,
    }
}

impl TitleSummary {
    /// The full-scan formula: what one key's summary row must equal
    /// after any write. Two statements rather than one because the
    /// representative's tiebreak (`first_posted DESC, id DESC`) is a
    /// two-column order, and SQLite's bare-column-beside-MAX rule only
    /// carries a row through for a SINGLE min/max aggregate - with the
    /// six MAXes below it, the bare columns would be an arbitrary row.
    ///
    /// `None` = the key has no qualifying release; its summary row must
    /// be deleted rather than zeroed (a zeroed row would still be
    /// counted by the wall).
    pub(crate) fn recompute(db: &Connection, key: &str) -> rusqlite::Result<Option<Self>> {
        let canon = at(CANON_SQL, "");
        let rank = at(RES_RANK, "");
        let agg: Option<(i64, i64, i64, bool, i64, i64, String)> = db
            .prepare_cached(&format!(
                "SELECT COUNT(*), COALESCE(MAX(first_posted),0),
                        COALESCE(MAX(first_seen),0), COALESCE(MAX(complete),0),
                        COALESCE(MAX(total_bytes),0), COALESCE(MAX({rank}),0),
                        COALESCE(MAX(kind),'')
                   FROM releases WHERE title_key = ?1 AND {canon}"
            ))?
            .query_row([key], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })
            .ok();
        let Some((n, latest, latest_seen, any_complete, max_bytes, best_res, rep_kind)) = agg
        else {
            return Ok(None);
        };
        if n == 0 {
            return Ok(None);
        }
        let rep: (i64, String, String) = db
            .prepare_cached(&format!(
                "SELECT id, COALESCE(NULLIF(pre_title,''), stem), grp
                   FROM releases WHERE title_key = ?1 AND {canon}
                  ORDER BY first_posted DESC, id DESC LIMIT 1"
            ))?
            .query_row([key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(Some(TitleSummary {
            n,
            latest,
            latest_seen,
            any_complete,
            max_bytes,
            best_res,
            rep_kind,
            rep_id: rep.0,
            rep_stem: rep.1,
            rep_grp: rep.2,
        }))
    }

    /// Fold one release JOINING or GROWING under this key.
    ///
    /// This is the only shape a running MAX can absorb. Anything that
    /// can lower a maximum - a release leaving the key (deleted, folded
    /// away, rekeyed, marked adult, or pushed past the junk ceiling) or
    /// one of the maxed columns decreasing in place - is not foldable,
    /// and the caller must recompute instead. `old` is the row's
    /// previous contribution, `None` when the release is new to the
    /// key; the function returns false when it refuses the fold, having
    /// changed nothing.
    // Not #[expect]: the unit tests exercise it, so the expectation is
    // unfulfilled under cfg(test).
    #[allow(dead_code)] // see RelFacts: the fold half is not wired yet.
    pub(crate) fn apply_release(&mut self, old: Option<&RelFacts>, new: &RelFacts) -> bool {
        if let Some(o) = old {
            debug_assert_eq!(o.id, new.id, "apply_release folds ONE release");
            // A maxed column moving DOWN can un-set a maximum this row
            // holds, and nothing here knows the runner-up.
            if new.first_posted < o.first_posted
                || new.first_seen < o.first_seen
                || new.total_bytes < o.total_bytes
                || new.res_rank < o.res_rank
                || new.kind < o.kind
                || (o.complete && !new.complete)
            {
                return false;
            }
        } else {
            self.n += 1;
        }
        self.latest = self.latest.max(new.first_posted);
        self.latest_seen = self.latest_seen.max(new.first_seen);
        self.any_complete |= new.complete;
        self.max_bytes = self.max_bytes.max(new.total_bytes);
        self.best_res = self.best_res.max(new.res_rank);
        if new.kind > self.rep_kind {
            self.rep_kind = new.kind.clone();
        }
        // The representative is the newest post, id breaking the tie -
        // strictly greater on the pair, so a re-touch of the sitting
        // representative keeps it (and picks up its new name).
        if (new.first_posted, new.id) >= (self.latest_field_for_rep(), self.rep_id) {
            self.rep_id = new.id;
            self.rep_stem = new.name.clone();
            self.rep_grp = new.grp.clone();
        }
        true
    }

    /// `first_posted` of the sitting representative. Not stored: the
    /// representative is by definition the newest qualifying post, so
    /// its `first_posted` IS `latest` - except during the one statement
    /// in [`Self::apply_release`] where `latest` has already absorbed
    /// the new row. Read before that assignment, so it is called on the
    /// pre-update value.
    // Not #[expect]: the unit tests exercise it, so the expectation is
    // unfulfilled under cfg(test).
    #[allow(dead_code)] // see RelFacts: the fold half is not wired yet.
    fn latest_field_for_rep(&self) -> i64 {
        self.latest
    }
}

/// The prototype's schema: the summary rows, their sort indexes, the
/// dirty set, and the triggers that fill it.
///
/// Separate from the open-time migration ladder on purpose - this is
/// behind [`Index::summaries`] and creating it must be an explicit act,
/// because the triggers are a per-write cost on `releases` that an
/// install which never opens the wall should not pay.
pub(crate) fn ensure_schema(db: &Connection) -> rusqlite::Result<()> {
    // Whether this call is the INSTALL. It decides whether the seed runs
    // below, and getting it wrong the safe-looking way - creating the
    // tables and leaving them empty - is the one failure mode this
    // module cannot detect at read time: an empty summary with an empty
    // dirty set reads as "fresh, and this catalogue has no cards".
    let fresh_install = !db
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='title_summaries'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    // DDL and seed in ONE transaction. Autocommit would let a seed that
    // dies leave the tables installed and EMPTY, which is the one state
    // the read path trusts and cannot detect: `summaries_fresh` sees an
    // empty dirty set beside an empty summary and answers zero cards
    // forever, because the next call is no longer a fresh install.
    // SQLite's DDL is transactional, so the rollback takes the tables
    // and triggers with it and the next call installs from scratch.
    let tx = db.unchecked_transaction()?;
    install_schema(&tx)?;
    if fresh_install {
        seed(&tx)?;
    }
    tx.commit()
}

/// The tables, indexes and triggers themselves - [`ensure_schema`]'s
/// DDL half, split out to keep that function inside the size ceiling.
/// Every statement is `IF NOT EXISTS`, so this is the idempotent part.
fn install_schema(db: &Connection) -> rusqlite::Result<()> {
    // `title_dirty` first: the triggers reference it, and a trigger
    // whose table is missing fails the WRITE, not the read.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS title_dirty(
            title_key TEXT PRIMARY KEY NOT NULL) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS title_summaries(
            title_key TEXT PRIMARY KEY NOT NULL,
            n INTEGER NOT NULL,
            latest INTEGER NOT NULL,
            latest_seen INTEGER NOT NULL,
            any_complete INTEGER NOT NULL,
            max_bytes INTEGER NOT NULL,
            best_res INTEGER NOT NULL,
            rep_kind TEXT NOT NULL,
            rep_id INTEGER NOT NULL,
            rep_stem TEXT NOT NULL,
            rep_grp TEXT NOT NULL) WITHOUT ROWID;
         -- One index per summary-borne sort key. These are what turn
         -- the page from a group-and-sort of the population into an
         -- ordered walk stopped by LIMIT; the title-borne sorts
         -- (rating, title, year, aired) sort the joined `titles`
         -- columns and get no index here.
         CREATE INDEX IF NOT EXISTS idx_ts_latest ON title_summaries(latest DESC);
         CREATE INDEX IF NOT EXISTS idx_ts_seen ON title_summaries(latest_seen DESC);
         CREATE INDEX IF NOT EXISTS idx_ts_bytes ON title_summaries(max_bytes DESC);
         CREATE INDEX IF NOT EXISTS idx_ts_n ON title_summaries(n DESC);",
    )?;
    // The triggers. `INSERT OR IGNORE` so a key touched a thousand
    // times in one batch is one dirty row and one recompute - which is
    // the "once per touched key per ingest batch" this design promises.
    //
    // The UPDATE trigger names its columns, so the many writers that
    // only stamp bookkeeping (oracle_at, gapfill_at, probe_at,
    // enc_class, pesto_*, pre_at, pre_source) never fire it. It dirties
    // BOTH sides of the change: a rekey moves a release between two
    // summaries, and a junk/adult flip moves it in or out of the
    // population entirely - in either direction, so it carries no
    // visibility test of its own beyond "was or is visible".
    db.execute_batch(
        "CREATE TRIGGER IF NOT EXISTS ts_rel_ai AFTER INSERT ON releases
           WHEN NEW.title_key <> '' AND NEW.junk < 50 AND NEW.adult = 0
           BEGIN INSERT OR IGNORE INTO title_dirty VALUES(NEW.title_key); END;
         CREATE TRIGGER IF NOT EXISTS ts_rel_ad AFTER DELETE ON releases
           WHEN OLD.title_key <> '' AND OLD.junk < 50 AND OLD.adult = 0
           BEGIN INSERT OR IGNORE INTO title_dirty VALUES(OLD.title_key); END;
         CREATE TRIGGER IF NOT EXISTS ts_rel_au AFTER UPDATE OF
             title_key, junk, adult, first_posted, first_seen, complete,
             total_bytes, res, kind, stem, pre_title, grp ON releases
           WHEN (OLD.junk < 50 AND OLD.adult = 0)
             OR (NEW.junk < 50 AND NEW.adult = 0)
           BEGIN
             INSERT OR IGNORE INTO title_dirty
               SELECT OLD.title_key WHERE OLD.title_key <> '';
             INSERT OR IGNORE INTO title_dirty
               SELECT NEW.title_key WHERE NEW.title_key <> ''
                                      AND NEW.title_key <> OLD.title_key;
           END;",
    )
}

/// Build every summary row in one pass and leave the dirty set empty:
/// the install's seed, and what [`Index::rebuild_title_summaries`] runs
/// to re-derive the lot from scratch.
///
/// The only place a summary is derived by a GROUP scan. Every later
/// change reaches a row through the dirty set, one key at a time.
pub(crate) fn seed(db: &Connection) -> rusqlite::Result<u64> {
    let canon = at(CANON_SQL, "r.");
    let rank = at(RES_RANK, "r.");
    let rep_canon = at(CANON_SQL, "s.");
    db.execute_batch("DELETE FROM title_summaries; DELETE FROM title_dirty;")?;
    let n = db.execute(
        &format!(
            "INSERT INTO title_summaries
             SELECT r.title_key, COUNT(*), MAX(r.first_posted), MAX(r.first_seen),
                    MAX(r.complete), MAX(r.total_bytes), MAX({rank}), MAX(r.kind),
                    (SELECT s.id FROM releases s
                      WHERE s.title_key = r.title_key AND {rep_canon}
                      ORDER BY s.first_posted DESC, s.id DESC LIMIT 1),
                    (SELECT COALESCE(NULLIF(s.pre_title,''), s.stem) FROM releases s
                      WHERE s.title_key = r.title_key AND {rep_canon}
                      ORDER BY s.first_posted DESC, s.id DESC LIMIT 1),
                    (SELECT s.grp FROM releases s
                      WHERE s.title_key = r.title_key AND {rep_canon}
                      ORDER BY s.first_posted DESC, s.id DESC LIMIT 1)
               FROM releases r WHERE {canon}
              GROUP BY r.title_key"
        ),
        [],
    )?;
    // The seed's own INSERTs do not fire the releases triggers, but a
    // concurrent writer's might have; the DELETE above ran before the
    // scan, so anything dirtied since is genuinely still owed.
    Ok(n as u64)
}

/// Drop the prototype's schema, triggers first - the measurement rig's
/// off-arm, and the uninstall path for a flag that gets turned back off.
pub(crate) fn drop_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "DROP TRIGGER IF EXISTS ts_rel_ai;
         DROP TRIGGER IF EXISTS ts_rel_ad;
         DROP TRIGGER IF EXISTS ts_rel_au;
         DROP TABLE IF EXISTS title_summaries;
         DROP TABLE IF EXISTS title_dirty;",
    )
}

impl Index {
    /// Is the summary usable right now: the tables exist and nothing is
    /// waiting to be recomputed.
    ///
    /// The emptiness test is what makes the whole arrangement safe. A
    /// writer that forgets to drain, a drain cut short by its budget, a
    /// bulk statement that dirtied fifty thousand keys - all of them
    /// come out as "not fresh", and the wall answers from the exact
    /// query it always used. There is no state in which a stale summary
    /// row reaches a user.
    pub(crate) fn summaries_fresh(&self) -> bool {
        self.summaries
            && self
                .db
                .query_row("SELECT NOT EXISTS(SELECT 1 FROM title_dirty)", [], |r| {
                    r.get::<_, bool>(0)
                })
                .unwrap_or(false)
    }

    /// Recompute up to `budget` dirty keys, newest work first is not a
    /// thing here - the set is unordered and every key in it is equally
    /// stale. Returns how many were retired.
    ///
    /// One transaction for the batch: the summary rows and the dirty
    /// rows that justify them must move together, or a crash between
    /// them leaves a row that looks fresh and is not.
    pub fn drain_title_dirty(&mut self, budget: usize) -> rusqlite::Result<usize> {
        if !self.summaries || budget == 0 {
            return Ok(0);
        }
        let keys: Vec<String> = {
            let mut stmt = self
                .db
                .prepare_cached("SELECT title_key FROM title_dirty LIMIT ?1")?;
            stmt.query_map([budget as i64], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        if keys.is_empty() {
            return Ok(0);
        }
        let tx = self.db.transaction()?;
        for key in &keys {
            match TitleSummary::recompute(&tx, key)? {
                Some(s) => {
                    tx.prepare_cached(
                        "INSERT INTO title_summaries(title_key, n, latest, latest_seen,
                            any_complete, max_bytes, best_res, rep_kind, rep_id,
                            rep_stem, rep_grp)
                         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
                         ON CONFLICT(title_key) DO UPDATE SET
                            n=excluded.n, latest=excluded.latest,
                            latest_seen=excluded.latest_seen,
                            any_complete=excluded.any_complete,
                            max_bytes=excluded.max_bytes, best_res=excluded.best_res,
                            rep_kind=excluded.rep_kind, rep_id=excluded.rep_id,
                            rep_stem=excluded.rep_stem, rep_grp=excluded.rep_grp",
                    )?
                    .execute(rusqlite::params![
                        key,
                        s.n,
                        s.latest,
                        s.latest_seen,
                        s.any_complete,
                        s.max_bytes,
                        s.best_res,
                        s.rep_kind,
                        s.rep_id,
                        s.rep_stem,
                        s.rep_grp
                    ])?;
                }
                // Every qualifying release is gone (evicted, folded,
                // rekeyed away, or newly junk/adult). The row must GO:
                // a zeroed row is still a card on the wall.
                None => {
                    tx.prepare_cached("DELETE FROM title_summaries WHERE title_key=?1")?
                        .execute([key])?;
                }
            }
            tx.prepare_cached("DELETE FROM title_dirty WHERE title_key=?1")?
                .execute([key])?;
        }
        tx.commit()?;
        Ok(keys.len())
    }

    /// Re-derive every summary row from scratch: the repair hatch, and
    /// what the measurement rig calls to time an install over an
    /// existing catalogue.
    pub fn rebuild_title_summaries(&mut self) -> rusqlite::Result<u64> {
        ensure_schema(&self.db)?;
        self.summaries = true;
        let tx = self.db.transaction()?;
        let n = seed(&tx)?;
        tx.commit()?;
        Ok(n)
    }
}

/// Can this request be answered from the summary rows?
///
/// Says yes only when every release-level predicate the request would
/// add is already baked into [`CANON_SQL`]. The title-level ones
/// (`matched_only`, the genre chip, the decade range, the hides, the
/// adult GENRE test) are constant across a title's releases, so they
/// stay ordinary read-time predicates against the joined `titles` row
/// and cost the fast path nothing.
///
/// `rules` is the user's `wall_rules`, already read: a `genre` rule
/// resolves through `titles` and is fine, every other field
/// (`lang`/`kind`/`group`/`word`) filters individual releases and
/// changes what the group aggregates to.
pub(crate) fn cards_summary_eligible(
    q: &BrowseQuery,
    sort: CardSort,
    affinity_used: bool,
    rules: &[(String, String)],
) -> bool {
    // The three halves of the canonical predicate, exactly.
    q.max_junk == Some(CANON_JUNK)
        && q.hide_adult
        && q.curated
        && rules.iter().all(|(field, _)| field == "genre")
        // Release-level filters with no summary column behind them.
        && q.kind.is_none()
        && q.res.is_none()
        && !q.complete_only
        && q.min_bytes == 0
        && q.newer_than == 0
        && q.title_keys.is_empty()
        && q.q.trim().is_empty()
        && q.verdict_ok.is_none()
        // The Affinity sort scores `MAX(r.kind)` and the owned set,
        // both of which the summary carries - but it also binds its own
        // parameters mid-build, and the prototype keeps that whole
        // branch on the exact path rather than duplicating the scorer.
        && !(sort == CardSort::Affinity && affinity_used)
}

impl Index {
    /// The summary-backed card page. `None` = this request is not
    /// eligible (or the summary is not fresh) and the caller must run
    /// the exact query.
    ///
    /// The projection, the title-level predicate list and the ORDER BY
    /// are the card query's own, re-aimed at `m.` columns instead of at
    /// `MAX(r.…)` over a group - so the two paths differ in HOW they
    /// reach an answer and not in which answer they reach.
    pub(super) fn browse_cards_summary(
        &self,
        q: &BrowseQuery,
        sort: CardSort,
        matched_only: bool,
        group_by_kind: bool,
        affinity_used: bool,
    ) -> rusqlite::Result<Option<(Vec<Card>, u64)>> {
        if !self.summaries_fresh() {
            return Ok(None);
        }
        let rules: Vec<(String, String)> = {
            let mut stmt = self
                .db
                .prepare_cached("SELECT field, value FROM wall_rules")?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        if !cards_summary_eligible(q, sort, affinity_used, &rules) {
            return Ok(None);
        }
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let bind = |params: &mut Vec<Box<dyn rusqlite::ToSql>>, v: Box<dyn rusqlite::ToSql>| {
            params.push(v);
            format!("?{}", params.len())
        };
        // Curation's title half. The release half (the hide rules) was
        // refused by the eligibility test above, except `genre`, which
        // is a titles lookup and reads the same here as it does there.
        let mut wheres: Vec<String> =
            vec!["m.title_key NOT IN (SELECT key FROM wall_hidden)".into()];
        for (field, value) in &rules {
            if field == "genre" {
                // Read off the joined `titles` row, not out of a
                // subquery: this path ALREADY joins `t` (the projection
                // below selects nine of its columns), and the exclusion-
                // list spelling was a full pass over `titles` in each of
                // the two statements this function runs. That is the
                // same term the exact path carries, one rendering
                // shallower - see the `genre` arm of `curation_wheres`
                // for the measurement and the release-list shape.
                // COALESCE keeps a title with no enriched row: an
                // unknown genre is not evidence, exactly as
                // `ADULT_GENRE_SQL` below has it.
                let p = bind(&mut params, Box::new(value.clone()));
                wheres.push(format!(
                    "NOT (COALESCE(t.genres,'') LIKE '%' || {p} || '%')"
                ));
            }
        }
        if matched_only {
            wheres.push("t.checked > 0 AND t.poster != ''".into());
        }
        if let Some(g) = q.genre.as_deref().filter(|g| !g.trim().is_empty()) {
            let p = bind(&mut params, Box::new(g.trim().to_string()));
            wheres.push(format!("t.genres LIKE '%' || {p} || '%'"));
        }
        // hide_adult is a precondition of eligibility, so the GENRE
        // half is unconditional here; the release-level MARK half is
        // already inside the summary's canonical predicate.
        wheres.push(super::ADULT_GENRE_SQL.to_string());
        if q.year_min > 0 {
            let p = bind(&mut params, Box::new(q.year_min as i64));
            wheres.push(format!("{CARD_YEAR_SUMMARY_SQL} >= {p}"));
        }
        if q.year_max > 0 {
            let p = bind(&mut params, Box::new(q.year_max as i64));
            wheres.push(format!(
                "{CARD_YEAR_SUMMARY_SQL} <= {p} AND {CARD_YEAR_SUMMARY_SQL} > 0"
            ));
        }
        let where_clause = wheres.join(" AND ");
        let total: u64 = self
            .db
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM title_summaries m
                       LEFT JOIN titles t ON t.key = m.title_key
                      WHERE {where_clause}"
                ),
                rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)?;
        // Same fixed vocabulary as the exact path, one column shallower:
        // what was MAX(r.x) over a group is m.x here. That includes the
        // `title_key` tiebreak on the ORDER BY below, which is not
        // optional on this side: the differential tests hold this path
        // and the exact one to a single answer, so a total order on one
        // of them and not the other is a disagreement the moment two
        // cards share a `first_posted` second. `cards.rs` carries the
        // reasoning.
        let key: &str = match sort {
            CardSort::Latest => "m.latest",
            CardSort::Arrived => "m.latest_seen",
            CardSort::Rating => "COALESCE(t.rating, 0)",
            CardSort::Title => "COALESCE(NULLIF(t.title,''), m.title_key) COLLATE NOCASE",
            CardSort::Releases | CardSort::Affinity => "m.n",
            CardSort::Size => "m.max_bytes",
            CardSort::Year => CARD_YEAR_SUMMARY_SQL,
            CardSort::Aired => CARD_AIRED_SUMMARY_SQL,
        };
        let dir = if q.desc { "DESC" } else { "ASC" };
        let group_prefix = if group_by_kind {
            "CASE m.rep_kind WHEN 'tv' THEN 0 WHEN 'movie' THEN 1
                             WHEN 'music' THEN 2 WHEN 'book' THEN 3
                             WHEN 'software' THEN 5
                             WHEN 'other' THEN 6 ELSE 4 END ASC,
             m.rep_kind ASC, "
        } else {
            ""
        };
        let sql = format!(
            "SELECT m.title_key, m.rep_kind, m.n, m.latest, m.any_complete, m.max_bytes,
                    m.best_res, m.rep_stem, m.rep_grp,
                    COALESCE(t.title,''), COALESCE(t.year,0), COALESCE(t.rating,0),
                    COALESCE(t.genres,''), COALESCE(t.overview,''),
                    COALESCE(t.poster,''), COALESCE(t.backdrop,''),
                    COALESCE(t.checked,0), COALESCE(t.actors,''),
                    COALESCE(t.air_date,'')
               FROM title_summaries m LEFT JOIN titles t ON t.key = m.title_key
              WHERE {where_clause}
              ORDER BY {group_prefix}{key} {dir}, m.latest DESC, m.title_key ASC
              LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Box::new(q.limit.min(500)));
        params.push(Box::new(q.offset));
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
            |r| {
                Ok(Card {
                    title_key: r.get(0)?,
                    kind: r.get(1)?,
                    n_releases: r.get(2)?,
                    latest_posted: r.get(3)?,
                    any_complete: r.get(4)?,
                    max_bytes: r.get::<_, i64>(5)? as u64,
                    best_res: match r.get::<_, i64>(6)? {
                        4 => "2160p",
                        3 => "1080p",
                        2 => "720p",
                        _ => "",
                    }
                    .to_string(),
                    rep_stem: r.get(7)?,
                    rep_grp: r.get(8)?,
                    title: r.get(9)?,
                    year: r.get::<_, i64>(10)? as u32,
                    rating: r.get(11)?,
                    genres: r.get(12)?,
                    overview: r.get(13)?,
                    poster_art: r.get(14)?,
                    backdrop_art: r.get(15)?,
                    checked: r.get(16)?,
                    actors: r.get(17)?,
                    air_date: r.get(18)?,
                })
            },
        )?;
        Ok(Some((rows.collect::<rusqlite::Result<_>>()?, total)))
    }
}

/// The card query's `CARD_YEAR_SQL`, re-aimed at the summary alias.
/// Same expression, `m.title_key` where the group's `r.title_key` was.
const CARD_YEAR_SUMMARY_SQL: &str = "COALESCE(NULLIF(t.year,0),
    CASE WHEN m.title_key GLOB 'm:*:[0-9][0-9][0-9][0-9]'
         THEN CAST(substr(m.title_key,-4) AS INTEGER) ELSE 0 END)";

/// The Aired sort key, likewise.
const CARD_AIRED_SUMMARY_SQL: &str = "CASE WHEN COALESCE(t.air_date,'') <> ''
        THEN t.air_date
        ELSE printf('%04d-00-00', COALESCE(NULLIF(t.year,0),
             CASE WHEN m.title_key GLOB 'm:*:[0-9][0-9][0-9][0-9]'
                  THEN CAST(substr(m.title_key,-4) AS INTEGER) ELSE 0 END)) END";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::teardown;
    use crate::index::{BrowseSort, VerdictFilter};
    use crate::nntp::OverEntry;

    fn open_ix(tag: &str) -> (std::path::PathBuf, Index) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-summaries-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        // The env flag is process-wide and other tests share the
        // process, so the fixture installs the schema directly rather
        // than through it.
        ix.rebuild_title_summaries().unwrap();
        (dir, ix)
    }

    /// One release row, as a tuple so the fixture below reads as a
    /// table: `(id, title_key, kind, first_posted, total_bytes, res,
    /// complete, junk, adult, pre_title)`.
    type Rel = (
        i64,
        &'static str,
        &'static str,
        i64,
        i64,
        &'static str,
        bool,
        i64,
        bool,
        &'static str,
    );

    /// Write one release. SQL rather than `ingest` on purpose: the
    /// triggers ARE the maintenance mechanism, so the test has to poke
    /// the table the way the forty other writers do, and it needs to
    /// place the junk/adult/tie shapes a derived junk score would not
    /// let it place.
    fn put(ix: &Index, r: Rel) {
        let (id, key, kind, posted, bytes, res, complete, junk, adult, pre_title) = r;
        ix.db
            .execute(
                "INSERT INTO releases(id, stem, poster, grp, total_bytes, files, complete,
                    first_posted, first_seen, kind, res, title_key, junk, adult, pre_title,
                    arrival_seq)
                 VALUES(?1,?2,'p@x',?3,?4,3,?5,?6,?7,?8,?9,?10,?11,?12,?13,?1)",
                rusqlite::params![
                    id,
                    format!("stem.{id}.{key}"),
                    format!("alt.binaries.g{}", id % 3),
                    bytes,
                    complete,
                    posted,
                    posted + 60,
                    kind,
                    res,
                    key,
                    junk,
                    adult,
                    pre_title,
                ],
            )
            .unwrap();
    }

    fn put_title(ix: &Index, key: &str, kind: &str, genres: &str, year: i64, enriched: bool) {
        ix.db
            .execute(
                "INSERT INTO titles(key, kind, title, year, rating, genres, poster, backdrop,
                    checked, air_date)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(key) DO UPDATE SET genres=excluded.genres",
                rusqlite::params![
                    key,
                    kind,
                    format!("Title {key}"),
                    year,
                    if enriched { 7.5 } else { 0.0 },
                    genres,
                    if enriched { "http://p/1.jpg" } else { "" },
                    if enriched { "http://b/1.jpg" } else { "" },
                    if enriched { 1_700_000_000i64 } else { 0 },
                    if enriched { "2019-04-01" } else { "" },
                ],
            )
            .unwrap();
    }

    /// The fixture every test below shares: eight titles across the
    /// shapes the summary has to survive - several releases per key,
    /// a same-second tie the id has to break, an all-junk title, an
    /// all-adult title, a pre-fed name on the representative, an
    /// enriched title beside two unenriched ones, and a movie key
    /// carrying its year.
    fn corpus(ix: &mut Index) {
        let rows: [Rel; 13] = [
            (
                1,
                "t:alpha",
                "tv",
                1_700_000_100,
                500,
                "1080p",
                true,
                0,
                false,
                "",
            ),
            (
                2,
                "t:alpha",
                "tv",
                1_700_000_300,
                900,
                "2160p",
                false,
                0,
                false,
                "",
            ),
            // Same second as id 2: the representative tiebreak is id DESC.
            (
                3,
                "t:alpha",
                "tv",
                1_700_000_300,
                100,
                "720p",
                false,
                0,
                false,
                "Fed.Alpha",
            ),
            (
                4,
                "t:alpha",
                "tv",
                1_700_000_900,
                9_000,
                "2160p",
                true,
                80,
                false,
                "",
            ),
            (
                5,
                "t:beta",
                "tv",
                1_700_000_200,
                400,
                "",
                true,
                0,
                false,
                "",
            ),
            (
                6,
                "t:beta",
                "movie",
                1_700_000_150,
                700,
                "1080p",
                false,
                0,
                false,
                "",
            ),
            (
                7,
                "m:gamma:2019",
                "movie",
                1_700_000_400,
                1_200,
                "2160p",
                true,
                0,
                false,
                "",
            ),
            (
                8,
                "t:alljunk",
                "tv",
                1_700_000_500,
                300,
                "1080p",
                true,
                99,
                false,
                "",
            ),
            (
                9,
                "t:alladult",
                "tv",
                1_700_000_600,
                300,
                "1080p",
                true,
                0,
                true,
                "",
            ),
            (
                10,
                "t:mixedadult",
                "tv",
                1_700_000_700,
                300,
                "1080p",
                true,
                0,
                true,
                "",
            ),
            (
                11,
                "t:mixedadult",
                "tv",
                1_700_000_050,
                200,
                "720p",
                false,
                0,
                false,
                "",
            ),
            (
                12,
                "t:hidden",
                "movie",
                1_700_000_800,
                600,
                "1080p",
                true,
                0,
                false,
                "",
            ),
            (13, "", "other", 1_700_000_950, 50, "", false, 0, false, ""),
        ];
        for r in rows {
            put(ix, r);
        }
        put_title(ix, "t:alpha", "tv", "Drama, Thriller", 2011, true);
        put_title(ix, "t:beta", "tv", "Hentai", 2015, true);
        put_title(ix, "m:gamma:2019", "movie", "Comedy", 0, true);
        put_title(ix, "t:mixedadult", "tv", "Adult", 2020, false);
        put_title(ix, "t:hidden", "movie", "Crime", 1999, true);
        ix.db
            .execute("INSERT INTO wall_hidden(key, at) VALUES('t:hidden', 1)", [])
            .unwrap();
        ix.drain_title_dirty(10_000).unwrap();
    }

    /// Every summary row equals what a full scan would say, and no key
    /// with a qualifying release is missing one. The oracle every
    /// mutation below is checked against.
    fn assert_rows_match_recompute(ix: &Index) {
        let stored: Vec<(String, TitleSummary)> = {
            let mut q = ix
                .db
                .prepare(
                    "SELECT title_key, n, latest, latest_seen, any_complete, max_bytes,
                            best_res, rep_kind, rep_id, rep_stem, rep_grp
                       FROM title_summaries ORDER BY title_key",
                )
                .unwrap();
            q.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    TitleSummary {
                        n: r.get(1)?,
                        latest: r.get(2)?,
                        latest_seen: r.get(3)?,
                        any_complete: r.get(4)?,
                        max_bytes: r.get(5)?,
                        best_res: r.get(6)?,
                        rep_kind: r.get(7)?,
                        rep_id: r.get(8)?,
                        rep_stem: r.get(9)?,
                        rep_grp: r.get(10)?,
                    },
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
        };
        for (key, got) in &stored {
            assert_eq!(
                Some(got.clone()),
                TitleSummary::recompute(&ix.db, key).unwrap(),
                "summary drifted from a full scan on {key}"
            );
        }
        // ...and the other direction: no qualifying key without a row.
        let canon = at(CANON_SQL, "");
        let want: Vec<String> = {
            let mut q = ix
                .db
                .prepare(&format!(
                    "SELECT DISTINCT title_key FROM releases WHERE {canon} ORDER BY title_key"
                ))
                .unwrap();
            q.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let have: Vec<String> = stored.into_iter().map(|(k, _)| k).collect();
        assert_eq!(want, have, "summary key set differs from the population");
    }

    /// The wall query the daemon actually sends, plus the one knob the
    /// caller wants to vary.
    fn wall_q() -> BrowseQuery {
        BrowseQuery {
            max_junk: Some(CANON_JUNK),
            curated: true,
            hide_adult: true,
            desc: true,
            limit: 60,
            ..Default::default()
        }
    }

    /// Run one request BOTH ways and require the same answer. Returns
    /// whether the fast path took it, so the caller can assert that the
    /// combination it meant to exercise actually was (or was not)
    /// eligible - a differential test that silently ran the slow path
    /// twice would prove nothing.
    fn both_ways(
        ix: &mut Index,
        q: &BrowseQuery,
        sort: CardSort,
        matched_only: bool,
        catgroup: bool,
    ) -> bool {
        let fast = ix
            .browse_cards_summary(q, sort, matched_only, catgroup, false)
            .unwrap();
        ix.summaries = false;
        let slow = ix
            .browse_cards_once(q, sort, matched_only, catgroup, None)
            .unwrap();
        ix.summaries = true;
        match fast {
            None => false,
            Some((cards, total)) => {
                assert_eq!(total, slow.1, "total differs: {q:?} {sort:?}");
                let key = |c: &[Card]| {
                    c.iter()
                        .map(|c| {
                            (
                                c.title_key.clone(),
                                c.kind.clone(),
                                c.n_releases,
                                c.latest_posted,
                                c.any_complete,
                                c.max_bytes,
                                c.best_res.clone(),
                                c.rep_stem.clone(),
                                c.rep_grp.clone(),
                                c.title.clone(),
                                c.year,
                            )
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(key(&cards), key(&slow.0), "page differs: {q:?} {sort:?}");
                true
            }
        }
    }

    /// The summary answers the whole ELIGIBLE surface exactly: every
    /// sort, both directions, matched/unmatched, category grouping, the
    /// genre chip, the decade chips, and paging past the end.
    #[test]
    fn summary_page_matches_the_exact_query_across_the_eligible_matrix() {
        let (dir, mut ix) = open_ix("matrix");
        corpus(&mut ix);
        assert_rows_match_recompute(&ix);
        let sorts = [
            CardSort::Latest,
            CardSort::Arrived,
            CardSort::Rating,
            CardSort::Title,
            CardSort::Releases,
            CardSort::Size,
            CardSort::Year,
            CardSort::Aired,
            CardSort::Affinity,
        ];
        let mut served = 0;
        for sort in sorts {
            for desc in [true, false] {
                for matched in [true, false] {
                    for catgroup in [true, false] {
                        for (genre, ymin, ymax, offset) in [
                            (None, 0, 0, 0),
                            (None, 0, 0, 1),
                            (None, 0, 0, 99),
                            (Some("Drama".to_string()), 0, 0, 0),
                            (None, 2010, 2019, 0),
                            (None, 0, 2000, 0),
                        ] {
                            let q = BrowseQuery {
                                genre: genre.clone(),
                                year_min: ymin,
                                year_max: ymax,
                                offset,
                                desc,
                                ..wall_q()
                            };
                            assert!(
                                both_ways(&mut ix, &q, sort, matched, catgroup),
                                "eligible request fell back: {q:?} {sort:?}"
                            );
                            served += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(served, 9 * 2 * 2 * 2 * 6);
        teardown(&dir, ix);
    }

    /// Every request that adds a release-level predicate the summary was
    /// not built under must be REFUSED, not answered approximately. The
    /// list is the whole of `BrowseQuery`'s release-level surface plus
    /// the curation knobs; anything new on that struct that this test
    /// does not cover is a silent correctness hole, which is why the
    /// cases are spelled out rather than derived.
    #[test]
    fn release_level_filters_are_refused_by_the_fast_path() {
        let (dir, mut ix) = open_ix("refuse");
        corpus(&mut ix);
        let cases: Vec<(&str, BrowseQuery)> = vec![
            (
                "kind chip",
                BrowseQuery {
                    kind: Some("tv".into()),
                    ..wall_q()
                },
            ),
            (
                "res chip",
                BrowseQuery {
                    res: Some("1080p".into()),
                    ..wall_q()
                },
            ),
            (
                "complete only",
                BrowseQuery {
                    complete_only: true,
                    ..wall_q()
                },
            ),
            (
                "size floor",
                BrowseQuery {
                    min_bytes: 100,
                    ..wall_q()
                },
            ),
            (
                "newer than",
                BrowseQuery {
                    newer_than: 1_700_000_200,
                    ..wall_q()
                },
            ),
            (
                "search text",
                BrowseQuery {
                    q: "alpha".into(),
                    ..wall_q()
                },
            ),
            (
                "exact key",
                BrowseQuery {
                    title_keys: vec!["t:alpha".into()],
                    ..wall_q()
                },
            ),
            (
                "show hidden",
                BrowseQuery {
                    max_junk: None,
                    ..wall_q()
                },
            ),
            (
                "other junk ceiling",
                BrowseQuery {
                    max_junk: Some(20),
                    ..wall_q()
                },
            ),
            (
                "adult shown",
                BrowseQuery {
                    hide_adult: false,
                    ..wall_q()
                },
            ),
            (
                "uncurated",
                BrowseQuery {
                    curated: false,
                    ..wall_q()
                },
            ),
            (
                "verdict filter",
                BrowseQuery {
                    verdict_ok: Some(VerdictFilter::default()),
                    ..wall_q()
                },
            ),
        ];
        for (what, q) in cases {
            assert!(
                ix.browse_cards_summary(&q, CardSort::Latest, true, false, false)
                    .unwrap()
                    .is_none(),
                "{what} was served from the summary"
            );
            // ...and the wrapper still answers it, from the exact path.
            let (_, total) = ix
                .browse_cards(&q, CardSort::Latest, true, false, None)
                .unwrap();
            let _ = total;
        }
        // A release-level hide rule refuses; a genre rule (which
        // resolves through `titles`) does not.
        ix.db
            .execute(
                "INSERT INTO wall_rules(field, value, added) VALUES('group','alt.binaries.g1',1)",
                [],
            )
            .unwrap();
        assert!(
            ix.browse_cards_summary(&wall_q(), CardSort::Latest, true, false, false)
                .unwrap()
                .is_none(),
            "a group hide rule was served from the summary"
        );
        ix.db.execute("DELETE FROM wall_rules", []).unwrap();
        ix.db
            .execute(
                "INSERT INTO wall_rules(field, value, added) VALUES('genre','Comedy',1)",
                [],
            )
            .unwrap();
        assert!(
            both_ways(&mut ix, &wall_q(), CardSort::Latest, true, false),
            "a genre hide rule should be answerable from the summary"
        );
        teardown(&dir, ix);
    }

    /// Prune, fold, rekey and eviction as touched-key events: after each
    /// one the drain must land the summary back on what a full scan
    /// says, and the wall must still answer identically.
    #[test]
    fn every_writer_shape_heals_through_the_dirty_set() {
        let (dir, mut ix) = open_ix("mutate");
        corpus(&mut ix);
        // (what, the statement a writer would run)
        let steps: [(&str, &str); 10] = [
            // Delete the sitting representative: the MAX and the rep
            // both have to fall back to the runner-up.
            (
                "prune the representative",
                "DELETE FROM releases WHERE id=2",
            ),
            // Rekey a whole group (titles.rs' merge).
            (
                "rekey a group",
                "UPDATE releases SET title_key='t:alpha2' WHERE title_key='t:alpha'",
            ),
            // Junk-score a release past the ceiling: it leaves the
            // population without being deleted.
            ("junk a release", "UPDATE releases SET junk=90 WHERE id=5"),
            // ...and back under it.
            ("un-junk a release", "UPDATE releases SET junk=0 WHERE id=5"),
            // The spot-born adult marker (spots.rs).
            ("mark adult", "UPDATE releases SET adult=1 WHERE id=7"),
            ("unmark adult", "UPDATE releases SET adult=0 WHERE id=7"),
            // A fed name landing on the representative (predb.rs).
            (
                "name the representative",
                "UPDATE releases SET pre_title='Fed.Name.Beta' WHERE id=6",
            ),
            // A maxed column moving DOWN in place - the shape the fold
            // cannot absorb and the recompute must.
            (
                "shrink the biggest",
                "UPDATE releases SET total_bytes=1 WHERE id=6",
            ),
            // The last qualifying release of a key: the row must GO.
            (
                "empty a key",
                "DELETE FROM releases WHERE title_key='m:gamma:2019'",
            ),
            // An unbounded bulk delete (maintenance.rs' size prune).
            ("bulk prune", "DELETE FROM releases WHERE total_bytes < 400"),
        ];
        for (what, stmt) in steps {
            ix.db.execute(stmt, []).unwrap();
            // Before the drain the read path must REFUSE - that is the
            // whole safety property.
            assert!(
                ix.browse_cards_summary(&wall_q(), CardSort::Latest, true, false, false)
                    .unwrap()
                    .is_none(),
                "{what}: served a summary with keys still dirty"
            );
            assert!(
                ix.drain_title_dirty(10_000).unwrap() > 0,
                "{what}: nothing dirty"
            );
            assert_rows_match_recompute(&ix);
            for sort in [CardSort::Latest, CardSort::Releases, CardSort::Size] {
                assert!(
                    both_ways(&mut ix, &wall_q(), sort, false, false),
                    "{what}: fell back after healing"
                );
            }
        }
        teardown(&dir, ix);
    }

    /// A drain cut short by its budget leaves the rest owed, and the
    /// wall keeps refusing until the last key is retired. The budget is
    /// a latency bound, never a correctness one.
    #[test]
    fn a_budgeted_drain_leaves_the_rest_owed() {
        let (dir, mut ix) = open_ix("budget");
        corpus(&mut ix);
        ix.db
            .execute("UPDATE releases SET first_seen = first_seen + 1", [])
            .unwrap();
        let dirty = |ix: &Index| -> i64 {
            ix.db
                .query_row("SELECT COUNT(*) FROM title_dirty", [], |r| r.get(0))
                .unwrap()
        };
        assert!(dirty(&ix) > 2);
        assert_eq!(ix.drain_title_dirty(1).unwrap(), 1);
        assert!(!ix.summaries_fresh(), "a partial drain must not read fresh");
        while ix.drain_title_dirty(1).unwrap() > 0 {}
        assert_eq!(dirty(&ix), 0);
        assert!(ix.summaries_fresh());
        assert_rows_match_recompute(&ix);
        teardown(&dir, ix);
    }

    /// The bookkeeping columns no summary reads must not dirty a key -
    /// otherwise the oracle sampler, the gapfill stamper and the probe
    /// pass would each cost a wall recompute per release they touch.
    #[test]
    fn bookkeeping_writes_do_not_dirty_a_title() {
        let (dir, mut ix) = open_ix("quiet");
        corpus(&mut ix);
        for stmt in [
            "UPDATE releases SET oracle_at=1 WHERE id=1",
            "UPDATE releases SET gapfill_at=1 WHERE id=1",
            "UPDATE releases SET probe_at=1, probe_tries=2 WHERE id=1",
            "UPDATE releases SET enc_class=1, enc_kind='rar5' WHERE id=1",
            "UPDATE releases SET pre_at=1, pre_source='spot' WHERE id=1",
            "UPDATE releases SET have_parts=9, need_parts=9 WHERE id=1",
        ] {
            ix.db.execute(stmt, []).unwrap();
            assert!(ix.summaries_fresh(), "{stmt} dirtied a title");
        }
        // ...and an insert that could never be visible is equally free.
        put(
            &ix,
            (
                99,
                "t:alpha",
                "tv",
                1_700_001_000,
                10,
                "",
                false,
                99,
                false,
                "",
            ),
        );
        put(
            &ix,
            (
                98,
                "t:alpha",
                "tv",
                1_700_001_000,
                10,
                "",
                false,
                0,
                true,
                "",
            ),
        );
        assert!(ix.summaries_fresh(), "an invisible arrival dirtied a title");
        teardown(&dir, ix);
    }

    /// The Rust rank and its SQL twin must agree on every spelling the
    /// index stores, or the card's badge and the sort disagree.
    #[test]
    fn res_rank_agrees_with_its_sql_twin() {
        let db = Connection::open_in_memory().unwrap();
        for res in ["2160p", "1080p", "720p", "", "480p", "SD", "2160P"] {
            let sql: i64 = db
                .query_row(
                    &format!("SELECT {}", at(RES_RANK, "").replace("res", "?1")),
                    [res],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(res_rank(res), sql, "rank twin split on {res:?}");
        }
    }

    /// The fold tracks `recompute` through the shapes it accepts, and
    /// REFUSES the ones it cannot: a maximum moving down, and a release
    /// leaving the population.
    #[test]
    fn apply_release_tracks_recompute_and_refuses_what_it_cannot_fold() {
        let (dir, mut ix) = open_ix("fold");
        put(
            &ix,
            (
                1,
                "t:f",
                "tv",
                1_700_000_100,
                500,
                "1080p",
                false,
                0,
                false,
                "",
            ),
        );
        ix.drain_title_dirty(10).unwrap();
        let mut agg = TitleSummary::recompute(&ix.db, "t:f").unwrap().unwrap();
        // A newer, bigger, better release joins.
        put(
            &ix,
            (
                2,
                "t:f",
                "tv",
                1_700_000_200,
                900,
                "2160p",
                true,
                0,
                false,
                "Fed.Name",
            ),
        );
        assert!(agg.apply_release(
            None,
            &RelFacts {
                id: 2,
                first_posted: 1_700_000_200,
                first_seen: 1_700_000_260,
                complete: true,
                total_bytes: 900,
                res_rank: res_rank("2160p"),
                kind: "tv".into(),
                name: "Fed.Name".into(),
                grp: "alt.binaries.g2".into(),
            }
        ));
        ix.drain_title_dirty(10).unwrap();
        assert_eq!(
            Some(agg.clone()),
            TitleSummary::recompute(&ix.db, "t:f").unwrap()
        );
        // The same release grows in place: still foldable.
        ix.db
            .execute("UPDATE releases SET total_bytes=1500 WHERE id=2", [])
            .unwrap();
        let old = RelFacts {
            id: 2,
            first_posted: 1_700_000_200,
            first_seen: 1_700_000_260,
            complete: true,
            total_bytes: 900,
            res_rank: res_rank("2160p"),
            kind: "tv".into(),
            name: "Fed.Name".into(),
            grp: "alt.binaries.g2".into(),
        };
        let new = RelFacts {
            total_bytes: 1500,
            ..old.clone()
        };
        assert!(agg.apply_release(Some(&old), &new));
        ix.drain_title_dirty(10).unwrap();
        assert_eq!(
            Some(agg.clone()),
            TitleSummary::recompute(&ix.db, "t:f").unwrap()
        );
        // Shrinking is refused, and refusing changes nothing.
        let before = agg.clone();
        let smaller = RelFacts {
            total_bytes: 4,
            ..new.clone()
        };
        assert!(!agg.apply_release(Some(&new), &smaller));
        assert_eq!(agg, before, "a refused fold must leave the row untouched");
        teardown(&dir, ix);
    }

    /// C3's write-side number: what the triggers plus the per-batch
    /// drain cost an ingest, against the same stream with the summaries
    /// uninstalled. Headers/sec and WAL bytes are the two figures the
    /// go/no-go turns on, so they are measured on the same corpus in
    /// the same process, arms alternating and repeated.
    ///
    /// Three arms, because the two halves of the cost are separable and
    /// only one of them is negotiable: `off` is the control, `dirty`
    /// installs the triggers and never drains (so it prices the
    /// trigger alone), and `on` is the shipping shape.
    ///
    /// `SKEW` is the second axis. A recompute costs one indexed walk of
    /// the title's releases, so a catalogue of small titles pays almost
    /// nothing and a catalogue with a few enormous ones - a long-running
    /// show, whose key is `t:<show>` with every episode of every season
    /// under it - pays that walk per batch that touches it.
    ///
    /// `cargo test --release -p nzbkit --lib summaries::tests::ingest_cost \
    ///  -- --ignored --nocapture`
    #[test]
    #[ignore = "measurement rig, run by hand"]
    fn ingest_cost_of_maintaining_the_summaries() {
        for skew in [false, true] {
            for round in 0..2 {
                for (tag, install, drain) in [
                    ("off      ", false, false),
                    ("dirty    ", true, false),
                    ("on       ", true, true),
                ] {
                    let all = cost_corpus(skew);
                    let wave = all.len() / COST_PARTS;
                    let dir = std::env::temp_dir().join(format!(
                        "nzbfast-c3-cost-{}-{round}-{}",
                        tag.trim(),
                        std::process::id()
                    ));
                    let _ = std::fs::remove_dir_all(&dir);
                    std::fs::create_dir_all(&dir).unwrap();
                    let mut ix = Index::open(&dir.join("index.db")).unwrap();
                    if install {
                        ix.rebuild_title_summaries().unwrap();
                        ix.summaries = drain;
                        // `summaries` gates the drain inside ingest; the
                        // triggers are schema and fire regardless, which
                        // is exactly the split this arm wants.
                    }
                    // WAL must only grow for the duration, or its length
                    // stops being "bytes written".
                    ix.db.execute_batch("PRAGMA wal_autocheckpoint=0;").unwrap();
                    let _ = ix
                        .db
                        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_r| Ok(()));
                    let t0 = std::time::Instant::now();
                    for c in all.chunks(wave) {
                        ix.ingest("alt.binaries.test", c, 1_700_000_100).unwrap();
                    }
                    let took = t0.elapsed();
                    let wal = std::fs::metadata(dir.join("index.db-wal"))
                        .map(|m| m.len())
                        .unwrap_or(0);
                    let dirty: i64 = ix
                        .db
                        .query_row("SELECT COUNT(*) FROM title_dirty", [], |r| r.get(0))
                        .unwrap_or(-1);
                    println!(
                        "skew={skew:<5} round={round} [{tag}] {} headers: {:>7.0} headers/s, \
                         WAL {:>5.1} MB, dirty left {dirty}",
                        all.len(),
                        all.len() as f64 / took.as_secs_f64(),
                        wal as f64 / 1e6,
                    );
                    if install && drain {
                        assert_rows_match_recompute(&ix);
                    }
                    teardown(&dir, ix);
                }
            }
        }
    }

    const COST_PARTS: usize = 6;

    /// A scan-shaped article stream. `skew` moves the same number of
    /// clusters onto a tenth as many titles, so each recompute walks ten
    /// times the rows - the long-running-show shape.
    fn cost_corpus(skew: bool) -> Vec<OverEntry> {
        let (titles, per_title) = if skew { (80, 40) } else { (800, 4) };
        let mut all: Vec<OverEntry> = Vec::new();
        for p in 1..=COST_PARTS {
            for t in 0..titles {
                for c in 0..per_title {
                    all.push(OverEntry {
                        number: 0,
                        subject: format!(
                            "\"Synthetic.Show.{t}.S{:02}E{:02}.1080p.WEB-DL.x264-GRP.part01.rar\" \
                             yEnc ({p}/{COST_PARTS})",
                            c / 20 + 1,
                            c % 20 + 1
                        ),
                        from: format!("poster{c}@example"),
                        message_id: format!("<seg-{t}-{c}-{p}@news>"),
                        bytes: 4_000_000,
                        date: 1_700_000_000 + (t * 60) as i64,
                    });
                }
            }
        }
        all
    }

    /// Installing over an existing catalogue must SEED, not just create.
    /// An empty summary beside an empty dirty set reads as "fresh, and
    /// this catalogue has no cards" - the one failure mode the read
    /// path cannot detect, and the reason `ensure_schema` looks for the
    /// table before creating it rather than leaning on IF NOT EXISTS.
    #[test]
    fn installing_over_an_existing_catalogue_seeds_it() {
        let dir = std::env::temp_dir().join(format!("nzbfast-c3-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(
            !ix.summaries,
            "a fresh index must not have the prototype on"
        );
        // Releases first, install second - the upgrade order.
        put(
            &ix,
            (
                1,
                "t:seeded",
                "tv",
                1_700_000_100,
                500,
                "1080p",
                true,
                0,
                false,
                "",
            ),
        );
        put(
            &ix,
            (
                2,
                "t:seeded",
                "tv",
                1_700_000_200,
                900,
                "2160p",
                true,
                0,
                false,
                "",
            ),
        );
        put_title(&ix, "t:seeded", "tv", "Drama", 2011, true);
        ensure_schema(&ix.db).unwrap();
        ix.summaries = true;
        assert!(ix.summaries_fresh());
        assert_rows_match_recompute(&ix);
        let (cards, total) = ix
            .browse_cards_summary(&wall_q(), CardSort::Latest, true, false, false)
            .unwrap()
            .expect("an installed summary must serve the default wall");
        assert_eq!((cards.len(), total), (1, 1), "the install did not seed");
        assert_eq!(cards[0].n_releases, 2);
        // A second call is a no-op, not a re-seed that could race a
        // writer: it must neither wipe rows nor dirty anything.
        ensure_schema(&ix.db).unwrap();
        assert!(ix.summaries_fresh());
        assert_rows_match_recompute(&ix);
        // ...and uninstalling leaves nothing behind for the next open
        // to detect.
        drop_schema(&ix.db).unwrap();
        for t in ["title_summaries", "title_dirty"] {
            assert!(
                ix.db
                    .query_row("SELECT 1 FROM sqlite_master WHERE name=?1", [t], |_| Ok(()))
                    .is_err(),
                "{t} survived the uninstall"
            );
        }
        // The triggers must go too, or the next write fails on a
        // missing title_dirty.
        put(
            &ix,
            (
                3,
                "t:seeded",
                "tv",
                1_700_000_300,
                100,
                "720p",
                true,
                0,
                false,
                "",
            ),
        );
        teardown(&dir, ix);
    }

    /// An install that dies part-way must leave NOTHING behind. The
    /// tables and the seed are one transaction, so a failed seed rolls
    /// the tables back and the next call is a fresh install again -
    /// where autocommit would leave an installed, empty summary beside
    /// an empty dirty set, which reads as "this catalogue has no cards"
    /// forever.
    ///
    /// The fault is injected by putting a VIEW where `title_dirty`
    /// goes: `CREATE TABLE IF NOT EXISTS` steps over it silently and
    /// the seed's own `DELETE FROM title_dirty` is what fails.
    #[test]
    fn a_failed_install_leaves_no_tables_behind() {
        let dir = std::env::temp_dir().join(format!("nzbfast-c3-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        put(
            &ix,
            (
                1,
                "t:atomic",
                "tv",
                1_700_000_100,
                500,
                "1080p",
                true,
                0,
                false,
                "",
            ),
        );
        ix.db
            .execute_batch("CREATE VIEW title_dirty AS SELECT title_key FROM releases WHERE 0;")
            .unwrap();
        assert!(
            ensure_schema(&ix.db).is_err(),
            "the injected fault did not fail the install"
        );
        assert!(
            ix.db
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='title_summaries'",
                    [],
                    |_| Ok(())
                )
                .is_err(),
            "an installed, empty summary survived a failed seed"
        );
        // With the fault removed the next call is a fresh install
        // again, and it seeds.
        ix.db.execute_batch("DROP VIEW title_dirty;").unwrap();
        ensure_schema(&ix.db).unwrap();
        assert_eq!(
            ix.db
                .query_row("SELECT COUNT(*) FROM title_summaries", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1,
            "the retry did not seed"
        );
        teardown(&dir, ix);
    }

    /// Flat browse is grouped by STEM, not by title, so a per-title
    /// summary cannot answer it. Recorded as a test so the next reader
    /// does not try: `browse` has no fast path and must not grow one
    /// from this table.
    #[test]
    fn flat_browse_is_untouched_by_the_summary() {
        let (dir, mut ix) = open_ix("browse");
        corpus(&mut ix);
        let q = BrowseQuery {
            sort: BrowseSort::Posted,
            ..wall_q()
        };
        let (with, n_with) = ix.browse(&q).unwrap();
        ix.summaries = false;
        let (without, n_without) = ix.browse(&q).unwrap();
        assert_eq!(n_with, n_without);
        assert_eq!(
            with.iter().map(|r| r.id).collect::<Vec<_>>(),
            without.iter().map(|r| r.id).collect::<Vec<_>>()
        );
        teardown(&dir, ix);
    }

    /// Paging over cards that TIE on the sort key returns each card
    /// exactly once - no repeat between pages, and nothing skipped.
    ///
    /// Both paths, because both had the same defect until 25 Aug 2026
    /// and fixing one alone would have made them disagree here: the
    /// outer ORDER BY ended `{key} {dir}, latest DESC`, and under the
    /// wall's default `CardSort::Latest` the key IS `latest`, so a row
    /// of cards sharing a `first_posted` second had no defined order
    /// between them. SQLite is entitled to settle that differently for
    /// the `OFFSET 0` statement and the `OFFSET 1` one, and the pages
    /// are separate HTTP requests, so "entitled to" is the whole risk.
    ///
    /// **This is a guard on the property, not a reproduction of a live
    /// bug, and the difference is worth stating rather than implying.**
    /// Measured 25 Aug 2026: the pre-fix ORDER BY passes this test too,
    /// on both paths, exactly as the handoff that reported the wart said
    /// it would ("stable in practice today"). What the tiebreak buys is
    /// that the order is now total by CONSTRUCTION instead of by
    /// observation - and the thing being observed is a planner's freedom
    /// to settle a tie differently for two statements it is under no
    /// obligation to settle the same way. So the fixture is built to
    /// make a regression decidable rather than to catch today's SQLite
    /// out: every card ties with every other on `latest`, so once the
    /// tiebreak goes the ONLY thing between this test and a duplicate is
    /// a choice nothing in the SQL constrains.
    #[test]
    fn paging_over_tied_cards_repeats_nothing_and_skips_nothing() {
        let (dir, mut ix) = open_ix("tiedpaging");
        // Eight titles, one release each, all posted in the SAME second.
        const TIED_AT: i64 = 1_700_000_000;
        const N: u32 = 8;
        for i in 0..N as i64 {
            let key: &'static str = [
                "t:tie-a", "t:tie-b", "t:tie-c", "t:tie-d", "t:tie-e", "t:tie-f", "t:tie-g",
                "t:tie-h",
            ][i as usize];
            put(
                &ix,
                (
                    i + 1,
                    key,
                    "tv",
                    TIED_AT,
                    100 + i,
                    "1080p",
                    true,
                    0,
                    false,
                    "",
                ),
            );
            put_title(&ix, key, "tv", "Drama", 2011, true);
        }
        ix.drain_title_dirty(1_000).unwrap();
        assert_rows_match_recompute(&ix);

        let mut seen: Vec<String> = Vec::new();
        for offset in 0..N {
            let q = BrowseQuery {
                limit: 1,
                offset,
                ..wall_q()
            };
            // Asserts the two paths agree on this page, and that the
            // fast path was the one that answered it - a differential
            // that quietly ran the slow query twice would prove nothing
            // about the summary's ORDER BY.
            assert!(
                both_ways(&mut ix, &q, CardSort::Latest, true, false),
                "page {offset} must be summary-eligible"
            );
            let (cards, total) = ix
                .browse_cards_once(&q, CardSort::Latest, true, false, None)
                .unwrap();
            assert_eq!(total, N as u64, "every tied card counts, page {offset}");
            assert_eq!(cards.len(), 1, "one card per page, page {offset}");
            seen.push(cards[0].title_key.clone());
        }

        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            seen.len(),
            "a card was served on two different pages: {seen:?}"
        );
        assert_eq!(
            sorted.len(),
            N as usize,
            "paging reached every tied card exactly once: {seen:?}"
        );
        teardown(&dir, ix);
    }
}
