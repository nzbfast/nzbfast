//! Search-miss log (TODO 131 workstream D, item D3): what this index
//! was asked for, and how much of it we could answer. Design note:
//! `research/DESIGN-D3-search-log-2026-08-11.md`.
//!
//! The point of the readout is that misses tell the scanner what to
//! deepen or backfill next. The parity scoreboard asks a reference
//! indexer what EXISTS; this asks the user what they WANTED, which is
//! a different question and names titles rather than categories.
//! Nothing here acts on its own findings - a miss is evidence, and
//! §131 puts a human on the other end of it.
//!
//! Everything in this module is local-only by construction. See the
//! privacy paragraph on the `search_log` table in schema.rs: the rows
//! are never enriched, never exported, and never aggregated across
//! installs.

use super::*;

/// One aggregated bucket on its way into the table. The daemon merges
/// searches in memory first (see `Daemon::note_search`) so the query
/// path never touches SQLite; this is what a flush hands over.
#[derive(Debug, Clone, Default)]
pub struct SearchRecord {
    /// `wall` or `newznab`.
    pub surface: String,
    /// Normalized query - see [`norm_query`].
    pub q: String,
    /// Kind filter in force, `""` when none.
    pub kind: String,
    /// Searches merged into this bucket.
    pub n: u32,
    /// How many of them came back with nothing at all.
    pub zero_n: u32,
    /// Hits the LAST of them returned.
    pub last_hits: u32,
    /// The most any of them returned.
    pub best_hits: u32,
    /// When the last of them ran.
    pub at: i64,
}

/// One row of the top-misses readout.
#[derive(Debug, Clone)]
pub struct SearchMiss {
    /// `wall` or `newznab` - which surface the searches came from.
    pub surface: String,
    /// The normalized query, as [`SearchRecord::q`] holds it.
    pub q: String,
    /// Kind filter in force, `""` when none.
    pub kind: String,
    /// Searches for this query in the window, summed over buckets.
    pub n: u64,
    /// How many of them returned nothing. `zero_n == n` is the case
    /// this readout exists to surface: something people look for and
    /// the index has never held.
    pub zero_n: u64,
    /// When the first of them ran, unix time.
    pub first_at: i64,
    /// When the last of them ran, unix time. Read with
    /// [`Self::first_at`]: a miss that stopped weeks ago is not the
    /// same problem as one still being asked today.
    pub last_at: i64,
    /// Hits the most recent of them returned.
    pub last_hits: u64,
    /// The most any of them returned. Non-zero here with a zero
    /// `last_hits` means coverage was LOST, not that it never existed.
    pub best_hits: u64,
}

/// The one-line answer to "is search the problem at all".
#[derive(Debug, Clone, Default)]
pub struct SearchLogSummary {
    /// Searches recorded in the window.
    pub searches: u64,
    /// Distinct (surface, query, kind) buckets behind them.
    pub distinct: u64,
    /// Searches that came back with nothing.
    pub zero_searches: u64,
    /// Distinct queries whose LAST answer was at or under the bar.
    pub missing: u64,
    /// Distinct queries that once answered zero and now answer above
    /// the bar - holes the scanner has since filled.
    pub resolved: u64,
}

/// The normalization the log stores queries under: lowercase, the
/// three release-name separators folded to spaces, whitespace runs
/// collapsed. Deliberately the same shape `Index::search` applies
/// before matching, so the readout shows what the matcher saw rather
/// than what the keyboard produced - a miss is only actionable if the
/// string in front of you is the string that failed.
pub fn norm_query(q: &str) -> String {
    q.to_lowercase()
        .replace(['.', '_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

impl Index {
    /// Fold a flush batch into the table. One transaction, upsert per
    /// bucket; safe to call with an empty batch.
    ///
    /// Counters ADD (the caller's batch is itself an aggregate over one
    /// flush window), `first_at` never moves, and `last_hits` only
    /// takes the incoming value when the incoming record is the newer
    /// one - a flush that arrives out of order must not rewrite the
    /// current truth with a stale answer.
    pub fn search_log_record(&mut self, batch: &[SearchRecord]) -> rusqlite::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        let tx = self.db.transaction()?;
        let mut stored = 0usize;
        for r in batch {
            if r.q.trim().is_empty() || r.n == 0 {
                continue;
            }
            stored += tx
                .prepare_cached(
                    "INSERT INTO search_log(
                        surface, q, kind, n, zero_n, first_at, last_at,
                        last_hits, best_hits)
                     VALUES(?1,?2,?3,?4,?5,?6,?6,?7,?8)
                     ON CONFLICT(surface, q, kind) DO UPDATE SET
                       n = search_log.n + excluded.n,
                       zero_n = search_log.zero_n + excluded.zero_n,
                       last_at = MAX(search_log.last_at, excluded.last_at),
                       last_hits = CASE
                         WHEN excluded.last_at >= search_log.last_at
                         THEN excluded.last_hits ELSE search_log.last_hits END,
                       best_hits = MAX(search_log.best_hits, excluded.best_hits)",
                )?
                .execute(rusqlite::params![
                    r.surface,
                    r.q,
                    r.kind,
                    r.n as i64,
                    r.zero_n as i64,
                    r.at,
                    r.last_hits as i64,
                    r.best_hits as i64,
                ])?;
        }
        tx.commit()?;
        Ok(stored)
    }

    /// Top missed queries over a rolling window, worst first.
    ///
    /// A "miss" is a query whose LAST answer was at or under `thin`
    /// (`thin = 0` is only the true zeroes). Last, not ever: a query
    /// that missed all week and now returns rows is a hole the scanner
    /// filled, and leaving it at the top of this list on the strength
    /// of its history would send the next backfill after work already
    /// done.
    ///
    /// Ordered by how often it came back empty, then by how often it
    /// was asked - the thing asked most and answered least is what a
    /// human should look at first.
    pub fn search_misses(
        &self,
        since: i64,
        thin: u32,
        surface: Option<&str>,
        limit: u32,
    ) -> rusqlite::Result<Vec<SearchMiss>> {
        let filter = if surface.is_some() {
            "AND surface=?4"
        } else {
            ""
        };
        let mut stmt = self.db.prepare(&format!(
            "SELECT surface, q, kind, n, zero_n, first_at, last_at,
                    last_hits, best_hits
               FROM search_log
              WHERE last_at>=?1 AND last_hits<=?2 {filter}
              ORDER BY zero_n DESC, n DESC, last_at DESC
              LIMIT ?3"
        ))?;
        let row = |r: &rusqlite::Row<'_>| {
            Ok(SearchMiss {
                surface: r.get(0)?,
                q: r.get(1)?,
                kind: r.get(2)?,
                n: r.get::<_, i64>(3)?.max(0) as u64,
                zero_n: r.get::<_, i64>(4)?.max(0) as u64,
                first_at: r.get(5)?,
                last_at: r.get(6)?,
                last_hits: r.get::<_, i64>(7)?.max(0) as u64,
                best_hits: r.get::<_, i64>(8)?.max(0) as u64,
            })
        };
        match surface {
            Some(s) => stmt
                .query_map(rusqlite::params![since, thin as i64, limit as i64, s], row)?
                .collect(),
            None => stmt
                .query_map(rusqlite::params![since, thin as i64, limit as i64], row)?
                .collect(),
        }
    }

    /// Window totals behind [`Self::search_misses`]. One pass, all five
    /// figures - the table is thousands of rows, so aggregating in SQL
    /// beats shipping them out.
    pub fn search_log_summary(&self, since: i64, thin: u32) -> rusqlite::Result<SearchLogSummary> {
        self.db.query_row(
            "SELECT COALESCE(SUM(n),0), COUNT(*), COALESCE(SUM(zero_n),0),
                    COALESCE(SUM(last_hits<=?2),0),
                    COALESCE(SUM(zero_n>0 AND last_hits>?2),0)
               FROM search_log WHERE last_at>=?1",
            rusqlite::params![since, thin as i64],
            |r| {
                Ok(SearchLogSummary {
                    searches: r.get::<_, i64>(0)?.max(0) as u64,
                    distinct: r.get::<_, i64>(1)?.max(0) as u64,
                    zero_searches: r.get::<_, i64>(2)?.max(0) as u64,
                    missing: r.get::<_, i64>(3)?.max(0) as u64,
                    resolved: r.get::<_, i64>(4)?.max(0) as u64,
                })
            },
        )
    }

    /// Both retention caps, run together from the hourly maintenance
    /// pass. Returns rows removed.
    ///
    /// Age alone does not bound this table: a Radarr pointed at a
    /// 10,000-film library asks 10,000 distinct questions, and that is
    /// a normal setup rather than an attack. The row cap keeps the
    /// least-recently-asked ones, since a query nobody has repeated is
    /// the one least worth backfilling for.
    pub fn search_log_prune(
        &self,
        max_age_secs: i64,
        max_rows: u32,
        now: i64,
    ) -> rusqlite::Result<usize> {
        let mut gone = 0usize;
        if max_age_secs > 0 {
            gone += self.db.execute(
                "DELETE FROM search_log WHERE last_at < ?1",
                [now.saturating_sub(max_age_secs)],
            )?;
        }
        if max_rows > 0 {
            // LIMIT -1 OFFSET n = "everything past the newest n".
            gone += self.db.execute(
                "DELETE FROM search_log WHERE id IN (
                   SELECT id FROM search_log
                    ORDER BY last_at DESC, id DESC
                    LIMIT -1 OFFSET ?1)",
                [max_rows as i64],
            )?;
        }
        Ok(gone)
    }

    /// Forget everything. Behind the privacy switch and the explicit
    /// clear action - turning recording off leaves nothing behind,
    /// because a privacy switch that keeps the history is not one.
    pub fn search_log_clear(&self) -> rusqlite::Result<usize> {
        self.db.execute("DELETE FROM search_log", [])
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::teardown;
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-searchlog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rec(
        surface: &str,
        q: &str,
        n: u32,
        zero_n: u32,
        last: u32,
        best: u32,
        at: i64,
    ) -> SearchRecord {
        SearchRecord {
            surface: surface.into(),
            q: q.into(),
            kind: String::new(),
            n,
            zero_n,
            last_hits: last,
            best_hits: best,
            at,
        }
    }

    /// The stored form is what the matcher sees, not what the keyboard
    /// produced: a miss you cannot read is a miss you cannot fix.
    #[test]
    fn queries_are_stored_the_way_the_matcher_reads_them() {
        assert_eq!(norm_query("Kill.Bill_Vol-1  "), "kill bill vol 1");
        assert_eq!(norm_query("  THE   Wire  "), "the wire");
        assert_eq!(norm_query(""), "");
    }

    /// Counters accumulate across flushes, `first_at` is the first time
    /// anyone asked, and `last_hits` is the CURRENT answer while
    /// `best_hits` remembers whether we ever had one.
    #[test]
    fn buckets_accumulate_and_last_hits_is_the_current_truth() {
        let d = dir("acc");
        let mut ix = Index::open(&d.join("index.db")).unwrap();

        ix.search_log_record(&[rec("wall", "kill bill", 3, 3, 0, 0, 1_000)])
            .unwrap();
        ix.search_log_record(&[rec("wall", "kill bill", 2, 1, 5, 5, 2_000)])
            .unwrap();

        let rows = ix.search_misses(0, 0, None, 10).unwrap();
        // last_hits is 5 now, so at thin=0 it is no longer a miss.
        assert!(rows.is_empty(), "resolved query still listed: {rows:?}");

        let rows = ix.search_misses(0, 99, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].n, 5);
        assert_eq!(rows[0].zero_n, 4);
        assert_eq!(rows[0].first_at, 1_000);
        assert_eq!(rows[0].last_at, 2_000);
        assert_eq!(rows[0].last_hits, 5);
        assert_eq!(rows[0].best_hits, 5);

        // A stale flush arriving late must not rewrite the answer.
        ix.search_log_record(&[rec("wall", "kill bill", 1, 1, 0, 0, 1_500)])
            .unwrap();
        let rows = ix.search_misses(0, 99, None, 10).unwrap();
        assert_eq!(
            rows[0].last_hits, 5,
            "an out-of-order flush overwrote the truth"
        );
        assert_eq!(rows[0].last_at, 2_000);
        assert_eq!(rows[0].n, 6);

        teardown(&d, ix);
    }

    /// The readout ranks by how often we answered nothing, keeps the
    /// surfaces apart, and counts the holes the scanner has since
    /// filled separately from the ones still open.
    #[test]
    fn top_misses_rank_by_emptiness_and_separate_the_resolved() {
        let d = dir("rank");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.search_log_record(&[
            // Asked a lot, never answered - the top of the list.
            rec("newznab", "the expanse s06", 40, 40, 0, 0, 5_000),
            // Asked less, never answered.
            rec("wall", "dune part three", 4, 4, 0, 0, 5_000),
            // Asked a lot, thin but non-zero answers.
            rec("wall", "obscure doco", 30, 0, 2, 2, 5_000),
            // Was a hole, now filled.
            rec("wall", "kill bill", 9, 6, 40, 40, 5_000),
        ])
        .unwrap();

        let rows = ix.search_misses(0, 0, None, 10).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.q.as_str()).collect::<Vec<_>>(),
            ["the expanse s06", "dune part three"]
        );

        // thin=2 brings in the query that only ever returns a couple of
        // rows, still ranked under the true zeroes.
        let rows = ix.search_misses(0, 2, None, 10).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.q.as_str()).collect::<Vec<_>>(),
            ["the expanse s06", "dune part three", "obscure doco"]
        );

        // Surface filter: an *arr's miss is a different problem.
        let rows = ix.search_misses(0, 0, Some("newznab"), 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].q, "the expanse s06");

        let s = ix.search_log_summary(0, 0).unwrap();
        assert_eq!(s.searches, 83);
        assert_eq!(s.distinct, 4);
        assert_eq!(s.zero_searches, 50);
        assert_eq!(s.missing, 2);
        // `resolved` is only for holes that were REAL holes: "obscure
        // doco" is thin but has never once come back empty, so it was
        // never a hole to fill and does not count as one filled.
        assert_eq!(s.resolved, 1, "kill bill was a hole, and is not one now");

        // The window is on last_at, so a stale bucket falls out.
        assert!(ix.search_misses(6_000, 0, None, 10).unwrap().is_empty());

        teardown(&d, ix);
    }

    /// Both caps. Age drops what nobody has asked about lately; the row
    /// cap is what actually bounds a client that invents a new query
    /// per title, and it keeps the most recently asked.
    #[test]
    fn retention_caps_bound_the_table_by_age_and_by_rows() {
        let d = dir("prune");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let now = 1_000_000i64;
        let batch: Vec<SearchRecord> = (0..10)
            .map(|i| rec("wall", &format!("q{i}"), 1, 1, 0, 0, now - i * 86_400))
            .collect();
        ix.search_log_record(&batch).unwrap();

        // Age: a 5-day window keeps q0..q5 - the cutoff is `last_at <
        // now - max_age`, so the bucket sitting exactly on it stays.
        assert_eq!(ix.search_log_prune(5 * 86_400, 0, now).unwrap(), 4);
        let left = ix.search_misses(0, 0, None, 50).unwrap();
        assert_eq!(left.len(), 6);

        // Rows: keep the 2 most recently asked.
        assert_eq!(ix.search_log_prune(0, 2, now).unwrap(), 4);
        let left = ix.search_misses(0, 0, None, 50).unwrap();
        assert_eq!(
            left.iter().map(|r| r.q.as_str()).collect::<Vec<_>>(),
            ["q0", "q1"]
        );

        // And the privacy clear leaves nothing behind.
        assert_eq!(ix.search_log_clear().unwrap(), 2);
        assert!(ix.search_misses(0, 0, None, 50).unwrap().is_empty());
        let s = ix.search_log_summary(0, 0).unwrap();
        assert_eq!(s.searches, 0);
        assert_eq!(s.distinct, 0);

        teardown(&d, ix);
    }

    /// The same query under two kind filters is two different holes: a
    /// movie search that misses says nothing about the TV half.
    #[test]
    fn the_kind_filter_is_part_of_the_identity() {
        let d = dir("kind");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let mut movie = rec("newznab", "the thing", 3, 3, 0, 0, 100);
        movie.kind = "movie".into();
        let mut tv = rec("newznab", "the thing", 1, 0, 7, 7, 100);
        tv.kind = "tv".into();
        ix.search_log_record(&[movie, tv]).unwrap();

        let rows = ix.search_misses(0, 0, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "movie");
        assert_eq!(ix.search_log_summary(0, 0).unwrap().distinct, 2);

        teardown(&d, ix);
    }
}
