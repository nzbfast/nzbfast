//! `SQLITE_SCHEMA` on a pooled reader: retry once, and make a failure
//! that survives the retry TELLABLE from "no rows".
//!
//! The failure this exists for is documented on the
//! `repeat_opens_do_not_churn_the_schema` test in [`super::schema`] (a
//! `cfg(test)` module, so nothing rendered links to it). A writer that
//! changes the schema invalidates every pooled read-only connection's
//! prepared statements. SQLite's `prepare_v2` re-prepares transparently,
//! so an ordinary statement never surfaces the change at all - but
//! re-preparing a statement that names an fts5 table calls that vtable's
//! constructor, and a constructor that loses the race fails the whole
//! statement outright:
//!
//! ```text
//! SqliteFailure(SchemaChanged/17, "vtable constructor failed: rel_fts")
//! ```
//!
//! `bc7b4e63` removed the churn that fired this every few seconds
//! (`Index::open` rewrote sqlite_master on EVERY open). It did not remove
//! the failure: the first `ANALYZE` creating sqlite_stat1, and any version
//! upgrade's migrations, still change the schema under a live reader.
//!
//! Two halves, because neither alone is honest:
//!
//! - **Retry once.** SQLITE_SCHEMA is by contract a "the statement is
//!   stale, prepare it again" signal, and re-preparing after the schema
//!   has settled is the handling SQLite asks for - not a paper over a
//!   bug. Measured: a single immediate retry on the SAME connection
//!   recovered 8 of 9 hits, instrumented over 160 parallel runs of the
//!   newznab test. It is logged at warn with `{e:?}`, which is what
//!   names `SchemaChanged`, so a rate anyone can grep survives - a
//!   SILENT retry here is exactly what nextest's `retries = 1` was
//!   already doing, and why the flake went unseen until 16 Aug.
//! - **Stamp what the retry could not fix.** The retry is not a
//!   guarantee, and the caller flattens the error: every query endpoint
//!   does `.ok()` on the Result and renders `None` as an empty answer, so
//!   a hard error reaches Sonarr as "this indexer has nothing".
//!   [`Index::schema_faults`] counts the queries that failed AFTER their
//!   retry, on THIS connection, so the daemon's read seam can read it
//!   across the closure that threw the error away and answer "ask again"
//!   instead of "nothing found".
//!
//! Only the queries that name an fts5 vtable are wrapped, because they
//! are the only ones that can surface SQLITE_SCHEMA at all - see above.
//! `hide_suggestions` touches `rel_fts` too and is deliberately left
//! alone: its one FTS read already falls back on error, and it is a
//! nudge nobody is waiting on.

use std::cell::Cell;

use super::*;

/// Is this the stale-statement error, whatever the message says?
fn is_schema_change(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::SchemaChanged
    )
}

/// The shape a lost fts5 constructor race produces, for the injector.
fn schema_changed_error() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_SCHEMA),
        Some("vtable constructor failed: rel_fts".into()),
    )
}

/// Per-connection retry/fault state. A plain [`Cell`] pair: `Index`
/// already holds a `RefCell` and is handed out one-thread-at-a-time
/// behind the daemon's pool guard, so nothing here needs to be atomic.
#[derive(Default)]
pub(super) struct SchemaRetry {
    /// Queries that failed with SQLITE_SCHEMA even after their retry.
    faults: Cell<u64>,
    /// Fault injector: fail this many further queries before running
    /// them. Test-only in intent, always compiled because the daemon's
    /// own tests live in a different crate and cannot see `cfg(test)`
    /// here. Costs one `Cell::get` per QUERY (never per row).
    fail_next: Cell<u32>,
}

impl Index {
    /// Queries on this connection that failed with SQLITE_SCHEMA and were
    /// still failing after a retry.
    ///
    /// Monotonic for the life of the connection, so a caller reads it
    /// BEFORE and AFTER the work it wants to judge. That is the whole
    /// interface: the daemon's read seam takes an
    /// `FnOnce(&Index) -> Option<T>`, so by the time it sees a result the
    /// error is already flattened to `None` and it cannot otherwise tell
    /// a real failure from a legitimately empty query. Retrying on `None`
    /// would be wrong AND would double the work of every miss.
    pub fn schema_faults(&self) -> u64 {
        self.retry.faults.get()
    }

    /// Fail the next `n` wrapped queries with the SQLITE_SCHEMA a lost
    /// fts5 constructor race produces.
    ///
    /// The real race needs a writer to change the schema in the window
    /// between a reader's prepare and its step; arming it is how the
    /// behaviour above gets a DETERMINISTIC test instead of a 9-in-160
    /// one. Arm 1 and the retry recovers; arm 2 and the fault is stamped
    /// and the error returned.
    #[doc(hidden)]
    pub fn debug_fail_next_queries(&self, n: u32) {
        self.retry.fail_next.set(n);
    }

    /// Run `f`, and if it reports a stale statement run it exactly once
    /// more. A second failure is counted in [`Self::schema_faults`] and
    /// returned. Every other error passes straight through on the first
    /// attempt - a retry there would be work for nothing.
    fn retry_on_schema_change<T>(
        &self,
        what: &str,
        f: impl Fn() -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let once = |f: &dyn Fn() -> rusqlite::Result<T>| -> rusqlite::Result<T> {
            match self.retry.fail_next.get() {
                0 => f(),
                n => {
                    self.retry.fail_next.set(n - 1);
                    Err(schema_changed_error())
                }
            }
        };
        match once(&f) {
            Err(e) if is_schema_change(&e) => {
                warn!(
                    target: "index",
                    "{what}: {e:?} - the schema changed under this reader, \
                     so its statements are stale; preparing again"
                );
                match once(&f) {
                    Err(again) if is_schema_change(&again) => {
                        self.retry.faults.set(self.retry.faults.get() + 1);
                        warn!(
                            target: "index",
                            "{what}: {again:?} again after re-preparing - answering \
                             with the ERROR, not with an empty result"
                        );
                        Err(again)
                    }
                    other => other,
                }
            }
            other => other,
        }
    }

    /// M25 browse view - see [`Self::browse_once`], wrapped in the
    /// stale-statement retry this module documents.
    pub fn browse(&self, q: &BrowseQuery) -> rusqlite::Result<(Vec<Release>, u64)> {
        self.retry_on_schema_change("browse", || self.browse_once(q))
    }

    /// M28 card view - see [`Self::browse_cards_once`], wrapped.
    pub fn browse_cards(
        &self,
        q: &BrowseQuery,
        sort: CardSort,
        matched_only: bool,
        group_by_kind: bool,
        affinity: Option<&AffinityCtx>,
    ) -> rusqlite::Result<(Vec<Card>, u64)> {
        self.retry_on_schema_change("browse_cards", || {
            self.browse_cards_once(q, sort, matched_only, group_by_kind, affinity)
        })
    }

    /// Free-text search - see [`Self::search_once`], wrapped.
    pub fn search(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        self.retry_on_schema_change("search", || self.search_once(query, limit))
    }

    /// Complete-only search - see [`Self::search_complete_once`], wrapped.
    pub fn search_complete(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        self.retry_on_schema_change("search_complete", || {
            self.search_complete_once(query, limit)
        })
    }

    /// Name search - see [`Self::people_search_once`], wrapped.
    pub fn people_search(&self, q: &str, limit: u32) -> rusqlite::Result<Vec<PersonHit>> {
        self.retry_on_schema_change("people_search", || self.people_search_once(q, limit))
    }

    /// Header lookup - see [`Self::find_by_header_once`], wrapped.
    pub fn find_by_header(&self, header: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        self.retry_on_schema_change("find_by_header", || self.find_by_header_once(header, limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};

    fn seeded(tag: &str) -> (std::path::PathBuf, Index) {
        let dir = std::env::temp_dir().join(format!("nzbfast-retry-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[entry(
                r#""Retry.Probe.S01E01.720p-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "retry1",
                900,
            )],
            1000,
        )
        .unwrap();
        (dir, ix)
    }

    fn q() -> BrowseQuery {
        BrowseQuery {
            q: "retry".into(),
            limit: 10,
            ..Default::default()
        }
    }

    /// One stale-statement failure is re-prepared and the caller never
    /// sees it. Without the retry this is an `Err` the endpoint renders
    /// as an empty feed.
    #[test]
    fn a_stale_statement_is_prepared_again_and_answers() {
        let (dir, ix) = seeded("recovers");
        let (before, _) = ix.browse(&q()).expect("a free connection answers");
        assert_eq!(before.len(), 1, "precondition: the seed is findable");

        ix.debug_fail_next_queries(1);
        let (rows, total) = ix
            .browse(&q())
            .expect("a single SQLITE_SCHEMA must be retried, not returned");
        assert_eq!(rows.len(), 1, "the retry answers with the real rows");
        assert_eq!(total, 1);
        assert_eq!(
            ix.schema_faults(),
            0,
            "a failure the retry fixed is not a fault"
        );
        teardown(&dir, ix);
    }

    /// A failure that OUTLIVES the retry is returned AND stamped, so the
    /// read seam can tell it from a query that legitimately matched
    /// nothing. Both halves are the point: the `Err` is what a caller
    /// doing `.ok()` throws away, and the stamp is what survives it.
    #[test]
    fn a_failure_that_outlives_the_retry_is_returned_and_stamped() {
        let (dir, ix) = seeded("stamped");
        ix.debug_fail_next_queries(2);
        let e = ix
            .browse(&q())
            .expect_err("two SQLITE_SCHEMA in a row is a real failure");
        assert!(
            is_schema_change(&e),
            "the error is reported as it was: {e:?}"
        );
        assert_eq!(
            ix.schema_faults(),
            1,
            "the fault is stamped on the connection for the read seam"
        );

        // ...and the connection is not poisoned: the next query is clean,
        // and the counter stays where it was.
        let (rows, _) = ix.browse(&q()).expect("the connection still works");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            ix.schema_faults(),
            1,
            "no fault is invented for a good query"
        );
        teardown(&dir, ix);
    }

    /// Exactly ONE extra attempt, never a loop: the injector's budget is
    /// what proves the count, so a third armed failure survives to the
    /// following query rather than being spent here.
    #[test]
    fn the_retry_is_one_attempt_not_a_loop() {
        let (dir, ix) = seeded("bounded");
        ix.debug_fail_next_queries(3);
        assert!(ix.browse(&q()).is_err(), "two attempts, both armed");
        // One armed failure is left, so the NEXT query spends it and
        // recovers on its retry. Three attempts would have spent it here.
        let (rows, _) = ix
            .browse(&q())
            .expect("the third armed failure is retried away");
        assert_eq!(rows.len(), 1);
        assert_eq!(ix.schema_faults(), 1, "only the first query faulted");
        teardown(&dir, ix);
    }

    /// The real trigger the residual named: a writer running `ANALYZE`
    /// (which CREATES sqlite_stat1 the first time) under a live reader.
    /// Green before this change too - the race is 9-in-160, not
    /// deterministic - so it is a regression guard on the scenario, and
    /// the injected tests above are the ones that pin the behaviour.
    #[test]
    fn an_analyze_under_a_live_reader_still_answers() {
        let (dir, ix) = seeded("analyze");
        let db = dir.join("index.db");
        let reader = Index::open_read_only(&db).expect("a pooled-shaped reader");
        assert_eq!(
            reader.browse(&q()).expect("first answer").0.len(),
            1,
            "the reader has prepared and run its statements"
        );

        ix.db.execute_batch("ANALYZE").expect("the writer analyzes");

        let (rows, total) = reader
            .browse(&q())
            .expect("a schema change under the reader must not lose the answer");
        assert_eq!((rows.len(), total), (1, 1));
        drop(reader);
        teardown(&dir, ix);
    }
}
