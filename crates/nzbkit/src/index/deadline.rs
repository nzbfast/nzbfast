//! A query on a pooled reader gets a BUDGET, and a query that outruns
//! it is abandoned rather than waited out (TODO 300).
//!
//! [`super::retry`]'s standing lesson, one resource along. The 2 Aug
//! wedge made the read path a bounded POOL - four connections, and a
//! caller that cannot get one inside 100 ms is told "busy" instead of
//! queueing - on the argument that a ceiling is what protects the HTTP
//! workers. The ceiling protects them from a QUEUE. It does nothing
//! about the query already inside: a borrowed connection is held for as
//! long as `sqlite3_step` takes, and nothing bounded that.
//!
//! Measured 25 Aug 2026 against the live 50 GB index (33.4M releases,
//! 8,988 enriched titles), one `mode=wall2` card page at `LIMIT 60`:
//!
//! | request | groups aggregated | wall |
//! | --- | --- | --- |
//! | matched-only (the default wall) | 1,450 | 0.7-1.2 s |
//! | `matched=0&all=1` (Show unmatched) | 1,251,672 | 57.8 s warm, >120 s cold |
//!
//! Show-all drops the `junk < 50` predicate that `idx_rel_visible_posted`
//! is a partial index on, so the plan goes from `SCAN t` over 8,988
//! titles to `SCAN r USING INDEX idx_rel_title_key` over all 33.4M
//! releases, and the page's `LIMIT 60` throws away 1.25M groups that had
//! to be built first. The offset is not the problem and neither are the
//! two representative subqueries (58.4 s with them removed): the
//! aggregate is proportional to the whole index and always will be.
//!
//! Four of those pin the pool, and the daemon stops answering - which is
//! the 28 Jul and 2 Aug wedge arriving through the wall. An abandoned
//! request makes it worse rather than better: the browser is gone, the
//! socket is closed, and `sqlite3_step` neither knows nor cares.
//!
//! **Why a progress handler and not an interrupt handle.** The daemon
//! already interrupts a statement, from `MaintenanceArm`, and that type's
//! doc comment is the warning: a handle is per CONNECTION, not per
//! statement, so an interrupt that arrives a moment late lands on
//! whatever the connection does next. Every mitigation there is
//! rendezvous machinery for that hazard. `sqlite3_progress_handler` has
//! none of it - the callback runs on the querying thread, between the VM
//! instructions of the statement it is judging, so there is no late
//! interrupt to land anywhere and no second thread to synchronise with.
//! It also needs no timer per query, which matters when the steady state
//! is that nothing ever trips.
//!
//! Two halves, the same two [`super::retry`] chose and for the same
//! reason:
//!
//! - **Abandon it.** Returning `true` from the callback interrupts the
//!   statement, which surfaces as `SQLITE_INTERRUPT` out of `step` and
//!   hands the connection back to the pool. Nothing rolls back: these
//!   are `query_only` connections in autocommit.
//! - **Stamp what was abandoned.** Every query endpoint flattens its
//!   `Result` with `.ok()`, so an interrupted query is indistinguishable
//!   from one that legitimately matched nothing - and "the wall is
//!   empty" is the wrong answer to "that view is too big". [`Index::deadline_trips`]
//!   counts them on THIS connection, so the daemon's read seam reads it
//!   either side of the closure and reports instead of blanking.
//!
//! The budget is the DAEMON's to choose - it is a statement about how
//! long an HTTP worker may hold a pooled reader, not about SQLite - so
//! it is passed in per borrow and lives beside `INDEX_READ_CONNS`.
//!
//! What this does NOT bound: a wait on the 10 s `busy_timeout`, which
//! happens outside the VM where no progress callback runs. WAL readers
//! only meet that in a checkpoint's brief WAL-reset window, and 10 s is
//! its own ceiling.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::*;

/// Virtual-machine instructions between callbacks. The callback is one
/// relaxed load plus - only while armed - an `Instant::now()`, so the
/// figure trades abort granularity against a clock read: ~10k VM ops is
/// tens of microseconds of work, which is finer than anyone waiting out
/// a 20-second budget can perceive.
///
/// PRICED rather than assumed, 25 Aug 2026, on the shape that flatters
/// it least: a 20M-row recursive CTE, pure VM work with no I/O to hide
/// anything behind. Four interleaved rounds of no-callback (the write
/// connection) / installed-and-disarmed / installed-and-armed gave
/// 3548-3660 ms, 3580-3637 ms and 3593-3677 ms - so armed is ~0.5-1.3%
/// over bare, and the round-to-round drift of the bare arm alone is
/// wider than the gap. A real index query is I/O bound, so its share is
/// smaller again; the steady state is the disarmed arm, which is the
/// relaxed load and nothing else.
const PROGRESS_OPS: std::ffi::c_int = 10_000;

/// The deadline the progress callback reads, shared with it by `Arc`
/// because the callback outlives every borrow and must be `'static`.
///
/// Stamps are nanoseconds from `base` rather than from a process-wide
/// origin so that nothing here needs a global: `Instant` is `Copy` and
/// immutable, and u64 nanos from a connection's open covers 584 years.
#[derive(Debug)]
struct DeadlineState {
    /// When this connection was opened; every stamp below counts from it.
    base: Instant,
    /// Nanos from `base` at which the running query must stop.
    /// 0 = disarmed, which is every moment no borrow is inside `f`.
    at: AtomicU64,
    /// Set by the callback when it decides to interrupt, cleared when the
    /// next query arms. SQLite may call back more than once before the
    /// step loop unwinds, and one abandoned query must count once.
    fired: AtomicBool,
    /// Queries on this connection abandoned for outrunning their budget.
    /// Monotonic, for the read-before/read-after interface
    /// [`Index::schema_faults`] documents at length.
    trips: AtomicU64,
}

impl DeadlineState {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            at: AtomicU64::new(0),
            fired: AtomicBool::new(false),
            trips: AtomicU64::new(0),
        }
    }

    /// The progress callback itself. `true` interrupts the statement.
    fn expired(&self) -> bool {
        let at = self.at.load(Ordering::Relaxed);
        if at == 0 {
            return false;
        }
        if self.base.elapsed().as_nanos() as u64 <= at {
            return false;
        }
        // Count the query, not the callback: `fired` is what makes a
        // second callback before the unwind free.
        if !self.fired.swap(true, Ordering::Relaxed) {
            self.trips.fetch_add(1, Ordering::Relaxed);
        }
        true
    }
}

/// Per-connection deadline state. `Default` so the two `Index`
/// constructors keep listing their fields flatly; nothing is installed
/// until [`Index::install_query_deadline`] runs, and a connection that
/// never installs one simply never has a callback.
#[derive(Debug)]
pub(super) struct QueryDeadline(Arc<DeadlineState>);

impl Default for QueryDeadline {
    fn default() -> Self {
        Self(Arc::new(DeadlineState::new()))
    }
}

impl Index {
    /// Register this connection's progress callback, disarmed.
    ///
    /// Read-only connections only, deliberately. The write connection is
    /// held by ingest, maintenance and eviction - lanes whose statements
    /// are SUPPOSED to run for minutes, and which already have
    /// `MaintenanceArm` for the one case that must be abortable - so
    /// installing a callback there would buy a per-op check on the
    /// hottest path in the crate for a budget nobody would ever arm.
    pub(super) fn install_query_deadline(&self) -> rusqlite::Result<()> {
        let state = Arc::clone(&self.deadline.0);
        self.db
            .progress_handler(PROGRESS_OPS, Some(move || state.expired()))
    }

    /// Give the next query on this connection at most `budget`, or
    /// `None` to let it run as long as it likes.
    ///
    /// A no-op on a connection that never called
    /// [`Self::install_query_deadline`]: the stamp is written and no
    /// callback ever reads it.
    ///
    /// **Disarming is not optional.** These connections are POOLED and
    /// reused, so a stamp left behind is a stamp the next borrower's
    /// first query is measured against - and it is already in the past,
    /// so that query is abandoned before it does anything. The daemon's
    /// `IndexReader::drop` is what guarantees it, on the unwind out of a
    /// panicking handler as much as on the ordinary path.
    pub fn set_query_deadline(&self, budget: Option<Duration>) {
        let st = &self.deadline.0;
        let at = match budget {
            // Saturating, and `max(1)` so a zero-length budget still
            // means "armed" rather than reading as the disarmed stamp.
            Some(d) => (st.base.elapsed().saturating_add(d).as_nanos() as u64).max(1),
            None => 0,
        };
        st.fired.store(false, Ordering::Relaxed);
        st.at.store(at, Ordering::Relaxed);
    }

    /// Queries on this connection abandoned for outrunning their budget.
    ///
    /// Monotonic for the life of the connection, so a caller reads it
    /// BEFORE and AFTER the work it wants to judge - the same interface,
    /// and for the same reason, as [`Self::schema_faults`]: the read
    /// seam takes an `FnOnce(&Index) -> Option<T>`, so by the time it
    /// sees a result the `SQLITE_INTERRUPT` has already been flattened
    /// to `None` and "abandoned" is indistinguishable from "matched
    /// nothing".
    pub fn deadline_trips(&self) -> u64 {
        self.deadline.0.trips.load(Ordering::Relaxed)
    }

    /// Run a query with no end, so a caller can prove what happens to
    /// one that outruns its budget.
    ///
    /// Test-only in intent, always compiled - the same arrangement, and
    /// for the same reason, as [`Index::debug_fail_next_queries`]: the
    /// daemon's own tests live in a different crate and cannot see
    /// `cfg(test)` here, and the behaviour worth pinning is the SEAM's,
    /// not this crate's. Deliberately a real query rather than a sleep,
    /// because a sleep is exactly what this mechanism cannot stop: the
    /// progress callback runs between VM instructions, so a handler that
    /// is not executing SQL is not something a budget has any opinion
    /// about. Reachable only through the NZBFAST_DEBUG_HOOKS-gated
    /// `mode=debug_slow_index_read`.
    ///
    /// Returns whatever ended it, which on a connection carrying a
    /// budget is `SQLITE_INTERRUPT` and on one that is not is never.
    #[doc(hidden)]
    pub fn debug_endless_query(&self) -> rusqlite::Result<i64> {
        self.db.query_row(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c)
             SELECT COUNT(*) FROM c",
            [],
            |r| r.get(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::teardown;

    /// A query with no end: the deadline is the only thing that can
    /// stop it, so a test that returns at all is a test that tripped.
    const FOREVER: &str = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c)
                           SELECT COUNT(*) FROM c";

    fn reader(tag: &str) -> (std::path::PathBuf, Index, Index) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-deadline-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let rw = Index::open(&db).unwrap();
        let ro = Index::open_read_only(&db).unwrap();
        (dir, rw, ro)
    }

    /// The whole point: a query past its budget is abandoned, the error
    /// says so, and the connection is left usable for the next borrower.
    #[test]
    fn a_query_past_its_budget_is_abandoned_and_stamped() {
        let (dir, rw, ro) = reader("abandons");
        ro.set_query_deadline(Some(Duration::from_millis(150)));
        let started = Instant::now();
        let e = ro
            .db
            .query_row(FOREVER, [], |r| r.get::<_, i64>(0))
            .expect_err("an endless query must not be waited out");
        let took = started.elapsed();

        assert!(
            matches!(
                e,
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::OperationInterrupted
            ),
            "abandoned, not failed some other way: {e:?}"
        );
        assert_eq!(ro.deadline_trips(), 1, "the trip is stamped for the seam");
        assert!(
            took < Duration::from_secs(10),
            "the budget bounds the wall, not just the outcome: {took:?}"
        );

        // The connection is not poisoned - it is about to go back into
        // the pool, and the next borrower's query must simply work.
        ro.set_query_deadline(None);
        assert_eq!(
            ro.db
                .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get::<_, i64>(0))
                .expect("the reader still answers"),
            0
        );
        assert_eq!(
            ro.deadline_trips(),
            1,
            "no trip is invented for a good query"
        );
        drop(ro);
        teardown(&dir, rw);
    }

    /// A query INSIDE its budget is untouched, and the counter stays put.
    /// Without this the test above passes just as well on a callback that
    /// interrupts everything.
    #[test]
    fn a_query_inside_its_budget_answers_normally() {
        let (dir, rw, ro) = reader("inside");
        ro.set_query_deadline(Some(Duration::from_secs(30)));
        let n = ro
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |r| r.get::<_, i64>(0))
            .expect("a quick query is never abandoned");
        assert_eq!(n, 0);
        assert_eq!(ro.deadline_trips(), 0);
        drop(ro);
        teardown(&dir, rw);
    }

    /// Disarmed is the steady state, and it must mean "no budget" rather
    /// than "a budget in the past". A pooled connection spends nearly all
    /// its life here, so a disarm that read as expiry would abandon every
    /// query the daemon ever ran.
    #[test]
    fn a_disarmed_deadline_never_interrupts() {
        let (dir, rw, ro) = reader("disarmed");
        // Arm, trip, and disarm: the state a connection is handed back in
        // after the incident this module exists for.
        ro.set_query_deadline(Some(Duration::from_millis(50)));
        assert!(
            ro.db
                .query_row(FOREVER, [], |r| r.get::<_, i64>(0))
                .is_err()
        );
        ro.set_query_deadline(None);

        // A budget that has already elapsed is what a MISSING disarm
        // would leave behind, so run something the interpreter has to
        // work at rather than a constant.
        let n = ro
            .db
            .query_row(
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 200000)
                 SELECT COUNT(*) FROM c",
                [],
                |r| r.get::<_, i64>(0),
            )
            .expect("nothing is abandoned while disarmed");
        assert_eq!(n, 200_000);
        assert_eq!(ro.deadline_trips(), 1, "the disarmed run added no trip");
        drop(ro);
        teardown(&dir, rw);
    }

    /// One abandoned query counts ONCE, however many times SQLite calls
    /// back before the step loop unwinds. The seam reads a delta, so an
    /// over-count is only invisible while the delta is compared against
    /// zero - and `deadline_trips` is documented as a count of queries.
    #[test]
    fn an_abandoned_query_counts_once() {
        let (dir, rw, ro) = reader("once");
        for expected in 1..=3 {
            ro.set_query_deadline(Some(Duration::from_millis(50)));
            assert!(
                ro.db
                    .query_row(FOREVER, [], |r| r.get::<_, i64>(0))
                    .is_err()
            );
            assert_eq!(
                ro.deadline_trips(),
                expected,
                "each abandoned query is one trip, not one per callback"
            );
        }
        ro.set_query_deadline(None);
        drop(ro);
        teardown(&dir, rw);
    }

    /// The read-WRITE connection deliberately has no callback, so a
    /// budget armed on it is inert. Pinned because the difference is
    /// invisible from the outside - `set_query_deadline` is on `Index`,
    /// not on some reader-only type - and a maintenance pass that
    /// started being abandoned mid-VACUUM would be a nasty way to find
    /// out this had changed.
    #[test]
    fn the_write_connection_has_no_deadline() {
        let (dir, rw, ro) = reader("writeconn");
        rw.set_query_deadline(Some(Duration::from_millis(50)));
        let n = rw
            .db
            .query_row(
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 200000)
                 SELECT COUNT(*) FROM c",
                [],
                |r| r.get::<_, i64>(0),
            )
            .expect("the writer is never interrupted by a budget");
        assert_eq!(n, 200_000);
        assert_eq!(rw.deadline_trips(), 0);
        rw.set_query_deadline(None);
        drop(ro);
        teardown(&dir, rw);
    }
}
