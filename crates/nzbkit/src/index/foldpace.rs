//! What a fold slice's budget bounds: the HOLD, not only the intake.
//!
//! The three budgeted folds - [`Index::shatter_fold`],
//! [`Index::session_fold`], [`Index::album_fold`] - all run inside the
//! daemon's index write mutex, one slice per `with_index_mut`, and all
//! take their budget from the same `index_fold_secs` dial. Every one of
//! them was written the same way: do a unit of work, then ask whether
//! the budget is spent. That bounds when the loop stops TAKING work. It
//! does not bound the hold, because the unit already in flight runs to
//! completion afterwards, and the caller has been waiting for the mutex
//! the whole time.
//!
//! The gap was measured on a live 125 GB index on 16 Sep 2026, on an
//! idle 32-core workstation
//! (`research/INDEX-SCAN-CHUNK-SWEEP-2026-09-16.md` section 10, and the
//! re-read in section 11): at the shipped `index_fold_secs` = 4 the
//! shatter fold's p50 hold was 4,002 ms - the budget, tracked exactly -
//! and its p90 was 4,108 ms, which is the overrun. It is ADDITIVE and
//! not proportional, which is why scaling a 1 s reading up by four
//! missed it: the overrun is one unit's cost, and a unit costs what it
//! costs whatever the budget is.
//!
//! What a unit costs, measured the same day against an APFS clone of a
//! real 122 GB index: the fold's own SQL is microseconds, and 50-350 ms
//! of it is `tx.commit()`, which at `WAL_AUTOCHECKPOINT_PAGES` = 4,000
//! is usually a WAL checkpoint writing 16 MiB of scattered pages back
//! into a multi-gigabyte file. So the unit that overruns is not a big
//! fold, it is any fold that commits.
//!
//! # The rule, and the one case it cannot cover
//!
//! Never START a unit unless the time left covers the dearest unit this
//! call has already run. Two properties follow, and the second is the
//! honest limit:
//!
//! - Once a call has run one unit, its hold is bounded by the budget
//!   unless a unit turns out dearer than every unit before it in the
//!   same call - the estimate is a running maximum, so it only
//!   under-predicts a new worst case.
//! - The FIRST unit always runs. It has to: a unit dearer than the
//!   whole budget would otherwise be refused for ever and the fold
//!   would never advance past it. So the true bound is `max(budget, one
//!   unit)` and not `budget`, and no amount of pacing changes that -
//!   shrinking it means making the unit itself smaller, which for a
//!   commit means checkpointing somewhere other than under the mutex.
//!
//! # Why a running MAXIMUM and not a mean
//!
//! The thing being bounded is a tail. A mean unit cost predicts the
//! median slice and under-predicts exactly the slices that cross the
//! bound, which are the only ones anybody is waiting on. The price of
//! the maximum is that a slice stops up to one worst-unit early, so the
//! fold gets less done per slice: measured on the clone at a 1 s budget,
//! [see the A/B in section 11 of the sweep]. `research/FOLD-BUDGET-DIAL-
//! 2026-09-02.md` measured the fold's per-second yield FLAT from a 4 s
//! slice to a 10 s one, so that loss is proportional and nothing worse.
//!
//! The maximum is per CALL and not remembered across calls, deliberately.
//! A single pathological unit - the 123 s first checkpoint an APFS clone
//! pays, say - would otherwise poison every later slice on a daemon that
//! never sees one again.

use std::cell::Cell;
use std::time::{Duration, Instant};

/// One budgeted fold slice's clock, plus what it has learned about the
/// cost of the indivisible units it is made of.
///
/// Shared immutably down the fold's call tree (the folds take
/// `&mut self`, so an `&mut` second argument would fight borrowck for
/// nothing), which is what the [`Cell`]s are for.
pub(crate) struct FoldPace {
    started: Instant,
    budget: Duration,
    /// The dearest unit this call has run.
    worst: Cell<Duration>,
    /// Units completed. Zero means "nothing measured yet, so run it".
    units: Cell<u64>,
}

impl FoldPace {
    pub(crate) fn new(budget: Duration) -> Self {
        Self {
            started: Instant::now(),
            budget,
            worst: Cell::new(Duration::ZERO),
            units: Cell::new(0),
        }
    }

    /// Is there room for one more indivisible unit?
    ///
    /// True for the first unit whatever the clock says - see the module
    /// header for why refusing it would stall the fold for good.
    pub(crate) fn room(&self) -> bool {
        if self.units.get() == 0 {
            return true;
        }
        let room = self.budget.saturating_sub(self.started.elapsed()) >= self.worst.get();
        #[cfg(test)]
        if !room {
            REFUSALS.with(|c| c.set(c.get() + 1));
        }
        room
    }

    /// Mark the start of one indivisible unit. Pair it with
    /// [`Self::unit_end`], which is what teaches the pacer.
    pub(crate) fn unit_start(&self) -> Instant {
        Instant::now()
    }

    /// Record what the unit started at `at` cost.
    pub(crate) fn unit_end(&self, at: Instant) {
        let took = at.elapsed();
        if took > self.worst.get() {
            self.worst.set(took);
        }
        self.units.set(self.units.get() + 1);
    }
}

// Units this process's folds have declined for want of time, for the
// end-to-end fold tests to read.
//
// It answers "is the pacer actually consulted inside the fold", which
// is the one thing an end-to-end test can ask here WITHOUT a clock in
// the assertion. What it deliberately does not answer is "is the hold
// inside the budget": see the test that reads it for the four timing
// formulations that were tried for that and why each one either passes
// on both rules or reds on a shared box.
#[cfg(test)]
thread_local! {
    static REFUSALS: Cell<u64> = const { Cell::new(0) };
}

/// Read and clear [`REFUSALS`].
#[cfg(test)]
pub(crate) fn take_refusals() -> u64 {
    REFUSALS.with(|c| c.take())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_unit_always_runs_however_dear_the_last_one_was() {
        let p = FoldPace::new(Duration::from_millis(10));
        assert!(p.room(), "nothing measured yet");
        let u = p.unit_start();
        std::thread::sleep(Duration::from_millis(30));
        p.unit_end(u);
        // Over budget AND the worst unit is dearer than the whole
        // budget: a fresh slice must still admit one of these or the
        // fold never gets past it.
        assert!(!p.room(), "this call is spent");
        assert!(FoldPace::new(Duration::from_millis(10)).room());
    }

    #[test]
    fn a_unit_that_would_not_fit_is_refused_before_it_starts() {
        let p = FoldPace::new(Duration::from_millis(200));
        let u = p.unit_start();
        std::thread::sleep(Duration::from_millis(120));
        p.unit_end(u);
        // ~80 ms left against a ~120 ms unit: refused, and the refusal
        // is what keeps the hold under the budget rather than at 240 ms.
        assert!(!p.room());
    }

    #[test]
    fn cheap_units_keep_their_room_until_the_budget_is_nearly_gone() {
        // Five seconds of budget against 5 ms units, and not 400 ms:
        // this fleet's boxes dilate a sleep by tens of times under the
        // parallel suite, and the margin has to swallow that or the
        // test reds on the box rather than on the rule.
        let p = FoldPace::new(Duration::from_secs(5));
        for _ in 0..3 {
            assert!(p.room());
            let u = p.unit_start();
            std::thread::sleep(Duration::from_millis(5));
            p.unit_end(u);
        }
        assert!(p.room(), "15 ms of 5 s spent on 5 ms units");
    }
}
