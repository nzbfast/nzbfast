//! Work counters for the recovery paths whose tests used to assert a wall
//! clock.
//!
//! nzbfast-local addition, 16 Sep 2026 - re-apply on the next rars
//! re-sync, see `vendor/rars/VENDORING.md`.
//!
//! Why it exists: six tests in this crate bounded a hostile-input refusal
//! with `Instant::elapsed()` - four at 500 ms, two at 5 s. Every one of
//! them was reaching for a claim about WORK DONE ("this scan is not
//! quadratic in the markers", "this refusal did not size the grid first")
//! and a wall clock is a poor instrument for that: it reds when the box is
//! busy and it passes when the box is quiet whatever the code did. That is
//! not hypothetical here - nightly's `one-process-loaded` campaign runs
//! `rars:lib` under deliberate load, and a mutation census on 16 Sep 2026
//! was told a mutation was "caught by 1 test" when the test that fired was
//! `rar5_inline_recovery_scan_is_not_quadratic_on_dense_markers` and the
//! only thing it had detected was the load.
//!
//! So the production paths charge what they actually do, and the tests
//! assert against that instead. Two counters, both meaning something the
//! code can be held to:
//!
//! - [`charge_sized_cells`] - units allocated in proportion to a count
//!   that arrived off the wire (encoder-matrix cells, per-shard state
//!   slots). A refusal that must happen "before anything is sized from the
//!   declaration" is exactly the claim that this counter stays at zero.
//! - [`charge_scanned_bytes`] - bytes a recovery scan commits to CRC64.
//!   The anti-quadratic hashing budget is a bound on precisely this sum,
//!   so the test can assert the budget rather than a proxy for it.
//!
//! **Zero cost outside the crate's own test build.** Both charge functions
//! compile to an empty body under `#[cfg(not(test))]`, which is every
//! build nzbfast ships; `cfg(test)` here is only true while `cargo test -p
//! rars` is compiling this crate.
//!
//! **Thread-local, not global.** These counters are read by tests that run
//! alongside 960 others, in a crate whose `parallel` feature puts rayon
//! workers in the same process. A process-global counter would be the same
//! shared-state defect the one-process jobs exist to find. The scanned and
//! sized paths measured here are sequential on the calling thread, so a
//! thread-local charge lands where the [`probe`] that reads it is.

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static SIZED_CELLS: Cell<u64> = const { Cell::new(0) };
    static SCANNED_BYTES: Cell<u64> = const { Cell::new(0) };
}

/// Charges `cells` units allocated in proportion to a declared count.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn charge_sized_cells(_cells: u64) {}

/// Charges `cells` units allocated in proportion to a declared count.
#[cfg(test)]
pub(crate) fn charge_sized_cells(cells: u64) {
    let _ = SIZED_CELLS.try_with(|slot| slot.set(slot.get().saturating_add(cells)));
}

/// Charges `bytes` that a recovery scan is about to CRC64.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn charge_scanned_bytes(_bytes: u64) {}

/// Charges `bytes` that a recovery scan is about to CRC64.
#[cfg(test)]
pub(crate) fn charge_scanned_bytes(bytes: u64) {
    let _ = SCANNED_BYTES.try_with(|slot| slot.set(slot.get().saturating_add(bytes)));
}

/// Zeroes both counters and reads them back for the rest of the test.
///
/// Take one immediately before the call under test: the counters are
/// cumulative for the life of the thread, and every test in this crate's
/// binary that touches a recovery path adds to them.
#[cfg(test)]
pub(crate) fn probe() -> Probe {
    SIZED_CELLS.with(|slot| slot.set(0));
    SCANNED_BYTES.with(|slot| slot.set(0));
    Probe(())
}

/// Reader for the counters, from the [`probe`] that zeroed them.
#[cfg(test)]
pub(crate) struct Probe(());

#[cfg(test)]
impl Probe {
    /// Units allocated from a wire-supplied count since the probe was taken.
    pub(crate) fn sized_cells(&self) -> u64 {
        SIZED_CELLS.with(|slot| slot.get())
    }

    /// Bytes committed to a scan CRC64 since the probe was taken.
    pub(crate) fn scanned_bytes(&self) -> u64 {
        SCANNED_BYTES.with(|slot| slot.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gauge itself: a probe zeroes, charges accumulate, and a second
    /// probe does not see the first one's charges. Without this, a gauge
    /// that silently counted nothing would make every assertion built on
    /// it vacuous - which is the exact failure mode the wall clocks it
    /// replaces already had.
    #[test]
    fn workgauge_counts_and_a_probe_zeroes() {
        let first = probe();
        assert_eq!(first.sized_cells(), 0);
        assert_eq!(first.scanned_bytes(), 0);
        charge_sized_cells(7);
        charge_scanned_bytes(11);
        charge_sized_cells(5);
        assert_eq!(first.sized_cells(), 12);
        assert_eq!(first.scanned_bytes(), 11);

        let second = probe();
        assert_eq!(second.sized_cells(), 0);
        assert_eq!(second.scanned_bytes(), 0);
    }
}
