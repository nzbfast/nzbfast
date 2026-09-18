//! Shared test fixtures for the index/ modules (TODO 106 phase 2.2):
//! the WALK budget, the close-before-remove teardown, and the OverEntry
//! builders. One home, so no test module reaches into another.

use super::*;

/// A budget the split-merge and sidecar-fold walks can never spend
/// on a test-sized index: tests exercise the cursor logic, not the
/// per-call time bound.
pub(super) const WALK: std::time::Duration = std::time::Duration::from_secs(60);

/// Tear a fixture down, closing the index BEFORE removing its directory.
///
/// Taking `ix` by value is the whole point: it makes the close
/// impossible to forget, because the directory cannot be named for
/// removal until the index has been surrendered.
///
/// The close is load-bearing, not tidiness. `Index` holds an open SQLite
/// connection to `dir/index.db` (plus its -wal and -shm), and SQLite
/// opens its files without FILE_SHARE_DELETE, so Windows refuses to
/// remove the directory underneath it: "The process cannot access the
/// file because it is being used by another process" (os error 32). Unix
/// unlinks an open file quite happily, which is why 29 tests in this
/// module carried this invisibly for as long as the suite only ever ran
/// on Linux and macOS. Every product assertion in all of them passed
/// first - the teardown line was the only thing Windows objected to.
///
/// Beware a SHADOWED index: `let mut ix = ...; let ix = ...;` leaves the
/// first connection open until the end of the block, so a fixture that
/// reopens must either scope the first one in an inner block or drop it
/// by name.
pub(super) fn teardown(dir: &Path, ix: Index) {
    drop(ix);
    std::fs::remove_dir_all(dir).unwrap();
}

pub(super) fn entry(subject: &str, from: &str, id: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: from.into(),
        message_id: format!("<{id}>"),
        bytes,
        date: 0,
    }
}

/// `entry()` hardcodes date=0 and its 4th argument is BYTES, so it
/// cannot express "posted at time T" - and a tiny payload scores as
/// junk (55), which the wall hides. This one sets a real Date and a
/// plausible size.
pub(super) fn dated_entry(subject: &str, id: &str, posted: i64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: "poster@example".into(),
        message_id: format!("<{id}>"),
        bytes: 4_000_000_000,
        date: posted,
    }
}

/// What a budgeted fold's slice costs on THIS box, priced in two parts,
/// for the end-to-end pacer test in `sessionfold_tests` (and for an
/// `albumfold_tests` twin, if one is ever found a fixture that holds
/// its walls - section 7 of
/// research/FOLD-BUDGET-DERIVATION-CENSUS-2026-09-17.md is why the
/// first attempt did not land).
///
/// The derivation is the one `a_fold_slice_declines_a_unit_it_has_no_time_for`
/// (`predb_tests::correlation_tests`) arrived at for `shatter_fold` on
/// 17 Sep 2026, and that test's comments are the record of every
/// simpler formulation that was tried and what each one did on a shared
/// box. It lives here so the two folds that share `FoldPace` with the
/// shatter fold share one copy of the arithmetic, rather than a third
/// and fourth that can drift back to `held / folds`. The shatter test
/// keeps its own inline copy on purpose: its comments ARE the incident
/// record and are read in place.
///
/// A budgeted fold call is a population READ - the pacer's own first
/// unit, which always runs whatever the clock says (see `foldpace`) -
/// followed by a run of merges, each admitted only while the time left
/// covers the dearest unit so far. The two behave differently under
/// load and the budget needs both, so they are priced separately:
///
/// * `read_mid` / `read_lo`: the read, sampled at a ZERO budget, where
///   a call does exactly the read, declines the first merge, folds
///   nothing and - because every one of these folds writes its cursor
///   only after a whole window survives its merge loop - leaves the
///   fixture untouched. Free to sample, so sampled five times. The
///   MEDIAN sets the admission floor (a slice takes its first merge
///   only while `budget - read >= read`) and starts the probe; the
///   cheapest is what gets subtracted below so the subtraction cannot
///   eat the merge it is isolating.
/// * `fold`: one merge's own cost, from the first escalating probe
///   round that buys any merge at all (a round that folds nothing
///   spends nothing, a round that folds two spends two for good, so
///   the first round to fold anything is the minimum-overshoot stop),
///   and the LESSER of that round and one more at the same budget. The
///   read is subtracted from what a round held; the naive rate with
///   the read counted as one more unit is a floor under it, for the
///   case where the round's own read beat every zero-budget sample and
///   the subtraction leaves nothing.
///
/// WHERE THIS DIFFERS FROM THE SHATTER TEST, AND WHY - both are
/// measured, both spend no fixture worth counting, and neither is a
/// simplification back to a rate:
///
/// * The shatter test takes the DEAREST of three read samples for the
///   floor and the probe start. Measured on the dev Mac at load
///   130-180 on the album fold: two runs in five drew one sample of
///   265 ms and 333 ms against a 5 ms read, and that one sample
///   started the probe at 530-665 ms, which bought 20-36 of the 100
///   units in its first round - the fixture guard's failure - and
///   then put 530 ms of "admission floor" into the slice's budget,
///   which after an honest 5 ms read is a hundred merges' worth of
///   room: the far wall, dressed as the floor. The floor only buys
///   admission when the slice's read costs about what the sample did.
///   A median of five ignores two outliers; the near wall it gives up
///   is a slice whose own read is dilated past `1 + UNITS * fold /
///   (2 * read)`, about sixfold here, which is what the `UNITS` term
///   was already buying.
/// * The shatter test prices a fold from ONE round. One preempted
///   round - 98 ms held for one merge, measured on the session fold at
///   load ~135 - prices a 3.5 ms merge at 93 ms and buys a 944 ms
///   slice, which folded 77 of 99. A second round at the same budget
///   costs about what the first bought (one or two units, out of a
///   hundred) and a preemption has to land on both to survive the
///   minimum.
///
/// `call(budget)` runs one slice and answers (units folded, caught up).
/// `built_in` is how long the fixture took to BUILD: the probe's
/// escalation ceiling is in the box's own units and never a constant
/// number of seconds, because a constant tightens exactly on the box
/// where the work is slowest. The regression the ceiling exists for is
/// a pacer that refuses units it has time for, which folds at no budget
/// and would otherwise escalate for ever.
pub(super) struct FoldProbe {
    pub read_mid: std::time::Duration,
    pub fold: std::time::Duration,
    /// Units the probe spent out of the fixture, which the caller's
    /// fixture guard has to subtract before it can say whether a slice
    /// is still meaningful.
    pub spent: usize,
}

pub(super) fn probe_fold_cost(
    built_in: std::time::Duration,
    mut call: impl FnMut(std::time::Duration) -> (usize, bool),
) -> FoldProbe {
    use std::time::{Duration, Instant};
    const READ_SAMPLES: usize = 5;
    // ONE WARM CALL, DISCARDED, before anything is priced. The slice
    // under test is never a fold's first call - it comes after the
    // samples and the probe - so the samples must price what a warm
    // call pays and not what a first one does. A first call pays for
    // things no later call sees: the statement cache is cold, and
    // `album_fold` writes `album_fold_floor` on its first call, which
    // is a committed WRITE that a zero-budget read sample would
    // otherwise carry into the floor. It spends no fixture: a
    // zero-budget call folds nothing and moves no cursor, which the
    // caller asserts after the probe.
    let (n, done) = call(Duration::ZERO);
    assert_eq!(n, 0, "the warm call folded units at a zero budget");
    assert!(!done, "the warm call caught up at a zero budget");
    let mut reads = Vec::with_capacity(READ_SAMPLES);
    for _ in 0..READ_SAMPLES {
        let t = Instant::now();
        let (n, done) = call(Duration::ZERO);
        let held = t.elapsed();
        assert_eq!(
            n, 0,
            "a zero-budget call folded units, so it is not the fixed cost \
             this is trying to price - and it spent fixture doing it"
        );
        assert!(!done, "the read samples must leave units for the slice");
        reads.push(held);
    }
    reads.sort_unstable();
    let (read_lo, read_mid) = (reads[0], reads[READ_SAMPLES / 2]);
    eprintln!("READSAMPLES {reads:?}");
    let mut spent = 0usize;
    // One round's estimate: the read subtracted, floored by the naive
    // rate with the read counted as one more unit.
    let estimate = |held: Duration, folds: usize| {
        let folds = folds as u32;
        (held.saturating_sub(read_lo) / folds).max(held / (folds + 1))
    };
    // Start where a budget stops folding nothing: the admission floor.
    let mut probe = read_mid * 2;
    let fold = loop {
        let t = Instant::now();
        let (folds, done) = call(probe);
        let held = t.elapsed();
        spent += folds;
        eprintln!("PROBEROUND probe={probe:?} held={held:?} folds={folds}");
        assert!(!done, "the probe must leave units for the slice");
        if folds > 0 {
            let first = estimate(held, folds);
            let t = Instant::now();
            let (folds, done) = call(probe);
            let held = t.elapsed();
            spent += folds;
            eprintln!("PROBEROUND probe={probe:?} held={held:?} folds={folds} (second)");
            assert!(!done, "the probe must leave units for the slice");
            break if folds > 0 {
                first.min(estimate(held, folds))
            } else {
                first
            };
        }
        assert!(
            probe < built_in,
            "the probe escalated past {built_in:?}, the cost of building \
             the whole fixture, without buying a fold - on any box that \
             is a fold refusing units it has time for rather than a box \
             that is slow"
        );
        probe *= 4;
    };
    eprintln!("PROBE read_lo={read_lo:?} read_mid={read_mid:?} fold={fold:?} spent={spent}");
    FoldProbe {
        read_mid,
        fold,
        spent,
    }
}

impl FoldProbe {
    /// The admission floor plus `units` merges' worth. Only the second
    /// term buys work, so a slice's spend out of the fixture is
    /// proportional to `units` whatever the box did to the read.
    pub(super) fn budget(&self, units: u32) -> std::time::Duration {
        self.read_mid * 2 + self.fold * units
    }
}
