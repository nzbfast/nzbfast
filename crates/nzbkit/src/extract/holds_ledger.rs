//! Process-wide held-span ledger: the holds cap shared across pipelines
//! that are alive at the same time (TODO 219 follow-up, 22 Aug 2026).
//!
//! Since the cross-job hand-over, job N+1's pipeline runs while job N's
//! drains and its tail unpacks, and each pipeline's [`HoldsBudget`] was
//! cut from the same `MemBudget::holds_cap()` (45% of the budget) - so
//! two pipelines could between them hold 2 x 45%. Measured on a big-RAM
//! 1 GbE box at 100 Mbit: live `holds` 2003 MB (two compressed-RAR5
//! hold sets of 1002 MB each), RSS peak 7.5 GB against 4.8 GB with the
//! hand-over off.
//! On a 16 GB box (budget ~4 GB, cap ~1.8 GB) the successor would trip
//! the spill during every overlap.
//!
//! The ledger seats every budget that joins it in join order. A budget's
//! EFFECTIVE cap is its own cap minus the live held bytes of every seat
//! senior to it (joined earlier and still alive), floored at the same
//! 8 MB `set_holds_cap` floors at. So:
//! - one pipeline alone (no seniors) sees exactly its own cap - byte-
//!   identical to the pre-ledger behaviour, single-job paths unchanged;
//! - a successor sees the remainder, which grows back as the
//!   predecessor's holds drain and unpack, and the process never holds
//!   more than one cap (plus the floor) between the two.
//! Seniority rather than a symmetric sum on purpose: the predecessor is
//! the job on the lane, the one whose holds are being consumed right
//! now, and it must not start paging because a successor that has all
//! the time in the world filled the shared slice behind it.
//!
//! Opt-in, not ambient: the daemon installs one ledger per process
//! ([`install_process_ledger`]) and the rig joins each job's root
//! extractor to it. `nzbfast get`, the repair path and in-process unit
//! tests never install one, so they see no sharing - `memgauge::Holds`
//! already counts holds process-wide and is exactly the cross-test noise
//! a ledger read straight off the gauge would import. A nested child
//! shares its parent's `HoldsBudget` Arc and therefore its seat.

use super::holds::HoldsBudget;
use crate::sync::MutexExt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// The ledger: the seated budgets, in join order. Seats are weak, so a
/// finished pipeline drops out of the sum the moment its extractor is
/// dropped and nothing has to remember to leave.
#[derive(Default)]
pub struct HoldsLedger {
    seats: Mutex<Vec<(u64, Weak<HoldsBudget>)>>,
    next: Mutex<u64>,
}

impl HoldsLedger {
    pub fn new() -> HoldsLedger {
        HoldsLedger::default()
    }

    /// Seat a budget; the returned id ranks it after every earlier seat.
    pub(super) fn join(&self, budget: &Arc<HoldsBudget>) -> u64 {
        let id = {
            let mut n = self.next.lock_ok();
            *n += 1;
            *n
        };
        let mut seats = self.seats.lock_ok();
        seats.retain(|(_, w)| w.strong_count() > 0);
        seats.push((id, Arc::downgrade(budget)));
        id
    }

    /// Live held bytes of every seat senior to `id`.
    pub(super) fn senior_bytes(&self, id: u64) -> usize {
        let seats = self.seats.lock_ok();
        seats
            .iter()
            .filter(|(sid, _)| *sid < id)
            .filter_map(|(_, w)| w.upgrade())
            .map(|b| b.bytes.load(Ordering::Relaxed))
            .fold(0usize, |a, n| a.saturating_add(n))
    }

    /// Held bytes of EVERY live seat, senior or not.
    ///
    /// What a budget joining right now would have taken off its own cap:
    /// a new seat is junior to all of them, so `senior_bytes` for it is
    /// exactly this. TODO 309(a), 27 Aug 2026 - `plan.rs
    /// resume_map_admits` decides before any extractor exists, so it has
    /// no seat to ask and reads this instead. Dynamic and therefore only
    /// ever an estimate: a predecessor's holds drain while the resumed
    /// job sets up, so this reads high, which is the safe direction for
    /// a gate that spends the remainder.
    pub fn live_bytes(&self) -> usize {
        self.seats
            .lock_ok()
            .iter()
            .filter_map(|(_, w)| w.upgrade())
            .map(|b| b.bytes.load(Ordering::Relaxed))
            .fold(0usize, |a, n| a.saturating_add(n))
    }

    /// Seats still alive (diagnostic / test hook).
    pub fn live_seats(&self) -> usize {
        self.seats
            .lock_ok()
            .iter()
            .filter(|(_, w)| w.strong_count() > 0)
            .count()
    }
}

static PROCESS_LEDGER: OnceLock<Arc<HoldsLedger>> = OnceLock::new();

/// Install the process-wide ledger (the daemon, once at boot). A second
/// call keeps the first ledger - seats must never split across two.
pub fn install_process_ledger() -> Arc<HoldsLedger> {
    PROCESS_LEDGER
        .get_or_init(|| Arc::new(HoldsLedger::new()))
        .clone()
}

/// The installed ledger, if any. `None` everywhere but the daemon.
pub fn process_ledger() -> Option<Arc<HoldsLedger>> {
    PROCESS_LEDGER.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Extractor;
    use crate::extract::testutil::tmpdir;

    fn rig(dir: &std::path::Path, ledger: &Arc<HoldsLedger>, cap: usize) -> Extractor {
        let ex = Extractor::new(dir, 4, true);
        ex.set_holds_cap(cap);
        ex.join_holds_ledger(ledger);
        ex
    }

    /// TODO 309(a): `live_bytes` is what a budget joining NEXT would have
    /// taken off its own cap - every live seat, not the ones senior to
    /// some existing id. `plan.rs resume_map_admits` reads it before any
    /// extractor exists, so there is no seat to ask `senior_bytes` about.
    #[test]
    fn live_bytes_is_what_the_next_seat_would_lose() {
        let dir = tmpdir("holds-ledger-live-bytes");
        let ledger = Arc::new(HoldsLedger::new());
        let cap = 64 << 20;
        assert_eq!(
            ledger.live_bytes(),
            0,
            "an empty ledger costs a joiner nothing"
        );

        let first = rig(&dir, &ledger, cap);
        let b1 = first.holds_budget_for_tests();
        b1.add(10 << 20);
        assert_eq!(ledger.live_bytes(), 10 << 20);

        let second = rig(&dir, &ledger, cap);
        let b2 = second.holds_budget_for_tests();
        b2.add(5 << 20);
        // Both seats count, and it agrees with what a third seat's own
        // `senior_bytes` says - which is the property that makes this a
        // sound estimate of the cap a joiner would get.
        assert_eq!(ledger.live_bytes(), 15 << 20);
        let third = rig(&dir, &ledger, cap);
        let b3 = third.holds_budget_for_tests();
        assert_eq!(b3.cap(), cap - (15 << 20));

        // A finished pipeline stops costing the next joiner anything.
        b1.sub(10 << 20);
        drop(b1);
        drop(first);
        assert_eq!(ledger.live_bytes(), 5 << 20);
        b2.sub(5 << 20);
    }

    /// Two pipelines on one ledger share ONE cap: the eldest keeps the
    /// whole slice, the successor sees the remainder, and the remainder
    /// grows back as the eldest's holds release. Alone, a budget's
    /// effective cap is exactly its own cap.
    #[test]
    fn two_pipelines_share_one_holds_cap() {
        let dir = tmpdir("holds-ledger-share");
        let ledger = Arc::new(HoldsLedger::new());
        let cap = 64 << 20;
        let first = rig(&dir, &ledger, cap);
        let b1 = first.holds_budget_for_tests();
        // Alone: the full cap, byte-identical to the unshared budget.
        assert_eq!(b1.cap(), cap);
        b1.add(40 << 20);
        assert_eq!(b1.cap(), cap, "the eldest never sees a successor");
        assert!(!b1.over());

        let second = rig(&dir, &ledger, cap);
        let b2 = second.holds_budget_for_tests();
        assert_eq!(ledger.live_seats(), 2);
        // The successor's cap is the remainder the eldest left.
        assert_eq!(b2.cap(), 24 << 20);
        b2.add(24 << 20);
        assert!(!b2.over());
        b2.add(1);
        assert!(b2.over(), "the pair together must not exceed one cap");
        // The eldest is untouched by the successor filling the slice.
        assert_eq!(b1.cap(), cap);
        assert!(!b1.over());

        // The eldest drains: the successor's remainder grows back.
        b1.sub(30 << 20);
        assert_eq!(b2.cap(), 54 << 20);
        assert!(!b2.over());
        b2.sub((24 << 20) + 1);

        // The eldest finishes: its seat dies with it, the successor is
        // now the eldest and owns the whole cap.
        b1.sub(10 << 20);
        drop(b1);
        drop(first);
        assert_eq!(b2.cap(), cap);
        assert_eq!(ledger.live_seats(), 1);

        // Floor: a predecessor over the whole cap leaves the successor
        // the 8 MB floor, never zero (or a wrapped cap).
        let third = rig(&dir, &ledger, cap);
        let b3 = third.holds_budget_for_tests();
        b2.add(cap + (1 << 20));
        assert_eq!(b3.cap(), 8 << 20);
        b2.sub(cap + (1 << 20));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a ledger nothing changes: cap() is the raw cap whatever
    /// other extractors in the process hold.
    #[test]
    fn unseated_budget_is_unshared() {
        let dir = tmpdir("holds-ledger-unseated");
        let a = Extractor::new(&dir, 4, true);
        let b = Extractor::new(&dir, 4, true);
        a.set_holds_cap(16 << 20);
        b.set_holds_cap(16 << 20);
        a.holds_budget_for_tests().add(100 << 20);
        assert_eq!(b.holds_budget_for_tests().cap(), 16 << 20);
        a.holds_budget_for_tests().sub(100 << 20);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The process ledger installs once; a second install returns the
    /// same ledger.
    #[test]
    fn process_ledger_installs_once() {
        let a = install_process_ledger();
        let b = install_process_ledger();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(process_ledger().is_some_and(|l| Arc::ptr_eq(&l, &a)));
    }
}
