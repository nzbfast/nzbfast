//! §158 item 7: fault injection for the two durable store writes, so the
//! "lost from BOTH stores" shapes can be measured rather than described.
//!
//! A record moving in or out of the live queue is TWO independent writes
//! - `.spool/queue.json` (`Daemon::save_queue`) and `.spool/history.jsonl`
//! (`Daemon::history_write_locked`) - and §158 fixed their ORDER: the
//! destination store goes first, so a tear reads "in both stores"
//! (reconcilable at load) rather than "in neither" (unrecoverable). Order
//! is only provable by stopping partway, which is what this module does.
//!
//! Two seams, both `#[cfg(test)]`, both thread-local so a test that calls
//! `enqueue`/`park` inline is the only thread affected:
//!
//!  * [`arm_cut`] lets N further durable writes land and drops every one
//!    after that. `arm_cut(1)` is a kill between a path's first and second
//!    write - the exact window the ordering exists for. Restoring a Daemon
//!    over the kept spool directory then reads the bytes a crash would
//!    have left, not a fixture somebody hand-wrote to match their belief.
//!    It is a BUDGET SPANNING BOTH STORES and not a per-store switch,
//!    which is easy to misread: on a path that writes history first,
//!    `arm_cut(1)` refuses the QUEUE save and `arm_cut(0)` refuses both.
//!  * [`arm_store_cut`] names the STORES to refuse instead of counting
//!    writes, which is the shape a permission fault has rather than the
//!    shape a kill has. P2-1's trigger is exactly that and cannot be
//!    written as a budget at all: `history.jsonl` left 0444 or owned by
//!    a uid this daemon no longer runs as refuses the APPEND for the
//!    life of the process while `queue.json` - and the atomic rewrite,
//!    which needs the DIRECTORY rather than the file - keep working.
//!    That asymmetry is what `Daemon::history_publish` rescues a refused
//!    append with, so a test of the rescue has to be able to refuse one
//!    side and not the other. The two arms compose: the mask is checked
//!    first, then the budget.
//!  * [`on_park_gap`] fires once, at the instant `Daemon::park` has
//!    dropped the row from the live queue. That window is a race rather
//!    than a kill - any other thread's `save_queue` publishes a queue.json
//!    without the row - so the test runs that save itself, right there,
//!    instead of hoping a background thread lands inside a few hundred
//!    microseconds.

use super::*;
use std::cell::{Cell, RefCell};

/// Which durable write a seam is standing in front of.
///
/// A discriminant per store rather than an index, so [`arm_store_cut`]
/// can hold a set of them in one `u8` and a seam asks one `&`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::serve) enum Store {
    /// `Daemon::save_queue`'s `queue.json` write. Atomic: temp file plus
    /// rename, so it needs the DIRECTORY.
    Queue = 1,
    /// `Daemon::history_write_locked`'s append to `history.jsonl`. Needs
    /// write permission ON THE FILE, which is the asymmetry P2-1 turns on.
    HistoryAppend = 2,
    /// `Daemon::history_rewrite_locked`'s atomic replacement of the whole
    /// store - the RESCUE a refused append falls back to, and the one
    /// that needs only the directory.
    HistoryRewrite = 4,
}

thread_local! {
    /// Durable store writes still allowed on this thread. `None` means no
    /// cut is armed and everything writes normally; `Some(0)` drops every
    /// further write.
    static BUDGET: Cell<Option<u32>> = const { Cell::new(None) };
    /// Stores refused outright on this thread, as a mask of [`Store`]
    /// discriminants; see [`arm_store_cut`].
    static STORES: Cell<u8> = const { Cell::new(0) };
    /// One-shot callback for the park window; see [`on_park_gap`].
    static PARK_GAP: RefCell<Option<Box<dyn FnOnce(&Daemon)>>> = const {
        RefCell::new(None)
    };
    /// One-shot callback for the activation window; see
    /// [`on_activate_gap`].
    static ACTIVATE_GAP: RefCell<Option<Box<dyn FnOnce(&Daemon)>>> = const {
        RefCell::new(None)
    };
    /// One-shot callback for the promotion window; see
    /// [`on_promote_gap`].
    static PROMOTE_GAP: RefCell<Option<Box<dyn FnOnce(&Daemon)>>> = const {
        RefCell::new(None)
    };
    /// One-shot callback for the early-publish window; see
    /// [`on_early_rename_gap`].
    static EARLY_RENAME_GAP: RefCell<Option<Box<dyn FnOnce(&Daemon)>>> = const {
        RefCell::new(None)
    };
}

/// Let `writes` further durable store writes land on this thread, then
/// drop every one after them. Disarmed by [`disarm`], never implicitly -
/// a test that leaves it armed would silently mute the next test on the
/// same thread.
pub(in crate::serve) fn arm_cut(writes: u32) {
    BUDGET.with(|b| b.set(Some(writes)));
}

/// Refuse every write to `stores` on this thread, for as long as the arm
/// stands - a PERMISSION fault rather than a kill, so it does not run
/// out the way [`arm_cut`]'s budget does.
///
/// Independent of that budget and checked before it, so the two can be
/// armed together. Disarmed by [`disarm`], never implicitly.
pub(in crate::serve) fn arm_store_cut(stores: &[Store]) {
    STORES.with(|s| s.set(stores.iter().fold(0u8, |m, st| m | *st as u8)));
}

pub(in crate::serve) fn disarm() {
    BUDGET.with(|b| b.set(None));
    STORES.with(|s| s.set(0));
    PARK_GAP.with(|g| *g.borrow_mut() = None);
    ACTIVATE_GAP.with(|g| *g.borrow_mut() = None);
    PROMOTE_GAP.with(|g| *g.borrow_mut() = None);
    EARLY_RENAME_GAP.with(|g| *g.borrow_mut() = None);
}

/// Called by the durable-write seams themselves. `true` means this write
/// must NOT happen, which is what a kill - or a store this daemon cannot
/// write - leaves on disk.
///
/// [`Store::HistoryRewrite`] is deliberately OUTSIDE the budget and
/// reachable only through [`arm_store_cut`]. The budget models a kill,
/// and the rewrite is not a step on any ordinary path: it is the rescue
/// a refused append falls back to, and `history_compact` also runs it at
/// load and from "Save queue". Counting it would silently change what
/// `arm_cut(1)` means for every test already using one.
pub(in crate::serve) fn cut_here(store: Store) -> bool {
    if STORES.with(|s| s.get()) & store as u8 != 0 {
        return true;
    }
    if store == Store::HistoryRewrite {
        return false;
    }
    BUDGET.with(|b| match b.get() {
        None => false,
        Some(0) => true,
        Some(n) => {
            b.set(Some(n - 1));
            false
        }
    })
}

/// Run `f` the next time `park` drops a row from the live queue on this
/// thread. One shot: the second park in the same test is unaffected.
pub(in crate::serve) fn on_park_gap(f: impl FnOnce(&Daemon) + 'static) {
    PARK_GAP.with(|g| *g.borrow_mut() = Some(Box::new(f)));
}

/// The `park` side of [`on_park_gap`]. Taken out of the cell BEFORE it
/// runs, so a callback that parks again cannot re-enter itself.
pub(in crate::serve) fn park_gap(d: &Daemon) {
    let f = PARK_GAP.with(|g| g.borrow_mut().take());
    if let Some(f) = f {
        f(d);
    }
}

/// Run `f` the next time `activate_parked` has dropped a record from
/// history and not yet pushed it onto the queue on this thread. One
/// shot, like [`on_park_gap`].
pub(in crate::serve) fn on_activate_gap(f: impl FnOnce(&Daemon) + 'static) {
    ACTIVATE_GAP.with(|g| *g.borrow_mut() = Some(Box::new(f)));
}

/// The `activate_parked` side of [`on_activate_gap`].
pub(in crate::serve) fn activate_gap(d: &Daemon) {
    let f = ACTIVATE_GAP.with(|g| g.borrow_mut().take());
    if let Some(f) = f {
        f(d);
    }
}

/// Run `f` the next time `park_gen` reaches its spare-promotion
/// decision on this thread - after the record is in history and after
/// `life_emit_parked` has told the world the job failed, and before
/// anything is unpaused. One shot, like [`on_park_gap`].
///
/// A third seam because that window is a RACE and not a kill, so
/// `arm_cut` cannot describe it: a subscriber acting on `job.failed`
/// (an *arr script, a dashboard history delete) can remove the record
/// this promotion is about while park is still inside it. The test runs
/// that delete itself, right there, rather than hoping a background
/// thread lands inside a few microseconds - the same argument
/// [`on_park_gap`] makes.
///
/// `cfg(feature = "indexer")` unlike its three siblings, and only
/// because of who ARMS it: the one caller is
/// `a_history_delete_inside_the_park_drops_the_spare_instead_of_starting_it`
/// in `serve/daemon_tests/spare_tests.rs`, which is a §282 spare test
/// and gated on `indexer`. The seam itself is not indexer-specific and
/// the cfg comes off the day a slim test arms it. Its emit side,
/// [`promote_gap`], stays ungated: `park_gen` calls it from a
/// `#[cfg(test)]` line in EVERY test build, slim included, which is why
/// that half never warned.
///
/// Not `#[expect(dead_code)]`: that lint is rustc's and is judged in
/// every configuration, so an expectation fulfilled slim goes
/// unfulfilled in the default build.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn on_promote_gap(f: impl FnOnce(&Daemon) + 'static) {
    PROMOTE_GAP.with(|g| *g.borrow_mut() = Some(Box::new(f)));
}

/// The `park_gen` side of [`on_promote_gap`].
pub(in crate::serve) fn promote_gap(d: &Daemon) {
    let f = PROMOTE_GAP.with(|g| g.borrow_mut().take());
    if let Some(f) = f {
        f(d);
    }
}

/// Run `f` the next time §296's publish has renamed a copy into the
/// destination and not yet relocked the job to decide whether the
/// record is pushed. One shot, like [`on_park_gap`].
///
/// A fourth seam because that window is a RACE and not a kill: the file
/// is at the destination and on no record, so park's failed arm running
/// right there takes back everything EXCEPT it. The test runs settle's
/// state flip and the take itself, inside the window, rather than
/// hoping a background thread lands inside a few microseconds - the
/// same argument [`on_park_gap`] makes.
pub(in crate::serve) fn on_early_rename_gap(f: impl FnOnce(&Daemon) + 'static) {
    EARLY_RENAME_GAP.with(|g| *g.borrow_mut() = Some(Box::new(f)));
}

/// The `early_publish_one` side of [`on_early_rename_gap`].
pub(in crate::serve) fn early_rename_gap(d: &Daemon) {
    let f = EARLY_RENAME_GAP.with(|g| g.borrow_mut().take());
    if let Some(f) = f {
        f(d);
    }
}
