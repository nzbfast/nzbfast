//! Test-only seam for the racing window [`super::open_out_leaf_under`]
//! closes (31 Aug 2026 residue item 3): a hook `walk_out_dirs` fires the
//! instant it hands back the last directory component it bound, before
//! the caller does anything with it.
//!
//! In its own file rather than inline in `relpath.rs`, on purpose:
//! `impl Drop` has to be spelled `fn drop`, and `relpath.rs`'s own tests
//! are full of ordinary bare `drop(f)` calls that have nothing to do
//! with this seam. Kept apart, [`AFTER_WALK`] never becomes the only
//! same-named item in that file - which is what `cfg-symbol-gate`'s
//! SAME-FILE arm resolves a bare, unqualified reference against, with
//! no check that the definition it found actually needs qualifying.
//! Rust itself never resolves a bare `drop(x)` to some unrelated type's
//! associated `Drop::drop`, so a `fn drop` living here rather than there
//! is the fix, not a workaround.

use std::cell::RefCell;

thread_local! {
    /// THREAD-local and not a shared static (CLAUDE.md's test-global-gate
    /// class): each test's own thread arms and consumes its own hook, so
    /// two tests racing this file's own tests cannot fight over one flag
    /// the way a process-global would. Consumed by its single trip inside
    /// `walk_out_dirs`, and cleared again by [`AfterWalkGuard`]'s `Drop`
    /// for the path where the walk errors before ever reaching it.
    pub(super) static AFTER_WALK: RefCell<Option<Box<dyn FnOnce()>>> =
        const { RefCell::new(None) };
}

/// RAII handle from [`after_walk`]. Dropping it - including on an early
/// return, a panic, or a walk that never reaches the hook at all -
/// clears [`AFTER_WALK`], so a forgotten guard cannot leak a stale
/// closure into whatever test runs next on this thread.
pub(super) struct AfterWalkGuard;

impl Drop for AfterWalkGuard {
    fn drop(&mut self) {
        AFTER_WALK.with(|h| *h.borrow_mut() = None);
    }
}

/// Arm [`AFTER_WALK`] for the next `walk_out_dirs` call on this thread.
/// Hold the returned guard for the duration of the call the hook belongs
/// to.
pub(super) fn after_walk(f: impl FnOnce() + 'static) -> AfterWalkGuard {
    AFTER_WALK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    AfterWalkGuard
}
