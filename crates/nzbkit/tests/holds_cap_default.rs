//! TODO 260: a bare `Extractor::new` inherits the PUBLISHED process
//! budget's holds slice.
//!
//! The defect this pins is silent by construction. `set_process_budget`
//! is the knob every other memory consumer reads implicitly, so a rig
//! that pins a small budget and then builds a bare extractor looks
//! wired - and before this change chased against a flat 2 GiB instead.
//! The TODO 209 dict-window rig did exactly that, and the unbounded
//! container buffering it produced was written up as an untracked
//! allocation wanting a new budget tier (TODO 256,
//! `research/NOTE-2026-08-22-nested-container-buffer-rss.md`).
//!
//! Its own test binary on purpose: `set_process_budget` is process-wide,
//! so publishing one inside the lib suite would change the default under
//! every other extract test sharing that process under plain
//! `cargo test`.
//!
//! test-target-gate: asserts what a VIRGIN process answers before any
//! `set_process_budget`, which cannot be un-published - even its
//! partials sibling cannot share the binary under `cargo test`

use nzbkit::extract::Extractor;
use nzbkit::mem::MemBudget;

const MIB: usize = 1 << 20;

#[test]
fn a_bare_extractor_inherits_the_published_budgets_holds_slice() {
    let dir = std::env::temp_dir().join(format!("nzbfast-holdscap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Unpublished: the flat default, host-independent. Asserted as a
    // RANGE with a floor well above any `MemBudget::auto` slice a small
    // CI runner would produce, so a regression that routed this through
    // `process_budget` (which substitutes `auto`) fails here rather than
    // passing on whichever box happened to run it.
    let before = Extractor::new(&dir, 1, true).holds_cap();
    assert_eq!(
        before,
        2 << 30,
        "with nothing published the default must stay the flat 2 GiB the \
         extract suite was written against"
    );

    // Published: 45% of it, and nothing near the flat default.
    let budget = MemBudget::with_total(256 * MIB as u64);
    nzbkit::mem::set_process_budget(budget);
    let after = Extractor::new(&dir, 1, true).holds_cap();
    assert_eq!(
        after,
        budget.holds_cap(),
        "a published budget must reach a bare Extractor::new"
    );
    assert!(
        after < before,
        "256 MiB published ({} MiB slice) must not still be the 2 GiB default",
        after / MIB
    );

    // The smallest budget the type admits (`with_total` clamps up to
    // `MIN`) still clears the 8 MB `set_holds_cap` floor, so the floor is
    // unreachable this way - pinned so a future MIN cut notices it is
    // now the binding constraint rather than the slice.
    nzbkit::mem::set_process_budget(MemBudget::with_total(0));
    let smallest = Extractor::new(&dir, 1, true).holds_cap();
    assert_eq!(smallest, MemBudget::with_total(0).holds_cap());
    assert!(smallest >= 8 << 20, "floor: {smallest}");

    let _ = std::fs::remove_dir_all(&dir);
}
