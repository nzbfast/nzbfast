//! TODO 265: a bare `LiveVerifier::new` inherits the PUBLISHED process
//! budget's partials slice.
//!
//! The sibling of `holds_cap_default.rs` (TODO 260) and pinned for the
//! same reason, one tier down. It is not a live memory bug: the only
//! production verifier is built by `crates/nzbfast-engine/src/get/vrig.rs`,
//! which already passes `budget.partials_cap()`. It is the same latent
//! trap - `set_process_budget` is the knob every other memory consumer
//! reads implicitly, so a rig that pins a small budget and then builds a
//! bare verifier looks wired, and before this change buffered against a
//! flat 256 MiB instead. On the extractor tier that exact shape cost a
//! measurement day (TODO 209 / 256).
//!
//! Its own test binary on purpose: `set_process_budget` is process-wide,
//! so publishing one inside the lib suite would change the default under
//! every other verify test sharing that process under plain
//! `cargo test`.
//!
//! test-target-gate: asserts what a VIRGIN process answers before any
//! `set_process_budget`, which cannot be un-published - even its holds
//! sibling cannot share the binary under `cargo test`

use nzbkit::live::LiveVerifier;
use nzbkit::mem::MemBudget;

const MIB: usize = 1 << 20;

#[test]
fn a_bare_live_verifier_inherits_the_published_budgets_partials_slice() {
    // Unpublished: the flat default, host-independent. A regression that
    // routed this through `process_budget` (which substitutes `auto` -
    // RAM/4 clamped to [256 MiB, 16 GiB], so 30% of it is anywhere from
    // 76 MiB to 4.8 GiB) fails here rather than passing on whichever box
    // happened to run it.
    let before = LiveVerifier::new(1).partials_cap();
    assert_eq!(
        before,
        256 * MIB,
        "with nothing published the default must stay the flat 256 MiB the \
         verify suite was written against"
    );

    // Published: 30% of it, and nothing near the flat default.
    let budget = MemBudget::with_total(256 * MIB as u64);
    nzbkit::mem::set_process_budget(budget);
    let after = LiveVerifier::new(1).partials_cap();
    assert_eq!(
        after,
        budget.partials_cap(),
        "a published budget must reach a bare LiveVerifier::new"
    );
    assert!(
        after < before,
        "256 MiB published ({} MiB slice) must not still be the 256 MiB default",
        after / MIB
    );

    // An explicit cap still wins over the published one - `vrig.rs` and
    // every rig that names a figure keep saying exactly what they meant.
    assert_eq!(
        LiveVerifier::with_partials_cap(1, 4 * MIB).partials_cap(),
        4 * MIB
    );

    // The smallest budget the type admits (`with_total` clamps up to
    // `MIN`) still clears the 1 MB floor, so the floor is unreachable
    // this way - pinned so a future MIN cut notices it is now the binding
    // constraint rather than the slice.
    nzbkit::mem::set_process_budget(MemBudget::with_total(0));
    let smallest = LiveVerifier::new(1).partials_cap();
    assert_eq!(smallest, MemBudget::with_total(0).partials_cap());
    assert!(smallest >= MIB, "floor: {smallest}");
}
