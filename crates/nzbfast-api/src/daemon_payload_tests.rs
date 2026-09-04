//! Daemon-layer behaviour asserted through the SAB QUEUE PAYLOAD.
//!
//! These five were `crates/nzbfast-daemon/src/daemon_tests/*.rs` until
//! lane 2 of the serve split. Each composes a daemon-layer item with
//! `sabcompat::queue_json`, which is api-layer and stayed in the bin, so
//! they are in the only crate that can see both halves - the same answer
//! steps 2, 3 and 4 of
//! `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md` reached for the
//! four tests each of them could not take down.
//!
//! They are RELOCATED, not rewritten: every assertion is verbatim and
//! every `#[path]` declaration below carries the prose it had in
//! `daemon_tests.rs`. What changed is that `super::` now means `serve`
//! rather than the daemon crate root, so a name that was a sibling
//! module's is spelled through serve's re-import of that unit.

#[path = "daemon_payload_tests/notice_tests.rs"]
mod notice_tests;

// TODO 205's disk-unpack counters on the queue row, out for the ceiling
// and carrying the same #[path] requirement.
#[path = "daemon_payload_tests/unpack_progress_tests.rs"]
mod unpack_progress_tests;

// The idle-server early start's banked bytes on the queue row and its
// rate in the header, out for the ceiling and carrying the same #[path]
// requirement.
#[path = "daemon_payload_tests/prefetch_progress_tests.rs"]
mod prefetch_progress_tests;

// B5's queue window, out for the ceiling and carrying the same
// #[path] requirement.
#[path = "daemon_payload_tests/queue_window_tests.rs"]
mod queue_window_tests;

// Queue durability and the locks around it: the §158 item 7 crash
// window, the queue-lock hold, the idle-scan CAS window and the
// wind-down. Moved out under the size gate (TODO 106); the three
// fixtures above it stay here because three other children drive them.
//
// #[cfg(test)] as well as #[path], unlike the fourteen declarations
// above: it is what size-gate.py's CFG_TEST_MOD resolver matches, and
// without it the child is scored as PRODUCTION code and its test
// functions judged at the 500-line fn ceiling.
#[cfg(test)]
#[path = "daemon_payload_tests/durability_tests.rs"]
mod durability_tests;
