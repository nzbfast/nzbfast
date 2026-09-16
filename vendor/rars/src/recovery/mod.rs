//! Recovery-record primitives shared by RAR writer and repair code.
//!
//! RAR 5 recovery data uses GF(2^16) with reduction polynomial `0x1100b`
//! and a Cauchy encoder matrix. This crate intentionally exposes the field
//! and matrix building blocks before wiring them into archive serialization.

mod gf16_fold;
// nzbfast-local change, 16 Sep 2026 - the work counters the refusal tests
// assert instead of a wall clock. Re-apply on the next rars re-sync; see
// `vendor/rars/VENDORING.md`. In the fork as `5d553f4` on `perf`.
pub(crate) mod workgauge;
pub mod rar3;
pub mod rar5;
pub mod stream;
