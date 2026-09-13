//! Recovery-record primitives shared by RAR writer and repair code.
//!
//! RAR 5 recovery data uses GF(2^16) with reduction polynomial `0x1100b`
//! and a Cauchy encoder matrix. This crate intentionally exposes the field
//! and matrix building blocks before wiring them into archive serialization.

mod gf16_fold;
pub mod rar3;
pub mod rar5;
pub mod stream;
