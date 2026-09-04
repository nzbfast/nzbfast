//! The folded rars integration target - one link instead of one per
//! file, the same fold `crates/nzbfast/tests/integration` made on
//! 17 Aug 2026 (9ef264fc6). nextest still runs every test in its own
//! process, so nothing about isolation changes; what changes is that
//! per-push CI links ONE executable for these suites instead of two.
//! Audit: research/TEST-BINARY-FOLD-AUDIT-2026-09-01.md.
//!
//! `striped_repair_memory` stays OUT of this target on purpose - it
//! measures the process's resident set size and its header requires a
//! process holding exactly one test, which a fold would silently break
//! under plain `cargo test` (one process per target, tests on threads).
//! A new rars test file belongs HERE as a module unless it has that
//! kind of process-wide claim, stated in its header.

// Directory entries must extract as directories, never 0-byte files.
mod directory_entries;
// Multi-group RAR5 recovery against real WinRAR output; every test
// `#[ignore]`d (needs the proprietary `rar` binary, not in CI).
mod winrar_recovery;
