//! The integration suites' scratch guard, reachable from the lib's own
//! unit tests.
//!
//! It is INCLUDED AS SOURCE rather than imported: `tests/scratch/mod.rs`
//! belongs to the integration targets and a `tests/` module cannot be
//! imported by a lib or bin any other way. One include per crate, from
//! here, so the whole tree holds the SAME type and the sweep's `Once`
//! fires once per process rather than once per including module.
//!
//! Use it for any test that puts a directory in the OS temp dir. A test
//! that rolls its own `temp_dir().join(..)` and never removes it leaves
//! one entry per RUN - nextest gives every test its own process - and
//! measured on 31 Aug 2026 that was 53,945 entries in $TMPDIR from 65
//! such sites, which every readdir on that directory then pays for, the
//! sweep in `tests/scratch/mod.rs` above all.

#[path = "../tests/scratch/mod.rs"]
mod guard;

pub(crate) use guard::ScratchDir;
