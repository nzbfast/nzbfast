//! The extraction, repair and filing layer of the nzbfast bin, lifted
//! out as its own crate by step 3 of
//! `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`.
//!
//! Every module here was a top-level module of `crates/nzbfast/src` and
//! moved with `git mv`; step 1 had already made the production module
//! graph a DAG, so this step is a file move and a `pub` widening rather
//! than a refactor. `crates/nzbfast/src/main.rs` and `lib.rs` re-import
//! each one under its OLD NAME (`pub(crate) use nzbfast_unpack::smart;`),
//! so every `crate::smart::...` path in the modules that stayed behind
//! resolves exactly as it did before.
//!
//! WHAT MAKES A MODULE UNPACK: it is above `nzbfast-core` and nothing in
//! `nzbfast-meta` reaches it. This crate and `nzbfast-meta` are SIBLINGS
//! - neither names the other, which is what lets cargo schedule the two
//! at the same time, and is the whole point of cutting them apart rather
//! than into one layer. `tools/modgraph.py --check` holds it from the
//! source side and the absence of a dependency line in Cargo.toml holds
//! it from the cargo side.
//!
//! WHY THE ITEMS ARE `pub` AND NOT `pub(crate)`: they were `pub(crate)`
//! while this was one crate, and a library's `pub(crate)` is invisible
//! to the bin. The widening is mechanical and was driven by the
//! compiler - only what nzbfast actually names crossed over.

// Matches both nzbfast roots and nzbfast-core: `job_json` in serve/ is
// one `json!` literal per persisted Job field and the macro recurses per
// key. Set here so a value type moved into this crate does not have to
// discover it.
#![recursion_limit = "256"]

// The bare names these modules reach through their own `use crate::*;`.
// They were main.rs's imports when this was one crate, and a glob of the
// crate root picks up an ancestor's private imports - so `Arc`,
// `PathBuf` and `lock_ok()` resolved through main.rs from inside these
// modules without ever naming it. That is an edge `tools/modgraph.py`
// cannot see (it reads `crate::X` paths, and these are bare names), so
// it is written out here rather than discovered again.
use anyhow::{Context, Result};
use nzbfast_core::tools::MutexExt;
use nzbkit::config::{Config, ServerConfig};
use nzbkit::nzb::{FileKind, Nzb};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

// The layer below, re-imported under the names the moved modules used
// while everything was one crate. `crate::diag::...` inside `unpack` has
// to keep resolving, and these lines are what make it: exactly the
// arrangement `crates/nzbfast/src/main.rs` uses for the same modules.
// The list is what the compiler leaves standing - a core module nothing
// here names is not re-imported, because `unused_imports` is `-D
// warnings` in this workspace and a `use` can be unused where a `mod`
// never could.
pub(crate) use nzbfast_core::{
    archname, diag, diskfree, eatvol, fileslot, lanegate, par2scan, persist, pwfile, relname,
    sizes, streamhub, tools, unpackprog,
};
// GATED where the rest are not, and the difference is what a `use` can
// say that a `mod` never could: the only thing here that names
// `failkind` is `repair::shortfall`'s clause pin, which is a test - so a
// production build binds a name nothing reads and `unused_imports` says
// so. Same shape as the bin's own `ratelimit` re-import.
#[cfg(test)]
pub(crate) use nzbfast_core::failkind;

pub mod check;
// Extraction: the RAR/7z/tar/zip ladder, the recovery-record probes and
// the native engines behind them.
pub mod rarfix;
// PAR2 verification and repair, plus the side fetch that buys the blocks
// a repair is short of.
pub mod repair;
// Resuming an interrupted extraction into an output directory.
pub mod resumeout;
// Self-extracting archives: the stub grammar and where the payload
// starts.
pub mod sfx;
// Filing: naming, moving, trashing and sweeping a finished download.
pub mod smart;
pub mod splitjoin;
// Spending a password on a locked archive, hoisted out of `smart` by the
// crate-split prep - it drives the extractor, not the filing code.
pub mod unlockpw;
pub mod unpack;

// The crate-root GLOBS, verbatim from `crates/nzbfast/src/main.rs`. A
// glob import at a crate root is private to the root and VISIBLE TO
// EVERY DESCENDANT MODULE, so `rar_magic`, `sanitized_entry_path`,
// `ExtractStaging` and about two hundred other names resolved bare from
// inside these modules without any of them ever naming the module they
// came from. Losing one is not a compile error in the module that
// exported it - it is an unresolved name in some cousin - so they move
// with the modules rather than being pruned here.
// `diag` and `streamhub` are nzbfast-core's, and main.rs globs them at
// its own root for the same reason: `bomb_failure`, `first_rar_volume`
// and `unsupported_archive_present` are named bare from inside `rarfix`.
use diag::*;
use rarfix::*;
use repair::*;
use sfx::*;
use splitjoin::*;
use unpack::*;

// The rename-race harness the occupancy claims are pinned with. It was
// `#[cfg(test)] mod renameclaim;` in `crates/nzbfast` until crate-split
// step 3, and its pins are spread across `smart`'s tests HERE and
// `serve`'s tests THERE - two crates now, where a `cfg(test)` item is
// invisible whatever its visibility. So it lives at the lower of the two
// and is gated on `test-support` as well; the bin re-imports it under
// its old name. Nothing in it reaches past `std`.
#[cfg(any(test, feature = "test-support"))]
pub mod renameclaim;

// The scratch guard this crate's own unit tests reach for. Its `#[path]`
// include is why the file below it sits under `tests/` in a crate with
// no integration target - see the module note.
#[cfg(test)]
mod testscratch;
