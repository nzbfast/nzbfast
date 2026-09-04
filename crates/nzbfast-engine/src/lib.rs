//! The download engine of the nzbfast bin - the one-pass fetch, decode,
//! settle and tail pipeline - lifted out as its own crate by step 4 of
//! `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`.
//!
//! `get` was a top-level module of `crates/nzbfast/src` and moved with
//! `git mv`; step 1 had already made the production module graph a DAG,
//! so this step is a file move and a `pub` widening rather than a
//! refactor. `crates/nzbfast/src/main.rs` and `lib.rs` re-import it
//! under its OLD NAME (`pub(crate) use nzbfast_engine::get;`) and keep
//! globbing it at their own roots, so every `crate::get::...` path and
//! every bare name the bin resolves through `use get::*;` is unchanged.
//!
//! WHAT MAKES A MODULE ENGINE: it is above `nzbfast-unpack` and nothing
//! in `nzbfast-meta` reaches it. This crate names neither `nzbfast-meta`
//! nor `nzbfast`, so cargo schedules it beside meta and under the bin.
//! `tools/modgraph.py --check` holds that from the source side and the
//! absence of a dependency line in Cargo.toml holds it from the cargo
//! side.
//!
//! WHY THE ITEMS ARE `pub` AND NOT `pub(crate)`: they were `pub(crate)`
//! while this was one crate, and a library's `pub(crate)` is invisible
//! to the bin. The widening is mechanical and was driven by the
//! compiler - only what nzbfast actually names crossed over.

// Matches both nzbfast roots, nzbfast-core and nzbfast-unpack: `job_json`
// in serve/ is one `json!` literal per persisted Job field and the macro
// recurses per key. Set here so a value type moved into this crate does
// not have to discover it.
#![recursion_limit = "256"]

// The bare names `get`'s files reach through their own `use crate::*;`.
// They were main.rs's imports when this was one crate, and a glob of the
// crate root picks up an ancestor's private imports - so `Arc`,
// `PathBuf`, `Config` and `lock_ok()` resolved through main.rs from
// inside these files without any of them ever naming it. That is an edge
// `tools/modgraph.py` cannot see (it reads `crate::X` paths, and these
// are bare names), so it is written out here rather than discovered
// again.
use anyhow::{Context, Result};
use nzbfast_core::tools::MutexExt;
use nzbkit::config::{Config, ServerConfig};
use nzbkit::nzb::{FileKind, Nzb};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// The layers below, re-imported under the names `get` used while
// everything was one crate. `crate::repair::...` inside `get` has to
// keep resolving, and these lines are what make it: exactly the
// arrangement `crates/nzbfast/src/main.rs` uses for the same modules.
// The list is what the compiler leaves standing - a module nothing here
// names is not re-imported, because `unused_imports` is `-D warnings` in
// this workspace and a `use` can be unused where a `mod` never could.
pub(crate) use nzbfast_core::{
    conntune, diag, diskfree, eatvol, failkind, lanegate, persist, streamhub, unpackprog,
};
pub(crate) use nzbfast_unpack::{rarfix, repair, resumeout, sfx, smart, splitjoin, unpack};

/// The download pipeline: planning a job's fetch, running the fleet,
/// settling the result on disk and the tail that finishes it.
pub mod get;

// The crate-root GLOBS, verbatim from `crates/nzbfast/src/main.rs`. A
// glob import at a crate root is private to the root and reachable as
// `crate::<name>` from every descendant, and `get`'s files each open
// with `use crate::*;` - so several hundred names resolved bare from
// inside them without any file ever naming the module they came from.
// Losing one is not a compile error in the module that exported it, it
// is an unresolved name somewhere in `get`, so they move with the
// module rather than being pruned here.
use diag::*;
use rarfix::*;
use repair::*;
use sfx::*;
use splitjoin::*;
use streamhub::*;
use unpack::*;

// This crate's scratch guard, reached by the route every other crate in
// the workspace uses - see the module note.
#[cfg(test)]
mod testscratch;
