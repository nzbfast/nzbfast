//! The search, index-scan and metadata layer of the nzbfast bin, lifted
//! out as its own crate by step 3 of
//! `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`.
//!
//! Every module here was a top-level module of `crates/nzbfast/src` and
//! moved with `git mv`; step 1 had already made the production module
//! graph a DAG, so this step is a file move and a `pub` widening rather
//! than a refactor. `crates/nzbfast/src/main.rs` and `lib.rs` re-import
//! each one under its OLD NAME (`pub(crate) use nzbfast_meta::wall;`), so
//! every `crate::wall::...` path in the modules that stayed behind
//! resolves exactly as it did before.
//!
//! WHAT MAKES A MODULE META: it is above `nzbfast-core` and nothing in
//! `nzbfast-unpack` reaches it. This crate and `nzbfast-unpack` are
//! SIBLINGS - neither names the other, which is what lets cargo schedule
//! the two at the same time, and is the whole point of cutting them apart
//! rather than into one layer. `tools/modgraph.py --check` holds it from
//! the source side and the absence of a dependency line in Cargo.toml
//! holds it from the cargo side.
//!
//! WHY THE ITEMS ARE `pub` AND NOT `pub(crate)`: they were `pub(crate)`
//! while this was one crate, and a library's `pub(crate)` is invisible
//! to the bin. The widening is mechanical and was driven by the
//! compiler - only what nzbfast actually names crossed over.

// Matches the other three roots: `job_json` in serve/ is one `json!`
// literal per persisted Job field and the macro recurses per key. Set
// here so a value type moved into this crate does not have to discover
// it.
#![recursion_limit = "256"]

// The bare names these modules reach through their own `use crate::*;`.
// They were main.rs's imports when this was one crate, and a glob of the
// crate root picks up an ancestor's private imports - so `Arc`,
// `PathBuf` and `lock_ok()` resolved through main.rs from inside these
// modules without ever naming it. That is an edge `tools/modgraph.py`
// cannot see (it reads `crate::X` paths, and these are bare names), so
// it is written out here rather than discovered again.
//
// EVERY ONE OF THEM IS `indexer`-GATED, and the reason is `scan`: it is
// the only module here that reaches the crate root for a bare name, and
// it is one of the six that compile out of a slim build. A `use` can be
// unused where a `mod` never could, and `unused_imports` is `-D
// warnings` in this workspace, so a slim build with these unconditional
// is a red one. `slim-check` is the job that says so.
#[cfg(feature = "indexer")]
use anyhow::{Context, Result};
#[cfg(feature = "indexer")]
use nzbfast_core::tools::MutexExt;
#[cfg(feature = "indexer")]
use nzbkit::config::{Config, ServerConfig};
#[cfg(feature = "indexer")]
use nzbkit::nntp::Connection;
#[cfg(feature = "indexer")]
use std::sync::Arc;
#[cfg(feature = "indexer")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "indexer")]
use std::time::Instant;
// TEST-only on top of that: `scan`'s fixture builder names `PathBuf` and
// `digital`'s live-provider rig names `logging::civil_from_days`, and
// neither is reached by anything this crate compiles for a release.
#[cfg(all(test, feature = "indexer"))]
use nzbfast_core::logging;
#[cfg(all(test, feature = "indexer"))]
use std::path::PathBuf;

// The layer below, re-imported under the names the moved modules used
// while everything was one crate. `crate::netfetch::...` inside `wall`
// has to keep resolving, and these lines are what make it: exactly the
// arrangement `crates/nzbfast/src/main.rs` uses for the same modules.
// The list is what the compiler leaves standing - a core module nothing
// here names is not re-imported, because `unused_imports` is `-D
// warnings` in this workspace and a `use` can be unused where a `mod`
// never could.
pub(crate) use nzbfast_core::{netfetch, sizes};
// `relname` and `tools` are the indexer half's too.
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_core::{relname, tools};
// The four the indexer half alone reaches, gated for the reason above.
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_core::{identity, persist, ratelimit, servers};

pub mod listsrc;
pub mod newznab;
// TODO 297 (issue #57): the nzbindex.com JSON API, a second search source
// dispatched to from indexers.rs on `newznab::SourceKind`.
pub mod nzbindex;
// TODO 151 (issue #36): the first list source's own wire formats.
pub mod plex;
pub mod rss;
pub mod watchlist;

// THE INDEXER-GATED HALF. These six were `#[cfg(feature = "indexer")]
// mod ...;` in main.rs and the gate came down here with them. The bin
// still gates its own `use` of the five that VANISH in a slim build - a
// `use` of an item that is not there is an error, which a `mod` was not
// - but `wall` no longer needs one on either side, because the
// wall/wall_slim swap below happens INSIDE this crate now instead of
// being a `#[path]` pair spelled out in both nzbfast roots.
#[cfg(feature = "indexer")]
pub mod gates;
#[cfg(feature = "indexer")]
pub mod groups;
#[cfg(feature = "indexer")]
pub mod groupstats;
#[cfg(feature = "indexer")]
pub mod oracle_backtest;
#[cfg(feature = "indexer")]
pub mod scan;
#[cfg(feature = "indexer")]
pub mod wall;
// Slim builds compile out wall.rs; wall_slim.rs keeps the `crate::wall::`
// paths the core filing/rename code uses alive. The `#[path]` pair was
// main.rs's and lib.rs's, spelled twice; it is one pair here.
#[cfg(not(feature = "indexer"))]
#[path = "wall_slim.rs"]
pub mod wall;

// The crate-root GLOBS, verbatim from `crates/nzbfast/src/main.rs`. A
// glob import at a crate root is private to the root and VISIBLE TO
// EVERY DESCENDANT MODULE, so names resolved bare from inside these
// modules without any of them ever naming the module they came from.
// Losing one is not a compile error in the module that exported it - it
// is an unresolved name in some cousin - so they move with the modules
// rather than being pruned here.
#[cfg(feature = "indexer")]
// `servers` is nzbfast-core's, and `scan` names all three of its
// selectors BARE - it reached them through main.rs's `use nettools::*;`
// while everything was one crate. That is the edge the step 3 cut found
// and the module note in `nzbfast_core::servers` writes up.
use servers::*;

// The scratch guard this crate's own unit tests reach for. Its `#[path]`
// include is why the file below it sits under `tests/` in a crate with
// no integration target - see the module note.
// The scratch guard is `scan`'s, and `scan` is `indexer`-only.
#[cfg(all(test, feature = "indexer"))]
mod testscratch;
