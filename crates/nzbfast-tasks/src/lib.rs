//! The nzbfast background-lane layer - the daemon's scheduled and
//! long-running tasks - lifted out as its own crate by lane 3 of Option C
//! in `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`.
//!
//! WHAT IS IN HERE is not a judgement made at this file: it is the
//! `tasks` layer of `SERVE_LAYERS` in `tools/modgraph.py`, whose
//! `--serve --check` arm runs in CI and refuses a cross-layer edge. One
//! unit, `git mv`d out of `crates/nzbfast/src/serve/` with its tests,
//! and `crates/nzbfast/src/serve/mod.rs` re-imports it under its OLD
//! NAME (`pub(crate) use nzbfast_tasks::tasks;`), so every
//! `crate::serve::tasks::...` path in the api and wiring layers that
//! stayed in the bin resolves unchanged.
//!
//! IT IS A SIBLING OF `nzbfast-api`, NOT A LAYER UNDER IT. Both stand on
//! `nzbfast-daemon` and neither may name the other - that is what lets
//! cargo check them in parallel, and it is the whole reason lane 1b
//! broke the twelve cross-layer edges before either crate existed. The
//! absence of an `nzbfast-api` dependency line in `Cargo.toml` holds the
//! rule from the cargo side; `--serve --check` holds it from the source
//! side.
//!
//! ZERO `impl Daemon` BLOCKS LIVE HERE, and that is what made the cut
//! possible at all: an inherent impl must live in its type's crate, so
//! one `impl Daemon` in this layer would have blocked the move outright
//! rather than merely enlarging it. Lane 1b's 61 lifts are what bought
//! it.

// Matches both nzbfast roots, the four layer crates and nzbfast-daemon:
// `job_json` is one `json!` literal per persisted Job field and the
// macro recurses per key.
#![recursion_limit = "256"]

use std::collections::VecDeque;
use std::path::PathBuf;
#[cfg(any(test, feature = "indexer"))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use serde_json::{Value, json};
use tracing::{info, warn};

// The lock-poisoning helpers every `.lock_ok()` in this crate resolves
// through, reached exactly as `nzbfast-daemon` reaches them.
pub use nzbfast_core::tools::{MutexExt, RwLockExt};

// The layers below, re-imported under the names serve used while
// everything was one crate: `crate::smart::...`, `crate::wall::...` and
// the rest have to keep resolving from inside these files, and these
// lines are what make them. The list is what the compiler leaves
// standing - `unused_imports` is `-D warnings` in this workspace, and a
// `use` can be unused where a `mod` never could.
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_core::servers;
pub(crate) use nzbfast_core::{conntune, diag, failkind, health, persist, streamhub};
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_core::{identity, interests, logging};
pub(crate) use nzbfast_engine::get;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::scan;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::{gates, groups, groupstats, wall, watchlist};
pub(crate) use nzbfast_meta::{newznab, rss};
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_unpack::rarfix;
pub(crate) use nzbfast_unpack::{check, smart};
// Test-only names. A `use` can be unused where a `mod` never could, so
// each carries the narrowest cfg that keeps it live: these three are
// named by this crate's own test modules and by nothing in production.
#[cfg(all(test, feature = "indexer"))]
pub(crate) use nzbfast_core::netfetch;
#[cfg(test)]
pub(crate) use nzbfast_unpack::renameclaim;
#[cfg(test)]
use streamhub::*;

// The daemon layer, re-imported under the names it had while serve was
// one module, so every `crate::serve::<unit>::...` path in this crate's
// files is unchanged. `nzbfast-daemon`'s own lib.rs carries the same
// list for the same reason.
//
// `watchlist` and `locallink` are named through `nzbfast_daemon::` at
// their references rather than here: each is BOTH a unit of the daemon
// crate and a module of a layer below it, so a bare re-import would
// fuse two different modules under one name.
pub(crate) use nzbfast_daemon::{
    bootstrap, daemon, disk, fetch, groupscan, hooks, httputil, hunt, insurance, job, mediadisk,
    naming, outage, postprobe, postproc, probeids, provquality, requeue, sched, sidecar, spill,
    stream, tunestate, update, watchfail, whyslow, wire,
};
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_daemon::{indexers, maint, rarprobe, seed_harvest};

// The crate-root GLOBS serve carried, verbatim, for the reason
// `nzbfast-engine`'s and `nzbfast-daemon`'s lib.rs files carry theirs: a
// glob at a crate root is reachable as a bare name from every
// descendant, and these files resolved `Daemon`, `Job`, `epoch_secs`,
// `with_build`, `load_server` and the rest through
// `crates/nzbfast/src/serve/mod.rs` without ever naming the module they
// came from. Losing one is not an error where it was exported - it is an
// unresolved name somewhere in here - so they move with the unit.
use bootstrap::*;
use check::*;
use daemon::*;
use diag::*;
use disk::*;
use fetch::*;
use get::*;
use groupscan::*;
use httputil::*;
#[cfg(feature = "indexer")]
use indexers::*;
use job::*;
#[cfg(feature = "indexer")]
use maint::*;
use mediadisk::*;
pub(crate) use nzbfast_daemon::{RunStop, epoch_secs, spawn_aux};
use outage::*;
use postprobe::*;
use postproc::*;
use requeue::*;
#[cfg(feature = "indexer")]
use scan::*;
use sched::*;
// The DAEMON layer's `servers` unit, globbed rather than NAMED, because
// `servers` as a name is nzbfast-core's here - the same two-modules-one-name
// pair `nzbfast-daemon`'s own lib.rs records for `watchlist` and
// `locallink`. `crate::servers::scan_servers` in the indexer lane is
// core's; the bare `watch_sig` and `nzb_looks_complete` the watch folder
// calls are the daemon unit's.
use nzbfast_daemon::servers::*;
#[cfg(feature = "indexer")]
use servers::*;
use sidecar::*;
use stream::*;
use tunestate::*;
use update::*;
// The DAEMON layer's `watchlist` unit, globbed rather than named,
// because `watchlist` as a NAME is nzbfast-meta's module here - the
// same two-modules-one-name pair `nzbfast-daemon`'s own lib.rs records.
// `crate::watchlist::InstantMatcher` is meta's; the bare `watchlist_pass`
// the scan lane calls is the daemon unit's.
use nzbfast_daemon::watchlist::*;
use wire::*;

// This crate's scratch guard, reached the way every other crate in the
// workspace reaches it: one `#[path]` include of `tests/scratch/mod.rs`
// per crate, so the whole tree holds the same type and the sweep's
// `Once` fires once per process.
#[cfg(test)]
mod testscratch;

// The daemon crate's test seams, on through this package's DEV
// dependency on `nzbfast-daemon` with `features = ["test-support"]`.
// Every test in here builds its Daemon with `testutil::test_daemon`;
// both were `#[cfg(test)]` items of one crate, and a `cfg(test)` item is
// invisible across a crate boundary whatever its visibility.
#[cfg(test)]
pub(crate) use nzbfast_daemon::testutil;
// `locallink` is the same two-modules-one-name pair as `watchlist`: the
// daemon crate has a unit of that name and so does nzbfast-core. The
// watch-folder test wants the DAEMON one.
#[cfg(test)]
pub(crate) use nzbfast_daemon::locallink;

pub mod tasks;
