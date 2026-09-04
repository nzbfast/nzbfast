//! The nzbfast request layer - the JSON API, the SABnzbd-compatible
//! surface, the report and preview endpoints, the Prometheus exposition
//! and the embedded web pages - lifted out as its own crate by lane 3 of
//! Option C in `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`.
//!
//! WHAT IS IN HERE is not a judgement made at this file: it is the `api`
//! layer of `SERVE_LAYERS` in `tools/modgraph.py`, whose `--serve
//! --check` arm runs in CI and refuses a cross-layer edge. Eight units,
//! `git mv`d out of `crates/nzbfast/src/serve/` with their tests, and
//! `crates/nzbfast/src/serve/mod.rs` re-imports each under its OLD NAME
//! (`pub(crate) use nzbfast_api::sabcompat;`), so every
//! `crate::serve::<unit>::...` path in the wiring layer that stayed
//! there resolves unchanged.
//!
//! IT IS A SIBLING OF `nzbfast-tasks`, NOT A LAYER OVER IT. Both stand
//! on `nzbfast-daemon` and neither may name the other - that is what
//! lets cargo check them in parallel, and it is the whole reason lane 1b
//! broke the twelve cross-layer edges before either crate existed. The
//! absence of an `nzbfast-tasks` dependency line in `Cargo.toml` holds
//! the rule from the cargo side; `--serve --check` holds it from the
//! source side.
//!
//! ZERO `impl Daemon` BLOCKS LIVE HERE, and that is what made the cut
//! possible at all: an inherent impl must live in its type's crate, so
//! one `impl Daemon` in this layer would have blocked the move outright.
//! Lane 1b's 61 lifts are what bought it.
//!
//! THIS IS THE CRATE THAT EMBEDS THE WEB. `assets.rs`, `webasset.rs` and
//! `devweb.rs` carry every `include_str!` / `include_bytes!` of `web/`,
//! and the OUT_DIR gz/etag pairs they read are written by this package's
//! own `build.rs` - `env!("OUT_DIR")` names the OUT_DIR of the package
//! being compiled, so the generator had to move with them. The
//! `dashboard` feature is declared here and `crates/nzbfast`'s forwards
//! to it, so the store build's compile-out is unchanged and
//! `tools/ffi-cutout-gate.py` still holds it.

// Matches both nzbfast roots, the four layer crates and nzbfast-daemon:
// `job_json` is one `json!` literal per persisted Job field and the
// macro recurses per key.
#![recursion_limit = "256"]

use std::collections::VecDeque;
#[cfg(feature = "indexer")]
use std::path::Path;
use std::path::PathBuf;
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
pub(crate) use nzbfast_core::{
    conntune, diag, eatvol, health, identify, import_sab, logging, notify, persist, setup,
    streamhub, unpackprog,
};
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_core::{interests, ratelimit};
pub(crate) use nzbfast_meta::{newznab, rss};
pub(crate) use nzbfast_unpack::{smart, unlockpw};
// `wall` and `watchlist` are UNGATED, matching `crates/nzbfast/src/lib.rs`:
// nzbfast-meta answers both in a slim build too (its `wall` swaps to
// `wall_slim.rs` under `not(indexer)`), and this crate's TEST targets
// name them in either configuration - which is more than its production
// code does without `indexer`, hence the cfg on the `use` rather than a
// bare one. A `use` can be unused where a `mod` never could.
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_core::xrel;
#[cfg(all(test, feature = "indexer"))]
pub(crate) use nzbfast_meta::gates;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::{groups, groupstats};
#[cfg(any(test, feature = "indexer"))]
pub(crate) use nzbfast_meta::{wall, watchlist};

// The daemon layer, re-imported under the names it had while serve was
// one module, so every `crate::serve::<unit>::...` path in this crate's
// files is unchanged. `nzbfast-daemon`'s own lib.rs carries the same
// list for the same reason.
//
// `watchlist`, `servers` and `locallink` are named through
// `nzbfast_daemon::` at their references, or globbed below, rather than
// bound here: each is BOTH a unit of the daemon crate and a module of a
// layer below it, so a bare re-import would fuse two different modules
// under one name.
#[cfg(feature = "dashboard")]
pub(crate) use nzbfast_daemon::uilocales;
pub(crate) use nzbfast_daemon::{
    altcand, apiutil, bootstrap, daemon, disk, earlyfile, fetch, finish_action, fsutil, groupscan,
    heal, histmigrate, history, httputil, hunt, indexers, insurance, job, lanaddr, listsrc,
    logscrub, maint, naming, origin, outage, postprobe, postproc, probeids, reqbody, requeue,
    sabvocab, sched, settings, slowstore, spare, stream, tunestate, update, watchfail,
};
// Named by this crate's own test modules and by nothing in its
// production code: a `use` can be unused where a `mod` never could.
#[cfg(test)]
pub(crate) use nzbfast_daemon::sidecar;
#[cfg(test)]
pub(crate) use nzbfast_unpack::unpack;
// `diag`'s `incomplete_reason`, `LossCauses` and `with_build` are named
// by `tests_grabs.rs` alone since the production readers went down with
// their layers.
#[cfg(test)]
use diag::*;
#[cfg(all(test, unix))]
pub(crate) use nzbfast_daemon::script;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_daemon::{predb_seed, rarprobe, seed_harvest};

// The crate-root GLOBS serve carried, verbatim, for the reason
// `nzbfast-engine`'s and `nzbfast-daemon`'s lib.rs files carry theirs: a
// glob at a crate root is reachable as a bare name from every
// descendant, and these files resolved `Daemon`, `Job`, `epoch_secs`,
// `with_build`, `load_server` and the rest through
// `crates/nzbfast/src/serve/mod.rs` without ever naming the module they
// came from. Losing one is not an error where it was exported - it is an
// unresolved name somewhere in here - so they move with the units.
use apiutil::*;
use bootstrap::*;
use daemon::*;
use disk::*;
use fetch::*;
use fsutil::*;
use groupscan::*;
use history::*;
use httputil::*;
use indexers::*;
use job::*;
use maint::*;
pub use nzbfast_daemon::{
    HTTP_IDLE_TICK, RunStop, SLOW_STORAGE_PAUSE_DEFAULT, STOP_BASELINE, STOP_EPOCH, ServeOpts,
    arm_embedded_stop, census_daemon, epoch_secs, live_aux_threads, live_daemons, parse_size,
    request_stop, spawn_aux, stop_notify,
};
// The DAEMON layer's `servers` unit, bound under its old name because
// `api/config.rs` reaches it by PATH (`super::super::servers::`) and not
// only by bare name. nzbfast-core has a `servers` module too - the same
// two-modules-one-name pair `nzbfast-daemon`'s own lib.rs records - and
// this crate names the daemon one, which is what serve did.
pub(crate) use nzbfast_daemon::servers;
use servers::*;
// And nzbfast-core's `servers`, globbed rather than named for the
// reason one line up: the index pull's `crate::scan_servers` resolved
// through the BIN root's own glob of it, which is a door this crate has
// to re-create. `nzbfast-daemon`'s lib.rs carries the identical line.
#[cfg(feature = "indexer")]
use nzbfast_core::servers::*;
use origin::*;
use outage::*;
use reqbody::*;
use sabvocab::*;
use sched::*;
use settings::*;
use stream::*;
use streamhub::*;
#[cfg(feature = "dashboard")]
use uilocales::*;
use update::*;

// This crate's scratch guard, reached the way every other crate in the
// workspace reaches it: one `#[path]` include of `tests/scratch/mod.rs`
// per crate, so the whole tree holds the same type and the sweep's
// `Once` fires once per process.
#[cfg(test)]
mod testscratch;

// The daemon crate's two test seams, on through this package's DEV
// dependency on `nzbfast-daemon` with `features = ["test-support"]`.
// Every test in here builds its Daemon with `testutil::test_daemon` and
// `api/queue/custody_tests.rs` arms `storecut`'s durable-write cut; both
// were `#[cfg(test)]` items of one crate, and a `cfg(test)` item is
// invisible across a crate boundary whatever its visibility.
// Test-only names, each with the narrowest cfg that keeps it live: a
// `use` can be unused where a `mod` never could.
#[cfg(test)]
pub(crate) use nzbfast_core::{diskfree, failkind, identity};
#[cfg(test)]
pub(crate) use nzbfast_daemon::watchlist as daemon_watchlist;
#[cfg(test)]
pub(crate) use nzbfast_unpack::repair;
#[cfg(test)]
pub use nzbkit::par2repair::FAST_PAR_DEFAULT;

#[cfg(test)]
pub(crate) use nzbfast_daemon::storecut;
#[cfg(test)]
pub(crate) use nzbfast_daemon::testutil;

// The diversity card's id sample, moved out of `serve/mod.rs` with its
// one caller (`api::servers`). See that file's header.
mod diversity;
use diversity::*;

pub mod api;
// NO `pub use api::*;` here, and that is not an omission. `serve/mod.rs`
// declared this `mod api;` with no glob, and adding one re-exports
// `api::servers` as `crate::servers` - which is a THIRD module of that
// name beside the daemon unit and nzbfast-core's, and it silently won
// the `super::super::servers::socks5_addr` in `api/config.rs`.

pub mod sabcompat;
pub use sabcompat::*;

pub mod metrics;

pub mod preview;
pub use preview::*;

pub mod report;

// The browser-facing page machinery, TODO 281 IO3b: every item in it
// serves a WEB page (the two shells, the precompressed catalogues and
// manuals, the per-request stylesheet, and the content negotiation the
// three share), so the module goes as one rather than item by item.
// Without `dashboard` the daemon still answers its whole API - which is
// the only thing either phone shell ever asks it.
#[cfg(feature = "dashboard")]
pub mod assets;
#[cfg(feature = "dashboard")]
pub use assets::*;

#[cfg(feature = "dashboard")]
pub mod webasset;
#[cfg(feature = "dashboard")]
pub use webasset::*;

// DEV-ONLY: the NZBFAST_DEV_WEB_DIR override that serves the pages from
// a checkout's web/ directory instead of the copies compiled in, so a
// dashboard edit is a browser reload rather than a rebuild and a
// restart. Off unless the variable is exported, and gated with the rest
// of the browser-facing half - a slim build carries no page to override.
#[cfg(feature = "dashboard")]
pub mod devweb;

// SERVE'S OWN TEST MODULES, moved here with the units they test (lane 3
// of Option C). They were `serve/tests_*.rs`, attached to `serve` as
// sibling children so `super` meant `serve`; the api layer IS what they
// reach, and 56 of the declarations they open `use super::*` against are
// this crate's. `super` now means this crate root, which is the same
// scope by another name.
#[cfg(test)]
#[path = "tests_api.rs"]
mod tests_api;

#[cfg(test)]
#[path = "tests_jobs.rs"]
mod tests_jobs;

#[cfg(test)]
#[path = "tests_grabs.rs"]
mod tests_grabs;

#[cfg(test)]
#[path = "tests_index.rs"]
mod tests_index;

// The daemon-layer tests lane 2 could not take down with their units,
// because each composes a daemon item with `sabcompat::queue_json` and
// that is api-layer. They came to rest in `serve/` then; this is where
// the thing they could not reach actually lives.
#[cfg(test)]
mod daemon_payload_tests;

// `daemon_api_tests.rs` is NOT here and cannot be: eight of its ten
// tests compose a daemon item with a `tasks::` one, and `nzbfast-tasks`
// is this crate's SIBLING. It stays in the bin, which is the only place
// that sees both - see `crates/nzbfast/src/serve/mod.rs`.
