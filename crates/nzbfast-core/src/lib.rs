//! The bottom layer of the nzbfast bin, lifted out as its own crate by
//! step 2 of `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`.
//!
//! Every module here was a top-level module of `crates/nzbfast/src`
//! and moved with `git mv`; step 1 had already made the production
//! module graph a DAG, so this step is a file move and a `pub` widening
//! rather than a refactor. `crates/nzbfast/src/main.rs` and `lib.rs`
//! re-import each one under its OLD NAME (`pub(crate) use
//! nzbfast_core::diag;`), so every `crate::diag::...` path in the
//! modules that stayed behind resolves exactly as it did before.
//!
//! WHAT MAKES A MODULE CORE: nothing above it depends on it in the
//! other direction. `tools/modgraph.py --check` is the measurement and
//! runs on every push - it refuses a `crate::` edge from a core module
//! up into the unpack, meta, engine or bin layers, which is the one
//! property that keeps this crate compilable on its own and therefore
//! keeps it OFF the critical path of every rebuild above it.
//!
//! WHY THE ITEMS ARE `pub` AND NOT `pub(crate)`: they were `pub(crate)`
//! while this was one crate, and a library's `pub(crate)` is invisible
//! to the bin. The widening is mechanical and was driven by the
//! compiler - only what nzbfast actually names crossed over.

// `job_json` in serve/ is one `json!` literal per persisted Job field
// and the macro recurses per key; the same limit is raised in both
// nzbfast roots. Nothing here needs it today, and it is set so a value
// type moved down into this crate does not have to discover it.
#![recursion_limit = "256"]

// The crate-root imports `diag` and `streamhub` reach through their own
// `use crate::*;`. They were main.rs's when this was one crate, and a
// glob of the root picks up an ancestor's private imports - so `Arc`,
// `PathBuf` and `lock_ok()` resolved through main.rs from inside these
// modules without ever naming it. That is an edge `tools/modgraph.py`
// cannot see (it reads `crate::X` paths, and these are bare names), so
// it is written out here rather than discovered again: this list is
// exactly what the two modules below still need.
use crate::tools::{MutexExt, RwLockExt};
use nzbkit::config::ServerConfig;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

// Archive name and magic grammar - pure path predicates every layer
// asks, hoisted out of `unpack` / `rarfix` by the crate-split prep.
pub mod archname;
pub mod conntune;
pub mod diag;
// Free-space measurement, hoisted out of serve/ by TODO 276 item 3 so
// eatvol, get, lanegate and rarfix can ask it without depending on the
// daemon.
pub mod diskfree;
pub mod eatvol;
// The failure-message classifier, hoisted out of serve/ by TODO 276
// item 3 so `diag` (and everything under it) stops depending on the
// daemon. Pure `&str` in, small value out.
pub mod failkind;
// The per-file runtime state of a download, hoisted out of `unpack`
// by the crate-split prep so the stream hub can hold one.
pub mod fileslot;
pub mod health;
pub mod identify;
pub mod identity;
pub mod import_sab;
pub mod interests;
pub mod lanegate;
// Which interface carries our traffic and how fast it is. Hoisted out of
// serve/ by TODO 276 item 3 so the CLI sysbench can ask without the daemon.
pub mod locallink;
pub mod logging;
pub mod manifest;
// Outbound HTTP for third-party URLs - the SSRF guard, the shared agents
// and URL credential redaction. Hoisted out of serve/ by TODO 276 item 3.
pub mod netfetch;
pub mod notify;
// The bounded PAR2 packet-byte scan of a directory, hoisted out of
// `unpack` by the crate-split prep so the junk sweep can ask it.
pub mod par2scan;
pub mod persist;
// Where the operator's passwords file lives - a process-wide setting
// the extraction ladder reads without a `Daemon` handle.
pub mod pwfile;
pub mod ratelimit;
// Release-name grammar - the password convention and the dedupe
// reduction, hoisted out of `smart` by the crate-split prep.
pub mod relname;
// Which configured server a lane should talk to - three pure selectors
// over `nzbkit::config::Config`, hoisted out of the bin's `nettools` by
// the crate-split step 3 cut because `scan` (nzbfast-meta) calls all
// three. See the module note for why nothing had reported that edge.
pub mod servers;
// TODO 314 stage 1: the ONE spawn wrapper every child that runs code we
// did not write goes through - unrar, par2 and the user's scripts.
pub mod sandbox;
pub mod setup;
// Human size/rate strings ("900Mb" -> bytes). Hoisted out of serve/ by
// TODO 276 item 3 - gates, rss and smart all parse them.
pub mod sizes;
pub mod srrdb;
pub mod streamhub;
pub mod tools;
pub mod unpackprog;
pub mod xrel;

// The scratch guard this crate's own unit tests reach for. Its `#[path]`
// include is why the file below it sits under `tests/` in a crate with
// no integration target - see the module note.
#[cfg(test)]
mod testscratch;
