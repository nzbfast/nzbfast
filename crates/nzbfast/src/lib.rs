//! Embedded (in-process) crate root, for hosts that cannot exec a
//! binary - the iOS staticlib is the customer (see crates/nzbfast-ffi).
//! Compiles to EMPTY unless the `ffi` feature is on, so every existing
//! build and test target is untouched: the bin root (main.rs) declares
//! this same module tree independently and nothing is shared at compile
//! time except the source files themselves.
//!
//! `dead_code`/`unused_imports` are waived because this root has no
//! CLI: everything only the subcommand arms call is dead here by
//! construction, and proving each item live per-root would fork the
//! module files. The bin root keeps full lint coverage.
//!
//! `#![expect]` rather than `#![allow]`, checked rather than assumed:
//! both are FULFILLED here, measured 23 Aug 2026 in every shape that
//! reaches this root - `-p nzbfast --features ffi`, the
//! `--no-default-features --features ffi` combination nzbfast-ffi
//! actually asks for, and `-p nzbfast-ffi --target
//! aarch64-apple-ios-sim`. The blanket is broad, so the claim it makes
//! is only that SOMETHING here is dead; the day that stops being true
//! the waiver should go, and this is what will say so.
#![cfg(feature = "ffi")]
#![expect(dead_code)]
#![expect(unused_imports)]
// Same reason as main.rs: `job_json` is one `json!` literal per
// persisted Job field, and the macro recurses per key.
#![recursion_limit = "256"]

// The same crate-root imports main.rs holds: module files resolve
// `crate::Arc`, `crate::info` etc. through these.
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::info;

mod chaos_serve;
mod conntune;
mod diag;
// Free-space measurement, hoisted out of serve/ by TODO 276 item 3 so
// eatvol, get, lanegate and rarfix can ask it without depending on the
// daemon.
mod diskfree;
mod eatvol;
#[cfg(feature = "indexer")]
mod gates;
// The failure-message classifier, hoisted out of serve/ by TODO 276
// item 3 so `diag` (and everything under it) stops depending on the
// daemon. Pure `&str` in, small value out.
mod failkind;
mod get;
#[cfg(feature = "indexer")]
mod groups;
#[cfg(feature = "indexer")]
mod groupstats;
mod health;
mod identify;
mod identity;
mod import_sab;
mod interests;
mod lanegate;
// TODO 151 (issue #36): external list sources for the watchlist.
mod listsrc;
// Which interface carries our traffic and how fast it is. Hoisted out of
// serve/ by TODO 276 item 3 so the CLI sysbench can ask without the daemon.
mod locallink;
pub mod logging;
mod manifest;
mod nettools;
// Outbound HTTP for third-party URLs - the SSRF guard, the shared agents
// and URL credential redaction. Hoisted out of serve/ by TODO 276 item 3.
mod netfetch;
mod newznab;
// TODO 297 (issue #57): the nzbindex.com JSON API, a second search
// source dispatched to from serve/indexers.rs on `newznab::SourceKind`.
mod notify;
mod nzbindex;
#[cfg(feature = "indexer")]
mod oracle_backtest;
mod persist;
// TODO 151 (issue #36): the first list source's own wire formats.
mod plex;
mod post_cmd;
mod rarfix;
mod ratelimit;
#[cfg(test)]
mod renameclaim;
mod repair;
mod resumeout;
mod rss;
#[cfg(feature = "indexer")]
mod scan;
pub mod serve;
mod setup;
mod sfx;
// Human size/rate strings ("900Mb" -> bytes). Hoisted out of serve/ by
// TODO 276 item 3 - gates, rss and smart all parse them.
mod sizes;
mod smart;
mod splitjoin;
mod srrdb;
#[cfg(test)]
mod testscratch;
mod tools;
mod unpack;
mod unpackprog;
#[cfg(feature = "indexer")]
mod wall;
#[cfg(not(feature = "indexer"))]
#[path = "wall_slim.rs"]
mod wall;
mod watchlist;
mod xrel;
use sfx::*;
use unpack::*;
mod check;
use check::*;
use get::*;
mod streamhub;
use diag::*;
use nettools::*;
use nzbkit::config::{Config, ServerConfig};
use nzbkit::nntp::Connection;
use nzbkit::nzb::{FileKind, Nzb};
// Re-exported, not merely imported: this is what lets the rest of the crate
// say `use crate::MutexExt;` for `lock_ok()` rather than naming nzbkit.
pub use nzbkit::sync::{MutexExt, RwLockExt};
use rarfix::*;
use repair::*;
#[cfg(feature = "indexer")]
use scan::*;
use splitjoin::*;
use streamhub::*;

/// The [`serve::ServeOpts`] an embedded host runs with: the CLI's
/// defaults, a loopback bind (the host process owns the only client),
/// everything else settings-driven - `apply_saved_settings` overlays
/// settings.json exactly as it does for the daemon.
///
/// `mem_limit` is the host's answer in BYTES, or `None` for
/// [`nzbkit::mem::MemBudget::auto`] - a quarter of physical RAM, which
/// is a DESKTOP figure and the one default in this function that a
/// phone must not take. `MemBudget::auto` reads the machine's RAM, and
/// on a 12 GB phone that is a 3 GB budget for a process the platform is
/// willing to kill for being large; `MemBudget::with_total` clamps
/// whatever arrives to the engine's own 64 MB floor, so a host that
/// passes something silly gets a small engine rather than a broken one.
/// See `nzbfast_start`'s `mem_limit_bytes` for why this is a parameter
/// and not an environment variable, and TODO 281 IO2 for the
/// measurement the iOS figure comes from.
///
/// A saved `mem_limit` in settings.json still overrides it: `serve`
/// runs `apply_saved_settings` before it publishes the process budget,
/// so this is the platform's DEFAULT and an explicit user setting wins,
/// which is the same precedence `--mem-limit` has on a desktop.
pub fn embedded_serve_opts(
    port: u16,
    apikey: Option<String>,
    out_root: PathBuf,
    mem_limit: Option<u64>,
) -> serve::ServeOpts {
    serve::ServeOpts {
        port,
        bind: "127.0.0.1".into(),
        // Loopback-only host process: TLS is settings-driven if ever
        // wanted here, same as everything else below.
        tls_cert: None,
        tls_key: None,
        open: false,
        apikey,
        nzbkey: None,
        out_root,
        watch: None,
        script: None,
        connections: 8,
        window: 4,
        decoders: 6,
        fast_verify: true,
        verify_lean: false,
        library_cats: Vec::new(),
        library_recheck_secs: 21600,
        min_free: None,
        out_umask: None,
        auto_retry_mins: 20,
        preflight: false,
        quota: None,
        quota_period: 'd',
        feeds: None,
        speedlimit: None,
        schedule: None,
        auto_speed: false,
        mem_budget: embedded_budget(mem_limit),
        group_desc_isc: false,
        #[cfg(feature = "indexer")]
        index_db: PathBuf::from("index.db"),
        #[cfg(feature = "indexer")]
        index_groups: Vec::new(),
        #[cfg(feature = "indexer")]
        index_interval_secs: 900,
        #[cfg(feature = "indexer")]
        index_backfill: 20000,
        #[cfg(feature = "indexer")]
        index_max_age_secs: 0,
        #[cfg(feature = "indexer")]
        index_gates: None,
    }
}

/// The budget an embedded host gets, in one place because TWO callers
/// need the identical answer: [`embedded_init`] publishes the process
/// budget before the engine thread exists, and [`embedded_serve_opts`]
/// puts it in the opts `serve` republishes from. Written twice, a host
/// that passed a phone-sized limit would still spend the window between
/// those two calls advertising a desktop one.
fn embedded_budget(mem_limit: Option<u64>) -> nzbkit::mem::MemBudget {
    match mem_limit {
        // Clamps to MemBudget::MIN and fits the address space, so a
        // host that asks for 1 byte gets the 64 MB floor rather than an
        // engine whose every tier rounds to nothing - and SAYS so, which
        // it did not until 31 Aug 2026. An embedded host is the one
        // caller that cannot see a `--mem-limit` it never typed, so a
        // phone-sized figure silently becoming the floor is a budget
        // nobody could have checked.
        Some(bytes) => nzbkit::mem::MemBudget::from_user_limit(bytes, "the host's memory limit"),
        None => nzbkit::mem::MemBudget::auto(),
    }
}

/// Process-wide one-time setup the CLI's `run()` does before serving,
/// minus the pieces that make no sense in a host app (power-throttling
/// opt-out is Windows-only and harmless; the allocator stays the
/// system's - mimalloc is cfg'd to macOS + Linux).
///
/// `mem_limit` is the same argument [`embedded_serve_opts`] takes and
/// must be the SAME VALUE: this is the budget in force from here until
/// `serve` republishes its own, and the repair and extract paths read
/// the process budget rather than the opts.
pub fn embedded_init(mem_limit: Option<u64>) {
    logging::init(logging::Style::Daemon);
    nzbkit::disk::raise_fd_limit();
    nzbkit::mem::opt_out_of_power_throttling();
    nzbkit::mem::set_process_budget(embedded_budget(mem_limit));
}
