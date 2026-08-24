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
mod nettools;
// Outbound HTTP for third-party URLs - the SSRF guard, the shared agents
// and URL credential redaction. Hoisted out of serve/ by TODO 276 item 3.
mod netfetch;
mod newznab;
mod notify;
#[cfg(feature = "indexer")]
mod oracle_backtest;
mod persist;
// TODO 151 (issue #36): the first list source's own wire formats.
mod plex;
mod post_cmd;
mod rarfix;
mod ratelimit;
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
pub fn embedded_serve_opts(
    port: u16,
    apikey: Option<String>,
    out_root: PathBuf,
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
        mem_budget: nzbkit::mem::MemBudget::auto(),
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

/// Process-wide one-time setup the CLI's `run()` does before serving,
/// minus the pieces that make no sense in a host app (power-throttling
/// opt-out is Windows-only and harmless; the allocator stays the
/// system's - mimalloc is cfg'd to macOS + Linux).
pub fn embedded_init() {
    logging::init(logging::Style::Daemon);
    nzbkit::disk::raise_fd_limit();
    nzbkit::mem::opt_out_of_power_throttling();
    let budget = nzbkit::mem::MemBudget::auto();
    nzbkit::mem::set_process_budget(budget);
}
