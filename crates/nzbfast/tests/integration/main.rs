//! Every integration test in this crate that is NOT one of the six
//! build-gated heavy suites, compiled into ONE test binary.
//!
//! Why: each `[[test]]` target is a separate executable that statically
//! links the whole crate graph, and linking those is the single biggest
//! cost in CI's Windows leg - measured 17 Aug 2026, 439s of a 699s warm
//! build was spent after the last `Compiling` line, linking 54 of them.
//! Twenty-three of those executables were these files. They are modules
//! now, so they link once. Five more - `log_daemon`, `log_split`,
//! `queue_handoff`, `remote_compat`, `stream_repair` - were added to main
//! after that change was cut and folded in here on 23 Aug 2026 (TODO 235),
//! for twenty-eight.
//!
//! This does NOT weaken isolation: nextest runs every test in its own
//! PROCESS regardless of which binary it lives in, so these tests are as
//! isolated from each other as they were when each had its own
//! executable. (That is also why this could not have been done before
//! the suites moved off `cargo test`, which shares one process per
//! binary.)
//!
//! ADDING A TEST: put the file beside this one and add a `mod` line
//! below. A new top-level `tests/*.rs` still becomes its own target, so
//! nothing silently changes behaviour - but prefer a module here unless
//! the test genuinely needs its own executable.
//!
//! The six heavy suites (daemon, e2e, leak_soak, index_size_cap,
//! http_wedge, queue_soak) stay as their own targets on purpose: their
//! `required-features = ["heavy-tests"]` gate (TODO 116b) is per-target,
//! and that gate is what keeps them out of per-push CI.

// Shared helpers, declared once here rather than in each module: a
// module file's children resolve against a directory named after it, so
// a per-file `mod scratch;` would look for tests/integration/<name>/.
#[path = "../scratch/mod.rs"]
mod scratch;

// The shared daemon launcher - free_port / KillOnDrop / DaemonLog /
// Daemon / serve / wait_ready - for every module here that spawns
// `nzbfast serve`. Same reason as `scratch` above, and the same
// `#[path]`: it is also included by the heavy suites that are still
// their own targets, where a plain `mod harness;` resolves.
#[path = "../harness/mod.rs"]
mod harness;

// These two are real product sources compiled straight in via #[path] -
// the source is NOT edited, only included - so the tests exercise the
// shipped code rather than a copy. Hoisted to the root because the
// included code resolves its own dependencies against `crate::`.
//
// Both waivers are `#[expect]` since 23 Aug 2026 and both are
// FULFILLED - measured in default, default + `heavy-tests`,
// `--no-default-features` (which drops the `indexer` half of
// watchlist.rs) and `--target x86_64-pc-windows-gnu --features
// heavy-tests`. The falsifiable form is worth having here precisely
// because the dead set is a property of the PRODUCT source, which
// moves under this file without touching it.
#[expect(dead_code)]
#[path = "../../src/chaos_serve.rs"]
mod chaos_serve;

/// Stand-in for `crate::wall` as seen from src/watchlist.rs. The real
/// wall module re-exports exactly these names from nzbkit::release, so
/// the included code and its embedded unit tests resolve identically.
/// Must live at the crate root: that is where `src/watchlist.rs` looks.
mod wall {
    pub use nzbkit::release::{Kind, Parsed, norm_title, parse_release};
}

// Product-side items this binary happens not to call (the daemon does)
// would otherwise be dead code here, as they were under the per-file
// `#![allow(dead_code)]` these modules used to carry.
#[expect(dead_code)]
#[path = "../../src/watchlist.rs"]
mod watchlist;

mod cors;
mod dashboard_load;
mod dashboard_rev;
mod fault_contract;
mod firstrun_key;
mod groups_api;
mod interests;
mod job_files;
mod library;
mod log_daemon;
mod log_lanes;
mod log_split;
mod newznab;
mod nzblnk;
mod oracle;
mod postproc_lane;
mod pull_search;
mod queue_handoff;
mod remote_compat;
mod settings_catalogue;
mod stream_repair;
mod throttle;
mod tls;
#[path = "wall.rs"]
mod wall_tests;
mod watch_dedupe;
mod watchlist_instant;
mod watchlist_packs;
mod watchlist_regressions;
mod webasset;
