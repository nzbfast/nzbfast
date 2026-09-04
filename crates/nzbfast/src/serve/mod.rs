//! nzbfastd (design: M5): queue daemon + SABnzbd-compatible API subset,
//! so Sonarr/Radarr/Prowlarr work day one.
//!
//! Endpoints (JSON): mode=version, get_config, queue, history, addfile
//! (multipart), queue&name=delete. One download runs at a time at full
//! pipeline speed; a watch folder is polled for new .nzb files.
//!
//! WHAT IS LEFT HERE, since lane 2 of Option C in
//! `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`: the api, tasks and
//! wiring layers of `SERVE_LAYERS`, plus the root globs that make their
//! bare names resolve. The 71 DAEMON-layer units are `nzbfast-daemon`
//! now and each is re-imported below under its old name, so every
//! `crate::serve::<unit>::...` path in this crate is unchanged.

use crate::MutexExt;

// The daemon layer's own root items, which were declared in this file
// while both layers were one module. `serve` and `park_for_embedded_stop`
// below still read the stop epoch, `ServeOpts` is this function's
// argument, and the api layer names `epoch_secs` in nine files - so they
// are re-exported rather than merely imported, keeping every
// `serve::ServeOpts` path in the bin and in `crates/nzbfast-ffi` alive.
pub use nzbfast_daemon::{
    HTTP_IDLE_TICK, RunStop, SLOW_STORAGE_PAUSE_DEFAULT, STOP_BASELINE, STOP_EPOCH, ServeOpts,
    arm_embedded_stop, census_daemon, epoch_secs, live_aux_threads, live_daemons, parse_size,
    request_stop, spawn_aux, stop_notify,
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use serde_json::json;
use tracing::{info, warn};

pub use job::*;
pub(crate) use nzbfast_daemon::job;

pub(crate) use nzbfast_daemon::sidecar;
pub use sidecar::*;

/// Default for the "fast par mode" setting (`fast_par`). ON since
/// 2026-07-31: the verify-failure fold retry makes wrong
/// output impossible to ship, the trip-breaker and this setting cover
/// live disable, and the RAM/cgroup-scaled retention budget in nzbkit
/// gates small machines onto the fold up front - which together
/// superseded the planned corpus-variety soak. A saved `fast_par` in
/// settings.json still wins over this default. The value lives in
/// nzbkit (it initializes the process-global flag there) so the CLI
/// repair path shares this default without a startup call.
pub use nzbkit::par2repair::FAST_PAR_DEFAULT;

use daemon::*;
pub(crate) use nzbfast_daemon::daemon;
pub(crate) use nzbfast_daemon::wire;
use wire::*;

pub(crate) use nzbfast_daemon::healauto;
pub(crate) use nzbfast_daemon::histmigrate;
pub(crate) use nzbfast_daemon::histstore;
// `pub(crate)` and not `pub`: these four items take and return `Daemon`,
// so a crate-public re-export makes `Daemon` reachable at `pub`, and
// `private_interfaces` then refuses any `pub` field of it that names a
// `pub(crate)` type - which `hub` and `local_link` both did, until
// bb8c6d633 narrowed those two to `pub(crate)` as well. Nothing outside
// this crate uses these four. The belt is on both ends now: this line
// stops `Daemon` being reachable at `pub`, and those fields would be
// legal even if it were.
//
// CORRECTION to what this comment claimed when it landed: the class is
// NOT Windows-specific, and windows-clippy is not the only job passing
// `-p nzbfast-ffi`. BOTH clippy steps in ci-private.yml pass it, and the
// Linux `check` one failed on the identical two errors minutes earlier
// on 24 Aug 2026. It read as a Windows red only because the verdict tool
// that digs a real conclusion out from under main's cancellations was
// rostered on the Windows jobs alone, and nothing did that for `check`.
// Closed the same day: `tools/ci-verdict.py` rosters the Linux jobs too.
// The flag is what pulls nzbfast's LIB target into the lint at all; the
// host clippy line in CLAUDE.md lacked it and gained it in 470efe74d.
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_daemon::predb_seed;

// The background-lane layer, cut out as `nzbfast-tasks` by lane 3 of
// Option C. Re-imported under its old name so every `tasks::spawn_x(..)`
// in this file and in the api layer resolves unchanged.
pub(crate) use nzbfast_tasks::tasks;

#[cfg(feature = "indexer")]
pub(crate) use nzbfast_daemon::seed_harvest;

pub(crate) use nzbfast_daemon::earlyfile;
pub(crate) use nzbfast_daemon::mover;

// The request layer, cut out as `nzbfast-api` by lane 3 of Option C.
// Re-imported under its old name so every `api::dispatch(..)` in
// `http.rs` and `startup.rs` resolves unchanged.
pub(crate) use nzbfast_api::api;

// The daemon crate's two test seams, on through this package's DEV
// dependency on `nzbfast-daemon` with `features = ["test-support"]`.
// Every api-layer test builds its Daemon with `testutil::test_daemon`
// and `api/queue/custody_tests.rs` arms `storecut`'s durable-write cut;
// both were `#[cfg(test)]` items of one crate, and a `cfg(test)` item is
// invisible across a crate boundary whatever its visibility.

use bootstrap::*;
pub(crate) use nzbfast_daemon::bootstrap;

pub(crate) use nzbfast_daemon::update;
use update::*;

// Named by `daemon_api_tests.rs` alone since the `tasks` layer left for
// `nzbfast-tasks` (lane 3), and a `use` can be unused where a `mod`
// never could.
#[cfg(test)]
pub(crate) use nzbfast_daemon::mediadisk;
#[cfg(test)]
pub(crate) use nzbfast_daemon::naming;

pub(crate) use nzbfast_daemon::watchlist;
use watchlist::*;

use listsrc::*;
pub(crate) use nzbfast_daemon::listsrc;

pub(crate) use nzbfast_daemon::servers;
use servers::*;

mod startup;
use startup::*;

pub(crate) use nzbfast_daemon::settings_restore;
use settings_restore::*;

pub(crate) use nzbfast_daemon::linkpeak;

pub(crate) use nzbfast_daemon::linecarry;

pub(crate) use nzbfast_daemon::provquality;

pub(crate) use nzbfast_daemon::whyslow;

pub(crate) use nzbfast_daemon::spill;

pub(crate) use nzbfast_daemon::locallink;
// The module stays private to `serve` - everything else in it is the
// daemon's (a probe loop, a `Daemon` field, a median window). One
// function is not: `nzbfast sysbench` runs outside any daemon and needs
// the same reading for its network row, so it gets that one and nothing
// else (TODO 210 item (b), CLI side).

pub(crate) use nzbfast_daemon::slowstore;

pub async fn serve(config: PathBuf, mut opts: ServeOpts) -> Result<()> {
    // First thing: capture our own stdout/stderr so the dashboard's log
    // viewer sees the whole session, startup lines included.
    nzbkit::logtee::install();
    let settings_path = settings_file(&config);
    apply_saved_settings(&mut opts, &settings_path);
    // Secure-by-default on a genuinely new install (and ONLY there - see
    // first_run_apikey). Printed once, prominently, next to the listener
    // banner below, which is where a new user is looking.
    let minted_key = first_run_apikey(&mut opts, &settings_path, &config)?;
    // A key minted THIS RUN must be disclosed even if startup dies before
    // the banner (see MintDisclosure).
    let mut mint_disclosure =
        MintDisclosure(minted_key.as_ref().map(|(_, keyfile)| keyfile.clone()));
    warn_if_config_moved(&minted_key, &opts.out_root);
    // Saved settings may have overridden the CLI budget; republish so the
    // repair paths use the same figure the rest of the daemon does.
    nzbkit::mem::set_process_budget(opts.mem_budget);
    // One holds ledger per daemon process, so the two pipelines a queue
    // hand-over keeps alive share one holds cap (TODO 219 follow-up).
    // `NZBFAST_HOLDS_LEDGER=0` leaves it uninstalled: each pipeline then
    // budgets its holds from the full slice, the 22 Aug shape.
    if !std::env::var("NZBFAST_HOLDS_LEDGER").is_ok_and(|v| v == "0") {
        nzbkit::extract::install_process_ledger();
    }
    // And one wire-side in-flight ledger, for the same two pipelines and
    // the same reason: `MemBudget::inflight_cap` is a slice of ONE
    // budget, so charged per pool the overlap put twice it on the wire
    // (TODO 313 item 1). `NZBFAST_WIRE_LEDGER=0` leaves it uninstalled -
    // each pipeline then measures only its own bytes, the shape that
    // shipped until 2 Sep 2026.
    if !std::env::var("NZBFAST_WIRE_LEDGER").is_ok_and(|v| v == "0") {
        nzbkit::pool::install_process_wire_charge();
    }
    // The listener, the single-instance lock and the Daemon itself
    // (startup.rs). The lock guard rides home in `booted` and must stay
    // alive for the whole run - dropping it frees the lock.
    let booted = boot(&config, &settings_path, opts)?;
    let daemon = booted.daemon.clone();
    let spool = &booted.spool;

    restore_runtime_state(&daemon, &settings_path, spool, &config, &booted.speedlimit)?;

    spawn_core_tasks(
        &daemon,
        &config,
        &settings_path,
        &booted.schedule,
        &booted.feeds,
        #[cfg(feature = "indexer")]
        &booted.index_db,
        booted.mem_budget,
    )?;

    #[cfg(feature = "indexer")]
    tasks::spawn_enrichment_workers(&daemon);
    spawn_aux_tasks(&daemon, &config);

    announce_ready(
        &daemon,
        &settings_path,
        &booted.bind,
        booted.port,
        booted.tls_on,
        &minted_key,
        &mut mint_disclosure,
        booted.open,
    );
    http::spawn_http_workers(booted.server, daemon.clone(), config.clone());

    park_for_embedded_stop().await;
    // Returning drops our Arc<server>; the workers drop theirs within one
    // HTTP_IDLE_TICK (they poll the stop flag between accepts), and the
    // last drop closes the listener so the port is free to rebind.
    Ok(())
}

/// Park until an embedded host asks for an in-process stop. The CLI
/// daemon never does - its stop paths (signals, tray Quit) exit the
/// process - so for it this parks forever, exactly as before.
async fn park_for_embedded_stop() {
    // The armed baseline cannot move while this run is alive: arming
    // happens under the embedded host's engine lock, which a next start
    // can only take after this run's stop() has joined the engine thread.
    let baseline = STOP_BASELINE.load(std::sync::atomic::Ordering::SeqCst);
    loop {
        stop_notify().notified().await;
        if STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst) > baseline {
            break;
        }
    }
}

mod http;
pub(crate) use nzbfast_daemon::stream;
use stream::*;

// §73 phase 3: the remux half of the preview player. Its own file
// because it is a second byte-serving path with a different contract -
// chunked, no ranges, and a body that can say "not yet" - and reading it
// beside /stream's is how the two stay honestly different.
pub(crate) use nzbfast_api::preview;
use preview::*;

// `GET /metrics`: the daemon's own numbers in Prometheus text
// exposition format. Its own file rather than an arm of the API
// dispatcher because it is a different contract - a text body, no
// `output=json`, no mode, and a hard rule that nothing in it may touch
// the index (TODO 166; a scrape is a poll loop, so it is the worst
// caller to put behind the index write mutex).
pub(crate) use nzbfast_api::metrics;

pub(crate) use nzbfast_daemon::httputil;

use httputil::*;

pub(crate) use nzbfast_api::sabcompat;
use sabcompat::*;

pub(crate) use nzbfast_daemon::nzbget_script;

pub(crate) use nzbfast_daemon::finish_action;

// Only the bin's own tests name these two now: `script` from
// `tests_api.rs`, `peeracct` from `http.rs`'s test module. A `use` can
// be unused where a `mod` never could, so they carry the cfg the `mod`
// never needed.
#[cfg(test)]
pub(crate) use nzbfast_daemon::peeracct;
// `script` is UNIX-ONLY here: `tests_api.rs` gates both of its uses on
// it (the plumbing they cover is a unix path), so an ungated re-import
// is dead on Windows and `-D warnings` makes that a build error there.

// "Create report": one download's facts and its own log lines, as
// shareable text.

pub(crate) use nzbfast_daemon::hooks;

#[cfg(feature = "indexer")]
use apiutil::*;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_daemon::apiutil;

pub(crate) use fetch::*;
pub(crate) use nzbfast_daemon::fetch;

pub(crate) use indexers::*;
pub(crate) use nzbfast_daemon::indexers;

pub(crate) use nzbfast_daemon::reqbody;
use reqbody::*;

// `history_space_tests` went down with `history` and is a private test
// module of that crate now, so there is nothing here to re-import.

#[cfg(feature = "dashboard")]
use assets::*;
#[cfg(feature = "dashboard")]
pub(crate) use nzbfast_api::assets;

#[cfg(feature = "dashboard")]
pub(crate) use nzbfast_daemon::uilocales;
// The catalogue roster is read by `assets` and `settings`, both of which
// are `dashboard` surfaces, so the glob has no slim-build reader - the
// `use`-can-be-unused-where-a-`mod`-cannot shape again.
#[cfg(feature = "dashboard")]
use uilocales::*;

// The browser-facing page machinery, TODO 281 IO3b: every item in it
// serves a WEB page (the two shells, the precompressed catalogues and
// manuals, the per-request stylesheet, and the content negotiation the
// three share), so the module goes as one rather than item by item.
// Without `dashboard` the daemon still answers its whole API - which is
// the only thing either phone shell ever asks it.
#[cfg(feature = "dashboard")]
pub(crate) use nzbfast_api::webasset;
#[cfg(feature = "dashboard")]
use webasset::*;

// DEV-ONLY: the NZBFAST_DEV_WEB_DIR override that serves the pages from
// a checkout's web/ directory instead of the copies compiled in, so a
// dashboard edit is a browser reload rather than a rebuild and a
// restart. Off unless the variable is exported, and gated with the rest
// of the browser-facing half - a slim build carries no page to override.
#[cfg(feature = "dashboard")]
pub(crate) use nzbfast_api::devweb;

// The ten daemon-layer tests that reach up into `api` AND `tasks`, which
// are SIBLING crates: eight of them compose a daemon item with one from
// each, so the bin is the only place that sees both. Lane 2 relocated
// them here from the daemon layer; lane 3 kept them, and the payload
// half went on to `nzbfast-api` because it reaches api alone.
#[cfg(test)]
mod daemon_api_tests;
