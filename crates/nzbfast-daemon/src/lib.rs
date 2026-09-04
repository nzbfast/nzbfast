//! The nzbfast daemon layer - the `Daemon` type, its queue and history
//! stores, its settings, its persistence and the background state every
//! request handler and every lane reads - lifted out as its own crate by
//! lane 2 of Option C in
//! `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`.
//!
//! WHAT MAKES A UNIT DAEMON-LAYER is not a judgement made here: it is
//! `SERVE_LAYERS` in `tools/modgraph.py`, whose `--serve --check` arm
//! runs in CI and refuses a cross-layer edge. The 71 units below are
//! exactly that layer's roster, `git mv`d out of
//! `crates/nzbfast/src/serve/` with their tests, and
//! `crates/nzbfast/src/serve/mod.rs` re-imports each under its OLD NAME
//! (`pub(crate) use nzbfast_daemon::daemon;`) and keeps its own root
//! globs - so every `crate::serve::<unit>::...` path in the api, tasks
//! and wiring layers that stayed in the bin resolves unchanged.
//!
//! THE ORPHAN RULE IS WHY THIS LAYER IS THE BIG ONE. An inherent impl
//! must live in its type's crate, and 282 `impl Daemon` methods in 18
//! units pin 30.5k production lines here whatever else is true. Lane 1b
//! lifted the 61 methods that did NOT belong to the type's own
//! vocabulary out as free functions, which is what took api, tasks and
//! wiring to ZERO impl blocks and made this cut possible at all; the
//! rest are `Daemon`'s own vocabulary and stay.
//!
//! WHAT IS NOT HERE, deliberately: every `include_str!` /
//! `include_bytes!` of `web/`. `assets`, `webasset` and `devweb` are
//! api-layer units and stayed in the bin with the `dashboard` feature,
//! so this crate embeds no web asset and has no build.rs.
//!
//! WHY THE ITEMS ARE `pub` AND NOT `pub(crate)`: they were `pub(crate)`
//! or `pub(in crate::serve)` while this was one crate, and a library's
//! `pub(crate)` is invisible to the bin. The widening was driven by the
//! compiler - only what the layers above actually name crossed over.

// Matches both nzbfast roots and the four layer crates below: `job_json`
// is one `json!` literal per persisted Job field and the macro recurses
// per key.
#![recursion_limit = "256"]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use serde_json::{Value, json};
use tracing::{error, info, warn};

// The lock-poisoning helpers every `.lock_ok()` in this crate resolves
// through. They are `pub use nzbkit::sync::*` in `nzbfast_core::tools`,
// and the bin has them at its own root under these bare names - so
// serve's files reached them without any of them naming a module.
pub use nzbfast_core::tools::{MutexExt, RwLockExt};

// Re-exported from serve's root because that is where it was: `startup`
// and `testutil` both seed a Daemon's fast-par setting from it, and the
// bin re-exports it again so `serve::FAST_PAR_DEFAULT` still resolves.
pub use nzbkit::par2repair::FAST_PAR_DEFAULT;

// The layers below, re-imported under the names serve used while
// everything was one crate: `crate::smart::...`, `crate::wall::...` and
// the rest have to keep resolving from inside these files, and these
// lines are what make them. Exactly the arrangement
// `crates/nzbfast/src/lib.rs` uses for the same modules. The list is
// what the compiler leaves standing - `unused_imports` is `-D warnings`
// in this workspace, and a `use` can be unused where a `mod` never
// could.
//
// FOUR NAMES ARE NOT HERE and cannot be: `listsrc`, `watchlist`,
// `locallink` and `servers` are each BOTH a unit of this crate and a
// module of a layer below it. In the bin those were `crate::watchlist`
// (meta's) and `crate::serve::watchlist` (serve's); here the second one
// IS `crate::watchlist`, so the layer crate is named outright at every
// reference instead (`nzbfast_meta::watchlist::WatchItem`).
pub(crate) use nzbfast_core::{
    conntune, diag, diskfree, eatvol, failkind, health, identify, identity, manifest, netfetch,
    notify, persist, pwfile, sandbox, setup, sizes, srrdb, streamhub, tools,
};
pub(crate) use nzbfast_engine::get;
pub(crate) use nzbfast_meta::{newznab, nzbindex, plex, rss, wall};
pub(crate) use nzbfast_unpack::{smart, unlockpw, unpack};
// `repair` has no PRODUCTION caller left in this layer - `cargo fix`
// pruned it off the lib target - but this crate's own tests name it,
// and a `use` can be unused where a `mod` never could (step 2's
// finding 3, met again). Same shape as `renameclaim` below.
#[cfg(test)]
pub(crate) use nzbfast_unpack::repair;

pub(crate) use nzbfast_core::{interests, xrel};
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::{gates, groups, groupstats};
#[cfg(test)]
pub(crate) use nzbfast_unpack::renameclaim;

// The crate-root GLOBS the bin carries, verbatim, for the same reason
// `nzbfast-engine`'s lib.rs carries them: a glob import at a crate root
// is reachable as a bare name from every descendant, and serve's files
// resolved `StreamHub`, `SeekCtl`, `LossCauses`, `incomplete_reason`,
// `with_build`, `nzb_age_days` and `load_server` through
// `crates/nzbfast/src/lib.rs` without ever naming the module they came
// from. Losing one is not an error where it was exported - it is an
// unresolved name somewhere in here - so they move with the units.
use diag::*;
use get::*;
// Two of serve's own root globs whose `mod` line and `use` line were not
// adjacent in mod.rs, so they are written out here rather than carried
// by the unit block: `peeracct` sat between `mod httputil;` and
// `use httputil::*;`, and `history_space_tests` between `mod history;`
// and `use history::*;`.
use httputil::*;
#[cfg(feature = "indexer")]
use nzbfast_core::servers::*;
use streamhub::*;
use unpack::*;

// This crate's scratch guard, reached the way every other crate in the
// workspace reaches it: one `#[path]` include of `tests/scratch/mod.rs`
// per crate, so the whole tree holds the same type and the sweep's
// `Once` fires once per process.
#[cfg(test)]
mod testscratch;

// `flatten_name` is the house release-name reduction and the pull
// search's cross-indexer merge reads it too, so this is crate-visible.
pub mod job;
pub use job::*;

// The idle-server prefetch sidecar, moved out of job.rs by TODO 106. A
// sibling rather than a child of `job`, so `pub(super)` still reads "pub
// in serve" and no call site moved.
pub mod sidecar;
pub use sidecar::*;

pub mod busy;

pub mod daemon;
use daemon::*;

// wire.rs: the active download's counters and the drain slot
// (cross-job hand-over), with `Daemon::wire_counters` on them.
pub mod wire;
use wire::*;

// requeue.rs: what a job's rerun will cost - the demotion
// watchdog's `RequeueCost` and `requeue_cost`, lifted out of
// `tasks/stall.rs` when the pause warning became a second caller
// (TODO 309(b)), plus `Daemon::pause_cost` and the cache that keeps it
// off the journal on the poll path.
pub mod requeue;

// altcand.rs: §282 alternate candidates - the settings, the queue
// row's offer and the switch. Inherent methods on `Daemon` plus free
// helpers, so no glob is needed.
pub mod altcand;

// altspend.rs: §290 (Codex F-09/F-11) - the one reserve-then-admit
// primitive the hunt, the clicked switch and the automatic promotion all
// pass through. Inherent methods on `Daemon`, so no glob is needed.
pub mod altspend;

// dupe.rs: inherent methods on `Daemon`, so no glob is needed.
pub mod dupe;

// spare.rs: TODO 282 section B - the ranked spares a grab holds
// against its own failure, and the same-post admission test the promote
// path now runs too.
pub mod spare;

pub mod giveup;

/// §310 stage 2: the heal wiring - settle-manifest damage to a job that
/// re-fetches only what is broken, donating from the library folder.
pub mod heal;

/// §310: the scheduled heal - the same two functions on a cadence, with
/// the ceilings a road nobody clicked has to bring of its own.
pub mod healauto;

pub mod histmigrate;

pub mod histstore;

/// §7a: the queue's own append-only store, history's `histstore` shape
/// applied to the queue - see that module's header for the motivation.
pub mod queuestore;

/// §282 section C: hunt for a replacement when a job cannot complete.
pub mod hunt;

// insurance.rs: retention insurance - bank a deferred row's
// payload while its articles are still alive, extract at promotion.
// Inherent picker on `Daemon` plus the watchdog's yield helper.
pub mod insurance;

pub mod moveseq;

/// Server-outage reporting, lifted out of daemon.rs (TODO 106).
pub mod outage;
// The lib target reaches nothing here since the cut - `cargo fix`
// pruned the glob - but `daemon_tests` names `ServerOutage`,
// `row_outage` and `server_down_secs` through it.
#[cfg(test)]
use outage::*;
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
pub mod predb_seed;

// Exact file-aware identity seeds harvested from NZBs the user already
// submitted. Local/offline work, deliberately independent of every
// commercial-indexer and network-enrichment switch.
#[cfg(feature = "indexer")]
pub mod seed_harvest;

pub mod probeids;

pub mod earlyfile;

pub mod mover;

pub mod naming;

pub mod postproc;

/// §163 item 5: the log tail's scrub, applied on the way out.
pub mod logscrub;

/// TODO 33: the route lookup behind remote_info's LAN and Tailscale
/// URLs, cached so its wildcard UDP bind stops being a per-call macOS
/// firewall dialog.
pub mod lanaddr;

// THE TEST-SUPPORT SEAM FAMILY. `cfg(test)` is a property of ONE
// crate's build, so an item behind it is invisible across a crate
// boundary whatever its visibility - the finding steps 2, 3 and 4 each
// met. The bin's api-layer tests build every Daemon with
// `testutil::test_daemon` and `api/queue/custody_tests.rs` arms
// `storecut`, so both are behind the `test-support` feature, turned on
// through nzbfast's DEV dependency and therefore off in
// `cargo build -p nzbfast`.
//
// BOTH ARE INERT UNLESS A TEST ARMS THEM, which is the question step 3
// says to ask per seam - would this feature reading true in the SPAWNED
// daemon change what a user gets? `testutil` only constructs a Daemon
// over a directory the caller names, and `storecut`'s cuts and gaps are
// thread-locals defaulting to None. So neither is a default-off runtime
// switch; the feature is enough.
#[cfg(any(test, feature = "test-support"))]
pub mod testutil;

/// §158 item 7: fault injection at the two durable store writes.
#[cfg(any(test, feature = "test-support"))]
pub mod storecut;

pub mod bootstrap;
use bootstrap::*;

pub mod disk;
pub(crate) use disk::*;

pub mod update;
use update::*;

pub mod groupscan;
#[cfg(feature = "indexer")]
use groupscan::*;

pub mod origin;
use origin::*;

pub mod maint;

/// The two writes a finished connection ladder makes into `Daemon`
/// state. Below `tasks` because the manual Test, the settings setter and
/// the local-link probe all make them; see the module header.
/// The §77 post-health probe engine. Below `tasks` because
/// `api::queue::preview` runs the §303 add-time preview; see the module
/// header.
pub mod postprobe;

/// The on-demand RAR byte-probe engine. Below `tasks` because
/// `api::index::pull` runs it for a row a human is looking at; see the
/// module header.
#[cfg(feature = "indexer")]
pub mod rarprobe;

/// The on-disk half of the §76 media prober. Below `tasks` because
/// `histmigrate`'s re-derivation pass reads it; see the module header.
pub mod mediadisk;

pub mod tunestate;

/// The watch-folder failure vocabulary - the six state strings, the
/// classifier, the ingested predicate and the row handle. Below `tasks`
/// because the SAB facade and `api::queue` read all four; see the module
/// header. No glob: every consumer names the module, and `watchfolder`
/// reaches the state strings as `watchfail::TRUNCATED` exactly as it did
/// when they were an inner module of its own file.
pub mod watchfail;

pub mod settings;

pub mod watchlist;
// Unused by the SLIM lib target and used by every other one - the
// slim TEST build reaches it through `testutil`, which builds a
// Daemon out of the seeders. A `use` can be unused where a `mod`
// never could (step 2's finding 3).
#[cfg(any(feature = "indexer", test, feature = "test-support"))]
use watchlist::*;

// TODO 151 (issue #36): external list sources feeding the watchlist.
pub mod listsrc;
use listsrc::*;

pub mod servers;
use servers::*;

// The settings-restore half of startup, moved out under the size gate
// (TODO 106). A sibling and not a child of `startup` on purpose - see
// that file's header: as a child, `pub(super)` on its ~45 seeders would
// have meant "visible in startup" rather than "visible in serve", and
// every one would have needed respelling.
pub mod settings_restore;
// Unused by the SLIM lib target and used by every other one - the
// slim TEST build reaches it through `testutil`, which builds a
// Daemon out of the seeders. A `use` can be unused where a `mod`
// never could (step 2's finding 3).
#[cfg(any(feature = "indexer", test, feature = "test-support"))]
use settings_restore::*;

// §125: the throughput graph's learned 100% anchor.
pub mod linkpeak;

// TODO 275 item 1 part 2: the per-socket carry the last job measured,
// which is what the next job's fleet seed starts from.
pub mod linecarry;

// Longitudinal per-provider quality: the rolling 30-day ledger of what
// each news server delivered, and the advice that reads out of it.
pub mod provquality;

// §129 4b: "Why is this slow?" - live per-job attribution.
pub mod whyslow;

// TODO 313 items 3-5 and 10: the spill governor - when a head cannot
// use the fleet it holds, lend the unused part of it to the QUEUE.
// Behind `queue_spill`, which is OFF.
pub mod spill;

// §210: the local link (Wi-Fi / port) that carries traffic to the
// news servers, so the tune hint can name it when it is the ceiling.
pub mod locallink;

// §129 3e (§108 decision 4): the chronic slow-storage pause.
pub mod slowstore;

pub mod stream;
use stream::*;

pub mod httputil;

// Not glob-imported: only the handoff redeem in `bootstrap` asks it, by
// path. Which local account owns the far end of a loopback connection.
pub mod peeracct;

/// The SAB vocabulary the DAEMON layer shares with the API layer -
/// `SAB_VERSION`, the newznab category map, the `search=` predicate.
/// Below both `sabcompat` and `api`, so a daemon-layer module reaching
/// for one of them is not an upward edge; see the module header.
pub mod sabvocab;
use sabvocab::*;

pub mod nzbget_script;
use nzbget_script::*;

pub mod script;

// Queue-finished actions (none / script / sleep / shut down).
pub mod finish_action;

// The blocking half of a completed job's finalization, lifted out of
// `job.rs` under the size gate (TODO 106).
pub mod job_finalize;
use job_finalize::FinalizeOutcome;

pub mod hooks;

// TODO 280: the container post - a finished download whose own payload
// is another .nzb - and the opt-in switch that queues it, paused.
pub mod refeed;

pub mod prequeue;

pub mod apiutil;
use apiutil::*;

pub mod fetch;
pub(crate) use fetch::*;

pub mod indexers;
pub(crate) use indexers::*;

pub mod reqbody;

pub mod fsutil;
use fsutil::*;

// Not glob-imported: only `os_open` calls into it, by path, and only on
// Windows. The title matcher inside is portable so it can be tested here.
pub mod winfront;

pub mod history;

#[cfg(test)]
mod history_space_tests;

pub mod sched;
use sched::*;

/// The UI locale tag list. Below `assets` because the DAEMON layer reads
/// it - `settings_setters` validates `ui_lang` against it on every build,
/// dashboard feature or not - where everything else about a locale is
/// browser-facing; see the module header.
pub mod uilocales;
use uilocales::*;

pub struct ServeOpts {
    pub port: u16,
    /// Listen address for the dashboard + API. Default "0.0.0.0" (all
    /// interfaces) and it stays that way deliberately: the product is
    /// routinely run on a NAS or a headless box with Sonarr/Radarr and
    /// the phone remote on OTHER hosts, so a loopback default would
    /// break the normal deployment for everybody in exchange for less
    /// protection than the API key itself provides. Operators who want
    /// the narrow bind can now ask for it (`--bind 127.0.0.1`).
    pub bind: String,
    /// §129 2a: PEM certificate chain for opt-in native HTTPS. With
    /// `tls_key` set too, the ONE listener serves https instead of http;
    /// either alone (or neither) keeps plain HTTP, with a startup note
    /// saying which half is missing. Applied at bind time only - change
    /// via settings + restart, like the port.
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching `tls_cert`.
    pub tls_key: Option<PathBuf>,
    /// Open the dashboard in a browser once the listener is up.
    pub open: bool,
    pub apikey: Option<String>,
    pub nzbkey: Option<String>,
    pub out_root: PathBuf,
    pub watch: Option<PathBuf>,
    pub script: Option<PathBuf>,
    pub connections: usize,
    pub window: usize,
    pub decoders: usize,
    /// PAR2 fast verify (TODO §10): claim in-stream blocks by CRC32 only
    /// (each article's yEnc CRC already passed); settle read-back and
    /// disk-fed spans keep full MD5. Default ON - bench-validated 2.9×
    /// on CPU-bound boxes (a quick-verify default).
    pub fast_verify: bool,
    /// M32 lean verify (slow-CPU boost, see verify_mode setting).
    pub verify_lean: bool,
    /// M14i: categories whose jobs are metadata-only library entries.
    pub library_cats: Vec<String>,
    /// Re-verify interval for parked library jobs (seconds).
    pub library_recheck_secs: u64,
    /// Pause new jobs while free space on out_root is below this (bytes).
    pub min_free: Option<u64>,
    /// Permissions for finished downloads, as a umask (#20). None =
    /// off, which is the default and today's behaviour.
    pub out_umask: Option<u32>,
    /// M32: minutes before the one automatic retry of a job that failed
    /// with missing articles (0 = off; default 20).
    pub auto_retry_mins: u64,
    /// Sample each job's articles with STAT before downloading, and fail
    /// it up front when the post cannot possibly complete. The CLI has
    /// had `--preflight` since M2; the daemon never offered it, so a
    /// wholly dead post was discovered the slow way - the 31 Jul Silo
    /// job spent six minutes and 0 bytes to reach a verdict a two-second
    /// sample gives. Off by default: it costs a round of STATs on every
    /// job, including the overwhelming majority that are perfectly fine.
    /// `settings.json` only - deliberately not in the dashboard, which
    /// would need the string in all 21 UI locales for a switch aimed at
    /// people whose provider is shedding posts.
    pub preflight: bool,
    /// Byte budget per quota period; new jobs wait for the next period
    /// once it's spent (Force-priority jobs bypass).
    pub quota: Option<u64>,
    /// 'd' (daily, UTC midnight) or 'm' (monthly, 1st 00:00 UTC).
    pub quota_period: char,
    /// M14k: RSS feed config file (see rss.rs for format).
    pub feeds: Option<PathBuf>,
    /// M14g2: initial download speed cap (e.g. "4M"; 0/absent = unlimited).
    pub speedlimit: Option<String>,
    /// M14g2: time-of-week schedule file (see parse_schedule).
    pub schedule: Option<PathBuf>,
    /// M14g3: RTT-governed auto speed (yield to other household traffic).
    pub auto_speed: bool,
    /// M15: pipeline cache-tier budget (see nzbkit::mem).
    pub mem_budget: nzbkit::mem::MemBudget,
    /// M12: index database path (newznab facade + dashboard browse).
    #[cfg(feature = "indexer")]
    pub index_db: PathBuf,
    /// M12: groups to OVER-scan continuously (empty = no scanning).
    #[cfg(feature = "indexer")]
    pub index_groups: Vec<String>,
    #[cfg(feature = "indexer")]
    pub index_interval_secs: u64,
    /// Articles to backfill on a group's first scan.
    #[cfg(feature = "indexer")]
    pub index_backfill: u64,
    /// Fetch newsgroup descriptions from ISC as well as the provider.
    pub group_desc_isc: bool,
    /// Only index posts newer than this (seconds; 0 = off). Overrides
    /// the backfill count on a first scan via Date bisection.
    #[cfg(feature = "indexer")]
    pub index_max_age_secs: u64,
    /// Ingest gates for the scanner (kind/year/res/language/title/size).
    #[cfg(feature = "indexer")]
    pub index_gates: Option<crate::gates::Gates>,
}

// `parse_size` moved to `crate::sizes` (TODO 276 item 3); re-exported
// here so every `serve` caller still spells it `parse_size`.
pub use crate::sizes::parse_size;

pub fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Default for `slow_storage_pause`. ON: decision 4's whole point is
/// that a user whose enclosure is dying should be TOLD, not left
/// watching a sawtooth and blaming their line. The downside of a false
/// positive is bounded by design - the job parks in the queue with its
/// journal intact and comes back on its own the moment three clean write
/// checks land - and the pause has to clear a windowed judge AND a real
/// slow probe before it can fire at all.
pub const SLOW_STORAGE_PAUSE_DEFAULT: bool = true;

/// One tick of the HTTP workers' accept wait. Long enough to cost
/// nothing (8 workers waking twice a second), short enough that an
/// embedded stop releases the listener promptly.
pub const HTTP_IDLE_TICK: std::time::Duration = std::time::Duration::from_millis(500);

/// Monotonic count of [`request_stop`] calls, compared against the
/// baseline armed by [`arm_embedded_stop`]. A run is stopped once the
/// epoch has moved past its armed baseline. Monotonic on purpose: a
/// previous run's workers keep winding up on the old epoch bump even
/// after the next run re-arms, and a stop issued in the window between
/// start() returning and serve() starting can never be erased (the old
/// reset-at-entry design lost exactly that stop and hung the caller's
/// join forever).
pub static STOP_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Epoch snapshot taken by [`arm_embedded_stop`] before the engine
/// thread for a run is spawned. The CLI daemon never arms (both stay 0
/// and `request_stop` is never called there).
pub static STOP_BASELINE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Set by [`arm_embedded_stop`], i.e. true exactly when a host app owns
/// this process rather than the CLI owning it. Latches on: a process
/// that has hosted the engine once keeps hosting it.
static EMBEDDED: AtomicBool = AtomicBool::new(false);

/// True when an embedded host owns the process. The paths that care are
/// the ones that would end it: an embedded stop must not take the host
/// app down with it.
pub(crate) fn is_embedded() -> bool {
    EMBEDDED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Arm the next embedded run: snapshot the stop epoch so a leftover
/// stop request from a previous run cannot fell this one. Must be
/// called by the embedded host BEFORE spawning the engine thread and
/// under the same lock that serializes start against stop, so every
/// `request_stop` issued after start() returns lands above the
/// baseline.
// dead_code: only the embedded crate root (lib.rs, `ffi` feature) has a
// caller; see request_stop below.
// Not #[expect] for that reason: under the ffi root the item is live
// and the expectation goes unfulfilled.
#[allow(dead_code)]
pub fn arm_embedded_stop() {
    EMBEDDED.store(true, std::sync::atomic::Ordering::SeqCst);
    STOP_BASELINE.store(
        STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst),
        std::sync::atomic::Ordering::SeqCst,
    );
}

pub fn stop_notify() -> &'static tokio::sync::Notify {
    static N: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

/// The blocking half of the stop signal. `stop_notify` only reaches
/// tasks on a runtime; the auxiliary lanes are plain OS threads asleep
/// in `thread::sleep`, and a condvar is what wakes those.
fn stop_gate() -> &'static (Mutex<()>, std::sync::Condvar) {
    static G: std::sync::OnceLock<(Mutex<()>, std::sync::Condvar)> = std::sync::OnceLock::new();
    G.get_or_init(|| (Mutex::new(()), std::sync::Condvar::new()))
}

/// A run's stop token: what every long-lived auxiliary thread carries so
/// an embedded stop actually reaches it.
///
/// The CLI daemon never arms and never stops, so for it [`stopping`] is
/// permanently false and [`sleep`] is exactly `thread::sleep` - the
/// behaviour these lanes have always had. An embedded host, though, runs
/// a NEW daemon generation per `nzbfast_start`, and `nzbfast_stop` only
/// joins the engine thread: before this token, every generation's update
/// checker, scheduled bench, auto-tuner and metadata lanes stayed alive
/// holding an `Arc<Daemon>`, so N start/stop cycles left N whole daemon
/// graphs - and their threads - still running, still touching config and
/// the network, after the host API had reported stopped.
///
/// [`stopping`]: RunStop::stopping
/// [`sleep`]: RunStop::sleep
#[derive(Clone, Copy, Debug)]
pub struct RunStop {
    baseline: u64,
}

impl RunStop {
    /// Bind to the run that is live now. Called while spawning, i.e.
    /// after the host armed this run's baseline and before the next
    /// start can re-arm it (that happens under the host's engine lock,
    /// which a next start can only take once this run's stop has
    /// joined).
    pub fn current() -> Self {
        RunStop {
            baseline: STOP_BASELINE.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    /// True once this run has been asked to stop. The epoch is
    /// monotonic, so a later generation re-arming cannot un-stop us.
    pub fn stopping(self) -> bool {
        STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst) > self.baseline
    }

    /// Sleep up to `dur`, waking the moment this run is asked to stop.
    /// `false` means stop: the caller must return, which is what drops
    /// its `Arc<Daemon>`.
    ///
    /// A plain `thread::sleep(6h)` is why this exists. The update
    /// checker sleeps six hours between passes; a host that starts and
    /// stops the engine a dozen times in that window used to accumulate
    /// a dozen checkers, none of which had looked at a stop flag yet.
    #[must_use]
    pub fn sleep(self, dur: std::time::Duration) -> bool {
        let deadline = Instant::now() + dur;
        let (lock, cv) = stop_gate();
        let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            // Re-read the epoch HOLDING the lock, and before waiting.
            // `request_stop` bumps it under this same lock, so the two
            // orderings are covered: a stop that lands before we park is
            // seen here, and one that lands while we hold the lock is
            // blocked until `wait_timeout` releases it and therefore
            // reaches us as a wake. Checking only after the wait would
            // lose the first case - and a lost wake on a six-hour sleep
            // IS the leak, arrived at from the other direction.
            if self.stopping() {
                return false;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            let (next, _) = cv.wait_timeout(g, left).unwrap_or_else(|p| p.into_inner());
            g = next;
        }
    }
}

/// Sleep up to `dur`, waking early on ANY stop request. For the few
/// parks that are not run-scoped (`Daemon::park_metadata_lanes`): the
/// caller's own [`RunStop`] check decides whether the wake means "exit",
/// this only makes sure a stop is not slept through.
#[cfg(feature = "indexer")]
pub(crate) fn sleep_until_stop_bump(dur: std::time::Duration) {
    let epoch = STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst);
    let deadline = Instant::now() + dur;
    let (lock, cv) = stop_gate();
    let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst) != epoch {
            return;
        }
        let (next, _) = cv.wait_timeout(g, left).unwrap_or_else(|p| p.into_inner());
        g = next;
    }
}

/// Long-lived auxiliary threads alive right now, across every
/// generation, counted per lane name. Named rather than merely counted
/// so a failed reclamation says WHICH lane is still running - a bare
/// "expected 0, got 2" is a day of bisecting.
///
/// Entered before the spawn, cleared by a guard the thread body owns, so
/// a panicking lane still clears its token and the census cannot stick
/// high.
static AUX_THREADS: Mutex<std::collections::BTreeMap<&'static str, usize>> =
    Mutex::new(std::collections::BTreeMap::new());

struct AuxCensus(&'static str);

impl Drop for AuxCensus {
    fn drop(&mut self) {
        let mut g = AUX_THREADS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = g.get_mut(self.0) {
            *n -= 1;
            if *n == 0 {
                g.remove(self.0);
            }
        }
    }
}

/// Spawn a named auxiliary thread and count it while it runs. `false`
/// means the OS refused the thread and nothing is running.
///
/// Every lane that outlives a single unit of work goes through here, so
/// [`live_aux_threads`] is a complete census of what a stop has to
/// reclaim - which is what makes the leak provable rather than asserted.
///
/// Most callers ignore the verdict: a lane that fails to start is a
/// feature that quietly does not happen, on a host with no threads
/// left. The pause timer reads it because it arms a live-worker flag
/// BEFORE the spawn, and a flag left set with nothing running would
/// disable auto-resume for the life of the process.
pub fn spawn_aux(name: &'static str, body: impl FnOnce() + Send + 'static) -> bool {
    *AUX_THREADS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(name)
        .or_default() += 1;
    let spawned = std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let _census = AuxCensus(name);
            body();
        });
    if let Err(e) = spawned {
        drop(AuxCensus(name));
        warn!(target: "serve", "{name} thread failed to start: {e}");
        return false;
    }
    true
}

/// Live auxiliary lanes (see [`spawn_aux`]) as `name x count`, empty
/// when everything has been reclaimed. Exposed for the embedded host's
/// reclamation test; nothing in the product reads it.
// dead_code: test-only reader, and it lives in another crate.
// Not #[expect] for that reason: under the ffi root the item is live
// and the expectation goes unfulfilled.
#[allow(dead_code)]
pub fn live_aux_threads() -> Vec<(String, usize)> {
    AUX_THREADS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .map(|(k, v)| ((*k).to_string(), *v))
        .collect()
}

/// Every `Arc<Daemon>` this process has built, held weakly.
///
/// A generation that fails to wind up keeps its `Weak` upgradable, which
/// is precisely the leak this exists to detect: one entry per run, and
/// after a stop only the live run may still upgrade.
static DAEMON_CENSUS: Mutex<Vec<std::sync::Weak<Daemon>>> = Mutex::new(Vec::new());

/// Enrol a freshly built daemon. Called at the one production
/// construction site, right after the `Arc`.
pub fn census_daemon(d: &Arc<Daemon>) {
    let mut g = DAEMON_CENSUS.lock().unwrap_or_else(|p| p.into_inner());
    g.retain(|w| w.strong_count() > 0);
    g.push(Arc::downgrade(d));
}

/// Daemon generations still alive. Exposed for the embedded host's
/// reclamation test; nothing in the product reads it.
// dead_code: test-only reader, and it lives in another crate.
// Not #[expect] for that reason: under the ffi root the item is live
// and the expectation goes unfulfilled.
#[allow(dead_code)]
pub fn live_daemons() -> usize {
    let mut g = DAEMON_CENSUS.lock().unwrap_or_else(|p| p.into_inner());
    g.retain(|w| w.strong_count() > 0);
    g.len()
}

/// In-process stop for embedded builds (the iOS staticlib, where exec
/// and process exit are not available): [`serve`] returns instead of
/// parking and the HTTP workers wind up, closing the listener. This is
/// NOT the graceful wind-down the signal path runs - the embedded host
/// stops the tokio runtime after serve() returns, which is what cancels
/// the background tasks. Safe to call before serve() reaches its park
/// loop or more than once per run: the epoch bump is permanent and a
/// Notify permit is held until consumed.
///
/// Stopping the runtime is NOT enough on its own: the auxiliary lanes
/// are plain OS threads, invisible to `shutdown_timeout`, so this also
/// wakes the blocking [`stop_gate`] every [`RunStop::sleep`] waits on.
// dead_code: only the embedded crate root (lib.rs, `ffi` feature) has a
// caller; the CLI daemon stops by process exit. The module compiles
// under both roots, so the bin build sees this as dead.
// Not #[expect] for that reason: the ffi root and the unit tests below
// both reach it, and the expectation goes unfulfilled there.
#[allow(dead_code)]
pub fn request_stop() {
    {
        // The bump happens UNDER the gate's lock, which is what makes
        // the auxiliary lanes' park race-free: a lane either reads the
        // new epoch before it parks, or it is already parked and gets
        // the notify. See `RunStop::sleep`.
        let (lock, cv) = stop_gate();
        let _g = lock.lock().unwrap_or_else(|p| p.into_inner());
        STOP_EPOCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        cv.notify_all();
    }
    stop_notify().notify_one();
}

/// The stop seam itself, at unit speed. `crates/nzbfast-ffi/tests/
/// reclaim.rs` proves the whole generation is reclaimed; these three
/// pin the primitive it rests on, including the ordering that a
/// full-daemon test could only catch by flaking.
#[cfg(test)]
mod stop_seam_tests {
    use super::*;
    use std::time::Duration;

    /// `STOP_EPOCH` is process-global, so these run one at a time. They
    /// deliberately do NOT call `arm_embedded_stop` - that latches the
    /// EMBEDDED flag for the whole binary - and take their baseline off
    /// the epoch directly instead, which is all arming does anyway.
    static SEAM: Mutex<()> = Mutex::new(());

    fn arm_here() -> RunStop {
        RunStop {
            baseline: STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    #[test]
    fn a_stop_wakes_a_parked_lane_instead_of_waiting_out_its_interval() {
        let _seam = SEAM.lock().unwrap_or_else(|p| p.into_inner());
        let stop = arm_here();
        let lane = std::thread::spawn(move || {
            let at = Instant::now();
            (stop.sleep(Duration::from_secs(3600)), at.elapsed())
        });
        // Long enough for the lane to be parked on the condvar.
        std::thread::sleep(Duration::from_millis(100));
        request_stop();
        let (keep_going, took) = lane.join().expect("lane");
        assert!(!keep_going, "sleep must report the stop");
        assert!(
            took < Duration::from_secs(30),
            "the lane slept {took:?} of its hour - the wake was lost"
        );
    }

    /// The interleaving a condvar makes easy to get wrong: the epoch
    /// moves while the lane is between "checked for a stop" and
    /// "parked". A condvar has no memory, so by the time the lane waits
    /// the notify is already spent - and it would sit out its full
    /// interval (six hours, for the update checker) still holding the
    /// generation it was told to release.
    ///
    /// Driven deterministically rather than by racing threads: the test
    /// holds the gate lock, which pins the lane in exactly that window,
    /// and moves the epoch with no notify at all. Waking from THAT is
    /// the contract - `sleep` must re-read the epoch under the lock
    /// before it waits, not only after.
    #[test]
    fn a_stop_that_lands_in_the_park_window_is_not_lost() {
        let _seam = SEAM.lock().unwrap_or_else(|p| p.into_inner());
        let stop = arm_here();
        let held = stop_gate().0.lock().unwrap_or_else(|p| p.into_inner());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Passes its own stop check, then blocks on the gate lock.
            let _ = tx.send(stop.sleep(Duration::from_secs(3600)));
        });
        // Let it reach the lock, then stop it without any notify.
        std::thread::sleep(Duration::from_millis(100));
        STOP_EPOCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        drop(held);
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(keep_going) => assert!(!keep_going, "sleep must report the stop"),
            Err(e) => panic!("the lane never woke ({e}) - the stop was lost in the park window"),
        }
    }

    #[test]
    fn an_unstopped_run_still_sleeps_out_its_interval() {
        let _seam = SEAM.lock().unwrap_or_else(|p| p.into_inner());
        let stop = arm_here();
        let at = Instant::now();
        assert!(stop.sleep(Duration::from_millis(150)), "no stop pending");
        // The CLI daemon's lanes must keep their pacing: a token that
        // returned early would turn every "check every 6 h" into a hot
        // loop. Slack for a coarse timer.
        assert!(
            at.elapsed() >= Duration::from_millis(120),
            "woke after only {:?}",
            at.elapsed()
        );
    }
}
