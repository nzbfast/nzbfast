//! nzbfastd (design: M5): queue daemon + SABnzbd-compatible API subset,
//! so Sonarr/Radarr/Prowlarr work day one.
//!
//! Endpoints (JSON): mode=version, get_config, queue, history, addfile
//! (multipart), queue&name=delete. One download runs at a time at full
//! pipeline speed; a watch folder is polled for new .nzb files.

use crate::{MutexExt, RwLockExt};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use serde_json::{Value, json};
use tracing::{error, info, warn};

// `flatten_name` is the house release-name reduction and the pull
// search's cross-indexer merge reads it too, so this is crate-visible.
pub(crate) mod job;
pub use job::*;

// The idle-server prefetch sidecar, moved out of job.rs by TODO 106. A
// sibling rather than a child of `job`, so `pub(super)` still reads "pub
// in serve" and no call site moved.
mod sidecar;
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

mod busy;

mod daemon;
use daemon::*;
// serve/wire.rs: the active download's counters and the drain slot
// (cross-job hand-over), with `Daemon::wire_counters` on them.
mod wire;
use wire::*;

// serve/dupe.rs: inherent methods on `Daemon`, so no glob is needed.
mod dupe;

// serve/spare.rs: TODO 282 section B - the ranked spares a grab holds
// against its own failure, and the same-post admission test the promote
// path now runs too.
mod spare;

mod giveup;
mod histmigrate;
mod histstore;
mod moveseq;
#[cfg(feature = "indexer")]
pub(crate) mod predb_seed;
mod tasks;

mod probeids;

mod mover;
mod naming;
mod postproc;
use postproc::*;

/// §163 item 5: the log tail's scrub, applied on the way out.
mod logscrub;

/// TODO 33: the route lookup behind remote_info's LAN and Tailscale
/// URLs, cached so its wildcard UDP bind stops being a per-call macOS
/// firewall dialog.
mod lanaddr;

mod api;

#[cfg(test)]
mod testutil;

/// §158 item 7: fault injection at the two durable store writes.
#[cfg(test)]
mod storecut;

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

mod bootstrap;
use bootstrap::*;

// `parse_size` moved to `crate::sizes` (TODO 276 item 3); re-exported
// here so every `serve` caller still spells it `parse_size`.
pub(crate) use crate::sizes::parse_size;

mod disk;
pub(crate) use disk::*;

mod update;
use update::*;

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

mod groupscan;
use groupscan::*;

mod origin;
use origin::*;

mod maint;
use maint::*;

mod settings;
use settings::*;

mod watchlist;
use watchlist::*;

// TODO 151 (issue #36): external list sources feeding the watchlist.
mod listsrc;
use listsrc::*;

mod servers;
use servers::*;

mod startup;
use startup::*;

// §125: the throughput graph's learned 100% anchor.
mod linkpeak;

// §129 4b: "Why is this slow?" - live per-job attribution.
mod whyslow;

// §210: the local link (Wi-Fi / port) that carries traffic to the
// news servers, so the tune hint can name it when it is the ceiling.
mod locallink;
// The module stays private to `serve` - everything else in it is the
// daemon's (a probe loop, a `Daemon` field, a median window). One
// function is not: `nzbfast sysbench` runs outside any daemon and needs
// the same reading for its network row, so it gets that one and nothing
// else (TODO 210 item (b), CLI side).

// §129 3e (§108 decision 4): the chronic slow-storage pause.
mod slowstore;

/// Default for `slow_storage_pause`. ON: decision 4's whole point is
/// that a user whose enclosure is dying should be TOLD, not left
/// watching a sawtooth and blaming their line. The downside of a false
/// positive is bounded by design - the job parks in the queue with its
/// journal intact and comes back on its own the moment three clean write
/// checks land - and the pause has to clear a windowed judge AND a real
/// slow probe before it can fire at all.
pub const SLOW_STORAGE_PAUSE_DEFAULT: bool = true;

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

/// One tick of the HTTP workers' accept wait. Long enough to cost
/// nothing (8 workers waking twice a second), short enough that an
/// embedded stop releases the listener promptly.
const HTTP_IDLE_TICK: std::time::Duration = std::time::Duration::from_millis(500);

/// Monotonic count of [`request_stop`] calls, compared against the
/// baseline armed by [`arm_embedded_stop`]. A run is stopped once the
/// epoch has moved past its armed baseline. Monotonic on purpose: a
/// previous run's workers keep winding up on the old epoch bump even
/// after the next run re-arms, and a stop issued in the window between
/// start() returning and serve() starting can never be erased (the old
/// reset-at-entry design lost exactly that stop and hung the caller's
/// join forever).
static STOP_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Epoch snapshot taken by [`arm_embedded_stop`] before the engine
/// thread for a run is spawned. The CLI daemon never arms (both stay 0
/// and `request_stop` is never called there).
static STOP_BASELINE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

fn stop_notify() -> &'static tokio::sync::Notify {
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
pub(crate) struct RunStop {
    baseline: u64,
}

impl RunStop {
    /// Bind to the run that is live now. Called while spawning, i.e.
    /// after the host armed this run's baseline and before the next
    /// start can re-arm it (that happens under the host's engine lock,
    /// which a next start can only take once this run's stop has
    /// joined).
    pub(crate) fn current() -> Self {
        RunStop {
            baseline: STOP_BASELINE.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    /// True once this run has been asked to stop. The epoch is
    /// monotonic, so a later generation re-arming cannot un-stop us.
    pub(crate) fn stopping(self) -> bool {
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
    pub(crate) fn sleep(self, dur: std::time::Duration) -> bool {
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
/// parks that are not run-scoped (`Daemon::park_if_off`): the caller's
/// own [`RunStop`] check decides whether the wake means "exit", this
/// only makes sure a stop is not slept through.
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

/// Spawn a named auxiliary thread and count it while it runs.
///
/// Every lane that outlives a single unit of work goes through here, so
/// [`live_aux_threads`] is a complete census of what a stop has to
/// reclaim - which is what makes the leak provable rather than asserted.
pub(crate) fn spawn_aux(name: &'static str, body: impl FnOnce() + Send + 'static) {
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
    }
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
pub(crate) fn census_daemon(d: &Arc<Daemon>) {
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

mod http;
mod stream;
use stream::*;

// §73 phase 3: the remux half of the preview player. Its own file
// because it is a second byte-serving path with a different contract -
// chunked, no ranges, and a body that can say "not yet" - and reading it
// beside /stream's is how the two stay honestly different.
mod preview;
use preview::*;

mod httputil;

// Not glob-imported: only the handoff redeem in `bootstrap` asks it, by
// path. Which local account owns the far end of a loopback connection.
mod peeracct;
use httputil::*;

mod sabcompat;
use sabcompat::*;

mod nzbget_script;
use nzbget_script::*;

mod script;

// Queue-finished actions (none / script / sleep / shut down).
mod finish_action;

// The blocking half of a completed job's finalization, lifted out of
// `job.rs` under the size gate (TODO 106).
mod job_finalize;
use job_finalize::FinalizeOutcome;

// "Create report": one download's facts and its own log lines, as
// shareable text.
mod report;

mod hooks;

// TODO 280: the container post - a finished download whose own payload
// is another .nzb - and the opt-in switch that queues it, paused.
mod refeed;

mod prequeue;

mod apiutil;
use apiutil::*;

mod fetch;
pub(crate) use fetch::*;

mod indexers;
pub(crate) use indexers::*;

mod reqbody;
use reqbody::*;

mod fsutil;
use fsutil::*;

// Not glob-imported: only `os_open` calls into it, by path, and only on
// Windows. The title matcher inside is portable so it can be tested here.
mod winfront;

mod history;
use history::*;

mod sched;
use sched::*;

mod assets;
use assets::*;

mod webasset;
use webasset::*;

/// Discover an article sample spanning a range of ages for the diversity
/// sweep: recent articles (last few thousand) plus progressively older
/// ranges, so retention limits and takedowns actually differentiate the
/// providers. Uses the first reachable server for discovery.
///
/// "First" is ranked ENABLED FIRST, in config order, and the walk stops
/// at the first server that actually yields a sample. Until 23 Aug 2026
/// this was a bare `servers.first()` with no fallback of any kind, which
/// is the `servers[0]`-with-no-`enabled`-test shape the disabled-server
/// sweep of that day went looking for: on an install whose FIRST
/// configured server is the switched-off one, the sample - and so the
/// shared basis every provider in the report is scored against - came
/// off the one account the user had taken out of service. The same line
/// made a first server that is merely UNREACHABLE fail the whole card,
/// though the sentence above has promised "first reachable" throughout.
///
/// A disabled server is a LAST RESORT here rather than a refusal, and
/// that arm is load-bearing rather than defensive. `m_diversity` hands
/// this the ENABLED servers only, so the ranking above is normally the
/// whole story - but that caller has an opt-in (`value=1`) for the "is
/// this account worth turning back on?" case, and on that path the list
/// carries switched-off entries deliberately. They must still be the
/// last thing tried, and an opt-in run against an all-disabled config
/// must still discover a sample rather than refuse, or the opt-in does
/// nothing on the one config that most needs it.
async fn sample_ids_for_diversity(
    servers: &[nzbkit::config::ServerConfig],
    group: &str,
) -> std::result::Result<Vec<String>, String> {
    let mut last = String::new();
    for srv in servers
        .iter()
        .filter(|s| s.enabled)
        .chain(servers.iter().filter(|s| !s.enabled))
    {
        match sample_ids_from_server(srv, group).await {
            Ok(ids) => return Ok(ids),
            // Keep walking: the point of the ranking is that a candidate
            // that cannot answer costs the next one nothing.
            Err(e) => last = e,
        }
    }
    Err(if last.is_empty() {
        "no servers configured".to_string()
    } else {
        last
    })
}

/// One candidate's half of [`sample_ids_for_diversity`]: connect, walk
/// five age bands, hang up. Split out so the ranking above reads as a
/// plain walk over candidates rather than as control flow wrapped around
/// a connection.
async fn sample_ids_from_server(
    srv: &nzbkit::config::ServerConfig,
    group: &str,
) -> std::result::Result<Vec<String>, String> {
    use nzbkit::nntp::Connection;
    let (mut conn, _) = Connection::connect(srv).await.map_err(|e| e.to_string())?;
    let g = match conn.group(group).await {
        Ok(g) => g,
        Err(e) => {
            // Hang up before moving on. A candidate that greeted us and
            // then refused the group still holds a session on that
            // account until it times out, and the next candidate in the
            // walk may be the same provider under another brand.
            conn.quit().await;
            return Err(e.to_string());
        }
    };
    let mut ids = Vec::new();
    // Five age bands across the group's article-number range.
    let span = g.high.saturating_sub(g.low).max(1);
    for band in 0..5u64 {
        let center = g.high.saturating_sub(span * band / 5);
        let from = center.saturating_sub(2_000).max(g.low);
        if let Ok(entries) = conn.over(from, center).await {
            // ≥150 KB: the sample doubles as the per-server speed probe's
            // fetch set, and header-only posts would understate it.
            for e in entries
                .into_iter()
                .filter(|e| !e.message_id.is_empty() && e.bytes >= 150_000)
                .take(20)
            {
                ids.push(nzbkit::sysbench::bracket_id(&e.message_id));
            }
        }
    }
    conn.quit().await;
    if ids.is_empty() {
        return Err("no sample articles found".into());
    }
    Ok(ids)
}

/// The diversity card's id sample must not be discovered from a server
/// the user switched off while an enabled one is sitting right there.
///
/// Same shape as the disabled-server sweep of 23 Aug 2026, which found a
/// machine holding live sockets to a provider marked `"enabled": false`
/// while another machine was using that same shared account: a lane took
/// `servers[0]` and consulted the flag nowhere. This one is reached by an
/// explicit click rather than by a background tick, so it is the milder
/// case - but it is the same line, and the sample it discovers is the
/// shared basis every provider in the report is scored against.
///
/// Both listeners hang up on the greeting, so no sample can succeed and
/// the call is expected to fail. That is the point: the assertion is on
/// WHICH accounts the walk reached and in what ORDER, which is the only
/// thing this ranking decides. The old `servers.first()` line reaches the
/// disabled listener and nothing else, so it fails here twice over.
#[cfg(test)]
mod diversity_sample_prefers_an_enabled_server {
    use std::sync::mpsc;

    /// A listener that reports the moment it accepts, then hangs up.
    ///
    /// Hanging up rather than going silent matters: `Connection::connect`
    /// has its own multi-second ceiling, and a listener that accepts and
    /// then says nothing makes every run of this test pay a network
    /// timeout it is not measuring.
    fn spy(tx: mpsc::Sender<&'static str>, tag: &'static str) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                // Send BEFORE the shutdown, so the report is on the
                // channel before the client can observe the hang-up and
                // move to the next candidate. That is what makes the
                // order assertion below deterministic rather than a race.
                let _ = tx.send(tag);
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        });
        port
    }

    fn server(port: u16, enabled: bool) -> nzbkit::config::ServerConfig {
        serde_json::from_value(serde_json::json!({
            "host": "127.0.0.1", "port": port, "tls": false,
            "enabled": enabled, "connections": 1
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn the_switched_off_server_is_the_last_candidate_not_the_first() {
        let (tx, rx) = mpsc::channel();
        // The incident's shape exactly: the DISABLED account is first in
        // the array, which is the position the old line took outright.
        let off = spy(tx.clone(), "disabled");
        let on = spy(tx, "enabled");
        let servers = [server(off, false), server(on, true)];

        let r = super::sample_ids_for_diversity(&servers, "alt.binaries.test").await;
        assert!(r.is_err(), "a listener that hangs up cannot yield a sample");

        let reached: Vec<&str> = rx.try_iter().collect();
        assert_eq!(
            reached,
            ["enabled", "disabled"],
            "the sample walk must try the ENABLED server first and reach a \
             switched-off one only after every enabled candidate has failed"
        );
    }

    /// The fallback is deliberate, so it is pinned: an all-disabled config
    /// still gets its sample discovered rather than a refusal. Which
    /// accounts the Analyze button may touch is a decision for its caller,
    /// not something this helper should settle by erroring.
    #[tokio::test]
    async fn an_all_disabled_config_still_walks_its_servers() {
        let (tx, rx) = mpsc::channel();
        let only = spy(tx, "disabled");
        let servers = [server(only, false)];

        let _ = super::sample_ids_for_diversity(&servers, "alt.binaries.test").await;

        assert_eq!(
            rx.try_iter().collect::<Vec<_>>(),
            ["disabled"],
            "with nothing enabled the walk must still reach the one \
             configured server"
        );
    }

    #[tokio::test]
    async fn an_empty_server_list_is_still_an_error() {
        let r = super::sample_ids_for_diversity(&[], "alt.binaries.test").await;
        assert_eq!(r.unwrap_err(), "no servers configured");
    }
}

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
