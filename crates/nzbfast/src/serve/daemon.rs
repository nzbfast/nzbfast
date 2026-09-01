use super::*;
use tracing::{debug, error, info, warn};

// The index-handle discipline, the read-connection pool behind it, and
// the M34 size cap - a second `impl Daemon`, moved out bodily (TODO
// 106). A child module, so it keeps `Daemon`'s private fields in scope.
// The pool's own types went with it (TODO 106 again, 25 Aug 2026): they
// exist for `index_read_acquire`, which is in there, and nothing else
// in the tree names `Reader`, `IndexReader` or `IndexReadState` - so
// moving them tightens their visibility instead of widening it, which
// is the opposite of what a sibling module would have cost.
#[path = "daemon_index.rs"]
mod daemon_index;
// `Daemon`'s own field is typed on this, and `startup.rs` and
// `testutil.rs` construct it by name, so the pool type keeps the
// reach it had inline.
#[cfg(feature = "indexer")]
pub use daemon_index::IndexReadPool;
// Same reason: `Daemon`'s `index_ledger` field is typed on it.
#[cfg(feature = "indexer")]
pub use daemon_index::IndexLedger;

// The whole `enqueue` add path, moved out bodily (TODO 106). Same
// child-module shape as daemon_index for the same reason.
#[path = "daemon_enqueue.rs"]
mod daemon_enqueue;

// Every way a job is sent round again - the M32 auto-retry cooldown, the
// manual retry, and the move-retry ladder under both (TODO 106). Same
// child-module shape.
#[path = "daemon_retry.rs"]
mod daemon_retry;

// The queue on disk: save_queue out, load_queue back (TODO 106). Same
// child-module shape.
#[path = "daemon_persist.rs"]
mod daemon_persist;

// §131 D3 search-miss logging - the in-memory buffer that keeps
// recording a search off the query path. Same child-module shape as
// daemon_index for the same reason.
// The provider ledger: bytes billed per server per day, the reliability
// tally, and the block-account arithmetic on top of both (TODO 106).
// Same child-module shape.
#[path = "daemon_usage.rs"]
mod daemon_usage;

// The warm pool, the idle-release policy, and the offline switch over
// the top (TODO 106). Same child-module shape.
#[path = "daemon_idle.rs"]
mod daemon_idle;
// How fast the line is running, what it costs in CPU, and what ceiling
// is imposed on it - the measured rate, the imposed cap, and the AIMD
// governor that picks its own (TODO 106). Same child-module shape as
// daemon_index. The governor is a free function, so it and its four
// constants are re-exported and tasks.rs and tests_index.rs still name
// them unqualified.
#[path = "daemon_speed.rs"]
mod daemon_speed;
pub(in crate::serve) use daemon_speed::{AUTO_SPEED_TARGET_MS, auto_speed_step, window_rate};
// Split from the line above rather than folded into it: production
// reads only the target and the step, and the three BOUNDS are read
// only by the arithmetic pin in tests_index.rs. A single re-export is
// three `unused_imports` in every non-test build, which `-D warnings`
// makes fatal - so the split is the gate's answer, not a preference.
#[cfg(test)]
pub(in crate::serve) use daemon_speed::{AUTO_SPEED_FLOOR, AUTO_SPEED_MAX, AUTO_SPEED_START};

// Which category a job is, and which directory it lands in - the
// offered set and its defaults, the per-category overrides, and the
// path routing that reads them (TODO 106). Same child-module shape as
// daemon_index. `CatMeta` and `DEFAULT_CATS` are named from elsewhere
// in serve, so those two are re-exported and every call site still
// spells them exactly as it did inline.
#[path = "daemon_cats.rs"]
mod daemon_cats;
pub(in crate::serve) use daemon_cats::{CatMeta, DEFAULT_CATS};

// How a job stops running - failure report, sidecar abort, delete
// quarantine, park into history, idle and give-up: one subject, moved
// whole (TODO 106).
#[path = "daemon_park.rs"]
mod daemon_park;
pub(in crate::serve) use daemon_park::{CustodyBatch, SidecarTailGuard};

// Which of the user's indexer accounts a background lane speaks to -
// the scoreboard's and the confirm lane's reference resolution, the
// display state of that verdict, and the request-per-day cost of a
// sample (TODO 106). Same child-module shape as daemon_index.
#[path = "daemon_indexref.rs"]
mod daemon_indexref;

// May a background index pass run right now, and how does it say why
// not - the per-source stand-down reasons, the sentence the log prints,
// and the job counter both reasons read (TODO 106). Same child-module
// shape as daemon_index. No cfg on the module: `begin_index_job` is on
// the download path, so the `indexer` gates stay per-item.
#[path = "daemon_indexgate.rs"]
mod daemon_indexgate;

// Winding down the RUNNING TRANSFER without ending the job - the pause
// button, the *arr remote, the scheduler and the slow-disk hold all
// land here, and the job stays in the queue and resumes from the
// article journal (TODO 106). Same child-module shape as daemon_index.
// Distinct from both neighbours below: daemon_park is how a job stops
// for good, daemon_shutdown is how the DAEMON stops.
#[path = "daemon_suspend.rs"]
mod daemon_suspend;

// How the daemon stops - the graceful wind-down under mode=shutdown and
// SIGTERM/SIGINT - and the pause timer that stops it temporarily, with
// the pause state carried across a restart (TODO 106). Same
// child-module shape. These are free functions rather than a second
// `impl Daemon`, so unlike its siblings this one is re-exported: every
// call site names them unqualified through serve/mod.rs's
// `use daemon::*`.
#[path = "daemon_shutdown.rs"]
mod daemon_shutdown;
pub(in crate::serve) use daemon_shutdown::*;

// §131 D3's search-miss log, whole: every write in it needs the index,
// so the module is gated rather than each item in it.
#[cfg(feature = "indexer")]
#[path = "searchlog.rs"]
mod searchlog;
#[cfg(feature = "indexer")]
pub use searchlog::*;

/// RAII claim on "a connection ladder is running".
///
/// Released on drop, INCLUDING the drop that happens when a ladder
/// future is cancelled by its caller's timeout - which is the case a
/// bare set/clear pair gets wrong, leaving the tuner permanently
/// "busy" after one slow provider.
pub(in crate::serve) struct LadderPermit(std::sync::Arc<Daemon>);

impl LadderPermit {
    /// `None` when another ladder already holds it.
    pub(in crate::serve) fn try_take(d: &std::sync::Arc<Daemon>) -> Option<Self> {
        d.ladder_busy
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
            .then(|| LadderPermit(d.clone()))
    }
}

impl Drop for LadderPermit {
    fn drop(&mut self) {
        self.0
            .ladder_busy
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// A connection ladder in flight, as the dashboard sees it.
#[derive(Clone, serde::Serialize)]
pub struct LadderLive {
    pub host: String,
    /// What the ladder is doing right now, as a TOKEN the UI translates:
    /// climb, recheck, refine, ceiling, runoff, runoff2, done.
    pub phase: String,
    /// Connection count currently being measured.
    pub at: usize,
    /// Every rung settled so far, oldest first.
    pub steps: Vec<nzbkit::sysbench::LadderStep>,
    /// Unix seconds when this run started, so the UI can show elapsed
    /// time without trusting its own clock against the daemon's.
    pub started: u64,
    pub done: bool,
}

pub struct Daemon {
    /// Streaming handle into the active download (M11).
    // `pub(crate)`, not `pub`: `StreamHub` is a `pub(crate)` type, so a
    // `pub` field naming it is `private_interfaces` - a DENY under the
    // clippy gate, and it took main red on 24 Aug 2026. Narrowed rather
    // than widening `StreamHub`, because every reader of this field is
    // inside this crate and the type is not part of any public surface.
    pub(crate) hub: Arc<crate::StreamHub>,
    /// Paused: no NEW job starts (the active transfer finishes).
    pub paused: std::sync::atomic::AtomicBool,
    /// OFFLINE: touch no provider at all, and hang up everything already
    /// held - the warm pools, the availability oracle's and tip
    /// watcher's sessions, the scan fleet.
    ///
    /// Stronger than pause, and a different question. Pause is about the
    /// QUEUE ("stop starting downloads") and deliberately leaves the
    /// background legs running, because indexing a group is not
    /// downloading. Offline is about the ACCOUNT ("this machine is not
    /// using the provider right now"), which the operator wants when
    /// they are about to use it from a laptop or a seedbox and their
    /// provider only allows one or two addresses at a time. The
    /// idle-release policy answers the same need on a timer; this is the
    /// instant version, for when waiting out a timeout is not what you
    /// want.
    pub offline: std::sync::atomic::AtomicBool,
    /// Whether it was OFFLINE that paused the queue.
    ///
    /// Going offline pauses, so the queue does not spend the outage
    /// starting jobs that cannot connect and burning retries on articles
    /// that were never missing. Coming back online must therefore NOT
    /// unpause a queue the operator had paused themselves, which this
    /// remembers. Set only while holding the transition.
    pub paused_by_offline: std::sync::atomic::AtomicBool,
    /// Set once the wind-down has started, and never cleared: this
    /// process is leaving.
    ///
    /// Read by [`Self::index_db_wanted`], which is the single gate every
    /// path to the index database passes through, so from this moment
    /// nothing reopens it. That is what makes closing it on the way out
    /// stick - the exit hands the write-ahead log back and drops the
    /// connections, and a status poll arriving a hundred milliseconds
    /// later must not lazily open a fresh one behind it and leave a new
    /// -wal on disk. Queries answer as they do for an index that is
    /// switched off (empty, never an error), which for the last moment
    /// of a daemon's life is the right answer.
    pub exiting: std::sync::atomic::AtomicBool,
    pub queue: Mutex<VecDeque<Arc<Mutex<Job>>>>,
    pub history: Mutex<Vec<Arc<Mutex<Job>>>>,
    /// §129 1b: the dashboard's change handles. Bumped at the
    /// persistence seam - `save_queue` for the queue, every history
    /// store write for history - so `mode=dashboard` can answer "nothing
    /// changed" with two atomic loads instead of two payloads. Progress
    /// counters deliberately touch neither: while anything downloads the
    /// queue section is sent regardless (continuous values have no
    /// honest revision).
    pub queue_rev: AtomicU64,
    pub history_rev: AtomicU64,
    /// nzo_ids whose park is between its history PREWRITE (on disk) and
    /// its final filing into `history` (in memory). `history_compact`
    /// snapshots memory, and a snapshot published inside that interval
    /// would erase the prewrite - the durable copy a crash recovers the
    /// job from. Registered by `park` via `hist_inflight_begin`'s guard.
    pub(super) hist_inflight: Mutex<std::collections::HashSet<String>>,
    /// When a rewrite that stood in for a REFUSED history append last
    /// failed, in `now_ms` (0 = never). `history_publish` falls back to
    /// the atomic rewrite when the append itself is refused, and the
    /// rewrite serializes every live record - so a data folder that is
    /// not coming back must not turn each job event into a full-store
    /// write. One attempt a minute after a failure; a rewrite that
    /// LANDS leaves this alone, because it heals the store and the next
    /// caller simply appends.
    pub(super) hist_rewrite_fail_ms: AtomicU64,
    /// §129 1b: discrete lifecycle events (job.completed, job.failed...)
    /// with a monotonic `seq`, so clients stop inferring toasts from
    /// snapshot diffs. Ring bounded at `histstore::LIFE_RING`; a client
    /// behind the tail is told to reseed rather than replayed.
    pub life_seq: AtomicU64,
    pub life_events: Mutex<VecDeque<Value>>,
    /// §129 4a: queue.idle is a TRANSITION, not a state - true once
    /// "the queue ran dry" has been said, cleared by the next add or
    /// pick so it can be said again. Without the latch every park of a
    /// quiet queue would repeat it.
    pub queue_idle_latch: AtomicBool,
    /// §129 1b(b): the pause flag's last ANNOUNCED value - the edge
    /// `queue.paused` / `queue.resumed` ride. EVERY writer of `paused`
    /// owes `announce_pause`; the rules, and why they are survivable,
    /// are at that function in daemon_shutdown.rs.
    pub(super) pause_announced: AtomicBool,
    /// §129 4a: post-processing tickets the lane has taken custody of
    /// and not yet parked (running + waiting). `PostprocLane` owns the
    /// increments; the counter lives HERE because `note_queue_idle` has
    /// to read it and the lane is the runner's, not the daemon's.
    ///
    /// It is what stops `queue.idle` being said over a tail that is
    /// still finishing. The scan below it asks the QUEUE, and a tail
    /// leaves that scan's sight twice before its `job.completed` is
    /// emitted: the row goes `Completed` early in `run_tail` (matching
    /// neither state arm, exactly the hole `finish_action::drain_blocker`
    /// grew `finalizing` for), and then `park_gen` retains it out of the
    /// queue a hundred lines before it files it into history. Two
    /// overlapping tails is all it takes - A's park announced the drain
    /// inside B's, so `queue.idle` landed between the two
    /// `job.completed`s, with B in neither list for a subscriber that
    /// went looking (23 Aug 2026).
    ///
    /// A counter and not a queue predicate because the failure modes are
    /// not symmetric: over-counting delays the event by one tail, while
    /// a terminal row that never leaves the queue would suppress a
    /// CONTRACT event (the queue-finished action, the webhooks) for the
    /// life of the daemon, silently. This one is paid back by
    /// `BacklogTicket`'s Drop, so a panicked or dropped supervisor
    /// cannot strand it.
    pub(super) postproc_backlog: Arc<AtomicUsize>,
    pub(super) finish: finish_action::FinishState,
    /// Issue #38 follow-up: the coalesced-save dirty flag. A completion
    /// used to call `save_queue` four times (postproc submit, finalize
    /// marker, finalize end, park), and at 14,500 jobs each rewrite
    /// serializes the whole queue - multi-second stalls. The hot sites
    /// call `save_queue_soon` instead, which sets this and wakes the
    /// saver task; one debounced write covers the burst.
    pub(super) save_soon: AtomicBool,
    /// Wakes `spawn_queue_saver` when `save_soon` is set.
    pub(super) save_wake: tokio::sync::Notify,
    /// Whether the saver task is running. Until it is (unit tests, and
    /// the window before `spawn_core_tasks`), `save_queue_soon` degrades
    /// to the synchronous `save_queue` so nothing is ever left unsaved.
    pub(super) saver_armed: AtomicBool,
    /// When the last `save_queue` FAILED, in unix seconds - 0 while the
    /// most recent one landed.
    ///
    /// A refused queue save is the one degraded state the daemon can be
    /// in that nothing on the outside could see: the queue keeps
    /// working, every add is accepted, and only a log line says that
    /// none of it will survive a restart. `sab_warnings` reads this so
    /// the pane every remote app and the dashboard render says so too.
    /// Set by the failing write and cleared by the next one that lands,
    /// because the condition it reports is "the queue on disk is stale
    /// RIGHT NOW" and not "a save failed once".
    pub(super) save_failed_at: AtomicU64,
    /// §129 4a: the lifecycle webhook dispatcher's inbox. None until
    /// the dispatcher is spawned (boot does it; unit tests that want
    /// deliveries call `hooks::spawn_dispatcher`). Offers are try-sends:
    /// the emitter never blocks on delivery.
    pub(super) hooks_tx: Mutex<Option<std::sync::mpsc::SyncSender<Value>>>,
    /// §129 D5: optional retention, BOTH 0 = unlimited (the shipped
    /// default, by ruling). Count keeps the newest N records; age drops
    /// Completed records that finished more than N seconds ago.
    ///
    /// The age knob is stored in SECONDS, and was days until issue #45. The
    /// unit is in the name because the value is compared against
    /// `finished_unix` directly, and a reader who guesses wrong here
    /// deletes the user's history 86,400x too eagerly. Issue #45 asked
    /// for minutes ("immediately after the download ended, or after XY
    /// minutes"), which days cannot express; seconds is also the unit
    /// every other duration setting here uses (`watch_interval_secs`,
    /// `library_recheck_secs`, `script_timeout_secs`). A saved
    /// `history_keep_days` from before the change is still read, and
    /// multiplied - see `restore_ui_and_index_settings`.
    pub history_keep_count: AtomicU64,
    pub history_keep_secs: AtomicU64,
    /// Serializes "decide where this job goes" against "publish it".
    ///
    /// `choose_out_dir` asks `dir_claim`, which takes and RELEASES the
    /// queue and history locks per probe, and the job only becomes
    /// visible when it is pushed onto the queue much later. Two of the
    /// eight HTTP workers adding names that resolve to one stem both saw
    /// Free, both passed the duplicate check before either was visible,
    /// and both jobs were published with the same `out_dir` - whose
    /// pipelines then overlap by design, so one truncates files the
    /// other is reading. The queue mutex protects the deque, not that
    /// decision. Held across choose + duplicate check + publish; also
    /// taken by the retry and recategorize paths, which pick
    /// directories by the same rule.
    ///
    /// Never taken while holding a queue, history or job lock - it sits
    /// ABOVE all three, and `dir_claim` locks every job in both lists.
    pub add_lock: Mutex<()>,
    /// nzo_ids whose payload is being MOVED on disk right now.
    ///
    /// Recategorizing a finished job runs `move_tree` with no locks
    /// held, deliberately - on a NAS it takes seconds and the queue must
    /// not stall behind it. But the job it snapshotted stays fully live
    /// meanwhile: an auto-retry whose cooldown came due pulled the same
    /// record out of history, reset it to Queued and let the scheduler
    /// start writers at the old path while the move was emptying it, and
    /// a history delete removed the record from under the move entirely.
    /// A job listed here refuses both until the move settles.
    pub moving: Mutex<std::collections::HashSet<String>>,
    /// The mover's work queue: finished jobs whose move to the
    /// completed folder is owed (Job::move_pending). Fed by finalize,
    /// unlock and the boot rescan; drained by per-TARGET sequential
    /// lanes (serve/mover.rs) - same destination stays serial, two
    /// different destinations never queue behind each other.
    pub(super) mover_q: Mutex<VecDeque<Arc<Mutex<Job>>>>,
    /// Moves in mover custody: counted up by `mover_enqueue`, down when
    /// a lane's `mover_process` returns without a requeue. `mover_q`
    /// and `moving` are BOTH empty while a job is in transit between
    /// them (the dispatcher's lane-key resolution, a lane's 2 s busy
    /// requeue sleep); the queue-finished drain check reads this so a
    /// sleep or shutdown cannot fire inside those windows.
    pub(super) mover_inflight: std::sync::atomic::AtomicUsize,
    /// Wakes the mover when `mover_q` gains work.
    pub(super) mover_wake: tokio::sync::Notify,
    /// The mover's pacing token bucket - ONE for the whole daemon, so
    /// concurrent lanes divide one budget instead of each granting
    /// itself the whole of it. See [`mover::mover_pacer`].
    pub(super) mover_bucket: Mutex<mover::PaceState>,
    /// How file moves share the machine with downloads ("File moves").
    /// "yield" (default): pace the copy to the measured headroom and go
    /// full speed when the queue is idle. "full": never pace. Any
    /// integer: a fixed cap in MB/s. One setting with three modes on
    /// purpose - fast networks want "full", shared links want a number,
    /// everyone else wants downloads to win.
    pub(super) move_pace: Mutex<String>,
    /// §296: publish a job's finished, PAR2-vouched plain files to the
    /// completed folder as they verify, instead of holding every one of
    /// them until the last file of the job does ("Publish files as they
    /// finish").
    ///
    /// Default OFF, and not because it is unfinished. It only ever
    /// engages for a job whose finalize tail will not rename, file or
    /// sweep anything (see `earlyfile::Daemon::early_publish_dest`), so
    /// a user who has left auto-rename or TV sort on gets nothing from
    /// it and would be paying a poll and a second read of every finished
    /// file for that nothing. Turning it on is a statement that the
    /// *arr on the other side does the renaming - which is what Sonarr
    /// and Radarr ask for anyway.
    pub early_file_publish: std::sync::atomic::AtomicBool,
    /// Write a `.nzbfast.manifest` beside every completed job's payload:
    /// the settle-time PAR2 checksums (whole-file MD5, first-16k MD5,
    /// per-block CRC32) kept so the directory can be re-verified after
    /// the `.par2` files are cleaned up. OFF by default: it is a new
    /// file in every finished folder, which is a default to choose
    /// deliberately, not inherit. Costs serialization only - the data
    /// is already in memory at settle.
    pub write_manifest: std::sync::atomic::AtomicBool,
    /// When this daemon started serving, so `/metrics` can report an
    /// uptime.
    ///
    /// An `Instant` and not a unix stamp: uptime is a DURATION, and a
    /// wall-clock subtraction hands you a negative one the first time
    /// NTP steps the clock backwards under a monitoring system that then
    /// alerts on a restart nobody performed. Distinct from `started_at`,
    /// which is the ACTIVE JOB's start and is cleared at network drain -
    /// a process uptime that reset to zero between downloads would say
    /// the daemon had restarted, which is the one thing an uptime series
    /// is read for.
    pub boot_at: Instant,
    /// Serve `/metrics` to callers with no API key.
    ///
    /// OFF by default, so the endpoint sits behind the full API key like
    /// every other read of this daemon's state. The switch exists
    /// because the Prometheus convention is an unauthenticated scrape -
    /// the scrape config has nowhere tidy to put a secret, and most
    /// installs put the exporter on a private network instead - and an
    /// operator who wants that should not have to choose between it and
    /// having a key at all.
    ///
    /// What it publishes to anyone who can reach the port: the numbers
    /// in `serve/metrics.rs`, which carry no job names and no paths, but
    /// DO carry each configured provider's hostname as a label. That is
    /// the disclosure to weigh, and the manual says so at the setting.
    pub metrics_open: std::sync::atomic::AtomicBool,
    /// Output directories chosen but not yet owned by any job record.
    ///
    /// `dir_claim` answers from the queue and history, so a directory
    /// picked for a payload that is still being MOVED into it belongs to
    /// nobody and reads as Free - and a job added meanwhile is handed
    /// the folder a move is filling. Held only across that gap, and
    /// consulted by `dir_claim` as Active.
    pub reserved: Mutex<std::collections::HashSet<PathBuf>>,
    /// Decoded bytes of the ACTIVE job (shared with the get pipeline).
    /// One counter PER JOB since the cross-job hand-over: job N's
    /// pipeline keeps counting its last in-flight articles into the
    /// handle it took at its start after job N+1 has claimed this cell,
    /// so the cell is re-pointed at a fresh counter per job rather than
    /// zeroed. See [`ProgressCell`].
    pub progress: ProgressCell,
    /// The previous job while it is still draining behind the active
    /// one (the cross-job hand-over, `tasks/worker.rs`): its own
    /// counters, so its row keeps reporting ITS bytes and the line-speed
    /// window sees the whole line rather than the newest job's share of
    /// it. None when no job is draining behind the active one. Written
    /// in the same lock section as `active_dl`, read under it.
    pub drain_dl: Mutex<Option<DrainSlot>>,
    pub active_total: AtomicU64,
    /// The nzo_id whose NETWORK phase owns `progress` / `active_total`
    /// right now, or None between jobs.
    ///
    /// The scheduler deliberately starts job N+1 while job N's tail
    /// (settle, verify, repair, unpack) still runs, and BOTH stay
    /// `Downloading` in the queue for all of it - so "the Downloading
    /// slot" was never a safe way to pair a row with these counters. It
    /// was not one: job N+1 zeroes them at its start, and job N's row,
    /// the hero card and the drawer's per-server baseline all read the
    /// globals unconditionally, so a finishing job's bar fell from ~98%
    /// to 0 and then climbed with a download that was not its own.
    ///
    /// Written with the counters themselves (one lock section, so no
    /// reader can pair this owner with the next job's zeroes) and
    /// cleared at network-drain beside `started_at`, whose lifetime this
    /// exactly shares: "this job's network phase is live".
    pub active_dl: Mutex<Option<String>>,
    pub started_at: Mutex<Option<Instant>>,
    /// When the daemon last stopped downloading - the clock the
    /// idle-release policy runs on. Initialised at boot, so a daemon
    /// that has never run a job counts as idle since it started rather
    /// than as never-idle.
    ///
    /// Distinct from `started_at`, which answers "is a job running right
    /// now". Releasing an account needs the other half of that: how long
    /// it has been since one was.
    pub last_download_end: Mutex<Instant>,
    /// Open transfer-stall episode on the active fetch, if any:
    /// (owning nzo_id, when bytes last moved). Written only by the
    /// watchdog's stall tracker (tasks.rs) - observation, never action -
    /// and read by the queue payload so the active row can say "no data
    /// for Ns" instead of a silently flat chart.
    pub stall_since: Mutex<Option<(String, Instant)>>,
    /// A2 playback contract: memo for the DISK half of per-file playback
    /// readiness, `nzo_id -> (unix secs, media file name and size)`.
    /// Finding a finished job's media file is a bounded directory walk,
    /// and the compact mobile poll asks about a page of history every
    /// few seconds; the answer only changes when someone moves the
    /// files. Entries age out (see `DISK_READINESS_TTL_SECS`).
    pub playback_disk: Mutex<std::collections::HashMap<String, (u64, Option<(String, u64)>)>>,
    pub next_id: AtomicU64,
    /// Download root. Live-swappable (Settings "Download folder"): a change
    /// applies to the NEXT enqueue without a restart. Read via `out_dir()`.
    /// The `spool` below is derived once at startup and stays put, so the
    /// queue journal / usage ledger / art cache never move out from under a
    /// running daemon.
    pub out_root: std::sync::RwLock<PathBuf>,
    /// M33: when set, completed jobs move here after unpack/rename/
    /// filing - e.g. a NAS share - preserving the category subfolder
    /// layout. None = leave downloads under out_root. Live setting
    /// (`move_completed`); for what a failed move leaves behind see
    /// `relocate_completed`.
    pub move_completed: std::sync::RwLock<Option<PathBuf>>,
    /// M33 v2: per-category destination overrides ("tv=/NAS/TV, …").
    /// An override IS that category's root - the category subfolder is
    /// not repeated inside it. Overrides apply even when the global
    /// `move_completed` is unset (only listed categories move then).
    pub move_completed_cats: std::sync::RwLock<Vec<(String, PathBuf)>>,
    /// TODO 317 (GitHub #67): write the payload STRAIGHT INTO the
    /// category's destination instead of moving it there at completion.
    ///
    /// Global half of the opt-in - every category that has a
    /// destination at all (a `move_completed_cats` override, or the
    /// global `move_completed`) downloads into it from byte 0. Off by
    /// default and it must stay that way: a destination on an SMB share
    /// then pays per-write network latency for the whole download
    /// instead of one bulk copy at the end, and nobody has measured
    /// that. The per-category half is
    /// [`Self::write_through_cats`] beside it; the two are a UNION, so
    /// leaving this off and naming only the local-drive categories is
    /// how a mixed install (one local disk, one share) is expressed.
    pub write_through: AtomicBool,
    /// TODO 317: the categories that write through even when
    /// [`Self::write_through`] is off. Names only - the destination is
    /// whatever `move_dest_root` already resolves for that category, so
    /// there is one destination map and not two.
    pub write_through_cats: Mutex<Vec<String>>,
    pub spool: PathBuf,
    /// The config file this daemon was started with. Held so the rename
    /// pipeline can read a bring-your-own-key value (the TMDB key) at
    /// the moment it needs one: the enrichment worker reads its copy
    /// once at startup, but a user who adds a key later should not have
    /// to restart for the identifier to gain its second source.
    pub cfg_path: PathBuf,
    /// Categories offered to the *arrs via `get_cats` and the NZBGet
    /// `config` category table. Seeded from [`DEFAULT_CATS`], extended by
    /// the `categories` setting, and by every category ever seen on an
    /// add call - see [`Daemon::register_cat`] for why the last of those
    /// is now written through to settings.
    pub cats: Mutex<std::collections::BTreeSet<String>>,
    pub port: u16,
    /// §193 c: the listen ADDRESS this run bound with. Bind-time state
    /// like [`port`](Self::port), not live state - the settings row
    /// persists a new value, `pending` surfaces the difference, and a
    /// restart applies it. Not to be confused with a server's
    /// `bind_ip`, which picks the local address OUTGOING NNTP
    /// connections leave from; this one is the dashboard's own listener.
    pub bind: String,
    /// Per-start secret shared with the desktop wrapper through
    /// `runtime.json` - see [`write_runtime_file`]. Never logged, never
    /// sent: it is only ever hashed with a caller-supplied nonce, which is
    /// what lets a wrapper tell this daemon from anything else holding the
    /// port before it hands over the API key.
    pub launcher_token: String,
    /// The launcher owns the port, not the dashboard (see
    /// [`port_locked`]). Set for a container, a compose service and the
    /// Synology package, where the listening port is baked into a
    /// published mapping, a healthcheck or DSM's own Open button, and a
    /// saved override just makes the install unreachable.
    pub port_locked: bool,
    /// §129 2a: the TLS pair THIS run is serving with (None = plain
    /// HTTP). Bind-time state like [`port`](Self::port), not live state:
    /// the settings rows persist a new pair, `pending` surfaces the
    /// difference, and a restart applies it.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub library_cats: Mutex<Vec<String>>,
    /// nzo_id whose extractor the hub holds (the last real download started).
    pub active_stream: Mutex<Option<String>>,
    /// M12: index database path.
    #[cfg(feature = "indexer")]
    pub index_db: PathBuf,
    /// M12: the shared read-WRITE Index connection (tip watcher, wall
    /// enricher, IMDb refresher, eviction, and every handler that
    /// mutates), opened lazily - None until first use, because the index
    /// is an optional feature and must never block the daemon from
    /// starting. The original single-connection rule ("one connection
    /// avoids cross-connection WAL races") stopped being literal at M28:
    /// each scan task ingests through its own scratch connection and the
    /// busy timeout arbitrates the writers, so cross-connection use
    /// against this WAL database is the daily norm, not a hazard.
    #[cfg(feature = "indexer")]
    pub index: Mutex<Option<nzbkit::index::Index>>,
    /// The read-ONLY siblings for interactive query handlers (wall2,
    /// search, browse, make_nzb, the newznab facade). WAL readers never
    /// wait on the writer, so these endpoints answer during a catch-up
    /// ingest or maintenance pass that holds the connection above for a
    /// minute straight - measured 28 Jul: a wall2 curl queued 62.4s
    /// behind a deepening pass. Opened lazily via `with_index_read`
    /// (only ever AFTER the read-write side has run the migrations), and
    /// retired at every point that drops or republishes the write
    /// connection.
    ///
    /// A POOL, and a bounded wait for it, since 2 Aug. The single shared
    /// read connection this replaces had "all its holds are short
    /// queries" as an unenforced assumption, and on a 32M-release index
    /// it stopped being true: `wall2` spent 85s on a COUNT and
    /// `wall_tip` 76s on a full scan, each holding that one mutex, so
    /// every other query handler queued behind it and parked an HTTP
    /// worker apiece. Eight such waits and the daemon answered nothing
    /// at all - the same silence as 28 Jul, one mutex further along.
    /// See [`INDEX_READ_CONNS`] for why a ceiling matters more than the
    /// concurrency.
    #[cfg(feature = "indexer")]
    pub index_read: IndexReadPool,
    /// When the saturation warning above was last logged (epoch seconds),
    /// so a wedged query surface reports itself once a minute instead of
    /// once per poll.
    #[cfg(feature = "indexer")]
    pub index_read_warned: AtomicU64,
    /// Whether a read-write `Index::open` has succeeded in this process
    /// - i.e. schema creation and migrations have run. Until then
    /// `with_index_read` routes through `with_index`, so a query handler
    /// can never open the read-only connection against a database an
    /// older binary wrote and trip over a missing column.
    #[cfg(feature = "indexer")]
    pub index_migrated: std::sync::atomic::AtomicBool,
    /// index_stats figures cache - see [`IndexStatsCache`]. The
    /// dashboard's status polls must never park an HTTP worker on the
    /// index mutex: a catch-up ingest once held it 62s straight, each
    /// poll parked another of the 4 workers, and one open dashboard
    /// tab wedged the whole API (28 Jul hang).
    #[cfg(feature = "indexer")]
    pub index_stats_cache: Mutex<IndexStatsCache>,
    /// M14g3 auto-speed governor on/off (live-toggleable).
    pub auto_speed: std::sync::atomic::AtomicBool,
    /// STAT-sample every job before downloading it (settings.json
    /// `preflight`). See `ServeOpts::preflight` for why it is off by
    /// default and why it has no dashboard switch.
    pub preflight: std::sync::atomic::AtomicBool,
    /// M7b.1 connection auto-tune on/off (live setting
    /// auto_connections): while the queue is idle, probe each provider's
    /// connection ladder and cap its per-job connections at the knee -
    /// over-asking measured 3-4× slower (connect-flood defense).
    pub auto_connections: std::sync::atomic::AtomicBool,
    /// TODO 112 live connection tuning on/off (live setting
    /// `live_tune`, default OFF until the §129 real-line gate passes;
    /// NZBFAST_LIVE_TUNE=1 is the dev override). With it ON the epoch
    /// controller chooses each server's connection count during
    /// downloads and the stored knee stops capping jobs - measurements
    /// SEED, only typed numbers cap (conn-tuning design, 8 Aug 2026).
    /// Mirrored onto `hub.live_tune` because the pool build in
    /// get/fleet.rs has the hub, not the daemon.
    pub live_tune: std::sync::atomic::AtomicBool,
    /// Hosts currently carrying the decay flag (conn-tuning design §6),
    /// mirrored from conntune.json by the live tuner so the 1 s queue
    /// poll never re-reads the file. Seeded at spawn, updated on every
    /// raise/clear.
    pub shaped_hosts: Mutex<std::collections::HashMap<String, crate::conntune::Shaped>>,
    /// Hosts this DAEMON SESSION has seen refuse us connections, and
    /// the ceiling each granted; see [`crate::conntune::Capped`]. Same
    /// shape and reasoning as `last_refusals` below: the pool's gauges
    /// are per JOB and the number outlives the job that measured it, so
    /// the next download says "capped at 38" from its first second
    /// instead of rediscovering a cap it already knew. Session, not
    /// lifetime - that ledger is in conntune.json, shown in Settings.
    pub capped_hosts: Mutex<std::collections::HashMap<String, crate::conntune::Capped>>,
    /// Leave adult titles out of the poster wall and the release list
    /// (settings key `wall_hide_adult`, default ON).
    ///
    /// On by default because the Spotnet source already made that call
    /// for the same reason and the wall should not disagree with it. The
    /// curated views only: every uncurated facade - newznab, the *arrs -
    /// is untouched, because a filter the user set for their own browsing
    /// is not a filter to impose on an automation's search results.
    pub wall_hide_adult: std::sync::atomic::AtomicBool,
    /// Slow-job watchdog on/off (live setting auto_defer): demote a job
    /// that is single-server-bound and slow while other jobs wait.
    pub auto_defer: std::sync::atomic::AtomicBool,
    /// TODO §77 post-health prediction on/off (live setting
    /// `post_health`): STAT a handful of a queued job's articles across
    /// every server and badge the row with the verdict. ON by default,
    /// unlike `preflight` above: that one FAILS a job on its own
    /// evidence and so has to be asked for, while this only ever puts a
    /// coloured dot and a sentence on a queue row.
    pub post_health: std::sync::atomic::AtomicBool,
    /// TODO §77 auto-defer on the health verdict (live setting
    /// `post_health_defer`): a red job sinks below healthier ones of the
    /// same priority in start order. ON by default, and REORDERING ONLY
    /// - nothing is removed, paused or failed. Eight STATs may put the
    /// healthy-looking items first, which costs the red job nothing when
    /// the sample was wrong; ending a release on them takes the far
    /// stricter bar below.
    pub post_health_defer: std::sync::atomic::AtomicBool,
    pub alt: super::altcand::AltSettings, // §282 items 12/13; docs on the type
    /// TODO §138 live setting `post_health_fail`, OFF by default and the
    /// ONLY thing in §77 that may fail a job - bar and why on
    /// [`crate::health::PostHealth::no_server_can_supply`].
    pub post_health_fail: std::sync::atomic::AtomicBool,
    /// Update checker: the manifest of a NEWER version once one is seen
    /// (None = up to date as far as we know), the check on/off toggle,
    /// and the manifest URL (live settings update_checks/update_url).
    /// NOTIFY-ONLY: the daemon never downloads or replaces its own
    /// binary - a newer version just raises the dashboard banner, which
    /// links to the download page.
    pub update_manifest: Mutex<Option<Value>>,
    pub update_checks: std::sync::atomic::AtomicBool,
    /// Highest `serial` ever seen in a signature-verified manifest; 0 =
    /// none seen yet. Persisted (settings `update_serial_seen`) so the
    /// ratchet survives a restart.
    ///
    /// READ-ONLY IN THIS RELEASE, DELIBERATELY. Nothing refuses a manifest
    /// on account of its serial yet - this build only records what it saw
    /// and warns when a serial goes backwards. The enforcing build comes
    /// later, and must not be the first one that clients meet: the stored
    /// value is a one-way local ratchet with no server-side reset, so a
    /// generator that emitted a wrong or absent serial would permanently
    /// wedge the update channel on every install that recorded it, and no
    /// later release could unwedge it. Shipping read-first buys a release
    /// cycle of field evidence that serials really are present and really
    /// are monotonic, before anything depends on that being true.
    pub update_serial_seen: std::sync::atomic::AtomicU64,
    /// Display preference only (not behaviour): show speeds in bits (Mb/s)
    /// instead of bytes (MB/s). Per-daemon so every dashboard client agrees.
    pub unit_bits: std::sync::atomic::AtomicBool,
    pub update_url: Mutex<String>,
    /// §5 i18n: daemon-default UI locale ("" = auto/navigator.language).
    /// Injected into the served dashboard/wall HTML so embedded webviews
    /// (which have no saved browser preference) come up in the right
    /// language. Live setting ui_locale; the API itself stays English.
    pub ui_locale: Mutex<String>,
    /// §141 live setting `cors_origin` - values and why on [`CORS_DEFAULT`].
    pub cors_origin: Mutex<String>,
    /// Auto-deepen (live setting index_deepen): articles of group
    /// HISTORY each scan pass adds below the low-water mark, so the
    /// index grows backward in the background. 0 = off.
    pub index_deepen: AtomicU64,
    /// A8 multi-server indexing (live setting index_coverage, ON by
    /// default): besides the per-group primary, every other eligible
    /// backbone advances its own forward tip so single-backbone posts
    /// and propagation holes still reach the index.
    pub index_coverage: std::sync::atomic::AtomicBool,
    /// A8 targeted gap-fill (live setting index_gapfill): incomplete
    /// releases per scan pass whose posting window is re-OVERed on the
    /// secondary backbones to hunt their missing segments. 0 = off.
    pub index_gapfill: AtomicU64,
    /// TODO 131 B3 byte-probe naming (live setting index_probe7z, ON
    /// by default): obfuscated single-7z posts get their real inner
    /// filename read from the archive's own end header, a bounded
    /// two-or-three article fetch per release. The kill switch for the
    /// whole lane.
    pub index_probe7z: std::sync::atomic::AtomicBool,
    /// Article budget for the byte prober (live setting
    /// index_probe7z_budget): articles per hour across all probes,
    /// 0 = off. Each probed release spends 2-6; the default 150 keeps
    /// up with the measured band inflow (~1,300-1,700 sets/day) at
    /// roughly 1-3 GB/day of probe traffic on non-metered servers.
    pub index_probe7z_budget: AtomicU64,
    /// TODO 131 pesto tiny-PAR2 naming (live setting index_pesto, ON
    /// by default): the pesto family's tiny PAR2 sidecars are fetched,
    /// parsed and linked backward by message-id counter, naming the
    /// obfuscated payload with PAR2-grade identity. The kill switch
    /// for the whole lane - a pesto tool update changes the MID
    /// grammar and the lane then needs re-derivation, not retries.
    pub index_pesto: std::sync::atomic::AtomicBool,
    /// Article budget for the pesto rung (live setting
    /// index_pesto_budget): articles per hour, 0 = off. A named set
    /// costs ~2 articles (one ~20 KB sidecar + one ~768 KB payload
    /// head for the mandatory hash gate); the default 120 clears the
    /// census's ~70 sets/day inflow many times over.
    pub index_pesto_budget: AtomicU64,
    /// §131 workstream D item D3 search-miss logging (live setting
    /// index_search_log, ON by default): record what this index was
    /// asked for and how much of it we answered, so the queries we
    /// answer with nothing can say what to deepen or backfill next.
    ///
    /// Purely local behaviour data - see the privacy paragraph on the
    /// `search_log` table. Switching this off also CLEARS the table:
    /// a privacy switch that leaves the history behind is not one.
    pub index_search_log: std::sync::atomic::AtomicBool,
    /// Searches waiting to be written, merged in memory.
    ///
    /// The load-bearing property: every interactive search runs on a
    /// pooled READ-ONLY index connection (`query_only=ON`), which
    /// exists precisely so an HTTP worker never queues behind the
    /// writer. Recording a search therefore may not touch SQLite at
    /// all on the query path - reaching for the read-write handle
    /// there is the http_wedge class of bug. [`Daemon::note_search`]
    /// only takes this mutex; the 60 s flush task does the writing.
    #[cfg(feature = "indexer")]
    pub search_log_buf: Mutex<std::collections::HashMap<SearchLogKey, SearchLogPending>>,
    /// TODO 166: a "forget every recorded search" that could not get the
    /// write mutex inside `HTTP_INDEX_WAIT`, waiting to be run on the
    /// writer's own thread by [`Daemon::search_log_tick`]. Only the
    /// SWITCH latches here - see `clear_search_log_deferred`, which
    /// carries the argument.
    #[cfg(feature = "indexer")]
    pub search_log_clear_pending: std::sync::atomic::AtomicBool,
    /// §131 #6 posted-NZB ingestion (live setting index_nzbimport, ON
    /// by default): one-file `*.nzb` posts are fetched, parsed and
    /// joined against the identity substrate by message-id. The kill
    /// switch for the whole lane.
    pub index_nzbimport: std::sync::atomic::AtomicBool,
    /// Article budget for the posted-NZB rung (live setting
    /// index_nzbimport_budget): articles per hour across all fetches,
    /// 0 = off. Most posted NZBs are one article; the 32 MiB decode cap
    /// bounds the rest at ~48. The default 300 keeps pace with the
    /// walk's own ceiling (3 objects a minute) on the census's
    /// mostly-single-article population.
    pub index_nzbimport_budget: AtomicU64,
    /// Scheduled system benchmark (live setting bench_interval): hours
    /// between automatic sysbench runs, 0 = off. Results (scheduled AND
    /// manual) append to .spool/bench_history.json.
    pub bench_interval: AtomicU64,
    /// Epoch-seconds of the last benchmark run (either kind).
    pub bench_last: AtomicU64,
    /// Single-flight latch for system benchmarks (Codex sweep 10 Aug
    /// M14): two tabs, or a manual run racing the schedule, ran the
    /// 128 MiB compute + 512 MiB disk + provider-traffic workload
    /// concurrently and distorted each other's numbers. Claim through
    /// [`Daemon::bench_begin`] only.
    pub bench_running: std::sync::atomic::AtomicBool,
    /// Serialises the load-modify-write in [`Daemon::bench_append`]:
    /// unlocked, two concurrent appends both read the same history and
    /// one overwrote the other's row.
    pub(super) bench_history_lock: Mutex<()>,
    /// Idle-server prefetch on/off (live setting auto_prefetch): servers
    /// the active job can't use (their copies 430'd) download the next
    /// queued job in a restricted secondary pipeline instead of idling.
    pub auto_prefetch: std::sync::atomic::AtomicBool,
    /// "Race slow articles" (live setting race_stragglers, ON by
    /// default): the pool may fetch a straggling article from more than
    /// one connection at once - first copy wins, the loser is abandoned
    /// - and replace a session delivering far below its siblings. Costs
    /// a fraction of a percent of extra traffic; measured to halve the
    /// end-of-job tail and to rescue stalled articles in under a second
    /// instead of eight. The pool reads settings.json per job, so a
    /// flip applies from the next download; this atomic backs the
    /// settings API's live read.
    pub race_stragglers: std::sync::atomic::AtomicBool,
    /// "Adaptive connection timeouts" (live setting adaptive_timeouts,
    /// ON by default): replaces the flat 30 s per-response timeout with
    /// a two-phase bound - a pre-first-byte budget trained on each
    /// server's measured response latency (a dead connection is cut in
    /// seconds instead of half a minute) plus a no-progress deadline
    /// once bytes flow, so a slow but alive transfer is never cut.
    /// Fault rigs: 4x on dead-air stalls, stacks on brownout, zero
    /// false kills on a jittery link. Read from settings.json per job
    /// like race_stragglers; this atomic backs the settings API's live
    /// read. NZBFAST_ADAPTIVE_TIMEOUT overrides in either direction.
    pub adaptive_timeouts: std::sync::atomic::AtomicBool,
    /// M29 opt-in routing (`oracle_route`, OFF by default): when on, a
    /// download asks any of your providers whose backbone the
    /// availability ledger is confident is GONE for the release's
    /// (family, age-bucket) LAST, so the doomed round-trips on
    /// takedown'd content come after every other server has missed.
    /// Nothing is removed from the pool: a wrong verdict costs ordering,
    /// not the download.
    pub oracle_route: std::sync::atomic::AtomicBool,
    /// The running prefetch sidecar, if any.
    pub sidecar: Mutex<Option<Sidecar>>,
    /// The cancel flag of every finished prefetch whose DETACHED
    /// completion tail is still running (`sidecar::completion_tail`).
    ///
    /// The slot above is emptied the moment the download task exits, so
    /// it says nothing about the tail that task spawned - and that tail
    /// is what unlocks, sweeps, renames and moves inside the directory.
    /// `sidecar_still_holds` consults both, so a delete waiting for the
    /// prefetch's writers waits for the last of them (read-only sweep
    /// 2, M6). Keyed by the flag's ALLOCATION, like every other sidecar
    /// identity test here: a retry keeps its nzo_id.
    pub sidecar_tails: Mutex<Vec<Arc<std::sync::atomic::AtomicBool>>>,
    /// nzo_ids owed the §76 prober's final on-disk pass. Drained by the
    /// prober each tick (its final-pass list is task-local, and a
    /// settled job has already left it).
    ///
    /// Two producers, both of them EVENTS rather than something the
    /// prober could notice for itself:
    ///
    /// - `park`, when the record reaches history. The prober cannot
    ///   infer this: it would have to catch the job Downloading at one
    ///   tick and stopped at the next, and a download shorter than one
    ///   tick is never caught at all.
    /// - post-processing, when the identity oracle answers after the
    ///   chip settled - the facts are complete but the NAME they were
    ///   judged against has changed.
    pub media_final_owed: Mutex<Vec<String>>,
    /// Best sustained download rate seen this session (bytes/sec) - the
    /// reference healthy jobs set for judging slow ones. Fed by the
    /// watchdog's rolling window and by completed-job averages.
    pub best_rate_bps: AtomicU64,
    /// The user/schedule speed cap (0 = unlimited). With the governor on,
    /// this is the CEILING the governed rate moves under; with it off,
    /// it IS the rate.
    pub speed_ceiling: AtomicU64,
    /// M15 budget total, surfaced in the stats host block so the
    /// dashboard can chart RSS as a fraction of its allowance.
    pub mem_budget_total: u64,
    /// M14k RSS feeds - a live setting: the poller re-reads this list
    /// each pass, so dashboard edits apply without a restart.
    pub feeds: Mutex<Vec<crate::rss::FeedConfig>>,
    /// §G: what each feed's last poll did, keyed by feed url. In memory
    /// only - it describes this daemon's run, and a poll interval is
    /// minutes, so a restart refills it almost at once. Pruned by the
    /// poller to the feeds that still exist.
    pub feed_health: Mutex<std::collections::HashMap<String, crate::rss::FeedHealth>>,
    /// §G: the last refusal each news server gave, kept AFTER the pool
    /// it came from is gone. `hub.pool_live` only exists while a job is
    /// running, so the Providers card's refusal detail vanished the
    /// moment the queue drained - which is exactly when someone goes
    /// looking for why nothing downloaded.
    pub last_refusals: Mutex<std::collections::HashMap<String, ServerRefusal>>,
    /// Throughput-attribution events the DAEMON owns - guard pauses,
    /// user pause/resume, cap changes, sidecar starts, indexer yields,
    /// late picks. Same shape and cap as the pool's ring in
    /// `nzbkit::pool::LiveStats`, kept here because `hub.pool_live`
    /// only exists while a job runs and half of what dents throughput
    /// happens outside the pool (the `last_refusals` precedent). The
    /// stats endpoint merges the two rings into one `events` list.
    pub events: Mutex<std::collections::VecDeque<DaemonEvent>>,
    /// M35 third-party Newznab indexers - a live setting, read on every
    /// pull search. Entries carry the user's per-site apikey: masked in
    /// get_config (`has_key`), never logged, never sent to a browser.
    pub indexers: Mutex<Vec<crate::newznab::IndexerConfig>>,
    /// M35 phase 2: may the WATCHLIST spend the user's indexer accounts
    /// looking for wanted items? Read it through
    /// [`Daemon::watchlist_external_on`], never directly: the stored bool
    /// only counts once `watchlist_external_set` says the user answered.
    pub watchlist_external: std::sync::atomic::AtomicBool,
    /// Did the user ever answer that question? The pair is a tri-state:
    /// unset falls back to "on iff at least one indexer is configured",
    /// which is the M35b posture (the local index cannot see obfuscated
    /// posts, so the accounts are the real search surface). An explicit
    /// answer - in EITHER direction - is stored and always wins, so
    /// somebody who turned this off does not get it turned back on by
    /// adding an indexer later.
    pub watchlist_external_set: std::sync::atomic::AtomicBool,
    /// M35 runtime state for the pull-search client: caps cache, daily
    /// hit/grab counters, limit backoffs and the token->result cache
    /// that keeps NZB links (which embed the apikey) server-side.
    pub(super) indexer_rt: Mutex<IndexerRuntime>,
    /// §74: run a watchlist pass the moment a watched release ARRIVES,
    /// rather than waiting up to a minute for the next periodic one.
    /// Default on, and inert without the built-in indexer - the arrivals
    /// it reacts to are the tip watcher's and the pre feed's, so an
    /// install with indexing off never sees one.
    pub watchlist_instant: AtomicBool,
    /// §74: how many instant passes an hour the arrival path may ask
    /// for. 0 = no limit. This bounds PASSES, not grabs: everything a
    /// skipped kick would have found is still grabbed by the periodic
    /// pass a minute later, so the ceiling costs latency on a busy hour
    /// and can never lose a download.
    pub watchlist_instant_max: std::sync::atomic::AtomicU32,
    /// Retention insurance (see [`Job::insurance`]): the disk budget, in
    /// GB, that deferred rows may fetch payload into ahead of promotion.
    /// 0 (the default) is the master OFF switch - no row is ever
    /// stamped, picked or fetched, byte-identical to a daemon without
    /// the feature. At the cap new insurance fetches are REFUSED, never
    /// evicted: silently deleting one deferred row's bytes to fetch
    /// another's would be the daemon deciding which post the user loses.
    pub insurance_cap_gb: AtomicU64,
    /// Grab-deferred watchlist mode: a watchlist match is enqueued
    /// PAUSED (an insurance candidate when the cap above is on) instead
    /// of downloading immediately, so the user chooses when to unpack
    /// while the payload is banked against takedowns. Off by default -
    /// the immediate grab is the watchlist's whole point for most
    /// people. Upgrade grabs (`promote`) are deliberately NOT deferred:
    /// they collide with the completed original and ride the duplicate
    /// hold machinery, which must never mix with insurance.
    pub watchlist_deferred: AtomicBool,
    /// §74: when the instant path last woke the pass, newest last,
    /// trimmed to the last hour - the window `watchlist_instant_max`
    /// applies over.
    #[cfg(feature = "indexer")]
    pub(super) instant_kicks: Mutex<std::collections::VecDeque<i64>>,
    /// §74: arrivals that MATCHED but were not complete yet - release id
    /// → when we first saw it. A post at +6 s is usually still going up,
    /// and the watchlist only ever grabs complete releases, so these are
    /// re-checked on a short cadence instead of being dropped. Missing
    /// articles are never read as final (that is a propagation trap, not
    /// a dead post): an entry simply expires back to the periodic pass.
    #[cfg(feature = "indexer")]
    pub(super) instant_pending: Mutex<std::collections::HashMap<i64, i64>>,
    /// §74: the arrival names that caused the pass now running to be
    /// woken. The pass drains this and stamps any grab it makes of one of
    /// these names as an instant grab - so the record says "this was
    /// grabbed because it arrived", not "a pass happened to run".
    pub(super) instant_hint: Mutex<Vec<String>>,
    /// The `mode=addnzblnk` rate and concurrency gate: a sliding window
    /// per peer, plus a cap on how many resolutions run at once. See
    /// [`NzblnkGate`], which carries the whole argument for why the one
    /// endpoint an OS protocol handler exposes to the open web has one.
    pub(super) nzblnk_gate: NzblnkGate,
    /// M23 Smart Folders - a live setting: rules evaluated at enqueue
    /// (first match wins) to pick the category, and remembered per-job
    /// for TV filing at completion.
    pub smart_folders: Mutex<Vec<crate::smart::Rule>>,
    /// Delete a job's .par2 recovery files once it completes and
    /// verifies. Default ON: recovery data is spent the moment the
    /// payload proves intact, and both major clients remove it, so
    /// leaving it reads as a bug ("this NZB is leaving PAR files
    /// behind"). Implemented as an implicit extra entry in the
    /// `cleanup_exts` sweep, so it inherits that sweep's guards.
    pub par_cleanup: AtomicBool,
    /// §129 lane width (settings.json `postproc_jobs`, default 2,
    /// clamp 1..=4). Deliberately not in the settings UI yet - a
    /// setting is three places, and the knob waits for demand.
    pub postproc_jobs: AtomicU64,
    /// §129 3e / §108 decision 4: pause the queue when the output volume
    /// stops keeping up for minutes at a time. The switch, the
    /// thresholds and the live pause all live inside it - see
    /// `serve::slowstore`.
    pub(super) slow_storage: super::slowstore::Governor,
    /// TODO 309(b): the last answer `Daemon::pause_cost` gave about what
    /// pausing the job on the wire would cost its next run, and when.
    /// The queue payload asks on every poll and the honest answer means
    /// parsing a journal, so the read is screened and then cached here -
    /// `serve::requeue` carries both arguments.
    pub(super) pause_cost: super::requeue::PauseCostCache,
    /// Permissions to put on finished downloads (#20), as a umask: dirs
    /// get `0o777 & !umask`, files `0o666 & !umask`. `u32::MAX` is OFF
    /// and is the default, so an install that says nothing keeps exactly
    /// the modes it has today.
    ///
    /// This exists because ONE umask was covering two trust zones. The
    /// systemd unit sets `UMask=0077` so the spool's API key and provider
    /// credentials are owner-only, which is right - but `--out` lives
    /// inside `ReadWritePaths=/var/lib/nzbfast`, so completed downloads
    /// came out 0700/0600 too and a Sonarr running as any other user
    /// could not read them, nor rename out of the directory. The three
    /// cheap fixes are each wrong in a different direction: relaxing
    /// `UMask` exposes everything the daemon creates at runtime including
    /// a generated API key, moving `--out` relocates downloads for every
    /// existing install on upgrade, and `ExecStartPost=chmod` only ever
    /// reaches the root directory and not the per-job ones made later.
    /// So the output tree gets its modes set explicitly, and the process
    /// umask stays strict.
    ///
    /// Unix only. On Windows it is stored and reported so a config file
    /// survives a round trip through either platform, and does nothing.
    pub out_umask: std::sync::atomic::AtomicU32,
    /// "Fast PAR mode" - route heavy PAR2 repairs through the NTT
    /// syndrome path (research/NTT-STAGE2/3 docs). Live setting,
    /// mirrored into `nzbkit::par2repair::set_fast_par_enabled`; the
    /// `NZBFAST_NTT` environment variable overrides it in both
    /// directions (the bench/test/ops escape hatch), and a verified
    /// divergence trips a process-wide breaker back to the fold path.
    /// Default [`FAST_PAR_DEFAULT`].
    pub fast_par: AtomicBool,
    /// "Unpack with external unrar" - route RAR unpacking through the
    /// unrar subprocess found beside the binary or on PATH, instead of
    /// the native (vendored rars) extractor. Escape hatch for extraction
    /// problems: the native path is faster on every benched shape, so
    /// default off. Obfuscated hash-named sets always take the native
    /// path regardless - the unrar subprocess cannot follow their
    /// naming. Live setting, mirrored into
    /// [`nzbkit::extract::set_prefer_external_unrar`]; the
    /// `NZBFAST_NO_NATIVE_UNRAR` env var forces it on (the pre-setting
    /// escape hatch, kept as an override).
    pub prefer_external_unrar: AtomicBool,
    /// M23 cleanup rules - file extensions deleted from a job's folder
    /// after successful completion. Empty = off.
    pub cleanup_exts: Mutex<Vec<String>>,
    /// SAB/NZBGet-parity passwords file (resolved path; default
    /// `passwords.txt` next to the config): plain text, one candidate
    /// archive password per line, tried in order when a job's volumes
    /// are encrypted and its own password is absent or wrong - both by
    /// the in-stream probe mid-download and by the completion unlock.
    /// Read fresh at every use so hand-edits apply immediately. The
    /// CONTENTS are credentials and never cross get_config or the log;
    /// only the path and a count do.
    pub password_file: Mutex<PathBuf>,
    /// What the dashboard does when an archive turns out passworded:
    /// "now" (prompt the moment the live probe wants one), "done"
    /// (prompt when the job finishes locked - the default), or "never"
    /// (no prompts: the job completes with the archive left packed,
    /// reported through unpack_blocked_by). Consumed client-side except
    /// for the "never" completion shape, which finalize applies.
    pub password_prompt: Mutex<String>,
    /// §73 phase 2: how far the preview-and-verify feature goes.
    /// "off" (nothing: `/preview/probe` refuses and the panel is gone),
    /// "metadata-only" (the default - the panel reads the container and
    /// says what the file is, and hands off to the user's own player),
    /// or "full" (the panel plus a player in the page for the files this
    /// browser can open). It gates the endpoint, not just the UI: "off"
    /// means the daemon stops reading half-downloaded files for anyone.
    pub preview: Mutex<String>,
    /// TODO 101: "off" (the default - volumes are only ever swept AFTER
    /// a successful extraction), "low_disk" (eat them during extraction,
    /// but only on a job whose forecast says it cannot otherwise fit and
    /// whose user consented in the disk-full drawer), or "always" (every
    /// on-disk unpack). Mirrored into [`crate::eatvol`], which is where
    /// the unpack ladder reads it from - several layers below anything
    /// holding a Daemon. An unverified set is never eaten in any mode.
    pub unpack_eat_volumes: Mutex<String>,
    /// TODO 24D user-definable categories - a live setting: match rules
    /// (Smart Folder syntax) that classify releases into user kinds at
    /// scan/finalize time, each with a declared base behavior. Order is
    /// priority. RwLock: read on every scan-pass classify and every
    /// finalize; written only by the settings API.
    pub custom_categories: std::sync::RwLock<Vec<nzbkit::categories::CustomCategory>>,
    /// Set when the category config changed and stored rows need a
    /// re-classification pass; the scan loop consumes it (same pattern
    /// as `scan_deep`).
    pub reclassify_pending: std::sync::atomic::AtomicBool,
    /// Ask the open naming oracles what a finished download actually is
    /// (see `crate::identity`). Default on, and the only outbound
    /// traffic it can produce is at most one srrdb request and at most
    /// one xREL request per completed job, both keyless and both
    /// silent when they fail.
    ///
    /// A switch rather than an assumption: it is the user's line, the
    /// requests name a release they downloaded, and somebody who does
    /// not want their daemon talking to third parties about that is
    /// entitled to say so - which is why it is now an advanced row on
    /// the Auto-rename card rather than an API-only setting. Somebody
    /// who wants to say no has to be able to find the switch.
    pub identity_lookup: std::sync::atomic::AtomicBool,
    /// Auto-rename: on completion, rename the folder + main media file to a
    /// friendly "Title (Year)[ quality]" form (TV keeps Show - S01E02).
    /// Master switch (default on); the five below tune what the quality
    /// suffix carries. Live settings.
    pub auto_rename: std::sync::atomic::AtomicBool,
    pub rename_resolution: std::sync::atomic::AtomicBool,
    pub rename_vcodec: std::sync::atomic::AtomicBool,
    pub rename_acodec: std::sync::atomic::AtomicBool,
    pub rename_source: std::sync::atomic::AtomicBool,
    pub rename_group: std::sync::atomic::AtomicBool,
    /// Wrap the year in parentheses when renaming. Off by default;
    /// "Title (Year)" is what Plex/Jellyfin/Radarr match on, so a
    /// media-server user usually wants it on.
    pub rename_year_parens: std::sync::atomic::AtomicBool,
    /// Wrap the quality facts in square brackets. Off by default.
    pub rename_quality_brackets: std::sync::atomic::AtomicBool,
    /// How many history rows the dashboard shows before the card has to
    /// be expanded. A display preference, but daemon-side like unit_bits
    /// so every browser pointed at this daemon agrees.
    pub history_rows: AtomicU64,
    /// Colour finished names green and failed ones red in History.
    pub history_color_names: std::sync::atomic::AtomicBool,
    /// Live state of a connection ladder while it runs, for the
    /// dashboard to poll. A full run is minutes long now, and the number
    /// it prints is the sharpest single knob in the product - watching
    /// it being derived is how a user comes to trust it, or to spot that
    /// it is measuring a bad evening. `None` between runs.
    ///
    /// SINGLE-WRITER, held by [`LadderPermit`]: do not write this without
    /// holding one. The invariant is structural rather than checked - one
    /// permit means one ladder means one writer - and a generation stamp
    /// here would be a second mechanism asserting what the permit already
    /// guarantees, which is the kind of pair that rots when a third
    /// writer appears and only one of them gets updated.
    pub ladder_live: Mutex<Option<LadderLive>>,
    /// One connection ladder at a time, across BOTH paths.
    ///
    /// Two ladders running at once do not merely race to write a knee -
    /// they invalidate each other's numbers, because each one's sockets
    /// are the other's contention, and a tuner whose whole job is
    /// measuring contention cannot be measuring itself. The existing
    /// post-hoc check ("a manual test landed while this probe ran")
    /// decides who WINS the write; it does not stop either measurement
    /// being wrong. They also both publish `ladder_live`, so the panel
    /// would show one provider's phase against another's rungs.
    pub ladder_busy: std::sync::atomic::AtomicBool,
    /// Set by the dashboard's Cancel to stop a ladder in flight.
    ///
    /// A full run is minutes long and spends real, billed provider
    /// traffic, so "I have changed my mind" has to be answerable. Read
    /// between rungs rather than mid-rung: a rung is 5-10 s, and
    /// abandoning one halfway would leave a half-measured step that is
    /// worse than no step. Cleared when a run starts, so a stale cancel
    /// cannot kill the next one.
    pub ladder_cancel: std::sync::atomic::AtomicBool,
    /// §303 grab-time preview: finished verdicts keyed by post identity
    /// (`spare::post_ids().identity()` - the same "is this the same
    /// post" question §295 answers, folded to one u64), with the unix
    /// time each probe ran. This is the preview's WHOLE re-ask budget:
    /// there is no queue row for `MAX_PROBES` to hang on, so a fresh
    /// entry answers without a provider round trip, and only an entry
    /// past `RECHECK_AFTER_SECS` is probed again (a post that was
    /// mid-propagation has usually landed by then - the prober's own
    /// recheck reasoning). Bounded; the handler evicts from the front.
    pub(crate) preview_cache: Mutex<Vec<(u64, i64, Value)>>,
    /// One preview probe at a time, daemon-wide. A probe opens its own
    /// connection per server, so N dialog files racing would open N
    /// fleets of them; the loser answers "busy" and the dialog says it
    /// could not check, which is the degrade-to-unknown contract. Held
    /// via an RAII guard in `api/queue/preview.rs`, never bare.
    pub(crate) preview_busy: std::sync::atomic::AtomicBool,
    /// Tint the media chip by video codec, and the archive-shape chip by
    /// what it took to unpack. Two switches rather than one because they
    /// answer different questions - "what is this file" and "what did
    /// getting it cost" - and a user who wants one is not asking for the
    /// other. Both default ON, matching how they shipped; the chips
    /// still spell both facts out in words when the colour is off.
    pub media_chip_color: std::sync::atomic::AtomicBool,
    pub shape_chip_color: std::sync::atomic::AtomicBool,
    /// Keep the words the parser did not recognise ("Round11 Hungary
    /// Race"), so releases differing only in those stay distinct.
    /// On by default: it only ever fires where the renamer would
    /// otherwise refuse to build a name at all.
    pub rename_extra_words: std::sync::atomic::AtomicBool,
    /// Post-download synthesised naming for obfuscated FILMS: when every
    /// other pass has left the feature wearing a hash, read the
    /// container's own facts and ask a film catalogue what it is.
    ///
    /// On by default, which is only defensible because the acceptance
    /// gate renames on certainty rather than on a best guess (see
    /// [`crate::identify`]) - the usual outcome is a note, not a rename.
    /// Visible next to the other rename settings so a user who would
    /// rather nothing reached the network after a download can turn it
    /// off.
    pub rename_identify: std::sync::atomic::AtomicBool,
    /// TODO 78: put the episode's own title in a TV filename
    /// ("Show - S01E02 - Children [1080p].mkv"), from the TVmaze episode
    /// list already cached for the show.
    ///
    /// Default OFF, and the only rename sub-setting that is. Two
    /// reasons: it is the shape Sonarr treats as a chosen token rather
    /// than a default, and turning it on changes the filenames an
    /// existing install already produced - which is exactly what an
    /// *arr's import matcher is looking at. A user who wants it opts in
    /// once and every later download follows.
    pub rename_episode_titles: std::sync::atomic::AtomicBool,
    /// Remove usenet junk (.par2/.nzb/.sfv/.nfo/… + sample clips) from a
    /// finished movie/TV folder (default on).
    pub rename_junk: std::sync::atomic::AtomicBool,
    /// PLAN M32 leftover (sabnzbd#3475): skip sample/proof clips at
    /// PLAN time, so their articles are never fetched. Distinct from
    /// `rename_junk`, which deletes them AFTER they have been paid for.
    /// Sampled once per job at download start, like the other live
    /// settings beside it.
    pub skip_samples: std::sync::atomic::AtomicBool,
    /// Aggressive: keep ONLY the media file(s), delete everything else
    /// (default off - irreversible).
    pub rename_media_only: std::sync::atomic::AtomicBool,
    /// TODO 142 / issue #32: name the finished folder and its main file
    /// after the .nzb file, instead of after what the release parses as.
    ///
    /// Default OFF - not a worse answer than the metadata renamer, a
    /// DIFFERENT one, and turning it on for everyone would rename
    /// finished downloads on installs that never asked. A category may
    /// override it either way: [`CatMeta::nzb_name`],
    /// [`Daemon::name_from_nzb`].
    pub rename_from_nzb: std::sync::atomic::AtomicBool,
    /// M12 volume control, live: only index posts newer than this
    /// (seconds; 0 = off). Read by the scan loop each pass.
    pub index_max_age_secs: AtomicU64,
    /// M31a retention, live: when on AND index_max_age_secs > 0, the scan
    /// loop deletes stored rows older than the window (max_age becomes a
    /// true retention window, not just an ingest gate). The stale-partial
    /// reaper runs regardless. Default: on.
    pub index_retention: std::sync::atomic::AtomicBool,
    /// Hold indexing back entirely while a download is running. Header
    /// scanning is not free next to a job: with the default 3 parallel
    /// group scans it takes `min(connections/3, 5)` connections EACH -
    /// 15 of a 20-connection account - and its SQLite writes compete
    /// with the download for CPU and disk on the same box. The daemon
    /// already yields in smaller ways (turbo fan-out off, prunes
    /// deferred, oracle sampler idle); this is the whole-hog version.
    /// On by default: a download is the foreground task, and the index
    /// catches up the moment the queue drains.
    pub(super) index_pause_on_download: std::sync::atomic::AtomicBool,
    /// Manual stop. Clearing the group list was the only way to halt
    /// indexing before, which meant losing the selection to get it back.
    pub(super) index_paused: std::sync::atomic::AtomicBool,
    /// Manual stop for the METADATA lanes only - the wall enricher, the
    /// person-photo fetcher and the ratings refresher, everything that
    /// puts names and artwork on rows the scan already holds.
    ///
    /// Separate from [`Self::index_paused`] because the two stop
    /// different spends. Pausing the index stops NNTP header traffic on
    /// the provider account; this stops outbound HTTP to TMDB, TVmaze,
    /// Wikidata, MusicBrainz and friends, which is what someone on a
    /// metered link or behind a watchful firewall actually wants off.
    /// Before it existed the only switch that reached these lanes was
    /// `index_enabled`, which takes the whole feature away.
    pub(super) enrich_paused: std::sync::atomic::AtomicBool,
    /// The built-in indexer's master switch, OFF by default.
    ///
    /// Pause is a "not right now"; this is a "not at all". Off means the
    /// feature does not exist for this install: no scanning, no
    /// enrichment, no availability sampling, no newznab facade, no
    /// database - `with_index` refuses to open the file - and the whole
    /// half of the UI it feeds is hidden rather than shown empty.
    ///
    /// Why default off: a header scanner only finds posts that carry a
    /// real filename, and a large share of usenet is deliberately posted
    /// without one (measured in research/index-parity-feasibility-\
    /// 2026-07-28.md: 14.78M scanned rows, 0.21% of them wall-visible).
    /// For anyone whose answer is a commercial indexer - which is most
    /// people - the built-in one is a background cost paid for a page
    /// they never open. Turning it on is one switch away, and the switch
    /// says what it does and does not do.
    ///
    /// EXISTING installs are seeded ON at startup (see `index_enabled`
    /// in `serve()`): an upgrade that silently stopped somebody's
    /// working index would be a data-shaped surprise, not a default.
    pub(super) index_enabled: std::sync::atomic::AtomicBool,
    /// Pre feed over IRC, OFF by default and independently of the
    /// indexer's own switch.
    ///
    /// A scanner can only read what was posted, and a large share of
    /// usenet is posted with the name taken out. The public relay
    /// channels announce `real title + posted filename` together, which
    /// is the one open mechanism that names those posts. It is opt-in
    /// and stays opt-in: it is a persistent connection to a third-party
    /// network that nothing else in this program talks to, and that is a
    /// decision for the user to make rather than a default to discover.
    pub(super) predb_enabled: std::sync::atomic::AtomicBool,
    /// `host` or `host:port` of the IRC network carrying the relay.
    pub(super) predb_server: Mutex<String>,
    /// Comma-separated channel list.
    pub(super) predb_channels: Mutex<String>,
    /// Base nick; a random suffix is appended per connection so two
    /// installs on one network never collide. No account, no NickServ.
    pub(super) predb_nick: Mutex<String>,
    /// Lines heard but not yet written. The relay is chatty in bursts
    /// and the index is shared with the scanner, so lines are batched
    /// rather than each taking the write lock on arrival.
    #[cfg(feature = "indexer")]
    pub(super) predb_pending: Mutex<Vec<nzbkit::predb::PreLine>>,
    /// Last thing the feed did, for the settings card. Plain text, shown
    /// as-is: a feature whose whole job is to talk to somebody else's
    /// server owes the user a legible account of whether it is working.
    pub(super) predb_status: Mutex<String>,
    /// Phase 2 correlation: infer names for obfuscated posts from pre
    /// timing + size. A separate switch from the feed itself, because
    /// hearing lines is harmless and inferring names is a policy.
    pub(super) predb_corr_enabled: std::sync::atomic::AtomicBool,
    /// The auto tier: apply a STRONG, unique, mutually-best correlation
    /// without a human click. Display-name only, revocable, and still
    /// off by default - it is earned per install, not assumed.
    pub(super) predb_corr_auto: std::sync::atomic::AtomicBool,
    /// How many pre rows the feed table may hold. Drives BOTH the prune
    /// and the seed importer's refusal threshold, which is the point of
    /// it being one number: a cap the importer does not know about is a
    /// cap that imports rows the next prune eats.
    #[cfg(feature = "indexer")]
    pub(super) predb_max_rows: std::sync::atomic::AtomicU64,
    /// Default history window, in days, for a seed import that does not
    /// name one. The design's 180; a bigger window costs the source
    /// more requests, which is why it is a knob and not a guess.
    pub(super) predb_seed_days: std::sync::atomic::AtomicU64,
    /// A seed import is in flight (one at a time, ever).
    #[cfg(feature = "indexer")]
    pub(super) predb_seed_running: std::sync::atomic::AtomicBool,
    /// What the seed importer is doing / last did, for the settings
    /// card. Same contract as `predb_status`.
    #[cfg(feature = "indexer")]
    pub(super) predb_seed_status: Mutex<String>,
    /// Parity scoreboard (research R1 / build-order #8): a daily sample
    /// of a reference indexer's newest releases, scored against our own
    /// index - coverage%, named% (exact title/episode parity) and lag
    /// per category. OFF by default, and inert without a reference URL:
    /// it is outbound traffic to a third party on the user's own
    /// account, so it is the user's decision, never a default.
    pub(super) scoreboard_enabled: std::sync::atomic::AtomicBool,
    /// The reference newznab base URL - the user's OWN indexer. There
    /// is deliberately no shipped default: a baked-in source would tie
    /// every install's sample queries to one project-chosen endpoint
    /// (and the one keyless candidate measured was ~92 days stale).
    pub(super) scoreboard_url: Mutex<String>,
    /// The user's own API key for that indexer. Never echoed to the UI
    /// (a `has_*` flag reports presence), never a shipped constant.
    pub(super) scoreboard_key: Mutex<Option<String>>,
    /// Name of the entry in `indexers` to measure against instead of
    /// the manual URL+key pair - the user's own already-entered account,
    /// so the same key never has to be pasted twice. Stored by NAME and
    /// resolved at run time, so a key rotated in the indexer editor
    /// carries over. Empty = use `scoreboard_url`/`scoreboard_key`.
    pub(super) scoreboard_source: Mutex<String>,
    /// Indexer-confirm lane: spend a small daily budget of the user's
    /// own indexer quota turning STRONG correlation suggestions into
    /// PROVEN names - search the suggested pre title, fetch the NZB,
    /// message-id-join it against our rows. OFF by default for the
    /// same reason as the scoreboard: it is outbound traffic on the
    /// user's own account, so it is the user's decision.
    pub(super) corr_confirm_enabled: std::sync::atomic::AtomicBool,
    /// Name of the `indexers` entry the confirm lane searches. Stored
    /// by NAME, resolved at run time like `scoreboard_source`. Empty =
    /// the lane is inert even when switched on.
    pub(super) corr_confirm_source: Mutex<String>,
    /// Which of [`SCOREBOARD_CATEGORIES`] the daily sample asks for -
    /// one request each, so this is the requests-per-day dial. Indexers
    /// meter every call, so the user gets to spend fewer than the full
    /// four; empty (the default) = all of them.
    ///
    /// A RESTRICTION, never an extension: `scoreboard_categories()`
    /// filters the built-in list with this, so the only thing this can
    /// do is take categories away.
    pub(super) scoreboard_cats: Mutex<Vec<String>>,
    /// Spend up to 5 of the user's daily NZB downloads on band-precision
    /// calibration (subject-stem exact matching). Off by default: it is
    /// the user's metered grab quota.
    pub(super) scoreboard_calibrate: std::sync::atomic::AtomicBool,
    /// A sample run is in flight (one at a time, ever).
    #[cfg(feature = "indexer")]
    pub(super) scoreboard_running: std::sync::atomic::AtomicBool,
    /// What the scoreboard is doing / last did, for the settings card.
    /// Same contract as `predb_status`.
    #[cfg(feature = "indexer")]
    pub(super) scoreboard_status: Mutex<String>,
    /// Spotnet spot ingestion, OFF by default and independent of
    /// `index_enabled`.
    ///
    /// A separate switch because it is a separate kind of source. The
    /// header indexer reads what usenet happens to say about a posting,
    /// which is nothing at all when the poster obfuscated it. A spot is
    /// somebody publishing a signed record of what they posted, name and
    /// NZB included, so it reaches exactly the releases the scanner
    /// cannot see. Making it a sub-option of the weaker source would
    /// mean running a header scan nobody asked for to get it.
    ///
    /// It shares the database, the pass gate and the pause rules with
    /// indexing (one SQLite file, one writer at a time, and a download
    /// still outranks both) - it just does not need the other switch on.
    ///
    /// Its READERS are the index gate (`indexer`-only) and the shell key
    /// that stamps the page before its first paint (`dashboard`-only),
    /// and `indexer` pulls `dashboard` in - so the one configuration
    /// where this is written and never read is the slim, pageless one
    /// the phones build (TODO 281 IO3b).
    // Not #[expect]: `dead_code` is a rustc lint judged in EVERY
    // configuration, and the field is plainly read in all of them but
    // the `--no-default-features` one, so an expectation would go
    // unfulfilled in the default build and redden the clippy gate.
    // Measured 28 Aug 2026: `cargo check -p nzbfast
    // --no-default-features --all-targets` is the only one that warns.
    #[cfg_attr(not(feature = "dashboard"), allow(dead_code))]
    pub(super) spot_enabled: std::sync::atomic::AtomicBool,
    /// Spot groups to scan. free.pt is the one live Spotnet group.
    pub(super) spot_groups: Mutex<Vec<String>>,
    /// Articles to walk back on the first pass; later passes resume from
    /// the stored `spots:<group>` high-water mark.
    pub(super) spot_backfill: AtomicU64,
    /// Articles of Spotnet HISTORY to read per pass, below the group's
    /// low-water mark (0 = off). Without this the catalogue is whatever
    /// the first backfill reached plus ~190 spots a day; free.pt carries
    /// 4.43 M articles back to 2011 and, measured at five depths, the
    /// NZBs behind them are all still fetchable.
    pub(super) spot_deepen: AtomicU64,
    /// Spot NZBs the resolver may fetch per pass (0 = off). Each costs
    /// one HEAD plus a few BODYs, so this is the throttle on the
    /// expensive half; the cheap half is `spot_deepen` above.
    pub(super) spot_resolve: AtomicU64,
    /// Bumped every time the database underneath the index is
    /// invalidated - switched off, or wiped. A scan pass owns a
    /// DEDICATED `Index::open` connection and republishes a fresh shared
    /// one when it finishes, so without a generation to check against it
    /// reopened (and, after a wipe, RECREATED) the database that had
    /// just been taken away. The switch then read as off while a live
    /// connection sat behind it, and a wipe reported success over files
    /// an exiting scan put back.
    #[cfg(feature = "indexer")]
    pub(super) index_generation: AtomicU64,
    /// Number of foreground jobs whose pipeline has not reached its
    /// terminal park yet. Job N's tail can overlap job N+1's network
    /// phase, so `started_at` cannot represent this lifetime.
    pub(super) index_jobs_active: Arc<AtomicUsize>,
    /// Size cap for the index database in bytes (0 = unlimited, the
    /// default). Live setting, SAB-style sizes accepted on input
    /// ("20G"). Only a cap: nothing is deleted until `index_evict` is
    /// also on - see that field.
    pub index_max_bytes: AtomicU64,
    /// The size cap's master switch, and the ONLY thing that lets the
    /// daemon delete indexed rows on its own. Default OFF, deliberately:
    /// a feature that throws data away does not turn itself on, and a
    /// user who sets a cap out of curiosity must not lose their index to
    /// it. With this off the cap is inert - `index_stats` still reports
    /// how big the database has grown, which is most of the value.
    pub index_evict: std::sync::atomic::AtomicBool,
    /// Which rows the cap sheds first: "ladder" (the engine's blended
    /// junk/age/availability order), "oldest", "newest", "largest",
    /// "smallest". Validated on write, so this always holds one of those.
    #[cfg(feature = "indexer")]
    pub index_evict_order: Mutex<String>,
    /// Restrict eviction to these release kinds ("movie", "tv",
    /// "software", "other"); empty = every kind is fair game.
    #[cfg(feature = "indexer")]
    pub index_evict_kinds: Mutex<Vec<String>>,
    /// The protective complement: kinds the cap must NEVER evict,
    /// whatever `index_evict_kinds` says (a kind in both lists is
    /// kept). Empty = nothing is exempt by kind.
    #[cfg(feature = "indexer")]
    pub index_keep_kinds: Mutex<Vec<String>>,
    /// Which rows are candidates at all: "all", "junk", "incomplete",
    /// "junk_incomplete" (never delete real complete content).
    /// Validated on write, so this always holds one of those.
    #[cfg(feature = "indexer")]
    pub index_evict_scope: Mutex<String>,
    /// How far below the cap an eviction empties, percent 0..=50.
    /// Default 10 - the engine's own hysteresis figure; see the
    /// headroom note in nzbkit's evict.rs for what 0 costs.
    #[cfg(feature = "indexer")]
    pub index_evict_headroom: AtomicU64,
    /// A prune left free pages behind and the file wants a VACUUM.
    /// Deliberately NOT acted on where it is set: VACUUM exclusive-locks
    /// and rewrites the whole database, so it waits for a genuinely idle
    /// moment (`spawn_index_compact`) rather than stalling a scan pass
    /// or a download. Survives only in memory - a restart is itself an
    /// idle moment and the next prune re-raises it.
    #[cfg(feature = "indexer")]
    pub compact_pending: std::sync::atomic::AtomicBool,
    /// Truth-audit I: what the last AUTOMATIC index trim removed, and
    /// when - (unix seconds, releases removed). The manual button
    /// narrates its own outcome in full; the hourly pass that does the
    /// same work silently was the reason a user could watch their index
    /// shrink with nothing anywhere admitting to it.
    ///
    /// In memory only. It describes this daemon's run: a restart has not
    /// trimmed anything yet, and claiming a trim from a previous process
    /// would be answering a question about now with a fact about then.
    #[cfg(feature = "indexer")]
    pub last_auto_trim: std::sync::Mutex<Option<(i64, u64)>>,
    /// The index space ledger - last compaction and evictions to date.
    /// Unlike `last_auto_trim` above this one is PERSISTED (in the
    /// index's own kv, reconciled by the maintenance loop), because it
    /// answers questions about the database file rather than about this
    /// process: "never compacted" is a wrong answer to give about a file
    /// that was compacted before the last restart. See `IndexLedger`.
    #[cfg(feature = "indexer")]
    pub index_ledger: std::sync::Mutex<IndexLedger>,
    /// Releases and titles the user has actually looked at: title_key /
    /// release id → unix seconds of the last touch. This is the fourth
    /// protection the size cap honours ("don't evict what I've been
    /// reading"), and it exists because the schema has no wall-render
    /// timestamp to stand in for it - `wall_hidden.at` records when
    /// something was HIDDEN, the opposite signal. Written on the three
    /// deliberate acts: opening a card's detail sheet, pulling an NZB
    /// through /getnzb, and queueing an indexed release.
    /// Persisted to .spool/index-opened.json.
    #[cfg(feature = "indexer")]
    pub index_opened: Mutex<OpenedLog>,
    /// M12 ingest gates, live: (raw JSON text as shown in the UI, parsed
    /// form the scanner uses). Text is empty when gates came from a
    /// --index-gates file (the parsed form still applies).
    #[cfg(feature = "indexer")]
    pub index_gates: Mutex<(String, Option<crate::gates::Gates>)>,
    /// M21: the connection's full line speed in bytes/sec (0 = unset).
    /// SAB remote apps set speed limits as PERCENTAGES - this is what
    /// the percentage is of. Doubles as the tuner's aim point: when the
    /// measured capability of every enabled provider together falls
    /// well short of it, `tune_hint` says so and suggests the lever.
    pub line_speed: AtomicU64,
    /// §125: the learned peak the throughput graph anchors 100% to -
    /// seeded by `line_speed`, overridden by sustained measurement.
    pub link_peak: super::linkpeak::LinkPeak,
    /// TODO 275 item 1 part 2: the per-socket carry the last job
    /// measured, persisted, so the next job's fleet seed starts where
    /// that one ended instead of re-walking the climb from the curve's
    /// planned carry. Fed by the same 1 s ticker as `link_peak`.
    pub line_carry: super::linecarry::LineCarry,
    /// §129 4b: the "Why is this slow?" attribution engine - fed by
    /// the same 1 s ticker as `link_peak`, published on the queue poll.
    pub(super) whyslow: super::whyslow::WhySlow,
    /// What the connection tuner wants the user to know: a shortfall
    /// against `line_speed` with the likeliest remedy, or empty when
    /// capability is fine (or unjudgeable - line speed unset, or an
    /// enabled server not yet probed). Read-only in the settings API;
    /// written by the probe loop and manual ladder runs.
    pub tune_hint: Mutex<String>,
    /// §210: the interface carrying traffic to the news servers, as
    /// last probed (None = not yet, or unjudgeable: container, no
    /// probe on this platform). Read by `update_tune_hint`.
    // `pub(crate)` for the reason given at `hub` above: `LocalLink` is a
    // `pub(crate)` type.
    pub(crate) local_link: Mutex<Option<super::locallink::LocalLink>>,
    /// CPU% sampling state for stats: (sample time, cpu-secs, last pct).
    pub(super) cpu_sample: Mutex<Option<(Instant, f64, f64)>>,
    /// Rolling (time, decoded-bytes) samples for the live speed readout -
    /// a whole-job average hides stalls (a wedged job kept "reporting"
    /// 400 KB/s); a ~5 s window shows what's happening NOW.
    pub(super) speed_win: Mutex<VecDeque<(Instant, u64)>>,
    /// M18b per-provider data-usage history: "YYYY-MM-DD" → host → bytes,
    /// persisted to .spool/usage.json (metered/block accounts need to see
    /// where the gigabytes went).
    pub(super) usage: Mutex<serde_json::Map<String, Value>>,
    /// The rolling 30-day per-provider quality ledger - article tries,
    /// 430s, bytes and connection caps, split by post age, plus the job
    /// outcomes those provider facts sat under. Persisted to
    /// .spool/provquality.json. Written once per finished job on the
    /// post-processing lane (where the outcome is known), read by
    /// `mode=usage`. See `serve::provquality`.
    pub(super) provquality: super::provquality::ProvQuality,
    /// §96.5: per-host bytes of the RUNNING download already billed to
    /// the usage ledger by `flush_run_usage` - the high-water map that
    /// makes mid-job billing idempotent against the end-of-job call.
    /// Cleared by the runner at every job start, beside `pool_live`.
    pub(super) run_usage_flushed: Mutex<std::collections::HashMap<String, u64>>,
    /// Which band each block account was last seen in - 0 fine, 1 low
    /// (>= `BLOCK_LOW_PCT`), 2 spent - so `block_threshold_tick` fires
    /// `server.block_low` / `server.block_spent` on the CROSSING and not
    /// on every 30 s flush. Absent means "not seen yet", which seeds
    /// silently: a daemon starting up against an already-spent block has
    /// not watched it cross anything. A band that goes DOWN (a refill)
    /// rewrites the entry, so the next crossing fires again. Keyed per
    /// CONFIG ENTRY (`host#ordinal`, the ordinal among same-host
    /// entries), because two entries may share one host with different
    /// block sizes and standings are per entry.
    pub(super) block_band: Mutex<std::collections::HashMap<String, u8>>,
    /// Timed pause ("pause for N minutes"): auto-resume deadline, and
    /// the ONLY thing that decides whether the timer fires. Every
    /// pause/resume writer clears or replaces it under this mutex (see
    /// `set_paused_cancel_timer`), so a cancelled or re-armed timer is
    /// cancelled or re-armed for the one worker that reads it - there is
    /// no second copy to go stale.
    pub(super) pause_until: Mutex<Option<Instant>>,
    /// Wakes the auto-resume worker when the deadline above is replaced
    /// or cleared. Paired with `pause_until`'s mutex: every writer of
    /// that deadline notifies this, so a re-arm reprograms the sleeping
    /// worker instead of stacking another one behind it.
    pub(super) pause_wake: std::sync::Condvar,
    /// Whether an auto-resume worker is running. Read and written ONLY
    /// under the `pause_until` lock, which is what makes "the worker
    /// retires" and "an arm reprograms it" mutually exclusive: the
    /// worker clears this on its way out under the same lock an armer
    /// sets it under, so exactly one of the two happens.
    pub(super) pause_timer_live: std::sync::atomic::AtomicBool,
    // --- M16 settings UI: live-tunable knobs. Each is read at its point
    // of use (per job / per loop tick / per request), so a change from
    // the dashboard takes effect without a restart. Changes are also
    // persisted to settings.json (see save_setting) for the next launch.
    /// Per-server connection cap for the NEXT download.
    pub(super) connections: std::sync::atomic::AtomicUsize,
    /// Pipelining window for the NEXT download.
    pub(super) window: std::sync::atomic::AtomicUsize,
    /// Decoder threads for the NEXT download.
    pub(super) decoders: std::sync::atomic::AtomicUsize,
    /// PAR2 fast verify (CRC32-only in-stream claims) for the NEXT
    /// download; full MD5 stays on settle read-back + disk-fed spans.
    pub(super) fast_verify: std::sync::atomic::AtomicBool,
    /// M32 lean verify: with fast_verify, also skip article CRCs once
    /// PAR2 covers a file (single-CRC32 in-stream; slow-CPU boost).
    pub(super) verify_lean: std::sync::atomic::AtomicBool,
    /// Pause new jobs below this many free bytes (0 = off).
    pub(super) min_free: AtomicU64,
    /// Why the scheduler is starting nothing, for the queue payload:
    /// `("disk", free_gb, floor_gb)` while the min_free guard holds, or
    /// `("quota", spent_gb, cap_gb)` while the period's quota is spent.
    /// `None` when downloads can start. Mirrors the worker's own
    /// guard_reason - without this the dashboard showed "idle" over a
    /// full queue and the only explanation lived in the daemon log.
    pub(super) queue_hold: Mutex<Option<(String, f64, f64)>>,
    /// Who paused the queue, for the header pill: `"user"` (a person at
    /// the dashboard, a remote app, the API) or `"schedule"` (a schedule
    /// entry fired). The offline case is derived from
    /// `paused_by_offline` at render time and needs no slot here.
    ///
    /// Display only - nothing schedules on this. A pause the user never
    /// made read exactly like one they did, so the only way to find out
    /// that a quiet hour had started was to open Settings and work
    /// through the schedule by hand.
    pub(super) pause_source: Mutex<&'static str>,
    /// Who set the speed ceiling now in force: `"user"` (the dashboard
    /// or the config API), `"schedule"`, or `"api"` (a remote app's rate
    /// call). `"auto"` is derived from `auto_speed` at render time.
    /// Display only, same reasoning as `pause_source`.
    pub(super) limit_source: Mutex<&'static str>,
    /// M32: seconds before the one automatic retry of a job that failed
    /// with missing articles (0 = off). Configured in minutes
    /// (auto_retry_mins); NZBFAST_AUTO_RETRY_SECS overrides for tests.
    pub(super) auto_retry_secs: AtomicU64,
    /// Minutes a server may spend granting NO connection during one job
    /// before the pool retires it for the rest of that job; 0 = never
    /// give up on it. See [`nzbkit::pool::PoolConfig::outage_budget`].
    ///
    /// A setting rather than a constant because the two answers are both
    /// defensible and the right one is the user's. The default (15) ends
    /// a wedged job with a transport verdict, which auto-retries from
    /// the journal and never reports the post dead to an indexer - the
    /// queue keeps moving. Zero waits instead, for as long as it takes,
    /// which is what someone who knows their provider comes back (or is
    /// downloading something they will not find again) actually wants.
    /// Both are now legible: the queue row names the provider and the
    /// duration either way.
    pub(super) server_outage_mins: AtomicU64,
    /// Byte budget per quota period (0 = off).
    pub(super) quota: AtomicU64,
    /// b'd' (daily), b'w' (weekly, Monday) or b'm' (monthly).
    pub(super) quota_period: std::sync::atomic::AtomicU8,
    /// Bytes billed to the CURRENT quota period, republished by the
    /// download runner (which owns the ledger) on every pass.
    ///
    /// The ledger itself is a local in that loop, so the SAB facade had
    /// no way to ask it and derived `left_quota` from the queue hold -
    /// which only exists once the quota is exhausted. Every client saw
    /// the full cap remaining right up to the moment it saw zero (L5,
    /// 10 Aug sweep).
    pub(super) quota_spent: AtomicU64,
    /// §129 2g: a scheduled quota_reset fired; the download runner owns
    /// the ledger and zeroes it on its next pass.
    pub(super) quota_reset: AtomicBool,
    /// §129 2d: what happens to a duplicate add. "pause" (the default,
    /// M14f: held as an ALTERNATIVE that auto-promotes if the original
    /// fails), "discard" (refused outright - the add errors), or "fail"
    /// (filed straight to history as Failed, which is what a *arr wants
    /// so its own failure handling can pick a different release).
    /// Live - read per add. `allow_dupe` (the wall's asked-and-said-yes)
    /// bypasses all three.
    pub(super) dupe_action: Mutex<String>,
    /// What counts as a duplicate in the first place. "smart" (the
    /// default): same identity - show, season and episode, or title and
    /// year - so a different release of an owned episode collides.
    /// "exact": only a re-add of the same release name collides, so a
    /// quality upgrade Sonarr or Radarr chose sails through while the
    /// same NZB sent twice is still caught (issue #41). Live - read per
    /// add, through `dupe_collision`.
    pub(super) dupe_scope: Mutex<String>,
    /// §129 2b (decision 5): real per-category behavior, keyed by the
    /// category name. Everything defaults to "as before": empty dir =
    /// the category's own subfolder, priority None = no default,
    /// empty script = the global one. Live - read per add and per
    /// job completion.
    pub(super) cat_meta: Mutex<std::collections::HashMap<String, CatMeta>>,
    /// Watch folder for dropped .nzb files (None = off).
    pub(super) watch_dir: Mutex<Option<PathBuf>>,
    /// Keep the picked-up .nzb in the watch folder instead of moving it
    /// to the Trash (Gary: collectors, and handing the file to someone
    /// for debugging). Off = today's behaviour, where deletion IS the
    /// processed-marker; on, the marker is the persisted seen-set the
    /// watch loop keeps beside the spool (see watch_seen_path), or every
    /// restart would re-download the whole folder. Live - read per
    /// pickup, so it needs no boot-apply beyond the saved-settings replay.
    pub watch_keep_nzb: AtomicBool,
    /// TODO 280: queue an NZB found in a finished download's own output,
    /// paused. Off; caps and reasoning in `serve/refeed.rs`. Live.
    pub refeed_nzb: AtomicBool,
    /// Scan subfolders of the watch folder too, with the first
    /// subfolder's name becoming the job's category (watch/tv/x.nzb
    /// lands in "tv") - the layout Sonarr-era muscle memory expects.
    /// A first-level folder named "rejected" is never scanned: it is
    /// the quarantine below. Live - read per pass.
    pub watch_recursive: AtomicBool,
    /// Move a complete-but-unusable .nzb (parse/enqueue rejection) into
    /// <watch>/rejected/ with a .txt beside it saying why. Off, the
    /// file stays put and only the dashboard strip explains it.
    /// Truncated files are NEVER moved regardless: a stalled copy can
    /// resume, and yanking the destination mid-copy is exactly the
    /// "nzbfast deleted my download" complaint the strip exists to
    /// prevent. Live - read per rejection.
    pub watch_move_rejected: AtomicBool,
    /// Watch-folder files that failed to parse/enqueue, with the
    /// (mtime, len, error, related nzo_id) they failed at. Skipped on
    /// later passes until the file changes - with the watch folder
    /// defaulting to the user's whole Downloads folder, a stray
    /// unparseable .nzb must not be re-read every 5 s forever. Surfaced
    /// in queue_json for the UI.
    ///
    /// The id is the RECORD this file lost to, empty when there isn't
    /// one: "already downloaded" is only actionable if the History entry
    /// standing in the way can be reached, and matching it back up by
    /// name in the page finds the wrong row for a re-post.
    pub(super) watch_failed: Mutex<std::collections::HashMap<PathBuf, (u64, u64, String, String)>>,
    /// Deletes whose RECORD went but whose FILES did not: (job name, the
    /// path still on disk, why it was refused, unix seconds), newest
    /// last, capped small. See `Daemon::note_delete_kept`.
    ///
    /// Unlike the rings above this one is not a moment that scrolls past.
    /// The dashboard keeps it on screen until the user dismisses it,
    /// because the path IS the handle: the history row they would have
    /// found the download by is exactly what the delete removed.
    pub(super) delete_kept: Mutex<std::collections::VecDeque<KeptNote>>,
    /// Releases the user has DELETED lately, newest last - the duplicate
    /// check reads it and declines to hold a re-add of any of them. See
    /// `Daemon::note_releases_deleted`.
    pub(super) deleted_recent: Mutex<std::collections::VecDeque<dupe::DeleteMark>>,
    /// Failed API-key attempts per source address: (count, window start).
    ///
    /// The key comparison is constant-time, but nothing recorded a wrong one
    /// and nothing slowed one down - so an unauthenticated peer on the LAN
    /// could grind the key at full request rate, leaving no trace anywhere in
    /// the logs. See `note_auth_failure`.
    pub(super) auth_fails: Mutex<std::collections::HashMap<std::net::IpAddr, (u32, Instant)>>,
    /// M30: viewport-priority enrichment - title keys the wall is
    /// showing unenriched RIGHT NOW. The enricher lanes drain these
    /// ahead of the newest-first backlog, so what's on screen gets its
    /// art first. Bounded FIFO (stale entries evict).
    #[cfg(feature = "indexer")]
    pub(super) enrich_hot: Mutex<std::collections::VecDeque<String>>,
    /// Newsgroup discovery catalogue (mode=groups): the primary server's
    /// LIST ACTIVE + LIST NEWSGROUPS, cached in groups.tsv next to the
    /// index db so a restart doesn't refetch ~100k groups. None until the
    /// cache loads or the first fetch lands.
    #[cfg(feature = "indexer")]
    pub(super) group_catalog: Mutex<Option<Arc<crate::groups::Catalog>>>,
    /// True while a catalogue fetch is in flight (single-flight guard).
    #[cfg(feature = "indexer")]
    pub(super) group_fetching: std::sync::atomic::AtomicBool,
    /// Last catalogue-fetch failure, surfaced in the browser UI.
    #[cfg(feature = "indexer")]
    pub(super) group_fetch_err: Mutex<Option<String>>,
    /// Sampled per-group profiles (size, freshness, rate, content mix)
    /// from an OVER over each group's newest articles. Separate from the
    /// catalogue because it is filled in lazily and incrementally: the
    /// catalogue is one fetch for every group, this is one round trip
    /// PER group, so it is only ever done for groups someone looked at
    /// or that the background pass has reached.
    #[cfg(feature = "indexer")]
    pub(super) group_stats: Mutex<Arc<crate::groupstats::StatsCache>>,
    /// Groups with a sample in flight, so two viewers opening the same
    /// row do not both go to the provider (and so the background pass
    /// never races an on-demand request).
    #[cfg(feature = "indexer")]
    pub(super) group_sampling: Mutex<std::collections::HashSet<String>>,
    /// Opt-in: also fetch newsgroup descriptions from ISC. Off by
    /// default because it is the daemon's only outbound request to a host
    /// that is not the user's news provider.
    pub(super) group_desc_isc: std::sync::atomic::AtomicBool,
    /// The post-processing script CHAIN (empty = off). §192: NZBGet
    /// runs an ordered list, not one script, and the `script` setting
    /// holds that list comma-separated; this is it, parsed. Order is
    /// the list's, and a failing link does not stop the ones after it -
    /// see [`Daemon::run_script_chain`] for both contracts.
    pub(super) scripts: Mutex<Vec<PathBuf>>,
    /// Seconds before a post-processing script is killed. 0 = wait
    /// forever, which is what a multi-hour transcode wants; the default
    /// is generous but finite, because a script that hangs otherwise
    /// holds its blocking thread for the life of the daemon and does so
    /// again for every job that completes after it.
    pub(super) script_timeout: AtomicU64,
    /// §129 4a: the pre-queue hook script (None = off) and its own
    /// deadline. Its own knob because 3600 is a post-processing budget
    /// and this one blocks an add: default 30 s, 0 = wait forever.
    pub(super) pre_queue_script: Mutex<Option<PathBuf>>,
    pub(super) pre_queue_timeout: AtomicU64,
    /// Media servers / webhooks told about every finished job. Empty =
    /// off, which is the default. See [`crate::notify`].
    pub(super) notify_targets: Mutex<Vec<crate::notify::Target>>,
    /// §G: how each target's last delivery went, keyed by
    /// [`crate::notify::target_key`]. A failed notification was log-only,
    /// so a webhook with a revoked token stopped working and the only
    /// place that said so was a log line nobody reads. The key embeds the
    /// target url, which is itself a bearer credential for Discord/ntfy:
    /// it is a map key and NOTHING else - never logged, never shipped.
    pub(super) notify_health: Mutex<std::collections::HashMap<String, crate::notify::Outcome>>,
    /// What to do with an indexer's `X-DNZB-Failure` link when a job
    /// fails: "off" (default), "report", or "regrab". See
    /// [`Daemon::report_failure`].
    pub(super) failure_link: Mutex<String>,
    /// Which encode the user would rather have when a title has several.
    /// Biases the order releases are listed in; never hides any of them.
    pub(super) quality_prefs: Mutex<crate::watchlist::QualityPrefs>,
    /// API keys, rotatable live. None = open (no auth).
    pub(super) apikey: Mutex<Option<String>>,
    pub(super) nzbkey: Mutex<Option<String>>,
    /// Per-install secret behind stream_token(). Generated once, persisted
    /// in settings.json - deliberately NOT the apikey, so rotating the key
    /// doesn't orphan every .strm pointer in a Jellyfin/Emby library.
    pub(super) stream_secret: String,
    /// Optional OMDb key (free tier, email-only signup) - richer movie
    /// metadata in the enricher + fix-match search. Live setting.
    pub(super) omdb_key: Mutex<Option<String>>,
    /// §193 d: optional TMDB key - the enricher's and the identifier's
    /// second source. Lived in the config file and the `TMDB_API_KEY`
    /// env only until this row existed, so the seed still READS both (see
    /// `seed_tmdb_key`) and settings.json is where the UI writes.
    /// Live: every consumer reads this mutex per lookup, so a key pasted
    /// into the settings page starts being used without a restart.
    pub(super) tmdb_key: Mutex<Option<String>>,
    /// Re-verify interval for parked library jobs.
    pub(super) library_recheck_secs: AtomicU64,
    /// Index scanner inputs, read each cycle.
    pub(super) index_groups: Mutex<Vec<String>>,
    /// What the user told the indexer to look for, as interest keys (see
    /// `crate::interests`). Empty means "nothing" and stays that way -
    /// this is the setting that exists so nobody has to accept a default
    /// they did not choose.
    pub(super) index_interests: Mutex<String>,
    /// The interest string whose groups have already been merged into
    /// `index_groups`. Applying is one-shot per change: without this,
    /// every catalogue refresh would re-add a group the user had since
    /// removed by hand, which is the same "we decided for you" behavior
    /// from a different direction.
    pub(super) index_interests_applied: Mutex<String>,
    /// Exact groups appended by interest resolution. A preset group that
    /// was already present is manual and never enters this list, so
    /// unticking the preset cannot delete the user's own subscription.
    pub(super) index_interest_groups: Mutex<Vec<String>>,
    pub(super) index_interval_secs: AtomicU64,
    pub(super) index_backfill: AtomicU64,
    /// mode=index_scan_now: wakes the scan loop out of its interval
    /// sleep; scan_deep carries a one-off backfill-depth override
    /// (0 = none) consumed at the start of the next pass.
    pub(super) scan_now: tokio::sync::Notify,
    #[cfg(feature = "indexer")]
    pub(super) scan_deep: AtomicU64,
    /// Live progress of the in-flight scan pass, for index_stats.
    /// Groups currently scanning (several at once since M28).
    #[cfg(feature = "indexer")]
    pub(super) scan_progress: Mutex<Vec<ScanProgress>>,
    /// M28: concurrent group scans per pass (live setting, clamp 1-8).
    pub(super) index_scan_par: AtomicU64,
    /// True from before the scan loop spawns its group tasks until the
    /// last one joins. `scan_progress` cannot serve this purpose: a task
    /// opens its own Index handle - which takes the database's write
    /// lock for the schema batch - BEFORE it registers itself there, and
    /// the tip watcher writing in that window failed the open outright
    /// with "database is locked".
    pub(super) scan_active: std::sync::atomic::AtomicBool,
    /// Background-subsystem gauge feeding the dashboard's status chip
    /// strip (stats.busy). Queue states live on the slots, not here.
    pub(super) busy: super::busy::BusyMap,
    /// Seconds between tip-watcher ticks - the short loop that tracks
    /// only what is NEW at the head of each group, so arrivals reach the
    /// wall in seconds instead of waiting out `index_interval_secs`
    /// (default 900) behind a 200k-article history backfill. Live
    /// setting; 0 turns the watcher off and leaves the full scan pass as
    /// the only path, as it was before.
    pub(super) index_tip_secs: AtomicU64,
    /// Watch-folder poll period. The filesystem watcher is what makes a
    /// drop feel instant; this is the backstop for the cases it cannot
    /// see - notably SMB/NFS mounts, where the kernel gets no events for
    /// a write made on another host.
    pub(super) watch_interval_secs: AtomicU64,
    /// Fired by the filesystem watcher so the loop wakes at once instead
    /// of sitting out the rest of its interval.
    pub(super) watch_scan_now: tokio::sync::Notify,
    /// M29 availability oracle: idle STAT sampling budget in
    /// STATs/hour/server (live setting; 0 disables the sampler).
    pub(super) oracle_sample: AtomicU64,
    /// Time-of-week scheduler entries + their JSON source text (the text
    /// is what get_config echoes back for the UI editor).
    pub(super) schedule: Mutex<Vec<SchedEntry>>,
    pub(super) schedule_text: Mutex<String>,
    /// M23 watchlist - a live setting (key "watchlist"): the watcher
    /// re-reads this each pass, so dashboard edits apply immediately.
    pub watchlist: Mutex<Vec<crate::watchlist::WatchItem>>,
    /// What the watcher has grabbed per item-slot, plus upgrades waiting
    /// to delete their predecessor. Persisted to .spool/watchlist-state.json.
    pub watch_state: Mutex<crate::watchlist::WatchState>,
    /// mode=watchlist_check_now: wakes the watcher out of its sleep.
    pub(super) watch_now: tokio::sync::Notify,
    /// §151 external list sources. Declared in `serve/listsrc.rs`, which
    /// owns it; `Daemon::watch_items` is how it is read.
    pub(super) lists: super::listsrc::ListState,
    /// §96.3 give-up breaker: distinct final failures per target
    /// (episode/movie) before the target is given up. 0 = off, the
    /// default - the breaker unmonitors things in the user's *arr, which
    /// is not behaviour to default on.
    pub(super) arr_giveup_threshold: AtomicU64,
    /// The *arr instances the breaker may act on (settings key
    /// `arr_instances`; apikeys redacted from get_config).
    pub(super) arr_instances: Mutex<Vec<super::giveup::ArrInstance>>,
    /// Per-target failure counters, fed by `park` from final failures of
    /// arr- and watchlist-originated jobs. Persisted to
    /// .spool/giveup-state.json. Arc'd so the *arr-calling thread can
    /// release the action latch when the remote work fails.
    pub(super) giveup: Arc<Mutex<super::giveup::GiveupState>>,
    /// §282 section C: the replacement hunt's work queue. Its ceilings
    /// are item 13's and live on `alt` above (see `serve/hunt.rs`).
    pub(super) hunt: super::hunt::HuntState,
    /// Where UI-changed settings persist (next to the server config).
    pub(super) settings_path: PathBuf,
    /// M31b "your wall": cached taste profile (built from completed
    /// history + watchlist). Rebuilt on a ~60 s TTL - a few hundred
    /// history rows is cheap, but the affinity sort hits it per page.
    #[cfg(feature = "indexer")]
    pub(super) taste_cache: Mutex<Option<(std::time::Instant, TasteProfile)>>,
    /// N12: `owned_title_keys`'s answer, tagged with the
    /// `(queue_rev, history_rev)` pair it was derived under. See that
    /// method for why the revision pair, and not a TTL, is the dirty
    /// signal here.
    #[cfg(feature = "indexer")]
    pub(super) owned_keys_cache: Mutex<Option<(u64, u64, Arc<std::collections::HashSet<String>>)>>,
    /// N12: the enabled-backbone list `oracle_ctx` needs, tagged with the
    /// [`CfgStamp`] of the config file it was read from. See
    /// `enabled_backbones`.
    #[cfg(feature = "indexer")]
    pub(super) oracle_bb_cache: Mutex<Option<(CfgStamp, Vec<String>)>>,
}

/// N12: what makes a cached config read stale - length, mtime and, on
/// unix, inode.
///
/// `write_atomic` publishes by RENAME, so every write the dashboard, the
/// scheduler or the setup wizard performs lands a NEW inode; an editor
/// that rewrites the file in place moves the length or the mtime
/// instead. One `stat` is cheap enough to take per poll, which is the
/// whole point - the alternative it replaces is a disk read plus a JSON
/// parse per poll.
#[cfg(feature = "indexer")]
pub(super) type CfgStamp = (u64, Option<std::time::SystemTime>, u64);

/// The stamp of `path`, or None when there is nothing there to stat.
///
/// None is not a failure: `Config::load` answers a missing file by
/// searching for a SABnzbd ini, and the list it then returns came from a
/// path this stamp does not describe. Uncacheable, so uncached.
#[cfg(feature = "indexer")]
fn cfg_stamp(path: &std::path::Path) -> Option<CfgStamp> {
    let md = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        md.ino()
    };
    #[cfg(not(unix))]
    let ino = 0u64;
    Some((md.len(), md.modified().ok(), ino))
}

/// M31b: the user's demonstrated taste, distilled from their completed
/// downloads and watchlist. Feeds the Affinity ("For you") wall sort and
/// the "Because you watch …" caption. Genre/kind weights are normalized
/// to sum ~1.0; `decade_center` is the weighted-mean release year.
#[cfg(feature = "indexer")]
#[derive(Debug, Clone, Default)]
pub struct TasteProfile {
    /// (genre, normalized weight), strongest first, top ~8.
    pub genres: Vec<(String, f32)>,
    /// (kind "tv"/"movie", normalized weight), strongest first.
    pub kinds: Vec<(String, f32)>,
    /// Weighted-mean release year of the taste set, or None.
    pub decade_center: Option<i32>,
    /// Count of source signals (completed history + watchlist items).
    /// 0 = cold start.
    pub n_signals: u32,
}

/// One daemon-owned moment for the throughput chart's marker ring -
/// the daemon-side twin of `nzbkit::pool::PoolEvent`, minus the host
/// (these moments belong to the whole daemon, not to one news server).
#[derive(Debug, Clone)]
pub struct DaemonEvent {
    /// Unix milliseconds, same clock as the pool ring and the chart's
    /// throughput samples, so all three lay on top of each other.
    pub at_ms: u64,
    /// `pause` | `resume` | `limit` | `disk` | `quota` | `clear` |
    /// `sidecar` | `indexer` | `late` | `finish` | `finished` - mapped by
    /// the dashboard to severity classes (fault / recovery / phase / user
    /// action); `finished` also closes its "checking files" phase shading.
    pub kind: &'static str,
    /// A whole sentence for the user, like the pool ring's details.
    pub detail: String,
}

/// Cap for [`Daemon::events`], matching the pool ring's reasoning: a
/// bounded window the UI can always afford to serve.
const DAEMON_EVENT_RING: usize = 256;

/// §G: one news server's last refusal to authenticate, remembered past
/// the pool that saw it.
///
/// [`nzbkit::pool::Refusal`] lives on the live pool, which exists only
/// while a job is running. Copying it here at the point it is observed
/// means the Providers card can still say "this provider rejected your
/// sign-in" once the queue has drained - the state in which a user
/// actually goes looking. Cleared when the same host later connects and
/// moves bytes, so a fixed password stops being reported as broken.
#[derive(Debug, Clone)]
pub struct ServerRefusal {
    /// True when retrying cannot help (a bad credential); false when the
    /// account is fine and the server is simply at a connection or IP cap.
    pub permanent: bool,
    /// WHERE the account is used from, not its socket count (M9).
    pub source_ips: bool,
    /// The server's own status line, verbatim - a paraphrase would lose
    /// the words that tell the user what to do.
    pub line: String,
    pub at: i64, // unix seconds, last seen
}

/// A4: the index_stats figures behind [`Daemon::index_stats_snapshot`],
/// with what makes them a real cache rather than a busy-fallback: a
/// TTL (a fresh snapshot is served without touching any index lock,
/// even when the writer mutex is free), an era stamp (a wipe or
/// source-off bumps [`Daemon::index_era`], which orphans the figures
/// instantly), and a singleflight flag (one caller recomputes the
/// expensive `SCAN releases`; everyone else serves the stale snapshot
/// instead of queueing more scans behind it).
#[cfg(feature = "indexer")]
#[derive(Default)]
pub struct IndexStatsCache {
    /// (releases, complete, db_bytes, live_bytes). None until the
    /// first successful read - the API forwards that as stats_cold.
    pub snap: Option<(u64, u64, u64, u64)>,
    /// When `snap` was computed. None forces the next snapshot call to
    /// recompute (the post-scan-pass refresh does exactly this).
    pub at: Option<std::time::Instant>,
    /// The [`Daemon::index_era`] the figures belong to.
    pub era: u64,
    /// A recompute is in flight on some other caller's thread.
    pub refreshing: bool,
    /// Bumped by every explicit [`Daemon::refresh_index_stats`] (sweep
    /// 8, L8). A flight that started before the bump is describing the
    /// database as it was BEFORE whatever the refresher just committed,
    /// so it may not publish itself as fresh.
    ///
    /// The interleaving without it: a dashboard poll begins its SQLite
    /// reads; the scan pass commits and calls the explicit refresh,
    /// which clears `at`, sees `refreshing` already set and returns;
    /// the older flight then finishes and stamps `Instant::now()`, and
    /// its pre-commit snapshot is served as current for the whole TTL.
    /// The one call whose entire job is "the cache must reflect what I
    /// just wrote" is the one the singleflight defeats.
    pub generation: u64,
}

/// What the scan loop is doing right now - the shared counter is bumped
/// by index_scan_into as OVER chunks land.
#[cfg(feature = "indexer")]
pub struct ScanProgress {
    pub group: String,
    pub done: Arc<AtomicU64>,
}

// M34 index size cap + eviction (daemon half) lives in
// daemon_evict.rs - the vocabularies, their validators and the
// opened-log are one subject with no reference to `Daemon`, so the
// size gate moved them whole (the daemon_index.rs precedent just
// below). Re-exported so every existing `daemon::` / `super::` path
// still resolves here.
#[path = "daemon_evict.rs"]
mod daemon_evict;
#[cfg(feature = "indexer")]
pub(in crate::serve) use daemon_evict::{EVICT_MAX_PASSES, EVICT_PREVIEW_MAX_EXAMINE};
#[cfg(feature = "indexer")]
pub use daemon_evict::{
    EVICT_ORDERS, EVICT_SCOPES, OPENED_PROTECT_DAYS, OpenedLog, parse_evict_kinds,
    parse_evict_order, parse_evict_scope,
};
pub use daemon_evict::{SCOREBOARD_CATEGORIES, parse_scoreboard_cats};
// The opened-log's two bounds have no reader outside their own module
// in a production build - only the suites reach them, through serve's
// `use daemon::*` - so re-exporting them unconditionally is an unused
// import, and this crate builds with `-D warnings`. Same shape, and
// the same reason, as the daemon_index trio just below.
#[cfg(all(test, feature = "indexer"))]
pub(in crate::serve) use daemon_evict::{OPENED_COALESCE_SECS, OPENED_MAX_ENTRIES};

// The protected-set trio (assemble_protected / watch_item_keys /
// shrink_shortfall_reason) lives with its callers in daemon_index.rs
// (TODO 106 code motion, size gate); re-exported so every existing
// `super::` and `daemon::` path still resolves here.
#[cfg(feature = "indexer")]
pub use daemon_index::shrink_shortfall_reason;
// The other two have no caller outside daemon_index.rs in a production
// build - only `serve::tests_index` reaches them, through serve's
// `use daemon::*`. Re-exporting them unconditionally is an unused import
// on the non-test build, and this crate builds with `-D warnings`.
#[cfg(all(test, feature = "indexer"))]
pub use daemon_index::{assemble_protected, watch_item_keys};

/// What one eviction attempt did. Every variant except `Ran` means
/// nothing was deleted.
#[cfg(feature = "indexer")]
pub enum EvictOutcome {
    /// The engine ran. Carries its report and how many protected keys
    /// stood in the way (0 = the shortfall, if any, is not protection).
    Ran(nzbkit::index::EvictReport, usize),
    /// Not applicable: eviction off, no cap set, or already under it.
    Nothing,
    /// The index could not be opened.
    Unavailable,
}

/// The job with this id, out of an already-locked list. Takes the
/// iterator rather than the daemon so a caller that is walking the queue
/// for other reasons does not lock it twice.
pub(super) fn find_job<'a>(
    list: impl IntoIterator<Item = &'a Arc<Mutex<Job>>>,
    id: &str,
) -> Option<Arc<Mutex<Job>>> {
    list.into_iter().find(|j| j.lock_ok().nzo_id == id).cloned()
}

/// The `wall_tip` response body. `tip: None` means the index read
/// FAILED, and that has to reach the browser as something other than a
/// number.
///
/// The wall latches the first `latest` it is given as its cursor
/// (`if(tipMark<0){tipMark=j.latest}`). Once `since=-1` made 0 a
/// meaningful cursor rather than "uninitialized", a failed read that
/// defaulted to `latest: 0` latched 0 - and the next successful poll
/// then answered "everything posted in the last 7 days arrived just
/// now", which is precisely the pill claiming 890,000 arrivals that the
/// `since=-1` case exists to prevent. A genuinely empty index reports a
/// real 0 and must keep working, so the two cannot share a value:
/// failure is `null`, which the poll's `typeof j.latest!=='number'`
/// guard drops on the floor, leaving the cursor unlatched for the next
/// tick.
#[cfg(feature = "indexer")]
pub(super) fn wall_tip_body(
    tip: Option<nzbkit::index::TipInfo>,
    initialized: bool,
) -> serde_json::Value {
    let Some(tip) = tip else {
        return json!({"latest": serde_json::Value::Null, "new": 0, "keys": []});
    };
    json!({
        "latest": tip.latest,
        "new": if initialized { tip.new_keys } else { 0 },
        "keys": if initialized { tip.keys } else { Vec::new() },
    })
}

// WHEN INDEX MAINTENANCE MAY RUN lives in daemon_maint.rs - the two
// "is this a moment for it" predicates, the VACUUM disk-space verdict,
// and the arm/abort rendezvous that stands down a statement already
// executing. One subject asked at three ranges, moved whole by the size
// gate on the daemon_evict.rs precedent above. Re-exported so every
// existing `daemon::` / `super::` path still resolves here.
#[path = "daemon_maint.rs"]
mod daemon_maint;
#[cfg(feature = "indexer")]
pub(in crate::serve) use daemon_maint::{
    COMPACT_CHUNK_PAGES, MaintenanceArm, abort_compact_when_job_starts,
};
#[cfg(feature = "indexer")]
pub use daemon_maint::{CompactVerdict, compact_verdict};
// COMPACT_ABORT_POLL_MS has no reader outside its own module in a
// production build - only `serve::tests_index` reaches it, through
// serve's `use daemon::*` - so re-exporting it unconditionally is an
// unused import, and this crate builds with `-D warnings`. Same shape,
// and the same reason, as the daemon_evict and daemon_index pairs above.
#[cfg(all(test, feature = "indexer"))]
pub(in crate::serve) use daemon_maint::COMPACT_ABORT_POLL_MS;

/// RAII half of [`Daemon::bench_begin`]: holds the single-flight latch
/// for one system-benchmark run and releases it on drop, so a panic in
/// the workload can never wedge benchmarks off forever.
pub(super) struct BenchRun<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for BenchRun<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Daemon {
    /// The passwords-file candidates, read fresh so hand-edits and a
    /// just-imported competitor file apply to the very next unlock.
    pub fn read_unpack_passwords(&self) -> Vec<String> {
        crate::smart::read_password_file(&self.password_file.lock_ok())
    }

    /// The same candidates in §99 try-order: the password last known to
    /// unlock a download from `site` first, then the last one for
    /// `poster`, then the rest in file order.
    pub fn read_unpack_passwords_for(&self, site: &str, poster: &str) -> Vec<String> {
        let path = self.password_file.lock_ok().clone();
        crate::smart::order_passwords(crate::smart::read_password_file(&path), &path, site, poster)
    }

    /// §99: remember that `pw` unlocked a download from `site` /
    /// `poster`, so the next passworded job tries it first. The value
    /// never reaches get_config or a log line.
    pub fn record_unlock_password(&self, site: &str, poster: &str, pw: &str) {
        let path = self.password_file.lock_ok().clone();
        crate::smart::record_password_assoc(&path, site, poster, pw);
    }

    /// May the watchlist spend the user's indexer accounts? See
    /// `watchlist_external_set` for why this is a tri-state rather than
    /// the plain bool it reads like.
    pub fn watchlist_external_on(&self) -> bool {
        if self.watchlist_external_set.load(Ordering::Relaxed) {
            self.watchlist_external.load(Ordering::Relaxed)
        } else {
            self.enabled_indexers() > 0
        }
    }

    /// §74: the instant watchlist path, compiled from the live watchlist.
    /// `None` when the feature is off or there is nothing enabled to
    /// match - the callers use that to skip installing an arrival watch
    /// at all, so an install without a watchlist pays nothing.
    #[cfg(feature = "indexer")]
    pub(super) fn instant_matcher(&self) -> Option<crate::watchlist::InstantMatcher> {
        if !self.watchlist_instant.load(Ordering::Relaxed) {
            return None;
        }
        // watch_items: a synced entry gets the instant grab too (§151).
        let m = crate::watchlist::InstantMatcher::compile(&self.watch_items());
        (!m.is_empty()).then_some(m)
    }

    /// §74: wake the watchlist pass because `names` just arrived, unless
    /// this hour's allowance of instant passes is already spent.
    ///
    /// Returns whether the pass was woken. A refusal is not a lost grab:
    /// the periodic pass runs a minute later over the same index and
    /// applies exactly the same rules, so the ceiling only ever costs the
    /// "instant" part.
    #[cfg(feature = "indexer")]
    pub(super) fn instant_kick(&self, names: &[String], now: i64) -> bool {
        let staged = self.stage_instant_hint(names, now);
        if staged {
            self.watch_now.notify_one();
        }
        staged
    }

    /// §74: the hint half of [`Self::instant_kick`], without the wake-up.
    ///
    /// Split out so the scan leg can stage its arrivals while it still
    /// holds the `index` mutex it is republishing under - see
    /// [`Daemon::publish_index_with_arrivals`]. Everything else wants the
    /// two together and calls `instant_kick`.
    ///
    /// Returns whether the names were staged; false means this hour's
    /// allowance is spent and there is nothing to wake anyone for.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn stage_instant_hint(&self, names: &[String], now: i64) -> bool {
        if names.is_empty() {
            return false;
        }
        {
            let mut k = self.instant_kicks.lock_ok();
            if !crate::watchlist::kick_allowed(
                &mut k,
                self.watchlist_instant_max.load(Ordering::Relaxed),
                now,
            ) {
                return false;
            }
        }
        {
            // The pass drains this, so a second arrival landing before it
            // runs joins the same wake-up rather than queueing another.
            let mut hint = self.instant_hint.lock_ok();
            for n in names {
                if !hint.contains(n) {
                    hint.push(n.clone());
                }
            }
            // A watchlist item nobody grabs (below min_quality, say) would
            // otherwise keep re-arriving and grow this without bound.
            const HINT_CAP: usize = 256;
            if hint.len() > HINT_CAP {
                let excess = hint.len() - HINT_CAP;
                hint.drain(..excess);
            }
        }
        true
    }

    /// Should the pre feed be connected right now?
    ///
    /// Two switches, both required. Its own, because it is an outbound
    /// connection to a network nothing else here talks to. The indexer's,
    /// because the feed writes into the index database and names indexed
    /// releases - with the indexer off there is nothing for it to name
    /// and nowhere to put what it hears.
    #[cfg(feature = "indexer")]
    pub(super) fn predb_feed_on(&self) -> bool {
        self.predb_enabled.load(Ordering::Relaxed) && self.index_enabled.load(Ordering::Relaxed)
    }

    /// Record what the feed is doing, for the settings card.
    #[cfg(feature = "indexer")]
    pub(super) fn predb_say(&self, what: &str) {
        *self.predb_status.lock_ok() = what.to_string();
    }

    /// Turn the stored settings into a connection description.
    #[cfg(feature = "indexer")]
    pub(super) fn predb_irc_config(&self) -> nzbkit::predb::IrcConfig {
        let raw = self.predb_server.lock_ok().trim().to_string();
        // `host`, `host:port`, `[v6]`, `[v6]:port`. The bracket form has
        // to be split before the last colon is consulted, or every
        // literal IPv6 address reads as a host with a nonsense port.
        let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
            match rest.split_once("]:") {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse().unwrap_or(nzbkit::predb::DEFAULT_PORT),
                ),
                None => (
                    rest.trim_end_matches(']').to_string(),
                    nzbkit::predb::DEFAULT_PORT,
                ),
            }
        } else {
            match raw.rsplit_once(':') {
                Some((h, p)) => match p.parse::<u16>() {
                    Ok(n) => (h.to_string(), n),
                    Err(_) => (raw.clone(), nzbkit::predb::DEFAULT_PORT),
                },
                None => (raw.clone(), nzbkit::predb::DEFAULT_PORT),
            }
        };
        nzbkit::predb::IrcConfig {
            host: if host.is_empty() {
                nzbkit::predb::DEFAULT_HOST.to_string()
            } else {
                host
            },
            port,
            // TLS, and no automatic downgrade. What TLS buys here is not
            // privacy (the channel is public) but ATTRIBUTION: without
            // it, anyone on the path can block 6697, answer on 6667 and
            // inject release names the exact legs go on to match
            // automatically. An operator whose network has no TLS relay
            // opts back in with NZBFAST_PREDB_ALLOW_PLAINTEXT.
            tls: true,
            allow_plaintext: std::env::var_os("NZBFAST_PREDB_ALLOW_PLAINTEXT")
                .is_some_and(|v| v == "1"),
            nick: self.predb_nick.lock_ok().clone(),
            channels: self
                .predb_channels
                .lock_ok()
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }

    /// The watch-failed strip rides the revisioned queue payload, so
    /// every mutation of the map must move `queue_rev` - an idle
    /// dashboard skips the payload while `client_q == qrev`, and a row
    /// removed without a bump is rendered forever: clicking its delete
    /// button then answers "no such rejected file" for an entry the
    /// daemon dropped long ago. Same trap as the update banner
    /// (`latch_update_manifest`) and `set_limit`'s bump above; these
    /// three helpers are the only doors to the map so the next
    /// mutation site cannot forget. Each bumps only when the map
    /// actually changed.
    ///
    /// Returns whether this insert changed anything - callers use that
    /// to log the first appearance only.
    pub(super) fn watch_failed_insert(
        &self,
        p: std::path::PathBuf,
        v: (u64, u64, String, String),
    ) -> bool {
        let changed = {
            let mut wf = self.watch_failed.lock_ok();
            match wf.get(&p) {
                Some(old) if *old == v => false,
                _ => {
                    wf.insert(p, v);
                    true
                }
            }
        };
        if changed {
            self.queue_rev.fetch_add(1, Ordering::Relaxed);
        }
        changed
    }

    pub(super) fn watch_failed_remove(&self, p: &std::path::Path) {
        if self.watch_failed.lock_ok().remove(p).is_some() {
            self.queue_rev.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drop every entry whose file has left the disk (the user deleted
    /// or moved it themselves).
    pub(super) fn watch_failed_prune_missing(&self) {
        let changed = {
            let mut wf = self.watch_failed.lock_ok();
            let before = wf.len();
            wf.retain(|p, _| p.exists());
            wf.len() != before
        };
        if changed {
            self.queue_rev.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record one daemon-owned moment for the throughput chart's marker
    /// ring, oldest dropped at the cap. Same contract as the pool
    /// ring's `note`: infallible and quiet, because instrumentation
    /// that can fail or block changes the thing it measures.
    pub(super) fn note_event(&self, kind: &'static str, detail: impl Into<String>) {
        let Ok(mut ring) = self.events.lock() else {
            return;
        };
        if ring.len() >= DAEMON_EVENT_RING {
            ring.pop_front();
        }
        ring.push_back(DaemonEvent {
            at_ms: nzbkit::pool::now_ms(),
            kind,
            detail: detail.into(),
        });
    }

    /// Daemon events newest first, for the stats endpoint's merge with
    /// the pool ring.
    pub(super) fn recent_events(&self, limit: usize) -> Vec<DaemonEvent> {
        self.events
            .lock()
            .map(|r| r.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    /// Per-job capability token for /stream URLs (`?t=…`). Media players
    /// can't send API keys, so the authenticated handoffs - /m3u and the
    /// library .strm pointer - embed this instead; it starts THIS job and
    /// nothing else. Derived, not stored: any nzo_id verifies statelessly,
    /// and it stays valid as long as the install (Jellyfin may first play
    /// a .strm months after it was written).
    pub fn stream_token(&self, nzo_id: &str) -> String {
        use sha2::Digest as _;
        let d = sha2::Sha256::digest(format!("{}:{nzo_id}", self.stream_secret).as_bytes());
        hex::encode(d)[..32].to_string()
    }
}

/// How many failure-link replacements deep an automatic re-grab will go
/// before it stops asking and only reports. An indexer with a run of
/// dead posts for one title would otherwise walk the entire run
/// unattended, which is a lot of someone's block account spent on a
/// title that is evidently not out there.
pub(super) const FAILURE_REGRAB_MAX: u8 = 3;

impl Daemon {
    /// Where the newsgroup catalogue cache lives: next to the index db,
    /// same lifecycle (wiping the index leaves it - it's server data,
    /// not scan data).
    #[cfg(feature = "indexer")]
    pub(super) fn groups_cache_path(&self) -> PathBuf {
        self.index_db.with_file_name("groups.tsv")
    }

    /// Sampled per-group profiles, beside the catalogue and with the same
    /// lifecycle.
    #[cfg(feature = "indexer")]
    pub(super) fn groupstats_cache_path(&self) -> PathBuf {
        self.index_db.with_file_name("groupstats.tsv")
    }

    /// M30: dupe keys of everything already in the library or on its
    /// way there - Completed history plus the current queue. The wall
    /// joins browse rows against this to badge "you have this".
    #[cfg(feature = "indexer")]
    pub(super) fn owned_dupe_keys(&self) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        for j in self.queue.lock_ok().iter() {
            if let Some(k) = j.lock_ok().dupe_key.clone() {
                set.insert(k);
            }
        }
        for j in self.history.lock_ok().iter() {
            let g = j.lock_ok();
            if g.state == JobState::Completed
                && let Some(k) = g.dupe_key.clone()
            {
                set.insert(k);
            }
        }
        set
    }

    /// M31b: the parse-key set of everything the user already has -
    /// completed history plus the live queue. These are `title_key`s (the
    /// wall's grouping key), NOT dupe keys, so the Affinity sort can sink
    /// owned titles with a plain `title_key IN (...)`.
    ///
    /// N12: cached against `(queue_rev, history_rev)`. Both consumers are
    /// per-poll - the Affinity wall sort through `affinity_ctx`, and the
    /// eviction pass through `protected_set` - and the walk below is a
    /// `parse_release` per job under that job's lock, ~14,500 of them at
    /// issue #38's history size.
    ///
    /// The revision pair rather than a TTL, deliberately: `protected_set`
    /// decides what eviction may NOT delete, so a key that went missing
    /// for a TTL's worth of seconds is a window in which the index can
    /// drop rows for a title the user has just finished. Both counters
    /// move at the persistence seams (`save_queue`, `histstore`), which
    /// every membership, state and name change comes through, and the
    /// house rule at those seams is store-before-bump (spelled out at
    /// `publish_hold`) - so a reader can see a change ahead of its bump,
    /// but never a bump ahead of its change.
    ///
    /// Which is why the revisions are read BEFORE the walk. A mutation
    /// landing mid-walk gets tagged with the pre-mutation revision and is
    /// discarded by the very next caller; reading them afterwards would
    /// instead stamp a pre-mutation answer as current and keep it.
    #[cfg(feature = "indexer")]
    pub(super) fn owned_title_keys(&self) -> std::collections::HashSet<String> {
        let rev = (
            self.queue_rev.load(Ordering::Relaxed),
            self.history_rev.load(Ordering::Relaxed),
        );
        // A leaf lock taken twice, not held across the walk: the walk
        // takes the queue and history locks and then a job lock, and a
        // cache mutex outranking those would add a fourth edge to that
        // order to de-duplicate a miss only two callers can race.
        let hit = self
            .owned_keys_cache
            .lock_ok()
            .as_ref()
            .filter(|(q, h, _)| (*q, *h) == rev)
            .map(|(_, _, set)| Arc::clone(set));
        if let Some(set) = hit {
            return (*set).clone();
        }
        let fresh = Arc::new(self.owned_title_keys_uncached());
        *self.owned_keys_cache.lock_ok() = Some((rev.0, rev.1, Arc::clone(&fresh)));
        (*fresh).clone()
    }

    /// The walk itself: what `owned_title_keys` answers on a miss, and
    /// the ground truth its tests check the cached answer against.
    #[cfg(feature = "indexer")]
    pub(super) fn owned_title_keys_uncached(&self) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        let mut push = |name: &str| {
            let k = crate::wall::parse_release(name).key;
            if !k.is_empty() {
                set.insert(k);
            }
        };
        for j in self.queue.lock_ok().iter() {
            push(&j.lock_ok().name);
        }
        for j in self.history.lock_ok().iter() {
            let g = j.lock_ok();
            if g.state == JobState::Completed {
                push(&g.name);
            }
        }
        set
    }

    /// M29: everything a wall verdict needs - the availability-ledger
    /// snapshot plus the user's enabled backbones. None when the ledger
    /// is still empty or no server is enabled (verdicts all null).
    #[cfg(feature = "indexer")]
    pub(super) fn oracle_ctx(
        &self,
        cfg_path: &std::path::Path,
    ) -> Option<(nzbkit::oracle::Snapshot, Vec<String>)> {
        // with_index_read: every caller is an interactive handler (wall2,
        // index_browse, oracle_takedowns) - none may park behind ingest.
        let snap = self.with_index_read(|ix| ix.oracle_snapshot().ok())?;
        if snap.is_empty() {
            return None;
        }
        let bbs = self.enabled_backbones(cfg_path);
        (!bbs.is_empty()).then_some((snap, bbs))
    }

    /// The sorted, deduped backbone of every ENABLED server, cached
    /// against the config file's [`CfgStamp`].
    ///
    /// N12: `oracle_ctx` runs on the wall2 poll, and this was a full
    /// `Config::load` - a disk read and a JSON parse - on every one of
    /// them, for a list that changes only when somebody edits the server
    /// set. The dashboard edits it through the API, which publishes by
    /// atomic rename, so the stamp moves the instant that write lands and
    /// the very next poll re-reads; an out-of-process edit moves it too.
    ///
    /// The stamp is taken BEFORE the load, for the same reason
    /// `owned_title_keys` reads its revisions first: a write landing
    /// mid-load is then tagged with the pre-write stamp and re-read by
    /// the next caller, where stamping afterwards would file bytes read
    /// before the write under metadata written after it and keep them.
    #[cfg(feature = "indexer")]
    fn enabled_backbones(&self, cfg_path: &std::path::Path) -> Vec<String> {
        let stamp = cfg_stamp(cfg_path);
        if let Some(stamp) = stamp.as_ref() {
            let hit = self
                .oracle_bb_cache
                .lock_ok()
                .as_ref()
                .filter(|(s, _)| s == stamp)
                .map(|(_, bbs)| bbs.clone());
            if let Some(bbs) = hit {
                return bbs;
            }
        }
        let mut bbs: Vec<String> = nzbkit::config::Config::load(cfg_path)
            .map(|c| {
                c.servers
                    .iter()
                    .filter(|s| s.enabled)
                    .map(|s| nzbkit::oracle::backbone_of(&s.host))
                    .collect()
            })
            .unwrap_or_default();
        bbs.sort();
        bbs.dedup();
        if let Some(stamp) = stamp {
            *self.oracle_bb_cache.lock_ok() = Some((stamp, bbs.clone()));
        }
        bbs
    }

    /// Enqueue an NZB that arrived over HTTP, keeping what the indexer
    /// said about it in the response headers. `depth` is how many
    /// failure-link replacements deep this one already is: 0 for a
    /// user's own add, +1 for each automatic re-grab.
    pub(super) fn enqueue_fetched(
        &self,
        f: &Fetched,
        name: &str,
        category: &str,
        priority: i32,
        pp: Option<i64>,
        password: Option<&str>,
        depth: u8,
        origin: &str,
        exempt: DupeExempt<'_>,
    ) -> Result<Enqueued> {
        let mut e = self.enqueue_as(
            None, &f.bytes, name, category, priority, pp, password, origin, exempt, None,
        )?;
        let mut stamped = false;
        if !f.failure_link.is_empty() {
            // Just pushed, so it is at the back; scan anyway rather than
            // assume - enqueue may re-order or park a duplicate.
            let q = self.queue.lock_ok();
            if let Some(job) = q.iter().find(|j| j.lock_ok().nzo_id == e.nzo_id) {
                let mut j = job.lock_ok();
                j.failure_link = f.failure_link.clone();
                j.failure_host = f.host.clone();
                j.failure_https = f.https;
                j.failure_depth = depth;
                stamped = true;
            }
        }
        // enqueue saved the queue BEFORE this stamp existed. Without a
        // second save, a restart in the window loses the link and the
        // depth: the job silently never reports, and a replacement chain
        // restarts its allowance at 0.
        if stamped {
            e.durable = self.save_queue();
        }
        Ok(e)
    }

    /// §129 4c: has this install EVER had a download? The dashboard's
    /// second empty state (set up, nothing downloaded yet) hides the
    /// cards that can only read zero until this is true, and TODO §129
    /// 4c's own contract is that it never hides telemetry again once a
    /// job has run - so this has to be sticky, not "is the queue empty
    /// right now". Clearing history must not drop a working install
    /// back into onboarding.
    ///
    /// The sticky term is the usage store's `"lifetime"` bucket:
    /// `add_usage` bills every finished download into it and the 60-day
    /// prune deliberately never touches it (block accounts span years).
    /// Queue and history answer for a job that is still running, or one
    /// that failed before it billed a byte.
    pub(super) fn jobs_ever(&self) -> bool {
        !self.queue.lock_ok().is_empty()
            || !self.history.lock_ok().is_empty()
            || self
                .usage
                .lock_ok()
                .get("lifetime")
                .and_then(Value::as_object)
                .is_some_and(|m| m.values().any(|v| v.as_u64().unwrap_or(0) > 0))
    }

    /// Next runnable job: highest priority first, FIFO within a priority.
    /// Per-job pause always holds a job back; a Force (2) job also runs
    /// while the whole queue is paused.
    pub(super) fn pick_job(&self, queue_paused: bool) -> Option<Arc<Mutex<Job>>> {
        let q = self.queue.lock_ok();
        // TODO §77: does a red pre-flight verdict sink a job? Off by
        // default, and it only ever REORDERS - a sunk job is still in
        // the queue, still startable, and runs the moment nothing
        // healthier is available.
        let health_defer = self.post_health_defer.load(Ordering::Relaxed);
        // Key: (not deferred, priority, not health-sunk) - a
        // watchdog-deferred (slow) job only runs when NO other job is
        // runnable, whatever its priority was. Ties keep queue order
        // (strict > with first-wins).
        let mut best: Option<((bool, i32, bool), Arc<Mutex<Job>>)> = None;
        for j in q.iter() {
            let g = j.lock_ok();
            // A tombstoned job is deleted; nothing may start it again. The
            // delete paths remove it from the queue themselves, so this is
            // the defensive invariant behind them rather than the mechanism -
            // it is what stops a job whose payload and spooled .nzb have
            // already been unlinked from running one more time.
            if g.paused || g.tombstone || g.state != JobState::Queued {
                continue;
            }
            // Codex F-06: a job whose destination is published but whose
            // earlier progress is still being merged into it. SKIPPED
            // rather than refused at the start: `start_next` re-reads
            // the fence in the critical section that flips the state,
            // and that arm can only answer "pick again" - so without
            // this the runner would spin on the same fenced job for the
            // whole of a large move instead of running the next one.
            if g.relocating > 0 {
                continue;
            }
            if queue_paused && g.priority < 2 {
                continue;
            }
            // The health sink sits BELOW priority in the key on purpose,
            // where the watchdog's defer sits above it. The watchdog has
            // measured this job going slowly on this line; pre-flight has
            // asked eight articles a question that propagation can
            // answer wrongly, so an advisory guess must never overrule
            // what the user explicitly asked for. Forced jobs (priority
            // 2, which is also what "start this next" sets) are exempt
            // outright.
            let sunk =
                health_defer && g.priority < 2 && g.health.as_ref().is_some_and(|h| h.sinks());
            let key = (!g.deferred, g.priority, !sunk);
            if best.as_ref().is_none_or(|(bk, _)| key > *bk) {
                best = Some((key, j.clone()));
            }
        }
        best.map(|(_, j)| j)
    }

    /// Benchmark history: one JSON array in .spool, appended by every
    /// sysbench run (manual or scheduled), capped at 400 entries.
    pub(super) fn bench_history_path(&self) -> PathBuf {
        // Working state lives in the fixed spool, not the (now live-swappable)
        // download folder.
        self.spool.join("bench_history.json")
    }

    pub(super) fn bench_history(&self) -> Vec<Value> {
        crate::persist::load_json_with_backup(&self.bench_history_path())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    }

    pub(super) fn bench_append(&self, entry: Value) {
        // Load-modify-write under the lock: two unlocked appends both
        // read the same history and one silently overwrote the other's
        // row (Codex sweep 10 Aug M14).
        let _serialised = self.bench_history_lock.lock_ok();
        let p = self.bench_history_path();
        let mut list = self.bench_history();
        list.push(entry);
        let n = list.len();
        if n > 400 {
            list.drain(0..n - 400);
        }
        let _ = crate::persist::write_atomic(&p, &serde_json::to_vec(&list).unwrap_or_default());
    }

    /// Claim the system-benchmark single-flight latch. `None` means a
    /// run is already in progress (another tab, or the schedule) - the
    /// caller must decline rather than run a second workload that
    /// distorts the first's numbers and doubles the provider traffic.
    /// The latch releases when the returned guard drops, panics
    /// included.
    pub(super) fn bench_begin(&self) -> Option<BenchRun<'_>> {
        self.bench_running
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .ok()
            .map(|_| BenchRun(&self.bench_running))
    }

    /// The queued job with this id, cloned out so the caller works
    /// without holding the queue lock. Locking a Job while holding the
    /// queue is how this tree deadlocks.
    pub(super) fn queue_job(&self, id: &str) -> Option<Arc<Mutex<Job>>> {
        find_job(self.queue.lock_ok().iter(), id)
    }

    /// Same, for history.
    pub(super) fn history_job(&self, id: &str) -> Option<Arc<Mutex<Job>>> {
        find_job(self.history.lock_ok().iter(), id)
    }

    /// Does the job the transfer currently belongs to satisfy `want`?
    ///
    /// The single owner test for every caller that is about to signal
    /// `hub.abort` / `hub.queue_ctl`. Those handles are overwritten per
    /// job and carry no owner tag, so "is this job the live transfer?"
    /// CANNOT be answered from `state == JobState::Downloading`: there is
    /// no Repairing/Extracting state, and job N deliberately stays
    /// Downloading through its whole post-network tail while job N+1 is
    /// already on the wire holding those handles. Steering by state
    /// therefore aimed the abort at the wrong job. `active_stream` is set
    /// to the picked job as the fetch spawns and is the thing the
    /// watchdog already steers by.
    pub(super) fn owns_hub(&self, want: impl Fn(&str) -> bool) -> bool {
        self.active_stream.lock_ok().as_deref().is_some_and(want)
    }

    /// Advance the queue row's activity token through a stage the
    /// DAEMON owns, after the engine's own pipeline has finished with
    /// it.
    ///
    /// The engine advances `hub.activity` at each of its section
    /// transitions and its last word is `"extracting"`, written when the
    /// disk-unpack ladder begins (`get/tail.rs`). Nothing wrote to the
    /// map after that and only `park` removes the entry - so every stage
    /// from the end of extraction to the history row inclusive rendered
    /// as "unpacking": the unlock probes, `resolve_identity` and its two
    /// third-party requests, the cleanup sweeps, the rename and TV
    /// filing, the M29 oracle fold on the index write mutex, and the
    /// post-processing script. A tester watching four minutes of that
    /// was told "unpacking" throughout and reported the job as hung,
    /// which is the reasonable reading of a word that never changes.
    ///
    /// The wire vocabulary is deliberately NOT extended here. Every
    /// token this writes maps to SABnzbd's `Moving` in
    /// [`Self::tail_phase`] - the same word a `Finishing` row already
    /// reported - so Sonarr and Radarr are told exactly what they were
    /// told before; only the dashboard's own sub-line, which is
    /// composed from the raw token, gets finer. Widening what the
    /// *arrs are told is a compatibility question and does not belong
    /// in a diagnostic change.
    ///
    /// They are mapped rather than left unknown because "unknown"
    /// silently means "not in a tail at all" to every caller of
    /// `tail_phase`, and the engine writes the first of these tokens
    /// (`finalizing`, from `get/tail.rs`) while the record is still
    /// `Downloading` - the lane only marks it `Finishing` when it takes
    /// custody, one hand-off later. A queue poll landing in that window
    /// found no phase, so the row fell back to `downloaded_bytes` (0 at
    /// that instant, the counters having been released at net-drain)
    /// and rendered `Downloading 0%` between `Extracting 100%` and
    /// `Moving 100%`. See `tail_phase`.
    pub(super) fn note_tail_stage(&self, nzo_id: &str, tok: &'static str) {
        self.hub.activity.lock_ok().insert(nzo_id.to_string(), tok);
        debug!(target: "lane", "{nzo_id}: tail stage -> {tok}");
    }

    /// The wire status for a job that has left the network but is still
    /// inside the pipeline - or None if it is not in a post-network tail.
    ///
    /// There is no Verifying/Repairing/Extracting `JobState`: the whole
    /// tail runs inside the same fetch future, so the record says
    /// `Downloading` from the first article to the last extracted byte.
    /// The pipeline does say where it is, though - it advances
    /// `hub.activity` at each section transition, tagged with the owning
    /// nzo_id precisely because job N's tail overlaps job N+1's fetch -
    /// so the phase word is read from there rather than from a second
    /// mechanism that would have to be kept in step with it.
    ///
    /// The words are SABnzbd's own state vocabulary - the same
    /// `Moving` queue_json renders a `Completed` row as: Sonarr and
    /// Radarr already read every one of them as "busy, keep waiting",
    /// which is exactly what they mean.
    ///
    /// Every token that means "past the network" must have an arm here,
    /// and the tokens are matched by NAME rather than by a catch-all:
    /// the same map also carries pre-network words (`preflight`, from
    /// the metadata-only check in `tasks.rs`) that are written while the
    /// record is `Downloading` and nothing has been fetched. A default
    /// arm answering `Some` would report those rows as all-in at 100%,
    /// which is the bug this function exists to prevent, pointed the
    /// other way.
    pub(super) fn tail_phase(&self, nzo_id: &str) -> Option<&'static str> {
        match self.hub.activity.lock_ok().get(nzo_id).copied() {
            Some("verifying") => Some("Verifying"),
            Some("repairing") => Some("Repairing"),
            Some("extracting") => Some("Extracting"),
            // The engine's hand-off word and the daemon's own tail
            // stages (`note_tail_stage`), which follow it. All one wire
            // word - `Moving` - so nothing new reaches the *arrs; what
            // changes is that the stretch from the end of extraction to
            // the history row is a TAIL to every caller, in the
            // `Downloading` window before the lane marks the record
            // `Finishing` just as much as after it.
            // `indexwait` is the tail parked behind the index write
            // mutex (TODO 200): still the same tail, still `Moving`.
            Some(
                "finalizing" | "unlocking" | "identifying" | "renaming" | "scripting" | "indexwait",
            ) => Some("Moving"),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod daemon_tests;
