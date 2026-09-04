//! §129 parallelism census, the mover half: per-TARGET mover lanes.
//!
//! The destination mover used to be ONE sequential worker across jobs -
//! right for one destination (two multi-GB copies to the same NAS or
//! disk fight each other, and `move_tree`'s staging-name scheme must
//! never arbitrate two live moves into one Season folder), wrong across
//! destinations: a move to a slow NAS held up a move to a fast local
//! disk that shares nothing with it. The target IS the wall, so the
//! serialization is now per target: one lane per destination DEVICE,
//! spawned on demand, each lane a sequential worker with exactly the
//! old semantics (blocking-pool `mover_process`, busy verdicts paused
//! and re-queued). Two different devices never queue behind each other;
//! the same device stays serial and FIFO.
//!
//! Three things carry the correctness:
//!
//! - the lane key is the destination root's DEVICE, not its path (see
//!   [`lane_key`]) - which is what keeps nested roots, a category
//!   override under its own global root, and every job that could land
//!   in one Season folder on ONE lane;
//! - [`MOVER_MAX_CONCURRENT`] bounds the whole fleet, because every
//!   move reads the same download volume however many destinations
//!   there are;
//! - the pacer's token bucket is one shared instance ([`mover_pacer`]),
//!   so N concurrent copies divide one budget instead of each granting
//!   itself the full one.

use super::*;
use std::collections::HashMap;
use tracing::debug;

/// How many moves may be in flight at once across ALL lanes.
///
/// Lanes exist so two destinations stop queueing behind each other, not
/// so a machine can run ten bulk copies at once: every move READS the
/// same download volume, and each one holds a blocking-pool thread for
/// as long as the copy takes. Three is plenty of lane freedom for the
/// shapes that motivated this (a NAS copy, a local copy, a straggler)
/// and keeps the source disk and the pool civil.
///
/// Deliberately a constant rather than a setting: a setting is three
/// places and a question nobody outside this file can answer better
/// than the file can.
const MOVER_MAX_CONCURRENT: usize = 3;

/// Test-only: how long a move pretends to take, inside the `moving`
/// fence, so a test can watch lanes overlap without a second physical
/// volume. Read by `Daemon::mover_process`.
#[cfg(any(test, feature = "test-support"))]
pub static TEST_MOVE_DELAY_MS: AtomicU64 = AtomicU64::new(0);

/// The device behind `root`, as a lane key. `None` when it cannot be
/// resolved at all, which the caller turns into the shared lane.
#[cfg(unix)]
fn device_key(root: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    // The destination root itself often does not exist yet - the first
    // move to a new completed folder creates it - so walk up to the
    // deepest ancestor that does. That is the volume the root will be
    // created on, which is the device the copy will actually hit.
    for cur in root.ancestors() {
        if let Ok(md) = std::fs::metadata(cur) {
            return Some(format!("dev:{}", md.dev()));
        }
    }
    None
}

/// The device behind `root`, as a lane key. `None` when it cannot be
/// resolved at all, which the caller turns into the shared lane.
#[cfg(windows)]
fn device_key(root: &Path) -> Option<String> {
    // The volume a path lives on IS its prefix here: a drive letter
    // (`C:\`) or a UNC server+share (`\\nas\media`). Case is not
    // significant on Windows, so key on the lowercased form or the same
    // share reached two ways would get two lanes.
    match root.components().next() {
        Some(std::path::Component::Prefix(p)) => Some(format!(
            "vol:{}",
            p.as_os_str().to_string_lossy().to_lowercase()
        )),
        _ => None,
    }
}

/// The lane a destination root belongs to: its DEVICE, never its path
/// string.
///
/// The device is what concurrent moves actually contend for, and it is
/// also what makes nested roots safe for free: a global root
/// `/nas/done` and a category root `/nas/done/tv` are one volume, so
/// they share one lane and stay serial. A path key would have split
/// them and pointed two bulk copies at one NAS. The same follows for
/// `move_tree`'s staging scheme - jobs that can meet in one Season
/// folder share a destination subtree, hence a device, hence a lane.
///
/// Anything unresolvable returns the shared lane (the empty key):
/// falling back to serial is always correct, a wrong split is not.
pub(super) fn lane_key(root: &Path) -> String {
    device_key(root).unwrap_or_default()
}

/// The lane for a job in `cat`: the device of the destination root
/// `relocate_completed` will pick for it.
///
/// A job with no destination configured never reaches the mover
/// (`move_destination_configured` gates `move_pending`); if one ever
/// does, it takes the shared lane.
pub(super) fn lane_key_for(d: &Daemon, cat: &str) -> String {
    match d.move_dest_root(cat) {
        Some((root, _)) => lane_key(&root),
        None => String::new(),
    }
}

/// The live lanes, keyed by device, and the one permit pool they all
/// draw from.
pub(super) struct Lanes {
    map: HashMap<String, tokio::sync::mpsc::UnboundedSender<Arc<Mutex<Job>>>>,
    permits: Arc<tokio::sync::Semaphore>,
}

impl Lanes {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            permits: Arc::new(tokio::sync::Semaphore::new(MOVER_MAX_CONCURRENT)),
        }
    }

    /// Hand `job` to `key`'s lane, starting that lane on first use.
    ///
    /// A lane lives for the daemon's life once started. The population
    /// is bounded by the number of destination DEVICES - a handful -
    /// and a lane that never dies cannot race an enqueue: there is no
    /// window in which the map holds a worker that has already decided
    /// to stop.
    pub fn dispatch(&mut self, d: &Arc<Daemon>, key: String, job: Arc<Mutex<Job>>) {
        let permits = self.permits.clone();
        let daemon = d.clone();
        let lane = key.clone();
        let tx = self
            .map
            .entry(key)
            .or_insert_with(|| spawn_lane(&daemon, lane, permits));
        // The receiver outlives every sender by construction, so this
        // cannot fail; if it somehow did, the job goes back on the
        // dispatcher's queue rather than vanishing.
        if let Err(e) = tx.send(job) {
            d.mover_q.lock_ok().push_back(e.0);
        }
    }

    /// How many lanes are running - the shape this whole change is
    /// about, and the only way a test can see it without two volumes.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.map.len()
    }
}

/// One device's lane: a sequential worker over that destination only,
/// with exactly the pre-lane semantics - the copy on the blocking pool,
/// a busy verdict paused and sent to the back of the queue.
fn spawn_lane(
    d: &Arc<Daemon>,
    key: String,
    permits: Arc<tokio::sync::Semaphore>,
) -> tokio::sync::mpsc::UnboundedSender<Arc<Mutex<Job>>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Arc<Mutex<Job>>>();
    let d = d.clone();
    let back = tx.clone();
    debug!(target: "move", "mover lane {} started", if key.is_empty() { "shared" } else { &key });
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            // The cap is global, not per lane: the lanes are separate
            // destinations but one SOURCE volume and one blocking pool.
            let permit = permits.clone().acquire_owned().await;
            let d2 = d.clone();
            let j2 = job.clone();
            let requeue = tokio::task::spawn_blocking(move || {
                let _busy = d2.busy.hold("moving");
                d2.mover_process(&j2)
            })
            .await
            .unwrap_or(false);
            drop(permit);
            if !requeue {
                // Custody ends here and nowhere else: across a requeue
                // (below) the job stays in this lane's channel, still
                // invisible to `mover_q` and `moving`, so the count
                // must ride with it.
                d.mover_inflight.fetch_sub(1, Ordering::Relaxed);
            }
            if requeue {
                // Another actor holds this job's files (a recategorize
                // mid-flight). Pause, then the BACK of this lane's own
                // queue: a job that cannot move must not hold up the
                // ones behind it, and must not spin either.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if let Err(e) = back.send(job) {
                    d.mover_q.lock_ok().push_back(e.0);
                }
            }
        }
    });
    tx
}

/// C: the mover dispatcher - drains `Daemon::mover_q` into per-device
/// lanes. The queue this frees is the DOWNLOAD queue - the finalize
/// tail used to run the move inline, and the runner awaited that tail
/// before starting the next job.
pub fn spawn_mover(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut lanes = Lanes::new();
        loop {
            let job = d.mover_q.lock_ok().pop_front();
            match job {
                Some(job) => {
                    let cat = job.lock_ok().category.clone();
                    // One config read and one stat walk per job, here on
                    // the dispatcher rather than in the lane: the key
                    // has to be decided before the job is handed over.
                    let key = lane_key_for(&d, &cat);
                    lanes.dispatch(&d, key, job);
                }
                None => d.mover_wake.notified().await,
            }
        }
    });
}

/// The mover's token bucket. ONE per daemon (`Daemon::mover_bucket`),
/// drawn from by every lane.
///
/// This state used to be built per CALL, inside `mover_pacer`. With
/// lanes that would be a bug with a number attached: N concurrent moves
/// would each grant themselves the FULL yield-mode budget, breaking the
/// "never slow a live download" promise by exactly the number of lanes
/// running. One bucket for the fleet is the whole design - splitting
/// the budget per lane would just re-introduce the same arithmetic in a
/// harder-to-see place.
pub struct PaceState {
    pub window: Instant,
    pub sent: u64,
    pub sample_at: Instant,
    pub sample_bytes: u64,
    pub wire_bps: u64,
}

impl Default for PaceState {
    fn default() -> Self {
        Self {
            window: Instant::now(),
            sent: 0,
            sample_at: Instant::now(),
            sample_bytes: 0,
            wire_bps: 0,
        }
    }
}

/// A pacing callback for `move_tree_paced`: a token bucket fed by
/// [`Daemon::mover_budget_bps`], with its own live sample of what
/// downloads are currently pulling. Called once per copied chunk with
/// the chunk's size; sleeps just enough to hold the budget.
///
/// The state is the daemon's, not the closure's, so every concurrent
/// move draws from the one bucket - the budget belongs to the mover,
/// not to each copy.
pub(super) fn mover_pacer(d: &Daemon) -> impl Fn(u64) + Send + Sync + '_ {
    move |bytes: u64| {
        let now = Instant::now();
        let nap = {
            let mut g = d.mover_bucket.lock_ok();
            // Refresh the download-rate sample every ~500 ms from the
            // daemon's own progress counter.
            let since = now.duration_since(g.sample_at).as_secs_f64();
            if since >= 0.5 {
                let prog = d.progress.load(Ordering::Relaxed);
                if g.sample_bytes > 0 && prog >= g.sample_bytes {
                    g.wire_bps = ((prog - g.sample_bytes) as f64 / since) as u64;
                }
                g.sample_bytes = prog;
                g.sample_at = now;
            }
            let Some(bps) = d.mover_budget_bps(g.wire_bps) else {
                // Uncapped: keep the window fresh so a cap arriving
                // mid-copy does not instantly charge for the burst.
                g.window = now;
                g.sent = 0;
                return;
            };
            g.sent += bytes;
            let elapsed = now.duration_since(g.window).as_secs_f64();
            let over = g.sent as f64 - bps as f64 * elapsed;
            let nap = (over > 0.0)
                .then(|| std::time::Duration::from_secs_f64((over / bps as f64).min(0.5)));
            if elapsed > 2.0 {
                // Roll the window from the moment this caller resumes,
                // so the debt it is about to pay is not charged twice.
                g.window = now + nap.unwrap_or_default();
                g.sent = 0;
            }
            nap
        };
        // Slept OUTSIDE the lock on purpose: several lanes can be in
        // here at once, and holding it across the sleep would turn one
        // shared budget into a convoy - each copy queueing for its turn
        // to wait.
        if let Some(nap) = nap {
            std::thread::sleep(nap);
        }
    }
}

#[cfg(test)]
mod lane_tests;

// TODO 317 (GitHub #67). Here rather than in a file of its own because
// the decisions it pins - which root, and whether a move is owed - are
// this module's, and `writes_through` / `write_through_root` sit beside
// `move_dest_root` for the reason that one's own header gives: a lane
// keyed off a root the move does not use is a lane keyed off the wrong
// device, and a DOWNLOAD written to one is worse.
#[cfg(test)]
#[path = "writethrough_tests.rs"]
mod writethrough_tests;

/// The `Daemon` half of the mover: where a finished job is allowed to
/// go, what it may spend getting there, and the move itself.
///
/// Moved off `crates/nzbfast-daemon/src/daemon.rs` (TODO 106) to sit with the lanes that
/// call it - `move_dest_root` in particular is the one lookup
/// [`lane_key_for`] and [`Daemon::relocate_completed`] must agree on,
/// and it now lives beside both. A sibling of `daemon` either way, so
/// the moved methods keep their `pub(super)` exactly.
impl Daemon {
    /// The root a completed job in `cat` moves to, and whether it came
    /// from the per-category override (`move_completed_cats`) rather
    /// than the global completed folder. `None` = no destination is
    /// configured for this category, which is the feature being off for
    /// it.
    ///
    /// One lookup, three callers: the finalize gate
    /// ([`Self::move_destination_configured`]), the move itself
    /// ([`Self::relocate_completed`]) and the mover's lane key
    /// ([`mover::lane_key_for`]). They must never disagree - a lane
    /// keyed off a root the move does not use is a lane keyed off the
    /// wrong device.
    pub(super) fn move_dest_root(&self, cat: &str) -> Option<(PathBuf, bool)> {
        // Per-category override wins, and applies even when the global
        // destination is unset.
        let cat_root = self
            .move_completed_cats
            .read_ok()
            .iter()
            .find(|(c, _)| *c == cat)
            .map(|(_, p)| p.clone());
        match cat_root {
            Some(p) => Some((p, true)),
            None => self.move_completed.read_ok().clone().map(|p| (p, false)),
        }
    }

    /// Is a move to a completed folder configured for this category?
    /// The gate finalize uses to decide whether a finished job owes the
    /// mover a visit.
    pub fn move_destination_configured(&self, cat: &str) -> bool {
        self.move_dest_root(cat).is_some()
    }

    /// TODO 317 (GitHub #67): does `cat` download STRAIGHT INTO its
    /// destination rather than moving there at completion?
    ///
    /// Two conditions, and both are load-bearing. The category must
    /// have a destination at all - write-through with nowhere to write
    /// through TO is just the ordinary download folder - and the opt-in
    /// must name it, either globally or by category. The two halves are
    /// a UNION rather than an override chain, which is what a mixed
    /// install needs: the reporter's setup is one drive per content
    /// type, and TODO 317's own warning is that the same feature on an
    /// SMB share pays per-write network latency for the entire
    /// download. Naming the local categories and leaving the global
    /// switch off is how you say that.
    pub(super) fn writes_through(&self, cat: &str) -> bool {
        if self.move_dest_root(cat).is_none() {
            return false;
        }
        self.write_through.load(Ordering::Relaxed)
            || self.write_through_cats.lock_ok().iter().any(|c| c == cat)
    }

    /// TODO 317: the directory a write-through category's jobs are
    /// placed UNDER - the destination-side twin of
    /// [`Daemon::cat_dir`]. `None` = this category does not write
    /// through, which is the feature being off for it.
    ///
    /// DERIVED by running the category's ordinary download directory
    /// through [`Self::move_dest_for`], rather than computed a second
    /// way from `move_dest_root`. That is deliberate and it is the
    /// whole safety argument for this feature: the mapping the mover
    /// WOULD have applied at completion is the one applied at enqueue,
    /// so `relocate_completed` computing a different path afterwards is
    /// not a case that can arise. Doing the arithmetic twice is how a
    /// per-category `dir` override (`cat_meta.dir = "anime"` under a
    /// category named `tv`) parts the two - the override is a component
    /// of the relative path, and only `move_dest_for` knows the rule
    /// for when the category level is dropped from it.
    ///
    /// A job directory is then `root.join(dir_stem)`, which is the same
    /// answer as mapping the job directory itself: both sides of
    /// `move_dest_for` are prefix operations, so appending the stem
    /// commutes with them.
    pub(super) fn write_through_root(&self, cat: &str) -> Option<PathBuf> {
        self.writes_through(cat)
            .then(|| self.move_dest_for(&self.cat_dir(cat), cat))
            .flatten()
    }

    /// Where a job whose payload is currently at `cur` (its `out_dir`,
    /// or whatever a rename left it as) will land under the destination
    /// root for `cat`. `None` = no destination is configured, which is
    /// the feature being off for this category.
    ///
    /// Lifted out of [`Self::relocate_completed`] so §296's early
    /// per-file publish computes the SAME path the whole-job move will,
    /// rather than a second derivation of it. That is the discipline
    /// [`Self::move_dest_root`] already documents one level up - a lane
    /// keyed off a root the move does not use is a lane keyed off the
    /// wrong device - and the failure here is sharper: a file published
    /// to a directory the move never visits is a payload split across
    /// two folders with nothing to say so.
    pub(super) fn move_dest_for(&self, cur: &std::path::Path, cat: &str) -> Option<PathBuf> {
        // A per-category override IS that category's root, so the
        // category component is not repeated inside it - which is what
        // `from_cat` is for below.
        let (root, from_cat) = self.move_dest_root(cat)?;
        // Mirror the layout under the destination: the path relative to
        // the download root already carries category/Show/Season NN. If
        // the job predates a live out_dir swap, fall back to
        // category + folder name.
        let mut rel = cur
            .strip_prefix(crate::naming::out_dir(self))
            .map(|r| r.to_path_buf())
            .unwrap_or_else(|_| {
                let base = PathBuf::from(cur.file_name().unwrap_or_default());
                if cat.is_empty() {
                    base
                } else {
                    PathBuf::from(cat).join(base)
                }
            });
        if from_cat
            && !cat.is_empty()
            && let Ok(r) = rel.strip_prefix(cat)
        {
            rel = r.to_path_buf();
        }
        Some(root.join(&rel))
    }

    /// The mover's byte budget right now, in bytes/second. None = no
    /// cap. Read per pacing decision, so a mode change or a download
    /// starting mid-copy takes effect within one chunk.
    ///
    /// `wire_bps` is the caller's live measurement of what downloads
    /// are pulling (the pacer samples the daemon's own progress
    /// counter). Yield mode subtracts it from the line's capacity plus
    /// a 10% margin: on most home setups downloads are receive and the
    /// NAS copy is send, so the wire rarely contends - but CPU, disk
    /// and the NAS itself do, and the download's own measured rate is
    /// the one lever that tracks all of them.
    pub fn mover_budget_bps(&self, wire_bps: u64) -> Option<u64> {
        let mode = self.move_pace.lock_ok().clone();
        match mode.as_str() {
            "full" => None,
            "yield" | "" => {
                // Idle queue: no cap. The threshold is generous so a
                // trickling health probe does not throttle a 10 GbE
                // copy to the floor.
                if wire_bps < 1_000_000 {
                    return None;
                }
                let line = match self.line_speed.load(Ordering::Relaxed) {
                    0 => self.best_rate_bps.load(Ordering::Relaxed),
                    l => l,
                };
                if line == 0 {
                    // Nothing known about the line: fall back to a
                    // fixed modest share rather than guessing zero.
                    return Some(20_000_000);
                }
                Some((line.saturating_sub(wire_bps + line / 10)).max(5_000_000))
            }
            n => n.parse::<u64>().ok().map(|mb| mb.max(1) * 1_000_000),
        }
    }

    /// Hand a finished job to the mover worker. Idempotent enough for
    /// its callers: a job re-enqueued while already queued just gets
    /// processed twice, and the second pass finds `move_pending` false
    /// and does nothing.
    pub fn mover_enqueue(&self, job: &Arc<Mutex<Job>>) {
        // Counted BEFORE the push, so no observer can see the queue
        // gain work the inflight count does not yet admit to. The
        // matching decrement is the lane's, when `mover_process`
        // returns without a requeue - a second enqueue of the same job
        // is balanced by its own pop reaching the "nothing owed" arm.
        self.mover_inflight.fetch_add(1, Ordering::Relaxed);
        self.mover_q.lock_ok().push_back(job.clone());
        self.mover_wake.notify_one();
    }

    /// One mover step: attempt the owed relocation for `job`. Runs on
    /// the blocking pool (bulk I/O). Returns true when the job should
    /// be RE-queued because another actor holds its files right now (a
    /// recategorize mid-flight).
    pub fn mover_process(self: &Arc<Self>, job: &Arc<Mutex<Job>>) -> bool {
        let (id, out_dir, cat) = {
            let mut g = job.lock_ok();
            if !g.move_pending || g.state != JobState::Completed || g.tombstone {
                // Nothing owed (a delete or a second enqueue got here
                // first). Clear the marker if it survived a tombstone,
                // so a restart does not resurrect the move. Under the
                // SAME hold that read it: dropping and re-taking the lock
                // let a completion in between raise `move_pending`, and
                // this store then erased an owed move nobody would run.
                g.move_pending = false;
                return false;
            }
            if g.finalizing {
                // An unlock re-run owns the directory; it re-enqueues
                // when it finishes.
                return false;
            }
            (g.nzo_id.clone(), g.out_dir.clone(), g.category.clone())
        };
        // Same fence as recategorize and redrive: deletes and retries
        // stand off while files are in flight.
        if !self.moving.lock_ok().insert(id.clone()) {
            return true; // busy - try again shortly
        }
        struct Fence(Arc<Daemon>, String);
        impl Drop for Fence {
            fn drop(&mut self) {
                self.0.moving.lock_ok().remove(&self.1);
            }
        }
        let _fence = Fence(self.clone(), id);
        // Test-only: a move with visible width, so a test can watch the
        // lanes overlap (and the fleet cap hold) on a machine with one
        // volume, where every real move is an instant rename.
        // The seam's OTHER half: the static is behind `test-support`, so
        // this read has to be too or a caller across the boundary sets a
        // delay nothing honours.
        #[cfg(any(test, feature = "test-support"))]
        {
            let ms = mover::TEST_MOVE_DELAY_MS.load(Ordering::Relaxed);
            if ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        // §296: settle whatever this job already published file by file
        // BEFORE the move walks the directory - `relocate_completed`
        // counts the source to tell a split from a clean failure, and a
        // file that is already at the destination must not be counted,
        // moved, or merged over.
        self.early_reconcile(job);
        let (moved, split, failed) = self.relocate_completed(&out_dir, &cat, None);
        let mut j = job.lock_ok();
        j.move_pending = false;
        j.move_failed = failed.unwrap_or_default();
        j.move_split = match &split {
            Some(src) => src.to_string_lossy().to_string(),
            None => String::new(),
        };
        self.settle_move_attempt(&mut j);
        if let Some(dest) = &moved {
            // §296 sweep S7: reconcile leaves an entry on the record
            // when its destination did not answer, so the retry can
            // settle it - but this attempt's move then SUCCEEDED, so
            // the merge has already resolved any meeting at the
            // destination and there is no retry coming. A record that
            // outlives the move it existed for is stale, and spending
            // it later (a delete's take-back) would unlink files the
            // move now owns. At worst the copies it named survive as
            // visible byte-identical duplicates, which is the safe
            // direction against removing a file that is now the only
            // one.
            if !j.early_published.is_empty() {
                warn!(
                    target: "move",
                    "early: {} unsettled record(s) dropped - the move landed \
                     around them",
                    j.early_published.len()
                );
                j.early_published.clear();
            }
            j.filed = j.tv_sort && is_season_dir(dest);
            j.out_dir = dest.clone();
            drop(j);
            // The modes go on after the payload stops moving (#20),
            // rooted at the destination the files now live under.
            let umask = self.out_umask.load(Ordering::Relaxed);
            if umask <= 0o777 {
                let root = self
                    .move_dest_root(&cat)
                    .map(|(r, _)| r)
                    .unwrap_or_else(|| self.out_root.read_ok().clone());
                crate::smart::apply_out_umask(dest, Some(&root), umask);
            }
        } else {
            drop(j);
        }
        // The record it just rewrote is a HISTORY record (movers run
        // post-park) - its store line has to follow the bytes, and a
        // line the store refuses is the sharpest of these losses:
        // `history_publish_move` says what it costs, after standing the
        // atomic rewrite in for the refused append.
        self.history_publish_move(job, &out_dir, moved.as_deref());
        self.save_queue();
        false
    }

    /// Post-download synthesised naming (films): if the main video is
    /// STILL nameless after every pass above, read its container facts
    /// and ask a film catalogue what it is.
    ///
    /// Returns the note to record on the job - what the file said about
    /// itself and what the catalogues offered - which is written whether
    /// or not the rename happened. That is the point: the common outcome
    /// is a decline, and a decline that tells the user "108 min, h264,
    /// audio en, and here are the eight films it could be" is worth far
    /// more than a silent one.
    ///
    /// Empty string means the ladder did not run at all (toggle off, or
    /// nothing nameless to rename), which is not worth a note.
    pub(super) fn identify_video(
        &self,
        out_dir: &std::path::Path,
        job: &FinalizeJob<'_>,
    ) -> String {
        if !self.rename.identify.load(Ordering::Relaxed) {
            return String::new();
        }
        // Cheapest question first: is there anything to fix? A payload
        // whose video already carries a human's name is left alone, and
        // costs no disk read and no request.
        let Some(video) = crate::smart::nameless_video(out_dir) else {
            return String::new();
        };
        let Some(facts) = nzbkit::media::probe(&video) else {
            return String::new();
        };
        // §193 d: the user's TMDB key, when they configured one. Read
        // per call rather than cached - it is a setting they may add at
        // any time, and this is not a hot path (once per obfuscated job).
        let tmdb = self.tmdb_key.lock_ok().clone();
        let outcome = crate::identify::identify(&facts, job.post_year, tmdb.as_deref());
        let line = outcome.log_line();
        match outcome.accepted_name() {
            Some(title) => {
                // The gate accepted, so the name has been earned by
                // evidence rather than by grammar - which is why this
                // takes the bare apply path rather than
                // `rename_obfuscated_video`'s release-name one.
                if crate::smart::rename_nameless_video(out_dir, &title) {
                    info!(target: "identify", "{} -> {title}", video.display());
                } else {
                    info!(target: "identify", "{line} (but the rename could not be applied)");
                }
            }
            None => info!(target: "identify", "{}: {line}", video.display()),
        }
        let mut note = line;
        for c in &outcome.shortlist {
            note.push('\n');
            note.push_str(c);
        }
        note
    }

    /// Why a move destination could not be reached, when the OS error
    /// on its own reads as something it is not.
    ///
    /// `create_dir_all` reports the failure of the deepest component it
    /// could not create. On macOS an absent network volume makes that
    /// component a child of `/Volumes`, which is owned by root - so the
    /// mkdir is refused for want of PERMISSION and the daemon logs
    /// "Permission denied (os error 13)" for a destination whose real
    /// problem is that nothing is mounted there. That message sent one
    /// investigation after a TCC grant that was never involved (8 Aug
    /// 2026); the filesystem could have said so in one line, so now it
    /// does.
    ///
    /// Only speaks when a component ABOVE the job's own folder is
    /// missing. The leaf being absent is the ordinary case - the mover
    /// creates it - and saying so on every failure would be noise.
    pub fn unreachable_dest_hint(dest: &std::path::Path) -> Option<String> {
        // `ancestors` walks leaf-first, so the last one that does not
        // exist is the SHALLOWEST missing component: the thing whose
        // absence explains all the others.
        let mut missing: Option<&std::path::Path> = None;
        for a in dest.ancestors() {
            if a.exists() {
                break;
            }
            missing = Some(a);
        }
        let missing = missing.filter(|m| *m != dest)?;
        // A mount point is a child of the platform's volume root, and
        // that is the mounted-or-not question rather than an ordinary
        // absent folder.
        let at_volume_root = missing.parent().and_then(|p| p.to_str()).is_some_and(|p| {
            matches!(p, "/Volumes" | "/media" | "/mnt") || p.eq_ignore_ascii_case("/net")
        });
        Some(if at_volume_root {
            format!(
                " - {} does not exist, so that volume is probably not mounted \
                 (its parent belongs to root, which is why an absent volume \
                 reports as a permission error)",
                missing.display()
            )
        } else {
            format!(" - {} does not exist", missing.display())
        })
    }

    /// M33: relocate a finished job to the `move_completed` destination
    /// (a NAS share etc.), keeping the category subfolder and whatever
    /// renaming/Season-filing just produced. Returns the job's final
    /// directory when it changed.
    ///
    /// A failed move is not one outcome but two, and they need opposite
    /// answers. `move_tree` stages the cross-device case, so a NAS that
    /// fills or drops leaves the payload whole where it was; but the
    /// same-filesystem merge moves entry by entry, so a failure there can
    /// leave the job split across both directories. We do not guess which
    /// happened - we count the source before and after. Split reports the
    /// destination, because those bytes exist nowhere else and the
    /// alternative is a job record, a dashboard link and a history storage
    /// path all pointing at a directory the files have left.
    ///
    /// Returns (the job's final directory when it changed, the SOURCE
    /// directory that still holds part of the payload, why nothing
    /// moved). The second is `Some` only for the split case - UX §18:
    /// the split was logged and then thrown away, so history painted the
    /// job green and named exactly one of the two folders it was now in.
    /// The third is `Some` only for the nothing-moved failure, and it
    /// exists for the same reason: the error was logged and then thrown
    /// away, so a completed job whose files never left the download
    /// folder looked exactly like one whose files did (7 Aug 2026 -
    /// five of them, for hours). It feeds [`Job::move_failed`], and
    /// with a destination configured this function now never declines
    /// silently: every outcome is a log line, including "already
    /// there".
    pub fn relocate_completed(
        &self,
        out_dir: &std::path::Path,
        cat: &str,
        renamed: Option<PathBuf>,
    ) -> (Option<PathBuf>, Option<PathBuf>, Option<String>) {
        // A per-category override IS that category's root, so the
        // category component is not repeated inside it - which is what
        // `from_cat` is for below.
        let cur = renamed.clone().unwrap_or_else(|| out_dir.to_path_buf());
        let Some(dest) = self.move_dest_for(&cur, cat) else {
            // The one legitimately silent decline: the feature is off.
            return (renamed, None, None);
        };
        // Byte equality is not path identity. A destination that ALIASES
        // the job's current folder - a case variant on APFS or NTFS, a
        // symlinked parent, a trailing-dot or "." component - compared
        // unequal here, so move_tree ran with dst == src. Its merge path
        // then walked the directory finding every target "occupied" by
        // the source file itself, and reserve_free_name renamed each real
        // file to "Episode (2).mkv". For a TV-filed job `cur` is the
        // SHARED season folder, so the user's already-filed siblings were
        // mangled too, and every later completion compounded it
        // ("Episode (2) (2).mkv"). Nothing is destroyed, but a whole
        // season loses its filenames and its subtitle stem pairings.
        //
        // canonicalize resolves case, symlinks and oddities; it only
        // works on paths that exist, so fall back to the byte compare
        // when either side does not yet.
        let same_place = dest == cur
            || match (dest.canonicalize(), cur.canonicalize()) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            };
        if same_place {
            // Not silent: with a destination configured, "no move
            // happened" and "the move was not owed" have to be
            // distinguishable from the outside. This is the line that
            // was missing while five finished jobs sat in the download
            // folder with nothing anywhere saying why.
            info!(
                target: "move",
                "{} is already inside the completed folder - nothing to move",
                cur.display()
            );
            return (renamed, None, None);
        }
        // One dirent walk of the job's own folder, so a failure can be
        // told apart: nothing moved (the job is still where it was) or
        // some of it did (the job is split, and `cur` is no longer the
        // truth). Counting the DESTINATION instead would not answer it -
        // it merges with what is already there, so a Season folder on a
        // NAS looks non-empty whether our files reached it or not.
        let before = file_count(&cur);
        // Paced: the mover must never slow a live download (mode
        // "yield", the default), and the pacer reads the mode live so
        // a settings change lands within one chunk. The bucket behind
        // it is the daemon's, shared by every lane copying right now.
        let pace = mover::mover_pacer(self);
        match crate::smart::move_tree_paced(&cur, &dest, Some(&pace)) {
            Ok(()) => {
                info!(target: "move", "completed → {}", dest.display());
                (Some(dest), None, None)
            }
            Err(e) => {
                // NOT the flat "leaving files in place" this used to say.
                // The staged cross-device path usually does leave the
                // payload whole, but the same-filesystem merge can stop
                // half way through, and that message sent the user looking
                // in exactly one of the two directories the job was now in.
                // Say which case this was rather than assuming either.
                let moved_some = file_count(&cur) < before;
                // Composed once and carried into BOTH the log line and
                // the job record: the record outlives the ring, and it
                // is the one the dashboard shows.
                let hint = Self::unreachable_dest_hint(&dest).unwrap_or_default();
                error!(
                    target: "move",
                    "{} → {}: {e}{hint}\n\
                     [move] {}",
                    cur.display(),
                    dest.display(),
                    if moved_some {
                        format!(
                            "the payload is now SPLIT - some files moved before this failed. \
                             Check both {} and {} before deleting either.",
                            cur.display(),
                            dest.display()
                        )
                    } else {
                        format!("nothing moved - the download is still at {}", cur.display())
                    }
                );
                // Report where the payload now is. The files that moved
                // exist nowhere else, so keeping the old directory on the
                // job record would send the dashboard, a later delete and
                // the *arr import at a folder they have left.
                // The source travels back beside it so the record can
                // say the payload is in TWO places - the log line above
                // is the only other witness, and it rolls out of the ring.
                if moved_some {
                    (Some(dest), Some(cur), None)
                } else {
                    // Destination + error, composed here because only
                    // this moment has both. It becomes Job::move_failed:
                    // the amber row, the drawer line and the auto-retry
                    // all hang off it.
                    (
                        renamed,
                        None,
                        Some(format!("{}: {e}{hint}", dest.display())),
                    )
                }
            }
        }
    }
}
