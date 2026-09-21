//! Durable exact-membership seeds from NZBs this daemon already accepted.
//!
//! Enqueue owns latency and this lane owns evidence. The add path writes an
//! atomic spool copy, publishes a queue or history record, and sends one
//! coalescible wake. This worker later snapshots a bounded number of those
//! records, releases every job lock, verifies and parses the saved bytes, and
//! stores the file-aware seed. Deleted history rows are excluded until an
//! explicit retry clears their delete status. A restart performs the same
//! scan, so a busy or stopped worker never turns into lost evidence.

use super::*;
use std::collections::{HashSet, VecDeque};
use std::io::Read as _;

const SOURCE: &str = "nzb-add";
pub const INDEXER_SOURCE: &str = "nzb-indexer";
const INSPECT_PER_PASS: usize = 64;
/// Parse one manifest at a time. A legal NZB can itself retain tens of MiB
/// of segment metadata; batching parsed manifests multiplies that bound.
const PROCESS_PER_PASS: usize = 1;
const NEWEST_HINTS: usize = 4;
const PENDING_CAP: usize = 128;
const SEEN_CAP: usize = 16_384;
// One exact set per commit keeps the foreground pass-gate hold bounded. The
// 250 ms continuation loop still advances four sets per second while idle.
const REPLAY_PER_PASS: usize = 1;
const REPAIR_SECS: u64 = 60;
const CONTINUE_DELAY_MS: u64 = 250;
/// The download keeps accepting the API's larger body ceiling; identity
/// capture is optional background work and declines an unusually large
/// manifest rather than adding another 256 MiB allocation beside the parser.
/// Read with `take(cap + 1)` as well as metadata so post-stat growth is capped.
const RAW_NZB_CAP: u64 = 128 << 20;
/// The indexer inbox - the staging directory an indexer writes into and
/// the pass that drains it. Out of this file for the size gate's
/// 4,000-line ceiling; re-exported so callers keep their paths.
mod inbox;
use inbox::{IndexerInboxError, tick_indexer_inbox};
// These two are PRODUCTION, under the `indexer` feature: `tick_with_gate`
// drains the inbox and quarantines an item whose fingerprint moved. The
// gate must name the feature and not just `test` - `cargo build
// -p nzbfast-daemon` alone has `indexer` OFF and says nothing, while the
// documented clippy line has `test-support` ON and covers for it. The
// build that sees this is `indexer` on, `test-support` off, which is what
// `cargo build -p nzbfast` is.
#[cfg(any(test, feature = "test-support", feature = "indexer"))]
use inbox::{hold_invalid_indexer_inbox_if_unchanged, next_indexer_inbox};
// The rest of the inbox's surface is this file's own `mod tests` reaching
// past it on purpose: the directory protocol, the capacity accounting and
// the hold moves are all exercised directly. Gated, so the PRODUCTION
// surface of `inbox` stays the four items re-exported below plus the
// error type.
#[cfg(test)]
use inbox::{
    INDEXER_INBOX_ARTIFACT_CAP, INDEXER_INBOX_IO, INDEXER_ORPHAN_GRACE_SECS, IndexerInboxUsage,
    ensure_indexer_inbox_dir, hold_indexer_inbox, indexer_inbox_dir, indexer_inbox_entries_locked,
    indexer_inbox_fingerprint, indexer_inbox_has_room, indexer_inbox_paths,
    lock_indexer_inbox_process, remove_indexer_inbox,
};
pub use inbox::{
    IndexerInboxRoom, indexer_inbox_room, reactivate_indexer_generation_holds, stage_indexer_seed,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeedKey {
    sha: String,
    name: String,
    path: PathBuf,
}

#[derive(Clone)]
pub struct Candidate {
    record: Arc<Mutex<Job>>,
    nzo_id: String,
    name: String,
    category: String,
    expected_sha: String,
    path: PathBuf,
    generation: (u32, u64),
}

impl Candidate {
    pub fn key(&self) -> SeedKey {
        SeedKey {
            sha: self.expected_sha.clone(),
            name: self.name.clone(),
            path: self.path.clone(),
        }
    }

    pub fn from_job(record: &Arc<Mutex<Job>>) -> Option<Self> {
        let job = record.lock_ok();
        (!job.tombstone
            && job.delete_status.is_empty()
            && job.relocating == 0
            && !job.nzb_path.as_os_str().is_empty())
        .then(|| Self {
            record: record.clone(),
            nzo_id: job.nzo_id.clone(),
            name: job.name.clone(),
            category: job.category.clone(),
            expected_sha: job.nzb_sha.clone(),
            path: job.nzb_path.clone(),
            generation: Daemon::record_generation(&job),
        })
    }
}

pub struct Prepared {
    candidate: Candidate,
    guid: String,
    posted: i64,
    bytes: u64,
    seed: nzbkit::index::NzbSeedPrepared,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HarvestReport {
    pub inspected: usize,
    pub stored: usize,
    pub already_stored: usize,
    pub invalid: usize,
    pub missing: usize,
    pub withdrawn: usize,
    pub deferred: usize,
    pub named: usize,
    pub pending: usize,
    blocked: bool,
    replay_cycle_complete: bool,
    /// Why this pass never reached the durable replay, for the
    /// rate-limited stall line in [`spawn`]. Every early return on the
    /// way to that call is otherwise silent, and on 2 Sep 2026 that
    /// silence hid a 91-minute stall across three restarts and two
    /// installs: 343 sets pending, the cursor byte-identical at set
    /// 328, and `grep -c '[seed]'` zero in both log files. A lane that
    /// can starve indefinitely has to be able to say it is starving -
    /// research/SEED-REPLAY-STARVATION-2026-09-02.md.
    stalled_at: Option<&'static str>,
}

impl HarvestReport {
    fn retry_later(&self) -> bool {
        self.blocked
    }
}

pub struct HarvestState {
    era: u64,
    queue_cursor: usize,
    history_cursor: usize,
    queue_done: bool,
    history_done: bool,
    pending: VecDeque<Candidate>,
    seen: HashSet<SeedKey>,
    seen_order: VecDeque<SeedKey>,
}

impl HarvestState {
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(era: u64) -> Self {
        Self::for_era(era)
    }

    fn for_era(era: u64) -> Self {
        Self {
            era,
            queue_cursor: 0,
            history_cursor: 0,
            queue_done: false,
            history_done: false,
            pending: VecDeque::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        }
    }

    fn reset_era(&mut self, era: u64) {
        if self.era != era {
            *self = Self::for_era(era);
        }
    }

    fn begin_sweep(&mut self) {
        self.queue_done = false;
        self.history_done = false;
    }

    fn sweep_done(&self) -> bool {
        self.queue_done && self.history_done && self.pending.is_empty()
    }

    fn mark_seen(&mut self, key: SeedKey) {
        if !self.seen.insert(key.clone()) {
            return;
        }
        self.seen_order.push_back(key);
        if self.seen_order.len() > SEEN_CAP
            && let Some(oldest) = self.seen_order.pop_front()
        {
            self.seen.remove(&oldest);
        }
    }

    fn queue_candidate(&mut self, candidate: Candidate) -> bool {
        let key = candidate.key();
        if self.seen.contains(&key) || self.pending.iter().any(|old| old.key() == key) {
            return false;
        }
        if self.pending.len() >= PENDING_CAP {
            return false;
        }
        self.pending.push_back(candidate);
        true
    }
}

/// Select newest rows first, then move a fair cursor through the collection.
/// The boolean says this selection crossed the cursor's end and completed the
/// current sweep of that store.
fn selected_indices(len: usize, cursor: &mut usize, quota: usize) -> (Vec<usize>, bool) {
    if len == 0 || quota == 0 {
        return (Vec::new(), len == 0);
    }
    let mut out = Vec::with_capacity(quota.min(len));
    for index in (len.saturating_sub(NEWEST_HINTS)..len).rev() {
        if out.len() == quota {
            break;
        }
        out.push(index);
    }
    let start = *cursor % len;
    let mut walked = 0usize;
    while walked < len && out.len() < quota {
        let index = (start + walked) % len;
        if !out.contains(&index) {
            out.push(index);
        }
        walked += 1;
    }
    *cursor = (start + walked) % len;
    (out, walked == len || start + walked >= len)
}

fn snapshot_candidates(d: &Arc<Daemon>, state: &mut HarvestState) -> (Vec<Candidate>, usize) {
    // Never advance a durable cursor across rows that cannot all fit. The
    // pending queue is drained to a full-pass reserve first; otherwise one
    // free slot could admit the first row in a 64-row window and silently
    // skip a valid row later in that same window on every sweep.
    if state.pending.len() > PENDING_CAP.saturating_sub(INSPECT_PER_PASS + PROCESS_PER_PASS) {
        return (Vec::new(), 0);
    }
    let half = INSPECT_PER_PASS / 2;
    let queue_jobs = if state.queue_done {
        Vec::new()
    } else {
        let queue = d.queue.lock_ok();
        let (indices, done) = selected_indices(queue.len(), &mut state.queue_cursor, half);
        state.queue_done = done;
        indices
            .into_iter()
            .filter_map(|index| queue.get(index).cloned())
            .collect()
    };
    let history_quota = INSPECT_PER_PASS.saturating_sub(queue_jobs.len());
    let history_jobs = if state.history_done {
        Vec::new()
    } else {
        let history = d.history.lock_ok();
        let (indices, done) =
            selected_indices(history.len(), &mut state.history_cursor, history_quota);
        state.history_done = done;
        indices
            .into_iter()
            .filter_map(|index| history.get(index).cloned())
            .collect()
    };
    let inspected = queue_jobs.len() + history_jobs.len();
    let candidates = queue_jobs
        .into_iter()
        .chain(history_jobs)
        .filter_map(|job| Candidate::from_job(&job))
        .collect();
    (candidates, inspected)
}

#[derive(Debug)]
pub enum PrepareError {
    Missing,
    Invalid,
    Transient,
}

pub fn prepare(candidate: &Candidate) -> Result<Prepared, PrepareError> {
    let file = std::fs::File::open(&candidate.path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PrepareError::Missing
        } else {
            PrepareError::Transient
        }
    })?;
    let size = file.metadata().map_err(|_| PrepareError::Transient)?.len();
    if size > RAW_NZB_CAP {
        return Err(PrepareError::Invalid);
    }
    let initial = usize::try_from(size.min(8 << 20)).unwrap_or(0);
    let mut raw = Vec::with_capacity(initial);
    file.take(RAW_NZB_CAP + 1)
        .read_to_end(&mut raw)
        .map_err(|_| PrepareError::Transient)?;
    if raw.len() as u64 > RAW_NZB_CAP {
        return Err(PrepareError::Invalid);
    }
    let guid = nzb_sha(&raw);
    if !candidate.expected_sha.is_empty() && candidate.expected_sha != guid {
        return Err(PrepareError::Invalid);
    }
    let nzb = nzbkit::nzb::Nzb::parse(&raw).map_err(|_| PrepareError::Invalid)?;
    drop(raw);
    let posted = nzb
        .files
        .iter()
        .map(|file| file.date)
        .filter(|date| *date > 0)
        .min()
        .unwrap_or(0);
    let bytes = nzb.total_bytes();
    let seed = nzbkit::index::NzbSeedPrepared::from_nzb(&nzb).map_err(|error| {
        if terminal_seed_error(&error) {
            PrepareError::Invalid
        } else {
            PrepareError::Transient
        }
    })?;
    Ok(Prepared {
        candidate: candidate.clone(),
        guid,
        posted,
        bytes,
        seed,
    })
}

fn candidate_matches(job: &Job, candidate: &Candidate) -> bool {
    !job.tombstone
        && job.delete_status.is_empty()
        && job.relocating == 0
        && job.nzo_id == candidate.nzo_id
        && job.name == candidate.name
        && job.category == candidate.category
        && job.nzb_sha == candidate.expected_sha
        && job.nzb_path == candidate.path
        && Daemon::record_generation(job) == candidate.generation
}

/// Re-check membership and fields under the established collection -> job
/// lock order. History deletion removes the Arc before it stamps tombstone,
/// so cloning a lookup result and checking it later is not a valid fence.
fn still_retained(d: &Arc<Daemon>, candidate: &Candidate) -> bool {
    {
        let queue = d.queue.lock_ok();
        if let Some(record) = queue
            .iter()
            .find(|record| Arc::ptr_eq(record, &candidate.record))
        {
            return candidate_matches(&record.lock_ok(), candidate);
        }
    }
    let history = d.history.lock_ok();
    history
        .iter()
        .find(|record| Arc::ptr_eq(record, &candidate.record))
        .is_some_and(|record| candidate_matches(&record.lock_ok(), candidate))
}

enum Retained<T> {
    Current(T),
    Withdrawn,
    Busy,
}

#[derive(Clone, Copy)]
enum CommitVerdict {
    Current,
    Withdrawn,
    Busy,
}

/// Acquire the exact catalog record at the transaction boundary. This runs
/// after winning the index mutex, so every inverse lock edge is a try-lock:
/// contention defers but can never deadlock. The returned job guard is held
/// only through SQLite SAVEPOINT release, not through manifest work or row
/// insertion.
fn try_retained_guard<'a>(
    d: &Arc<Daemon>,
    candidate: &'a Candidate,
) -> Retained<std::sync::MutexGuard<'a, Job>> {
    let moving = match d.moving.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return Retained::Busy,
    };
    if moving.contains(&candidate.nzo_id) {
        return Retained::Busy;
    }
    drop(moving);
    let hist_inflight = match d.hist_inflight.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return Retained::Busy,
    };
    if hist_inflight.contains(&candidate.nzo_id) {
        return Retained::Busy;
    }
    drop(hist_inflight);

    let queue = match d.queue.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return Retained::Busy,
    };
    if queue
        .iter()
        .any(|record| Arc::ptr_eq(record, &candidate.record))
    {
        let job = match candidate.record.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Retained::Busy,
        };
        if job.relocating > 0 {
            return Retained::Busy;
        }
        if !candidate_matches(&job, candidate) {
            return Retained::Withdrawn;
        }
        drop(queue);
        return Retained::Current(job);
    }
    drop(queue);

    let history = match d.history.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return Retained::Busy,
    };
    let retained = history
        .iter()
        .any(|record| Arc::ptr_eq(record, &candidate.record));
    if !retained {
        return Retained::Withdrawn;
    }
    let job = match candidate.record.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return Retained::Busy,
    };
    if job.relocating > 0 {
        return Retained::Busy;
    }
    if !candidate_matches(&job, candidate) {
        return Retained::Withdrawn;
    }
    drop(history);
    Retained::Current(job)
}

fn terminal_seed_error(error: &nzbkit::index::NzbSeedError) -> bool {
    matches!(
        error,
        nzbkit::index::NzbSeedError::Invalid(_) | nzbkit::index::NzbSeedError::Nzb(_)
    )
}

/// One bounded synchronous pass. Tests drive this directly; the task wrapper
/// below only supplies wake, periodic repair, and a blocking thread.
#[cfg(any(test, feature = "test-support"))]
pub fn tick(d: &Arc<Daemon>, state: &mut HarvestState) -> HarvestReport {
    tick_with_gate(d, state, None)
}

/// What a pass that `db_maintenance_ok` declined tells the stall clock.
/// `None` when the index is not wanted at all - the indexer and Spotnet
/// both off, or the daemon exiting - because then the durable replay is
/// not OWED and a lane that is not owed work is not starving. Until
/// 20 Sep 2026 this arm said "index maintenance is closed" too, and
/// the ten-minute stall line in [`spawn`] repeated for the life of
/// every daemon whose owner had simply left the indexer off (reported
/// on Reddit as a WARN every ten minutes with no setting to explain
/// it). The transient closures - paused, offline, a download running
/// under pause-on-download - still name the gate, because those are
/// the states where the replay IS owed and the 2 Sep 2026 stall could
/// hide again.
fn maintenance_stall(d: &Daemon) -> Option<&'static str> {
    if d.index_db_wanted() {
        Some("index maintenance is closed")
    } else {
        None
    }
}

pub fn tick_with_gate(
    d: &Arc<Daemon>,
    state: &mut HarvestState,
    index_pass_gate: Option<&tokio::sync::Mutex<()>>,
) -> HarvestReport {
    let mut report = HarvestReport::default();
    state.reset_era(d.index_era());
    if !d.db_maintenance_ok() {
        report.deferred = state.pending.len().max(1);
        report.pending = state.pending.len();
        report.blocked = true;
        report.stalled_at = maintenance_stall(d);
        return report;
    }

    // Paid commercial evidence has no queue/history record to rediscover, so
    // drain its committed inbox marker first. One item per pass preserves the
    // same parse and writer bounds as accepted-NZB capture.
    match next_indexer_inbox(d) {
        Ok(Some(item)) => {
            report.inspected = 1;
            tick_indexer_inbox(d, index_pass_gate, item, &mut report);
            report.pending = state.pending.len();
            // The inbox drain returns before the replay call at the
            // bottom. One item per pass is the intended bound, but a
            // permanently non-empty inbox would starve the replay just
            // as completely as a held gate, so it is named too.
            report.stalled_at = Some("a commercial NZB inbox item took the pass");
            return report;
        }
        Err(IndexerInboxError::Invalid {
            meta_path,
            fingerprint,
        }) => {
            report.inspected = 1;
            // Validation already established that the live candidate is
            // invalid. A failed conditional move also reports deferred and
            // blocked, but must not erase that observed disposition.
            report.invalid = 1;
            match hold_invalid_indexer_inbox_if_unchanged(&meta_path, fingerprint.as_deref()) {
                Ok(Some(hold_path)) => {
                    warn!(
                    target: "seed",
                    "quarantined one invalid commercial NZB seed inbox item at {}",
                    hold_path.display()
                    );
                }
                Ok(None) => {
                    report.deferred = 1;
                    report.blocked = true;
                    warn!(
                        target: "seed",
                        "commercial NZB seed changed during validation; retrying the live marker"
                    );
                }
                Err(error) => {
                    report.deferred = 1;
                    report.blocked = true;
                    warn!(target: "seed", "invalid commercial NZB seed quarantine deferred: {error}");
                }
            }
            report.pending = state.pending.len();
            // Same reason as the drained-item arm above: a marker that
            // cannot be quarantined is retried every pass, and every one
            // of those passes returns before the replay.
            report.stalled_at = Some("an invalid commercial NZB inbox item took the pass");
            return report;
        }
        Err(IndexerInboxError::Transient) => {
            report.deferred = 1;
            report.blocked = true;
            report.pending = state.pending.len();
            report.stalled_at = Some("the commercial NZB inbox could not be read");
            return report;
        }
        Ok(None) => {}
    }

    // Reserve processing capacity before scanning. Otherwise a full retry
    // queue can prevent the durable queue/history cursors from ever reaching
    // a newer valid record. The in-flight key is excluded from this scan so a
    // newest-hint failure cannot immediately occupy its own freed slot.
    let mut batch = Vec::new();
    if let Some(candidate) = state.pending.pop_front()
        && !state.seen.contains(&candidate.key())
    {
        batch.push(candidate);
    }
    let in_flight = batch.first().map(Candidate::key);
    let (candidates, inspected) = snapshot_candidates(d, state);
    report.inspected = inspected;
    for candidate in candidates {
        if in_flight.as_ref() != Some(&candidate.key()) {
            state.queue_candidate(candidate);
        }
    }

    if batch.is_empty() {
        for _ in 0..PROCESS_PER_PASS {
            let Some(candidate) = state.pending.pop_front() else {
                break;
            };
            if !state.seen.contains(&candidate.key()) {
                batch.push(candidate);
            }
        }
    }

    let known = d.try_with_index(|index| {
        Some(
            batch
                .iter()
                .map(|candidate| {
                    if candidate.expected_sha.is_empty() {
                        Ok(false)
                    } else {
                        index.nzb_seed_strong_assertion_exists(
                            SOURCE,
                            &candidate.expected_sha,
                            &candidate.name,
                        )
                    }
                })
                .collect::<Vec<_>>(),
        )
    });
    let Some(known) = known else {
        report.deferred += batch.len().max(1);
        report.blocked = true;
        report.stalled_at = Some("the index reader was busy");
        for candidate in batch {
            state.queue_candidate(candidate);
        }
        report.pending = state.pending.len();
        return report;
    };

    let mut prepared = Vec::new();
    for (candidate, known) in batch.into_iter().zip(known) {
        match known {
            Ok(true) => {
                report.already_stored += 1;
                state.mark_seen(candidate.key());
            }
            Err(error) if terminal_seed_error(&error) => {
                report.invalid += 1;
                state.mark_seen(candidate.key());
            }
            Err(_) => {
                report.deferred += 1;
                report.blocked = true;
                state.queue_candidate(candidate);
            }
            Ok(false) => match prepare(&candidate) {
                Ok(item) => prepared.push(item),
                Err(PrepareError::Missing) => {
                    report.missing += 1;
                    if still_retained(d, &candidate) {
                        report.deferred += 1;
                    } else {
                        report.withdrawn += 1;
                    }
                }
                Err(PrepareError::Invalid) => {
                    report.invalid += 1;
                    // The immutable spool content or its persisted digest is
                    // bad. Do not log or retry it every minute in this era.
                    // A re-add has a different spool path and remains eligible.
                    state.mark_seen(candidate.key());
                }
                Err(PrepareError::Transient) => {
                    report.deferred += 1;
                }
            },
        }
    }

    let mut active = Vec::new();
    for item in prepared {
        if still_retained(d, &item.candidate) {
            active.push(item);
        } else {
            report.withdrawn += 1;
        }
    }

    // Parsing is deliberately outside the pass gate. Commit is optional
    // background work: if a scanner, compactor, or starting download owns
    // the rendezvous, retain only the compact catalog candidate and yield.
    let _index_pass = if let Some(gate) = index_pass_gate {
        match gate.try_lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                report.deferred += active.len().max(1);
                report.blocked = true;
                // The 2 Sep 2026 stall was here, every pass for 91
                // minutes: the scan lap holds this gate for the whole
                // of its work, and its work had grown past the restart
                // cadence, so the inter-lap window the lane used to run
                // in stopped happening. The reserved slice in
                // `maintenance_slice` is the fix; this line is how the
                // next one gets noticed in minutes rather than by a
                // hand query against the live index.
                report.stalled_at = Some("the index pass gate is held by a scan lap");
                for item in active {
                    state.queue_candidate(item.candidate);
                }
                report.pending = state.pending.len();
                return report;
            }
        }
    } else {
        None
    };
    if !d.db_maintenance_ok() {
        report.deferred += active.len().max(1);
        report.blocked = true;
        report.stalled_at = maintenance_stall(d);
        for item in active {
            state.queue_candidate(item.candidate);
        }
        report.pending = state.pending.len();
        return report;
    }

    let now = epoch_secs() as i64;
    let commit_era = state.era;
    let stored = d.try_with_index_mut_retiring_ddl(|index| {
        let stores = active
            .iter()
            .map(|item| {
                let verdict = std::cell::Cell::new(CommitVerdict::Busy);
                let result = index.nzb_seed_store_prepared_guarded(
                    nzbkit::index::NzbSeedSpec {
                        source: SOURCE,
                        source_guid: &item.guid,
                        name: &item.candidate.name,
                        category: &item.candidate.category,
                        posted: item.posted,
                        bytes: item.bytes,
                    },
                    &item.seed,
                    now,
                    || {
                        if d.index_era() != commit_era
                            || d.index_jobs_active.load(Ordering::Acquire) > 0
                            || d.offline.load(Ordering::Relaxed)
                            || d.index_paused.load(Ordering::Relaxed)
                            || !d.index_db_wanted()
                        {
                            return None;
                        }
                        match try_retained_guard(d, &item.candidate) {
                            Retained::Current(guard) => {
                                verdict.set(CommitVerdict::Current);
                                Some(guard)
                            }
                            Retained::Withdrawn => {
                                verdict.set(CommitVerdict::Withdrawn);
                                None
                            }
                            Retained::Busy => None,
                        }
                    },
                );
                match result {
                    Ok(Some(stored)) => Retained::Current(Ok(stored)),
                    Ok(None) => match verdict.get() {
                        CommitVerdict::Current => {
                            unreachable!("commit guard accepted without commit")
                        }
                        CommitVerdict::Withdrawn => Retained::Withdrawn,
                        CommitVerdict::Busy => Retained::Busy,
                    },
                    Err(error) => Retained::Current(Err(error)),
                }
            })
            .collect::<Vec<_>>();
        let replay = if d.index_jobs_active.load(Ordering::Acquire) == 0 {
            index.nzb_seed_reconcile_guarded(now, REPLAY_PER_PASS, || {
                d.index_era() == commit_era
                    && d.index_jobs_active.load(Ordering::Acquire) == 0
                    && !d.offline.load(Ordering::Relaxed)
                    && !d.index_paused.load(Ordering::Relaxed)
                    && d.index_db_wanted()
            })
        } else {
            Ok(None)
        };
        Some((stores, replay))
    });
    let Some((stores, replay)) = stored else {
        report.deferred += active.len().max(1);
        report.blocked = true;
        report.stalled_at = Some("the index writer was busy");
        for item in active {
            state.queue_candidate(item.candidate);
        }
        report.pending = state.pending.len();
        return report;
    };

    for (item, outcome) in active.into_iter().zip(stores) {
        match outcome {
            Retained::Current(Ok(_)) => {
                report.stored += 1;
                state.mark_seen(item.candidate.key());
            }
            Retained::Current(Err(error)) if terminal_seed_error(&error) => {
                report.invalid += 1;
                state.mark_seen(item.candidate.key());
            }
            Retained::Current(Err(_)) | Retained::Busy => {
                report.deferred += 1;
                report.blocked = true;
                state.queue_candidate(item.candidate);
            }
            Retained::Withdrawn => report.withdrawn += 1,
        }
    }
    match replay {
        Ok(Some(stats)) => {
            report.replay_cycle_complete = stats.cycle_wrapped;
            report.named = stats.claims_applied + stats.claims_replaced;
            if report.named > 0 {
                info!(
                    target: "seed",
                    "exact NZB seed replay named {} release(s) from {} set(s)",
                    report.named,
                    stats.sets_examined
                );
            }
            if stats.sets_errored > 0 {
                warn!(
                    target: "seed",
                    "exact NZB seed replay quarantined {} corrupt set(s)",
                    stats.sets_errored
                );
            }
        }
        Ok(None) => {
            report.deferred += 1;
            report.blocked = true;
            report.stalled_at = Some("the replay guard yielded to foreground work");
        }
        Err(error) => {
            report.deferred += 1;
            report.blocked = true;
            report.stalled_at = Some("the replay write failed");
            warn!(target: "seed", "exact NZB seed replay deferred: {error}");
        }
    }
    if report.stored > 0 {
        info!(
            target: "seed",
            "saved {} accepted NZB seed assertion(s)",
            report.stored
        );
    }
    if report.invalid > 0 {
        warn!(
            target: "seed",
            "refused {} invalid accepted NZB seed candidate(s)",
            report.invalid
        );
    }
    report.pending = state.pending.len();
    report
}

pub fn spawn(daemon: &Arc<Daemon>, index_pass_gate: &Arc<tokio::sync::Mutex<()>>) {
    let daemon = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    tokio::spawn(async move {
        let mut state = HarvestState::for_era(daemon.index_era());
        state.begin_sweep();
        let mut run_now = true;
        // How long the durable replay may stay unreachable before this
        // lane says so, and how often it repeats while it stays that
        // way. Ten minutes, not one pass: the gates below decline for
        // correct and usually brief reasons (a download is running, a
        // scan lap owns the pass gate), and at the 60 s repair cadence
        // a line per blocked pass would be a line a minute of noise
        // that nobody would read - which is the same as silence. Ten
        // minutes is short enough that the 2 Sep 2026 stall would have
        // been in the log nine times before the first person looked,
        // and long enough that an ordinary busy hour says nothing.
        const STALL_SAY_SECS: u64 = 600;
        // Start of the current run of passes that never reached the
        // replay, and how many lines this run has already said.
        let mut stalled: Option<(std::time::Instant, u64)> = None;
        loop {
            if !run_now {
                tokio::select! {
                    _ = daemon.seed_harvest_wake.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(REPAIR_SECS)) => {}
                }
                state.begin_sweep();
            }
            let daemon2 = daemon.clone();
            let index_pass_gate2 = index_pass_gate.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let mut state = state;
                let report = tick_with_gate(&daemon2, &mut state, Some(&index_pass_gate2));
                (state, report)
            })
            .await;
            let Ok((next, report)) = outcome else {
                state = HarvestState::for_era(daemon.index_era());
                run_now = false;
                continue;
            };
            state = next;
            match report.stalled_at {
                Some(gate) => {
                    let (since, said) = stalled.get_or_insert((std::time::Instant::now(), 0));
                    let held = since.elapsed().as_secs();
                    if held >= STALL_SAY_SECS.saturating_mul(*said + 1) {
                        *said += 1;
                        warn!(
                            target: "seed",
                            "exact NZB seed replay has not run for {} min - {gate}",
                            held / 60
                        );
                    }
                }
                // The replay was reached. Whatever it decided, the lane
                // is not starving, so the next run starts its own clock.
                None => stalled = None,
            }
            run_now =
                !report.retry_later() && (!state.sweep_done() || !report.replay_cycle_complete);
            if run_now {
                tokio::time::sleep(std::time::Duration::from_millis(CONTINUE_DELAY_MS)).await;
            }
        }
    });
}

// The reconcile ENGINE the indexer lap and this module's own
// opportunistic call both run, moved here from
// `tasks/indexer/passes.rs` by lane 2 of the serve split. It
// takes a `&Arc<Daemon>` and one index transaction and owns no lane
// state, so it belongs under both callers rather than inside one of
// them - lane 1b's ENGINE DOWN, LANE UP rule.
/// Sets the durable seed replay walks in one slice of
/// [`seed_replay_pass`]. Four, not the harvest's one and not the folds'
/// time budget, because this call holds the index write mutex for its
/// whole duration and `nzb_seed_reconcile_guarded` takes a COUNT, not a
/// deadline: a low count is the only bound available. See the sizing
/// note in `maintenance_slice`.
const SEED_REPLAY_SETS_PER_SLICE: usize = 4;

/// One budgeted slice of the durable seed replay per lap: walk the
/// saved-NZB cursor far enough that a set which can name a local
/// release gets to, without ever holding the index write mutex for
/// longer than the lane's own background task already does.
///
/// Here, and not only in `seed_harvest.rs`, because that task
/// reaches the replay ONLY through `index_pass_gate.try_lock()` - and
/// the scan lap holds that gate for the whole of its work. That was
/// cheap while a lap was ~9 minutes of work followed by a 900 s sleep:
/// the harvest simply ran in the sleep. Measured 2 Sep 2026 on the live
/// 122 GB index, lap WORK had grown to 2,539-2,760 s and was no longer
/// completing at all between the deploy lane's restarts, so there was no
/// inter-lap sleep to run in. The harvest's last reconcile was
/// 15:24:20Z, the tail of the last window there has been; the durable
/// cursor then sat byte-identical at set 328 across three restarts and
/// two installs, with 343 sets pending, 12,926 reconciles unchanged, and
/// not one line of log to say so, because every early return on that
/// path is silent. Write-up, measurement and the stated limits:
/// research/SEED-REPLAY-STARVATION-2026-09-02.md.
///
/// So the lap INVITES the replay in, exactly as it did for the folds
/// after research/SHATTER-FOLD-STARVATION-2026-09-01.md, rather than
/// leaving a background lane to win a gate this loop is itself holding.
/// The harvest keeps its own opportunistic call: that one reacts to a
/// newly captured NZB within seconds, and this is the floor under it,
/// never a replacement.
///
/// After the folds, for the same reason the album fold follows the
/// session fold: an exact seed hit needs COMPLETE local file rows whose
/// full manifest matches, and a row a fold has just made whole is
/// precisely the row this scan wants next.
///
/// Returns true when the caller's slice loop should stop - the cursor
/// wrapped a whole cycle, the guard asked the lane to yield, or the
/// write failed.
#[cfg(feature = "indexer")]
pub fn seed_replay_pass(daemon2: &Arc<Daemon>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let era = daemon2.index_era();
    let started = std::time::Instant::now();
    let Some(outcome) = daemon2.with_index_mut_retiring_ddl(|ix| {
        Some(ix.nzb_seed_reconcile_guarded(
            now,
            SEED_REPLAY_SETS_PER_SLICE,
            // The same five conditions the harvest's own guard asks, so
            // a set half-scanned here rolls back and retries under
            // whichever lane gets there first. `index_jobs_active` is
            // the load-bearing one and is deliberately NOT widened: the
            // replay must never compete with a live download.
            || {
                daemon2.index_era() == era
                    && daemon2.index_jobs_active.load(Ordering::Acquire) == 0
                    && !daemon2.offline.load(Ordering::Relaxed)
                    && !daemon2.index_paused.load(Ordering::Relaxed)
                    && daemon2.index_db_wanted()
            },
        ))
    }) else {
        return true;
    };
    match outcome {
        Ok(Some(stats)) => {
            let named = stats.claims_applied + stats.claims_replaced;
            if named > 0 {
                info!(
                    target: "seed",
                    "seed replay slice named {named} release(s) from {} set(s) in {:.1?}",
                    stats.sets_examined,
                    started.elapsed()
                );
            }
            if stats.sets_errored > 0 {
                warn!(
                    target: "seed",
                    "seed replay slice quarantined {} corrupt set(s)",
                    stats.sets_errored
                );
            }
            stats.cycle_wrapped
        }
        // The guard declined. Standing down is correct and says nothing
        // about the backlog, so stop this lap's loop and leave the
        // cursor exactly where it was.
        Ok(None) => true,
        Err(e) => {
            // An error here must be SAID: a silent Err on a cursor that
            // never advances is the whole defect this pass exists to
            // end, and it would look exactly like "nothing to do".
            warn!(target: "seed", "seed replay slice error: {e}");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn with_daemon(name: &str, test: impl FnOnce(&Arc<Daemon>)) {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-seed-harvest-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create seed-harvest scratch");
        let daemon = crate::testutil::test_daemon(&dir);
        test(&daemon);
        drop(daemon);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn file_xml(subject: &str, ids: &[&str], date: i64) -> String {
        let segments: String = ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                format!(
                    r#"<segment bytes="1000" number="{}">{id}</segment>"#,
                    index + 1
                )
            })
            .collect();
        format!(
            r#"<file poster="p" date="{date}" subject="&quot;{subject}&quot; yEnc (1/{})"><groups><group>a.b.dark</group></groups><segments>{segments}</segments></file>"#,
            ids.len()
        )
    }

    pub fn nzb(files: &[(&str, &[&str])]) -> Vec<u8> {
        let files: String = files
            .iter()
            .enumerate()
            .map(|(index, (subject, ids))| file_xml(subject, ids, 1_700_000_000 + index as i64))
            .collect();
        format!(r#"<?xml version="1.0"?><nzb>{files}</nzb>"#).into_bytes()
    }

    pub fn add(d: &Arc<Daemon>, bytes: &[u8], name: &str) -> String {
        d.enqueue(bytes, name, "tv", -100, None, None, "test", true)
            .expect("enqueue seed fixture")
            .nzo_id
    }

    pub fn inventory(d: &Arc<Daemon>) -> nzbkit::index::NzbSeedInventory {
        d.with_index(|index| Some(index.nzb_seed_inventory().unwrap()))
            .expect("seed inventory")
    }

    fn settle_seed_names(d: &Arc<Daemon>) -> nzbkit::index::NzbSeedReplayStats {
        d.with_index_mut_retiring_ddl(|index| {
            index
                .nzb_seed_reconcile(epoch_secs() as i64 + 3_600, 64)
                .ok()
        })
        .expect("settle exact seed names after the quiet window")
    }

    pub fn enable_index(d: &Arc<Daemon>) {
        d.index_enabled.store(true, Ordering::Relaxed);
        // These tests drive the background pass while jobs deliberately
        // remain queued. Production waits until that foreground work has
        // drained; disabling the yield policy here isolates capture logic.
        d.index_pause_on_download.store(false, Ordering::Relaxed);
    }

    fn ingest_ids(d: &Arc<Daemon>, group: &str, stem: &str, ids: &[&str]) -> i64 {
        d.with_index_mut(|index| {
            let entries: Vec<_> = ids
                .iter()
                .enumerate()
                .map(|(part, id)| nzbkit::nntp::OverEntry {
                    number: part as u64 + 1,
                    subject: format!(r#""{stem}.bin" yEnc ({}/{})"#, part + 1, ids.len()),
                    from: "p@x".into(),
                    message_id: format!("<{id}>"),
                    bytes: 1_000,
                    date: 1_700_000_000,
                })
                .collect();
            index.ingest(group, &entries, 1_700_000_010).ok()?;
            index
                .release_ids_by_stem(&format!("{stem}.bin"))
                .ok()?
                .into_iter()
                .next()
        })
        .expect("ingest local seed row")
    }

    pub fn drain_sweep(d: &Arc<Daemon>, state: &mut HarvestState) -> HarvestReport {
        let mut total = HarvestReport::default();
        for _ in 0..256 {
            let report = tick(d, state);
            total.inspected += report.inspected;
            total.stored += report.stored;
            total.already_stored += report.already_stored;
            total.invalid += report.invalid;
            total.missing += report.missing;
            total.withdrawn += report.withdrawn;
            total.deferred += report.deferred;
            total.named += report.named;
            total.pending = report.pending;
            if report.retry_later() || state.sweep_done() {
                return total;
            }
        }
        panic!("seed-harvest test sweep did not converge: {total:?}");
    }

    #[test]
    fn enqueue_only_banks_a_coalesced_wake_while_the_index_is_busy() {
        with_daemon("nonblocking", |d| {
            enable_index(d);
            let first = nzb(&[("one.bin", &["wake1@x", "wake2@x", "wake3@x"])]);
            let second = nzb(&[("two.bin", &["wake4@x", "wake5@x", "wake6@x"])]);
            let writer = d.index.lock_ok();
            let (tx, rx) = std::sync::mpsc::channel();
            let d2 = d.clone();
            let add_thread = std::thread::spawn(move || {
                let a = add(&d2, &first, "Wake.Show.S01E01.1080p-GRP.nzb");
                let b = add(&d2, &second, "Wake.Show.S01E02.1080p-GRP.nzb");
                tx.send((a, b)).unwrap();
            });
            rx.recv_timeout(crate::testutil::NO_PROGRESS)
                .expect("enqueue waited for the held index writer");
            add_thread.join().unwrap();
            drop(writer);

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    d.seed_harvest_wake.notified(),
                )
                .await
                .expect("accepted adds did not wake the harvester");
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(20),
                        d.seed_harvest_wake.notified(),
                    )
                    .await
                    .is_err(),
                    "Notify should coalesce; the catalog scan carries every add"
                );
            });

            let mut state = HarvestState::new(d.index_era());
            let report = drain_sweep(d, &mut state);
            assert_eq!(report.stored, 2, "{report:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (2, 2));
        });
    }

    #[test]
    fn identical_content_dedupes_but_a_conflicting_asserted_name_survives() {
        with_daemon("dedupe", |d| {
            enable_index(d);
            let xml = nzb(&[("payload.bin", &["same1@x", "same2@x", "same3@x"])]);
            add(d, &xml, "Real.Show.S01E01.1080p-GRP.nzb");

            let mut state = HarvestState::new(d.index_era());
            let first = tick(d, &mut state);
            assert_eq!(first.stored, 1, "{first:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));

            add(d, &xml, "Real.Show.S01E01.1080p-GRP.nzb");
            state.begin_sweep();
            let duplicate = tick(d, &mut state);
            assert_eq!(duplicate.stored, 0, "{duplicate:?}");
            assert!(duplicate.already_stored >= 1, "{duplicate:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));

            add(d, &xml, "Other.Show.S09E09.720p-BAD.nzb");
            state.begin_sweep();
            let conflict = tick(d, &mut state);
            assert_eq!(conflict.stored, 1, "{conflict:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 2));
        });
    }

    #[test]
    fn accepted_harvest_upgrades_a_legacy_keyless_assertion() {
        with_daemon("legacy-upgrade", |d| {
            enable_index(d);
            let xml = nzb(&[("payload.bin", &["legacy1@x", "legacy2@x", "legacy3@x"])]);
            add(d, &xml, "Legacy.Show.S01E01.1080p-GRP.nzb");

            let mut first_state = HarvestState::new(d.index_era());
            let first = tick(d, &mut first_state);
            assert_eq!(first.stored, 1, "{first:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));

            // Model an index created by the pre-manifest prototype. A fresh
            // worker must not mistake its assertion row for complete exact
            // evidence and skip reacquiring the still-retained NZB.
            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            d.close_index();
            let db = rusqlite::Connection::open(&d.index_db).unwrap();
            db.execute(
                "UPDATE nzb_seed_sets SET membership_key=?1",
                rusqlite::params!["0".repeat(32)],
            )
            .unwrap();
            db.execute("DELETE FROM nzb_seed_file_keys", []).unwrap();
            // Suppress the open-path purge for this one test. A legacy set
            // with no file keys is exactly the residue
            // `Index::nzb_seed_unrepairable_purge_slice` deletes at open, and
            // letting it run here would make this test pass by having no
            // legacy assertion row left to be fooled by - which is the guard
            // it exists to hold. The purge has its own end-to-end coverage in
            // `index::seed_tests`; what is measured HERE is the harvest
            // worker, so it gets a live legacy row to be measured against.
            db.execute(
                "INSERT INTO kv(k,v) VALUES('nzb_seed_purge_v1','1')
                 ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                [],
            )
            .unwrap();
            drop(db);
            enable_index(d);

            let mut second_state = HarvestState::new(d.index_era());
            let second = tick(d, &mut second_state);
            assert_eq!(second.stored, 1, "{second:?}");
            assert_eq!(second.already_stored, 0, "{second:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (2, 2));
        });
    }

    #[test]
    fn an_off_index_defers_without_losing_the_retained_spool() {
        with_daemon("defer", |d| {
            let xml = nzb(&[("payload.bin", &["late1@x", "late2@x", "late3@x"])]);
            add(d, &xml, "Late.Show.S01E02.1080p-GRP.nzb");
            let mut state = HarvestState::new(d.index_era());

            let off = tick(d, &mut state);
            assert!(off.deferred > 0, "{off:?}");
            assert!(!d.index_db.exists(), "capture created a switched-off index");

            enable_index(d);
            state.begin_sweep();
            let on = tick(d, &mut state);
            assert_eq!(on.stored, 1, "{on:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));
        });
    }

    #[test]
    fn an_invalid_spool_does_not_starve_the_valid_candidate_behind_it() {
        with_daemon("invalid", |d| {
            enable_index(d);
            let bad = nzb(&[("bad.bin", &["bad1@x", "bad2@x", "bad3@x"])]);
            let good = nzb(&[("good.bin", &["good1@x", "good2@x", "good3@x"])]);
            let bad_id = add(d, &bad, "Bad.Show.S01E01.1080p-GRP.nzb");
            add(d, &good, "Good.Show.S01E01.1080p-GRP.nzb");
            let bad_path = d.queue_job(&bad_id).unwrap().lock_ok().nzb_path.clone();
            std::fs::write(&bad_path, b"not an nzb").unwrap();

            let mut state = HarvestState::new(d.index_era());
            let first = drain_sweep(d, &mut state);
            assert_eq!(first.invalid, 1, "{first:?}");
            assert_eq!(first.stored, 1, "{first:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));

            state.begin_sweep();
            let second = drain_sweep(d, &mut state);
            assert_eq!(second.invalid, 0, "immutable failure retried: {second:?}");
        });
    }

    #[test]
    fn a_full_retry_queue_cannot_hide_a_valid_catalog_record() {
        with_daemon("retry-fairness", |d| {
            enable_index(d);
            let xml = nzb(&[("payload.bin", &["fair1@x", "fair2@x", "fair3@x"])]);
            add(d, &xml, "Fair.Show.S01E01.1080p-GRP.nzb");

            let mut bad = Vec::new();
            for index in 0..PENDING_CAP {
                bad.push(add(
                    d,
                    &xml,
                    &format!("Missing.Show.S01E{index:03}.1080p-GRP.nzb"),
                ));
            }

            let mut state = HarvestState::new(d.index_era());
            for id in bad {
                let job = d.queue_job(&id).unwrap();
                let candidate = Candidate::from_job(&job).unwrap();
                std::fs::remove_file(&candidate.path).unwrap();
                assert!(state.queue_candidate(candidate));
            }
            assert_eq!(state.pending.len(), PENDING_CAP);

            let mut stored = 0;
            for _ in 0..=PENDING_CAP {
                let report = tick(d, &mut state);
                assert!(
                    !report.retry_later(),
                    "local spool failure blocked: {report:?}"
                );
                stored += report.stored;
                if stored > 0 {
                    break;
                }
            }
            assert_eq!(stored, 1, "valid record never escaped retry pressure");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));
        });
    }

    #[test]
    fn cursor_never_skips_rows_that_do_not_fit_the_pending_window() {
        with_daemon("pending-window", |d| {
            enable_index(d);
            let xml = nzb(&[("payload.bin", &["window1@x", "window2@x", "window3@x"])]);
            let valid_index = PENDING_CAP + 13;
            for index in 0..PENDING_CAP + INSPECT_PER_PASS {
                let name = if index == valid_index {
                    "Window.Show.S01E01.1080p-GRP.nzb".to_string()
                } else {
                    format!("Missing.Window.{index:03}.1080p-GRP.nzb")
                };
                let id = add(d, &xml, &name);
                if index != valid_index {
                    let path = d.queue_job(&id).unwrap().lock_ok().nzb_path.clone();
                    std::fs::remove_file(path).unwrap();
                }
            }

            let mut state = HarvestState::new(d.index_era());
            let first_sweep = drain_sweep(d, &mut state);
            assert_eq!(
                first_sweep.stored, 1,
                "cursor skipped a full window: {first_sweep:?}"
            );
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));
        });
    }

    #[test]
    fn deletion_after_snapshot_withdraws_the_candidate_before_store() {
        with_daemon("withdrawn", |d| {
            enable_index(d);
            let xml = nzb(&[(
                "withdraw.bin",
                &["withdraw1@x", "withdraw2@x", "withdraw3@x"],
            )]);
            let id = add(d, &xml, "Withdraw.Show.S01E01.1080p-GRP.nzb");
            let mut state = HarvestState::new(d.index_era());
            let (snapshot, inspected) = snapshot_candidates(d, &mut state);
            assert_eq!(inspected, 1);
            assert_eq!(snapshot.len(), 1);
            state.queue_candidate(snapshot[0].clone());

            let job = d.queue_job(&id).unwrap();
            let path = {
                let mut job = job.lock_ok();
                job.tombstone = true;
                job.nzb_path.clone()
            };
            d.queue.lock_ok().clear();
            std::fs::remove_file(path).unwrap();

            let report = tick(d, &mut state);
            assert_eq!(report.missing, 1, "{report:?}");
            assert_eq!(report.withdrawn, 1, "{report:?}");
            assert_eq!(report.stored, 0, "{report:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (0, 0));
        });
    }

    #[test]
    fn final_commit_rolls_back_inside_the_remove_before_tombstone_window() {
        with_daemon("commit-delete-race", |d| {
            enable_index(d);
            let xml = nzb(&[(
                "race.bin",
                &["race-delete1@x", "race-delete2@x", "race-delete3@x"],
            )]);
            let id = add(d, &xml, "Race.Show.S01E01.1080p-GRP.nzb");
            let record = d.queue_job(&id).unwrap();
            let candidate = Candidate::from_job(&record).unwrap();
            let prepared = prepare(&candidate).expect("prepare retained seed");

            // REST history deletion removes the Arc first and stamps the
            // tombstone after durable I/O. Reproduce that exact middle
            // window: every Job field still matches, but membership is gone.
            d.queue.lock_ok().clear();
            assert!(!record.lock_ok().tombstone);

            let result = d
                .with_index_mut_retiring_ddl(|index| {
                    Some(index.nzb_seed_store_prepared_guarded(
                        nzbkit::index::NzbSeedSpec {
                            source: SOURCE,
                            source_guid: &prepared.guid,
                            name: &prepared.candidate.name,
                            category: &prepared.candidate.category,
                            posted: prepared.posted,
                            bytes: prepared.bytes,
                        },
                        &prepared.seed,
                        epoch_secs() as i64,
                        || match try_retained_guard(d, &prepared.candidate) {
                            Retained::Current(guard) => Some(guard),
                            Retained::Withdrawn | Retained::Busy => None,
                        },
                    ))
                })
                .unwrap()
                .unwrap();
            assert_eq!(result, None);
            assert_eq!(inventory(d), nzbkit::index::NzbSeedInventory::default());
        });
    }

    #[test]
    fn final_guard_fences_moves_relocations_and_record_generations() {
        with_daemon("commit-fences", |d| {
            enable_index(d);
            let xml = nzb(&[("fence.bin", &["fence1@x", "fence2@x", "fence3@x"])]);
            let id = add(d, &xml, "Fence.Show.S01E01.1080p-GRP.nzb");
            let record = d.queue_job(&id).unwrap();
            let candidate = Candidate::from_job(&record).unwrap();

            d.moving.lock_ok().insert(id.clone());
            assert!(matches!(try_retained_guard(d, &candidate), Retained::Busy));
            d.moving.lock_ok().remove(&id);

            d.hist_inflight.lock_ok().insert(id.clone());
            assert!(matches!(try_retained_guard(d, &candidate), Retained::Busy));
            d.hist_inflight.lock_ok().remove(&id);

            record.lock_ok().relocating = 1;
            assert!(matches!(try_retained_guard(d, &candidate), Retained::Busy));
            record.lock_ok().relocating = 0;

            record.lock_ok().retries += 1;
            assert!(matches!(
                try_retained_guard(d, &candidate),
                Retained::Withdrawn
            ));
        });
    }

    #[test]
    fn a_deleted_retryable_history_row_is_withdrawn_until_explicit_retry() {
        with_daemon("deleted-history", |d| {
            enable_index(d);
            let xml = nzb(&[("deleted.bin", &["deleted1@x", "deleted2@x", "deleted3@x"])]);
            let id = add(d, &xml, "Deleted.Show.S01E01.1080p-GRP.nzb");
            let mut state = HarvestState::new(d.index_era());
            let (snapshot, inspected) = snapshot_candidates(d, &mut state);
            assert_eq!(inspected, 1);
            assert_eq!(snapshot.len(), 1);
            state.queue_candidate(snapshot[0].clone());

            let job = d.queue_job(&id).unwrap();
            job.lock_ok().delete_status = "MANUAL".into();
            d.queue.lock_ok().clear();
            d.history.lock_ok().push(job.clone());

            let raced = tick(d, &mut state);
            assert_eq!(raced.withdrawn, 1, "{raced:?}");
            assert_eq!(raced.stored, 0, "{raced:?}");

            state.begin_sweep();
            let deleted = drain_sweep(d, &mut state);
            assert_eq!(deleted.stored, 0, "{deleted:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (0, 0));

            job.lock_ok().delete_status.clear();
            state.begin_sweep();
            let retried = drain_sweep(d, &mut state);
            assert_eq!(retried.stored, 1, "{retried:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));
        });
    }

    #[test]
    fn a_multi_file_pack_split_across_rows_is_recorded_but_never_renamed() {
        with_daemon("fragmented", |d| {
            enable_index(d);
            d.with_index_mut(|index| {
                let entries = |stem: &str, prefix: &str| {
                    (1..=3u64)
                        .map(|part| nzbkit::nntp::OverEntry {
                            number: part,
                            subject: format!(r#""{stem}.bin" yEnc ({part}/3)"#),
                            from: "p@x".into(),
                            message_id: format!("<{prefix}{part}@x>"),
                            bytes: 1_000,
                            date: 1_700_000_000,
                        })
                        .collect::<Vec<_>>()
                };
                index
                    .ingest(
                        "a.b.dark.one",
                        &entries("opaque77aa", "packa"),
                        1_700_000_010,
                    )
                    .ok()?;
                index
                    .ingest(
                        "a.b.dark.two",
                        &entries("opaque77bb", "packb"),
                        1_700_000_010,
                    )
                    .ok()
            })
            .expect("seed fragmented local rows");

            let xml = nzb(&[
                ("episode1.bin", &["packa1@x", "packa2@x", "packa3@x"]),
                ("episode2.bin", &["packb1@x", "packb2@x", "packb3@x"]),
            ]);
            add(d, &xml, "Whole.Show.S01.1080p.WEB-GRP.nzb");
            let mut state = HarvestState::new(d.index_era());
            let report = tick(d, &mut state);
            assert_eq!(report.stored, 1, "{report:?}");
            assert_eq!(report.named, 0, "a pack title escaped: {report:?}");
            let inventory = inventory(d);
            assert_eq!(inventory.fragmented_sets, 1, "{inventory:?}");

            d.with_index(|index| {
                for stem in ["opaque77aa.bin", "opaque77bb.bin"] {
                    let release_id = index.release_ids_by_stem(stem).unwrap()[0];
                    assert!(
                        index.name_claims(release_id).unwrap().is_empty(),
                        "fragment {stem} acquired the pack title"
                    );
                }
                Some(())
            })
            .unwrap();
        });
    }

    #[test]
    fn accepted_nzb_catalog_corruption_retries_and_recovers_in_the_same_era() {
        with_daemon("accepted-catalog-repair", |d| {
            enable_index(d);
            let xml = nzb(&[(
                "payload.bin",
                &["accepted-a1@x", "accepted-a2@x", "accepted-a3@x"],
            )]);
            add(d, &xml, "Accepted.Catalog.Show.S01E01.1080p-GRP.nzb");
            let mut initial = HarvestState::new(d.index_era());
            assert_eq!(tick(d, &mut initial).stored, 1);
            let era = d.index_era();

            // A second WAL connection can corrupt and repair the catalog
            // without retiring the daemon handle. This keeps the retry in
            // the same era, which is the behavior under test.
            let db = rusqlite::Connection::open(&d.index_db).unwrap();
            db.execute(
                "INSERT INTO nzb_seed_file_keys(set_id,file_ord,kind,manifest_key)
                 VALUES((SELECT MIN(id) FROM nzb_seed_sets),999,0,?1)",
                [format!("sha256:{}", "0".repeat(64))],
            )
            .unwrap();
            drop(db);
            assert_eq!(d.index_era(), era);

            let mut retrying = HarvestState::new(era);
            let corrupt = tick(d, &mut retrying);
            assert!(corrupt.deferred > 0, "{corrupt:?}");
            assert_eq!(corrupt.invalid, 0, "{corrupt:?}");

            let db = rusqlite::Connection::open(&d.index_db).unwrap();
            db.execute("DELETE FROM nzb_seed_file_keys WHERE file_ord=999", [])
                .unwrap();
            drop(db);
            assert_eq!(d.index_era(), era);

            let repaired = tick(d, &mut retrying);
            assert_eq!(repaired.already_stored, 1, "{repaired:?}");
            assert_eq!(repaired.invalid, 0, "{repaired:?}");
        });
    }

    #[test]
    fn commercial_inbox_survives_an_off_index_and_replays_after_enable() {
        with_daemon("commercial-off", |d| {
            d.spot_enabled.store(false, Ordering::Relaxed);
            let ids = ["commercial1@x", "commercial2@x", "commercial3@x"];
            let xml = nzb(&[("payload.bin", &ids)]);
            let name = "Commercial.Show.S01E01.1080p-GRP";
            let inbox_id = stage_indexer_seed(d, &xml, name, "tv", 1_700_000_000, 3_000).unwrap();
            let (meta_path, raw_path) = indexer_inbox_paths(d, &inbox_id);
            assert!(meta_path.is_file() && raw_path.is_file());

            let mut state = HarvestState::new(d.index_era());
            let off = tick(d, &mut state);
            assert!(off.deferred > 0, "{off:?}");
            assert!(meta_path.is_file() && raw_path.is_file());
            assert!(!d.index_db.exists());

            enable_index(d);
            let rid = ingest_ids(d, "a.b.dark", "aB7kQ2mZ9xP4vN6tR", &ids);
            let on = tick(d, &mut state);
            assert_eq!(on.stored, 1, "{on:?}");
            assert_eq!(on.named, 0, "a fresh manifest must wait: {on:?}");
            assert!(!meta_path.exists() && !raw_path.exists());
            let settled = settle_seed_names(d);
            assert_eq!(settled.claims_applied, 1, "{settled:?}");
            d.with_index(|index| {
                assert!(
                    index
                        .nzb_seed_assertion_exists(INDEXER_SOURCE, &nzb_sha(&xml), name)
                        .unwrap()
                );
                let claims = index.name_claims(rid).unwrap();
                assert_eq!(claims.len(), 1);
                let (claim_name, _tier, _key, source, _at) = &claims[0];
                assert_eq!(claim_name, name);
                assert_eq!(source, "external-nzb:nzb-indexer");
                Some(())
            })
            .unwrap();
        });
    }

    #[test]
    fn commercial_capacity_pauses_paid_acquisition_without_blocking_inbox_replay() {
        with_daemon("commercial-capacity", |d| {
            enable_index(d);
            let first = nzb(&[(
                "first.bin",
                &["capacity-a1@x", "capacity-a2@x", "capacity-a3@x"],
            )]);
            stage_indexer_seed(
                d,
                &first,
                "Capacity.Show.S01E01.1080p-GRP",
                "tv",
                1_700_000_000,
                3_000,
            )
            .unwrap();
            let mut state = HarvestState::new(d.index_era());
            assert_eq!(tick(d, &mut state).stored, 1);

            // Fill the deterministic logical-byte ledger through a second
            // connection. Capacity is a durable administrative limit. The
            // worker must preserve the raw evidence but remove this item from
            // the live lexicographic queue so it cannot starve later work.
            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            d.close_index();
            let db = rusqlite::Connection::open(&d.index_db).unwrap();
            db.execute(
                "UPDATE nzb_seed_usage SET charged_bytes=?1 WHERE id=1",
                [1_i64 << 30],
            )
            .unwrap();
            drop(db);
            enable_index(d);

            let second = nzb(&[(
                "second.bin",
                &["capacity-b1@x", "capacity-b2@x", "capacity-b3@x"],
            )]);
            let id = stage_indexer_seed(
                d,
                &second,
                "Capacity.Show.S01E02.1080p-GRP",
                "tv",
                1_700_000_100,
                3_000,
            )
            .unwrap();
            let (meta_path, raw_path) = indexer_inbox_paths(d, &id);
            let held = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(held.stored, 0, "{held:?}");
            assert_eq!(held.invalid, 0, "{held:?}");
            assert!(!held.retry_later(), "{held:?}");
            assert!(!meta_path.exists());
            assert!(meta_path.with_extension("capacity").is_file());
            assert!(raw_path.is_file());
            assert!(
                !indexer_inbox_has_room(d),
                "a durable logical-capacity hold must stop further paid acquisitions"
            );
            // A durable marker is AtCapacity, distinct from Busy or
            // Unreadable - the confirm lane's log must be able to say "at
            // capacity" here, not "full or unavailable".
            assert!(matches!(
                indexer_inbox_room(d),
                IndexerInboxRoom::AtCapacity(_)
            ));
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));

            // A later zero-delta duplicate remains admissible at the hard
            // limit. Its successful settlement proves the held marker no
            // longer starves subsequent live inbox work.
            let duplicate_id = stage_indexer_seed(
                d,
                &first,
                "Capacity.Show.S01E01.1080p-GRP",
                "tv",
                1_700_000_000,
                3_000,
            )
            .unwrap();
            let (duplicate_meta, duplicate_raw) = indexer_inbox_paths(d, &duplicate_id);
            let advanced = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(advanced.stored, 1, "{advanced:?}");
            assert!(!duplicate_meta.exists() && !duplicate_raw.exists());
        });
    }

    #[test]
    fn an_index_wipe_reactivates_generation_scoped_commercial_capacity_holds() {
        with_daemon("commercial-capacity-wipe", |d| {
            enable_index(d);
            let baseline = nzb(&[(
                "baseline.bin",
                &["wipe-cap-a1@x", "wipe-cap-a2@x", "wipe-cap-a3@x"],
            )]);
            stage_indexer_seed(
                d,
                &baseline,
                "Wipe.Capacity.Show.S01E01.1080p-GRP",
                "tv",
                1_700_000_000,
                3_000,
            )
            .unwrap();
            assert_eq!(tick(d, &mut HarvestState::new(d.index_era())).stored, 1);

            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            d.close_index();
            let db = rusqlite::Connection::open(&d.index_db).unwrap();
            db.execute(
                "UPDATE nzb_seed_usage SET charged_bytes=?1 WHERE id=1",
                [1_i64 << 30],
            )
            .unwrap();
            drop(db);
            enable_index(d);

            let held_xml = nzb(&[(
                "held.bin",
                &["wipe-cap-b1@x", "wipe-cap-b2@x", "wipe-cap-b3@x"],
            )]);
            let held_id = stage_indexer_seed(
                d,
                &held_xml,
                "Wipe.Capacity.Show.S01E02.1080p-GRP",
                "tv",
                1_700_000_100,
                3_000,
            )
            .unwrap();
            let (meta_path, raw_path) = indexer_inbox_paths(d, &held_id);
            let held = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(held.stored, 0, "{held:?}");
            assert!(meta_path.with_extension("capacity").is_file());
            assert!(!indexer_inbox_has_room(d));

            {
                let mut guard = d.index.lock_ok();
                d.index_generation.fetch_add(1, Ordering::SeqCst);
                *guard = None;
                for suffix in ["", "-wal", "-shm"] {
                    let path = PathBuf::from(format!("{}{suffix}", d.index_db.display()));
                    let _ = std::fs::remove_file(path);
                }
                d.drop_index_read();
                assert_eq!(reactivate_indexer_generation_holds(d).unwrap(), 1);
            }
            d.reset_index_ledger();
            assert!(meta_path.is_file());
            assert!(!meta_path.with_extension("capacity").exists());
            assert!(raw_path.is_file());
            assert!(indexer_inbox_has_room(d));

            let replayed = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(replayed.stored, 1, "{replayed:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));
            assert!(!meta_path.exists() && !raw_path.exists());
        });
    }

    #[test]
    fn corrupt_commercial_catalog_evidence_is_quarantined_without_starving_the_next_item() {
        with_daemon("commercial-corrupt-catalog", |d| {
            enable_index(d);
            let duplicate_xml = nzb(&[(
                "duplicate.bin",
                &["catalog-a1@x", "catalog-a2@x", "catalog-a3@x"],
            )]);
            stage_indexer_seed(
                d,
                &duplicate_xml,
                "Catalog.Show.S01E01.1080p-GRP",
                "tv",
                1_700_000_000,
                3_000,
            )
            .unwrap();
            assert_eq!(tick(d, &mut HarvestState::new(d.index_era())).stored, 1);

            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            d.close_index();
            let db = rusqlite::Connection::open(&d.index_db).unwrap();
            assert_eq!(
                db.execute(
                    "DELETE FROM nzb_seed_file_keys
                      WHERE set_id=(SELECT MIN(id) FROM nzb_seed_sets)",
                    [],
                )
                .unwrap(),
                1
            );
            drop(db);
            enable_index(d);

            let corrupt_id = stage_indexer_seed(
                d,
                &duplicate_xml,
                "Catalog.Show.S01E01.Corrupt-Proof-GRP",
                "tv",
                1_700_000_001,
                3_000,
            )
            .unwrap();
            let (corrupt_meta, corrupt_raw) = indexer_inbox_paths(d, &corrupt_id);
            let quarantined = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(quarantined.invalid, 1, "{quarantined:?}");
            assert!(!quarantined.retry_later(), "{quarantined:?}");
            assert!(corrupt_meta.with_extension("catalog").is_file());
            assert!(corrupt_raw.is_file());

            let next_xml = nzb(&[(
                "next.bin",
                &["catalog-b1@x", "catalog-b2@x", "catalog-b3@x"],
            )]);
            let next_id = stage_indexer_seed(
                d,
                &next_xml,
                "Catalog.Show.S01E02.1080p-GRP",
                "tv",
                1_700_000_100,
                3_000,
            )
            .unwrap();
            let (next_meta, next_raw) = indexer_inbox_paths(d, &next_id);
            let advanced = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(advanced.stored, 1, "{advanced:?}");
            assert!(!next_meta.exists() && !next_raw.exists());

            {
                let mut guard = d.index.lock_ok();
                d.index_generation.fetch_add(1, Ordering::SeqCst);
                *guard = None;
                for suffix in ["", "-wal", "-shm"] {
                    let path = PathBuf::from(format!("{}{suffix}", d.index_db.display()));
                    let _ = std::fs::remove_file(path);
                }
                d.drop_index_read();
                assert_eq!(reactivate_indexer_generation_holds(d).unwrap(), 1);
            }
            d.reset_index_ledger();
            assert!(corrupt_meta.is_file());
            assert!(!corrupt_meta.with_extension("catalog").exists());
            let repaired = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(repaired.stored, 1, "{repaired:?}");
            assert!(!corrupt_meta.exists() && !corrupt_raw.exists());
        });
    }

    #[test]
    fn commercial_split_pack_stays_a_collection_and_never_names_shards() {
        with_daemon("commercial-fragmented", |d| {
            enable_index(d);
            let first = ["commercial-a1@x", "commercial-a2@x", "commercial-a3@x"];
            let second = ["commercial-b1@x", "commercial-b2@x", "commercial-b3@x"];
            let a = ingest_ids(d, "a.b.dark.one", "opaquecommerciala", &first);
            let b = ingest_ids(d, "a.b.dark.two", "opaquecommercialb", &second);
            let xml = nzb(&[("episode1.bin", &first), ("episode2.bin", &second)]);
            stage_indexer_seed(
                d,
                &xml,
                "Commercial.Show.S01.1080p.WEB-GRP",
                "tv",
                1_700_000_000,
                6_000,
            )
            .unwrap();

            let mut state = HarvestState::new(d.index_era());
            let report = tick(d, &mut state);
            assert_eq!(report.stored, 1, "{report:?}");
            assert_eq!(report.named, 0, "{report:?}");
            let inventory = inventory(d);
            assert_eq!(inventory.fragmented_sets, 1, "{inventory:?}");
            d.with_index(|index| {
                assert!(index.name_claims(a).unwrap().is_empty());
                assert!(index.name_claims(b).unwrap().is_empty());
                Some(())
            })
            .unwrap();
        });
    }

    #[test]
    fn commercial_inbox_rejects_invalid_metadata_before_writing() {
        with_daemon("commercial-metadata", |d| {
            let xml = nzb(&[("payload.bin", &["meta1@x", "meta2@x", "meta3@x"])]);
            assert!(
                stage_indexer_seed(d, &xml, "Bad\nName", "tv", 0, 3_000).is_err(),
                "control-bearing title entered the durable inbox"
            );
            let _io = INDEXER_INBOX_IO.lock_ok();
            assert_eq!(
                indexer_inbox_entries_locked(d).unwrap(),
                IndexerInboxUsage::default()
            );
        });
    }

    #[test]
    fn invalid_quarantine_cannot_capture_a_concurrently_repaired_paid_proof() {
        with_daemon("commercial-invalid-repair-race", |d| {
            let xml = nzb(&[(
                "payload.bin",
                &["repair-a1@x", "repair-a2@x", "repair-a3@x"],
            )]);
            let name = "Repair.Race.Show.S01E01.1080p-GRP";
            let id = stage_indexer_seed(d, &xml, name, "tv", 1_700_000_000, 3_000).unwrap();
            let (meta_path, raw_path) = indexer_inbox_paths(d, &id);
            std::fs::write(&raw_path, b"corrupt replacement").unwrap();
            let failed_fingerprint = indexer_inbox_fingerprint(&meta_path).unwrap();

            assert_eq!(
                stage_indexer_seed(d, &xml, name, "tv", 1_700_000_000, 3_000).unwrap(),
                id
            );
            assert!(
                hold_invalid_indexer_inbox_if_unchanged(&meta_path, Some(&failed_fingerprint))
                    .unwrap()
                    .is_none(),
                "an old validation result quarantined replacement bytes"
            );
            assert!(meta_path.is_file() && raw_path.is_file());
            assert!(!meta_path.with_extension("hold").exists());

            enable_index(d);
            let report = tick(d, &mut HarvestState::new(d.index_era()));
            assert_eq!(report.stored, 1, "{report:?}");
            assert!(!meta_path.exists() && !raw_path.exists());
        });
    }

    #[test]
    fn commercial_inbox_counts_then_reclaims_crash_artifacts() {
        with_daemon("commercial-orphan", |d| {
            let id = "a".repeat(64);
            let (meta_path, raw_path) = indexer_inbox_paths(d, &id);
            std::fs::create_dir_all(raw_path.parent().unwrap()).unwrap();
            std::fs::write(&raw_path, b"uncommitted raw proof").unwrap();
            let raw_tmp = raw_path.with_file_name(format!("{id}.nzb.{}.7.tmp", std::process::id()));
            let meta_tmp =
                meta_path.with_file_name(format!("{id}.json.{}.8.tmp", std::process::id()));
            std::fs::write(&raw_tmp, b"torn raw temp").unwrap();
            std::fs::write(&meta_tmp, b"torn metadata temp").unwrap();
            let unrelated = raw_path.with_file_name("operator-note.tmp");
            std::fs::write(&unrelated, b"not owned by the inbox protocol").unwrap();

            {
                let _io = INDEXER_INBOX_IO.lock_ok();
                assert_eq!(
                    indexer_inbox_entries_locked(d).unwrap(),
                    IndexerInboxUsage {
                        items: 0,
                        artifacts: 3,
                        bytes: b"uncommitted raw proof".len() as u64
                            + b"torn raw temp".len() as u64
                            + b"torn metadata temp".len() as u64,
                    }
                );
            }
            assert!(raw_path.exists() && raw_tmp.exists() && meta_tmp.exists());

            let old = std::time::SystemTime::now()
                - std::time::Duration::from_secs(INDEXER_ORPHAN_GRACE_SECS + 1);
            for path in [&raw_path, &raw_tmp, &meta_tmp] {
                std::fs::File::options()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
            }
            let _io = INDEXER_INBOX_IO.lock_ok();
            assert_eq!(
                indexer_inbox_entries_locked(d).unwrap(),
                IndexerInboxUsage::default()
            );
            assert!(!raw_path.exists());
            assert!(!raw_tmp.exists() && !meta_tmp.exists());
            assert!(unrelated.exists());
        });
    }

    #[test]
    fn commercial_inbox_bounds_zero_length_crash_artifacts_by_count() {
        with_daemon("commercial-artifact-cap", |d| {
            let dir = ensure_indexer_inbox_dir(d).unwrap();
            for index in 0..INDEXER_INBOX_ARTIFACT_CAP {
                let id = format!("{index:064x}");
                let path = dir.join(format!("{id}.nzb.{}.{index}.tmp", std::process::id()));
                std::fs::write(path, []).unwrap();
            }
            assert!(
                !indexer_inbox_has_room(d),
                "zero-byte crash artifacts bypassed the acquisition cap"
            );
            // The count-based cap is AtCapacity too, with the numbers in the
            // detail string - not the marker path, but the same verdict.
            match indexer_inbox_room(d) {
                IndexerInboxRoom::AtCapacity(detail) => {
                    assert!(detail.contains("artifacts"), "{detail}");
                }
                _ => panic!("expected AtCapacity for the artifact-count cap"),
            }
            let xml = nzb(&[("payload.bin", &["cap1@x", "cap2@x", "cap3@x"])]);
            let error = stage_indexer_seed(
                d,
                &xml,
                "Cap.Show.S01E01.1080p-GRP",
                "tv",
                1_700_000_000,
                3_000,
            )
            .unwrap_err();
            assert!(error.to_string().contains("artifact cap"), "{error}");
        });
    }

    #[test]
    fn a_second_process_lock_fails_commercial_admission_closed() {
        with_daemon("commercial-process-lock", |d| {
            let dir = ensure_indexer_inbox_dir(d).unwrap();
            let _held = lock_indexer_inbox_process(&dir).unwrap();
            assert!(!indexer_inbox_has_room(d));
            // The contended lock reports Busy, never AtCapacity or
            // Unreadable - the confirm lane logs this one at debug and
            // retries next tick rather than warning about a fault.
            assert!(matches!(indexer_inbox_room(d), IndexerInboxRoom::Busy));
            let xml = nzb(&[("payload.bin", &["lock-a1@x", "lock-a2@x", "lock-a3@x"])]);
            let error = stage_indexer_seed(
                d,
                &xml,
                "Lock.Show.S01E01.1080p-GRP",
                "tv",
                1_700_000_000,
                3_000,
            )
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        });
    }

    /// The same lock file, opened twice in one process (never `dup`'d), gets
    /// two independent file descriptions - `flock`-style advisory locks
    /// contend on those, not on the process. This is the shape the confirm
    /// lane's own harvest worker hits against itself, which the `Busy`
    /// wording now names correctly instead of blaming "another process".
    #[test]
    fn the_process_lock_contends_with_a_second_open_in_the_same_process() {
        with_daemon("commercial-self-contend", |d| {
            let dir = ensure_indexer_inbox_dir(d).unwrap();
            let _first_open = lock_indexer_inbox_process(&dir).unwrap();
            let error = lock_indexer_inbox_process(&dir).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        });
    }

    /// A real io error reading the inbox must report `Unreadable`, not the
    /// same verdict as a genuine capacity hold. Before this, `unwrap_or(true)`
    /// (on the capacity-marker scan) and `Result::is_ok_and` (on the entry
    /// scan) both folded an error into "no room", indistinguishable from a
    /// durable cap from outside the function.
    #[test]
    fn an_unreadable_inbox_directory_reports_unreadable_not_at_capacity() {
        with_daemon("commercial-unreadable", |d| {
            let dir = indexer_inbox_dir(d);
            std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
            // A plain file occupies the inbox directory's own path, so
            // `create_dir_all` inside `ensure_indexer_inbox_dir` fails
            // instead of finding (or making) a directory to scan.
            std::fs::write(&dir, b"blocking the inbox directory path").unwrap();
            assert!(matches!(
                indexer_inbox_room(d),
                IndexerInboxRoom::Unreadable(_)
            ));
            assert!(!indexer_inbox_has_room(d));
        });
    }

    #[test]
    fn commercial_inbox_never_removes_raw_when_marker_removal_fails() {
        with_daemon("commercial-cleanup", |d| {
            let id = "b".repeat(64);
            let (meta_path, raw_path) = indexer_inbox_paths(d, &id);
            std::fs::create_dir_all(&meta_path).unwrap();
            std::fs::write(&raw_path, b"committed raw proof").unwrap();

            assert!(remove_indexer_inbox(&meta_path, Some(&raw_path)).is_err());
            assert!(raw_path.is_file());
        });
    }

    #[test]
    fn commercial_inbox_hold_is_counted_and_does_not_hide_the_next_item() {
        with_daemon("commercial-hold", |d| {
            let first_xml = nzb(&[("first.bin", &["hold-a1@x", "hold-a2@x", "hold-a3@x"])]);
            let second_xml = nzb(&[("second.bin", &["hold-b1@x", "hold-b2@x", "hold-b3@x"])]);
            let first =
                stage_indexer_seed(d, &first_xml, "First.Show.S01E01-GRP", "tv", 1, 3_000).unwrap();
            let second =
                stage_indexer_seed(d, &second_xml, "Second.Show.S01E01-GRP", "tv", 2, 3_000)
                    .unwrap();
            let (held, next) = if first < second {
                (first, second)
            } else {
                (second, first)
            };
            let (held_meta, held_raw) = indexer_inbox_paths(d, &held);
            let held_path = hold_indexer_inbox(&held_meta).unwrap();
            let old = std::time::SystemTime::now()
                - std::time::Duration::from_secs(INDEXER_ORPHAN_GRACE_SECS + 1);
            std::fs::File::options()
                .write(true)
                .open(&held_raw)
                .unwrap()
                .set_modified(old)
                .unwrap();

            {
                let _io = INDEXER_INBOX_IO.lock_ok();
                assert_eq!(
                    indexer_inbox_entries_locked(d).unwrap(),
                    IndexerInboxUsage {
                        items: 2,
                        artifacts: 4,
                        bytes: (first_xml.len() + second_xml.len()) as u64,
                    }
                );
            }
            assert!(held_path.is_file() && held_raw.is_file());
            assert_eq!(next_indexer_inbox(d).unwrap().unwrap().id, next);
        });
    }

    #[test]
    fn commercial_corrupt_marker_is_held_without_losing_raw_or_hiding_the_next_item() {
        with_daemon("commercial-corrupt-marker", |d| {
            enable_index(d);
            let first_xml = nzb(&[("first.bin", &["json-a1@x", "json-a2@x", "json-a3@x"])]);
            let second_xml = nzb(&[("second.bin", &["json-b1@x", "json-b2@x", "json-b3@x"])]);
            let first =
                stage_indexer_seed(d, &first_xml, "First.Show.S01E01-GRP", "tv", 1, 3_000).unwrap();
            let second =
                stage_indexer_seed(d, &second_xml, "Second.Show.S01E01-GRP", "tv", 2, 3_000)
                    .unwrap();
            let (corrupt, valid) = if first < second {
                (first, second)
            } else {
                (second, first)
            };
            let (corrupt_meta, corrupt_raw) = indexer_inbox_paths(d, &corrupt);
            std::fs::write(&corrupt_meta, b"not json").unwrap();

            let mut state = HarvestState::new(d.index_era());
            let held = tick(d, &mut state);
            assert_eq!(held.invalid, 1, "{held:?}");
            assert!(corrupt_meta.with_extension("hold").is_file());
            assert!(corrupt_raw.is_file(), "paid raw proof was deleted");
            let next = tick(d, &mut state);
            assert_eq!(next.stored, 1, "valid item behind quarantine: {next:?}");
            let (valid_meta, valid_raw) = indexer_inbox_paths(d, &valid);
            assert!(!valid_meta.exists() && !valid_raw.exists());
        });
    }

    #[test]
    fn commercial_raw_hash_mismatch_is_quarantined_with_the_raw_bytes() {
        with_daemon("commercial-corrupt-raw", |d| {
            enable_index(d);
            let xml = nzb(&[("payload.bin", &["raw-a1@x", "raw-a2@x", "raw-a3@x"])]);
            let id = stage_indexer_seed(d, &xml, "Raw.Show.S01E01-GRP", "tv", 1, 3_000).unwrap();
            let (meta_path, raw_path) = indexer_inbox_paths(d, &id);
            std::fs::write(&raw_path, b"damaged paid proof").unwrap();

            let mut state = HarvestState::new(d.index_era());
            let report = tick(d, &mut state);
            assert_eq!(report.invalid, 1, "{report:?}");
            assert!(meta_path.with_extension("hold").is_file());
            assert_eq!(std::fs::read(&raw_path).unwrap(), b"damaged paid proof");
        });
    }

    #[test]
    fn failed_commercial_quarantine_keeps_the_marker_and_reports_blocked() {
        with_daemon("commercial-hold-failure", |d| {
            enable_index(d);
            let xml = nzb(&[("payload.bin", &["hold-f1@x", "hold-f2@x", "hold-f3@x"])]);
            let id = stage_indexer_seed(d, &xml, "Hold.Show.S01E01-GRP", "tv", 1, 3_000).unwrap();
            let (meta_path, raw_path) = indexer_inbox_paths(d, &id);
            std::fs::write(&meta_path, b"not json").unwrap();
            let hold_path = meta_path.with_extension("hold");
            std::fs::write(&hold_path, b"occupied quarantine target").unwrap();

            let mut state = HarvestState::new(d.index_era());
            let report = tick(d, &mut state);
            assert_eq!(report.invalid, 1, "{report:?}");
            assert!(report.retry_later(), "{report:?}");
            assert!(meta_path.is_file() && raw_path.is_file() && hold_path.is_file());
        });
    }

    #[cfg(unix)]
    #[test]
    fn commercial_inbox_directory_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        with_daemon("commercial-mode", |d| {
            assert!(indexer_inbox_has_room(d));
            let mode = std::fs::metadata(indexer_inbox_dir(d))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        });
    }

    #[test]
    fn an_index_era_change_rehydrates_a_fresh_database_from_the_same_spool() {
        with_daemon("era", |d| {
            enable_index(d);
            let xml = nzb(&[("payload.bin", &["era1@x", "era2@x", "era3@x"])]);
            add(d, &xml, "Era.Show.S01E01.1080p-GRP.nzb");
            let mut state = HarvestState::new(d.index_era());
            assert_eq!(tick(d, &mut state).stored, 1);
            assert_eq!(inventory(d).assertions, 1);

            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            d.close_index();
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{suffix}", d.index_db.display()));
                let _ = std::fs::remove_file(path);
            }
            d.index_migrated.store(false, Ordering::Release);
            d.index_enabled.store(true, Ordering::Relaxed);
            state.begin_sweep();

            let rebuilt = tick(d, &mut state);
            assert_eq!(rebuilt.stored, 1, "{rebuilt:?}");
            assert_eq!((inventory(d).sets, inventory(d).assertions), (1, 1));
        });
    }
    // Lifted from `crates/nzbfast-daemon/src/seed_harvest.rs`.
    /// 2 Sep 2026: the durable seed replay had reconciled nothing for
    /// 91 minutes on the live index, across three restarts and two
    /// installs, with 343 sets pending and the cursor byte-identical at
    /// set 328. The cause was structural, not a bad row: this lane
    /// reaches the replay only by winning `index_pass_gate`, and the
    /// index scan lap holds that gate for the whole of its work - work
    /// that had grown from ~9 minutes to 42-46, so the inter-lap sleep
    /// the lane used to run in had stopped happening at all.
    ///
    /// Both halves of the fix are pinned here, in the exact condition
    /// that starved it. With the gate held: this task still stands down
    /// (correctly - it must not park behind a multi-minute pass) but now
    /// SAYS which gate declined, and the lap's own reserved slice
    /// advances the durable cursor anyway.
    ///
    /// Do not answer a failure here by making the harvest wait on the
    /// gate: parking this lane behind a pass is the http_wedge shape,
    /// and the reserved slice exists so it never has to.
    #[test]
    fn the_lap_slice_replays_seeds_the_held_pass_gate_locks_this_lane_out_of() {
        with_daemon("gate-held-replay", |d| {
            enable_index(d);
            let bytes = nzb(&[("gatehold.bin", &["gate1@x", "gate2@x", "gate3@x"])]);
            add(d, &bytes, "Gate.Show.S01E01.1080p-GRP.nzb");
            let mut state = HarvestState::for_era(d.index_era());
            state.begin_sweep();
            drain_sweep(d, &mut state);
            assert!(
                inventory(d).sets > 0,
                "the fixture never stored a seed set, so this proves nothing \
                 about the replay"
            );

            // A cursor value the walk can only leave by doing work: it
            // writes "0" solely when there is no set to walk at all.
            d.with_index_mut(|index| index.kv_set(nzbkit::index::SEED_REPLAY_CURSOR, "0").ok())
                .expect("park the durable replay cursor");

            let gate = tokio::sync::Mutex::new(());
            let held = gate.try_lock().expect("hold the pass gate for the test");

            let mut blocked = HarvestState::for_era(d.index_era());
            blocked.begin_sweep();
            let report = tick_with_gate(d, &mut blocked, Some(&gate));
            assert_eq!(
                report.stalled_at,
                Some("the index pass gate is held by a scan lap"),
                "a pass that never reached the replay must name the gate \
                 that declined - silence here is the whole defect"
            );
            assert_eq!(
                d.with_index(|index| index.kv_get(nzbkit::index::SEED_REPLAY_CURSOR)),
                Some("0".to_string()),
                "the harvest cannot replay behind a held gate, by design"
            );

            assert!(
                !seed_replay_pass(d)
                    || d.with_index(|index| index.kv_get(nzbkit::index::SEED_REPLAY_CURSOR))
                        != Some("0".to_string()),
                "the lap slice reported nothing to do while a set was waiting"
            );
            assert_ne!(
                d.with_index(|index| index.kv_get(nzbkit::index::SEED_REPLAY_CURSOR)),
                Some("0".to_string()),
                "the lap's reserved slice did not advance the durable replay \
                 cursor, so the replay still runs only when it wins a gate \
                 the scan lap holds for tens of minutes"
            );
            drop(held);
        });
    }

    #[test]
    fn indexer_off_is_idle_not_stalled() {
        // The ten-minute stall WARN in `spawn` fires on any pass that
        // names a gate. With the indexer and Spotnet both off the
        // replay is not owed, so the pass must name nothing; with the
        // indexer ON but paused it must still name the gate.
        with_daemon("idle-off", |d| {
            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            let mut state = HarvestState::new(d.index_era());
            let report = tick(d, &mut state);
            assert!(report.blocked, "{report:?}");
            assert_eq!(
                report.stalled_at, None,
                "an indexer that is OFF is not a starving replay - this \
                 is the line a Reddit user saw every ten minutes forever"
            );

            d.index_enabled.store(true, Ordering::Relaxed);
            d.index_paused.store(true, Ordering::Relaxed);
            let report = tick(d, &mut state);
            assert_eq!(
                report.stalled_at,
                Some("index maintenance is closed"),
                "a paused indexer still owes the replay and must say so"
            );
            d.index_paused.store(false, Ordering::Relaxed);
        });
    }
}
