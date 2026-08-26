//! WHEN INDEX MAINTENANCE MAY RUN, and how a statement already running
//! is stood down. One subject asked at three ranges.
//!
//! Before a pass begins: [`Daemon::index_maintenance_ok`] and
//! [`Daemon::db_maintenance_ok`], two predicates and the trap that
//! keeps them apart. Before the one rewrite that also needs disk to
//! land: [`CompactVerdict`] and [`compact_verdict`], with
//! [`COMPACT_CHUNK_PAGES`] bounding how long a download can wait for a
//! chunk. And for a statement ALREADY executing: the rendezvous between
//! it and the watcher that may need to abort it (Codex sweep 3 Aug M5) -
//! the `MaintenanceArm` both sides go through, and the watcher itself,
//! polling at [`COMPACT_ABORT_POLL_MS`]. That last range is the case the
//! other two structurally cannot reach, because by then the rewrite
//! holds the gate the download worker blocks on.
//!
//! Grew from the rendezvous alone to the whole subject on 25 Aug 2026,
//! by two lanes an hour apart. `ae6d4e5a6` moved the rendezvous here
//! while another lane was moving all three ranges to a file of its own;
//! theirs landed on origin first, so the wider split was rebuilt into
//! THIS module rather than beside it. One subject, one module - the
//! alternative was two files whose names both describe the same
//! question.
//!
//! Split out of daemon.rs rather than left in it (TODO 106 code motion,
//! size gate): that file was over its slack on 25 Aug 2026 and the
//! numbers only go down. Same seam daemon_evict.rs and daemon_index.rs
//! already moved along. Most of it owes nothing to `Daemon` at all,
//! which is why the rendezvous is testable without a database; the two
//! predicates that DO are a second `impl Daemon` in a child module of
//! `daemon`, on the daemon_idle and daemon_index shape, so `Daemon`'s
//! private fields stay in scope exactly as they were inline.
//! `pub(super)` became `pub(in crate::serve)` for that reason - `super`
//! is `daemon` from inside the child, and every call site is one level
//! up - and every item is re-exported from daemon.rs, so every existing
//! `daemon::` and `super::` path still resolves.
//!
//! Indexer-only, like everything it talks to: the whole file is behind
//! the callers' own `#[cfg(feature = "indexer")]`, kept ON THE ITEMS
//! rather than on the `mod` declaration so the slim build sees exactly
//! what it saw when these sat inline. The import carries the gate for
//! the same reason it carries every item: with the file cfg'd away to
//! nothing, a bare `use super::*` is an unused import, and the slim
//! build is one of the few places anything ever compiles this empty.

#[cfg(feature = "indexer")]
use super::*;

/// The rendezvous between a maintenance statement and the watcher that
/// may need to abort it (Codex sweep 3 Aug M5).
///
/// An interrupt handle is per CONNECTION, not per statement, so handing
/// the watcher a handle taken during an EARLIER `with_index` call was
/// two bugs at once: a job starting before the maintenance closure
/// reacquired the index mutex interrupted whatever unrelated writer
/// held it in the gap (that write rolled back for nothing), and the
/// maintenance then began anyway, with the job now active and the
/// watcher already retired - the multi-minute stall the whole mechanism
/// exists to prevent.
///
/// Both sides go through this one mutex, so exactly one of them wins:
/// either the statement arms first (and the watcher's interrupt lands
/// on it and nothing else), or the watcher stands the statement down
/// first (and it never runs).
#[cfg(feature = "indexer")]
#[derive(Default)]
pub(in crate::serve) struct MaintenanceArm {
    inner: Mutex<MaintenanceArmState>,
}

#[cfg(feature = "indexer")]
#[derive(Default)]
struct MaintenanceArmState {
    handle: Option<nzbkit::index::InterruptHandle>,
    stood_down: bool,
}

#[cfg(feature = "indexer")]
impl MaintenanceArm {
    /// Called from the blocking task while it HOLDS the index guard,
    /// immediately before the statement. `false` means a job appeared
    /// first and the statement must not run at all.
    pub(in crate::serve) fn arm(&self, handle: nzbkit::index::InterruptHandle) -> bool {
        let mut st = self.inner.lock_ok();
        if st.stood_down {
            return false;
        }
        st.handle = Some(handle);
        true
    }

    /// Called from the blocking task once the statement has returned,
    /// still holding the guard: a later interrupt must not land on
    /// whatever this connection does next.
    pub(in crate::serve) fn disarm(&self) {
        self.inner.lock_ok().handle = None;
    }

    /// Called from the watcher when a download starts. Interrupts the
    /// armed statement if there is one, and in every case makes a
    /// not-yet-armed statement stand down.
    pub(in crate::serve) fn abort(&self) {
        let mut st = self.inner.lock_ok();
        st.stood_down = true;
        if let Some(h) = st.handle.take() {
            h.interrupt();
        }
    }
}

/// Watch for a download starting while a VACUUM is in flight, and abort
/// the rewrite when one does. Returns true if it aborted.
///
/// `compact_verdict` asks whether a download is running BEFORE the
/// rewrite begins, and there is nothing it can do about a job that
/// arrives one moment later - by then the rewrite holds the gate that
/// the download worker blocks on, so the job sits in `Downloading` with
/// no progress and no log line for as long as the rewrite lasts. This is
/// the other half of that check: the same question, asked continuously,
/// with an answer that can still act.
///
/// `abort` is a closure rather than the interrupt handle itself so this
/// can be tested without a database - and so the caller keeps the
/// decision about WHICH connection it is entitled to interrupt.
#[cfg(feature = "indexer")]
pub(in crate::serve) async fn abort_compact_when_job_starts(
    jobs: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
    abort: impl Fn(),
) -> bool {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(COMPACT_ABORT_POLL_MS)).await;
        // Checked first: once the rewrite is over there is no statement
        // to interrupt, and interrupting is per-connection - a late
        // abort would hit whatever the index is doing next.
        if done.load(Ordering::Acquire) {
            return false;
        }
        if jobs.load(Ordering::Acquire) > 0 {
            abort();
            return true;
        }
    }
}

/// Is this a moment a VACUUM may run in? The engine's `compact()` doc
/// puts the burden on the caller: it exclusive-locks and rewrites the
/// whole file, so anything else touching the database waits it out.
/// Split out from the loop so the "defer while busy, fire when idle"
/// rule is testable on its own.
#[cfg(feature = "indexer")]
#[derive(Debug, PartialEq, Eq)]
pub enum CompactVerdict {
    /// Nothing to do - no prune has asked for it.
    NotNeeded,
    /// A scan pass or a download is in flight; wait.
    Busy(&'static str),
    /// VACUUM wants up to twice the database size in temp space and this
    /// runs on NAS boxes with 8 GB of headroom. Stay deferred rather
    /// than half-rewrite the file onto a full volume.
    NoRoom {
        need: u64,
        free: u64,
    },
    Go,
}

/// How often the compact watcher looks for a foreground job. The whole
/// point is that a download does not visibly stall, so this is the worst
/// case the user could see - it wants to be well under the moment it
/// takes them to notice, and it costs one relaxed atomic load per tick.
#[cfg(feature = "indexer")]
pub(in crate::serve) const COMPACT_ABORT_POLL_MS: u64 = 100;

/// §95: how much of the freelist one `compact_chunk` reclaims, in pages.
///
/// This is the worst case a download can wait for the compactor, so it
/// is the whole quality of the feature: the loop checks for a job
/// between chunks, and a chunk cannot be cut short.
///
/// 2048 pages is 8 MB at the default 4 KB page size. Measured by
/// `nzbkit/tests/integration/compact_abort_latency.rs` on a 1.16 GB index: 66
/// chunks, worst single chunk 169 ms, and across a sweep of arrival
/// offsets the worst a job actually waited was 113 ms - against 4061 ms
/// for the VACUUM path it replaces, which also failed to stop at all
/// for 3 of 9 arrivals. Same order as the COMPACT_ABORT_POLL_MS the old
/// design already accepted, and far below the moment a user notices.
///
/// Chunk cost grows with the FILE, not with this number alone: the same
/// 2048 pages took 67 ms on a 103 MB index and 169 ms on a 1.16 GB one,
/// because the pages being moved are scattered further apart. So this
/// bound is soft at the top end - halve it if a really large index ever
/// makes the wait visible.
///
/// Smaller is not free: each chunk is its own write transaction and
/// truncate. At this size the whole chunked pass costs ~40% more than
/// the single VACUUM did (5991 ms vs 4218 ms on that 1.16 GB index),
/// which is the right trade for idle work that is now both abortable
/// and resumable.
#[cfg(feature = "indexer")]
pub(in crate::serve) const COMPACT_CHUNK_PAGES: u32 = 2048;

/// `needs_scratch` is the FullRewrite path: only a VACUUM writes a
/// second copy of the database beside the original. §95's chunked path
/// moves pages down inside the file it already has and truncates, so
/// asking a nearly-full volume for twice the file would defer it
/// forever - on exactly the small NAS volumes where reclaiming the space
/// matters most, and where `compact_pending` being sticky means the
/// deferral is silent and permanent.
#[cfg(feature = "indexer")]
pub fn compact_verdict(
    pending: bool,
    scanning: bool,
    downloading: bool,
    db_bytes: u64,
    free: Option<u64>,
    needs_scratch: bool,
) -> CompactVerdict {
    if !pending {
        return CompactVerdict::NotNeeded;
    }
    if downloading {
        return CompactVerdict::Busy("a download is running");
    }
    if scanning {
        return CompactVerdict::Busy("a scan pass is running");
    }
    if !needs_scratch {
        // Chunked: each chunk commits and shortens the file, so the
        // high-water mark is the file itself. Nothing to reserve.
        return CompactVerdict::Go;
    }
    // SQLite writes the rebuilt database beside the original and only
    // then swaps, so peak usage is ~2x. The 64 MB on top covers the
    // journal and keeps a nearly-full volume from being taken to zero.
    let need = db_bytes.saturating_mul(2).saturating_add(64 << 20);
    match free {
        // free_bytes answering None means we could not measure the
        // volume at all. Proceeding blind is how the min-free guard
        // once filled the disk it was protecting; stay deferred.
        None => CompactVerdict::NoRoom { need, free: 0 },
        Some(f) if f < need => CompactVerdict::NoRoom { need, free: f },
        Some(_) => CompactVerdict::Go,
    }
}

/// The two "is this a moment for it" predicates - the earliest of this
/// module's three ranges, and the only part of it that needs `Daemon`.
#[cfg(feature = "indexer")]
impl Daemon {
    /// Safe to run heavy index maintenance (prune, reseed, compact) right
    /// now? Two separate questions that one pause predicate cannot answer.
    /// Indexing must be enabled - that is user preference - AND no
    /// download may be in flight, which is a hard constraint REGARDLESS of
    /// the pause preference: with "pause while downloading" switched off,
    /// `indexing_pause_reason()` is None during a job, so gating on it
    /// alone let a prune run straight through somebody's download.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn index_maintenance_ok(&self) -> bool {
        self.indexing_pause_reason().is_none()
            && self.index_jobs_active.load(Ordering::Acquire) == 0
    }

    /// May maintenance of the SHARED index database run right now
    /// (sweep 8, L12, and its policy half)?
    ///
    /// [`index_maintenance_ok`] is the wrong predicate for anything the
    /// database owns jointly, and wrong in the exact configuration the
    /// finding is about: it goes through [`indexing_pause_reason`],
    /// which answers `Some("off")` whenever `index_enabled` is false -
    /// which is what a Spot-only install IS. Gating on it would leave
    /// the work permanently paused there, which is the state the
    /// finding describes, so the suggested fix would have changed
    /// nothing. That trap is why this is a separate predicate rather
    /// than a tweak to the one above; the tests in
    /// `tasks/picker_index_tests.rs` pin the correction as well as the
    /// fix.
    ///
    /// The database is shared: [`index_db_wanted`] keeps it for EITHER
    /// source, both sources write releases into the same tables, and
    /// every reader - browse, wall, newznab, the picker - reads it the
    /// same way whichever filled it. So the gate is "some scan source
    /// is live and nothing is downloading" - if either pause predicate
    /// is clear then this machine is not offline, not paused and not
    /// standing down for a job, because both carry all three of those.
    ///
    /// Named for the DATABASE, not the picker, since 22 Aug 2026: the
    /// retention reap, the planner-statistics refresh and the shatter
    /// fold are on it too. They are properties of the rows, and a
    /// spot-promoted release row is the same row a scanned one is.
    ///
    /// [`index_maintenance_ok`]: Daemon::index_maintenance_ok
    /// [`indexing_pause_reason`]: Daemon::indexing_pause_reason
    /// [`index_db_wanted`]: Daemon::index_db_wanted
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn db_maintenance_ok(&self) -> bool {
        self.index_db_wanted()
            && self.index_jobs_active.load(Ordering::Acquire) == 0
            && (self.indexing_pause_reason().is_none() || self.spot_pause_reason().is_none())
    }
}
