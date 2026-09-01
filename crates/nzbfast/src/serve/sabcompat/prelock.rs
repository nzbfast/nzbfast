//! The reads `queue_json` takes BEFORE the queue lock (TODO 106).
//!
//! A child module of `sabcompat` rather than a sibling under `serve`,
//! because `hold_json` is private to sabcompat.rs and `use super::*` is
//! what keeps it reachable from here.

use super::*;

/// Everything `queue_json` reads BEFORE it takes the queue lock.
///
/// Lifted out of the payload builder whole (TODO 106) - it was 101 lines
/// of the function's 506 and it is one subject. Making it a function
/// turns the issue #38 deadlock invariant from a comment into structure:
/// every read in here provably happens before `d.queue.lock_ok()`,
/// because the lock is not in scope. Nothing is re-ordered - the reads
/// are in their original order and the call sits exactly where the first
/// one did - and the caller destructures back onto the inline names, so
/// every downstream read is untouched.
pub(super) struct PreLock {
    pub(super) live_shape: Option<(String, String)>,
    pub(super) pw_wanted: Option<String>,
    pub(super) health_defer: bool,
    /// §282 item 12: every row currently parked as a held alternate.
    /// Taken ONCE here, like everything else in this struct, so the
    /// per-row offer is a filter over a small Vec instead of a second
    /// walk of the queue under the queue lock. Empty on the
    /// overwhelmingly common install, where nothing is held at all.
    pub(super) alt_held: Vec<crate::serve::altcand::HeldSpare>,
    /// §282 item 20: `alt_auto_search`. Read here with the rest, for the
    /// rest's reason - one instant for the whole payload.
    pub(super) alt_auto_search: bool,
    pub(super) disk_now: Option<(u64, u64)>,
    pub(super) free_now: Option<u64>,
    pub(super) now_unix: u64,
    pub(super) hold: Option<Value>,
    pub(super) hold_quota_spent: Option<f64>,
    pub(super) sc: Option<(String, u64)>,
    /// What the early start is pulling right now, bytes/sec - the second
    /// series on the dashboard's throughput chart. 0 with no sidecar
    /// running. Sampled in the SAME read as `sc` above, so the rate and
    /// the byte count a row reports are one instant, like everything
    /// else here.
    pub(super) prefetch_bps: f64,
    pub(super) activity_map: std::collections::HashMap<String, &'static str>,
    pub(super) unpack_map:
        std::collections::HashMap<String, Arc<crate::unpackprog::UnpackProgress>>,
    pub(super) active_id: Option<String>,
    pub(super) stall: Option<(String, Instant)>,
    pub(super) pool_view: Vec<(String, usize, u64)>,
    pub(super) outages: Vec<ServerOutage>,
    /// TODO 309(b): `(nzo_id, cost)` for each job on the wire whose
    /// pause would cost its next run something, so the dashboard can say
    /// so BEFORE the click rather than after. EMPTY on every ordinary
    /// poll - see `Daemon::pause_cost`, which screens on bytes moved
    /// before it will look at a journal at all. Matched to its slot by
    /// id during the walk, the way `live_shape` and `sc` are.
    ///
    /// A LIST because the hand-over puts two jobs on the wire at once
    /// and pausing stops both - see `PauseCostState::owners`. At most
    /// two entries, and empty is the common case.
    pub(super) pause_cost: Vec<(String, crate::serve::requeue::RequeueCost)>,
}

pub(super) fn prelock_reads(d: &Daemon) -> PreLock {
    // The running job's live archive shape, straight off its extractor -
    // the badge updates the moment the first volume's headers parse, long
    // before anything is latched onto the Job at completion. Taken before
    // the queue lock so the hub's lock is never nested inside it, and read
    // once for the whole payload (it is matched to its owning slot below).
    let live_shape = d
        .hub
        .extractor
        .lock_ok()
        .as_ref()
        .and_then(|(owner, ex)| ex.archive_shape().map(|sh| (owner.clone(), sh.tag())));
    // The live "this download wants a password" owner tag (raised by the
    // in-stream probe when an encrypted set blocked with no working
    // candidate). Read once, matched per slot below - same pattern as
    // live_shape, and taken before the queue lock for the same reason.
    let pw_wanted = d.hub.password_wanted.lock_ok().clone();
    // §77: is the health sink switched on at all? Read once for the
    // whole payload rather than per slot.
    let health_defer = d.post_health_defer.load(Ordering::Relaxed);
    // §282 item 12, same rule: read once for the whole payload.
    let alt_held = d.alt_held_spares();
    // §282 item 20: whether a row with nothing held can still expect a
    // search when it finally fails. One atomic load per payload.
    let alt_auto_search = d.alt.auto_search.load(Ordering::Relaxed);
    // Free space on the output disk, read once per payload: feeds the
    // per-slot unpack-space check below. This is per-job arithmetic,
    // deliberately separate from the min_free floor (which holds the
    // whole queue and knows nothing about shapes).
    //
    // §91 again, and the reason this is the (free, total) walk rather
    // than a bare `free_bytes`: SAB's header carries both numbers for
    // the same disk, and a second statvfs of its own could report a
    // total that its own free exceeds. `free_bytes` IS this walk with
    // the total dropped, so nothing changes for the callers below.
    let disk_now = disk_stat_walk(&d.out_dir());
    let free_now = disk_now.map(|(free, _)| free);
    // Wall-clock now, once per payload: the slots' `time_added` is
    // derived from each job's monotonic `queued_at` against it (issue
    // #34 - SAB carries an absolute add time and we kept only an
    // Instant).
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Why nothing is starting, if the scheduler is holding the queue -
    // the dashboard renders this instead of an unexplained "idle".
    // One read of the hold, two answers off it: the dashboard's own
    // {kind, a, b} card, and - when the kind is "quota" - the GB
    // already spent, which is the only live view this payload has of
    // SAB's `left_quota`.
    let (hold, hold_quota_spent) = {
        let h = d.queue_hold.lock_ok();
        (
            h.as_ref().map(|(k, a, b)| hold_json(k, *a, *b)),
            h.as_ref()
                .filter(|(k, _, _)| k == "quota")
                .map(|(_, spent, _)| *spent),
        )
    };
    // Prefetch sidecar state, matched by nzo_id per slot below, plus its
    // own live rate off the same read - see `PreLock::prefetch_bps`.
    // ONE lock of the sidecar mutex, taken here with everything else,
    // because a second read under the queue lock is the issue #38
    // ordering this whole function exists to keep.
    let (sc, prefetch_bps) = d
        .sidecar
        .lock_ok()
        .as_ref()
        .map(|s| {
            (
                Some((s.nzo_id.clone(), s.progress.load(Ordering::Relaxed))),
                s.rate_bps(),
            )
        })
        .unwrap_or((None, 0.0));
    // Queue-row activity: the pipeline's own token per job, the hub
    // owner, an open stall episode, and a per-server pool view - all
    // read BEFORE the queue lock like live_shape above. The fetch
    // refinement below (connecting/reconnecting/waiting) only ever
    // applies to the job that owns the hub.
    //
    // "Before the queue lock" is a deadlock invariant, not a style note
    // (issue #38): these reads once drifted below `let q = ...`, which
    // put a queue -> active_stream edge in this handler while the media
    // prober held active_stream and asked for the queue - and one
    // mode=queue poll landing in a job-completion queue-lock convoy
    // froze both sides, and with them the whole HTTP worker pool, for
    // good. Nothing here needs the queue's instant anyway: every value
    // is re-matched to its owning slot by nzo_id during the walk.
    let activity_map = d.hub.activity.lock_ok().clone();
    // TODO 205: and the disk-unpack ladder's live counters beside it,
    // under the same before-the-queue-lock rule as everything here.
    // Handles, not a snapshot - the counters advance in place, so the
    // row reads them at render time and this stays one cheap clone of a
    // map that holds at most one entry per unpacking job.
    let unpack_map = d.hub.unpack.lock_ok().clone();
    let active_id = d.active_stream.lock_ok().clone();
    let stall = d.stall_since.lock_ok().clone();
    let pool_view: Vec<(String, usize, u64)> = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| {
            l.servers
                .iter()
                .map(|s| {
                    (
                        s.host.clone(),
                        s.connected.load(Ordering::Relaxed),
                        s.bytes.load(Ordering::Relaxed),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    // Same instant as the pool view above, and read the same way: once,
    // before the queue lock.
    let outages = server_outages(d);
    // TODO 309(b), and it belongs in here rather than in the walk for
    // this module's own reason: it must not reach into the queue, and it
    // does not - the runner leaves the out_dir it needs beside the wire
    // owner.
    let pause_cost = d.pause_cost();
    PreLock {
        live_shape,
        pw_wanted,
        health_defer,
        alt_held,
        alt_auto_search,
        disk_now,
        free_now,
        now_unix,
        hold,
        hold_quota_spent,
        sc,
        prefetch_bps,
        activity_map,
        unpack_map,
        active_id,
        stall,
        pool_view,
        outages,
        pause_cost,
    }
}
