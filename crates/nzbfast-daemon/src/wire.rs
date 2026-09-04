//! The active download's counters, and the one job that may still be
//! on the wire BEHIND it since the cross-job hand-over
//! (`nzbkit::pool::handoff`, `tasks/worker.rs`): the re-pointable
//! progress cell, the drain slot, and the per-row pairing that reads
//! them. Split out of daemon.rs for the size gate; every item is in
//! `Daemon`'s scope exactly as it was there.

use super::*;

/// What a job still on the wire behind the active one reports from -
/// see [`Daemon::drain_dl`].
pub struct DrainSlot {
    pub nzo_id: String,
    pub t_start: Instant,
    pub progress: Arc<AtomicU64>,
    pub counters: Arc<crate::streamhub::FetchCounters>,
    pub total: u64,
    pub resume_seeded: u64,
    /// Its pool's live gauges and stop handles, for the slow-job
    /// watchdog: the queue waits on THIS job, not the active one, so
    /// this is the job the defer verdict keeps judging.
    pub pool_live: Option<Arc<nzbkit::pool::LiveStats>>,
    pub abort: Option<Arc<AtomicBool>>,
    pub queue_ctl: Option<Arc<nzbkit::pool::QueueControl>>,
}

/// The active job's decoded-byte counter as a re-pointable cell. Reads
/// go through the same `load` spelling an `AtomicU64` has, so every
/// reader is unchanged; the runner calls [`ProgressCell::reset`]
/// at a job transition and hands the fresh counter to that job's
/// pipeline, which is the one thing a plain shared atomic could not do
/// (a zeroed shared counter credited the previous job's last articles
/// to the new job's bar).
#[derive(Default)]
pub struct ProgressCell(std::sync::Mutex<Arc<AtomicU64>>);

impl ProgressCell {
    pub fn load(&self, o: Ordering) -> u64 {
        self.0.lock_ok().load(o)
    }
    /// Re-point at a fresh zero counter and return it for the job that
    /// owns it from here. The previous counter lives on in whichever
    /// pipeline still holds it.
    pub fn reset(&self) -> Arc<AtomicU64> {
        let fresh = Arc::new(AtomicU64::new(0));
        *self.0.lock_ok() = fresh.clone();
        fresh
    }
}

impl Daemon {
    /// `(done, total, left)` for the row `nzo_id` if it is on the wire
    /// right now - the active download's counters, or the previous
    /// job's own while it drains behind it (the cross-job hand-over).
    /// `None` means "not on the wire": the caller falls through to the
    /// tail arm or the record.
    ///
    /// UX §15's published plan pair is preferred whenever the pipeline
    /// has one: both halves are declared NZB bytes of the run's article
    /// set, so the fraction reaches exactly 100% at net-drain and cannot
    /// pass it, and the seed already includes everything a resume had in
    /// hand. The arithmetic is the fallback, and it is why the plan
    /// exists: decoded payload over the NZB's encoded bytes minus
    /// recovery volumes stalls near 97% on a clean set.
    ///
    /// §91: the owner is read WITH the counters, under the one lock the
    /// writer sets both in, so no reader can pair a stale owner with the
    /// next job's zeroes - and the drain slot is written in that same
    /// section, so the same holds for it.
    pub fn wire_counters(&self, nzo_id: &str) -> Option<(u64, u64, u64)> {
        let owner = self.active_dl.lock_ok();
        // F5: a TOTAL of 0 is the NZB having declared no `bytes=` at
        // all, a shape this repo accepts on purpose and whose own
        // parser comment reads it as "unknown, not zero"
        // (`nzbkit::nzb`'s `<segment>` attribute block, and
        // `Nzb::geometry_bytes`). This guard was `total.max(1)`, which
        // is not a divide-by-zero defence - the only division is
        // `slot_progress`'s `pct_of`, which already answers with
        // `checked_div` - it is an unknown being turned into a
        // measurement, and into the WORST one: it clamps `done` to 1
        // and reports `(1, 1, 0)`, so the row read 100% with nothing
        // left for the whole of a download that had barely started.
        // Measured on the tree before this line changed: 5 MB fetched
        // against an undeclared total answered `Some((1, 1, 0))`.
        // "Pinned at 100% / 0 left with articles still in flight" is
        // the exact defect `get::plan`'s own UX §15 comment records
        // this pair being rebuilt to end, so this restores that
        // position rather than taking a new one. An unknown total is
        // reported AS unknown: `pct_of` then answers 0 and the
        // remainder is 0, which is what every other unknown on this
        // surface already renders as, and `done` is passed through
        // truthfully rather than clamped against a total nobody has -
        // which is also what `requeue_cost`'s refetch arm needs, since
        // it reads that figure and was seeing 1.
        let arith = |done: u64, total: u64| {
            if total == 0 {
                return (done, 0, 0);
            }
            (done.min(total), total, total.saturating_sub(done))
        };
        if owner.as_deref() == Some(nzo_id) {
            if let Some(honest) = self.hub.fetch_left() {
                return Some(honest);
            }
            // Bytes a resume never had to fetch. Counted here rather
            // than in the shared counter so that everything measuring
            // the WIRE (quota, average speed, best_rate_bps, the CLI
            // ticker, the rolling speed window) goes on seeing only what
            // this run actually moved. See StreamHub::resume_seeded.
            let done = self
                .progress
                .load(Ordering::Relaxed)
                .saturating_add(self.hub.resume_seeded.load(Ordering::Relaxed));
            return Some(arith(done, self.active_total.load(Ordering::Relaxed)));
        }
        let drain = self.drain_dl.lock_ok();
        let s = drain.as_ref().filter(|s| s.nzo_id == nzo_id)?;
        if let Some(honest) = s.counters.left() {
            return Some(honest);
        }
        let done = s
            .progress
            .load(Ordering::Relaxed)
            .saturating_add(s.resume_seeded);
        Some(arith(done, s.total))
    }

    /// Signal the DRAINING predecessor's detached stop handles, but only
    /// when the request names it. `hard` is the immediate abort (in-flight
    /// reads are dropped); otherwise the graceful drain. Returns whether a
    /// live `QueueControl` took the signal.
    ///
    /// `owns_hub` answers for the ACTIVE transfer alone, so from the
    /// instant the successor claims the hub every pause and delete aimed
    /// at the predecessor declined forever: its `abort`/`queue_ctl` moved
    /// into the drain slot and only the slow-job watchdog ever read them
    /// (`tasks/stall.rs`). Within the hand-over window - which can carry a
    /// large share of a job's remaining bytes - pause was a no-op that
    /// answered success, and a deleted job's metered traffic ran to its
    /// own end.
    ///
    /// The handles are cloned OUT and the slot lock dropped before
    /// anything is signalled, the way `stall::watched` does it, so no pool
    /// call happens under the drain-slot mutex. The successor is never
    /// touched: a slot whose `nzo_id` `want` rejects answers false.
    pub fn fire_drain(&self, hard: bool, want: impl Fn(&str) -> bool) -> bool {
        let (abort, ctl) = {
            let g = self.drain_dl.lock_ok();
            match g.as_ref().filter(|s| want(&s.nzo_id)) {
                Some(s) => (s.abort.clone(), s.queue_ctl.clone()),
                None => return false,
            }
        };
        if hard {
            if let Some(f) = &abort {
                f.store(true, Ordering::Relaxed);
            }
            ctl.is_some_and(|c| c.abort())
        } else {
            ctl.is_some_and(|c| c.drain())
        }
    }

    /// Is this job on the wire at all - the active hub, or the drain slot
    /// behind it? The ownership test for a caller that is going to steer
    /// EITHER slot; [`Self::owns_hub`] stays the test for a caller that
    /// only ever signals `hub.*`.
    pub fn owns_wire(&self, want: impl Fn(&str) -> bool) -> bool {
        self.owns_hub(&want)
            || self
                .drain_dl
                .lock_ok()
                .as_ref()
                .is_some_and(|s| want(&s.nzo_id))
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;
