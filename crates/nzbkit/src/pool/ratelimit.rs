//! The pool-level download speed limiter (M14g). Moved out of
//! `pool.rs` whole under the size gate; the code is verbatim, the
//! public path (`pool::RateLimit`) is re-exported unchanged.

use super::*;

/// Pool-level download speed limiter (M14g): one shared coarse token
/// window charged by every worker of every server after each article body
/// read. 0 = unlimited. Deliberately cheap and coarse (±10% is fine) -
/// one mutex'd (window_start, bytes) pair, workers sleep off any debt
/// asynchronously so runtime threads are never blocked.
pub struct RateLimit {
    bytes_per_sec: AtomicU64,
    /// Virtual clock: the instant the next charged byte is allowed to
    /// land. See [`RateLimit::throttle`].
    next: std::sync::Mutex<Instant>,
    /// Bumped whenever the cap changes, so a worker already sleeping
    /// against the OLD cap stops waiting instead of stranding.
    generation: AtomicU64,
    /// Test seam (F-11): parks a worker between the unlocked fast-path
    /// cap load and the locked pricing - the gap the pre-fix code
    /// carried its price across while `set` swapped cap, clock and
    /// generation. Two-stage shape as `Shared::drain_send_barrier`.
    #[cfg(test)]
    pub(super) reserve_barrier:
        std::sync::Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            bytes_per_sec: AtomicU64::new(0),
            next: std::sync::Mutex::new(Instant::now()),
            generation: AtomicU64::new(0),
            #[cfg(test)]
            reserve_barrier: std::sync::Mutex::new(None),
        }
    }
}

impl RateLimit {
    pub fn new(bytes_per_sec: u64) -> Arc<RateLimit> {
        let rl = RateLimit::default();
        rl.set(bytes_per_sec);
        Arc::new(rl)
    }

    /// Change the cap live. 0 = unlimited.
    ///
    /// A change restarts the virtual clock and bumps the generation:
    /// reservations priced against the old cap are neither re-priced nor
    /// left holding workers, which is what the old 5-second sleep clamp
    /// was reaching for.
    ///
    /// The `next` mutex is the coherence point (F-11): cap, clock and
    /// generation all move under it, and `throttle` re-reads cap and
    /// generation under the same lock, so a reservation is never priced
    /// at one cap and then tagged with the other's generation.
    pub fn set(&self, bytes_per_sec: u64) {
        let mut next = self.next.lock_ok();
        if self.bytes_per_sec.swap(bytes_per_sec, Ordering::Relaxed) == bytes_per_sec {
            return;
        }
        *next = Instant::now();
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.bytes_per_sec.load(Ordering::Relaxed)
    }

    /// Test window onto the virtual clock: the instant the last-priced
    /// reservation runs to. What it sits at AFTER a mid-reservation
    /// `set` is the F-11 question - a price carried across the swap
    /// lands old-cap debt on the fresh clock, where every later worker
    /// queues behind it.
    #[cfg(test)]
    pub(super) fn debt_horizon(&self) -> Instant {
        *self.next.lock_ok()
    }

    /// Charge `n` bytes against the cap and sleep off any debt so the
    /// aggregate rate stays under `bytes_per_sec`. No-op when unlimited.
    ///
    /// A virtual clock, not a byte window: each charge reserves the slice
    /// of wall time its own bytes are worth AT THE CAP IN FORCE WHEN IT
    /// IS CHARGED, and the caller waits out that slice. N workers
    /// therefore queue behind one another and the aggregate rate is the
    /// cap by construction, at any connection count or article size.
    ///
    /// The byte-window version this replaces could not do that. Its sleep
    /// was clamped to 5 s so that a live cap decrease could not strand a
    /// worker against stale debt - but nothing ever forgave that debt,
    /// and its only discharge path (the re-anchor) required the window to
    /// be paid off, which the clamp itself made unreachable. Once the
    /// aggregate settled above the cap it stayed there: every call slept
    /// exactly 5 s forever and the real floor was `connections *
    /// article_size / 5 s` - about 1.28 MB/s at the shipped default of 8
    /// connections, so any cap under ~10 Mbit/s was silently exceeded
    /// with no log line. It also made the --auto-speed governor's whole
    /// back-off range a no-op, since AUTO_SPEED_FLOOR sits inside it.
    /// Forgiving the debt and enforcing the cap are mutually exclusive in
    /// that formulation, which is why the clamp looks reasonable and is
    /// nonetheless wrong; pricing each charge when it is charged removes
    /// the need for either.
    pub async fn throttle(&self, n: u64) {
        // Unlocked fast path for the unlimited case; the authoritative
        // cap and generation are re-read under the lock (F-11).
        if self.bytes_per_sec.load(Ordering::Relaxed) == 0 || n == 0 {
            return;
        }
        #[cfg(test)]
        {
            let pair = self.reserve_barrier.lock_ok().clone();
            if let Some((entered, released)) = pair {
                entered.wait();
                released.wait();
            }
        }
        let (deadline, generation) = {
            let mut next = self.next.lock_ok();
            let cap = self.bytes_per_sec.load(Ordering::Relaxed);
            if cap == 0 {
                return;
            }
            let generation = self.generation.load(Ordering::Relaxed);
            let now = Instant::now();
            // `.max(now)` is what stops an idle line banking credit: a
            // clock left behind in the past resumes from now, not from
            // where it stopped.
            let start = (*next).max(now);
            *next = start + Duration::from_secs_f64(n as f64 / cap as f64);
            (*next, generation)
        };
        // Sliced rather than one long sleep so that a live cap change is
        // noticed within a second even when the reservation is minutes
        // long (a very low cap against a large article).
        loop {
            let now = Instant::now();
            if now >= deadline || self.generation.load(Ordering::Relaxed) != generation {
                return;
            }
            tokio::time::sleep((deadline - now).min(Duration::from_secs(1))).await;
        }
    }
}
