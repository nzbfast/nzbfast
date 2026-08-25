//! Live-target admission (TODO 112, reworked under F-22): how many of a
//! server's spawned workers may dial RIGHT NOW is a COUNT held against
//! `ConnTarget`, not a slot ordinal. An [`Admitted`] guard is the unit;
//! `wait_for_slot` hands one out. A child module of `pool`, so `Shared`
//! and `run_over` are in scope as they were inline.

use super::*;

/// An admission under the live target (F-22): this worker counts toward
/// its server's `Shared::admitted` until the guard drops, at which
/// point the count falls and one parked worker is woken to take the
/// place. Admission is a COUNT, not a slot ordinal: a fixed-ordinal
/// rule (`slot < target`) left the job hanging whenever the one
/// admitted ordinal retired for good (session-attempt exhaustion, a
/// budget bow-out, a dead episode) while every other ordinal stayed
/// parked - the target never rises without bytes, and the parked
/// workers still counted as alive for the single-prober election, so
/// nobody dialled and the run never sealed.
pub(super) struct Admitted {
    shared: Arc<Shared>,
    idx: usize,
    pub(super) released: bool,
}

impl Admitted {
    /// Give the admission back if the server is over its target, in one
    /// atomic step so that of N workers seeing the same over-count
    /// exactly N-minus-target of them shed. Returns true when THIS
    /// worker is the one to quit; its guard is then spent (Drop is a
    /// no-op) and the caller should let it go.
    pub(super) fn try_shed(&mut self, target: usize) -> bool {
        if self.released {
            return false;
        }
        let shed = self.shared.admitted[self.idx]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |a| {
                (a > target).then_some(a - 1)
            })
            .is_ok();
        if shed {
            self.released = true;
            self.shared.admit_wake[self.idx].notify_one();
        }
        shed
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        if !self.released {
            self.shared.admitted[self.idx].fetch_sub(1, Ordering::SeqCst);
            self.shared.admit_wake[self.idx].notify_one();
        }
    }
}

/// A worker counted in [`Shared::parked`] for exactly as long as it is
/// blocked in [`wait_for_slot`] without an admission (TODO 277).
///
/// RAII, and for the same reason `WaiterGuard` in `handoff` is: the
/// wait below lives inside a `tokio::select!`, so the future can be
/// dropped mid-await, and every exit - a wake, the run ending, a panic
/// unwinding - has to give the count back.
struct Parked {
    shared: Arc<Shared>,
    idx: usize,
}

impl Parked {
    fn new(shared: &Arc<Shared>, idx: usize) -> Self {
        shared.parked[idx].fetch_add(1, Ordering::AcqRel);
        shared.parked_total.fetch_add(1, Ordering::AcqRel);
        Parked {
            shared: Arc::clone(shared),
            idx,
        }
    }
}

impl Drop for Parked {
    fn drop(&mut self) {
        self.shared.parked[self.idx].fetch_sub(1, Ordering::AcqRel);
        self.shared.parked_total.fetch_sub(1, Ordering::AcqRel);
    }
}

impl PoolConfig {
    /// The sockets this server's fleet INTENDS to hold right now: the
    /// live target where there is one, else the spawn count. It lives
    /// in the admission module because the gap between the two IS a
    /// parked worker, which is this module's subject.
    ///
    /// The two part company because a fleet may be SPAWNED above the
    /// number it runs at, so that a live target can later be raised
    /// into slots that already exist - TODO 112's `live_tune` walker
    /// and, since TODO 277, the line-cap seed, which spawns the fleet
    /// curve's ceiling and runs at the curve's own number. Every
    /// surplus worker parks holding nothing, so `connections` is the
    /// wrong answer to "how many connections is this run asking a
    /// provider for" - it is the answer to "how many slots exist".
    pub fn dialled(&self) -> usize {
        self.live_target
            .as_ref()
            .map_or(self.connections, |t| t.get().min(self.connections))
    }
}

impl Shared {
    /// How many of this run's workers are actually able to move bytes:
    /// live, minus the ones parked under a live target holding no
    /// connection (TODO 277).
    ///
    /// **This is the divisor, and `workers_live` is not.** Two shipped
    /// quantities size themselves off "how many ways is the line split
    /// right now", and TODO 277's seed spawns the fleet curve's ceiling
    /// while running at its floor - so on a five-provider install the
    /// spawned count is 50 where the fleet holding sockets is 25.
    /// Handing them the spawned count would have moved BOTH, silently,
    /// on every install:
    ///
    /// * [`Shared::stall_bound_at`] divides the line by the sharer
    ///   count to size one article's expected time. Twice the count is
    ///   twice the deadline, which weakens the §208.2 rescue that is
    ///   the only thing a wedged last-article has - and it was tuned on
    ///   the count this restores.
    /// * [`Shared::tail_window`] tapers on `pending / (2 x live)`.
    ///   Twice the count halves the depth at which the taper starts
    ///   biting, so a fleet that parks its surplus would taper twice as
    ///   early for no reason the measurement knows about.
    ///
    /// Both are therefore left on the count they were measured with,
    /// which is what this returns. That is not a stand-still: it is
    /// also a correction to TODO 112's `live_tune`, which has always
    /// spawned above its target and has always over-counted here - and
    /// both corrections move toward the flat, untapered shipped
    /// behaviour rather than away from it, because the stall bound is
    /// floored at `ADAPTIVE_STALL` and the taper is ceilinged at
    /// `base`.
    ///
    /// Scope is the ADMISSION park alone. A worker parked in
    /// `park_or_probe` (the capacity yield) also holds no connection
    /// and is deliberately not counted: that shape shipped long before
    /// this counter and nothing about the fleet curve changes how often
    /// it happens, so folding it in would move numbers this change has
    /// no business moving.
    pub(super) fn workers_dialling(&self) -> usize {
        self.workers_live
            .load(Ordering::Relaxed)
            .saturating_sub(self.parked_total.load(Ordering::Relaxed))
    }

    /// [`Shared::workers_dialling`] for one server: its `alive` count
    /// less the workers of it parked without an admission. None when
    /// `si` is not a server of this run.
    ///
    /// The per-server twin exists because two more shipped quantities
    /// divide by `alive` - [`Shared::rate_per_worker`] and
    /// [`Shared::srv_rate_per_worker`], which are what every steering,
    /// racing and session-recycle gate compares servers by. A parked
    /// worker delivers nothing, so counting it there reads a server as
    /// slower per connection than it is, and the recycle slope
    /// (`0.25 x fleet`) would stop rotating degraded sessions.
    ///
    /// Every OTHER reader of `alive` is a presence test (`> 0`) and is
    /// right as it stands, with one that is worth naming because it
    /// looks like a count: `want_handoff`'s `alive > 1`, which keeps
    /// one worker on the server for a requeue. A parked worker satisfies
    /// that honestly - it takes the admission the handing-off worker
    /// released and dials - so it belongs in that count and not here.
    pub(super) fn workers_dialling_on(&self, si: usize) -> Option<usize> {
        let alive = self.alive.get(si)?.load(Ordering::Relaxed);
        Some(alive.saturating_sub(self.parked.get(si)?.load(Ordering::Relaxed)))
    }
}

/// Park this worker until its server has an admission free under the
/// live target. Returns None if the run ended (or began draining)
/// while parked - the caller must retire, not dial.
///
/// The caller has already returned any connection it held: a parked
/// worker costs the provider nothing.
pub(super) async fn wait_for_slot(
    target: &ConnTarget,
    idx: usize,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    shared: &Arc<Shared>,
) -> Option<Admitted> {
    let mut rx = target.subscribe();
    // Armed on the first turn that fails to admit, so a worker that
    // takes a slot straight away is never counted as parked (TODO 277).
    // Dropped on every exit from this function, which is what makes the
    // count safe to divide by.
    let mut parked: Option<Parked> = None;
    loop {
        let t = *rx.borrow_and_update();
        let admitted = shared.admitted[idx]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |a| {
                (a < t).then_some(a + 1)
            })
            .is_ok();
        if admitted {
            return Some(Admitted {
                shared: Arc::clone(shared),
                idx,
                released: false,
            });
        }
        parked.get_or_insert_with(|| Parked::new(shared, idx));
        tokio::select! {
            r = rx.changed() => {
                // Controller gone with the target parked low: admit the
                // worker rather than strand it. The sender lives inside
                // the PoolConfig clones, so in practice this outlives
                // the run.
                if r.is_err() {
                    shared.admitted[idx].fetch_add(1, Ordering::SeqCst);
                    return Some(Admitted {
                        shared: Arc::clone(shared),
                        idx,
                        released: false,
                    });
                }
            }
            _ = shared.admit_wake[idx].notified() => {}
            _ = run_over(finished, shared) => return None,
        }
    }
}
