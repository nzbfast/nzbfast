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
