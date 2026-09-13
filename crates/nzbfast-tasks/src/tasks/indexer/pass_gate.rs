//! The scan lap's hold on `index_pass_gate`, and the handback that lets
//! a peer lane in between the lap's stages.
//!
//! `index_pass_gate` is documented as a rendezvous rather than a
//! resource: a starting download raises `begin_index_job` and every
//! holder stands down for it. That contract works, and the lap already
//! honours it at six points. What it never covered is the OTHER lanes
//! that were later hung on the same mutex to serialise their SQLite
//! writes against the scan - the tip watcher, the index compactor, the
//! seed-harvest replay. For those the gate IS a resource, and a
//! resource whose only holder lets go once a lap has no fairness
//! property at all.
//!
//! Measured on the live :6789 daemon, 2 Sep 2026
//! (research/INDEX-LAP-DUTY-CYCLE-2026-09-02.md): the lap took the gate
//! for 1,517-2,538 s at a stretch against a 900 s interval, so every
//! peer's duty cycle was `interval / (interval + lap work)` - 28.6% at
//! its worst. The tip watcher is configured for one pass per 25 s and
//! measured one per 71 s across the cycle, in bursts that started and
//! stopped within seconds of the lap's `lap work` lines.
//!
//! The handback is an explicit `drop` and re-`lock`, never a gap left
//! open in the hope a waiter polls into it: tokio's mutex is a FIFO
//! semaphore, so the release hands the permit to the queued waiter
//! directly and the re-`lock` goes to the back of that queue. The
//! passive version does not work and has been measured not working -
//! research/FOLD-HTTP-WRITE-PROBE-2026-09-02.md found the write mutex
//! free for microseconds between fold slices and an HTTP index write
//! refused across the whole fold regardless.
//!
//! Uncontended it costs one atomic swap and no await point, which is
//! what makes it affordable between all ~200 maintenance slices.

use super::*;

/// The lap's gate hold. Drop it to release the gate for good; call
/// [`PassGate::handback`] to release it and take it again, which lets
/// any queued peer through first.
///
/// Owns its guard rather than borrowing the mutex, so it can be handed
/// down into [`super::maintenance_slice`] and the loops inside it.
#[cfg(feature = "indexer")]
pub(crate) struct PassGate {
    gate: Option<Arc<tokio::sync::Mutex<()>>>,
    held: Option<tokio::sync::OwnedMutexGuard<()>>,
}

#[cfg(feature = "indexer")]
impl PassGate {
    /// Take the gate, waiting for it. The lap's first act.
    pub(crate) async fn acquire(gate: &Arc<tokio::sync::Mutex<()>>) -> Self {
        Self {
            gate: Some(gate.clone()),
            held: Some(gate.clone().lock_owned().await),
        }
    }

    /// A handle over no gate at all, for the tests that call the lap's
    /// legs directly. Every method is a no-op on it, so a test drives
    /// exactly the leg it means to and nothing queues behind it.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self {
            gate: None,
            held: None,
        }
    }

    /// Release the gate and take it again, yielding to any lane already
    /// queued for it.
    ///
    /// Only safe where the lap is between stages - see the resumability
    /// argument at each call site. After this returns the world may have
    /// moved: a download may have started, the index may have been
    /// closed or compacted. Every caller re-asks its own predicates
    /// (`ok()`, `waiting()`) on the next turn of its loop, and every leg
    /// reads its cursor back out of the database rather than carrying it
    /// in memory.
    pub(crate) async fn handback(&mut self) {
        let Some(gate) = self.gate.clone() else {
            return;
        };
        // Drop FIRST and in its own statement: `self.held = Some(..)`
        // would evaluate the new guard while the old one is still held,
        // which is a deadlock and not a handback.
        self.held = None;
        self.held = Some(gate.lock_owned().await);
    }
}

// The two tests below are the behavioural half of this item: that a
// peer queued behind the lap gets in at the next handback, and that it
// gets in BEFORE the lap's next stage runs.
#[cfg(all(test, feature = "indexer"))]
mod tests {
    use super::*;

    /// A waiter queued while the lap holds the gate acquires it at the
    /// lap's next handback, not at the end of the lap.
    ///
    /// Deliberately a current-thread runtime: the waiter can only run
    /// when this task awaits, so "the waiter got in" cannot be a lucky
    /// interleaving on a second core - it can only be the handback's
    /// own await point, which is the thing under test.
    #[test]
    fn a_queued_waiter_gets_in_at_the_handback() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gate = Arc::new(tokio::sync::Mutex::new(()));
            let mut lap = PassGate::acquire(&gate).await;
            let got = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (g2, got2) = (gate.clone(), got.clone());
            let peer = tokio::spawn(async move {
                let _held = g2.lock().await;
                got2.store(true, Ordering::SeqCst);
            });
            // Let the peer reach `lock().await` and queue.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                !got.load(Ordering::SeqCst),
                "the lap holds the gate: nothing else may have it"
            );
            lap.handback().await;
            assert!(
                got.load(Ordering::SeqCst),
                "a peer queued behind the lap must get the gate at the \
                 handback - it is the only window it has until the lap ends"
            );
            // And the lap has it back, so its next stage runs under it.
            drop(lap);
            peer.await.unwrap();
        });
    }

    /// The uncontended handback keeps the gate. A lap that dropped it to
    /// nobody and came back without it would run its next stage
    /// unguarded, which is the failure this whole gate exists to refuse.
    #[test]
    fn an_uncontended_handback_comes_back_holding_it() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gate = Arc::new(tokio::sync::Mutex::new(()));
            let mut lap = PassGate::acquire(&gate).await;
            lap.handback().await;
            assert!(
                gate.try_lock().is_err(),
                "after an uncontended handback the lap must still hold the gate"
            );
        });
    }
}
