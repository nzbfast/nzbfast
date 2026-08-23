//! Cross-job connection hand-over: how job N's idle connections become
//! job N+1's working ones while N is still draining.
//!
//! **The shape this replaces.** A run spawns one worker per configured
//! connection and every worker keeps its socket until the run's last
//! article is terminal. Once the queue is dry (every article handed
//! out) the fleet empties unevenly - a fast provider's connections
//! finish their `window` articles in seconds while a slow one's hold
//! theirs for a minute - and each connection that finishes early sits
//! in a 25 ms idle loop with nothing to fetch but duplicates of what
//! the slow ones still hold. Measured on the 22 Aug 2026 class F legs:
//! ~400 MB of duplicate bodies per 1 GB job, and the next job's fleet
//! does not dial until the run returns. The line is full of duplicate
//! bytes, then briefly empty, at every queue boundary.
//!
//! **The shape now.** Two pieces, both inert unless a caller wires them:
//!
//! - [`ConnBudget`] is one per daemon and per host: the account's
//!   connection cap as a pool of [`Permit`]s. A primary worker takes a
//!   permit before it claims or dials a socket and holds it for as long
//!   as it has one, so two runs on the same host can never hold more
//!   sockets between them than one run was allowed. The successor's
//!   workers block on `acquire` until the predecessor's release theirs.
//! - [`HandoffSignal`] is one per run: latched the first time a primary
//!   worker finds itself idle after queue-dry. That - not the dry latch
//!   itself - is the moment the fleet starts shedding capacity, so it is
//!   when the caller starts the next job. On a 360-connection fleet at
//!   100 Mbit the queue is dry at 11% of the run while every connection
//!   still holds four articles; the signal fires when the first one
//!   actually runs out of work.
//!
//! An idle worker hands its connection back (warm-parks or quits it and
//! drops the permit) only when `ConnBudget::waiters` says a successor is
//! blocked on it AND it is not its server's last live worker. With no
//! successor there are no waiters, so a single job's fleet idles, hedges
//! and drains exactly as it did before this module existed.

use crate::sync::MutexExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;

/// A counted registration in [`HostLease::waiters`] that is released on
/// every exit from the wait: a wake, a panic, and - the one that
/// matters - the future being dropped mid-await by a `tokio::select!`.
struct WaiterGuard<'a>(&'a AtomicUsize);

impl<'a> WaiterGuard<'a> {
    fn new(c: &'a AtomicUsize) -> Self {
        c.fetch_add(1, Ordering::AcqRel);
        Self(c)
    }
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A host's connection cap as permits. See the module doc.
#[derive(Debug)]
pub struct HostLease {
    state: std::sync::Mutex<LeaseState>,
    /// Successor workers parked in `acquire`. Read lock-free by the
    /// predecessor's idle workers on every idle turn.
    waiters: AtomicUsize,
    woken: Notify,
}

#[derive(Debug)]
struct LeaseState {
    cap: usize,
    held: usize,
}

/// One held connection slot. Dropping it frees the slot and wakes one
/// waiter.
pub struct Permit {
    lease: Arc<HostLease>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        {
            let mut st = self.lease.state.lock_ok();
            st.held = st.held.saturating_sub(1);
        }
        self.lease.woken.notify_one();
    }
}

impl HostLease {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(LeaseState {
                cap: cap.max(1),
                held: 0,
            }),
            waiters: AtomicUsize::new(0),
            woken: Notify::new(),
        })
    }

    /// Re-point the cap at the figure the newest run computed for this
    /// host. Lowering it never revokes a held permit - the holders drain
    /// on their own and the successor simply waits until `held` falls
    /// under the new cap, which is the right answer when a user turns
    /// connections down between two queued jobs.
    pub fn set_cap(&self, cap: usize) {
        let cap = cap.max(1);
        let changed = {
            let mut st = self.state.lock_ok();
            let was = st.cap;
            st.cap = cap;
            was != cap
        };
        if changed {
            self.woken.notify_waiters();
        }
    }

    /// Take a slot, waiting for one if the host is at its cap. Counted
    /// as a waiter for the whole wait, which is what the predecessor's
    /// idle workers read.
    pub async fn acquire(self: &Arc<Self>) -> Permit {
        loop {
            {
                let mut st = self.state.lock_ok();
                if st.held < st.cap {
                    st.held += 1;
                    return Permit {
                        lease: self.clone(),
                    };
                }
            }
            // Registered by RAII, not by a plain decrement after the
            // await: `runlife` races this future against `run_over` in
            // a `tokio::select!`, so a run that drains or finishes
            // while a worker is parked here DROPS the future mid-await.
            // A plain `fetch_sub` below the await never runs on that
            // path, and the lease outlives the run (one per account for
            // the daemon's life), so the ghost made `want_handoff` true
            // forever and every later run shed its idle connections
            // down to one per server with no successor waiting.
            let _w = WaiterGuard::new(&self.waiters);
            // `notified()` is armed before the state is re-read on the
            // next turn, and a release that lands between the check
            // above and this await is kept by Notify's one-permit
            // memory, so a wake is never lost.
            self.woken.notified().await;
        }
    }

    /// Successor workers currently blocked in [`HostLease::acquire`].
    pub fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// `(held, cap)` right now - diagnostics and tests.
    pub fn snapshot(&self) -> (usize, usize) {
        let st = self.state.lock_ok();
        (st.held, st.cap)
    }
}

/// The daemon's per-account leases. An account seen for the first time
/// gets a lease at the cap the caller computed; one seen again has its
/// cap re-pointed (see [`HostLease::set_cap`]).
///
/// Keyed by [`ConnBudget::key`], which is the ACCOUNT - host, port and
/// user - and not the host alone. A connection cap is a property of an
/// account: the same hostname on two ports with two logins (a block
/// account beside a flat-rate one at one provider) is two caps, and two
/// mock servers on 127.0.0.1 are two servers. Keyed by host alone the
/// two shared one lease, and a run's own second server's workers read as
/// "a successor waiting" on the first's.
#[derive(Debug, Default)]
pub struct ConnBudget {
    hosts: std::sync::Mutex<HashMap<String, Arc<HostLease>>>,
}

impl ConnBudget {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The lease key for a server: its account identity.
    pub fn key(s: &crate::config::ServerConfig) -> String {
        format!(
            "{}:{}:{}",
            s.host,
            s.port,
            s.username.as_deref().unwrap_or("")
        )
    }

    /// The lease for the account `key` at `cap` connections.
    pub fn lease(&self, key: &str, cap: usize) -> Arc<HostLease> {
        let mut hosts = self.hosts.lock_ok();
        match hosts.get(key) {
            Some(l) => {
                l.set_cap(cap);
                l.clone()
            }
            None => {
                let l = HostLease::new(cap);
                hosts.insert(key.to_string(), l.clone());
                l
            }
        }
    }

    /// Slots held across every host - the figure a connection-count
    /// invariant is checked against.
    pub fn held_total(&self) -> usize {
        self.hosts.lock_ok().values().map(|l| l.snapshot().0).sum()
    }
}

/// Per-run latch: "this run's fleet has started going idle". See the
/// module doc for why this is the hand-over moment rather than the
/// queue-dry latch.
#[derive(Debug, Default)]
pub struct HandoffSignal {
    latched: AtomicBool,
    notify: Notify,
}

impl HandoffSignal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Latch once; every later call is a no-op. Returns true on the
    /// latching call.
    pub fn latch(&self) -> bool {
        let first = !self.latched.swap(true, Ordering::AcqRel);
        if first {
            self.notify.notify_waiters();
        }
        first
    }

    pub fn is_latched(&self) -> bool {
        self.latched.load(Ordering::Acquire)
    }

    /// Resolves once latched; immediately if it already was.
    pub async fn wait(&self) {
        loop {
            if self.is_latched() {
                return;
            }
            let n = self.notify.notified();
            if self.is_latched() {
                return;
            }
            n.await;
        }
    }
}

impl super::Shared {
    /// Should an idle worker on server `idx` hand its connection to the
    /// successor run right now? Three conditions, all cheap:
    /// a successor is actually blocked on this host's lease, this run
    /// is past queue-dry (so the idleness is the tail, not a gap), and
    /// the worker is not its server's last - one stays to pick up a
    /// requeue, exactly as the fleet always had at least one worker per
    /// server for that.
    pub(super) fn want_handoff(&self, idx: usize) -> bool {
        let Some(Some(lease)) = self.leases.get(idx) else {
            return false;
        };
        lease.waiters() > 0
            && self.alive[idx].load(Ordering::Acquire) > 1
            && self.tail_started.lock_ok().is_some()
    }

    /// A primary worker found itself idle after queue-dry: latch the
    /// run's hand-over signal. Fill servers (level > 0) idle for their
    /// own reasons and say nothing about the fleet.
    pub(super) fn note_idle_after_dry(&self, idx: usize) {
        if let Some(h) = &self.handoff
            && self.levels.get(idx).is_some_and(|l| *l == 0)
            && self.tail_started.lock_ok().is_some()
            && h.latch()
            && let Some(l) = &self.live
        {
            l.note_run(
                "handoff",
                "connections are going idle - the next job may start on them",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_lease_never_exceeds_its_cap_and_waiters_are_counted() {
        let b = ConnBudget::new();
        let l = b.lease("h", 2);
        let p1 = l.acquire().await;
        let p2 = l.acquire().await;
        assert_eq!(l.snapshot(), (2, 2));
        assert_eq!(l.waiters(), 0);
        let l2 = l.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(l.waiters(), 1, "the third acquire parks");
        assert!(!waiter.is_finished());
        drop(p1);
        let p3 = waiter.await.unwrap();
        assert_eq!(l.waiters(), 0);
        assert_eq!(l.snapshot(), (2, 2));
        assert_eq!(b.held_total(), 2);
        drop(p2);
        drop(p3);
        assert_eq!(b.held_total(), 0);
    }

    #[tokio::test]
    async fn a_cancelled_acquire_leaves_no_ghost_waiter() {
        let b = ConnBudget::new();
        let l = b.lease("h", 1);
        let _held = l.acquire().await;
        let l2 = l.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(l.waiters(), 1, "the second acquire parks");
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(l.waiters(), 0, "cancellation must remove waiter demand");
    }

    /// The shape `runlife` actually races: `acquire` against `run_over`
    /// in a `tokio::select!`. The losing branch's future is dropped
    /// mid-await, and a later run must not read that as a successor.
    #[tokio::test]
    async fn a_run_that_ends_while_parked_drops_its_waiter() {
        let b = ConnBudget::new();
        let l = b.lease("h", 1);
        let _held = l.acquire().await;
        let run_over = tokio::time::sleep(std::time::Duration::from_millis(30));
        let permit = tokio::select! {
            p = l.acquire() => Some(p),
            _ = run_over => None,
        };
        assert!(permit.is_none(), "the run ended before a permit freed");
        assert_eq!(l.waiters(), 0, "no phantom successor for the next run");
    }

    #[tokio::test]
    async fn lowering_the_cap_holds_the_successor_until_holders_drain() {
        let b = ConnBudget::new();
        let l = b.lease("h", 3);
        let held: Vec<Permit> = vec![l.acquire().await, l.acquire().await, l.acquire().await];
        // The next job computed a smaller cap for the same host.
        let l_again = b.lease("h", 1);
        assert!(Arc::ptr_eq(&l, &l_again), "one lease per host");
        assert_eq!(l.snapshot(), (3, 1), "held permits are never revoked");
        let l2 = l.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        let mut held = held;
        drop(held.pop());
        drop(held.pop());
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "2 held > cap 1: still waiting");
        drop(held.pop());
        let _p = waiter.await.unwrap();
        assert_eq!(l.snapshot(), (1, 1));
    }

    #[tokio::test]
    async fn the_signal_latches_once_and_wakes_a_waiter() {
        let s = HandoffSignal::new();
        let s2 = s.clone();
        let w = tokio::spawn(async move { s2.wait().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!w.is_finished());
        assert!(s.latch());
        assert!(!s.latch(), "second latch is a no-op");
        w.await.unwrap();
        // Already latched: resolves at once.
        s.wait().await;
    }
}
