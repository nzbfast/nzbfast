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
            // Register with the Notify BEFORE re-reading `held`/`cap`,
            // and only await after a failed re-check. Notify's memory
            // for UNREGISTERED waiters is ONE stored permit, so with
            // two waiters past the check above and neither polled yet,
            // two `notify_one` calls collapse into one wake - a slot
            // sits free while a waiter sleeps forever (27 Aug sweep
            // finding 24). An enabled waiter is woken directly instead
            // of through that single-permit memory, and a release that
            // lands between the check above and `enable` is caught by
            // the re-check.
            let notified = self.woken.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.state.lock_ok();
                if st.held < st.cap {
                    st.held += 1;
                    return Permit {
                        lease: self.clone(),
                    };
                }
            }
            notified.as_mut().await;
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
    ///
    /// A PEEK, and the only caller that may act on it is one that has
    /// then taken [`Self::claim_handoff`]: this answer is the same for
    /// every idle worker on the server at once, which is exactly how two
    /// of them both concluded they were not the last. `next_work`'s use
    /// is a peek by nature - it decides not to hand out a duplicate, and
    /// hands nothing back that could be claimed - so it stays on this
    /// one; the retiring arm in `idle_turn` takes the claim.
    pub(super) fn want_handoff(&self, idx: usize) -> bool {
        self.handoff_wanted(idx) && self.handoff_room(idx)
    }

    /// The two conditions that are about the RUN rather than about this
    /// server's fleet: a successor blocked on this host's lease, and this
    /// run past queue-dry.
    fn handoff_wanted(&self, idx: usize) -> bool {
        let Some(Some(lease)) = self.leases.get(idx) else {
            return false;
        };
        lease.waiters() > 0 && self.tail_started.lock_ok().is_some()
    }

    /// Is there room for ONE more worker to leave this server - i.e.
    /// would someone still be here afterwards? A peek; [`Self::claim_handoff`]
    /// is the version that may be acted on.
    ///
    /// Bounded on SOCKET-CAPABLE bodies (`workers_dialling_on`: alive
    /// minus admission-parked), not on `alive` (27 Aug sweep finding
    /// 7). A worker parked in `wait_for_slot` holds no `Permit` and no
    /// socket - the admission the leaver releases wakes it, but it
    /// still races the successor job's workers for the host lease, so
    /// a "leftover" that is a parked body can sit in `acquire` holding
    /// nothing while `live_mask` still counts the server and requeues
    /// only this host can serve wait for the watchdog.
    fn handoff_room(&self, idx: usize) -> bool {
        self.workers_dialling_on(idx)
            .is_some_and(|d| d > self.handoff_out[idx].load(Ordering::Acquire) + 1)
    }

    /// [`Self::want_handoff`], CLAIMED: true only for a worker that may
    /// act on it and leave.
    ///
    /// The bare `alive > 1` peek was a decision, not a claim, and every
    /// idle worker on the server makes it against the same number. Two
    /// idle workers on a two-worker server both read 2, both pass, and
    /// both retire - so the server that "keeps one for requeues" keeps
    /// nobody, `live_mask` stops counting it, and an article the other
    /// servers have already 430'd is declared unservable without this
    /// host ever being asked for it. Not a rare interleaving either: the
    /// idle loop re-asks every 25 ms, so a fleet draining past queue-dry
    /// walks itself down to exactly two and then loses both.
    ///
    /// The room is judged against `workers_dialling_on`, not `alive`,
    /// for [`Self::handoff_room`]'s reason: a parked body is not "kept
    /// for requeues". `handoff_out` still serializes concurrent claims
    /// in the window between the two steps below, and the cost of it
    /// staying charged is that a large idle fleet hands over about half
    /// of itself per round rather than all but one; the alternative is
    /// a window in which a server goes dark mid-run, which is
    /// unrecoverable.
    ///
    /// A granted claim also takes the leaver OUT OF `alive` on the
    /// spot, through a CAS that refuses to take the last socket-capable
    /// body (27 Aug sweep finding 25). The claim alone pinned no
    /// specific leftover: between the claim and the worker's own
    /// `life.retire()` a sibling could leave through another door
    /// (connect/auth exhaustion, a budget bow-out), and the claimed
    /// hand-over then took the server dark anyway. Reserving the
    /// decrement here makes the check and the departure one atomic
    /// step; `WorkerLife` consumes the pre-paid decrement via
    /// `handoff_retired` instead of counting the exit twice. When the
    /// reservation fails, the claim is given back - safe, because it
    /// was never acted on - and the worker keeps its socket.
    pub(super) fn claim_handoff(&self, idx: usize) -> bool {
        if !self.handoff_wanted(idx) {
            return false;
        }
        if self.handoff_out[idx]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |h| {
                self.workers_dialling_on(idx)
                    .is_some_and(|d| d > h + 1)
                    .then_some(h + 1)
            })
            .is_err()
        {
            return false;
        }
        // The reservation: leave at least one socket-capable body
        // behind, judged at the same instant the departure lands.
        let reserved = self.alive[idx]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |a| {
                let parked = self.parked[idx].load(Ordering::SeqCst);
                (a > parked + 1).then(|| a - 1)
            })
            .is_ok();
        if !reserved {
            self.handoff_out[idx].fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        self.handoff_retired[idx].fetch_add(1, Ordering::SeqCst);
        true
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
    use crate::pool::{ArticleReq, Shared, inline_tests::one_server};
    use std::time::Instant;

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

    /// The last worker on a server may not hand its socket away, and
    /// TWO idle workers may not both conclude they are not the last.
    ///
    /// The old `want_handoff` answered from `alive > 1` with no claim, so
    /// on a two-worker server both idle workers read 2, both passed, and
    /// both retired - leaving the host with nobody to take a requeue,
    /// `live_mask` no longer counting it, and an article every OTHER
    /// server has 430'd declared unservable without this one ever being
    /// asked. This drives the exact interleaving: the peek stays true for
    /// both, and only one claim is granted.
    #[tokio::test]
    async fn only_one_of_two_idle_workers_may_hand_its_socket_over() {
        let budget = ConnBudget::new();
        let lease = budget.lease("s", 1);
        let mut servers = one_server();
        servers[0].1.lease = Some(lease.clone());
        let reqs: Vec<ArticleReq> = vec![ArticleReq::fresh("<a0>")];
        let (shared, _) = Shared::new(reqs, &servers);

        // A successor parked on this host's lease.
        let held = lease.acquire().await;
        let l2 = lease.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(lease.waiters(), 1);

        shared.alive[0].store(2, Ordering::Relaxed);
        assert!(
            !shared.want_handoff(0),
            "before queue-dry the idleness is a gap, not the tail"
        );
        *shared.tail_started.lock_ok() = Some(Instant::now());

        assert!(shared.want_handoff(0), "the peek is true for both workers");
        assert!(shared.claim_handoff(0), "the first claim is granted");
        assert!(
            !shared.claim_handoff(0),
            "the second must be refused - somebody has to stay"
        );
        assert!(
            !shared.want_handoff(0),
            "and the peek agrees, so the refused worker goes back to \
             picking duplicates instead of idling on a door that is shut"
        );

        // A third worker joining re-opens exactly one more seat.
        shared.alive[0].store(3, Ordering::Relaxed);
        assert!(shared.claim_handoff(0));
        assert!(!shared.claim_handoff(0));

        drop(held);
        drop(waiter.await.unwrap());
    }

    /// 27 Aug sweep findings 7 and 25: the leftover must be a body
    /// that can hold a socket, and the claim must PIN it. A worker
    /// parked in `wait_for_slot` has no permit and no connection, so a
    /// server whose only other body is parked may not hand its socket
    /// away; and a granted claim takes the leaver out of `alive` at the
    /// claim, so a sibling leaving through another door between claim
    /// and retire cannot make the hand-over the last body out.
    #[tokio::test]
    async fn a_parked_body_is_not_a_leftover_and_a_claim_pins_one() {
        let budget = ConnBudget::new();
        let lease = budget.lease("s", 1);
        let mut servers = one_server();
        servers[0].1.lease = Some(lease.clone());
        let reqs: Vec<ArticleReq> = vec![ArticleReq::fresh("<a0>")];
        let (shared, _) = Shared::new(reqs, &servers);

        let held = lease.acquire().await;
        let l2 = lease.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(lease.waiters(), 1);
        *shared.tail_started.lock_ok() = Some(Instant::now());

        // Two alive, but one of them is admission-parked: no socket to
        // take a requeue on, so the door stays shut.
        shared.alive[0].store(2, Ordering::Relaxed);
        shared.parked[0].store(1, Ordering::Relaxed);
        assert!(!shared.want_handoff(0), "a parked body is not a leftover");
        assert!(!shared.claim_handoff(0));
        assert_eq!(
            shared.handoff_out[0].load(Ordering::Relaxed),
            0,
            "a refused claim leaves nothing charged"
        );

        // The parked body dialled: two socket-capable bodies, one may go.
        shared.parked[0].store(0, Ordering::Relaxed);
        assert!(shared.claim_handoff(0));
        assert_eq!(
            shared.alive[0].load(Ordering::Relaxed),
            1,
            "the claim takes the leaver out of `alive` on the spot"
        );
        assert_eq!(
            shared.handoff_retired[0].load(Ordering::Relaxed),
            1,
            "and pre-pays the decrement WorkerLife would otherwise repeat"
        );
        assert!(
            !shared.claim_handoff(0),
            "the pinned leftover is the last socket-capable body"
        );

        drop(held);
        drop(waiter.await.unwrap());
    }

    /// No lease and no tail: the door is shut whatever the fleet size,
    /// which is what keeps the CLI and every test that does not opt in
    /// on the old path verbatim.
    #[tokio::test]
    async fn a_run_with_no_successor_never_hands_anything_over() {
        let servers = one_server();
        let reqs: Vec<ArticleReq> = vec![ArticleReq::fresh("<a0>")];
        let (shared, _) = Shared::new(reqs, &servers);
        shared.alive[0].store(8, Ordering::Relaxed);
        *shared.tail_started.lock_ok() = Some(Instant::now());
        assert!(!shared.want_handoff(0));
        assert!(!shared.claim_handoff(0));
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
