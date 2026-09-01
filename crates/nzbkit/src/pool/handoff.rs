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
//!
//! **And one permit is not a download's to take** ([`POST_PROCESS_RESERVE`],
//! 30 Aug 2026). The cap is divided by [`LeaseClass`] rather than handed
//! out first-come: a download fleet stops one short of the account's
//! number so a post-processing side-fetch - a recovery-volume pull, the
//! speculative prefetch - always has a permit to dial on. Without it a
//! repair running on job A's tail waits on connections job B holds for
//! the whole of its own run, and every retry waits the same way. The
//! account's total is unchanged, so the provider never sees a socket it
//! did not license; what moves is who may hold the last one.

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

/// Permits held back from every account's cap so a POST-PROCESSING
/// fetch always has one (30 Aug 2026; the measurement that priced it
/// and the option taken are `research/SIDEFETCH-LEASE-2026-08-30.md`).
///
/// **Why a reserve exists at all.** A recovery side-fetch runs by
/// construction on job A's post-download tail, which is exactly when
/// job B has started downloading and taken every permit on the account.
/// The lease is per-account and lives for the daemon's life, so without
/// a reserve job A's repair parks in [`HostLease::acquire`] until job
/// B's fleet starts going idle - which on a healthy long download is
/// near the END of it, and on a wedged one never. The repair then
/// fails, retries, and each retry starves the same way: a repair behind
/// a long job cannot succeed however often it is tried.
///
/// **Why the number is ONE and not a fleet.** Measured, not guessed, in
/// `one_spare_permit_is_enough_for_a_side_fetch_to_finish`: a width-6
/// side pool against a cap-6 lease with five permits held drains the
/// whole recovery set on the single spare. A side pool does not need
/// its configured width to make progress, it needs A PERMIT. One worker
/// that can dial drains the set, slower; the others sit in `acquire`
/// and retire when the run ends. So the price of removing the "cannot
/// succeed" property is one connection, per account - 2.5% of a
/// 40-connection account's width, paid whether or not a repair ever
/// runs. It is not free and it is not sold as free.
///
/// **Why not simply let the side pool ignore the lease.** Because the
/// repair side-fetch runs at the MAIN FLEET's width, not at one
/// connection per server (pinned by
/// `the_repair_side_fetch_runs_at_the_main_fleets_width`), so a side
/// pool outside the accounting is a whole SECOND fleet on an account
/// that already has one - 2x the provider's cap, which is the "502
/// connection limit reached" wall `park_or_probe` and the ghost-capacity
/// machinery exist for. The reserve never exceeds the cap: the
/// account's total is unchanged and only its DIVISION moves.
///
/// **The stated limit, and it is bigger than one account.** The 2.5%
/// above is 1/40, and the reserve is ONE PERMIT rather than a share, so
/// on a small cap it is a large fraction: 1 in 4 is 25% and 1 in 2 is
/// half. It also comes out of what THIS RUN dialled and not out of the
/// provider's licensed number - `get::fleet` sizes the lease to the
/// fleet it spawns, which a line cap or the auto-tune knee may have put
/// well under the account's own figure. So a download narrowed by a cap
/// is narrowed once more here. [`MIN_DOWNLOAD_FLEET`] bounds the worst
/// of that and nothing bounds the middle of it; a user on a small
/// account pays a real share of their line for a repair that may never
/// run.
pub const POST_PROCESS_RESERVE: usize = 1;

/// Connections a download keeps whatever [`POST_PROCESS_RESERVE`] would
/// otherwise take (30 Aug 2026).
///
/// **Measured, and it is why this const exists at all.** With a flat
/// reserve and no floor, an account at cap 2 gives its download ONE
/// connection - half the line for a repair that may never run - and the
/// daemon then reports one thing and does another: `whyslow`'s fleet
/// panel publishes `fleet_cap` from the gauge the run computed, so it
/// says 2 while two sockets is exactly what the fleet may no longer
/// hold. `daemon_whyslow::the_fleet_verdict_is_produced_end_to_end_on_a_
/// running_daemon` fails on precisely that, at a typed fleet cap of 2.
///
/// **Two and not some larger tidy number**, because two is the point at
/// which this pool stops being a fleet at all: `get::fleet` will not
/// even build a live connection target below it (`applied > 1`), the
/// endgame's duplicate racing has nothing to race, and a single socket
/// is the one shape whose throughput is not a share of the line but a
/// different regime. Anything above two would be a number nobody
/// measured. What this does NOT do is bound the middle of the curve -
/// at cap 3 the reserve is still a third - and that is stated rather
/// than papered over.
pub const MIN_DOWNLOAD_FLEET: usize = 2;

/// Which class of work a pool's workers take their permits as.
///
/// The two differ ONLY in what they are allowed to take from the
/// account's cap; both are bounded by it, so no class can put a socket
/// on the wire the provider has not licensed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LeaseClass {
    /// A download fleet. Bounded by [`HostLease::download_cap`], which
    /// is the account's cap minus [`POST_PROCESS_RESERVE`].
    #[default]
    Download,
    /// A post-processing side pool - a recovery-volume fetch, or the
    /// M2c.5 speculative prefetch. May take the reserved permit, so it
    /// is never starved by a download that holds its own cap for the
    /// whole of a long run.
    ///
    /// Two post-processing pools on one account contend with each other
    /// for the reserve, which is fine and bounded: both terminate, and
    /// neither can hold it past its own run.
    PostProcess,
}

/// One server row's seat at its account's lease: the shared
/// [`HostLease`], plus THIS run's count of its own workers parked in
/// [`HostLease::acquire_as`] on it.
///
/// The count is here rather than in `HostLease` because the lease is
/// per ACCOUNT and outlives every run on it, while the question the
/// count answers is a run's own: [`POST_PROCESS_RESERVE`] holds one
/// permit back from every download while `get::fleet` spawns a fleet the
/// size of the lease's own cap, so on a server with no line-cap spawn
/// headroom the reserve leaves this run's LAST worker parked for the
/// whole run - blocked by its own fleet and not by anybody else's.
/// `HostLease::waiters` counts it like any other; the run subtracts its
/// own before concluding a successor is waiting
/// (`Shared::own_lease_waiters`).
#[derive(Debug)]
pub(super) struct LeaseSeat {
    lease: Arc<HostLease>,
    parked: AtomicUsize,
}

impl LeaseSeat {
    /// One seat per server row, `None` where that row has no lease -
    /// the CLI and every test that does not opt in.
    pub(super) fn seats(
        servers: &[(crate::config::ServerConfig, super::PoolConfig)],
    ) -> Vec<Option<Self>> {
        servers
            .iter()
            .map(|(_, c)| {
                c.lease.clone().map(|lease| Self {
                    lease,
                    parked: AtomicUsize::new(0),
                })
            })
            .collect()
    }
}

/// See [`super::Shared::park_on_lease`].
pub(super) struct LeaseParkGuard<'a>(&'a AtomicUsize);

impl Drop for LeaseParkGuard<'_> {
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

/// One held connection slot. Dropping it frees the slot and wakes every
/// parked acquirer to re-check.
pub struct Permit {
    lease: Arc<HostLease>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        {
            let mut st = self.lease.state.lock_ok();
            st.held = st.held.saturating_sub(1);
        }
        // `notify_waiters` and NOT `notify_one`, and the reserve is why.
        // Since [`POST_PROCESS_RESERVE`] the parked acquirers no longer
        // all want the same thing: a `Download` waiter is satisfied only
        // below [`HostLease::download_cap`] and a `PostProcess` one
        // anywhere below `cap`. `notify_one` wakes ONE of them, and a
        // download waiter woken by a release that only frees the
        // RESERVED slot fails its re-check and goes back to sleep
        // without passing the wake on - so the side-fetch the reserve
        // exists for sleeps forever with its slot standing free. That is
        // the lost-wakeup shape of the 27 Aug sweep's finding 24, one
        // release later. Waking all of them costs a re-check per parked
        // worker on an event that happens when a worker retires, not per
        // article; at most one wins and the rest park again.
        self.lease.woken.notify_waiters();
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

    /// Take a slot as a DOWNLOAD worker: bounded by
    /// [`Self::download_cap`], so the post-processing reserve is never
    /// the permit this hands out.
    pub async fn acquire(self: &Arc<Self>) -> Permit {
        self.acquire_as(LeaseClass::Download).await
    }

    /// Take a slot, waiting for one if the account has none free for
    /// this class. Counted as a waiter for the whole wait, which is what
    /// the predecessor's idle workers read.
    ///
    /// A waiter here is any parked acquirer and NOT necessarily a
    /// successor: since [`POST_PROCESS_RESERVE`] a download fleet
    /// spawned to the size of its own lease cap parks its last worker
    /// here for the whole run, blocked by its own run rather than by
    /// anybody else's. This type has no notion of a run, so it counts
    /// what it can see; `Shared::handoff_wanted` subtracts the workers
    /// that are its own before concluding anything.
    pub async fn acquire_as(self: &Arc<Self>, class: LeaseClass) -> Permit {
        loop {
            {
                let mut st = self.state.lock_ok();
                if st.held < limit_for(&st, class) {
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
            // two wakes collapse into one - a slot sits free while a
            // waiter sleeps forever (27 Aug sweep finding 24). An
            // enabled waiter is woken directly instead of through that
            // single-permit memory, and a release that lands between the
            // check above and `enable` is caught by the re-check.
            let notified = self.woken.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.state.lock_ok();
                if st.held < limit_for(&st, class) {
                    st.held += 1;
                    return Permit {
                        lease: self.clone(),
                    };
                }
            }
            notified.as_mut().await;
        }
    }

    /// Workers currently blocked in [`HostLease::acquire_as`], of every
    /// class and of every run. Read by a predecessor's idle workers,
    /// which subtract their own first - see [`Self::acquire_as`].
    pub fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// `(held, cap)` right now - diagnostics and tests. `cap` is the
    /// ACCOUNT's number, which is what no class may exceed; what a
    /// download alone may hold is [`Self::download_cap`].
    pub fn snapshot(&self) -> (usize, usize) {
        let st = self.state.lock_ok();
        (st.held, st.cap)
    }

    /// What [`LeaseClass::Download`] alone may hold: the cap less
    /// [`POST_PROCESS_RESERVE`], floored at [`MIN_DOWNLOAD_FLEET`] so
    /// the reserve can never take a download's fleet down to one socket
    /// (and floored again at the cap itself, so a one- or
    /// two-connection account is left exactly as it was).
    pub fn download_cap(&self) -> usize {
        let st = self.state.lock_ok();
        download_cap_of(st.cap)
    }
}

/// [`HostLease::download_cap`] as arithmetic, so both the acquire path
/// (which already holds the lock) and the public reader spell the rule
/// once.
///
/// The `min(cap)` is what keeps [`MIN_DOWNLOAD_FLEET`] a FLOOR and never
/// a raise: a one-connection account may not be handed two.
fn download_cap_of(cap: usize) -> usize {
    cap.saturating_sub(POST_PROCESS_RESERVE)
        .max(MIN_DOWNLOAD_FLEET)
        .min(cap.max(1))
}

/// How many permits `class` may hold at a cap of `st.cap`. Bounded by
/// the account's own number for BOTH classes: the reserve moves the
/// division, never the total.
fn limit_for(st: &LeaseState, class: LeaseClass) -> usize {
    match class {
        LeaseClass::Download => download_cap_of(st.cap),
        LeaseClass::PostProcess => st.cap,
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
        let Some(Some(seat)) = self.leases.get(idx) else {
            return false;
        };
        seat.lease.waiters() > self.own_lease_waiters(&seat.lease)
            && self.tail_started.lock_ok().is_some()
    }

    /// This run's own workers parked on `lease` - the ones a hand-over
    /// would feed back to itself.
    ///
    /// Summed over every server sharing that lease by `Arc::ptr_eq` and
    /// not read out of one index, because the lease is per ACCOUNT while
    /// `lease_parked` is per SERVER ROW: two rows for one account (a
    /// second entry for the same host, port and login) share one
    /// `HostLease`, so its `waiters` already counts both rows' parked
    /// workers and subtracting one row's would leave the other's reading
    /// as a successor. Identity by pointer rather than by key, because
    /// the pointer IS what `waiters` was counted on.
    fn own_lease_waiters(&self, lease: &Arc<HostLease>) -> usize {
        self.leases
            .iter()
            .flatten()
            .filter(|s| Arc::ptr_eq(&s.lease, lease))
            .map(|s| s.parked.load(Ordering::Acquire))
            .sum()
    }

    /// RAII around one worker's park in [`HostLease::acquire_as`], so
    /// [`Self::own_lease_waiters`] counts it for exactly as long as
    /// `HostLease::waiters` does.
    ///
    /// Held across the whole `tokio::select!` in `runlife::worker` and
    /// not around the await alone: that select DROPS the acquire future
    /// mid-await when the run ends, which is the same cancellation path
    /// `WaiterGuard` exists for on the other side of the count. Both
    /// sides must fall to zero on it or the subtraction goes negative in
    /// meaning - `waiters` back at 0 with this still charged reads as
    /// "fewer waiters than my own", which saturates to no hand-over ever
    /// again on a lease that outlives the run.
    pub(super) fn park_on_lease(&self, idx: usize) -> Option<LeaseParkGuard<'_>> {
        let seat = self.leases.get(idx)?.as_ref()?;
        seat.parked.fetch_add(1, Ordering::AcqRel);
        Some(LeaseParkGuard(&seat.parked))
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
        // Cap 3, so a download may hold 2 and the third permit is the
        // post-processing reserve.
        let l = b.lease("h", 3);
        assert_eq!(l.download_cap(), 2);
        let p1 = l.acquire().await;
        let p2 = l.acquire().await;
        assert_eq!(l.snapshot(), (2, 3), "a download stops one short");
        assert_eq!(l.waiters(), 0);
        // Bounded, here and below: a reserve that stops working turns
        // these into hangs, and a test that hangs reports nothing.
        let p3 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            l.acquire_as(LeaseClass::PostProcess),
        )
        .await
        .expect("post-processing may take the reserved permit");
        assert_eq!(l.snapshot(), (3, 3), "and post-processing may have it");
        let l2 = l.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(l.waiters(), 1, "the next download parks");
        assert!(!waiter.is_finished());
        // The RESERVED slot freeing is not a download's slot freeing.
        drop(p3);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            !waiter.is_finished(),
            "a download may not take the reserve back"
        );
        assert_eq!(l.snapshot(), (2, 3));
        drop(p1);
        let p4 = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("a freed download slot seats the parked download")
            .unwrap();
        assert_eq!(l.waiters(), 0);
        assert_eq!(l.snapshot(), (2, 3));
        assert_eq!(b.held_total(), 2);
        drop(p2);
        drop(p4);
        assert_eq!(b.held_total(), 0);
    }

    /// The reserve, from the download side: a fleet spawned to its own
    /// lease cap seats one fewer worker, and the permit it leaves is
    /// there for a post-processing side pool. The account's TOTAL is
    /// unchanged - which is the whole difference between this and simply
    /// letting the side pool ignore the lease.
    #[tokio::test]
    async fn the_reserve_holds_one_permit_back_from_a_download() {
        let b = ConnBudget::new();
        const CAP: usize = 6;
        let l = b.lease("h", CAP);
        assert_eq!(l.download_cap(), CAP - POST_PROCESS_RESERVE);
        let mut fleet = Vec::new();
        for _ in 0..CAP - 1 {
            fleet.push(l.acquire().await);
        }
        assert_eq!(l.snapshot(), (CAP - 1, CAP));
        // The fleet's last worker: spawned, and it may not be seated.
        let l2 = l.clone();
        let surplus = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!surplus.is_finished(), "the reserve is not a download's");

        // The side pool takes it at once, with no wait at all.
        let side = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            l.acquire_as(LeaseClass::PostProcess),
        )
        .await
        .expect("post-processing is never starved by a download");
        assert_eq!(
            l.snapshot(),
            (CAP, CAP),
            "and the account is at its cap, never past it"
        );

        // A SECOND post-processing worker is bounded by the same cap:
        // the reserve is one permit, not a second fleet's licence.
        let l3 = l.clone();
        let side2 = tokio::spawn(async move { l3.acquire_as(LeaseClass::PostProcess).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            !side2.is_finished(),
            "the reserve must never take the account past its cap"
        );
        assert_eq!(l.snapshot(), (CAP, CAP));

        side2.abort();
        surplus.abort();
        let _ = side2.await;
        let _ = surplus.await;
        drop(side);
        drop(fleet);
        assert_eq!(b.held_total(), 0);
    }

    /// The lost wakeup the reserve introduces, and the reason
    /// `Permit::drop` wakes ALL parked acquirers rather than one.
    ///
    /// Two classes park on one `Notify` wanting different things. A
    /// download release frees a slot only post-processing may take; wake
    /// one waiter and it can be the download, which fails its re-check,
    /// sleeps again and passes the wake on to nobody - so the side-fetch
    /// the reserve exists for sleeps forever beside a free slot.
    #[tokio::test]
    async fn a_post_processing_waiter_is_woken_when_a_download_permit_frees() {
        let b = ConnBudget::new();
        let l = b.lease("h", 3);
        let d1 = l.acquire().await;
        let d2 = l.acquire().await;
        let pp1 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            l.acquire_as(LeaseClass::PostProcess),
        )
        .await
        .expect("the reserved permit seats the first post-processing worker");
        assert_eq!(l.snapshot(), (3, 3));

        // The download waiter parks FIRST, so a single wake goes to it.
        let l2 = l.clone();
        let dw = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let l3 = l.clone();
        let pw = tokio::spawn(async move { l3.acquire_as(LeaseClass::PostProcess).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(l.waiters(), 2);

        drop(d1);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), pw)
            .await
            .expect("the post-processing waiter must be woken by the release")
            .unwrap();
        assert!(!dw.is_finished(), "which the download still may not have");
        dw.abort();
        let _ = dw.await;
        drop(got);
        drop(d2);
        drop(pp1);
        assert_eq!(b.held_total(), 0);
    }

    /// The whole curve, in one place, because the reserve is a PERMIT
    /// and not a share and the cost of it is therefore 1/cap: what a
    /// download keeps at every cap a user can set.
    ///
    /// The two floors are the ones with incidents behind them. At cap 1
    /// there is nothing to hold back without exceeding the account's own
    /// number. At cap 2 the reserve would leave a download ONE socket -
    /// half the line for a repair that may never run, and a daemon that
    /// publishes `fleet_cap` 2 while holding one, which is what
    /// `daemon_whyslow::the_fleet_verdict_is_produced_end_to_end_on_a_
    /// running_daemon` catches.
    #[test]
    fn the_reserve_never_takes_a_downloads_fleet_below_two() {
        // cap 1 and 2 keep everything; from 3 up the reserve is one.
        for (cap, keep) in [(1usize, 1usize), (2, 2), (3, 2), (4, 3), (6, 5), (40, 39)] {
            assert_eq!(
                download_cap_of(cap),
                keep,
                "a download at cap {cap} keeps {keep}"
            );
            assert!(
                download_cap_of(cap) <= cap,
                "the floor is a floor, never a raise past the cap"
            );
        }
    }

    /// The stated limit at [`POST_PROCESS_RESERVE`]: a one-connection
    /// account has nothing to hold back without exceeding its own
    /// number, so the download keeps its single permit and a side-fetch
    /// waits for it exactly as it did before the reserve existed.
    #[tokio::test]
    async fn a_single_connection_account_has_no_reserve_to_give() {
        let b = ConnBudget::new();
        let l = b.lease("h", 1);
        assert_eq!(l.download_cap(), 1, "floored, so a download still runs");
        let d = l.acquire().await;
        let l2 = l.clone();
        let side = tokio::spawn(async move { l2.acquire_as(LeaseClass::PostProcess).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            !side.is_finished(),
            "there is no spare slot to reserve at cap 1"
        );
        drop(d);
        let p = tokio::time::timeout(std::time::Duration::from_secs(5), side)
            .await
            .expect("the single permit reaches it once the download lets go")
            .unwrap();
        assert_eq!(l.snapshot(), (1, 1));
        drop(p);
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
        // Cap 4 for three download permits: one is the reserve.
        let l = b.lease("h", 4);
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
        assert!(!waiter.is_finished(), "1 held is already the cap of 1");
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

    /// A run's OWN worker, parked because the post-processing reserve
    /// holds back the permit it would have taken, must not read as a
    /// successor waiting on this host.
    ///
    /// `get::fleet` spawns a fleet the size of the lease's own cap, so on
    /// a server with no line-cap spawn headroom the reserve leaves
    /// exactly one worker parked here for the whole run. Counted as a
    /// waiter it would make `want_handoff` true on EVERY download that
    /// reaches queue-dry with no successor anywhere - and that answer
    /// turns the endgame's duplicate fetching off (`next_work` returns
    /// None rather than a dup) and retires an idle worker to hand its
    /// socket to its own sibling. The lease has no notion of a run, so
    /// the run subtracts its own.
    #[tokio::test]
    async fn a_run_does_not_read_its_own_reserve_parked_worker_as_a_successor() {
        let budget = ConnBudget::new();
        // Cap 3: two download seats, one reserved permit. Not cap 2 -
        // `MIN_DOWNLOAD_FLEET` leaves a two-connection account whole, so
        // there is no surplus worker there to be mistaken for anybody.
        let lease = budget.lease("s", 3);
        assert_eq!(lease.download_cap(), 2);
        let mut servers = one_server();
        servers[0].1.lease = Some(lease.clone());
        let reqs: Vec<ArticleReq> = vec![ArticleReq::fresh("<a0>")];
        let (shared, _) = Shared::new(reqs, &servers);
        shared.alive[0].store(2, Ordering::Relaxed);
        *shared.tail_started.lock_ok() = Some(Instant::now());

        let seated = vec![lease.acquire().await, lease.acquire().await];
        let l2 = lease.clone();
        let surplus = tokio::spawn(async move { l2.acquire().await });
        let parked = shared.park_on_lease(0).expect("this server has a lease");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(lease.waiters(), 1, "the surplus worker is parked");
        assert!(
            !shared.want_handoff(0),
            "but it is this run's own, so there is nobody to hand over to"
        );
        assert!(!shared.claim_handoff(0));

        // Another RUN's worker on the same account: a real successor,
        // and the door opens for it with the same own count charged.
        let l3 = lease.clone();
        let successor = tokio::spawn(async move { l3.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(lease.waiters(), 2);
        assert!(
            shared.want_handoff(0),
            "a waiter that is not one of ours is a successor"
        );

        // And the count falls back to zero when our worker gives up, so
        // a lease that outlives the run carries no charge into the next.
        drop(parked);
        assert_eq!(shared.own_lease_waiters(&lease), 0);
        successor.abort();
        surplus.abort();
        let _ = successor.await;
        let _ = surplus.await;
        drop(seated);
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
