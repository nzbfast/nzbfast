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
//!
//! **And a FOURTH party since TODO 313 item 8**, which is not a class:
//! the standing warm reserve (`crate::warmreserve`) holds slots for
//! sockets that are parked with nothing to do. It is counted here
//! because a proactive dialler is the one thing on the tree that can put
//! a socket on the wire no fleet was sized for - but it is counted as
//! `LeaseState::spares`, OUTSIDE [`limit_for`], because the sizing rule
//! is that active work outranks a parked spare for the same permit. So no
//! acquire of any class is ever refused because of a spare: the spare is
//! trimmed inside the same lock hold that admits the worker taking its
//! slot ([`trim_spares`]), and `held + spares <= cap` is arithmetic
//! rather than a race.

use crate::sync::MutexExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;

/// A counted registration in [`HostLease::waiters`] that is released on
/// every exit from the wait: a wake, a panic, and - the one that
/// matters - the future being dropped mid-await by a `tokio::select!`.
///
/// TWO counters since TODO 313 item 10, not one, and both are charged
/// and released together: every parked acquirer counts in `waiters`,
/// which is the number a predecessor's idle workers read, and every
/// acquirer that is NOT [`LeaseClass::Spill`] counts a second time in
/// `prio`, which is the number a spilled lane's own acquire yields to.
/// One guard for both so no exit path can release one and keep the
/// other - a leaked `prio` charge would stop every spilled lane taking
/// a permit for the daemon's life, and the lease outlives every run.
struct WaiterGuard<'a> {
    all: &'a AtomicUsize,
    prio: Option<&'a AtomicUsize>,
}

impl<'a> WaiterGuard<'a> {
    fn new(all: &'a AtomicUsize, prio: Option<&'a AtomicUsize>) -> Self {
        all.fetch_add(1, Ordering::AcqRel);
        if let Some(p) = prio {
            p.fetch_add(1, Ordering::AcqRel);
        }
        Self { all, prio }
    }
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.all.fetch_sub(1, Ordering::AcqRel);
        if let Some(p) = self.prio {
            p.fetch_sub(1, Ordering::AcqRel);
        }
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
    /// A lane SPILLED behind a struggling head (TODO 313 item 10).
    /// Bounded by [`HostLease::download_cap`] exactly like
    /// [`Self::Download`] - a spill may not put a socket on the wire
    /// the provider has not licensed, and it may not eat the
    /// post-processing reserve either - and YIELDS to every parked
    /// waiter of the other two classes.
    ///
    /// **That yield is the RECLAIM half of item 10 and it is not
    /// decoration.** The head is ahead of the spilled lane in the
    /// queue, so when its articles come unstuck its claim on a freed
    /// permit has to outrank the lane's or the spill inverts queue
    /// priority: the user's first job finishes last because the jobs
    /// behind it kept re-taking the sockets it gave them. Ordering by
    /// class rather than by arrival is what makes the rule hold for
    /// permits the lane itself is about to release - a released permit
    /// wakes every parked acquirer at once
    /// (see [`Permit::drop`]), and without this the lane's own next
    /// worker is as likely to win the race as the head is.
    ///
    /// The yield is one-directional and cannot deadlock the lane: a
    /// spilled lane's workers hold their permits until they retire, and
    /// `handoff_room` refuses to take a server's LAST worker, so a lane
    /// that has started always keeps a socket to finish on. What it
    /// loses is the right to GROW while the head is waiting, which is
    /// the whole intent.
    Spill,
    /// A HEAD worker taking back a permit it gave up while parked under
    /// a lowered [`ConnTarget`](super::ConnTarget) - the acquire at the
    /// bottom of `session::pre_dial_gates`, and the only place this
    /// class is ever used.
    ///
    /// **A class of its own rather than [`Self::Download`], and the
    /// difference is the whole of whether a spill works at all.** The
    /// priority rule has to be "the head is asking for its own socket
    /// back", and "a download worker is parked here" is not that: a
    /// fleet spawned to its own lease cap parks its LAST worker in
    /// `acquire` for the whole run by construction, because
    /// [`POST_PROCESS_RESERVE`] holds one permit back from it. Counting
    /// that worker as a reclaim made every spilled lane yield forever
    /// to a head that was not waiting for anything - measured 2 Sep
    /// 2026 on the e2e A/B, where the lane started, took no socket for
    /// twenty-nine seconds, and finished nothing.
    ///
    /// Bounded by [`HostLease::download_cap`] like the other two
    /// download classes: this takes back what was lent, never more.
    Reclaim,
}

/// TODO 313 items 2 and 10: the switch that lets a run lend its fleet
/// to the QUEUE while it is still downloading.
///
/// One per daemon hub, shared by the struggling head and by every lane
/// spilled behind it, and SHUT unless the daemon's spill governor has
/// opened it for a live episode. Everything it gates is inert while it
/// is shut, so the mechanism is off at the pool as well as off in
/// settings - a pool built with a gate that never opens behaves exactly
/// as every pool on the tree did before this type existed.
///
/// It is a gate and not a count deliberately. What may hold how many
/// sockets is the LEASE's business and stays there; this answers only
/// "is a spill episode live right now", which is a property of the
/// daemon's queue rather than of any one account.
#[derive(Debug, Default)]
pub struct SpillGate {
    live: AtomicBool,
}

impl SpillGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Open the episode. Returns whether it moved, so a caller can log
    /// the transition and not the level.
    pub fn open(&self) -> bool {
        !self.live.swap(true, Ordering::AcqRel)
    }

    /// Shut it. Every gated behaviour reverts on the next turn that
    /// asks; nothing is unwound, because nothing here is state - a head
    /// worker that already gave its permit back re-acquires it through
    /// the ordinary path, and a lane that already shed a socket keeps
    /// running on the ones it has.
    pub fn close(&self) -> bool {
        self.live.swap(false, Ordering::AcqRel)
    }

    pub fn is_open(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
}

/// Which side of a spill a pool is on. Decided when the fleet is built
/// (the daemon knows which job it is starting and why) and fixed for
/// the run; what moves later is only whether [`SpillGate`] is open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpillRole {
    /// The struggling job the sockets are being lent BY. Its only
    /// changed behaviour is that a worker parked under a lowered
    /// [`ConnTarget`](super::ConnTarget) gives its lease permit back
    /// while it is parked, so the walk-down actually reaches the
    /// successor instead of stopping at this run's own accounting.
    ///
    /// A head NEVER hands a socket over through
    /// [`Shared::claim_handoff`](super::Shared) on this account: that
    /// exit RETIRES the worker, `alive` does not come back within a
    /// run, and a head that retired its fleet could never reclaim it.
    /// Parking is reversible and retiring is not, which is the whole
    /// reason the mechanism walks a target rather than shedding.
    Head,
    /// A job started BEHIND a struggling head on the sockets it lent.
    /// Takes its permits as [`LeaseClass::Spill`], and may hand a
    /// socket back before its own queue is dry - which is the one place
    /// the `tail_started` gate on `want_handoff` is lifted, and the
    /// only place it may be.
    Lane,
}

/// A pool's seat in a live spill: the shared gate, and which side of it
/// this pool is on.
#[derive(Clone, Debug)]
pub struct SpillSeat {
    pub gate: Arc<SpillGate>,
    pub role: SpillRole,
    /// For a [`SpillRole::Lane`], the most sockets it may build PER
    /// SERVER ROW - the absorption figure the daemon's governor sized
    /// it at (`min(its remaining articles, what is left of the
    /// slice)`). 0 is no ceiling, which is what a [`SpillRole::Head`]
    /// always carries.
    ///
    /// A ceiling and not a target: the fleet builder takes the smaller
    /// of this and what it would have built anyway, so a lane on a
    /// two-connection account is not handed eight.
    ///
    /// **Stated limit, per ROW rather than per fleet.** On the
    /// single-account install this was measured on the two are the same
    /// number. With several accounts a lane may build up to this on
    /// each of them, which is more than the head lent on any one - and
    /// what stops that being an overshoot is the thing that always
    /// stopped it, [`HostLease`]: every account's permits are counted
    /// separately and no class may exceed its own cap, so the extra
    /// workers park in `acquire` rather than reaching a provider. The
    /// cost is spawned slots that never dial, not sockets nobody
    /// licensed. Sizing per row properly means carrying the head's
    /// whole per-row walk-down here, which is a map and a schedule, and
    /// is worth doing when a multi-account install has measured a
    /// reason to.
    pub sockets: usize,
}

impl SpillSeat {
    /// Is a spill episode live AND is this pool the given side of it?
    /// Both halves in one call so no caller can check the gate and
    /// forget the role - the two roles enable opposite behaviours and
    /// applying either to the wrong side is the way this mechanism
    /// breaks.
    pub fn open_as(&self, role: SpillRole) -> bool {
        self.role == role && self.gate.is_open()
    }
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
    /// Of those, the ones that are NOT [`LeaseClass::Spill`] - the
    /// subset a spilled lane's own acquire must stand behind (TODO 313
    /// item 10's reclaim rule). Charged and released by the same
    /// [`WaiterGuard`] as `waiters`.
    prio_waiters: AtomicUsize,
    woken: Notify,
}

#[derive(Debug)]
struct LeaseState {
    cap: usize,
    held: usize,
    /// TODO 313 item 8: slots this account is currently holding for the
    /// STANDING WARM RESERVE - authenticated sockets parked with nothing
    /// to do, as a surge source (`crate::warmreserve`).
    ///
    /// A COUNT rather than a set of [`Permit`]s, and the difference is
    /// the whole invariant. A spare has to be revocable SYNCHRONOUSLY,
    /// inside the same lock hold that admits the worker taking its slot,
    /// because the sizing rule is that active work outranks a parked
    /// spare for the same permit and `active + spares <= cap` must hold BY
    /// CONSTRUCTION rather than after a background task notices. A
    /// `Permit` handed to a reserve task can only be given back when
    /// that task is next polled, which is a window in which the sum is
    /// wrong; a count that [`trim_spares`] shrinks under the state lock
    /// has no such window.
    ///
    /// It is deliberately NOT part of what any class may hold: see
    /// [`limit_for`], which does not read it. A download is never
    /// refused a permit because a spare is sitting on one - the spare
    /// gets out of the way instead.
    spares: usize,
}

/// Give back whatever the standing reserve is holding above what the
/// account can still back: `held + spares <= cap`, always, under the
/// state lock.
///
/// Called from every place `held` rises or `cap` falls. It is what makes
/// "active work outranks a parked spare" a property of the arithmetic
/// rather than a race between a fleet and a dialler.
fn trim_spares(st: &mut LeaseState) {
    st.spares = st.spares.min(st.cap.saturating_sub(st.held));
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
                spares: 0,
            }),
            waiters: AtomicUsize::new(0),
            prio_waiters: AtomicUsize::new(0),
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
            // A cap turned DOWN between two jobs cannot revoke a held
            // permit (see above), but it can and must revoke a standing
            // spare: the reserve is the one holder that is not doing any
            // work, so it is the one that gives way first.
            trim_spares(&mut st);
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
            if let Some(p) = self.try_take(class) {
                return p;
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
            let _w = WaiterGuard::new(
                &self.waiters,
                matches!(class, LeaseClass::Reclaim | LeaseClass::PostProcess)
                    .then_some(&self.prio_waiters),
            );
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
            if let Some(p) = self.try_take(class) {
                return p;
            }
            notified.as_mut().await;
        }
    }

    /// One admission attempt: take a slot for `class` if the account has
    /// one free for it right now.
    ///
    /// Spelled once and called from both checks in
    /// [`Self::acquire_as`] because the SPILL class made those two
    /// checks two statements rather than one, and a rule copied into a
    /// re-check that then drifts is how the 27 Aug lost-wakeup got in.
    /// The `prio_waiters` read is deliberately inside the lock hold:
    /// a permit released between reading it and taking the slot would
    /// otherwise let a spilled lane step in front of the head it just
    /// woke.
    fn try_take(self: &Arc<Self>, class: LeaseClass) -> Option<Permit> {
        let mut st = self.state.lock_ok();
        let yielding = class == LeaseClass::Spill && self.prio_waiters.load(Ordering::Acquire) > 0;
        if yielding || st.held >= limit_for(&st, class) {
            return None;
        }
        st.held += 1;
        // TODO 313 item 8: the fleet just grew into the gap, so the
        // reserve shrinks to make room. Same lock hold as the admission,
        // so no observer ever sees `held + spares` above `cap`.
        trim_spares(&mut st);
        Some(Permit {
            lease: self.clone(),
        })
    }

    /// Workers currently blocked in [`HostLease::acquire_as`], of every
    /// class and of every run. Read by a predecessor's idle workers,
    /// which subtract their own first - see [`Self::acquire_as`].
    pub fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// Of [`Self::waiters`], those a [`LeaseClass::Spill`] acquire
    /// stands behind: a head RECLAIMING a socket it lent, and a
    /// post-processing side pool. Deliberately not every parked
    /// download - see [`LeaseClass::Reclaim`]. Diagnostics and tests;
    /// the acquire path reads the atomic under the state lock.
    pub fn prio_waiters(&self) -> usize {
        self.prio_waiters.load(Ordering::Acquire)
    }

    /// `(held, cap)` right now - diagnostics and tests. `cap` is the
    /// ACCOUNT's number, which is what no class may exceed; what a
    /// download alone may hold is [`Self::download_cap`].
    pub fn snapshot(&self) -> (usize, usize) {
        let st = self.state.lock_ok();
        (st.held, st.cap)
    }

    /// TODO 313 item 8: ask to hold `want` slots for the standing warm
    /// reserve, and get back how many this account can ACTUALLY spare
    /// right now - which is the effective reserve, and is the number
    /// that has to be reported rather than the configured one.
    ///
    /// A LEVEL and not an increment: it sets the holding to the granted
    /// figure, so the caller re-asserts its ask on every turn, a
    /// [`trim_spares`] that happened in between is simply reconciled,
    /// and there is nothing to leak and nothing to double-count.
    ///
    /// Two things bound the grant, and both are the item's stated
    /// invariants rather than a policy this type chose:
    ///
    /// * the gap under the account's own cap, `cap - held`, so
    ///   `active + spares <= cap` holds by construction and the reserve
    ///   never causes a dial past the number the user configured; and
    /// * nobody parked in [`Self::acquire_as`]. A worker waiting for a
    ///   permit is active work outranking a parked spare, so the answer
    ///   while anyone is waiting is zero - the reserve does not take a
    ///   slot out from under a fleet that is asking for one.
    ///
    /// On a server whose fleet already runs at max the answer is 0, and
    /// that is correct rather than a failure: see `crate::warmreserve`
    /// for where the shortfall is published.
    pub fn set_spares(&self, want: usize) -> usize {
        let mut st = self.state.lock_ok();
        let granted = match self.waiters.load(Ordering::Acquire) > 0 {
            true => 0,
            false => want.min(st.cap.saturating_sub(st.held)),
        };
        st.spares = granted;
        granted
    }

    /// Slots currently held by the standing warm reserve. Diagnostics,
    /// the reserve's own reconciliation, and the tests that pin
    /// `active + spares <= cap`.
    pub fn spares(&self) -> usize {
        self.state.lock_ok().spares
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
        // A spilled lane is a download by every measure that matters
        // here - it puts bodies on the wire on the user's account - so
        // it is bounded by the download cap and leaves the
        // post-processing reserve alone. What separates it from
        // `Download` is the yield in `try_take`, not a different
        // ceiling: a spill that could take a permit the head cannot is
        // the priority inversion this class exists to prevent.
        LeaseClass::Download | LeaseClass::Spill | LeaseClass::Reclaim => download_cap_of(st.cap),
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

    /// The lease for `key` as it ALREADY stands, or `None` if this
    /// account has none yet - the borrower's door, for a run that must
    /// not redefine the account's cap.
    ///
    /// **[`Self::lease`] re-points the cap to the caller's own fleet
    /// size**, which is right for the ordinary queue where each job in
    /// turn is the account's whole download and its spawn count IS the
    /// number in force. It is catastrophic for a job sized by
    /// ABSORPTION (TODO 313 item 10): a spilled lane built for one
    /// article would set the account's cap to 1, and the head's five
    /// held permits would then keep every acquire on that account -
    /// including the lane's own - blocked until the head finished.
    /// Measured 2 Sep 2026 on the e2e A/B: permits went 7 -> 5 as the
    /// head lent them, and the lane took neither for twenty-nine
    /// seconds.
    ///
    /// A lane therefore BORROWS: same permits, same cap, decided by
    /// whoever sized the fleet the cap describes.
    pub fn lease_borrowed(&self, key: &str) -> Option<Arc<HostLease>> {
        self.hosts.lock_ok().get(key).cloned()
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
    ///
    /// **The queue-dry half is lifted for a SPILLED LANE and for
    /// nothing else** (TODO 313 item 2). That gate is the whole of what
    /// makes the shipped hand-over safe - an idle worker in the tail is
    /// genuinely spare, and lifted generally every mid-run idle turn
    /// would start shedding - so the lift is spelled as one role of one
    /// gate that is shut unless the daemon's spill governor has opened
    /// an episode. A lane spilled behind a struggling head is the one
    /// run on the tree whose idle socket is owed BACK before its own
    /// queue is dry, because the head it borrowed from is ahead of it
    /// in the user's queue and may want it at any moment. Two
    /// independent things still have to be true for a socket to move
    /// even then: somebody is actually parked on this account's lease,
    /// and this server would still have a worker afterwards.
    fn handoff_wanted(&self, idx: usize) -> bool {
        let Some(Some(seat)) = self.leases.get(idx) else {
            return false;
        };
        seat.lease.waiters() > self.own_lease_waiters(&seat.lease)
            && (self.tail_started.lock_ok().is_some() || self.spill_lane_open())
    }

    /// Is this pool a lane of a LIVE spill episode? False for every
    /// pool built without a seat (the CLI, every test that does not opt
    /// in, and every job on an install with the setting off), false for
    /// the head's own pool, and false while the gate is shut.
    pub(super) fn spill_lane_open(&self) -> bool {
        self.spill
            .as_ref()
            .is_some_and(|s| s.open_as(SpillRole::Lane))
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

    /// Bodies on `idx` parked on the account lease - the SECOND park
    /// class, which `workers_dialling_on` (admission only) cannot see.
    ///
    /// Per ROW and not summed across the account like
    /// [`Self::own_lease_waiters`], because this asks who is left on
    /// THIS server, not who is waiting on the account. A worker cannot
    /// be in both classes at once: `runlife::worker` clears the
    /// admission park before it parks on the lease, so subtracting both
    /// counts double-counts nobody.
    fn lease_parked_on(&self, idx: usize) -> usize {
        self.leases
            .get(idx)
            .and_then(|s| s.as_ref())
            .map_or(0, |s| s.parked.load(Ordering::Acquire))
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
    ///
    /// LESS THE LEASE PARK TOO (1 Sep 2026 sweep). Since
    /// [`POST_PROCESS_RESERVE`] there are two park classes and
    /// `workers_dialling_on` subtracts only the admission one, so a
    /// row whose surplus worker is held in `acquire_as` by the reserve
    /// read as having a socket-capable leftover it did not have - the
    /// same defect finding 7 fixed, through the door the reserve added.
    /// The leftover it keeps must be able to take a requeue, and a body
    /// blocked on the lease can no more do that than one blocked on an
    /// admission.
    fn handoff_room(&self, idx: usize) -> bool {
        self.workers_dialling_on(idx).is_some_and(|d| {
            d.saturating_sub(self.lease_parked_on(idx))
                > self.handoff_out[idx].load(Ordering::Acquire) + 1
        })
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
    /// The room is judged against `workers_dialling_on` less
    /// [`Self::lease_parked_on`], not against `alive`, for
    /// [`Self::handoff_room`]'s reason: a parked body is not "kept for
    /// requeues", and since the post-processing reserve there are two
    /// ways to be parked. `handoff_out` still serializes concurrent claims
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
                    .is_some_and(|d| d.saturating_sub(self.lease_parked_on(idx)) > h + 1)
                    .then_some(h + 1)
            })
            .is_err()
        {
            return false;
        }
        // The reservation: leave at least one socket-capable body
        // behind, judged at the same instant the departure lands.
        // BOTH park classes are discounted here for
        // [`Self::handoff_room`]'s reason - a body parked on the
        // account lease holds no permit either.
        let reserved = self.alive[idx]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |a| {
                let parked = self.parked[idx].load(Ordering::SeqCst) + self.lease_parked_on(idx);
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
    /// TODO 313 item 10's RECLAIM rule, at the lease: a spilled lane
    /// stands behind every parked waiter of the other two classes.
    ///
    /// This is the whole of what keeps a spill from inverting queue
    /// priority. The head is ahead of the lane in the user's queue, so
    /// when its articles come unstuck and its parked workers ask for
    /// their sockets back, a permit the lane releases has to reach the
    /// HEAD - and `Permit::drop` wakes every parked acquirer at once, so
    /// without an ordering rule the lane's own next worker wins that
    /// race as often as not.
    #[tokio::test]
    async fn a_spilled_lane_stands_behind_a_reclaiming_head() {
        let b = ConnBudget::new();
        // Cap 4: three for a download, one held back for the reserve.
        let l = b.lease("h", 4);
        assert_eq!(l.download_cap(), 3);
        let head = l.acquire().await;
        let lane = l.acquire_as(LeaseClass::Spill).await;
        let lane2 = l.acquire_as(LeaseClass::Spill).await;
        assert_eq!(
            l.snapshot(),
            (3, 4),
            "a spill is bounded by the DOWNLOAD cap"
        );

        // The head reclaims: one of its parked workers asks for a slot.
        let lh = l.clone();
        let reclaim = tokio::spawn(async move { lh.acquire_as(LeaseClass::Reclaim).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(l.waiters(), 1);
        assert_eq!(
            l.prio_waiters(),
            1,
            "a head RECLAIMING is a priority park - an ordinary parked \
             download is not, or the reserve's own parked worker would \
             block every spill for the life of the run"
        );

        // The lane wants to grow at the same moment, and may not.
        let ls = l.clone();
        let grow = tokio::spawn(async move { ls.acquire_as(LeaseClass::Spill).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(l.prio_waiters(), 1, "and a lane's park is not");
        assert!(!grow.is_finished());

        // The lane gives one back. It must reach the head.
        drop(lane);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), reclaim)
            .await
            .expect("the head's claim outranks the lane's")
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            !grow.is_finished(),
            "the lane may not take the permit it just released while the head holds it"
        );

        // With no priority waiter left the lane may grow again.
        drop(got);
        let grown = tokio::time::timeout(std::time::Duration::from_secs(5), grow)
            .await
            .expect("a lane is not starved once nothing better is waiting")
            .unwrap();
        drop(head);
        drop(lane2);
        drop(grown);
        assert_eq!(b.held_total(), 0);
    }

    /// A spilled lane may hand a socket over BEFORE its own queue is
    /// dry, and nothing else may. The gate is shut by default, the role
    /// decides which side of it a pool is on, and both have to agree.
    #[tokio::test]
    async fn only_a_spilled_lane_hands_over_before_queue_dry() {
        let budget = ConnBudget::new();
        let lease = budget.lease("s", 1);
        let gate = SpillGate::new();
        let mut servers = one_server();
        servers[0].1.lease = Some(lease.clone());
        servers[0].1.spill = Some(SpillSeat {
            gate: gate.clone(),
            role: SpillRole::Lane,
            sockets: 0,
        });
        let reqs: Vec<ArticleReq> = vec![ArticleReq::fresh("<a0>")];
        let (shared, _) = Shared::new(reqs, &servers);

        // Somebody else parked on this account's lease - the head
        // reclaiming, in the shape this mechanism is built for.
        let held = lease.acquire().await;
        let l2 = lease.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(lease.waiters(), 1);
        shared.alive[0].store(2, Ordering::Relaxed);

        assert!(
            !shared.want_handoff(0),
            "the gate is SHUT until a governor opens an episode, so this              is the shipped rule verbatim"
        );
        gate.open();
        assert!(
            shared.want_handoff(0),
            "an open episode lifts the queue-dry gate for a lane"
        );
        gate.close();
        assert!(
            !shared.want_handoff(0),
            "and shutting it puts the gate back"
        );

        drop(held);
        drop(waiter.await.unwrap());
    }

    /// The same seat on the HEAD's side changes nothing here, which is
    /// the half that keeps a reallocated head reclaimable: a head that
    /// handed sockets over through `claim_handoff` would RETIRE those
    /// workers, `alive` does not come back inside a run, and the fleet
    /// could never be walked up again. A head lends by parking, never by
    /// shedding.
    #[tokio::test]
    async fn a_spill_head_never_hands_over_early() {
        let budget = ConnBudget::new();
        let lease = budget.lease("s", 1);
        let gate = SpillGate::new();
        let mut servers = one_server();
        servers[0].1.lease = Some(lease.clone());
        servers[0].1.spill = Some(SpillSeat {
            gate: gate.clone(),
            role: SpillRole::Head,
            sockets: 0,
        });
        let reqs: Vec<ArticleReq> = vec![ArticleReq::fresh("<a0>")];
        let (shared, _) = Shared::new(reqs, &servers);

        let held = lease.acquire().await;
        let l2 = lease.clone();
        let waiter = tokio::spawn(async move { l2.acquire().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        shared.alive[0].store(2, Ordering::Relaxed);
        gate.open();
        assert!(
            !shared.want_handoff(0),
            "an open episode gives the HEAD no new way to shed a socket"
        );
        // Past queue-dry it hands over exactly as it always did.
        *shared.tail_started.lock_ok() = Some(Instant::now());
        assert!(shared.want_handoff(0));

        drop(held);
        drop(waiter.await.unwrap());
    }

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
        // The half this test is about is the SUCCESSOR half, and it is
        // asked directly since the 1 Sep 2026 sweep: `want_handoff` is
        // that half AND `handoff_room`, and the room half is separately
        // false here for the reason the next assertion pins - the
        // surplus body parked on the lease is not a leftover. Before
        // that sweep this line read `want_handoff` and passed, which is
        // exactly the answer that gave a row's last socket away.
        assert!(
            shared.handoff_wanted(0),
            "a waiter that is not one of ours is a successor"
        );

        // 1 Sep 2026 sweep: but the reserve-parked body is not a
        // LEFTOVER either. `alive` is 2 and one of the two is parked on
        // the lease holding no permit, so granting this claim would
        // leave the row represented by a body that cannot take a
        // requeue - the shape 27 Aug finding 7 fixed for the admission
        // park, through the door the reserve opened.
        assert!(
            !shared.claim_handoff(0),
            "the reserve-parked body is not a leftover either"
        );
        assert_eq!(
            shared.handoff_out[0].load(Ordering::Relaxed),
            0,
            "a refused claim leaves nothing charged"
        );
        assert_eq!(
            shared.alive[0].load(Ordering::Relaxed),
            2,
            "and takes nobody out of `alive`"
        );

        // And the count falls back to zero when our worker gives up, so
        // a lease that outlives the run carries no charge into the next.
        drop(parked);
        assert_eq!(shared.own_lease_waiters(&lease), 0);

        // With the reserve park gone both bodies can hold a socket and
        // the same claim IS granted - so the refusal above is the
        // subtraction and not a door that shut for good.
        assert!(
            shared.want_handoff(0),
            "and the whole peek is true again once there is room"
        );
        assert!(
            shared.claim_handoff(0),
            "a row with two socket-capable bodies may hand one over"
        );
        assert_eq!(shared.alive[0].load(Ordering::Relaxed), 1);

        successor.abort();
        surplus.abort();
        let _ = successor.await;
        let _ = surplus.await;
        drop(seated);
    }

    /// TODO 313 item 8, at the lease's own level: a standing spare is
    /// bounded by the account's gap, it never gates an acquire, and a
    /// worker parked in `acquire` is not stepped in front of.
    ///
    /// The reserve's own behaviour is pinned in `crate::warmreserve`;
    /// this is the arithmetic those tests stand on.
    #[tokio::test]
    async fn a_standing_spare_is_bounded_by_the_gap_and_never_gates_a_worker() {
        let b = ConnBudget::new();
        let l = b.lease("h", 4);
        assert_eq!(l.set_spares(9), 4, "an idle account can spare all of it");
        assert_eq!(l.spares(), 4);

        // Never gates: `limit_for` does not read `spares`, so the fleet
        // walks straight in and the spare gives way inside the same lock
        // hold that admits it.
        let mut held = Vec::new();
        for i in 1..=3 {
            held.push(
                tokio::time::timeout(std::time::Duration::from_secs(5), l.acquire())
                    .await
                    .unwrap_or_else(|_| panic!("worker {i} blocked behind a spare")),
            );
            let (h, cap) = l.snapshot();
            assert!(h + l.spares() <= cap, "held {h} + spares over cap {cap}");
        }
        assert_eq!(l.spares(), 1, "three working, one slot left to spare");

        // A parked acquirer outranks a fresh ask: the reserve does not
        // take a slot out from under a fleet that is waiting for one.
        let l2 = l.clone();
        let w = tokio::spawn(async move { l2.acquire().await });
        for _ in 0..200 {
            if l.waiters() > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(l.waiters(), 1);
        assert_eq!(l.set_spares(1), 0, "a waiter outranks a new spare");

        held.clear();
        let _late = tokio::time::timeout(std::time::Duration::from_secs(5), w)
            .await
            .expect("the parked worker was woken")
            .expect("join");
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
