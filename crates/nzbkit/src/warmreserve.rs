//! TODO 313 item 8: a STANDING WARM RESERVE - connections kept
//! authenticated and parked with nothing to do, as a surge source.
//!
//! The shape asked for, 28 Aug 2026: keep some extra lanes warm without
//! using them, except when needed, so they do not hinder normal use;
//! how many is user configurable, and even a small number may help.
//! The measurement that says a small number is the right number
//! is TODO 313 item 7's: on a head with 25% of its articles behind two
//! seconds of dead air, the first TWO extra sockets recover 23% of the
//! recoverable loss for 25% more sockets, and going to twenty-four
//! recovers 65% for 200% more. Steeply diminishing, so this defaults to
//! zero and expects a low single digit when it is on at all.
//!
//! **Most of this is [`crate::warmpool`] with one word changed.** That
//! module already holds authenticated sessions across jobs, pings them
//! so providers do not reap them, validates each one with a DATE
//! round-trip on checkout, reaps on a generation change and keys
//! everything per ACCOUNT. `WarmPool::per_server` is a CEILING on what
//! may be parked; this is a FLOOR to maintain, plus the background
//! dialler that fills it. Everything else is borrowed.
//!
//! # Not the release floor, which is in the same file and reads alike
//!
//! `WarmPool::set_release_policies` already carries a floor
//! (`ReleasePolicy::keep`, from `ServerConfig::idle_keep`), and it is a
//! different quantity in both directions:
//!
//! * the release floor is how much of an ALREADY-PARKED set survives the
//!   idle trim. It can never cause a dial, can never exceed what some
//!   job already parked, and needs no permit, because every socket it
//!   keeps was licensed by the fleet that parked it.
//! * this floor is MAINTAINED. A dialler puts sockets on the wire that
//!   no job asked for, so it is the one thing in the module that can
//!   overshoot an account, and it is the reason for every permit rule
//!   below.
//!
//! The two compose rather than fight: this reserve stands DOWN while the
//! release policy has trimmed the pool (see [`ReserveNote::Released`]),
//! so a daemon with nothing to download hands the account back exactly
//! as it did before, and there is never a tick where one refills what the
//! other just let go.
//!
//! # The correctness constraint is not memory, it is PERMITS
//!
//! Memory is trivial and was accepted up front. What a floor breaks
//! and a ceiling does not is `handoff`'s invariant that two runs on one
//! host can never hold more sockets between them than one run was
//! allowed. `WarmPool::per_server`'s own comment says the account cap is
//! respected *"because the fleet that parks them was already sized by
//! it"* - which is exactly the reasoning a PROACTIVE reserve invalidates.
//!
//! So the reserve holds [`HostLease`] slots like any other socket, and
//! is carved out of the capped fleet's headroom rather than layered on
//! top. The failure mode if it is not is in `warmpool`'s own header: the
//! 25-26 Aug 2026 live-daemon incident, *"502 connection limit (40)
//! reached"*, for hours, across a restart.
//!
//! # Sizing, and all three parts are invariants rather than policies
//!
//! The premise was RULED rather than guessed, 28 Aug 2026: an install
//! typically uses fewer connections than the maximum defined for each
//! server, so keeping a few extra lanes warm does not reach that maximum
//! - and by design cannot.
//!
//! * **`active + spares <= the configured per-server max`, always, by
//!   construction.** Held in `handoff`'s own state lock by
//!   `trim_spares`, not by this module remembering to check.
//! * **Active work outranks a parked spare for the same permit.** The
//!   reserve is never consulted for admission (`handoff`'s `limit_for`
//!   does not read it), so a fleet raised into the gap by the line-cap
//!   governor simply takes the slots and the RESERVE SHRINKS.
//! * **The configured count is a REQUEST bounded by the available gap,
//!   not a guarantee.** On a server already at max the effective reserve
//!   is zero, which is correct - and it is published rather than
//!   silently absent ([`ReserveStatus`]). The precedent for why that
//!   matters is the memory topic `nzbfast-redeploy-resets-server-enables`:
//!   a setting quietly different from what the user configured is how
//!   people lose an evening.
//!
//! # Where a reserve belongs
//!
//! Secondary and backup providers, and this is a design preference
//! rather than something to leave to a tuner: their slots are idle
//! anyway, and a spare there doubles as the cross-provider escape for
//! when the PRIMARY is what is stuck - which the study's section 2 says
//! is exactly the case a same-account surge cannot serve, because the
//! stuck server has no spare capacity to surge into.
//!
//! `0` on any `block_account` server, always: a warm spare on a metered
//! account is paid-for headroom doing nothing, and it is the same
//! question every other speculative picker on the tree has to ask.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::config::ServerConfig;
use crate::nntp::Connection;
use crate::pool::handoff::{ConnBudget, HostLease};
use crate::sync::MutexExt;
use crate::warmpool::WarmPool;

/// How often the dialler reconciles its floor.
///
/// Deliberately shorter than `warmpool::KEEPALIVE_EVERY` (60 s), which
/// is a REAPER's cadence: a minute is fine for noticing that a parked
/// session died, and far too slow for a reserve that has just been
/// revoked by a fleet growing and wants to be back before the next
/// stall. Deliberately not seconds either - the tick's only work when
/// there is nothing to do is one lock and one map lookup per server, but
/// each dial it does make is a real authenticated session on the user's
/// account, and a fast loop against a provider that is refusing is a
/// dial storm with a timer on it.
pub const RESERVE_EVERY: Duration = Duration::from_secs(15);

/// Why the effective reserve is not the configured number.
///
/// A closed set rather than a free string so the daemon's echo and the
/// tests read the same values, and so a new reason cannot be added
/// without deciding what it says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveNote {
    /// Effective == configured. Nothing to say.
    Held,
    /// Not asked for - the default, and the whole feature is inert.
    Off,
    /// This server is switched off in the config.
    Disabled,
    /// `block_account`: every byte here is billed, so paid-for headroom
    /// doing nothing is never the right trade.
    Metered,
    /// The server has not opted into `warm_pool`, so its fleet never
    /// CHECKS OUT a parked session (`get::fleet` passes no pool). A
    /// reserve nobody may take from is pure cost, so there is not one.
    PoolOffForServer,
    /// The daemon is offline or shutting down (`WarmPool::accepting` is
    /// false), so nothing is being parked at all.
    PoolClosed,
    /// The pool has gone untouched long enough for that server's own
    /// idle-release policy to hand the account back. The reserve stands
    /// down with it rather than refilling what the release just freed.
    Released,
    /// The account's own cap leaves less room than was asked for - the
    /// live fleet is using it. Zero here is the "already at max" case
    /// and is correct.
    AccountAtCap,
}

impl ReserveNote {
    /// One line, for the daemon's echo and its log. Present tense, no
    /// dashes, and it says what is true rather than what failed.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "",
            Self::Off => "no reserve configured",
            Self::Disabled => "server disabled",
            Self::Metered => "block account: never held warm",
            Self::PoolOffForServer => "connection pooling is off for this server",
            Self::PoolClosed => "the connection pool is closed",
            Self::Released => "released while idle, so the account is free",
            Self::AccountAtCap => "the live fleet is using this account's connections",
        }
    }
}

/// What one server's reserve is doing right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveStatus {
    pub host: String,
    /// `ConnBudget::key` - the ACCOUNT, which is what a cap belongs to.
    pub key: String,
    /// What the user asked for, after the sanity clamp.
    pub configured: usize,
    /// What the account can actually spare, which is the number that is
    /// true.
    pub effective: usize,
    /// Sessions parked for this identity right now, reserve's or a
    /// finished job's - the floor is measured against the pool, not
    /// against a private set.
    pub parked: usize,
    pub note: ReserveNote,
}

impl ReserveStatus {
    /// Is this a case somebody should be told about: a reserve that was
    /// asked for and is not being held?
    pub fn shortfall(&self) -> bool {
        self.configured > 0 && self.effective < self.configured
    }
}

/// What this server is asking for, and why it is asking for nothing when
/// it is asking for nothing.
///
/// Pure and separate from the tick so the rules can be tested without a
/// provider, a runtime or a lease.
///
/// The clamp is to the server's own `connections`: a reserve larger than
/// the account's whole connection count is not a number anybody can mean,
/// and clamping here rather than at the lease keeps the CONFIGURED figure
/// in [`ReserveStatus`] a number the user could actually have.
pub fn request_for(s: &ServerConfig) -> (usize, ReserveNote) {
    let asked = (s.warm_reserve.unwrap_or(0) as usize).min(s.connections.max(1) as usize);
    if asked == 0 {
        return (0, ReserveNote::Off);
    }
    if !s.enabled {
        return (0, ReserveNote::Disabled);
    }
    if s.block_account {
        return (0, ReserveNote::Metered);
    }
    if !s.warm_pool {
        return (0, ReserveNote::PoolOffForServer);
    }
    (asked, ReserveNote::Held)
}

/// The dialler that maintains the floor.
///
/// One per daemon, holding the same [`WarmPool`] the jobs park into and
/// the same [`ConnBudget`] they take their permits from - a reserve on a
/// pool or a budget of its own would be the second fleet this module
/// exists to prevent.
pub struct WarmReserve {
    warm: Arc<WarmPool>,
    budget: Arc<ConnBudget>,
    /// The config as of the last job. Replaced wholesale by
    /// [`Self::set_servers`], which the daemon calls at the same seam it
    /// reconciles the warm pool at.
    servers: std::sync::Mutex<Vec<ServerConfig>>,
    /// Leases this reserve currently holds spares on, so a server that
    /// leaves the config gets its slots back on the next tick instead of
    /// when the daemon restarts.
    ///
    /// Keyed by ACCOUNT, so two config rows that are the same account
    /// (`ConnBudget::key` is host, port and user - the collapse the
    /// memory topic `nzbfast-same-host-account-identity` records)
    /// collapse to one entry here too. Since `HostLease::set_spares` is
    /// a LEVEL, that means such a pair holds the LAST row's ask rather
    /// than the sum of the two, which is the conservative answer and the
    /// right one: there is one account and one cap, so there is one
    /// reserve.
    held: std::sync::Mutex<HashMap<String, Arc<HostLease>>>,
    status: std::sync::Mutex<Vec<ReserveStatus>>,
    dialled: AtomicU64,
    dial_failures: AtomicU64,
}

impl Drop for WarmReserve {
    /// Hand every slot back. The lease outlives this type (one per
    /// account for the daemon's life), so a dropped reserve that kept
    /// its count would pin those connections against the account with
    /// nothing left to release them.
    fn drop(&mut self) {
        for lease in self.held.lock_ok().values() {
            lease.set_spares(0);
        }
    }
}

impl WarmReserve {
    /// Build a reserve and spawn its tick. Like `WarmPool::new`, the
    /// tick stops when the last strong reference goes.
    pub fn new(warm: Arc<WarmPool>, budget: Arc<ConnBudget>) -> Arc<WarmReserve> {
        let me = Arc::new(WarmReserve {
            warm,
            budget,
            servers: std::sync::Mutex::new(Vec::new()),
            held: std::sync::Mutex::new(HashMap::new()),
            status: std::sync::Mutex::new(Vec::new()),
            dialled: AtomicU64::new(0),
            dial_failures: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&me);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RESERVE_EVERY).await;
                let Some(r) = weak.upgrade() else { return };
                r.tick().await;
            }
        });
        me
    }

    /// Point the reserve at the config the daemon has just loaded.
    ///
    /// Sync, like `WarmPool::set_release_policies` beside it and for the
    /// same reason: the callers are config paths, not async ones.
    pub fn set_servers(&self, servers: &[ServerConfig]) {
        *self.servers.lock_ok() = servers.to_vec();
    }

    /// What every configured server's reserve is doing, for the daemon's
    /// diagnostics. Empty until the first tick.
    pub fn status(&self) -> Vec<ReserveStatus> {
        self.status.lock_ok().clone()
    }

    /// This server's status, by account key.
    pub fn status_for(&self, server: &ServerConfig) -> Option<ReserveStatus> {
        let key = ConnBudget::key(server);
        self.status.lock_ok().iter().find(|s| s.key == key).cloned()
    }

    /// Sessions this reserve has dialled, and dials that failed. For the
    /// tests and for a future diagnostics row.
    pub fn counts(&self) -> (u64, u64) {
        (
            self.dialled.load(Ordering::Relaxed),
            self.dial_failures.load(Ordering::Relaxed),
        )
    }

    /// One reconciliation: decide each server's effective reserve, take
    /// or give back the slots, and dial whatever the pool is short.
    ///
    /// Public so the tests can drive it without waiting out
    /// [`RESERVE_EVERY`]; the daemon only ever gets it from the spawned
    /// tick.
    pub async fn tick(&self) {
        let servers = self.servers.lock_ok().clone();
        let accepting = self.warm.accepting();
        let idle_for = self.warm.idle_for();
        let mut status = Vec::with_capacity(servers.len());
        let mut keep: HashMap<String, Arc<HostLease>> = HashMap::new();
        let mut to_dial: Vec<(ServerConfig, Arc<HostLease>, usize)> = Vec::new();
        for s in &servers {
            let (mut want, mut note) = request_for(s);
            // Both of these leave `configured` alone and zero the ask, so
            // the shortfall is reported rather than looking like a server
            // that never asked for anything.
            if want > 0 && !accepting {
                want = 0;
                note = ReserveNote::PoolClosed;
            }
            // Stand down with the release policy rather than against it.
            // `after: None` is the install that is its account's only
            // consumer (a NAS, a seedbox), which never releases and where
            // a standing reserve costs nobody anything - so it never
            // stands down either.
            if want > 0
                && let Some(after) = s.idle_release_policy().after
                && idle_for >= after
            {
                want = 0;
                note = ReserveNote::Released;
            }
            let key = ConnBudget::key(s);
            // BORROW the lease wherever one exists, and state a cap only
            // for an account no job has reached yet. `ConnBudget::lease`
            // RE-POINTS the cap to the caller's own figure, and the
            // reserve is the last caller that should be deciding how wide
            // a fleet may run: a running job's line cap or conntune knee
            // may have put the number well under the configured
            // `connections`, and re-pointing it up from here would undo
            // that on every tick. Same rule, and the same reason, as a
            // spilled lane's `lease_borrowed` (TODO 313 item 10).
            //
            // A server asking for NOTHING never creates one. With the
            // feature off - which is every install by default - this
            // whole module must leave the daemon's accounting exactly
            // where it found it, and minting a lease for an account no
            // job has touched is not that.
            let lease = match want {
                0 => self.budget.lease_borrowed(&key),
                _ => Some(match self.budget.lease_borrowed(&key) {
                    Some(l) => l,
                    // Nothing has downloaded on this account yet, so
                    // nothing has an opinion about its width but the
                    // user. Stating it here is what lets the reserve be
                    // STANDING - warm before the first job rather than
                    // after it.
                    None => self.budget.lease(&key, s.connections.max(1) as usize),
                }),
            };
            let effective = lease.as_ref().map_or(0, |l| l.set_spares(want));
            if let Some(l) = lease.as_ref().filter(|_| effective > 0) {
                keep.insert(key.clone(), l.clone());
            }
            if want > 0 && effective < want {
                note = ReserveNote::AccountAtCap;
            }
            let parked = match effective > 0 {
                true => self.warm.parked_for(s).await,
                // Nothing to compare a floor against, and a map lock per
                // configured server per tick for a feature nobody turned
                // on is a cost with no reader.
                false => 0,
            };
            let short = effective.saturating_sub(parked);
            if let (Some(l), true) = (lease, short > 0) {
                to_dial.push((s.clone(), l, short));
            }
            status.push(ReserveStatus {
                host: s.host.clone(),
                key,
                configured: (s.warm_reserve.unwrap_or(0) as usize)
                    .min(s.connections.max(1) as usize),
                effective,
                parked,
                note,
            });
        }
        // Servers that left the config, or whose reserve went to zero,
        // release the slots they were holding. Done from the recorded set
        // rather than from the config, because a server REMOVED from the
        // config is exactly the case the config can no longer name.
        {
            let mut held = self.held.lock_ok();
            for (k, lease) in held.iter() {
                if !keep.contains_key(k) {
                    lease.set_spares(0);
                }
            }
            *held = keep;
        }
        *self.status.lock_ok() = status;
        for (s, lease, n) in to_dial {
            self.fill(&s, &lease, n).await;
        }
    }

    /// Dial `n` sessions for one server and park them.
    ///
    /// Concurrently, for the reason `warmpool::quit_all` gives for the
    /// same shape: a dial has its own 20 s timeout, and serially a
    /// handful against an unreachable provider would outlast the interval
    /// this tick is due again in.
    async fn fill(&self, s: &ServerConfig, lease: &Arc<HostLease>, n: usize) {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..n {
            let s = s.clone();
            set.spawn(async move { (Connection::connect(&s).await, s) });
        }
        while let Some(joined) = set.join_next().await {
            let Ok((dialed, s)) = joined else { continue };
            let Ok((conn, _)) = dialed else {
                self.dial_failures.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // Re-check under the answer rather than under the ask. The
            // slot was reserved before this dial and the fleet may have
            // taken it back while the dial was in flight (`trim_spares`
            // is synchronous and this is not), and the pool may have gone
            // offline. Parking anyway would be exactly the unlicensed
            // socket this module exists to prevent - so it says goodbye
            // instead, which is what gives the provider its slot back on
            // a session-counting account.
            if !self.warm.accepting() || lease.spares() == 0 {
                conn.quit().await;
                continue;
            }
            self.dialled.fetch_add(1, Ordering::Relaxed);
            self.warm.give(&s, conn).await;
        }
    }
}

#[cfg(test)]
mod tests;
