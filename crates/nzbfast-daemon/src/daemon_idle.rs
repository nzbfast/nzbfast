//! What the daemon does with connections when nothing is downloading,
//! and the offline switch over the top (TODO 106 code motion out of
//! daemon.rs).
//!
//! `set_offline` is the user-facing half - it stands the background legs
//! down and pauses the queue, remembering whether the pause was its own
//! so coming back does not unpause a queue the user paused. The rest is
//! the warm pool: closing it, waiting for the fleet to park before
//! clearing it, the per-server idle-release policy pushed into the pool,
//! and whether the sampler may hold a socket on a metered server at all.
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, so `Daemon`'s private fields and daemon.rs's
//! private types stay in scope exactly as they were inline. `pub(super)`
//! became `pub(crate)` for exactly that reason: `super` is
//! `daemon` here, and every call site is one level up.

use super::*;

impl Daemon {
    /// Go offline or come back, and do it NOW rather than on a timer.
    ///
    /// Offline is the instant sibling of the idle-release policy: same
    /// goal (stop occupying the account so the operator can use it from
    /// somewhere else), no waiting. It:
    ///
    /// - pauses the queue, so the outage is not spent starting jobs that
    ///   cannot connect. Without this every job would fail its way
    ///   through the queue against articles that were never missing, and
    ///   the operator would come back to a screen of red that says
    ///   nothing about what happened. The active job winds down through
    ///   the ordinary pause path and parks with its journal intact - a
    ///   one-pass extraction survives, because the journal records where
    ///   each article's bytes physically landed;
    /// - hangs up every parked connection in the warm pool, and shuts
    ///   the pool to new ones until this comes back online - the job
    ///   winding down above parks its fleet as it finishes, so a drain
    ///   on its own is undone seconds later;
    /// - stands the background legs down through
    ///   [`Self::indexing_pause_reason`], which the scan loop, the tip
    ///   watcher and the spot leg all consult, and which makes the tip
    ///   watcher QUIT the sessions it holds.
    ///
    /// Coming back online only unpauses a queue that going offline
    /// paused - see `paused_by_offline`.
    pub fn set_offline(self: &Arc<Self>, want_offline: bool) {
        let was = self.offline.swap(want_offline, Ordering::SeqCst);
        if was == want_offline {
            return;
        }
        // Cleared either way: an in-flight job has to wind down whether
        // or not this transition was the thing that paused the queue,
        // because staying connected is exactly what offline forbids.
        // Flag and deadline move under the pause_until lock so the
        // auto-resume worker's check-and-clear cannot interleave (see
        // `set_paused_cancel_timer`) - and the transition is DECIDED
        // under it too: read outside, a resume landing in between was
        // computed away and the queue stuck paused with nothing saying so.
        //
        // BOTH edges drop the deadline, which is what the generation
        // bump this replaced did: it cancelled the pending timer on the
        // way back online as well, and left the deadline behind for
        // `pause_int` to report as time still to run on a timer that had
        // already been cancelled.
        {
            let mut until = self.pause_until.lock_ok();
            let (paused, by_offline) = offline_pause_transition(
                want_offline,
                self.paused.load(Ordering::Relaxed),
                self.paused_by_offline.load(Ordering::Relaxed),
            );
            self.paused.store(paused, Ordering::Relaxed);
            self.paused_by_offline.store(by_offline, Ordering::Relaxed);
            *until = None;
        }
        // Outside the lock: the worker wakes, reads no deadline, and
        // retires rather than sleeping out the rest of a cancelled pause.
        self.pause_wake.notify_all();
        // The offline transition writes the flag under the `pause_until`
        // lock itself (the whole point of that block), so it owes the
        // edge by hand once the lock is gone. Idempotent, so the arms
        // below are free to reach paths that announce again.
        crate::announce_pause(self);
        match want_offline {
            true => {
                // The pause flag above is a START-time gate (`pick_job`);
                // nothing samples it inside a running fetch. Without the
                // wind-down below, going offline turned the dot red,
                // answered `{"offline":true}` and printed the line under
                // this comment while the active job's whole fleet stayed
                // connected and transferring - on a big job, hours of
                // exactly the occupancy the operator pressed the control
                // to end. Graceful, like every other pause path: in-flight
                // articles land and journal, so the job re-queues instead
                // of failing and a one-pass extraction survives.
                self.suspend_active(true);
                // The prefetch sidecar is its own hub and its own fleet,
                // so the signal above does not reach it. Sync context
                // here (a blocking API handler thread), so this is the
                // sync poke rather than the async `stop_sidecar`.
                self.poke_sidecar(|_| true);
                self.close_warm_pools();
                // ...and again once the fleet has parked. A graceful
                // wind-down ends with each worker HANDING its connection
                // to the warm pool (`park_or_quit`), so the clear fired
                // above drains a map those sessions have not reached yet
                // and they then sit parked for the whole idle timeout -
                // the occupancy offline exists to end.
                self.clear_warm_pool_once_the_fleet_parks();
                info!(target: "offline", "going offline: queue paused, provider connections closing");
            }
            false => {
                // The load-bearing half of `close_warm_pools`. Offline
                // stops the pool taking connections at all, and only
                // this path reopens it - leave it shut and every later
                // job silently pays the cold start again.
                if let Some(pool) = self.hub.warm.get() {
                    pool.set_accepting(true);
                }
                info!(target: "offline", "back online");
            }
        }
        persist_pause(self);
    }

    /// Hang up every parked connection now, and stop it filling back up.
    ///
    /// Both halves are needed, because the queue pause that goes with
    /// offline is a GRACEFUL wind-down: the workers finish their
    /// in-flight windows and park from the pool's drained exits, which
    /// happens over the following seconds - i.e. after the drain below.
    /// A drain alone would empty the pool and then watch the tail of the
    /// job refill it, up to 64 sessions per server, kept alive by the
    /// keepalive tick while the UI reports offline. So the flag goes
    /// down FIRST, synchronously, and is already down when the spawned
    /// clear lands. (`clear` itself must not latch it: config reloads
    /// call that, and pooling has to survive a saved password.)
    ///
    /// `clear` is async (the goodbyes run concurrently under one bound),
    /// while the callers here are sync API handlers, so this hands it to
    /// the runtime rather than blocking a handler thread on a provider
    /// that may be mute. Nothing waits on the result: the sessions are
    /// already unreachable from the pool the moment `clear` takes its
    /// lock, which is what "offline" actually promises.
    pub(crate) fn close_warm_pools(&self) {
        if let Some(pool) = self.hub.warm.get() {
            pool.set_accepting(false);
            let pool = pool.clone();
            tokio::spawn(async move { pool.clear().await });
        }
    }

    /// Hang up again once the wound-down fleet has finished parking.
    ///
    /// The second half of going offline while a job is running. A
    /// graceful wind-down does not close the fleet's sockets: each worker
    /// says goodbye to the queue and then HANDS its live connection to
    /// the warm pool (`park_or_quit`). So the `close_warm_pools()` fired
    /// at the moment of the offline call drains a map those sessions have
    /// not entered yet, and ~one fleet's worth of them park into it a
    /// second later and stay for the whole idle timeout - which is the
    /// occupancy the operator pressed the control to end.
    ///
    /// Waits on the live-connection gauge rather than on the job, for the
    /// reason `wind_down` records: a job leaves `Downloading` well before
    /// its fleet has said goodbye. Bounded, because a provider that never
    /// answers must not leave this polling forever.
    ///
    /// Re-checks `offline` every pass, and that check is load-bearing:
    /// coming back online and starting a job must not meet a clear that
    /// was armed for the previous state and QUITs the new job's freshly
    /// warmed sessions.
    pub(crate) fn clear_warm_pool_once_the_fleet_parks(self: &Arc<Self>) {
        let d = self.clone();
        tokio::spawn(async move {
            let connected = || -> usize {
                d.hub
                    .pool_live
                    .lock_ok()
                    .as_ref()
                    .map(|l| {
                        l.servers
                            .iter()
                            .map(|s| s.connected.load(Ordering::Relaxed))
                            .sum()
                    })
                    .unwrap_or(0)
            };
            let deadline = Instant::now() + OFFLINE_PARK_BUDGET;
            loop {
                if !d.offline.load(Ordering::Relaxed) {
                    return;
                }
                if connected() == 0 || Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if !d.offline.load(Ordering::Relaxed) {
                return;
            }
            // `.get()`, never the constructing accessor - see
            // `close_warm_pools` and the wind-down's note at the same
            // call: asking for the pool in order to empty it CREATES it,
            // and creation spawns a keepalive tick.
            if let Some(pool) = d.hub.warm.get() {
                pool.clear().await;
            }
        });
    }

    /// Push each server's idle-release policy into the warm pool.
    ///
    /// The pool is created lazily by the download path, which has the
    /// hub but not the daemon, so this is called from both: at job start
    /// against the config that job is about to use, and again whenever a
    /// server is saved - an operator turning this on while idle, which
    /// is exactly when they would, must not have to wait for the next
    /// download to see it take effect.
    pub fn push_idle_release_policies(&self, servers: &[nzbkit::config::ServerConfig]) {
        if let Some(pool) = self.hub.warm.get() {
            pool.set_release_policies(servers);
        }
    }

    /// How long since a download last ran, or `None` while one is
    /// running. The clock the background samplers check before deciding
    /// whether to hold a session open across their sleep.
    #[cfg(feature = "indexer")]
    pub fn download_idle_for(&self) -> Option<std::time::Duration> {
        if self.started_at.lock_ok().is_some() {
            return None;
        }
        Some(self.last_download_end.lock_ok().elapsed())
    }

    /// Should a background sampler keep its connection to THIS server
    /// open across ticks, or close it and reconnect on the next one?
    ///
    /// The samplers - the M29 availability oracle and the tip watcher -
    /// each hold one session per server for as long as the indexer is
    /// on, whether or not that server opted into warm pooling. That is a
    /// permanently occupied slot for work that uses the socket for a
    /// fraction of a second per tick, and against a provider limiting
    /// source addresses it is the whole account. Once the daemon has
    /// been download-idle past that server's release timeout they borrow
    /// a slot per tick instead of owning one: the traffic is unchanged,
    /// the occupancy drops to the length of the probe.
    ///
    /// Per server, like everything else here: a strict provider's
    /// timeout must not make the samplers churn reconnects against a lax
    /// one that never had a problem.
    ///
    /// Holding is still right while a download runs, when the account is
    /// in use by this host anyway and the reconnects would be pure cost.
    #[cfg(feature = "indexer")]
    pub fn sampler_may_hold(&self, server: &nzbkit::config::ServerConfig) -> bool {
        let Some(after) = server.idle_release_policy().after else {
            return true;
        };
        self.download_idle_for().is_none_or(|idle| idle < after)
    }
}
