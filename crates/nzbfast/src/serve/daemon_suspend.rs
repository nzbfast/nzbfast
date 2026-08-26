//! Winding down the running transfer without ending the job (TODO 106
//! code motion out of daemon.rs).
//!
//! `suspend_matching` marks the jobs a predicate accepts as suspended
//! and then drives the wind-down machinery at them until they actually
//! stop; `suspend_active` is the all-jobs case, and `fire_pause` is the
//! one shot at the hub the loop repeats. A suspended job STAYS IN THE
//! QUEUE and resumes from the article journal, so bytes already on disk
//! are never re-downloaded - which is what makes this a different
//! subject from either neighbour, and why it is not folded into one of
//! them. daemon_park.rs is how a job stops running FOR GOOD (the
//! failure report, the park into history); daemon_shutdown.rs is how
//! the DAEMON stops, plus the timer that pauses the whole QUEUE for N
//! minutes. This is per-JOB and reversible, and five of its seven
//! callers - the pause button, the *arr remote facade, the scheduler,
//! slowstore's slow-disk hold and the idle-release policy - are in
//! neither of those files.
//!
//! Three incidents are recorded in the comments below and all three are
//! the same mistake in different clothes: assuming that marking a job
//! paused is the same as stopping the transfer it owns. `g.paused`
//! alone only bites when a job NEXT enters the queue, the wind-down
//! signal is GLOBAL so it lands on whoever owns the hub rather than on
//! whoever was named, and a job in its post-network tail has no
//! transfer to wind down at all - marking that one suspended turned an
//! unpack failure into a silent re-queue. Read them before changing the
//! predicate, the ownership re-check or the tail-phase guard.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`hub`, `queue`) stay in scope exactly as they were
//! inline. `pub(super)` becomes `pub(in crate::serve)` here, because
//! `super` is `daemon` from inside a child, and every call site is one
//! level up. The three are inherent methods on `Daemon`, so nothing
//! needs re-exporting.

use super::*;

impl Daemon {
    /// Fire the pause signal once. `hard` = the immediate abort (drop
    /// in-flight reads, they re-download on resume); otherwise the graceful
    /// drain (admit no new work, let in-flight finish and journal).
    pub(in crate::serve) fn fire_pause(&self, hard: bool) {
        if hard {
            if let Some(f) = self.hub.abort.lock_ok().as_ref() {
                f.store(true, Ordering::Relaxed);
            }
            if let Some(c) = self.hub.queue_ctl.lock_ok().as_ref() {
                c.abort();
            }
        } else if let Some(c) = self.hub.queue_ctl.lock_ok().as_ref() {
            c.drain();
        }
    }

    /// Pause the active download. `graceful` winds it down - no new
    /// articles admitted, everything in flight finishes and journals, so a
    /// resume re-fetches only the unstarted queue. `graceful = false` is
    /// the immediate abort (frees the line at once; in-flight re-downloads).
    pub(in crate::serve) fn suspend_active(self: &Arc<Self>, graceful: bool) {
        self.suspend_matching(graceful, |_| true)
    }

    /// Wind down the running transfer, but only for jobs `want` accepts.
    ///
    /// M23e: pause means PAUSE. Abort the active transfer (Force jobs
    /// are exempt, SAB semantics) after marking it suspended - the tail
    /// handler re-queues it instead of failing it, and the article
    /// journal makes the eventual resume fetch only what's still
    /// missing. Bytes already on disk are never re-downloaded.
    ///
    /// Pausing ONE job used to set `g.paused` and stop there: the flag
    /// only takes effect when a job next enters the queue, so pausing the
    /// item that was actually downloading left it transferring at full
    /// speed while both API facades answered success and kept reporting
    /// it as Downloading. Only the global pause was wired to the
    /// wind-down machinery. The daemon runs one job at a time, so
    /// scoping that machinery by predicate is all a per-job pause needs.
    pub(in crate::serve) fn suspend_matching(
        self: &Arc<Self>,
        graceful: bool,
        want: impl Fn(&Job) -> bool,
    ) {
        let mut paused: Vec<String> = Vec::new();
        for j in self.queue.lock_ok().iter() {
            let mut g = j.lock_ok();
            if !want(&g) {
                continue;
            }
            // A job in its post-network tail has no transfer left to wind
            // down, and marking it suspended did real damage: it read
            // "Paused" in every client while its repair and unpack
            // carried on, and the tail-completion arm treats
            // `suspended && res.is_err()` as "the user paused this" and
            // puts the job back in the QUEUE - so a pause-all issued
            // during an unpack turned that unpack's failure into a
            // silent re-queue, with no history record and no failure
            // notification. `state == Downloading` cannot tell the two
            // apart on its own; the pipeline's phase word can - for the
            // whole tail, hand-off window included, which is why every
            // token past the network has an arm in `tail_phase`.
            if g.state == JobState::Downloading
                && g.priority < 2
                && !g.tombstone
                && self.tail_phase(&g.nzo_id).is_none()
            {
                g.suspended = true;
                paused.push(g.nzo_id.clone());
                info!(
                    target: "pause",
                    "{} {} - resumes from the journal",
                    if graceful {
                        "winding down"
                    } else {
                        "suspending"
                    },
                    g.nzo_id
                );
            }
        }
        // The wind-down machinery is global - it signals whichever job
        // owns the hub - so pausing ONE job may only drive it when that
        // job is the owner. `state == Downloading` is not that test (see
        // `owns_hub`): pausing job N during its post-network tail drained
        // job N+1 instead, and N+1's own tail reads N+1's `suspended`
        // (false), so it was never re-queued - it just failed. The
        // re-fire loop below made it worse by firing every 250 ms for up
        // to 60 s and escalating to a hard abort at ~10 s, so a job
        // started after a quick resume could be killed too. Every matched
        // job is still marked suspended above; only the SIGNAL is scoped.
        // The ownership re-check inside the loop is what stops the next
        // owner inheriting this pause.
        //
        // Note `active_stream` is published before the hub handles are
        // installed, so the "signal landed in the gap" race the loop
        // exists for is unaffected: ownership is already true while
        // fire_pause is still a no-op, and the loop keeps retrying.
        let owner_paused =
            |d: &Arc<Self>, ids: &[String]| d.owns_hub(|id| ids.iter().any(|s| s == id));
        if !paused.is_empty() {
            // The pipeline installs its hub abort/queue-ctl handles
            // asynchronously after launch (the same race stop_sidecar
            // re-fires around): a single signal can land in the gap
            // before QueueControl attaches and no-op, leaving the
            // transfer running while the job reads as suspended.
            // Re-fire until the tail handler actually parks it. First
            // shot goes out inline so the transfer is already stopping
            // by the time the pause API call returns.
            if owner_paused(self, &paused) {
                self.fire_pause(!graceful);
            }
            // A job that handed the hub over but is still draining behind
            // the new one holds its own stop handles in the drain slot,
            // and they are the ONLY way to wind it down. Aimed by id, so
            // the successor is never touched.
            self.fire_drain(!graceful, |id| paused.iter().any(|s| s == id));
            let d = self.clone();
            std::thread::spawn(move || {
                for i in 0..240 {
                    let live = d.queue.lock_ok().iter().any(|j| {
                        let g = j.lock_ok();
                        g.suspended
                            && g.state == JobState::Downloading
                            && !g.tombstone
                            && paused.iter().any(|s| *s == g.nzo_id)
                    });
                    if !live {
                        return;
                    }
                    // Ownership can change under us - job N+1 takes the
                    // hub while N's tail runs - so re-check every pass
                    // rather than inheriting the pause onto whoever is
                    // downloading now.
                    if !d.owns_hub(|id| paused.iter().any(|s| s == id)) {
                        // Not the hub's - but it may be the job draining
                        // behind it, whose handles are in the drain slot.
                        // Same escalation, same aim-by-id.
                        d.fire_drain(!graceful || i >= 40, |id| paused.iter().any(|s| s == id));
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        continue;
                    }
                    // A graceful pause lets in-flight articles finish, but
                    // not forever: after ~10 s escalate to a hard abort so
                    // one pathological article can't stall the pause (what
                    // already drained is journaled, so nothing extra is
                    // lost by then aborting the stragglers).
                    d.fire_pause(!graceful || i >= 40);
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            });
        }
    }
}
