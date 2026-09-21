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
//! inline. `pub(super)` becomes `pub(crate)` here, because
//! `super` is `daemon` from inside a child, and every call site is one
//! level up. The three are inherent methods on `Daemon`, so nothing
//! needs re-exporting.

use super::*;

/// Does this job run THROUGH a queue-wide pause?
///
/// Force priority does - SABnzbd semantics, and what `pick_job` has
/// always done (`queue_paused && priority < 2` is the only thing a queue
/// pause holds back). What Force never outranked is the job's OWN pause
/// flag: `pick_job` skips `g.paused` at any priority, and this is the
/// same rule read from the wind-down side. Until 21 Sep 2026 the
/// wind-down tested `priority < 2` alone, so pausing an ACTIVE Force job
/// by name set its flag, answered success and left the transfer running
/// at full speed - the row's own Pause did nothing to the one kind of row
/// most likely to be running.
///
/// One place, so the wind-down and the pause payload
/// (`Daemon::pause_exempt`) cannot drift apart on what "exempt" means.
pub(crate) fn runs_through_queue_pause(g: &Job) -> bool {
    g.priority >= 2 && !g.paused
}

/// Does this job keep transferring through the wind-down being asked for
/// RIGHT NOW? A pause exempts Force ([`runs_through_queue_pause`]);
/// OFFLINE exempts nothing.
///
/// Offline is a promise about the network in absolute terms - the confirm
/// dialog says every connection is closed "so you can use the account from
/// another machine", and the runner refuses to START any job, Force
/// included, while it holds (TODO 65). The wind-down has to keep the same
/// promise for the job already on the wire: until 21 Sep 2026 it read only
/// the priority, so pressing Offline over a running Force job answered
/// success, turned the dot red and left the whole fleet connected, and the
/// operator's other machine was refused at the account's connection cap.
///
/// `offline` is passed in rather than read, so one wind-down pass judges
/// every job under the same reading.
pub(crate) fn exempt_from_wind_down(g: &Job, offline: bool) -> bool {
    runs_through_queue_pause(g) && !offline
}

impl Daemon {
    /// The jobs a queue pause is NOT stopping: on the wire now, because
    /// Force priority runs through a pause (see
    /// `runs_through_queue_pause`). Empty when the queue is not paused,
    /// and empty for a job that is already winding down or is past its
    /// network phase. Empty under OFFLINE as well, for the reason
    /// `exempt_from_wind_down` gives: offline stops Force too, so
    /// there is nothing to name and the header must not say forced
    /// downloads keep running.
    ///
    /// This is the truth the header's "paused" needs to carry. A pause
    /// that leaves a Force download running at line rate reads, in every
    /// client, as a pause that did nothing - it was reported on 21 Sep
    /// 2026 as "didn't pause at all" over a duplicate the user had
    /// released with the row's download-anyway control, which sets Force.
    /// Nothing was broken in that wind-down; the page just said `paused`
    /// over a queue that was, by design, still moving. Ids only: the row
    /// already says what it is.
    ///
    /// The prefetch sidecar counts too - it is a transfer, and a Force
    /// job it serves is exempt by the same rule.
    pub fn pause_exempt(&self) -> Vec<String> {
        if !self.paused.load(Ordering::Relaxed) || self.offline.load(Ordering::SeqCst) {
            return Vec::new();
        }
        // Before the queue lock: the sidecar mutex under queue+job would
        // be a new lock edge (see `sidecar_owner`).
        let sidecar = self.sidecar_owner().map(|(id, _)| id);
        let mut out: Vec<String> = Vec::new();
        for j in self.queue.lock_ok().iter() {
            let g = j.lock_ok();
            if g.tombstone || !runs_through_queue_pause(&g) {
                continue;
            }
            let on_wire = match g.state {
                JobState::Downloading => !g.suspended && self.tail_phase(&g.nzo_id).is_none(),
                // A prefetch serves a still-Queued record.
                JobState::Queued => sidecar.as_deref() == Some(g.nzo_id.as_str()),
                _ => false,
            };
            if on_wire {
                out.push(g.nzo_id.clone());
            }
        }
        out
    }

    /// A priority write just landed on `ids`: make any pause that was
    /// standing aside for them take effect NOW.
    ///
    /// Force runs through a queue pause (`runs_through_queue_pause`),
    /// so a Force job that is on the wire when the queue is paused keeps
    /// transferring - by design, and `suspend_matching` says so in the log
    /// and `pause_exempt` says so in the payload. Lowering that job's
    /// priority is the user withdrawing the exemption, and nothing then
    /// re-ran the wind-down: the priority write changed a number, the
    /// answer was success, the header still read "paused" and the job
    /// went on pulling at line rate until it finished (the pause was
    /// pressed, the exemption was lifted, and neither did anything). This
    /// is the missing half - the same wind-down a fresh pause runs, aimed
    /// at the rows that were written and only at those.
    ///
    /// What counts as "a pause that should now bite" is the queue-wide
    /// pause OR the row's own flag, which is what `pick_job` reads and
    /// what a re-hold to Duplicate priority sets. With neither, a
    /// priority write must NOT touch the transfer - `suspend_matching`
    /// marks any Downloading row its predicate accepts, whether or not a
    /// pause is in force, so the guard lives HERE and not there. An
    /// already-winding-down row is skipped, so a second write does not
    /// start a second re-fire loop. Quota, disk and postproc holds are
    /// deliberately not in this: they gate a START (`download_guards`)
    /// and nothing anywhere winds a running job down for them.
    ///
    /// Call it with no queue or job lock held: it takes both, like every
    /// caller of `suspend_matching`. The prefetch sidecar and the
    /// drain-behind job ride the same path (`wind_sidecar`, `fire_drain`),
    /// so a Force job that is running through either is covered too.
    pub fn wind_down_unforced(self: &Arc<Self>, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let queue_paused = self.paused.load(Ordering::Relaxed);
        let stops = |g: &Job| {
            ids.contains(&g.nzo_id)
                && !g.tombstone
                && !g.suspended
                && !runs_through_queue_pause(g)
                && (queue_paused || g.paused)
        };
        // The one-line answer to "is there anything to wind down", so an
        // ordinary priority write on an unpaused queue costs a scan and
        // no signal at all.
        let any = self.queue.lock_ok().iter().any(|j| stops(&j.lock_ok()));
        if any {
            self.suspend_matching(true, stops);
        }
    }

    /// Fire the pause signal once. `hard` = the immediate abort (drop
    /// in-flight reads, they re-download on resume); otherwise the graceful
    /// drain (admit no new work, let in-flight finish and journal).
    pub(crate) fn fire_pause(&self, hard: bool) {
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
    pub(crate) fn suspend_active(self: &Arc<Self>, graceful: bool) {
        self.suspend_matching(graceful, |_| true)
    }

    /// Wind down the running transfer, but only for jobs `want` accepts.
    ///
    /// M23e: pause means PAUSE. Abort the active transfer (Force jobs
    /// are exempt from a pause, SAB semantics, and never from OFFLINE -
    /// see `exempt_from_wind_down`) after marking it suspended - the tail
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
    pub fn suspend_matching(self: &Arc<Self>, graceful: bool, want: impl Fn(&Job) -> bool) {
        let mut paused: Vec<String> = Vec::new();
        // The prefetch sidecar runs a still-Queued record on a hub of its
        // own, so neither the state test below nor `fire_pause` (which
        // signals the daemon hub) can see it. Snapshotted before the
        // queue lock - see `sidecar_owner` for the lock order.
        let sidecar = self.sidecar_owner().map(|(id, _)| id);
        let mut wind_sidecar = false;
        // One reading for the whole pass, so every job is judged under the
        // same wind-down: offline exempts NOBODY, Force included (see
        // `exempt_from_wind_down`).
        let offline = self.offline.load(Ordering::SeqCst);
        for j in self.queue.lock_ok().iter() {
            let mut g = j.lock_ok();
            if !want(&g) {
                continue;
            }
            let exempt = exempt_from_wind_down(&g, offline);
            // Said out loud, once per Force job the pause would have
            // spared: the pause path prints "keeps downloading" for the
            // job it leaves alone, and this is the matching line for the
            // job offline does NOT leave alone, so a log reader can tell
            // a Force job that stopped for Offline from one that was
            // never asked.
            let force_stopped_by_offline = offline
                && runs_through_queue_pause(&g)
                && !g.tombstone
                && !g.suspended
                && self.tail_phase(&g.nzo_id).is_none();
            if sidecar.as_deref() == Some(g.nzo_id.as_str()) && !g.tombstone && !exempt {
                wind_sidecar = true;
                if force_stopped_by_offline {
                    info!(
                        target: "offline",
                        "{} is Force priority and its early start is stopped anyway - offline \
                         outranks Force; it resumes when you go back online",
                        g.nzo_id
                    );
                }
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
                && !exempt
                && !g.tombstone
                && self.tail_phase(&g.nzo_id).is_none()
            {
                g.suspended = true;
                paused.push(g.nzo_id.clone());
                if force_stopped_by_offline {
                    info!(
                        target: "offline",
                        "{} is Force priority and is stopped anyway - offline outranks Force; \
                         it stays queued and resumes from the journal when you go back online",
                        g.nzo_id
                    );
                }
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
            } else if g.state == JobState::Downloading
                && exempt
                && !g.tombstone
                && !g.suspended
                && self.tail_phase(&g.nzo_id).is_none()
            {
                // Said out loud, because the alternative is a "paused"
                // header over a transfer nothing in the log accounts for
                // (the 21 Sep 2026 report: one `downloads paused` line
                // and no other word from this path, over a job that kept
                // pulling 110 MB/s for minutes).
                info!(
                    target: "pause",
                    "{} keeps downloading - Force priority runs while the queue is paused \
                     (pause the download itself, or lower its priority, to stop it)",
                    g.nzo_id
                );
            }
        }
        // A prefetch for a matched job stops with it. Until 21 Sep 2026
        // only the runner's job-end `stop_sidecar` did that, which is no
        // stop at all while an exempt (Force) primary keeps the runner
        // busy: the early start went on pulling the NEXT job's articles
        // through a pause for as long as the primary ran.
        if wind_sidecar {
            self.poke_sidecar(|id| sidecar.as_deref() == Some(id));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::test_daemon;

    fn tmp(tag: &str) -> crate::testscratch::ScratchDir {
        let d = std::env::temp_dir().join(format!("nzbfast-suspend-{tag}-{}", std::process::id()));
        crate::testscratch::ScratchDir::attach(&d)
    }

    /// A record in `state`, shaped like the runner leaves one.
    fn row(id: &str, state: &str, priority: i32, paused: bool) -> Arc<Mutex<Job>> {
        let mut j = crate::job_from_json(&serde_json::json!({
            "nzo_id": id,
            "name": id,
            "out_dir": "/tmp/o",
            "nzb_path": "/tmp/n.nzb",
            "state": "Queued",
            "priority": priority,
            "paused": paused,
            "total_bytes": 1000u64,
        }))
        .unwrap();
        // Set after the load, which re-queues an interrupted download
        // (a restored row is never mid-transfer).
        j.state = match state {
            "Downloading" => JobState::Downloading,
            _ => JobState::Queued,
        };
        Arc::new(Mutex::new(j))
    }

    fn suspended(d: &Daemon, id: &str) -> bool {
        d.queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .is_some_and(|j| j.lock_ok().suspended)
    }

    /// Let the 60 s re-fire loop a wind-down starts retire: it exits the
    /// moment no matched job is still `suspended` and `Downloading`.
    fn settle(d: &Daemon) {
        for j in d.queue.lock_ok().iter() {
            j.lock_ok().state = JobState::Queued;
        }
    }

    /// 21 Sep 2026: a global pause pressed over a running download "did
    /// not pause at all". The wind-down was right and the words were not:
    /// the job was Force (the row's download-anyway button sets it), Force
    /// runs through a queue pause by SAB semantics, and nothing in the
    /// header, the pause answer or the log said so. This pins both halves
    /// - the exemption stands, and it is NAMED.
    #[test]
    fn a_queue_pause_leaves_a_force_job_on_the_wire_and_says_so() {
        let dir = tmp("force");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("forced", "Downloading", 2, false));
        d.paused.store(true, Ordering::Relaxed);

        d.suspend_active(true);

        assert!(
            !suspended(&d, "forced"),
            "Force runs through a queue pause - that semantic is not this fix's to change"
        );
        assert_eq!(d.pause_exempt(), vec!["forced".to_string()]);
        settle(&d);
    }

    /// The same pause over an ordinary job: it winds down, and the
    /// exemption list stays empty, so the header claims nothing extra.
    #[test]
    fn a_queue_pause_winds_an_ordinary_job_down_and_exempts_nothing() {
        let dir = tmp("plain");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("plain", "Downloading", 0, false));
        d.paused.store(true, Ordering::Relaxed);

        d.suspend_active(true);

        assert!(suspended(&d, "plain"));
        assert!(d.pause_exempt().is_empty(), "{:?}", d.pause_exempt());
        settle(&d);
    }

    /// No pause, no exemption: the list is a statement about a pause in
    /// force, and a Force job downloading on an unpaused queue is just a
    /// download.
    #[test]
    fn nothing_is_exempt_from_a_pause_that_is_not_in_force() {
        let dir = tmp("nopause");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("forced", "Downloading", 2, false));
        assert!(d.pause_exempt().is_empty());
    }

    /// A job already winding down, in its post-network tail, or deleted
    /// is not on the wire, so it is not "still downloading" either.
    #[test]
    fn a_winding_down_or_finished_force_job_is_not_reported_as_running() {
        let dir = tmp("notwire");
        let d = test_daemon(&dir);
        let winding = row("winding", "Downloading", 2, false);
        winding.lock_ok().suspended = true;
        let tail = row("tail", "Downloading", 2, false);
        let gone = row("gone", "Downloading", 2, false);
        gone.lock_ok().tombstone = true;
        d.queue.lock_ok().push_back(winding);
        d.queue.lock_ok().push_back(tail);
        d.queue.lock_ok().push_back(gone);
        d.queue
            .lock_ok()
            .push_back(row("waiting", "Queued", 2, false));
        d.hub
            .activity
            .lock_ok()
            .insert("tail".to_string(), "extracting");
        d.paused.store(true, Ordering::Relaxed);

        assert!(d.pause_exempt().is_empty(), "{:?}", d.pause_exempt());
    }

    /// The bug this change found on the way: Force outranks a QUEUE pause
    /// and never a job's OWN. `apply_pause` sets the flag, the wind-down
    /// then skipped the row for `priority < 2` alone, and the transfer ran
    /// at full speed under an API answer of success.
    #[test]
    fn pausing_an_active_force_job_by_name_winds_it_down() {
        let dir = tmp("byname");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("forced", "Downloading", 2, true));

        d.suspend_matching(true, |g| g.nzo_id == "forced");

        assert!(
            suspended(&d, "forced"),
            "a Force job carrying its own pause flag kept transferring"
        );
        settle(&d);
    }

    /// OFFLINE OUTRANKS FORCE (TODO 65), on the wind-down side. Force runs
    /// through a queue PAUSE, and the test above pins that. It must not
    /// run through OFFLINE: the promise is that every connection is
    /// closed so the account can be used from another machine, and the
    /// wind-down used to read only the priority, so a Force job already
    /// transferring when Offline was pressed kept its whole fleet open.
    #[test]
    fn going_offline_winds_a_force_job_down_where_a_pause_does_not() {
        let dir = tmp("offforce");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("forced", "Downloading", 2, false));
        // What `set_offline(true)` leaves behind: the flag, and the queue
        // pause that goes with it.
        d.offline.store(true, Ordering::SeqCst);
        d.paused.store(true, Ordering::Relaxed);

        d.suspend_active(true);

        assert!(
            suspended(&d, "forced"),
            "a Force job kept transferring through Offline"
        );
        assert!(
            d.pause_exempt().is_empty(),
            "offline stops Force, so nothing is exempt and the header must not \
             say forced downloads keep running: {:?}",
            d.pause_exempt()
        );
        settle(&d);
    }

    /// The same Force job, the same call, offline OFF: the exemption a
    /// pause has always had is untouched, and it is what tells the two
    /// cases apart.
    #[test]
    fn a_force_job_is_exempt_from_a_pause_and_not_from_offline() {
        let dir = tmp("offcontrast");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("forced", "Downloading", 2, false));
        d.paused.store(true, Ordering::Relaxed);
        d.suspend_active(true);
        assert!(!suspended(&d, "forced"));
        assert_eq!(d.pause_exempt(), vec!["forced".to_string()]);

        d.offline.store(true, Ordering::SeqCst);
        assert!(d.pause_exempt().is_empty());
        d.suspend_active(true);
        assert!(suspended(&d, "forced"));
        settle(&d);
    }

    /// The prefetch of a Force job is exempt from a pause and not from
    /// offline - `set_offline` pokes the sidecar itself, and this pins the
    /// same answer for every other caller of the wind-down while the flag
    /// stands.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offline_stops_the_prefetch_of_a_force_job_too() {
        let dir = tmp("offsidecar");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("early-force", "Queued", 2, false));
        d.offline.store(true, Ordering::SeqCst);
        d.paused.store(true, Ordering::Relaxed);
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.sidecar.lock_ok() = Some(crate::sidecar::Sidecar {
            nzo_id: "early-force".into(),
            hub: Arc::new(crate::StreamHub::default()),
            progress: Arc::new(AtomicU64::new(0)),
            rate_win: Mutex::new(VecDeque::new()),
            cancelled: cancelled.clone(),
            task: tokio::spawn(async {}),
            borrowed: false,
        });

        d.suspend_active(true);

        assert!(
            cancelled.load(Ordering::Relaxed),
            "offline left a Force job's early start on the wire"
        );
        assert!(d.pause_exempt().is_empty());
        *d.sidecar.lock_ok() = None;
    }

    /// The prefetch sidecar is a transfer on a hub of its own: neither
    /// the state test nor `fire_pause` reaches it, so a pause left an
    /// early start pulling the NEXT job's articles for as long as its
    /// primary ran. A Force primary makes that "for ever".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_queue_pause_stops_the_prefetch_of_a_non_force_job_only() {
        let dir = tmp("sidecar");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("early", "Queued", 0, false));
        d.queue
            .lock_ok()
            .push_back(row("early-force", "Queued", 2, false));
        d.paused.store(true, Ordering::Relaxed);
        let put = |id: &str| {
            let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
            *d.sidecar.lock_ok() = Some(crate::sidecar::Sidecar {
                nzo_id: id.into(),
                hub: Arc::new(crate::StreamHub::default()),
                progress: Arc::new(AtomicU64::new(0)),
                rate_win: Mutex::new(VecDeque::new()),
                cancelled: cancelled.clone(),
                task: tokio::spawn(async {}),
                borrowed: false,
            });
            cancelled
        };

        let c = put("early");
        d.suspend_active(true);
        assert!(
            c.load(Ordering::Relaxed),
            "a queue pause left the early start on the wire"
        );
        assert!(d.pause_exempt().is_empty());

        // A Force job's early start is exempt like the job itself, and is
        // named as running.
        let c = put("early-force");
        d.suspend_active(true);
        assert!(!c.load(Ordering::Relaxed));
        assert_eq!(d.pause_exempt(), vec!["early-force".to_string()]);

        // Slot cleared, so the 60 s re-fire threads retire.
        *d.sidecar.lock_ok() = None;
    }

    /// The withdrawn exemption, at the wind-down itself. A Force job on
    /// the wire under a queue pause, its priority then lowered by hand
    /// (the priority arms write the record and call this after): the
    /// pause has to bite now. The API-level twins of these are in
    /// `nzbfast-api`'s `unforce_tests`; these hold the rule where it lives.
    #[test]
    fn a_job_that_stops_being_force_under_a_pause_is_wound_down() {
        let dir = tmp("unforce");
        let d = test_daemon(&dir);
        let r = row("forced", "Downloading", 2, false);
        d.queue.lock_ok().push_back(r.clone());
        d.paused.store(true, Ordering::Relaxed);
        d.wind_down_unforced(&["forced".to_string()]);
        assert!(
            !suspended(&d, "forced"),
            "still Force: the exemption stands"
        );

        r.lock_ok().priority = 0;
        d.wind_down_unforced(&["forced".to_string()]);
        assert!(suspended(&d, "forced"));
        settle(&d);
    }

    /// No pause in force, nothing to wind down - and a row nobody named
    /// is never touched, whatever else is going on.
    #[test]
    fn unforcing_without_a_pause_and_unnamed_rows_are_left_alone() {
        let dir = tmp("unforce-none");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("forced", "Downloading", 0, false));
        d.queue
            .lock_ok()
            .push_back(row("bystander", "Downloading", 0, false));
        d.wind_down_unforced(&["forced".to_string()]);
        assert!(!suspended(&d, "forced"), "no pause, no wind-down");

        d.paused.store(true, Ordering::Relaxed);
        d.wind_down_unforced(&["forced".to_string()]);
        assert!(suspended(&d, "forced"));
        assert!(
            !suspended(&d, "bystander"),
            "the wind-down is aimed by id, not at whoever is downloading"
        );
        settle(&d);
    }

    /// The job's own pause counts as a pause in force on an unpaused
    /// queue - the re-hold of a released duplicate takes this path - and a
    /// second call over an already-winding-down row starts nothing new.
    #[test]
    fn a_job_carrying_its_own_pause_is_wound_down_once() {
        let dir = tmp("unforce-own");
        let d = test_daemon(&dir);
        d.queue
            .lock_ok()
            .push_back(row("held", "Downloading", -3, true));
        d.wind_down_unforced(&["held".to_string()]);
        assert!(suspended(&d, "held"));
        // Already suspended: the guard skips it (no second re-fire loop).
        let before = Arc::strong_count(&d);
        d.wind_down_unforced(&["held".to_string()]);
        assert_eq!(Arc::strong_count(&d), before, "a second wind-down spawned");
        settle(&d);
    }

    /// Unforcing the job a PREFETCH is serving stops the prefetch with
    /// it: a queue pause stops an early start of a non-Force job, so a job
    /// that has just become one has to lose its early start as well (the
    /// sidecar is on a hub of its own that the wind-down's state test
    /// never sees).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unforcing_a_job_stops_the_prefetch_serving_it() {
        let dir = tmp("unforce-sidecar");
        let d = test_daemon(&dir);
        let r = row("early-force", "Queued", 2, false);
        d.queue.lock_ok().push_back(r.clone());
        d.paused.store(true, Ordering::Relaxed);
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.sidecar.lock_ok() = Some(crate::sidecar::Sidecar {
            nzo_id: "early-force".into(),
            hub: Arc::new(crate::StreamHub::default()),
            progress: Arc::new(AtomicU64::new(0)),
            rate_win: Mutex::new(VecDeque::new()),
            cancelled: cancelled.clone(),
            task: tokio::spawn(async {}),
            borrowed: false,
        });

        d.wind_down_unforced(&["early-force".to_string()]);
        assert!(
            !cancelled.load(Ordering::Relaxed),
            "still Force: its early start is exempt"
        );

        r.lock_ok().priority = 0;
        d.wind_down_unforced(&["early-force".to_string()]);
        assert!(
            cancelled.load(Ordering::Relaxed),
            "the early start kept pulling after the Force was withdrawn"
        );
        *d.sidecar.lock_ok() = None;
    }
}
