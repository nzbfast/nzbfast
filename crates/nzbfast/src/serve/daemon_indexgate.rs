//! May a background index pass run right now, and how does it say why
//! not (TODO 106 code motion out of daemon.rs).
//!
//! The READ side is `indexing_pause_reason` and `spot_pause_reason` -
//! one per source, asked at every 100 ms stand-down poll - plus
//! `pause_phrase`, which turns the reason word into the sentence the
//! log prints, and `queue_has_runnable`, the deliberately cheap "is a
//! download imminent" the two of them share. `index_db_wanted` is the
//! same switches asked one level down: does anything want the database
//! OPEN at all.
//!
//! The WRITE side is `begin_index_job`, and it is here rather than
//! beside the runner because it is the other end of one rendezvous: it
//! raises the very counter `index_jobs_active` that both pause reasons
//! read, and it emits the "indexing set aside while downloads run"
//! marker on the 0 -> 1 edge. Reading the two sides in different files
//! is what makes an ordering question look like an unrelated one.
//!
//! TWO MEASUREMENTS ARE RECORDED IN THE COMMENTS BELOW and both are
//! about this file being read as a whole. `index_jobs_active` only
//! rises AFTER the runner picks a job, so on 2026-08-05 four adds sat
//! 38 s while the scanners ran on, blind to work the runner had not
//! reached - which is why `queue_has_runnable` is consulted beside the
//! counter and not instead of it, in BOTH reasons. And on 11 Aug 2026 a
//! scan loop stood down for fourteen hours printing "paused for
//! foreground job" while the daemon was OFFLINE and the queue empty:
//! a stand-down that names the wrong cause is worse than one that names
//! none, which is the whole of why `pause_phrase` exists. Neither is
//! visible from one function.
//!
//! The two reasons are deliberately NOT one function with a parameter.
//! Everything after the master switch is shared - a paused index means
//! stop scanning, and a download outranks every background pass
//! whichever source it feeds - but the switches are independent, so
//! "off" has to be asked separately, and the precedence order IS the
//! product decision: offline outranks off, off outranks paused, because
//! "paused" invites a Resume button in the UI and "off" hides the
//! feature.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`offline`, `index_enabled`, `spot_enabled`,
//! `index_paused`, `index_pause_on_download`, `index_jobs_active`,
//! `exiting`, `queue`) stay in scope exactly as they were inline.
//! `pub(super)` becomes `pub(in crate::serve)` here, because `super` is
//! `daemon` from inside a child. The module itself carries NO cfg:
//! `begin_index_job` is on the download path and is needed in the slim
//! build, so the `indexer` gates stay per-item exactly as they were.

use super::*;

impl Daemon {
    /// Why indexing is standing down, or None if it should run. A reason
    /// rather than a bool so the UI can say WHICH it is - an index that
    /// has quietly stopped growing is otherwise a mystery, and the two
    /// causes need opposite actions from the user.
    ///
    /// The download half counts jobs in flight, NOT `started_at`: job
    /// N's tail overlaps job N+1's network phase, so `started_at` goes
    /// None between queued jobs while the pipeline is still busy.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn indexing_pause_reason(&self) -> Option<&'static str> {
        // Offline outranks everything: it is a promise that this machine
        // is touching no provider, and a scan is provider traffic. The
        // tip watcher already drops and QUITs its held sessions on any
        // reason here, which is most of what going offline has to do.
        if self.offline.load(Ordering::Relaxed) {
            return Some("offline");
        }
        // The master switch outranks pause, and reads differently in the
        // UI: "paused" invites a Resume button, "off" does not - the
        // whole feature is hidden while this one holds.
        if !self.index_enabled.load(Ordering::Relaxed) {
            return Some("off");
        }
        if self.index_paused.load(Ordering::Relaxed) {
            return Some("paused");
        }
        if self.index_pause_on_download.load(Ordering::Relaxed)
            && self.index_jobs_active.load(Ordering::Acquire) > 0
        {
            return Some("downloading");
        }
        // A QUEUED job outranks background scans exactly as a running
        // one does. Measured 2026-08-05: four adds sat 38 s before the
        // runner could pick the first - `index_jobs_active` only rises
        // AFTER pick, so the scanners' whole 100 ms stand-down
        // machinery was blind to work the runner had not reached yet.
        if self.index_pause_on_download.load(Ordering::Relaxed) && self.queue_has_runnable() {
            return Some("downloading");
        }
        None
    }

    /// The same question for the spot leg. Everything after the master
    /// switch is shared with indexing - a paused index means "stop
    /// scanning", and a download outranks every background scan
    /// regardless of which source it feeds - but the switches are
    /// independent, so "off" is asked separately.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn spot_pause_reason(&self) -> Option<&'static str> {
        if self.offline.load(Ordering::Relaxed) {
            return Some("offline");
        }
        if !self.spot_enabled.load(Ordering::Relaxed) {
            return Some("off");
        }
        if self.index_paused.load(Ordering::Relaxed) {
            return Some("paused");
        }
        if self.index_pause_on_download.load(Ordering::Relaxed)
            && self.index_jobs_active.load(Ordering::Acquire) > 0
        {
            return Some("downloading");
        }
        // A QUEUED job outranks background scans exactly as a running
        // one does. Measured 2026-08-05: four adds sat 38 s before the
        // runner could pick the first - `index_jobs_active` only rises
        // AFTER pick, so the scanners' whole 100 ms stand-down
        // machinery was blind to work the runner had not reached yet.
        if self.index_pause_on_download.load(Ordering::Relaxed) && self.queue_has_runnable() {
            return Some("downloading");
        }
        None
    }

    /// The reason words above, in the words a log reader needs.
    ///
    /// The background legs used to print one fixed sentence, "paused for
    /// foreground job", whichever reason had actually fired. On 11 Aug
    /// 2026 that sentence was the entire record of a scan loop that had
    /// been standing down for fourteen hours because the daemon was
    /// OFFLINE: the log said a download had the line, the queue was
    /// empty, and the two could not be reconciled without reading the
    /// source. A stand-down that names the wrong cause is worse than one
    /// that names none.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn pause_phrase(reason: &str) -> &'static str {
        match reason {
            "offline" => "the daemon is offline",
            "off" => "the switch is off",
            "paused" => "indexing is paused",
            "downloading" => "a download is running",
            _ => "standing down",
        }
    }

    /// True when some queue entry is ready for the runner (Queued and
    /// not paused; deferred counts - the runner picks deferred work
    /// when nothing else is runnable, so it still wants the threads).
    /// Deliberately cheap and approximate: this feeds the scanners'
    /// 100 ms stand-down polls, which need "is a download imminent",
    /// not the runner's full pick logic.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn queue_has_runnable(&self) -> bool {
        self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.state == JobState::Queued && !g.paused
        })
    }

    /// Does anything want the index database open? The file backs both
    /// sources, so it is created and held for as long as EITHER switch
    /// is on - and with both off it is never opened, never created on a
    /// fresh install, exactly as when indexing was the only source.
    ///
    /// Answers no once the daemon is [`exiting`](Self::exiting),
    /// whatever the switches say: the wind-down closes the database, and
    /// a lazy reopen behind it would undo that.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn index_db_wanted(&self) -> bool {
        if self.exiting.load(Ordering::Relaxed) {
            return false;
        }
        self.index_enabled.load(Ordering::Relaxed) || self.spot_enabled.load(Ordering::Relaxed)
    }

    pub(in crate::serve) fn begin_index_job(self: &Arc<Self>) -> IndexJobGuard {
        let prev = self.index_jobs_active.fetch_add(1, Ordering::AcqRel);
        // Phase marker on the 0 -> 1 edge only (tails overlap the next
        // job, so the counter can sit above 1 for a while), and only
        // when the yield-to-downloads setting actually pauses anything.
        if prev == 0
            && self.index_pause_on_download.load(Ordering::Relaxed)
            && self.index_enabled.load(Ordering::Relaxed)
        {
            self.note_event("indexer", "indexing set aside while downloads run");
        }
        IndexJobGuard(self.index_jobs_active.clone(), Arc::downgrade(self))
    }
}
