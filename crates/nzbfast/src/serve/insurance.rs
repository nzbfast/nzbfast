//! Retention insurance: fetch a DEFERRED row's payload now, while its
//! articles are still alive, and extract only when the user promotes it.
//!
//! Articles get taken down; a post grabbed next week completes worse
//! than the same post grabbed today. For rows the user has deferred -
//! added paused, or a `watchlist_deferred` grab - the daemon banks the
//! payload early under the `insurance_cap_gb` disk budget, into the
//! NORMAL resumable on-disk state (out_dir + `.nzbfast.journal`, volumes
//! materialized by `no_extract`), so promotion is just an unpause: the
//! ordinary run resumes from the journal, fetches whatever is somehow
//! still missing, and extracts from what is on disk. No spool format was
//! invented and none must be - the journal IS the durable partial form,
//! and every sweep already treats a queue row's directory as live.
//!
//! What this module owns is the two QUEUE-side decisions:
//!
//! * [`Daemon::pick_insurance_job`] - which deferred row may fetch,
//!   asked by the runner only when [`Daemon::pick_job`] found nothing
//!   runnable, so insurance is the lowest priority there is. The cap is
//!   enforced here, by REFUSING new fetches - never by evicting a
//!   banked row's bytes, which would be the daemon deciding which post
//!   the user loses.
//! * [`insurance_yields_to_arrivals`] - wind an insurance fetch down
//!   (gracefully, journal intact) the moment a real job becomes
//!   runnable, so banking a deferred row never holds up a download the
//!   user actually asked for. Rides the slow-job watchdog's tick.
//!
//! The fetch itself is the ordinary pipeline: the runner threads
//! `insurance` through to `get_with_progress` as `no_extract`, and the
//! post-processing tail re-queues the row paused with `fetched` set
//! (see the insurance arm in `postproc::run_tail`) instead of filing it
//! in history.
//!
//! **Held spares are out of bounds, twice over.** A spare that downloads
//! payload is the one outcome §282 forbids outright, so the add-time
//! stamp in `daemon_enqueue` never marks a held row and the picker below
//! refuses `held_for` and `DUPE_PRIORITY` rows again as a belt.

use super::*;

/// Failed fetch attempts after which the picker leaves a row alone for
/// the rest of this process. Deliberately process-local (see
/// [`Job::insurance_attempts`]).
const INSURANCE_MAX_ATTEMPTS: u32 = 3;

impl Daemon {
    /// The add-time stamp (see [`Job::insurance`]): an add-paused row
    /// is a deferred download, and with the feature on its payload is
    /// banked in the background while the articles are still alive.
    /// Only at add time - a later pause means "stop", not "fetch
    /// anyway". `held` covers both the duplicate hold and an explicit
    /// spare (`hold_for`): a spare that downloads payload is the one
    /// outcome §282 forbids outright. And never a library row, whose
    /// whole mode is not-downloading.
    pub(super) fn insurance_at_add(&self, priority: i32, held: bool, library: bool) -> bool {
        priority == -2 && !held && !library && self.insurance_cap_gb.load(Ordering::Relaxed) > 0
    }

    /// The deferred row whose payload should be banked next, or None.
    ///
    /// Only called when nothing else is runnable, which is what makes
    /// insurance the lowest priority in the queue without touching
    /// `pick_job`'s ordering key. Oldest first (queue order): the oldest
    /// deferred post is the one whose articles have been exposed to
    /// takedown longest.
    ///
    /// The cap counts every insurance row that already holds bytes -
    /// fetched, mid-fetch, or a partial from an earlier wind-down - at
    /// the larger of its declared size and what is on disk, and admits a
    /// candidate only if its own declared size still fits. Conservative
    /// by design: refusing a fetch costs latency the user opted into,
    /// while overshooting the budget eats disk they fenced off.
    pub(super) fn pick_insurance_job(&self) -> Option<Arc<Mutex<Job>>> {
        let cap_gb = self.insurance_cap_gb.load(Ordering::Relaxed);
        if cap_gb == 0 {
            return None;
        }
        let cap = cap_gb.saturating_mul(1_000_000_000);
        let q = self.queue.lock_ok();
        let mut spent: u64 = 0;
        // (row, its own bytes already counted into `spent`) in queue
        // order, so admitting a partial does not double-count it.
        let mut candidates: Vec<(Arc<Mutex<Job>>, u64)> = Vec::new();
        for j in q.iter() {
            let g = j.lock_ok();
            if !g.insurance {
                continue;
            }
            let holds_bytes =
                g.fetched || g.state == JobState::Downloading || g.downloaded_bytes > 0;
            if holds_bytes {
                spent = spent.saturating_add(g.total_bytes.max(g.downloaded_bytes));
            }
            if g.fetched || g.state != JobState::Queued {
                continue;
            }
            // The belt behind the add-time stamp: nothing here may ever
            // start payload on a held spare, a library row, a row being
            // relocated, or one the user has since promoted (an unpaused
            // row is `pick_job`'s business, at its real priority).
            if !g.paused
                || g.tombstone
                || !g.held_for.is_empty()
                || g.priority == DUPE_PRIORITY
                || g.library
                || g.relocating > 0
                || g.insurance_attempts >= INSURANCE_MAX_ATTEMPTS
            {
                continue;
            }
            let own = if holds_bytes {
                g.total_bytes.max(g.downloaded_bytes)
            } else {
                0
            };
            candidates.push((j.clone(), own));
        }
        drop(q);
        // First FIT, not first in line: a row bigger than the remaining
        // budget must not starve the smaller ones behind it - refusing
        // it banks nothing, and banking something is the feature.
        candidates.into_iter().find_map(|(job, own)| {
            let declared = job.lock_ok().total_bytes;
            (spent.saturating_sub(own).saturating_add(declared) <= cap).then_some(job)
        })
    }
}

/// Wind an active insurance fetch down when a real job is waiting.
///
/// The runner picks an insurance row only when nothing else is runnable,
/// but a real add (or a resume, a retry, an auto-promotion) can land
/// mid-fetch and would otherwise wait behind a background errand for the
/// rest of its network phase. This asks `suspend_matching` for the
/// GRACEFUL wind-down - in-flight articles land and journal, so nothing
/// fetched is lost - and the suspended arm in `postproc::run_tail` puts
/// the row back in the queue exactly as a user pause would. The next
/// idle stretch resumes the bank from the journal.
///
/// Rides the slow-job watchdog's 1-5 s tick, so a wanted job waits
/// seconds, not the fetch's remainder. One atomic load when the feature
/// is off; an insurance run in flight is identified from the record
/// alone (Downloading + paused + insurance + not already suspended - no
/// ordinary run is ever paused while Downloading), so nothing threads
/// runner state here.
pub(in crate::serve) fn insurance_yields_to_arrivals(d: &Arc<Daemon>) {
    if d.insurance_cap_gb.load(Ordering::Relaxed) == 0 {
        return;
    }
    let target: Option<String> = {
        let q = d.queue.lock_ok();
        let active = q.iter().find_map(|j| {
            let g = j.lock_ok();
            (g.insurance && g.paused && !g.suspended && g.state == JobState::Downloading)
                .then(|| g.nzo_id.clone())
        });
        active.filter(|_| {
            q.iter().any(|j| {
                let g = j.lock_ok();
                g.state == JobState::Queued && !g.paused && !g.tombstone && g.relocating == 0
            })
        })
    };
    if let Some(id) = target {
        info!(
            target: "insurance",
            "{id}: a runnable job arrived - winding the background fetch down \
             (progress kept in the journal)"
        );
        d.suspend_matching(true, |g| g.nzo_id == id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-insurance-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A queued row shaped like the enqueue stamp would leave it.
    fn row(id: &str, insurance: bool, total: u64) -> Arc<Mutex<Job>> {
        let j = crate::serve::job_from_json(&serde_json::json!({
            "nzo_id": id,
            "name": id,
            "out_dir": "/tmp/o",
            "nzb_path": "/tmp/n.nzb",
            "state": "Queued",
            "paused": true,
            "insurance": insurance,
            "total_bytes": total,
        }))
        .unwrap();
        Arc::new(Mutex::new(j))
    }

    /// Off (cap 0) picks nothing whatever the queue holds - the
    /// not-hinder contract's queue-side half.
    #[test]
    fn cap_zero_never_picks() {
        let dir = tmp("off");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row("a", true, 1_000));
        assert!(d.pick_insurance_job().is_none());
    }

    /// On, the oldest eligible insurance row is picked; plain paused
    /// rows, held spares and fetched rows are not.
    #[test]
    fn picks_oldest_eligible_insurance_row_only() {
        let dir = tmp("pick");
        let d = test_daemon(&dir);
        d.insurance_cap_gb.store(10, Ordering::Relaxed);
        {
            let mut q = d.queue.lock_ok();
            q.push_back(row("plain-paused", false, 1_000));
            let spare = row("spare", true, 1_000);
            {
                let mut g = spare.lock_ok();
                g.held_for = "owner".into();
                g.priority = DUPE_PRIORITY;
            }
            q.push_back(spare);
            let banked = row("banked", true, 1_000);
            banked.lock_ok().fetched = true;
            q.push_back(banked);
            q.push_back(row("first", true, 1_000));
            q.push_back(row("second", true, 1_000));
        }
        let picked = d.pick_insurance_job().expect("one eligible row");
        assert_eq!(picked.lock_ok().nzo_id, "first");
    }

    /// The cap refuses a candidate that does not fit beside what is
    /// already banked - and never evicts to make room.
    #[test]
    fn cap_refuses_instead_of_evicting() {
        let dir = tmp("cap");
        let d = test_daemon(&dir);
        d.insurance_cap_gb.store(1, Ordering::Relaxed); // 1 GB
        {
            let mut q = d.queue.lock_ok();
            let banked = row("banked", true, 800_000_000);
            banked.lock_ok().fetched = true;
            q.push_back(banked);
            q.push_back(row("big", true, 300_000_000));
        }
        assert!(
            d.pick_insurance_job().is_none(),
            "800 MB banked + 300 MB candidate must not fit a 1 GB cap"
        );
        // A smaller candidate still fits: the refusal is per-fetch, not
        // a latch.
        d.queue.lock_ok().push_back(row("small", true, 100_000_000));
        let picked = d.pick_insurance_job().expect("the small row fits");
        assert_eq!(picked.lock_ok().nzo_id, "small");
    }

    /// A partial row (earlier wind-down) is both counted and resumable:
    /// its own bytes must not be double-counted against its size.
    #[test]
    fn a_partial_row_resumes_without_double_counting() {
        let dir = tmp("partial");
        let d = test_daemon(&dir);
        d.insurance_cap_gb.store(1, Ordering::Relaxed);
        {
            let mut q = d.queue.lock_ok();
            let partial = row("partial", true, 900_000_000);
            partial.lock_ok().downloaded_bytes = 400_000_000;
            q.push_back(partial);
        }
        // Counted once (900 MB declared), it fits the 1 GB cap; counted
        // as banked AND candidate (900 + 900) it would not.
        let picked = d.pick_insurance_job().expect("the partial resumes");
        assert_eq!(picked.lock_ok().nzo_id, "partial");
    }

    /// The attempt ladder retires a row the fetch keeps failing on.
    #[test]
    fn attempts_exhaust_the_ladder() {
        let dir = tmp("attempts");
        let d = test_daemon(&dir);
        d.insurance_cap_gb.store(10, Ordering::Relaxed);
        let j = row("dead", true, 1_000);
        j.lock_ok().insurance_attempts = INSURANCE_MAX_ATTEMPTS;
        d.queue.lock_ok().push_back(j);
        assert!(d.pick_insurance_job().is_none());
    }
}
