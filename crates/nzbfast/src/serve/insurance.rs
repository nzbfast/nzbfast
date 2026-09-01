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
//! What this module owns is the QUEUE-side decisions, and what a client
//! is told about them:
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
//! * [`slot_payload`] / [`insure_arm`] - the surface (TODO 304 stage 2).
//!   A banked row was indistinguishable from a merely paused one, and a
//!   post the fetch had given up on said nothing at all, which is the
//!   news this whole feature exists to deliver early. The refusals both
//!   halves ask are one list, [`insure_refusal`].
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
///
/// Read by the queue payload too ([`slot_payload`]), so the row can say
/// it has been retired rather than sitting there looking merely paused -
/// a post the background fetch has given up on three times is the one
/// the user most needs to hear about while the articles are still
/// half-there.
pub(in crate::serve) const INSURANCE_MAX_ATTEMPTS: u32 = 3;

/// Why this row may never be insured, in the daemon's own words, or None
/// when it may.
///
/// ONE list, asked by the picker's belt below AND by the per-row control
/// ([`insure_arm`]), so "the daemon will not bank this" and "the button
/// offers to bank this" cannot drift apart. The strings are English on
/// the wire like every other API refusal (the SAB-compat contract); the
/// dashboard translates at the display edge.
pub(in crate::serve) fn insure_refusal(j: &Job) -> Option<&'static str> {
    if !j.paused {
        // Insurance is for a download the user DEFERRED. An unpaused row
        // is already `pick_job`'s business at its real priority.
        Some("this download is not paused")
    } else if j.tombstone {
        Some("this job is being removed")
    } else if !j.held_for.is_empty() || j.priority == DUPE_PRIORITY {
        // A spare that downloads payload is the one outcome §282 forbids
        // outright, and the button is not an exception to it.
        Some("a held copy must not download payload")
    } else if j.library {
        Some("a library item never downloads payload")
    } else if j.relocating > 0 {
        Some("this job is being moved")
    } else {
        None
    }
}

/// The row's insurance state for the queue payload, or Null on every
/// ordinary row - which is every row on a queue with the feature off.
///
/// Stage 1 left a banked row indistinguishable from a merely paused one:
/// same "Paused", same 100%, and a fetch running in the background under
/// a status word that said "Downloading". These five facts are what a
/// client needs to tell those four states apart, and they are additive
/// keys the *arrs ignore, like `deferred` and `alt_offer` beside them.
pub(in crate::serve) fn slot_payload(j: &Job) -> Value {
    if !j.insurance {
        return Value::Null;
    }
    json!({
        // The payload is on disk and journalled: promotion is an unpause
        // that extracts from what is here, not a second download.
        "banked": j.fetched,
        // This row's background fetch is on the wire NOW. Downloading +
        // paused + not suspended is the identity
        // `insurance_yields_to_arrivals` uses, and it is exact: no
        // ordinary run is ever paused while Downloading.
        "fetching": j.paused && !j.suspended && j.state == JobState::Downloading,
        "attempts": j.insurance_attempts,
        "retired": j.insurance_attempts >= INSURANCE_MAX_ATTEMPTS,
        // The daemon's own sentence for the last failure (see
        // `Job::insurance_note`), empty when there has not been one.
        "note": j.insurance_note,
    })
}

/// The per-row control: insure this row, or stop insuring it.
///
/// The add-time stamp is deliberately narrow - a row the user pauses
/// mid-queue said "stop", not "fetch anyway" - and this is the explicit
/// statement that narrowness leaves no room for. It overrides the
/// INFERENCE, never the doctrine: [`insure_refusal`] still refuses a
/// held spare and a library row, and the cap still has to be on, because
/// a button that switches a feature on for one row while the budget it
/// spends is zero would do nothing and say it had.
///
/// Turning it OFF winds a fetch that is already running down gracefully
/// - the same `suspend_matching` call the arrivals yield makes, so the
/// journal is intact and the bytes already on disk stay - rather than
/// leaving the errand the user just cancelled running to completion.
pub(in crate::serve) fn insure_arm(
    d: &Arc<Daemon>,
    params: &std::collections::HashMap<String, String>,
) -> Value {
    let id = params.get("value").cloned().unwrap_or_default();
    let on = params.get("value2").map(String::as_str) != Some("0");
    if on && d.insurance_cap_gb.load(Ordering::Relaxed) == 0 {
        return json!({"status": false, "error": "no disk budget is set for saving downloads early"});
    }
    let job = {
        let q = d.queue.lock_ok();
        q.iter().find(|j| j.lock_ok().nzo_id == id).cloned()
    };
    let Some(job) = job else {
        return json!({"status": false, "error": "unknown nzo_id"});
    };
    let mut winding_down = false;
    {
        let mut g = job.lock_ok();
        if on {
            if let Some(why) = insure_refusal(&g) {
                return json!({"status": false, "error": why});
            }
            g.insurance = true;
            // A fresh ladder: the user asking for this row by name is a
            // new answer to the question three failed attempts retired.
            g.insurance_attempts = 0;
            g.insurance_note.clear();
        } else {
            g.insurance = false;
            winding_down = g.paused && !g.suspended && g.state == JobState::Downloading;
        }
    }
    d.save_queue();
    if winding_down {
        info!(
            target: "insurance",
            "{id}: no longer insured - winding the background fetch down              (progress kept in the journal)"
        );
        d.suspend_matching(true, |g| g.nzo_id == id);
    }
    json!({"status": true})
}

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
            // relocated, or one the user has since promoted. One list,
            // shared with the per-row control - see `insure_refusal`.
            if insure_refusal(&g).is_some() || g.insurance_attempts >= INSURANCE_MAX_ATTEMPTS {
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

    fn tmp(tag: &str) -> crate::testscratch::ScratchDir {
        let d =
            std::env::temp_dir().join(format!("nzbfast-insurance-{tag}-{}", std::process::id()));
        crate::testscratch::ScratchDir::attach(&d)
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

    /// Every row an ordinary queue holds reports NOTHING: the surface is
    /// silent unless the feature is on and this row is in it.
    #[test]
    fn an_ordinary_row_carries_no_insurance_block() {
        assert_eq!(
            slot_payload(&row("plain", false, 1_000).lock_ok()),
            Value::Null
        );
    }

    /// The four states stage 1 left indistinguishable, told apart.
    #[test]
    fn the_payload_tells_the_four_states_apart() {
        let waiting = row("waiting", true, 1_000);
        let v = slot_payload(&waiting.lock_ok());
        assert_eq!(v["banked"], false);
        assert_eq!(v["fetching"], false);
        assert_eq!(v["retired"], false);

        // On the wire NOW: paused + Downloading + not suspended, which
        // is the identity `insurance_yields_to_arrivals` uses.
        let fetching = row("fetching", true, 1_000);
        fetching.lock_ok().state = JobState::Downloading;
        assert_eq!(slot_payload(&fetching.lock_ok())["fetching"], true);
        // ...and a WIND-DOWN in flight is not: the row is on its way
        // back to the queue, and saying "saving this now" through it
        // would be the one moment the claim is false.
        fetching.lock_ok().suspended = true;
        assert_eq!(slot_payload(&fetching.lock_ok())["fetching"], false);

        let banked = row("banked", true, 1_000);
        banked.lock_ok().fetched = true;
        assert_eq!(slot_payload(&banked.lock_ok())["banked"], true);

        // Retired, with the daemon's own sentence for why - the count
        // alone cannot say whether the post is going or a provider was
        // simply down, which is the whole news this feature carries.
        let dead = row("dead", true, 1_000);
        {
            let mut g = dead.lock_ok();
            g.insurance_attempts = INSURANCE_MAX_ATTEMPTS;
            g.insurance_note = "7 missing of 7 segments".into();
        }
        let v = slot_payload(&dead.lock_ok());
        assert_eq!(v["retired"], true);
        assert_eq!(v["attempts"], INSURANCE_MAX_ATTEMPTS);
        assert_eq!(v["note"], "7 missing of 7 segments");
    }

    /// The per-row control is an override of the add-time INFERENCE, not
    /// of the doctrine: the cap still has to be on, and a held spare is
    /// still refused - by the same list the picker's belt asks.
    #[test]
    fn the_control_overrides_the_stamp_but_not_the_doctrine() {
        let dir = tmp("arm");
        let d = test_daemon(&dir);
        let plain = row("plain", false, 1_000);
        d.queue.lock_ok().push_back(plain.clone());
        let ask = |id: &str, on: &str| {
            let mut p = std::collections::HashMap::new();
            p.insert("value".to_string(), id.to_string());
            p.insert("value2".to_string(), on.to_string());
            insure_arm(&d, &p)
        };

        // Off: a switch that spends a budget of nothing must not report
        // success over a fetch that will never happen.
        assert_eq!(ask("plain", "1")["status"], false);
        assert!(!plain.lock_ok().insurance);

        d.insurance_cap_gb.store(10, Ordering::Relaxed);
        assert_eq!(ask("plain", "1")["status"], true);
        assert!(plain.lock_ok().insurance);
        assert_eq!(
            d.pick_insurance_job()
                .map(|j| j.lock_ok().nzo_id.clone())
                .as_deref(),
            Some("plain")
        );

        // ...and off again, which the picker must honour at once.
        assert_eq!(ask("plain", "0")["status"], true);
        assert!(d.pick_insurance_job().is_none());

        // A held spare is refused however it is asked for: §282's one
        // forbidden outcome is not a default the button may override.
        let spare = row("spare", false, 1_000);
        {
            let mut g = spare.lock_ok();
            g.held_for = "owner".into();
            g.priority = DUPE_PRIORITY;
        }
        d.queue.lock_ok().push_back(spare.clone());
        assert_eq!(ask("spare", "1")["status"], false);
        assert!(!spare.lock_ok().insurance);

        assert_eq!(ask("nobody", "1")["status"], false);
    }

    /// Asking for a retired row by name is a new answer to the question
    /// three failed attempts closed: the ladder starts over, and the
    /// stale reason goes with it.
    #[test]
    fn re_insuring_resets_the_retired_ladder() {
        let dir = tmp("reset");
        let d = test_daemon(&dir);
        d.insurance_cap_gb.store(10, Ordering::Relaxed);
        let dead = row("dead", true, 1_000);
        {
            let mut g = dead.lock_ok();
            g.insurance_attempts = INSURANCE_MAX_ATTEMPTS;
            g.insurance_note = "7 missing of 7 segments".into();
        }
        d.queue.lock_ok().push_back(dead.clone());
        assert!(d.pick_insurance_job().is_none(), "retired");
        let mut p = std::collections::HashMap::new();
        p.insert("value".to_string(), "dead".to_string());
        p.insert("value2".to_string(), "1".to_string());
        assert_eq!(insure_arm(&d, &p)["status"], true);
        assert_eq!(dead.lock_ok().insurance_attempts, 0);
        assert!(dead.lock_ok().insurance_note.is_empty());
        assert!(d.pick_insurance_job().is_some());
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
