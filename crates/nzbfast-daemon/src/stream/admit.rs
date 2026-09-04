//! TODO 16m: is the answer to a `/stream/<id>` knowable NOW?
//!
//! The M14i admit wait exists because a play can legitimately arrive
//! before its writers do - a parked library entry this request has just
//! force-enqueued has none for a second or two, and refusing it would
//! break the one feature the wait was built for. What it must not do is
//! wait for writers that are never coming: a player (and the
//! dashboard's play button) then spends half a minute looking hung on
//! an answer the daemon already has.
//!
//! So this module is one question and the reading that supports it -
//! [`no_writers_and_no_prospect`], and [`custody`], which is the half
//! that can tell a job the user just deleted from an ordinary queued
//! one. The wait loop in the parent asks it twice: once on the way in,
//! and once a second on the way round.
//!
//! A child module of `stream.rs` - it sat inline there until that file
//! reached the size gate's ceiling - glob-imported back through
//! `use super::*`, so `Daemon`, `Job` and `pick_media` are the parent's
//! own and not a second opinion.

use super::*;

/// How long `/stream/<id>` waits for a job's writers to appear before
/// giving up (M14i). Named because the §16m predicate below has to judge
/// an armed auto-retry against it: a retry that fires after this request
/// is already answered is no prospect for THIS request.
pub(super) const ADMIT_WAIT_SECS: u64 = 30;

/// Which store owns the record a `/stream` request is waiting on, at
/// the instant it is read.
///
/// Three answers and not two. "Parked" and "gone" look identical to a
/// caller holding an `Arc`, because the handle stays valid and its
/// fields keep reading exactly what they read before - which is how a
/// deleted job went on looking like an ordinary queued one for the rest
/// of the admit wait (TODO 16m's third shape).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Custody {
    /// In `d.queue`: being picked, downloading, or running its tail.
    Queued,
    /// In `d.history`, whatever its row says.
    Parked,
    /// In NEITHER store, read under the publish lock so that the
    /// absence is an answer rather than a torn move - see [`custody`].
    Gone,
}

/// Where is this request's record right now?
///
/// Membership is `Arc::ptr_eq` and not the nzo_id, because the question
/// is "does a store still own the record THIS request is holding" -
/// the same identity `activate_parked`'s own `retain` and `park`'s
/// history push move between the two stores. An id comparison would
/// answer about whatever record wears the id now.
///
/// Read under `add_lock`, and that is the whole of the care this
/// needed. "In neither store" is NOT by itself "deleted": `park`,
/// `retry` and `activate_parked` each take the record out of one store
/// before pushing it into the other, and each holds `add_lock` across
/// that window precisely so nothing may read the gap as an answer
/// (`moveseq`'s two `*_holds_the_add_lock_across_its_neither_store_window`
/// tests pin that, and a park's window is the dangerous one - the
/// record inside it is `Completed`, so an absence read as a delete
/// would 404 a job that had just finished). Under the lock no such
/// move can be mid-flight, so an absence is a delete.
///
/// `try_lock`, NEVER `lock`. An HTTP worker must not park on the
/// publish lock behind a directory scan - that is §166's whole subject
/// one lock over - and a busy lock is not an emergency here: this pass
/// then answers exactly what a plain two-store read answered before
/// this function existed, the caller keeps waiting, and the next poll a
/// second later asks again. A permanently busy `add_lock` degrades to
/// the behaviour that shipped.
///
/// Queue first, then history, so a record momentarily readable in both
/// reads as queued - the waiting answer, and the conservative one.
pub fn custody(d: &Daemon, job: &Arc<Mutex<Job>>) -> Custody {
    // Poison is not contention. Some thread panicked mid-publish, and
    // `lock_ok`'s argument holds here too - what this lock serializes
    // is a directory decision, not a data structure, so a panicked
    // publisher leaves nothing half-written behind it. Reading poison
    // as "busy" would disable the third case for the daemon's whole
    // remaining life.
    let publish = match d.add_lock.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    };
    if d.queue.lock_ok().iter().any(|j| Arc::ptr_eq(j, job)) {
        return Custody::Queued;
    }
    if d.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, job)) {
        return Custody::Parked;
    }
    // In neither. Only the holder of the publish lock may call that a
    // delete; anyone else is looking into a move's own window and owes
    // the caller the waiting answer instead.
    if publish.is_some() {
        Custody::Gone
    } else {
        Custody::Parked
    }
}

/// TODO 16m: may this `/stream/<id>` answer its 404 immediately, instead
/// of sitting out the M14i admit wait for writers that are never coming?
///
/// The question is "are there writers, and is there any PROSPECT of
/// any" - deliberately NOT "does the status word say Completed". Both
/// halves of that distinction are live:
///
/// - A `Completed` job can still materialise its media LATE. Its
///   extractor stays installed after the run for post-completion
///   playback (`tasks/runner.rs` only clears it when the NEXT job
///   claims the hub), the disk-unpack ladder outlives the download it
///   belongs to (§205), and a completion with a move configured still
///   owes the payload a move to its final home. So the writer registry
///   and the settle state are asked, and a "yes" from either is enough
///   to keep waiting.
/// - A `Queued` job is the opposite error: its status word says nothing
///   has happened yet, and its writers appear the moment the runner
///   picks it up. That is the wait working as designed.
///
/// - And a record in NEITHER store is a THIRD case, not a flavour of
///   either. A `mode=queue&name=delete` landing under the wait leaves
///   this loop holding an `Arc` no store owns any more, and the status
///   word inside it is frozen at whatever it said when the delete took
///   it out - `Queued`, for the commonest shape of all, a play that
///   force-enqueued the job and a user who changed their mind before
///   the runner reached it. Reading that word is reading a record that
///   has stopped existing: nothing will advance it and no runner will
///   ever pick the job up, so there is no prospect whatever it says.
///   That is what [`Custody::Gone`] carries, and why it is asked BEFORE
///   the settle rather than folded into it.
///
/// Hence: nothing in the queue, a terminal history row that owes
/// nothing more (no move still owed, and no armed auto-retry that could
/// bring the job back INSIDE `wait_ends`) or no row at all any more, no
/// activity or unpack entry against the id, and no media writer in the
/// extractor that belongs to it.
///
/// The writer terms are asked of a `Gone` record too, deliberately: a
/// job deleted while it was DOWNLOADING leaves the queue at once and
/// its pipeline drains afterwards, so "the record is gone" and "the
/// writers are gone" are two different instants and only the second one
/// answers this question.
///
/// `wait_ends` is when this request's admit wait expires, in unix
/// seconds - the horizon the retry stamp is judged against.
///
/// The job snapshot is taken and RELEASED before any hub lock: the
/// serve/ order is queue -> job, and a job -> hub edge is exactly the
/// shape issue #38's deadlock was built from.
pub(super) fn no_writers_and_no_prospect(
    d: &Daemon,
    id: &str,
    parked: Option<&Arc<Mutex<Job>>>,
    held: Custody,
    wait_ends: u64,
) -> bool {
    // In the queue at all - being picked, downloading, or running its
    // tail. Writers are coming or already here.
    if held == Custody::Queued {
        return false;
    }
    // Deleted under the wait: no record left to read, and none needed.
    // Straight on to the writer terms below.
    if held != Custody::Gone {
        // In neither store, with no handle to judge: `stream_request` has
        // already answered that one with `unknown nzo_id`, so this arm is
        // unreachable from there. Refusing rather than answering keeps it
        // right for anyone else.
        let Some(job) = parked else {
            return false;
        };
        let settled = {
            let j = job.lock_ok();
            matches!(j.state, JobState::Completed | JobState::Failed)
            // M32: an armed automatic retry brings the whole job back -
            // but only a retry that lands while this request is still
            // waiting can produce a writer FOR IT. Testing the stamp for
            // None left the commonest failure of all still hanging: a
            // partly-propagated post arms the 20-minute "articles
            // missing" arm, the transport arm is 2 minutes, and neither
            // can reach a 30 s deadline - so the shape a stale .strm
            // most often points at sat out the full wait for a 404 that
            // was knowable on arrival. `auto_retry_at` is an ABSOLUTE
            // unix-seconds stamp (`unix_now() + secs`, daemon_park.rs /
            // daemon_retry.rs), so it compares straight against the
            // wait's own end. `<=` counts as a prospect: a retry due at
            // the last instant is one the caller may still be given, and
            // the delay is a user setting that can be shortened.
            && j.auto_retry_at.is_none_or(|at| at > wait_ends)
            && !j.move_pending
        };
        if !settled {
            return false;
        }
    }
    // Both maps are keyed by owning nzo_id precisely because a tail
    // outlives its own download, so an entry here means the pipeline
    // has not finished with this job whatever its row says.
    if d.hub.activity.lock_ok().contains_key(id) || d.hub.unpack.lock_ok().contains_key(id) {
        return false;
    }
    // And the registry itself, through the same ownership-checked pick
    // the loop below uses - so "no writers" is the loop's own answer,
    // not a second opinion that could disagree with it.
    pick_media(d, Some(id)).is_none()
}

/// Is the run whose writers the hub is still holding IN the queue -
/// being picked, downloading, or running its tail?
///
/// This is the premise the live `/stream` route is open ON. Byte-serving
/// the pipeline needs no key because a player cannot send one and the
/// bytes are only ever the download in front of you; a FINISHED
/// download is a different thing, and takes the key-or-token gate
/// [`super::serve_finished_from_disk`] applies, because nzo_ids are
/// enumerable and the library is not the caller's to walk.
///
/// Nothing kept those two apart. `active_stream` is set as a job's
/// fetch spawns and is NEVER cleared - only overwritten when the NEXT
/// job claims the hub (`tasks/runner.rs`, which drops the spent
/// extractor in the same breath) - so on an idle daemon it goes on
/// naming the last job that ran, for as long as nothing else runs. The
/// extractor beside it keeps listing that run's media writers, whose
/// backing files a normal completion leaves whole. Measured 25 Aug
/// 2026 against the real daemon: a keyless `GET /stream` with a Range
/// header answered `206` with the finished download's payload bytes,
/// byte-exact, still doing so 25 s after the row parked, and the
/// `/stream/<id>` spelling did the same for every history row the disk
/// gate declines to judge - a `Failed` one, or a tombstoned one - since
/// that gate fires only on `Completed && fetched && !tombstone`.
///
/// So the openness is scoped to the premise instead of to the route.
/// In the queue covers the whole of what the M11 contract means by the
/// active download, the post-network tail included: job N stays in the
/// queue through repair, unpack and the move while job N+1 may already
/// be on the wire (`Daemon::owns_hub`), which is the same reading
/// [`Custody::Queued`] takes two functions up.
///
/// `want = None` is the bare M11 route, which owns whatever the hub
/// holds - so the owner comes from `active_stream`, the only thing that
/// names it. A missing owner is `false` and not `true`: an extractor is
/// only ever installed by a run that published its id first, so there
/// is no live pick to protect here, and the honest answer to "is the
/// owner still queued" when there is no owner is no.
///
/// The id is cloned out from under `active_stream` before the queue is
/// read. That ordering is not decoration - `sabcompat/prelock.rs`
/// records the deadlock the other direction built, a handler holding
/// the queue and asking for `active_stream` while the media prober held
/// `active_stream` and asked for the queue.
pub(super) fn hub_run_still_queued(d: &Daemon, want: Option<&str>) -> bool {
    let owner = match want {
        Some(id) => Some(id.to_string()),
        None => d.active_stream.lock_ok().clone(),
    };
    let Some(owner) = owner else {
        return false;
    };
    let q = d.queue.lock_ok();
    find_job(q.iter(), &owner).is_some()
}

/// The one refusal both `/stream` gates give an unauthenticated caller,
/// so they cannot drift apart on what they say, on what they answer, or
/// on whether the attempt is counted.
///
/// `what` is the `note_auth_failure` label: which door was knocked on,
/// for the rate limiter that turns a sweep of guesses into a 429.
pub(super) fn refuse_finished(d: &Daemon, req: tiny_http::Request, what: &str) {
    let blocked = d.note_auth_failure(peer_ip(&req), what);
    let _ = req.respond(if blocked {
        tiny_http::Response::from_string("too many bad keys").with_status_code(429)
    } else {
        tiny_http::Response::from_string(
            "playing a finished download needs an apikey or stream token (?t=)",
        )
        .with_status_code(401)
    });
}

#[cfg(test)]
mod stream_admit_tests {
    use super::*;

    /// A history record, from the same wire shape the stores replay.
    pub fn rec(id: &str, state: &str, extra: serde_json::Value) -> Arc<Mutex<Job>> {
        let mut v = serde_json::json!({
            "nzo_id": id, "name": id, "nzb_path": "/tmp/x.nzb",
            "out_dir": format!("/tmp/out/{id}"), "state": state,
        });
        if let Some(m) = extra.as_object() {
            for (k, val) in m {
                v[k] = val.clone();
            }
        }
        Arc::new(Mutex::new(job_from_json(&v).expect("job_from_json")))
    }

    /// The live route's openness follows the RUN, not the route and not
    /// the row: hub bytes are the download in front of you only while
    /// the job that made them is still in the queue.
    ///
    /// Every arm here was reachable. `active_stream` is never cleared,
    /// only overwritten by the next job, so on an idle daemon it goes
    /// on naming the last run for as long as nothing else starts - and
    /// the disk gate beside it judges only `Completed && fetched &&
    /// !tombstone`, so the `Failed` and tombstoned rows walked past it
    /// into the open path, and the bare `/stream` spelling reads no row
    /// at all.
    #[test]
    fn hub_bytes_are_open_only_while_the_run_is_queued() {
        let dir = std::env::temp_dir().join(format!("nzbfast-16m-spent-{}", std::process::id()));
        let d = crate::testutil::test_daemon(&dir);

        // Nothing has ever run: no owner, so nothing to hand out. The
        // bare route must not read a missing owner as "mine".
        assert!(!hub_run_still_queued(&d, None));
        assert!(!hub_run_still_queued(&d, Some("r1")));

        // A run in flight. The bare route owns whatever the hub holds,
        // so it resolves its owner through `active_stream`.
        let running = rec("r1", "Downloading", serde_json::json!({}));
        d.queue.lock_ok().push_back(running.clone());
        *d.active_stream.lock_ok() = Some("r1".to_string());
        assert!(hub_run_still_queued(&d, Some("r1")));
        assert!(hub_run_still_queued(&d, None));
        // ...but only for the job it belongs to.
        assert!(!hub_run_still_queued(&d, Some("r2")));

        // Parked. The hub keeps the spent extractor and `active_stream`
        // keeps the name, and neither of those is the download in front
        // of the caller any more.
        d.queue.lock_ok().clear();
        d.history.lock_ok().push(running);
        assert_eq!(d.active_stream.lock_ok().as_deref(), Some("r1"));
        assert!(!hub_run_still_queued(&d, Some("r1")));
        assert!(!hub_run_still_queued(&d, None));

        // A retry puts the same job back on the queue, and its writers
        // are its own either way - so it is open again.
        let again = rec("r1", "Queued", serde_json::json!({}));
        d.queue.lock_ok().push_back(again);
        assert!(hub_run_still_queued(&d, Some("r1")));
        assert!(hub_run_still_queued(&d, None));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The horizon a live request judges an armed retry against: this
    /// instant plus the admit wait, in unix seconds.
    fn horizon() -> u64 {
        unix_now() as u64 + ADMIT_WAIT_SECS
    }

    /// TODO 16m: the answer is knowable now for a terminal record that
    /// owes nothing more - whichever way it ended, and with its own
    /// spent extractor still installed (the hub keeps it for
    /// post-completion playback until the next job claims the hub, and
    /// an extractor holding no media writer is not a prospect of one).
    #[test]
    fn a_settled_terminal_record_needs_no_wait() {
        let dir = std::env::temp_dir().join(format!("nzbfast-16m-unit-{}", std::process::id()));
        let d = crate::testutil::test_daemon(&dir);
        for state in ["Completed", "Failed"] {
            let j = rec("s1", state, serde_json::json!({}));
            assert!(
                no_writers_and_no_prospect(&d, "s1", Some(&j), Custody::Parked, horizon()),
                "{state} with nothing owed should answer at once"
            );
        }
        *d.hub.extractor.lock_ok() = Some((
            "s1".to_string(),
            Arc::new(nzbkit::extract::Extractor::new(&dir, 1, false)),
        ));
        let j = rec("s1", "Failed", serde_json::json!({}));
        assert!(
            no_writers_and_no_prospect(&d, "s1", Some(&j), Custody::Parked, horizon()),
            "a spent extractor with no media writer is not a writer to wait for"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and every way a job can still acquire one waits. Each arm is
    /// a record a "state is Completed/Failed" test would have answered
    /// immediately and wrongly.
    #[test]
    fn every_remaining_prospect_still_waits() {
        let dir = std::env::temp_dir().join(format!("nzbfast-16m-unit2-{}", std::process::id()));
        let d = crate::testutil::test_daemon(&dir);

        // In the queue: about to be picked, or running its tail. The
        // record itself says nothing useful here, so the terminal one
        // is used deliberately.
        let j = rec("p1", "Completed", serde_json::json!({}));
        assert!(!no_writers_and_no_prospect(
            &d,
            "p1",
            Some(&j),
            Custody::Queued,
            horizon()
        ));

        // A record that reached history while its pipeline was still
        // running - a park torn between its prewrite and its filing.
        // `job_from_json` restores any nonterminal state as Queued.
        let torn = rec("p2", "Downloading", serde_json::json!({}));
        assert_eq!(torn.lock_ok().state, JobState::Queued);
        assert!(!no_writers_and_no_prospect(
            &d,
            "p2",
            Some(&torn),
            Custody::Parked,
            horizon()
        ));

        // The settle's other half: the payload still owes its move, so
        // the media file materialises at its destination later.
        let moving = rec("p3", "Completed", serde_json::json!({"move_pending": true}));
        assert!(!no_writers_and_no_prospect(
            &d,
            "p3",
            Some(&moving),
            Custody::Parked,
            horizon()
        ));

        // M32: an armed automatic retry brings the whole job back -
        // when it lands inside the wait. Five seconds out, so it fires
        // with most of the deadline still to run.
        let soon = unix_now() as u64 + 5;
        let armed = rec("p4", "Failed", serde_json::json!({"auto_retry_at": soon}));
        assert!(!no_writers_and_no_prospect(
            &d,
            "p4",
            Some(&armed),
            Custody::Parked,
            horizon()
        ));

        // And one already DUE: the retry worker is about to pick it up.
        let due = rec(
            "p4b",
            "Failed",
            serde_json::json!({"auto_retry_at": unix_now() as u64 - 1}),
        );
        assert!(!no_writers_and_no_prospect(
            &d,
            "p4b",
            Some(&due),
            Custody::Parked,
            horizon()
        ));

        // The tail outlives the download it belongs to, and both maps
        // are keyed by owning nzo_id for exactly that reason.
        let busy = rec("p5", "Completed", serde_json::json!({}));
        d.hub
            .activity
            .lock_ok()
            .insert("p5".to_string(), "extracting");
        assert!(!no_writers_and_no_prospect(
            &d,
            "p5",
            Some(&busy),
            Custody::Parked,
            horizon()
        ));

        // And a record in neither store cannot be judged from here at
        // all - the caller has its own answer for that one.
        assert!(!no_writers_and_no_prospect(
            &d,
            "p6",
            None,
            Custody::Parked,
            horizon()
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TODO 16m, the shape the first pass left behind: a Failed job
    /// whose automatic retry cannot possibly fire before this request is
    /// answered.
    ///
    /// Both arms `arm_auto_retry` can choose are here, at the values it
    /// actually uses. Neither is reachable inside a 30 s deadline, and
    /// the propagation one is armed by the COMMONEST failure there is -
    /// a post that is only partly propagated - which is also the
    /// likeliest thing a stale .strm in a media library points at. Under
    /// the `is_none()` test those both sat out the whole wait for a 404
    /// that was knowable on arrival.
    #[test]
    fn an_auto_retry_that_lands_after_the_deadline_is_no_prospect() {
        let dir = std::env::temp_dir().join(format!("nzbfast-16m-unit3-{}", std::process::id()));
        let d = crate::testutil::test_daemon(&dir);
        for (secs, what) in [
            (crate::SHORT_RETRY_SECS, "the transport arm"),
            (20 * 60, "the propagation arm"),
        ] {
            let at = unix_now() as u64 + secs;
            let j = rec("r1", "Failed", serde_json::json!({ "auto_retry_at": at }));
            assert!(
                no_writers_and_no_prospect(&d, "r1", Some(&j), Custody::Parked, horizon()),
                "{what} ({secs}s) cannot produce a writer inside a {ADMIT_WAIT_SECS}s wait"
            );
        }

        // The boundary belongs to the waiting side: a retry due at the
        // very last instant of the wait is still one this caller may be
        // given, and the delay is a user setting that can be shortened
        // to anything.
        let edge = horizon();
        let j = rec("r2", "Failed", serde_json::json!({ "auto_retry_at": edge }));
        assert!(!no_writers_and_no_prospect(
            &d,
            "r2",
            Some(&j),
            Custody::Parked,
            edge
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TODO 16m's THIRD shape: the job is DELETED while the request
    /// waits for its writers.
    ///
    /// The loop holds the record as an `Arc`, so a delete under the wait
    /// leaves it reading a record nothing owns any more - and every
    /// field in it still says what it said when the delete took it out.
    /// For the commonest shape of all that word is `Queued`, which is
    /// the one answer the predicate treats as "writers are coming": the
    /// request then sat out the remaining deadline for a 404 that was
    /// knowable the instant the delete landed.
    ///
    /// The same record is asserted BOTH ways here on purpose. Read as
    /// parked it must still wait - that is the ordinary queued-looking
    /// history row `a_job_still_settling_still_waits` covers - so the
    /// custody read is doing the whole of the work, and a fix that had
    /// instead loosened the settle would fail the control arm.
    #[test]
    fn a_record_deleted_under_the_wait_needs_no_wait() {
        let dir = std::env::temp_dir().join(format!("nzbfast-16m-unit4-{}", std::process::id()));
        let d = crate::testutil::test_daemon(&dir);

        let j = rec("g1", "Queued", serde_json::json!({}));
        assert_eq!(j.lock_ok().state, JobState::Queued);
        assert!(
            no_writers_and_no_prospect(&d, "g1", Some(&j), Custody::Gone, horizon()),
            "a record in neither store can never be picked up by a runner"
        );
        assert!(
            !no_writers_and_no_prospect(&d, "g1", Some(&j), Custody::Parked, horizon()),
            "the control arm: the SAME record still waits while a store owns it"
        );

        // ...and it needs no record at all. `stream_request` always has
        // one, but the predicate must not depend on that: the answer is
        // about the stores, not about the handle.
        assert!(no_writers_and_no_prospect(
            &d,
            "g1",
            None,
            Custody::Gone,
            horizon()
        ));

        // The writer terms still apply. A job deleted while it was
        // DOWNLOADING leaves the queue at once and its pipeline drains
        // afterwards, so the record going is not the writers going.
        d.hub
            .activity
            .lock_ok()
            .insert("g1".to_string(), "aborting");
        assert!(
            !no_writers_and_no_prospect(&d, "g1", Some(&j), Custody::Gone, horizon()),
            "a deleted job whose pipeline is still draining has writers to wait for"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The custody read itself: which store, by IDENTITY.
    ///
    /// The id arm is the one worth pinning. A store holding a DIFFERENT
    /// record under the same nzo_id does not own THIS request's handle,
    /// and the loop's whole problem is that it is holding one - so an
    /// id comparison would answer about whatever record wears the name
    /// now, which is the question nobody asked.
    #[test]
    fn custody_names_the_store_that_owns_this_record() {
        let dir = std::env::temp_dir().join(format!("nzbfast-16m-unit5-{}", std::process::id()));
        let d = crate::testutil::test_daemon(&dir);

        let j = rec("c1", "Queued", serde_json::json!({}));
        assert_eq!(custody(&d, &j), Custody::Gone, "in neither store yet");

        d.queue.lock_ok().push_back(j.clone());
        assert_eq!(custody(&d, &j), Custody::Queued);

        d.queue.lock_ok().clear();
        d.history.lock_ok().push(j.clone());
        assert_eq!(custody(&d, &j), Custody::Parked);

        // A namesake in both stores is not this record.
        d.history.lock_ok().clear();
        let twin = rec("c1", "Completed", serde_json::json!({}));
        d.history.lock_ok().push(twin);
        assert_eq!(
            custody(&d, &j),
            Custody::Gone,
            "custody is about the handle this request holds, not the id"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The care the third case actually needed: a record is in NEITHER
    /// store for the width of every store-to-store move, and reading
    /// that gap as a delete would 404 a job that is merely in flight.
    ///
    /// `park`'s window is the dangerous one - the record inside it is
    /// `Completed`, so it clears the settle and the predicate would
    /// answer at once - and `activate_parked`'s is the one `/stream`
    /// opens ITSELF, one statement before arming this wait. Both hold
    /// `add_lock` across the window (pinned in `moveseq` as the
    /// dir-claim fence), which is what `custody` leans on.
    ///
    /// The seams run their callback on the moving thread, so the
    /// `try_lock` here fails as the owner rather than as a contender -
    /// the same `WouldBlock`, reached the way a real reader on another
    /// thread reaches it, and the same answer is owed.
    #[test]
    fn a_store_to_store_move_is_never_read_as_a_delete() {
        let dir = std::env::temp_dir().join(format!("nzbfast-16m-unit6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = crate::testutil::test_daemon(&dir);

        // The activation window: out of history, not yet in the queue.
        let a = rec("w1", "Completed", serde_json::json!({"library": true}));
        d.history.lock_ok().push(a.clone());
        assert!(d.history_upsert(std::slice::from_ref(&a)));
        assert!(d.save_queue());
        a.lock_ok().state = JobState::Queued;
        let seen = Arc::new(Mutex::new(None));
        let sink = seen.clone();
        let probe = a.clone();
        crate::storecut::on_activate_gap(move |d| {
            *sink.lock_ok() = Some(custody(d, &probe));
        });
        d.activate_parked(&a);
        crate::storecut::disarm();
        assert_eq!(
            seen.lock_ok().take(),
            Some(Custody::Parked),
            "the activation's neither-store window was read as a delete"
        );

        // The park window: out of the queue, not yet in history - and
        // the record inside it reads `Completed`.
        let b = rec("w2", "Completed", serde_json::json!({"fetched": true}));
        d.queue.lock_ok().push_back(b.clone());
        assert!(d.save_queue());
        let seen2 = Arc::new(Mutex::new(None));
        let sink2 = seen2.clone();
        let probe2 = b.clone();
        crate::storecut::on_park_gap(move |d| {
            *sink2.lock_ok() = Some(custody(d, &probe2));
        });
        d.park_gen(b, None);
        crate::storecut::disarm();
        assert_eq!(
            seen2.lock_ok().take(),
            Some(Custody::Parked),
            "park's neither-store window was read as a delete - a job that \
             had just finished would 404"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
