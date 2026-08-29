//! serve tests: job records - restore, history deletes, filing and
//! the queue-file round trips.//!
//! Split out of serve/mod.rs's inline `mod tests` by TODO 106 phase 4;
//! attached to serve as a sibling child module, so `super` still means
//! `serve` exactly as it did inline.

use super::*;

/// A LossCauses with nothing known, for messages under test.
pub(super) fn no_causes() -> crate::LossCauses<'static> {
    crate::LossCauses {
        missing_430: 0,
        takedown_430: 0,
        unasked_430: 0,
        retention_excluded: 0,
        transport_failed: 0,
        missing_430_recovery: 0,
        takedown_430_recovery: 0,
        retention_excluded_recovery: 0,
        transport_failed_recovery: 0,
        recovery_segments: 0,
        recovery_unobtainable: false,
        transport_sample: None,
        decode_sample: None,
        recovery_errs: 0,
        dead_servers: &[],
        left_servers: &[],
        par2_slots: 1,
        stalled: false,
        missing_segments: 0,
        total_segments: 0,
        bytes_arrived: 0,
        backbones: &[],
        post_age_days: 0,
    }
}

/// Build a Job the way a restart does, so a test does not have to
/// spell out forty fields.
pub(super) fn job(v: serde_json::Value) -> Job {
    super::job_from_json(&v).expect("job_from_json")
}

/// UX §16: "verified clean" is a claim, and a claim needs a verifier.
///
/// `bad_blocks` used to be a plain `u64` that defaulted to 0, so a
/// post carrying no PAR2 - and a resume that mapped no block to a
/// recovery set - arrived at the dashboard indistinguishable from a
/// download something had checked and found perfect. The health tile
/// counted them as clean verifications and the timeline drew them as
/// green ticks. Null is the third answer: nothing verified this.
#[test]
fn a_verify_verdict_needs_a_verifier_behind_it() {
    let base = |extra: serde_json::Value| {
        let mut v = json!({
            "nzo_id": "x", "name": "Show.1080p", "nzb_path": "/spool/x.nzb",
            "state": "Completed", "out_dir": "/dl/x",
        });
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        job(v)
    };
    // Nothing recorded at all: not a verdict.
    assert_eq!(base(json!({})).bad_blocks, None);
    // A modern record that verified and found nothing wrong. The
    // block count is what makes the zero mean something.
    let clean = base(json!({"bad_blocks": 0, "verify_blocks": 12_847}));
    assert_eq!(clean.bad_blocks, Some(0));
    assert_eq!(clean.verify_blocks, 12_847);
    // A modern record that verified and found damage.
    assert_eq!(
        base(json!({"bad_blocks": 900, "verify_blocks": 12_847})).bad_blocks,
        Some(900)
    );
    // A record from before the field could be null. A zero with no
    // companion count is unknowable - "verified clean" and "nobody
    // looked" both wrote 0 - and must not be reported as a clean
    // verification. A non-zero count is proof a verifier ran, so it
    // survives as a verdict.
    assert_eq!(base(json!({"bad_blocks": 0})).bad_blocks, None);
    assert_eq!(base(json!({"bad_blocks": 3})).bad_blocks, Some(3));
    // ...and a verifier that ran but mapped nothing checked zero
    // blocks, which is the same non-answer.
    assert_eq!(
        base(json!({"bad_blocks": 0, "verify_blocks": 0})).bad_blocks,
        None
    );
}

/// UX §15: the queue percentage's two halves must count ONE thing.
///
/// The pair this replaced divided decoded payload (every slot, PAR2
/// included) by the NZB's encoded bytes minus recovery volumes, so a
/// clean download stopped near 97% still claiming a gigabyte "left"
/// that did not exist, and a damaged one - where the extra recovery
/// bytes land on the numerator alone - pinned at 100% with articles
/// still in flight.
#[test]
fn fetch_progress_reaches_a_hundred_and_never_passes_it() {
    use std::sync::atomic::Ordering;
    let hub = crate::streamhub::StreamHub::default();
    // No plan published yet: every caller must fall back rather than
    // divide by a plan belonging to nobody.
    assert_eq!(hub.fetch_left(), None);
    hub.fetch_counters().plan.store(1_000, Ordering::Relaxed);
    assert_eq!(hub.fetch_left(), Some((0, 1_000, 1_000)));
    // A resume seeds `done` with what is already in hand, so the bar
    // starts where the bytes are.
    hub.fetch_counters().done.store(600, Ordering::Relaxed);
    assert_eq!(hub.fetch_left(), Some((600, 1_000, 400)));
    // Drained: exactly 100%, exactly nothing left.
    hub.fetch_counters().done.store(1_000, Ordering::Relaxed);
    assert_eq!(hub.fetch_left(), Some((1_000, 1_000, 0)));
    // Two independent atomics, so a reader can land past the plan.
    // Clamped, never an overshoot or an underflowed remainder.
    hub.fetch_counters().done.store(1_200, Ordering::Relaxed);
    assert_eq!(hub.fetch_left(), Some((1_000, 1_000, 0)));
}

/// The NZBGet history verdict must separate the failures a user can
/// actually act on.
///
/// Every failure used to report `FAILURE/PAR` with
/// `ParStatus: FAILURE` - one bit, so "needs a password", "the disk
/// filled up" and "the post is missing articles" were
/// indistinguishable to a client, and all three were blamed on a
/// repair that in two of the three cases never ran. That sends the
/// user looking at the release when the problem is on their machine.
#[test]
fn nzbget_status_separates_the_failure_kinds() {
    let j = |state: &str, msg: &str| {
        job(json!({
            "nzo_id": "x", "name": "Show.1080p", "nzb_path": "/spool/x.nzb",
            "state": state, "out_dir": "/dl/x", "fail_message": msg,
        }))
    };

    assert_eq!(
        super::nzbget_status(&j("Completed", "")),
        ("SUCCESS/UNPACK", "SUCCESS", "SUCCESS"),
        "the success shape is what the M26 round certified - do not drift it"
    );
    // A password is an unpack verdict with its own NZBGet status, and
    // the par stage succeeded, so blaming par is wrong twice over.
    assert_eq!(
        super::nzbget_status(&j("Failed", "password required to unpack")),
        ("FAILURE/UNPACK", "SUCCESS", "PASSWORD")
    );
    assert_eq!(
        super::nzbget_status(&j("Failed", "write failed: no space left on device")),
        ("FAILURE/UNPACK", "SUCCESS", "SPACE")
    );
    // Windows spells a full disk differently (error 112), and the
    // check that only knew the Unix words reported a tester's
    // disk-full unpack as a generic unpack failure.
    assert_eq!(
        super::nzbget_status(&j(
            "Failed",
            "unpack failed: There is not enough space on the disk. (os error 112)"
        )),
        ("FAILURE/UNPACK", "SUCCESS", "SPACE")
    );
    // The post could not be fetched whole: health, and no par verdict,
    // because par never got to run.
    assert_eq!(
        super::nzbget_status(&j("Failed", "download incomplete: 12 articles missing")),
        ("FAILURE/HEALTH", "NONE", "NONE")
    );
    // The one case that really is a failed repair.
    assert_eq!(
        super::nzbget_status(&j("Failed", "repair could not complete")),
        ("FAILURE/PAR", "FAILURE", "NONE")
    );
}

/// NZBGet's priority scale is not ours: theirs runs -100/-50/0/50/100
/// with 900 for force, ours is SAB's -1/0/1 with 2 for force. Passed
/// through unmapped, "high" from an *arr landed far above Force.
#[test]
fn nzbget_priority_maps_onto_our_scale() {
    assert_eq!(super::nzbget_priority(900), 2, "force");
    assert_eq!(super::nzbget_priority(100), 1, "very high");
    assert_eq!(super::nzbget_priority(50), 1, "high");
    assert_eq!(super::nzbget_priority(0), 0, "normal");
    assert_eq!(super::nzbget_priority(-50), -1, "low");
    assert_eq!(super::nzbget_priority(-100), -1, "very low");
}

/// BUG (HIGH): a job caught in post-processing became a permanent
/// zombie.
///
/// `finalize_completed` corrects the record's out_dir only as its last
/// statement, so during post-processing - unlock, cleanup, rename, TV
/// filing, and a NAS move that can run for minutes - the durable
/// record says "Completed, payload is at X" while the payload is on
/// its way to Y. A restart there filed the job as a clean success
/// with a storage path that could be half-copied, or already emptied
/// by the move, and the *arrs act on that: import the partial file,
/// or stall with no Failed state to trigger a re-grab.
///
/// Nothing can tell the two apart AFTER the fact, which is why the
/// intent is written down first. This pins both directions.
#[test]
fn only_a_job_caught_mid_finalize_is_reported_failed() {
    let rec = |id: &str, finalizing: bool| {
        json!({
            "nzo_id": id, "name": format!("Show.{id}.1080p"),
            "nzb_path": format!("/spool/{id}.nzb"), "state": "Completed",
            "out_dir": format!("/dl/{id}"), "finalizing": finalizing,
        })
    };
    let (_q, h) = super::restore_records(&[rec("mid", true), rec("done", false)], &[]);

    let mid = h
        .iter()
        .find(|j| j.nzo_id == "mid")
        .expect("interrupted job kept");
    assert_eq!(
        mid.state,
        JobState::Failed,
        "a job caught mid-finalize must not claim success - the *arrs would import \
         a half-moved directory"
    );
    assert!(
        mid.fail_message.contains("/dl/mid"),
        "the message must say where the bytes are, so nothing is lost: {:?}",
        mid.fail_message
    );
    assert!(
        !mid.finalizing,
        "the flag is consumed on restore, not carried forward"
    );

    // The common case is untouched: post-processing finished, only the
    // hooks were lost, so it stays a success.
    let done = h
        .iter()
        .find(|j| j.nzo_id == "done")
        .expect("finished job kept");
    assert_eq!(
        done.state,
        JobState::Completed,
        "a finished job still reports success"
    );
    assert!(done.fail_message.is_empty(), "and carries no failure text");

    // A record written before this field existed must read as "not
    // interrupted" rather than failing every old completed job.
    let legacy = json!({
        "nzo_id": "old", "name": "Old.1080p", "nzb_path": "/spool/old.nzb",
        "state": "Completed", "out_dir": "/dl/old",
    });
    let (_q2, h2) = super::restore_records(&[legacy], &[]);
    assert_eq!(
        h2[0].state,
        JobState::Completed,
        "an upgrade must not mass-fail history that predates the flag"
    );
}

/// A job goes Completed (or Failed) the instant its download ends, but
/// only reaches history when `park` files it - and the whole of
/// post-processing sits between those two points. Any `save_queue`
/// during that window persists a TERMINAL record inside the "queue"
/// array, and restoring it there left it somewhere nothing could reach:
/// `pick_job` takes only `Queued` jobs, nothing reconciles the arrays,
/// so it sat in the queue forever - never ran, never appeared in
/// history, never reported an outcome to the *arrs waiting for one.
#[test]
fn a_job_caught_in_post_processing_comes_back_in_history() {
    let rec = |id: &str, state: &str| {
        json!({
            "nzo_id": id, "name": format!("Show.S01E0{}.1080p", id.len()),
            "nzb_path": format!("/spool/{id}.nzb"), "state": state,
            "out_dir": format!("/dl/{id}"),
        })
    };
    // What save_queue writes mid-post-processing, plus the two records
    // that legitimately belong in the queue.
    let queue_arr = vec![
        rec("n1", "Completed"),
        rec("n2", "Failed"),
        // The interrupted transfer: it must STAY queued so the
        // scheduler restarts it and its journal resumes.
        rec("n3", "Downloading"),
        rec("n4", "Queued"),
    ];
    let hist_arr = vec![rec("h1", "Completed")];
    let (q, h) = super::restore_records(&queue_arr, &hist_arr);

    let qids: Vec<&str> = q.iter().map(|j| j.nzo_id.as_str()).collect();
    assert_eq!(
        qids,
        ["n3", "n4"],
        "only records the scheduler can run stay queued"
    );
    // Exactly pick_job's precondition: anything else in this array is
    // unreachable forever.
    assert!(
        q.iter().all(|j| j.state == JobState::Queued),
        "every restored queue record is one pick_job can actually pick"
    );

    let hids: Vec<&str> = h.iter().map(|j| j.nzo_id.as_str()).collect();
    assert_eq!(
        hids,
        ["h1", "n1", "n2"],
        "the interrupted jobs join history after the records already there"
    );
    // The outcome park() would have given them, not a rewrite of it.
    assert_eq!(h[1].state, JobState::Completed);
    assert_eq!(h[2].state, JobState::Failed);
    // ...and no job is in both arrays.
    assert!(q.iter().all(|j| !h.iter().any(|k| k.nzo_id == j.nzo_id)));
}

/// `park` retains-then-pushes before its single save, so a well-formed
/// file never holds one job twice - but a torn or hand-edited one must
/// not be turned into two history entries by the reconciliation above.
#[test]
fn a_record_in_both_arrays_is_restored_once() {
    let rec = |state: &str| {
        json!({"nzo_id": "dup", "name": "X.2024", "nzb_path": "/spool/dup.nzb",
               "state": state, "out_dir": "/dl/dup"})
    };
    let (q, h) = super::restore_records(&[rec("Completed")], &[rec("Completed")]);
    assert!(q.is_empty());
    assert_eq!(h.len(), 1, "one record, not two");
}

/// BUG (MEDIUM, data loss): two Completed records can name ONE
/// directory, so a delete wiped the live job's files.
///
/// `publish_over_previous` (A6) hands the canonical directory to a
/// verified re-download but leaves the superseded job's history record
/// pointing at it too. A delete-with-files on the OLDER record then
/// `remove_dir_all`'d the NEWER job's payload: the record deleted was
/// not the data destroyed.
#[test]
fn deleting_a_superseded_record_spares_the_newer_jobs_directory() {
    let canon = PathBuf::from("/dl/Movie.2024");
    let rec = |id: &str, state: JobState, dir: &PathBuf, filed: bool| super::DeleteRecord {
        nzo_id: id.to_string(),
        state,
        out_dir: dir.clone(),
        filed,
        locked: false,
    };
    // Both records name the canonical directory; "new" lives there.
    let shared = vec![
        rec("old", JobState::Completed, &canon, false),
        rec("new", JobState::Completed, &canon, false),
    ];

    let plan = super::plan_history_delete(&shared, "old", &[]);
    assert!(plan[0].doomed, "the record still goes");
    assert!(
        !plan[0].may_remove_files,
        "but the files are the newer job's"
    );
    assert!(!plan[1].doomed);

    // The ordinary single-owner delete is untouched.
    let solo = vec![rec(
        "solo",
        JobState::Completed,
        &PathBuf::from("/dl/A"),
        false,
    )];
    let plan = super::plan_history_delete(&solo, "solo", &[]);
    assert!(plan[0].doomed && plan[0].may_remove_files);

    // value=all must still delete. The claimant test runs against the
    // records that SURVIVE, and `all` leaves no history survivors -
    // testing it against the pre-delete list would find every record's
    // directory "claimed" by a doomed sibling and silently stop
    // deleting anything at all.
    let plan = super::plan_history_delete(&shared, "all", &[]);
    assert!(
        plan.iter().all(|p| p.doomed && p.may_remove_files),
        "value=all still removes files"
    );
    // ...but a LIVE queue job in that directory does survive, and wins.
    let plan = super::plan_history_delete(&shared, "all", std::slice::from_ref(&canon));
    assert!(plan.iter().all(|p| p.doomed && !p.may_remove_files));

    // value=failed: the failed record goes, the completed one survives
    // and still claims the directory.
    let mixed = vec![
        rec("f", JobState::Failed, &canon, false),
        rec("c", JobState::Completed, &canon, false),
    ];
    let plan = super::plan_history_delete(&mixed, "failed", &[]);
    assert!(plan[0].doomed && !plan[0].may_remove_files);
    assert!(!plan[1].doomed);

    // A TV-filed record shares its season folder with every sibling by
    // design, and its delete is already narrow (per episode). It must
    // not be disarmed by the claimant test or nothing filed could ever
    // be deleted again.
    let season = PathBuf::from("/dl/Show/Season 03");
    let filed = vec![
        rec("e5", JobState::Completed, &season, true),
        rec("e6", JobState::Completed, &season, true),
    ];
    let plan = super::plan_history_delete(&filed, "e5", &[]);
    assert!(
        plan[0].doomed && plan[0].may_remove_files,
        "the per-episode delete still runs"
    );

    // A comma list still selects exactly what it names.
    let plan = super::plan_history_delete(&mixed, "c,missing", &[]);
    assert!(!plan[0].doomed && plan[1].doomed);
}

/// The dashboard's one-click "Clear completed" tidies the list without
/// throwing away anything the user still has to act on.
///
/// The trap is that "completed" is NOT the same set as the card's
/// Completed filter chip: a password-locked job downloaded fine, so its
/// state is Completed and the chip counts it - but its payload is still
/// packed and that history row carries the only 🔑 to unlock it. A
/// sweep that took it would silently strand the download.
#[test]
fn clear_completed_spares_failures_and_password_locked_records() {
    let rec = |id: &str, state: JobState, locked: bool| super::DeleteRecord {
        nzo_id: id.to_string(),
        state,
        out_dir: PathBuf::from(format!("/dl/{id}")),
        filed: false,
        locked,
    };
    let recs = vec![
        rec("done", JobState::Completed, false),
        rec("failed", JobState::Failed, false),
        rec("locked", JobState::Completed, true),
    ];

    let plan = super::plan_history_delete(&recs, "completed", &[]);
    assert!(
        plan[0].doomed && plan[0].may_remove_files,
        "the finished one goes"
    );
    assert!(
        !plan[1].doomed,
        "a failure stays: it is what retry works from"
    );
    assert!(
        !plan[2].doomed,
        "password-locked stays: only this row can unlock it"
    );

    // The neighbouring selectors keep their own meaning. `failed` is
    // the exact complement of what `completed` takes ONLY for the
    // unlocked records - the locked one is in neither sweep, which is
    // the point: it leaves by an explicit ✕, never by a bulk clear.
    let plan = super::plan_history_delete(&recs, "failed", &[]);
    assert_eq!(
        plan.iter().map(|p| p.doomed).collect::<Vec<_>>(),
        vec![false, true, false]
    );
    let plan = super::plan_history_delete(&recs, "all", &[]);
    assert!(
        plan.iter().all(|p| p.doomed),
        "`all` still means all of them"
    );
    // And an nzo_id that happens to read like a bulk word is still
    // matched by the id arm, not the word arm.
    let plan = super::plan_history_delete(&recs, "locked", &[]);
    assert_eq!(
        plan.iter().map(|p| p.doomed).collect::<Vec<_>>(),
        vec![false, false, true]
    );
}

/// The same bug end to end, against real files: delete the superseded
/// record with del_files=1 and the replacement's payload survives.
#[test]
fn a_published_over_directory_is_not_the_old_records_to_delete() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-published-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let canon = root.join("Movie.2024");
    std::fs::create_dir_all(&canon).unwrap();
    // The NEW job's verified payload, published over the canonical dir.
    std::fs::write(canon.join("movie.mkv"), b"the good copy").unwrap();

    let rec = |id: &str| super::DeleteRecord {
        nzo_id: id.to_string(),
        state: JobState::Completed,
        out_dir: canon.clone(),
        filed: false,
        locked: false,
    };
    let records = vec![rec("old"), rec("new")];
    let plan = super::plan_history_delete(&records, "old", &[]);
    for (r, p) in records.iter().zip(&plan) {
        if p.doomed && p.may_remove_files {
            super::remove_job_files(
                &r.out_dir,
                "Movie.2024",
                r.filed,
                &crate::smart::FiledTail::default(),
            );
        }
    }
    assert!(
        canon.join("movie.mkv").exists(),
        "the live job's payload survived"
    );

    // Once the new record is gone too, the directory is deletable.
    let last = vec![rec("new")];
    let plan = super::plan_history_delete(&last, "new", &[]);
    assert!(plan[0].may_remove_files);
    super::remove_job_files(
        &canon,
        "Movie.2024",
        false,
        &crate::smart::FiledTail::default(),
    );
    assert!(!canon.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// BUG (HIGH, 31 Jul queue soak): the slow-job watchdog's demote flag
/// landed on a job whose download had already drained (it was waiting
/// on the previous job's stalled tail), the fetch completed cleanly,
/// auto-rename moved its directory - and park's demote arm re-queued
/// the finished job, downloading all 34.5 GB a second time into the
/// renamed folder. A demotion only counts when its abort actually
/// failed the download.
#[test]
fn a_demote_flag_on_a_completed_job_does_not_requeue_it() {
    // The abort landed: the job failed, the re-queue is the design.
    assert!(demote_requeues(true, false, true));
    // The abort lost the race and the job COMPLETED: history, not queue.
    assert!(!demote_requeues(true, false, false));
    // A deleted job stays deleted, failed or not.
    assert!(!demote_requeues(true, true, true));
    assert!(!demote_requeues(true, true, false));
    // No demotion, no re-queue.
    assert!(!demote_requeues(false, false, true));
}

/// BUG (MEDIUM): SAB's DEFAULT_PRIORITY sentinel was stored and sorted
/// as a literal priority, so a job the user had explicitly marked Low
/// (-1) ran BEFORE every job the UI labelled Normal (-100).
#[test]
fn the_default_priority_sentinel_does_not_outrank_low() {
    let normal = enqueue_priority(SAB_DEFAULT_PRIORITY, false);
    let low = enqueue_priority(-1, false);
    // What every client already calls it...
    assert_eq!(priority_name(SAB_DEFAULT_PRIORITY), "Normal");
    assert_eq!(priority_name(normal), "Normal");
    // ...is now what pick_job orders it as. pick_job's key is
    // (!deferred, priority), so the raw comparison IS the queue order.
    assert!(normal > low, "a Normal job must run before a Low one");
    assert!(
        normal > enqueue_priority(-3, false),
        "and before a held duplicate"
    );
    assert!(enqueue_priority(1, false) > normal);
    assert!(enqueue_priority(2, false) > enqueue_priority(1, false));

    // Everything else is unchanged.
    assert_eq!(enqueue_priority(2, false), 2);
    assert_eq!(enqueue_priority(1, false), 1);
    assert_eq!(enqueue_priority(0, false), 0);
    assert_eq!(enqueue_priority(-1, false), -1);
    // SAB -2 is "add paused", not a priority: the job is Normal and
    // the caller sets `paused` from the request.
    assert_eq!(enqueue_priority(-2, false), 0);
    // A held M14f alternative outranks nothing, whatever was asked for.
    assert_eq!(enqueue_priority(SAB_DEFAULT_PRIORITY, true), -3);
    assert_eq!(enqueue_priority(2, true), -3);
}

/// BUG (HIGH): a TV-filed job's out_dir is the SHARED `Show/Season NN`
/// folder. `retry` used to re-queue it as-is, and because every
/// delete-with-files guard was re-derived from `state == Completed`,
/// the re-queue turned "leave the siblings alone" into
/// `remove_dir_all(SeasonDir)` - the whole season.
#[test]
fn retrying_a_filed_job_leaves_the_season_folder_alone() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-refile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let out_root = root.join("downloads");
    let season = out_root.join("tv").join("Some Show").join("Season 02");
    std::fs::create_dir_all(&season).unwrap();
    // This job's episode plus a sibling that must survive.
    std::fs::write(season.join("Some.Show.S02E03.mkv"), b"mine").unwrap();
    std::fs::write(season.join("Some.Show.S02E04.mkv"), b"sibling").unwrap();

    let mut j = job(json!({
        "nzo_id": "SABnzbd_nzo_nzbfast1",
        "name": "Some.Show.S02E03.1080p",
        "nzb_path": "/spool/x.nzb",
        "category": "tv",
        "state": "Completed",
        "out_dir": season.to_string_lossy(),
        "tv_sort": true,
    }));
    // A record written before `filed` existed still answers correctly.
    assert!(
        j.filed,
        "a completed tv_sort job in a Season NN dir is filed"
    );

    // What retry() does to a filed job.
    let (dir, replaces) = refile_out_dir(&out_root, &j.category, &j.name, &|_| DirClaim::Free);
    j.out_dir = dir;
    j.replaces = replaces;
    j.filed = false;
    j.state = JobState::Queued;

    assert_ne!(
        j.out_dir, season,
        "the retry must not download into the season folder"
    );
    assert!(j.out_dir.starts_with(out_root.join("tv")));

    // ...and the delete-with-files that used to take the season now
    // only touches the job's own (empty) directory.
    super::remove_job_files(
        &j.out_dir,
        &j.name,
        j.filed,
        &crate::smart::FiledTail::default(),
    );
    assert!(
        season.join("Some.Show.S02E04.mkv").exists(),
        "sibling episode survived"
    );
    assert!(season.exists(), "the season folder survived");
    let _ = std::fs::remove_dir_all(&root);
}

/// The other half: a job that IS still filed deletes only its own
/// episode, and an ordinary (unfiled) job still loses its whole
/// private directory.
#[test]
fn remove_job_files_reads_the_flag_not_the_state() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-rmfiles-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let season = root.join("Show").join("Season 01");
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(season.join("Show.S01E01.mkv"), b"a").unwrap();
    std::fs::write(season.join("Show.S01E02.mkv"), b"b").unwrap();
    super::remove_job_files(
        &season,
        "Show.S01E01.1080p",
        true,
        &crate::smart::FiledTail::default(),
    );
    assert!(season.exists());
    assert!(season.join("Show.S01E02.mkv").exists());

    let private = root.join("Movie.2020");
    std::fs::create_dir_all(&private).unwrap();
    std::fs::write(private.join("movie.mkv"), b"c").unwrap();
    super::remove_job_files(
        &private,
        "Movie.2020",
        false,
        &crate::smart::FiledTail::default(),
    );
    assert!(!private.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// UX §18 + the filed flag, together: a split payload's SOURCE side
/// obeys `Job::filed` exactly as its destination does.
///
/// `relocate_completed` moves a TV-filed job OUT of the shared
/// season folder (its own `same_place` comment says so), so a move
/// that fails part way records that shared folder as `move_split`.
/// The history delete now removes both halves - and it reads the
/// flag for both. Passing `false` for the source instead, on the
/// reasoning that a split source "is always a job-owned folder",
/// would hand a whole season of the user's episodes to
/// `remove_user_dir` on one episode's delete.
#[test]
fn a_split_source_that_is_a_season_folder_is_deleted_narrowly() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-splitfiled-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    // The SOURCE half of a split move: a shared season folder still
    // holding this episode and two siblings that are nothing to do
    // with the job being deleted.
    let season = root.join("Show").join("Season 01");
    std::fs::create_dir_all(&season).unwrap();
    for ep in ["Show.S01E01.mkv", "Show.S01E02.mkv", "Show.S01E03.mkv"] {
        std::fs::write(season.join(ep), b"x").unwrap();
    }
    super::remove_job_files(
        &season,
        "Show.S01E01.1080p",
        true,
        &crate::smart::FiledTail::default(),
    );
    assert!(
        season.join("Show.S01E02.mkv").exists() && season.join("Show.S01E03.mkv").exists(),
        "deleting one episode took its siblings from the split SOURCE folder"
    );
    assert!(
        season.exists(),
        "the shared season folder itself must survive"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A recoverable delete the Trash refuses must LEAVE the download and
/// hand the reason back, both arms of it.
///
/// The leaving-it-alone half landed in 70990f19; this pins the half
/// that makes it visible. `remove_job_files` used to answer a plain
/// bool, so the refusal reached a `warn!` and stopped there - while
/// the history or queue row went regardless, taking with it the only
/// place the user could see that download named. A caller cannot
/// narrate what it was never told.
#[test]
fn a_refused_delete_keeps_the_files_and_says_why() {
    let _serial = crate::smart::one_trash_test_at_a_time();
    let root = std::env::temp_dir().join(format!("nzbfast-refused-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let private = root.join("Movie.2020");
    let season = root.join("Show").join("Season 01");
    std::fs::create_dir_all(&private).unwrap();
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(private.join("movie.mkv"), b"c").unwrap();
    std::fs::write(season.join("Show - S01E01.mkv"), b"a").unwrap();

    let was = crate::smart::delete_to_trash();
    crate::smart::set_delete_to_trash(true);
    crate::smart::force_trash_unresponsive(true);
    let unfiled = super::remove_job_files(
        &private,
        "Movie.2020",
        false,
        &crate::smart::FiledTail::default(),
    );
    // The filed arm deletes per FILE inside the user's own library,
    // and refuses per file - it must report the same way.
    let filed = super::remove_job_files(
        &season,
        "Show.S01E01.1080p",
        true,
        &crate::smart::FiledTail::default(),
    );
    crate::smart::force_trash_unresponsive(false);
    crate::smart::set_delete_to_trash(was);

    for (out, path, what) in [
        (unfiled, private.join("movie.mkv"), "the private folder"),
        (filed, season.join("Show - S01E01.mkv"), "the filed episode"),
    ] {
        assert!(path.exists(), "{what} must survive a refused delete");
        match out {
            FilesGone::Kept(why) => assert!(
                !why.is_empty(),
                "{what}: the refusal has to carry a reason to show"
            ),
            FilesGone::Yes(_) => panic!("{what}: a refused delete reported success"),
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `filed` has to survive a restart: re-deriving it from the current
/// state is exactly the bug above.
#[test]
fn filed_round_trips_through_the_queue_file() {
    let mut j = job(json!({
        "nzo_id": "n1", "name": "Show.S01E01", "nzb_path": "/s/x.nzb",
        "state": "Completed", "out_dir": "/dl/tv/Show/Season 01", "tv_sort": true,
    }));
    assert!(j.filed);
    // Re-queued (a retry that, say, kept the folder) - the flag stays
    // whatever it was set to, and a restart must not "helpfully"
    // recompute it from Queued.
    j.state = JobState::Queued;
    let round = job(super::job_json(&j));
    assert!(round.filed, "filed survives a restart of a re-queued job");
    assert_eq!(round.out_dir, j.out_dir);
}

/// BUG (MEDIUM, data loss): the migration for records written before
/// `filed` existed used to also require `state == "Completed"`. The
/// pre-upgrade `retry` re-queued a filed job WITHOUT moving it off the
/// shared season folder and then persisted it, so a legacy record can
/// perfectly well read `Queued` while `out_dir` is still
/// `Show/Season NN`. Migrating that as `filed = false` hands the next
/// delete-with-files a `remove_dir_all` of the whole season - the exact
/// outcome the flag exists to prevent.
///
/// Deliberately end-to-end: it migrates a real legacy record and then
/// runs the real delete against a real season folder, rather than just
/// asserting on the shape predicate.
#[test]
fn a_legacy_requeued_record_still_migrates_as_filed() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-legacyfiled-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let season = root.join("tv").join("Some Show").join("Season 03");
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(season.join("Some.Show.S03E01.mkv"), b"mine").unwrap();
    std::fs::write(season.join("Some.Show.S03E02.mkv"), b"sibling").unwrap();

    // Exactly what a pre-`filed` daemon wrote after a retry: no
    // `filed` key at all, and a state of Queued.
    let j = job(json!({
        "nzo_id": "n1",
        "name": "Some.Show.S03E01.1080p",
        "nzb_path": "/spool/x.nzb",
        "category": "tv",
        "state": "Queued",
        "out_dir": season.to_string_lossy(),
        "tv_sort": true,
    }));
    assert!(
        matches!(j.state, JobState::Queued),
        "the legacy record is re-queued, not done"
    );
    assert!(
        j.filed,
        "a legacy tv_sort record in a Season NN dir migrates as filed"
    );

    // And the delete that used to take the season now spares it.
    super::remove_job_files(
        &j.out_dir,
        &j.name,
        j.filed,
        &crate::smart::FiledTail::default(),
    );
    assert!(season.exists(), "the season folder survived");
    assert!(
        season.join("Some.Show.S03E02.mkv").exists(),
        "sibling episode survived"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The naming settings a filed episode was named under, as the tests
/// below need them: bracketed tokens plus the group, which is the
/// shape a quality suffix actually takes on disk.
pub(super) fn filing_style() -> crate::wall::NameStyle {
    crate::wall::NameStyle {
        resolution: true,
        video_codec: true,
        audio_codec: false,
        source: true,
        group: true,
        year_parens: true,
        quality_brackets: true,
        extra_words: true,
    }
}

pub(super) fn suffix_of(stem: &str) -> String {
    crate::wall::quality_suffix(&crate::wall::parse_release(stem), &filing_style())
}

/// BUG (HIGH, data loss): turn auto-rename OFF after episodes have
/// been filed and the next watchlist upgrade deletes BOTH copies.
///
/// The suffix that keeps a filed delete release-specific used to be
/// recomputed from the LIVE rename settings at delete time. With
/// auto-rename off the recompute returns "", and an empty suffix is
/// not "no suffix on disk" but "the episode base plus any rename tail
/// at all" - so the delete of the superseded copy swept up the
/// replacement that had just landed beside it in the same season
/// folder. The slot still recorded the new release as owned, so
/// nothing ever re-grabbed it and the user was left with neither.
///
/// The suffix filing used is persisted instead. `legacy` here stands
/// in for `Daemon::job_suffix` on an install whose auto-rename is now
/// off: it returns exactly the empty string that did the damage.
#[test]
fn turning_auto_rename_off_does_not_delete_the_upgrade_that_replaced_an_episode() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-filedsfx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let season = root.join("tv").join("The Bear").join("Season 03");
    std::fs::create_dir_all(&season).unwrap();

    let old_stem = "The.Bear.S03E05.720p.HDTV-A";
    let new_stem = "The.Bear.S03E05.1080p.WEB.h264-GRP";
    let (old_sfx, new_sfx) = (suffix_of(old_stem), suffix_of(new_stem));
    assert!(
        !old_sfx.is_empty(),
        "auto-rename was on when this was filed"
    );
    assert_ne!(old_sfx, new_sfx, "the upgrade is a different quality");
    let old_file = format!("The Bear - S03E05{old_sfx}.mkv");
    let new_file = format!("The Bear - S03E05{new_sfx}.mkv");
    let sibling = "The Bear - S03E06 [1080p WEB h264]-GRP.mkv";
    for f in [old_file.as_str(), new_file.as_str(), sibling] {
        std::fs::write(season.join(f), b"x").unwrap();
    }

    // The superseded record, as it was filed and then persisted.
    let j = job(json!({
        "nzo_id": "n1",
        "name": old_stem,
        "nzb_path": "/spool/x.nzb",
        "category": "tv",
        "state": "Completed",
        "out_dir": season.to_string_lossy(),
        "tv_sort": true,
        "filed": true,
        "filed_suffix": old_sfx,
    }));

    // The upgrade landed; the watchlist drops what it supersedes -
    // with auto-rename since switched off, so the recompute is "".
    let tail = super::delete_tail(&j, String::new);
    super::remove_job_files(&j.out_dir, &j.name, j.filed, &tail);
    assert!(
        !season.join(&old_file).exists(),
        "the superseded copy is gone"
    );
    assert!(
        season.join(&new_file).exists(),
        "the replacement we just downloaded must survive its own upgrade"
    );
    assert!(
        season.join(sibling).exists(),
        "a sibling episode is never touched"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// An obfuscated post identified by an oracle is FILED under the
/// oracle's name - "a4f9c2e1" is not a show - so every later
/// operation on it has to look for the files that were really
/// written. Keyed on `Job::name`, the delete below finds nothing:
/// the episode is left in the season folder forever, and the "play"
/// route cannot find it either.
#[test]
fn a_job_filed_under_an_oracles_name_is_deleted_by_that_name() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-fbase-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let season = root.join("tv").join("The Bear").join("Season 03");
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(season.join("The Bear - S03E05 [1080p].mkv"), b"x").unwrap();
    std::fs::write(season.join("The Bear - S03E06 [1080p].mkv"), b"x").unwrap();

    let j = job(json!({
        "nzo_id": "n1",
        // What usenet called it, and what the *arr still matches on.
        "name": "a4f9c2e1b7d048395166cf20",
        "nzb_path": "/spool/x.nzb",
        "category": "tv",
        "state": "Completed",
        "out_dir": season.to_string_lossy(),
        "tv_sort": true,
        "filed": true,
        "filed_suffix": " [1080p]",
        // What it turned out to be, and what filing used.
        "identity_name": "The.Bear.S03E05.1080p.WEB.h264-GRP",
        "identity_src": "srrdb",
        "filed_base": "The.Bear.S03E05.1080p.WEB.h264-GRP",
    }));
    assert_eq!(super::filed_stem(&j), "The.Bear.S03E05.1080p.WEB.h264-GRP");

    let tail = super::delete_tail(&j, String::new);
    super::remove_job_files(&j.out_dir, super::filed_stem(&j), j.filed, &tail);
    assert!(
        !season.join("The Bear - S03E05 [1080p].mkv").exists(),
        "the filed episode was not found by the name it was filed under"
    );
    assert!(
        season.join("The Bear - S03E06 [1080p].mkv").exists(),
        "a sibling episode is never touched"
    );

    // A record with no filed_base - every record written before the
    // identity ladder, and every job whose own name was fine - still
    // answers with its own name.
    let plain = job(json!({
        "nzo_id": "n2",
        "name": "The.Bear.S03E06.1080p.WEB.h264-GRP",
        "nzb_path": "/spool/x.nzb",
        "state": "Completed",
        "out_dir": season.to_string_lossy(),
        "tv_sort": true,
        "filed": true,
    }));
    assert_eq!(
        super::filed_stem(&plain),
        "The.Bear.S03E06.1080p.WEB.h264-GRP"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The other direction: an install that has had auto-rename OFF all
/// along filed `{base}.{ext}` with no suffix, and its delete must
/// still work. Its stored suffix is an empty string, and there that
/// empty string is the truth rather than a wildcard.
///
/// Plus the legacy record that has no stored suffix at all: it falls
/// back to a recompute, never to a bare "".
#[test]
fn an_auto_rename_off_install_still_deletes_the_episode_it_filed() {
    let _steady = crate::smart::trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-nosfx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let season = root.join("tv").join("The Bear").join("Season 03");
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(season.join("The Bear - S03E05.mkv"), b"x").unwrap();
    std::fs::write(season.join("The Bear - S03E05.en.srt"), b"x").unwrap();
    std::fs::write(season.join("The Bear - S03E06.mkv"), b"x").unwrap();

    let rec = |extra: serde_json::Value| {
        let mut v = json!({
            "nzo_id": "n1",
            "name": "The.Bear.S03E05.720p.HDTV-A",
            "nzb_path": "/spool/x.nzb",
            "category": "tv",
            "state": "Completed",
            "out_dir": season.to_string_lossy(),
            "tv_sort": true,
            "filed": true,
        });
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        job(v)
    };

    // A record written before the suffix was persisted says "I don't
    // know", and the recompute answers for it - not a bare "".
    let legacy = rec(json!({}));
    assert!(
        legacy.filed_suffix.is_none(),
        "a legacy record has no stored suffix"
    );
    assert_eq!(
        super::delete_tail(&legacy, || " [1080p]".to_string()).suffix,
        " [1080p]",
        "a legacy record falls back to the recompute"
    );
    assert_eq!(
        super::delete_tail(&legacy, String::new).title,
        "",
        "and carries no episode title: it was filed before titles existed"
    );

    // The auto-rename-off install: "" is what filing really used.
    let j = rec(json!({"filed_suffix": ""}));
    assert_eq!(j.filed_suffix.as_deref(), Some(""));
    let tail = super::delete_tail(&j, || " [1080p]".to_string());
    assert_eq!(tail.suffix, "", "the stored suffix wins over any recompute");
    super::remove_job_files(&j.out_dir, &j.name, j.filed, &tail);
    assert!(
        !season.join("The Bear - S03E05.mkv").exists(),
        "our episode went"
    );
    assert!(
        !season.join("The Bear - S03E05.en.srt").exists(),
        "and its sidecar"
    );
    assert!(
        season.join("The Bear - S03E06.mkv").exists(),
        "the sibling stayed"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The suffix is history, so it has to survive a restart - including
/// the empty one, which `unwrap_or_default()` on the way back in
/// could not tell from "no record at all".
#[test]
fn the_filed_suffix_round_trips_through_the_queue_file() {
    let rt = |stored: Option<&str>| {
        let mut j = job(json!({
            "nzo_id": "n1", "name": "Show.S01E01.1080p.WEB-GRP",
            "nzb_path": "/s/x.nzb", "state": "Completed",
            "out_dir": "/dl/tv/Show/Season 01", "tv_sort": true, "filed": true,
        }));
        j.filed_suffix = stored.map(str::to_string);
        job(super::job_json(&j)).filed_suffix
    };
    assert_eq!(
        rt(Some(" [1080p WEB]-GRP")).as_deref(),
        Some(" [1080p WEB]-GRP")
    );
    assert_eq!(
        rt(Some("")).as_deref(),
        Some(""),
        "an empty suffix is a real answer"
    );
    assert_eq!(
        rt(None),
        None,
        "and \"never recorded\" stays distinct from it"
    );
}
