//! Truth-telling for the SAB facade's queue tail: what `slot_progress`
//! reports while jobs finish, what a hold publishes, and which script
//! name a job carries.
//!
//! Split out of `sabcompat.rs` for the size gate (TODO 106) - the parent
//! crossed its 3,000-line ceiling. Same module, its own file.

use super::{JobState, hold_json, sab_script_name, slot_progress};
use nzbkit::sync::MutexExt;

const GB: u64 = 1_000_000_000;

/// Two jobs are `Downloading` whenever one is finishing, and only one
/// of them owns the daemon's progress counters. The finishing one
/// reading them anyway is the wrong-bar bleed: job A sat at ~98%,
/// job B started and zeroed the counters, and A's row, the hero card
/// and the drawer all redrew A's bar as B's - 98%, then 0%, then
/// climbing through a download that was not A's.
#[test]
fn a_finishing_job_never_reads_the_next_download_s_counters() {
    // B owns the counters and has fetched 2 of its 40 GB.
    let b = slot_progress(
        JobState::Downloading,
        Some((2 * GB, 40 * GB)),
        false,
        40 * GB,
        0,
        0,
    );
    assert_eq!(b, (5, 38 * GB), "the owner reports the live counters");

    // A is in its tail: same state, no ownership, a phase word.
    let a = slot_progress(JobState::Downloading, None, true, 50 * GB, 0, 0);
    assert_eq!(
        a,
        (100, 0),
        "a finishing job reports its own bytes as all in - never the \
         other job's fraction"
    );
}

/// The single-job case, which ownership alone does not cover: nothing
/// starts behind the last job of a queue, so it still holds the
/// counters through its whole tail. Reported off them it read
/// "Downloading, 100%, 0 MB/s" for however long the repair and unpack
/// took - indistinguishable from a pool that had died.
#[test]
fn the_tail_phase_outranks_ownership() {
    let done = (10 * GB, 10 * GB);
    assert_eq!(
        slot_progress(JobState::Downloading, Some(done), true, 10 * GB, 0, 0),
        (100, 0),
        "still the owner, but verifying: the phase wins"
    );
    assert_eq!(
        slot_progress(JobState::Downloading, Some(done), false, 10 * GB, 0, 0),
        (100, 0),
        "and the numbers agree when it is still downloading"
    );
}

/// A job that has flipped to Downloading but has not yet claimed the
/// counters (the index-pause gate can hold that gap open). It has
/// fetched nothing; reading the previous job's counters to claim
/// otherwise is the same bug from the other side.
#[test]
fn a_job_that_has_not_claimed_the_counters_reports_nothing_fetched() {
    assert_eq!(
        slot_progress(JobState::Downloading, None, false, 8 * GB, 0, 0),
        (0, 8 * GB)
    );
}

/// A paused or re-queued job reports what its journal is holding.
/// Reporting 0% with the full size still to fetch is what has users
/// deleting a job that would resume in seconds - and it contradicts
/// the "nothing is re-downloaded" promise three copy sites make.
#[test]
fn a_paused_job_reports_what_is_already_on_disk() {
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 40 * GB, 25 * GB, 0),
        (62, 15 * GB)
    );
    // Never run: no record, no claim.
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 40 * GB, 0, 0),
        (0, 40 * GB)
    );
}

/// The idle-server early start banks bytes into the QUEUED job's out_dir
/// and journal, and until this arm read them the row said `Queued, 0%,
/// mbleft unchanged` for the whole of it - measured on the live daemon
/// on 29 Aug 2026, where a prefetch pulled 29.5 GB in 9.4 minutes and
/// the user reasonably concluded the queue was stuck.
#[test]
fn a_job_the_early_start_is_holding_reports_what_it_has_banked() {
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 40 * GB, 0, 10 * GB),
        (25, 30 * GB),
        "the banked bytes are bytes this queue no longer has to fetch"
    );
    // Nothing banked is the ordinary row, and it must not move.
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 40 * GB, 0, 0),
        (0, 40 * GB)
    );
}

/// The MAX and never the sum. A sidecar resumes from the journal, so its
/// counter already contains whatever an earlier run left behind - adding
/// the two puts a resumed early start past 100% of its own job, which is
/// the same double count the bar would show.
#[test]
fn banked_bytes_and_a_previous_run_s_bytes_are_the_same_bytes() {
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 40 * GB, 12 * GB, 30 * GB),
        (75, 10 * GB),
        "the early start's counter already includes the resumed bytes"
    );
    // And a stale sidecar counter never walks the bar BACKWARDS past
    // what a completed run recorded.
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 40 * GB, 30 * GB, GB),
        (75, 10 * GB)
    );
}

/// A row the early start is NOT holding gets 0 from the walk, but the
/// arm must also stay out of the way of a job on the wire: the sidecar
/// only ever runs a queued job, and a live row reports its own counters.
#[test]
fn a_live_row_ignores_banked_bytes() {
    assert_eq!(
        slot_progress(
            JobState::Downloading,
            Some((2 * GB, 40 * GB)),
            false,
            40 * GB,
            0,
            39 * GB,
        ),
        (5, 38 * GB),
        "the counters of the job actually on the wire win"
    );
}

/// The move to the destination, unchanged from before this bundle.
#[test]
fn a_completed_job_is_all_in() {
    assert_eq!(
        slot_progress(JobState::Completed, None, false, 40 * GB, 40 * GB, 0),
        (100, 0)
    );
}

/// Untrusted arithmetic: `total_bytes` comes from an NZB attribute
/// and `downloaded_bytes` from a previous run, so neither bounds the
/// other. A row must not divide by zero, and a bar must not overshoot
/// its own end.
#[test]
fn the_percentage_cannot_divide_by_zero_or_pass_100() {
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 0, 0, 0),
        (0, 0)
    );
    assert_eq!(
        slot_progress(JobState::Queued, None, false, 10, 999, 0),
        (100, 0),
        "more on disk than the NZB claims: clamped, not 9990%"
    );
    assert_eq!(
        slot_progress(JobState::Downloading, Some((0, 0)), false, 0, 0, 0),
        (0, 0)
    );
    // A hostile NZB can present a saturated total (nzb.rs sums the
    // segment attribute with saturating_add rather than wrapping),
    // and `done * 100` in u64 overflows long before it.
    assert_eq!(
        slot_progress(JobState::Queued, None, false, u64::MAX, u64::MAX, 0),
        (100, 0)
    );
    assert_eq!(
        slot_progress(
            JobState::Downloading,
            Some((u64::MAX / 2, u64::MAX)),
            false,
            0,
            0,
            0
        ),
        (49, u64::MAX - u64::MAX / 2)
    );
}

/// SAB's `script` field is the script that RUNS, not just an
/// explicit per-job override.
///
/// A job taking its category's script - or the global one - was
/// published to every SAB client as `"None"`, so a client's
/// "which jobs run my script" view was wrong for the ordinary case
/// (L4, 10 Aug sweep). Basename, because that is the vocabulary
/// `mode=get_scripts` and an add's `script=` both use.
#[test]
fn the_script_field_reports_the_script_that_will_run() {
    use std::path::PathBuf;
    let global = vec![PathBuf::from("/opt/nzb/scripts/global.sh")];
    let none: Vec<PathBuf> = Vec::new();
    // The ladder, top down.
    assert_eq!(
        sab_script_name("/opt/nzb/scripts/job.py", "cat.sh", &global),
        "job.py"
    );
    assert_eq!(sab_script_name("", "cat.sh", &global), "cat.sh");
    assert_eq!(sab_script_name("", "", &global), "global.sh");
    assert_eq!(sab_script_name("", "", &none), "None");
    // SAB's own null suppresses the whole ladder.
    assert_eq!(sab_script_name("None", "cat.sh", &global), "None");
    assert_eq!(sab_script_name("none", "", &global), "None");
    // §192: every rung may be a CHAIN, and the field has to name the
    // whole of what runs. A client rendering only the first link tells
    // the user the wrong thing about the other two.
    assert_eq!(
        sab_script_name("/opt/s/a.py,/opt/s/b.py", "cat.sh", &global),
        "a.py,b.py"
    );
    assert_eq!(
        sab_script_name("", "sort.sh;notify.sh", &global),
        "sort.sh,notify.sh"
    );
    assert_eq!(
        sab_script_name(
            "",
            "",
            &[PathBuf::from("/o/one.sh"), PathBuf::from("/o/two.sh")]
        ),
        "one.sh,two.sh"
    );
}

/// TODO §154: the no-servers hold carries no numbers, and must not
/// borrow the quota pair's names.
///
/// `hold_json`'s last arm is the quota one, so a new kind that fell
/// through it would publish `spent_gb: 0, cap_gb: 0` - and any
/// reader keyed on those fields (the dashboard's banner picks its
/// sentence by kind, but the payload is a documented shape other
/// clients read) would be told the user's quota was spent when they
/// simply have no server switched on.
#[test]
fn the_no_servers_hold_publishes_no_quota_pair() {
    let h = hold_json("noservers", 0.0, 0.0);
    assert_eq!(h["kind"], "noservers");
    assert_eq!(h["reason"], "noservers");
    // The pair stays, both zero: the {kind, a, b} shape is the
    // contract every hold answers in.
    assert_eq!(h["a"], 0.0);
    assert_eq!(h["b"], 0.0);
    assert!(h.get("spent_gb").is_none(), "not a quota hold: {h}");
    assert!(h.get("cap_gb").is_none(), "not a quota hold: {h}");
    assert!(h.get("free_gb").is_none(), "not a disk hold: {h}");
    assert!(h.get("finishing").is_none(), "not a postproc hold: {h}");

    // The arm it must not have fallen into still names its own.
    let q = hold_json("quota", 50.0, 50.0);
    assert_eq!(q["spent_gb"], 50.0);
    assert_eq!(q["cap_gb"], 50.0);
}

/// The phase word must never lapse between the last article and the
/// history row - and specifically not in the window where the ENGINE
/// has handed off but the lane has not yet marked the record
/// `Finishing`.
///
/// The engine's last act is `note_activity("finalizing")` (get/tail.rs)
/// and the record is still `JobState::Downloading` for the moment it
/// takes the postproc lane to take custody and set `Finishing`. Those
/// five daemon-owned tokens used to map to no phase at all, so a queue
/// poll landing in that window computed `phase = None` on a
/// `Downloading` row - and with the counters already released at
/// net-drain there was nothing to read but `downloaded_bytes`, which is
/// 0. The row rendered `Downloading 0%` between `Extracting 100%` and
/// `Moving 100%`: a finished download going backwards to nothing for
/// one poll. Observed under full-suite load, 20 Aug 2026.
///
/// This walks the whole ladder token by token and pins the transitions
/// as token-TO-TOKEN rather than leaving the gap to a load-sensitive
/// end-to-end race.
#[test]
fn the_phase_word_never_lapses_across_the_finalize_hand_off() {
    let dir = std::env::temp_dir().join(format!("nzbfast-tailladder-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    // Every stage a job passes through from the disk-unpack ladder to
    // the history row, in order: the engine's own words
    // (get/tail.rs, get/settle.rs) then the daemon's
    // (`Daemon::note_tail_stage`). The state each is seen in is the
    // point: `Downloading` right through the hand-off, because the
    // lane only writes `Finishing` once it has taken custody.
    let ladder: &[(&str, JobState)] = &[
        ("verifying", JobState::Downloading),
        ("repairing", JobState::Downloading),
        ("extracting", JobState::Downloading),
        // The hand-off. Still Downloading - this is the window.
        ("finalizing", JobState::Downloading),
        ("finalizing", JobState::Finishing),
        ("unlocking", JobState::Finishing),
        ("identifying", JobState::Finishing),
        ("renaming", JobState::Finishing),
        ("scripting", JobState::Finishing),
    ];
    for (tok, state) in ladder {
        d.hub
            .activity
            .lock_ok()
            .insert("nzo-ladder".to_string(), tok);
        let phase = d.tail_phase("nzo-ladder");
        assert!(
            phase.is_some(),
            "{tok} left the row with no phase at all - a {state:?} row with no phase \
             reports its downloaded_bytes, which is 0 once the counters are released"
        );
        // Composed exactly as the queue walk composes it: no live
        // counters (released at net-drain), the phase as the tail flag.
        assert_eq!(
            slot_progress(*state, None, phase.is_some(), 40 * GB, 0, 0),
            (100, 0),
            "{tok}: the bytes are all in and the row must say so"
        );
    }

    // ...and the vocabulary the *arrs read is unchanged by that: the
    // daemon's stages are all SAB's `Moving`, which is what a
    // `Finishing` row reported before any of them were mapped.
    for tok in [
        "finalizing",
        "unlocking",
        "identifying",
        "renaming",
        "scripting",
    ] {
        d.hub
            .activity
            .lock_ok()
            .insert("nzo-ladder".to_string(), tok);
        assert_eq!(d.tail_phase("nzo-ladder"), Some("Moving"), "{tok}");
    }

    // The other side of the same coin: a word written BEFORE the
    // network is not a tail, and a row carrying it reports nothing
    // fetched rather than all-in.
    d.hub
        .activity
        .lock_ok()
        .insert("nzo-pre".to_string(), "preflight");
    let pre = d.tail_phase("nzo-pre");
    assert_eq!(pre, None, "preflight is not a post-network stage");
    assert_eq!(
        slot_progress(JobState::Downloading, None, pre.is_some(), 40 * GB, 0, 0),
        (0, 40 * GB)
    );

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}
