//! A held duplicate that is the SAME POST as its original never
//! downloads beside it (21 Sep 2026).
//!
//! The incident: a byte-different NZB of one 63.75 GiB post was queued
//! behind the first and held, as the duplicate ladder is meant to. The
//! held row's escape hatch - the dashboard's "download anyway", which is
//! `priority=2` plus a resume - released it, and the runner then started
//! it beside its own original and fetched a full second copy of the same
//! articles. Nothing in the daemon's log said why: the release is a plain
//! field write.
//!
//! What is pinned here is the RULE, not the click. A row whose
//! `held_for` original is still delivering the post, and which declares
//! (nearly) the same articles, is removed at the two doors where a queued
//! row becomes a download - the runner's pick and the prefetch picker -
//! and at the moment its original completes. Everything the rule must
//! leave alone is pinned beside it: a different post of the same title
//! (a real alternative), a twin lifted after its original is already in
//! history (the re-download escape `daemon_samepost` leg A measures), a
//! twin behind an original the user paused, and a twin that is still HELD.
//!
//! A child of daemon_tests, in its own file for the size gate; the
//! module name matches the file name so size-gate.py reads it as test
//! code. `use super::*` brings `with_daemon` and the harness.
//!
//! The second half of the file is the ACTIVE twin (21 Sep 2026, claim
//! `twin-on-wire-stops-21sep`): a released copy that is already
//! TRANSFERRING - on the hub, draining behind a successor, or running as
//! the prefetch - when its original completes. It is wound down through
//! `suspend_matching`, the same machinery a per-job pause uses, and then
//! removed with its spool copy and partial payload.

use super::*;

/// An NZB declaring exactly `ids`.
fn nzb_of(ids: &[&str]) -> String {
    let segs: String = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            format!(
                "<segment bytes=\"1000\" number=\"{}\">{id}</segment>",
                i + 1
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"0\" subject=\"&quot;m.bin&quot; yEnc (1/{})\">\
         <groups><group>g</group></groups><segments>{segs}</segments></file></nzb>",
        ids.len()
    )
}

fn add(d: &Arc<Daemon>, xml: &str, name: &str) -> String {
    d.enqueue(xml.as_bytes(), name, "", -100, None, None, "test", false)
        .map(|e| e.nzo_id)
        .expect("enqueue")
}

/// What the dashboard's "download anyway" leaves on a held row: the
/// priority raised to Force and the pause lifted, `held_for` untouched.
fn force(d: &Arc<Daemon>, id: &str) {
    let j = d.queue_job(id).expect("row is queued");
    let mut g = j.lock_ok();
    g.priority = 2;
    g.paused = false;
}

fn queued(d: &Arc<Daemon>, id: &str) -> bool {
    d.queue_job(id).is_some()
}

/// Two grabs of one post under different obfuscated names, the second
/// held against the first. Returns `(original, twin)`.
fn twin_pair(d: &Arc<Daemon>, ids: &[&str]) -> (String, String) {
    let post = nzb_of(ids);
    let orig = add(d, &post, "a9f3c2b1d4e5.nzb");
    let twin = add(d, &post, "0b7e9d1aa2c8.nzb");
    assert!(
        d.held_as_duplicate(&twin),
        "the twin was not held to begin with"
    );
    assert_eq!(d.queue_job(&twin).unwrap().lock_ok().held_for, orig);
    (orig, twin)
}

/// The incident, at the runner's pick. The Force outranks the original,
/// so before the door `pick_job` handed the runner the TWIN first - and
/// the runner started a full second copy of the post.
#[test]
fn a_released_twin_is_not_started_beside_its_live_original() {
    with_daemon("twin-pick", |d| {
        let (orig, twin) = twin_pair(d, &["tw1@x", "tw2@x", "tw3@x"]);
        let twin_spool = d.queue_job(&twin).unwrap().lock_ok().nzb_path.clone();
        assert!(twin_spool.exists(), "the twin has a spool copy to drop");
        force(d, &twin);

        assert_eq!(
            d.pick_job(false).unwrap().lock_ok().nzo_id,
            twin,
            "the premise: a forced twin outranks its original in the raw pick"
        );
        let picked = d
            .pick_job_for_start(false)
            .expect("the original is still runnable");
        assert_eq!(
            picked.lock_ok().nzo_id,
            orig,
            "the runner started the twin of a post it is already fetching"
        );
        assert!(!queued(d, &twin), "the twin is still in the queue");
        assert!(
            !twin_spool.exists(),
            "the twin's spool copy would be re-adopted"
        );
        assert!(queued(d, &orig), "the original must be untouched");
    });
}

/// The prefetch picker's door is the same function, so it is enough to
/// prove the function answers `true` and removes the row; this pins the
/// direct call the sidecar makes, including that it refuses to touch a
/// row that is not a twin at all.
#[test]
fn the_sidecar_door_removes_a_twin_and_leaves_an_ordinary_row_alone() {
    with_daemon("twin-door", |d| {
        let (orig, twin) = twin_pair(d, &["sd1@x", "sd2@x", "sd3@x"]);
        force(d, &twin);
        let stranger = add(d, &nzb_of(&["st1@x", "st2@x"]), "c4d5e6f7a8b9.nzb");

        let s = d.queue_job(&stranger).unwrap();
        assert!(!d.refuse_twin_start(&s), "an unrelated row is not a twin");
        let o = d.queue_job(&orig).unwrap();
        assert!(!d.refuse_twin_start(&o), "an original is not a twin");
        let t = d.queue_job(&twin).unwrap();
        assert!(d.refuse_twin_start(&t));
        assert!(!queued(d, &twin));
        assert!(queued(d, &orig) && queued(d, &stranger));
    });
}

/// The other half of "download anyway", and the reason the rule asks
/// about the POST and not the title: a different release of the same
/// film is a real alternative, and forcing one is an informed choice to
/// pay for a second post. It must still start.
#[test]
fn a_released_alternative_of_a_different_post_still_starts() {
    with_daemon("twin-different-post", |d| {
        let orig = add(
            d,
            &nzb_of(&["dp1@x", "dp2@x", "dp3@x"]),
            "Big.Movie.2003.2160p.UHD.BluRay.REMUX-AAA.nzb",
        );
        let alt = add(
            d,
            &nzb_of(&["dq1@x", "dq2@x", "dq3@x"]),
            "Big.Movie.2003.1080p.BluRay.x264-BBB.nzb",
        );
        assert!(d.held_as_duplicate(&alt), "same title, so held by name");
        assert_eq!(d.queue_job(&alt).unwrap().lock_ok().held_for, orig);
        force(d, &alt);

        let picked = d.pick_job_for_start(false).expect("something is runnable");
        assert_eq!(
            picked.lock_ok().nzo_id,
            alt,
            "a different release of the same film was refused as a twin"
        );
        assert!(queued(d, &alt) && queued(d, &orig));
    });
}

/// The re-download escape. Once the original is in history the twin is
/// the user fetching a payload they may have deleted from disk, which is
/// what `daemon_samepost` leg A measures end to end and what "download
/// anyway" is documented to do.
#[test]
fn a_twin_lifted_after_its_original_completed_may_still_download() {
    with_daemon("twin-after-complete", |d| {
        let (orig, twin) = twin_pair(d, &["ac1@x", "ac2@x", "ac3@x"]);
        // The original finished and left for history.
        let o = d.queue_job(&orig).unwrap();
        o.lock_ok().state = JobState::Completed;
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != orig);
        d.history.lock_ok().push(o);
        force(d, &twin);

        let picked = d.pick_job_for_start(false).expect("the twin is runnable");
        assert_eq!(picked.lock_ok().nzo_id, twin);
        assert!(queued(d, &twin), "the re-download escape was closed");
    });
}

/// Forcing a twin past an original the USER paused is a swap they asked
/// for; refusing it would leave nothing downloading at all.
#[test]
fn a_twin_forced_past_a_paused_original_may_start() {
    with_daemon("twin-paused-orig", |d| {
        let (orig, twin) = twin_pair(d, &["po1@x", "po2@x", "po3@x"]);
        d.queue_job(&orig).unwrap().lock_ok().paused = true;
        force(d, &twin);

        let picked = d.pick_job_for_start(false).expect("the twin is runnable");
        assert_eq!(picked.lock_ok().nzo_id, twin);
        assert!(queued(d, &twin));
    });
}

/// A twin that was never released is not touched by the door: it is
/// paused, `pick_job` never offers it, and it costs nothing.
#[test]
fn a_twin_that_is_still_held_is_never_picked_and_never_removed() {
    with_daemon("twin-held", |d| {
        let (orig, twin) = twin_pair(d, &["hd1@x", "hd2@x", "hd3@x"]);
        let picked = d.pick_job_for_start(false).expect("the original runs");
        assert_eq!(picked.lock_ok().nzo_id, orig);
        assert!(queued(d, &twin), "a held twin is a hold, not a drop");
        assert!(d.held_as_duplicate(&twin));
    });
}

/// The hole the start door alone leaves. The runner starts the next row
/// while the original is still in its post-network tail, so the door
/// sees a live original - but a twin the runner reaches only after the
/// original has parked finds none, and would download in full. Dropped
/// when the original completes instead.
///
/// A twin still HELD survives (the escape above), a different post
/// survives (a real alternative), and so does a spare-origin row, which
/// is `drop_spares_for`'s and not this rule's.
#[test]
fn a_released_twin_still_queued_when_its_original_completes_is_dropped() {
    with_daemon("twin-complete", |d| {
        let post = nzb_of(&["cp1@x", "cp2@x", "cp3@x"]);
        let orig = add(d, &post, "a9f3c2b1d4e5.nzb");
        let released = add(d, &post, "0b7e9d1aa2c8.nzb");
        let held = add(d, &post, "1c8f0e2bb3d9.nzb");
        let other = add(d, &nzb_of(&["cq1@x", "cq2@x", "cq3@x"]), "2d9a1f3cc4e0.nzb");
        assert!(d.held_as_duplicate(&released) && d.held_as_duplicate(&held));
        force(d, &released);
        // A DIFFERENT post that happens to name the same original, as an
        // alternative the user released on purpose.
        {
            let j = d.queue_job(&other).unwrap();
            let mut g = j.lock_ok();
            g.held_for = orig.clone();
            g.priority = 2;
            g.paused = false;
        }

        // The original completes and parks.
        let o = d.queue_job(&orig).unwrap();
        {
            let mut g = o.lock_ok();
            g.state = JobState::Completed;
            g.finished_unix = Some(1);
        }
        d.park_gen(o, None);

        assert!(
            !queued(d, &released),
            "a released copy of the post the original just delivered is still queued"
        );
        assert!(queued(d, &held), "a twin still held must survive");
        assert!(queued(d, &other), "a different post is a real alternative");
        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == orig),
            "the original itself was filed"
        );
    });
}

/// A FAILED original is the case a twin can never help - it fails
/// identically - and it is also the case the ladder already owns
/// (promotion refuses a same-post candidate). The completion sweep must
/// not run on a failure and take a row the ladder is still deciding on.
#[test]
fn a_failed_original_does_not_sweep_its_twins() {
    with_daemon("twin-failed", |d| {
        let (orig, twin) = twin_pair(d, &["fl1@x", "fl2@x", "fl3@x"]);
        force(d, &twin);
        let o = d.queue_job(&orig).unwrap();
        {
            let mut g = o.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "not enough blocks".into();
            g.finished_unix = Some(1);
        }
        d.park_gen(o, None);
        assert!(
            queued(d, &twin),
            "the completion sweep ran on a failed original"
        );
    });
}

// -- the twin that is already on the wire -----------------------------------

/// Poll `cond` for up to ten seconds. The wind-down is a real thread on
/// a 250 ms cadence, so the tests wait on its OUTCOME and not a sleep.
fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let t0 = std::time::Instant::now();
    while !cond() {
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(10),
            "timed out waiting for: {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Put `id` on the hub as the download in progress, with the hard-abort
/// flag a real pipeline installs. The flag is how a test tells the
/// graceful wind-down (untouched) from the hard abort (set): the
/// `QueueControl` beside it is unattached here and answers nothing.
fn on_the_hub(d: &Arc<Daemon>, id: &str) -> Arc<std::sync::atomic::AtomicBool> {
    d.queue_job(id).unwrap().lock_ok().state = JobState::Downloading;
    *d.active_stream.lock_ok() = Some(id.to_string());
    let abort = Arc::new(std::sync::atomic::AtomicBool::new(false));
    *d.hub.abort.lock_ok() = Some(abort.clone());
    abort
}

/// The original finishes and parks, as the runner's lane does it.
fn complete(d: &Arc<Daemon>, orig: &str) {
    let o = d.queue_job(orig).unwrap();
    {
        let mut g = o.lock_ok();
        g.state = JobState::Completed;
        g.finished_unix = Some(1);
    }
    d.park_gen(o, None);
}

/// What `postproc::run_tail` does with a suspended job whose fetch was
/// wound down: back to the queue, journal kept. Waits for the wind-down
/// to MARK the job first, so a wind-down that never comes fails here
/// rather than passing on the strength of this stand-in alone.
fn tail_requeues(d: &Arc<Daemon>, id: &str) {
    let j = d.queue_job(id).unwrap();
    wait_for("the twin to be marked suspended", || j.lock_ok().suspended);
    let mut g = j.lock_ok();
    g.state = JobState::Queued;
    g.suspended = false;
}

/// A partial payload for the twin, as the wire leaves one.
fn partial_payload(d: &Arc<Daemon>, id: &str) -> std::path::PathBuf {
    let dir = d.queue_job(id).unwrap().lock_ok().out_dir.clone();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("part.bin"), b"half a copy").unwrap();
    dir
}

/// THE GAP. The twin was on the hub when its original completed, so
/// neither the start door (it had already started) nor the completion
/// sweep (it is not `Queued`) saw it, and it went on to download the
/// whole second copy - tens of GB in the incident's shape.
///
/// Wound down GRACEFULLY (in-flight articles finish and journal - the
/// hard abort is only the ten-second escalation), marked so the tail
/// parks it back rather than filing a failure, paused so nothing starts
/// it again, and then removed with its spool copy and its partial files.
#[test]
fn a_twin_on_the_wire_is_wound_down_and_removed_when_its_original_completes() {
    with_daemon("twin-wire", |d| {
        let (orig, twin) = twin_pair(d, &["wr1@x", "wr2@x", "wr3@x"]);
        force(d, &twin);
        let spool = d.queue_job(&twin).unwrap().lock_ok().nzb_path.clone();
        let payload = partial_payload(d, &twin);
        let abort = on_the_hub(d, &twin);

        complete(d, &orig);

        let t = d
            .queue_job(&twin)
            .expect("still winding down, not yet gone");
        {
            let g = t.lock_ok();
            assert!(g.suspended, "the transfer was not wound down");
            assert!(g.paused, "nothing may start the twin again");
        }
        assert!(
            !abort.load(Ordering::Relaxed),
            "the wind-down must be the graceful drain, not the hard abort"
        );

        tail_requeues(d, &twin);
        // The row leaves the queue first and its files go a moment later
        // (the slow half runs with no lock held), so wait on the files.
        wait_for("the twin's files to be removed", || {
            !queued(d, &twin) && !spool.exists() && !payload.exists()
        });
        assert!(
            d.history
                .lock_ok()
                .iter()
                .all(|j| j.lock_ok().nzo_id != twin),
            "a removed twin is not a history row"
        );
        let said = d
            .recent_events(50)
            .into_iter()
            .find(|e| e.kind == "queue" && e.detail.contains(&twin))
            .expect("the removal left no note in the event ring");
        assert!(
            said.detail.contains(&orig),
            "the note must name both jobs: {}",
            said.detail
        );
    });
}

/// The drain slot. The twin handed the hub to its successor and is
/// still on the wire behind it, so `owns_hub` answers for the SUCCESSOR
/// and the twin's stop handles are only in the drain slot. The successor
/// is somebody's honest download and must come out untouched.
#[test]
fn a_twin_draining_behind_a_successor_is_stopped_and_the_successor_is_not() {
    with_daemon("twin-drain", |d| {
        let (orig, twin) = twin_pair(d, &["dr1@x", "dr2@x", "dr3@x"]);
        force(d, &twin);
        let succ = add(d, &nzb_of(&["ds1@x", "ds2@x"]), "e5f6a7b8c9d0.nzb");
        d.queue_job(&twin).unwrap().lock_ok().state = JobState::Downloading;
        let hub_abort = on_the_hub(d, &succ);
        let drain_abort = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.drain_dl.lock_ok() = Some(crate::wire::DrainSlot {
            nzo_id: twin.clone(),
            t_start: Instant::now(),
            progress: Arc::new(AtomicU64::new(0)),
            counters: Arc::new(crate::streamhub::FetchCounters::default()),
            total: 0,
            resume_seeded: 0,
            pool_live: None,
            abort: Some(drain_abort.clone()),
            queue_ctl: Some(Arc::new(nzbkit::pool::QueueControl::default())),
        });

        complete(d, &orig);

        assert!(d.queue_job(&twin).unwrap().lock_ok().suspended);
        let s = d.queue_job(&succ).unwrap();
        {
            let g = s.lock_ok();
            assert!(
                !g.suspended && !g.paused,
                "the successor was wound down too"
            );
        }
        assert!(
            !hub_abort.load(Ordering::Relaxed),
            "the successor's hub was signalled"
        );
        assert!(
            !drain_abort.load(Ordering::Relaxed),
            "the drainer's wind-down must be graceful"
        );

        tail_requeues(d, &twin);
        wait_for("the twin to be removed", || !queued(d, &twin));
        assert!(queued(d, &succ), "the successor left the queue");
        assert!(!hub_abort.load(Ordering::Relaxed));
        *d.drain_dl.lock_ok() = None;
    });
}

/// The prefetch (early-start) slot: a twin that is still `Queued` as far
/// as the record goes, with bytes landing on a hub of its own. Signalled
/// through the sidecar's own abort, and removed only once it has left
/// the slot - `drop_twin`'s refusal of a row a sidecar is running is
/// what keeps the removal from racing the transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prefetching_twin_is_stopped_and_removed_when_its_original_completes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-twin-sidecar-{}", std::process::id()));
    let _scratch = crate::testscratch::ScratchDir::attach(&dir);
    let d = crate::testutil::test_daemon(&dir);
    let (orig, twin) = twin_pair(&d, &["sc1@x", "sc2@x", "sc3@x"]);
    force(&d, &twin);
    let payload = partial_payload(&d, &twin);
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    *d.sidecar.lock_ok() = Some(crate::sidecar::Sidecar {
        nzo_id: twin.clone(),
        hub: Arc::new(crate::StreamHub::default()),
        progress: Arc::new(AtomicU64::new(0)),
        rate_win: Mutex::new(VecDeque::new()),
        cancelled: cancelled.clone(),
        task: tokio::spawn(async {}),
        borrowed: false,
    });

    let dd = d.clone();
    let o = orig.clone();
    tokio::task::spawn_blocking(move || complete(&dd, &o))
        .await
        .unwrap();

    assert!(
        cancelled.load(Ordering::Relaxed),
        "the prefetch of a twin whose original is done was left running"
    );
    assert!(queued(&d, &twin), "removed while the sidecar still owns it");
    // The sidecar's exit path: the slot empties, the record stays Queued.
    *d.sidecar.lock_ok() = None;
    let dd = d.clone();
    let t = twin.clone();
    let p = payload.clone();
    tokio::task::spawn_blocking(move || {
        wait_for("the twin and its partial to be removed", || {
            !queued(&dd, &t) && !p.exists()
        })
    })
    .await
    .unwrap();
}

/// A DIFFERENT post on the wire, released on purpose, is a real
/// alternative and keeps running when the original completes.
#[test]
fn a_different_post_on_the_wire_keeps_running_when_the_original_completes() {
    with_daemon("twin-wire-different", |d| {
        let orig = add(
            d,
            &nzb_of(&["wd1@x", "wd2@x", "wd3@x"]),
            "Big.Movie.2003.2160p.UHD.BluRay.REMUX-AAA.nzb",
        );
        let alt = add(
            d,
            &nzb_of(&["we1@x", "we2@x", "we3@x"]),
            "Big.Movie.2003.1080p.BluRay.x264-BBB.nzb",
        );
        assert!(d.held_as_duplicate(&alt));
        force(d, &alt);
        let abort = on_the_hub(d, &alt);

        complete(d, &orig);

        let j = d.queue_job(&alt).expect("the alternative was removed");
        assert!(
            !j.lock_ok().suspended,
            "a genuine alternative was wound down"
        );
        assert!(!abort.load(Ordering::Relaxed));
    });
}

/// A twin already past its network phase (verifying, repairing,
/// extracting) has nothing left to stop: the wire is idle, and winding
/// it down would throw away a finished download for no saving.
#[test]
fn a_twin_already_in_its_tail_is_left_to_finish() {
    with_daemon("twin-wire-tail", |d| {
        let (orig, twin) = twin_pair(d, &["tl1@x", "tl2@x", "tl3@x"]);
        force(d, &twin);
        let abort = on_the_hub(d, &twin);
        d.hub.activity.lock_ok().insert(twin.clone(), "extracting");

        complete(d, &orig);

        let t = d.queue_job(&twin).expect("a finishing twin was removed");
        assert!(!t.lock_ok().suspended && !t.lock_ok().paused);
        assert!(!abort.load(Ordering::Relaxed));
    });
}

/// A twin the user has already paused is not transferring (a paused
/// row that is still `Downloading` is mid-wind-down by the user's own
/// pause) and its release is the user's call: left alone.
#[test]
fn a_twin_the_user_already_paused_is_left_alone() {
    with_daemon("twin-wire-userpaused", |d| {
        let (orig, twin) = twin_pair(d, &["up1@x", "up2@x", "up3@x"]);
        force(d, &twin);
        let abort = on_the_hub(d, &twin);
        {
            let j = d.queue_job(&twin).unwrap();
            let mut g = j.lock_ok();
            g.paused = true;
            g.suspended = true;
        }

        complete(d, &orig);
        std::thread::sleep(std::time::Duration::from_millis(600));

        assert!(queued(d, &twin), "a user-paused twin was removed");
        assert!(!abort.load(Ordering::Relaxed), "the hub was signalled");
    });
}

/// A FAILED original leaves an active twin running: a twin cannot help
/// a post that failed (it fails identically), but that verdict and what
/// to do about it belong to the ladder, not to this sweep.
#[test]
fn a_failed_original_does_not_wind_down_an_active_twin() {
    with_daemon("twin-wire-failed", |d| {
        let (orig, twin) = twin_pair(d, &["ff1@x", "ff2@x", "ff3@x"]);
        force(d, &twin);
        let abort = on_the_hub(d, &twin);
        let o = d.queue_job(&orig).unwrap();
        {
            let mut g = o.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "not enough blocks".into();
            g.finished_unix = Some(1);
        }
        d.park_gen(o, None);

        let t = d.queue_job(&twin).expect("the twin was removed");
        assert!(!t.lock_ok().suspended && !t.lock_ok().paused);
        assert!(!abort.load(Ordering::Relaxed));
    });
}
