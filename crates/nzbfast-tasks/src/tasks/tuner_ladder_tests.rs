//! The auto connection-ladder's idleness rule: one predicate, asked in
//! the three places that must agree.
//!
//! A child module of `tuner.rs` rather than a sibling of it, so
//! [`super::link_idle`] stays private - the alternative was widening an
//! item for a test.
//!
//! **What was live until 1 Sep 2026.** The gate that starts a probe was
//! CHECK-ONCE: it passed, and then up to 60 s of STAT verification, four
//! minutes of climbing and two more minutes of re-measuring ran with
//! nothing re-asking. A job the scheduler picked up in that window was
//! measured by every remaining rung - the faked-low-knee shape, arriving
//! from our own side - and, worse, the ladder went on competing with
//! that very download for four more minutes of the user's account. The
//! result was already discarded (the guard after the re-measure has been
//! there all along); what nothing did was STOP.
//!
//! The predicate itself was also written out TWICE, at the gate and at
//! that guard, in a file with no tests at all - so a third asker was
//! going to be a third copy. These pin the one copy instead.
//!
//! **What is NOT covered, and why.** The three CALL SITES. Reaching any
//! of them means running `spawn_auto_connections`, which is an aux
//! thread on a 120 s settle plus a 60 s tick that then wants a provider
//! with a stale knee and a supply of STAT-verifiable articles - and the
//! per-rung one additionally wants the queue to go busy mid-climb, on a
//! timer. What that would assert is that a call written three lines from
//! the one below it happens; what would rot is the PREDICATE, which is
//! pinned here. The equivalent seam on the manual door IS reachable and
//! is pinned end to end by `daemon_connladder`.

use super::*;

use crate::testutil::test_daemon;

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-tuneridle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// The state is set AFTER the record is read, not through it:
/// `job_from_json` maps every live state to `Queued` on purpose, so a
/// job caught mid-download by a shutdown goes back through the
/// scheduler. Writing `"state": "Downloading"` into the json therefore
/// builds a QUEUED row, and this test would pass on a predicate that
/// looked at nothing at all.
fn job(id: &str, state: JobState) -> Arc<Mutex<Job>> {
    let v = serde_json::json!({
        "nzo_id": id, "name": format!("Rel.{id}"), "nzb_path": "/tmp/x.nzb",
        "out_dir": format!("/tmp/out/{id}"), "state": "Queued",
    });
    let mut j = crate::job_from_json(&v).expect("job_from_json");
    j.state = state;
    Arc::new(Mutex::new(j))
}

/// "Idle" is the LINK, not the queue, and it is one rule.
///
/// `Finishing` counts because the tail is still pulling articles, and
/// `scan_active` counts because an index scan or deepening pass pulls
/// headers over the SAME provider the ladder is measuring - the field
/// case behind the comment on the predicate: a 90k headers/s deepening
/// pull mid-probe reads every rung flat and fakes a knee at a fraction
/// of the true one.
///
/// A `Queued` row is deliberately NOT busy. Nothing of its is on the
/// wire, and treating it as busy would stop an install that keeps a
/// paused backlog from ever measuring a provider.
#[test]
fn idle_means_the_link_and_a_queued_row_is_not_busy() {
    let dir = tdir("pred");
    let d = test_daemon(&dir);
    assert!(link_idle(&d), "a fresh daemon with nothing running is idle");

    d.queue.lock_ok().push_back(job("q1", JobState::Queued));
    assert!(
        link_idle(&d),
        "a queued row has nothing on the wire, so it must not stop a probe"
    );

    for state in [JobState::Downloading, JobState::Finishing] {
        d.queue.lock_ok().clear();
        d.queue.lock_ok().push_back(job("j1", state));
        assert!(
            !link_idle(&d),
            "{state:?} is the link in use, so the ladder must not run"
        );
    }

    // An index scan alone, with an empty queue: still not idle. This is
    // the half a queue-only reading loses, and it is the one with a
    // field case behind it.
    d.queue.lock_ok().clear();
    assert!(link_idle(&d), "the queue is empty again");
    d.scan_active.store(true, Ordering::Relaxed);
    assert!(
        !link_idle(&d),
        "an index scan pulls headers over the same provider - not idle"
    );
    d.scan_active.store(false, Ordering::Relaxed);
    assert!(link_idle(&d), "and idle again once the scan stops");
}
