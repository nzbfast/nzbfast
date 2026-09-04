//! §129 3e. The NO-FALSE-POSITIVE cases are the point of this file.
//!
//! The stall watchdog once aborted a healthy run off a misread rate
//! window, and the fix for that class is not a better threshold - it is
//! a judge whose "must not fire" cases are pinned as hard as its "must
//! fire" one. So: one trip test, and six ways of proving the judge stays
//! quiet (fast-but-parked, burst, repeating sawtooth, idle-diluted,
//! wholly-idle, network-slow, degraded-but-delivering, too-few-samples,
//! latch), the fresh-window-after-rearm rule, the tick gating, and the
//! probe: hysteresis, cleanup, and a payload that cannot compress away.

use super::*;
use crate::job::JobState;
use std::sync::Mutex;

/// House temp-dir pattern, with Drop cleanup so a failing assertion
/// still removes the directory. Named per test, since the process id
/// alone does not separate two tests in one binary.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(name: &str) -> TmpDir {
        let p =
            std::env::temp_dir().join(format!("nzbfast-slowstore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A queued-then-running job record, built the way a restart builds one
/// so the test does not have to spell out forty fields.
fn mkjob(nzo_id: &str, out_dir: &Path) -> Arc<Mutex<crate::job::Job>> {
    let mut j = crate::job_from_json(&json!({
        "nzo_id": nzo_id,
        "name": "Some.Release.2026.1080p",
        "nzb_path": "/spool/slow.nzb",
        "out_dir": out_dir.to_string_lossy(),
        "state": "Queued",
    }))
    .expect("job_from_json");
    j.state = JobState::Downloading;
    Arc::new(Mutex::new(j))
}

const SPAN: u64 = 2_000;
const CONNS: u64 = 20;
/// The rate a healthy run of this fixture moves at.
const FAST: f64 = 100e6;

/// A short-window tune so a test can cover minutes of evidence in a few
/// hundred synthetic ticks. Ratios stay at the shipping defaults - those
/// are what the cases below are actually about.
fn tune() -> Tune {
    Tune {
        window_secs: 60,
        min_samples: 10,
        norm_secs: 300,
        ..Tune::default()
    }
}

/// Drives a judge over a synthetic series. `at` is the fake clock; every
/// step is one `TICK`.
struct Rig {
    judge: Judge,
    at: u64,
    /// Every evidence the judge produced, so a test can assert on the
    /// count as well as the content.
    trips: Vec<Evidence>,
}

impl Rig {
    fn new() -> Rig {
        Rig {
            judge: Judge::new(tune()),
            at: 1_000_000,
            trips: Vec::new(),
        }
    }

    /// `secs` of ticks with this write-side parking fraction and this
    /// goodput. Returns whether anything tripped during the stretch.
    fn run(&mut self, secs: u64, blocked_frac: f64, bps: f64) -> bool {
        let before = self.trips.len();
        for _ in 0..(secs * 1000 / SPAN) {
            self.at += SPAN;
            let worker_ms = SPAN * CONNS;
            let s = Sample {
                at_ms: self.at,
                span_ms: SPAN,
                worker_ms,
                blocked_ms: (worker_ms as f64 * blocked_frac) as u64,
                bytes: (bps * (SPAN as f64 / 1000.0)) as u64,
            };
            if let Some(ev) = self.judge.observe(s) {
                self.trips.push(ev);
            }
        }
        self.trips.len() > before
    }

    /// `secs` with nothing moving and nothing parked - the pipeline
    /// between jobs, or a provider that has gone quiet.
    fn idle(&mut self, secs: u64) -> bool {
        self.run(secs, 0.0, 0.0)
    }

    /// A healthy fast download: the fetch->decode channel is FULL most
    /// of the time (the network outruns decode, which is normal and is
    /// exactly what makes blocked_ms alone useless as evidence) while
    /// the bytes keep coming.
    fn healthy(&mut self, secs: u64) -> bool {
        self.run(secs, 0.9, FAST)
    }

    /// The dying enclosure: everything parked on the write side, goodput
    /// down to a trickle.
    fn stalled(&mut self, secs: u64) -> bool {
        self.run(secs, 0.95, FAST / 100.0)
    }
}

// ---------------------------------------------------------------- trip

#[test]
fn a_dying_enclosure_trips_after_a_full_window() {
    let mut r = Rig::new();
    assert!(!r.healthy(120), "a healthy run must never nominate");
    // Half a window of stalling is not a verdict yet.
    assert!(!r.stalled(30), "half a window is not chronic");
    assert!(
        r.stalled(60),
        "a window of sustained write stalls must trip"
    );
    let ev = &r.trips[0];
    assert_eq!(ev.window_secs, 60.0);
    assert!(
        ev.stalled_secs >= 45.0,
        "evidence must carry the stalled span: {ev:?}"
    );
    assert!(
        ev.norm_bps >= FAST * 0.9,
        "the reference must be the healthy rate, not the stalled one: {ev:?}"
    );
    assert!(ev.goodput_bps < ev.norm_bps * 0.2);
    let s = ev.sentence(Path::new("/Volumes/Backup"));
    assert!(s.starts_with("write stalls: "), "{s}");
    assert!(s.contains("/Volumes/Backup"), "{s}");
    assert!(s.contains("of 60 s"), "{s}");
}

// ------------------------------------------------- must NOT fire (a-c)

/// Distinguish case (b): a legitimately busy disk absorbing a burst.
/// Seconds, not minutes - and it self-clears.
#[test]
fn a_busy_disk_burst_never_trips() {
    let mut r = Rig::new();
    r.healthy(120);
    for _ in 0..20 {
        assert!(!r.stalled(8), "an 8 s burst is not a dying volume");
        assert!(!r.healthy(60), "...and it self-clears");
    }
    assert!(r.trips.is_empty());
}

/// The same shape without the recovery gap: bursts arriving back to back
/// but each shorter than the trip bar, which is the sawtooth a busy
/// single-SSD box actually shows.
#[test]
fn a_repeating_sawtooth_never_trips() {
    let mut r = Rig::new();
    r.healthy(120);
    for _ in 0..40 {
        r.stalled(10);
        r.healthy(20);
    }
    assert!(
        r.trips.is_empty(),
        "a third of the time stalled is a busy disk, not a failing one"
    );
}

/// Distinguish case (c): network-idle stretches. The judge only counts
/// ticks that HAVE bytes to write - and because the trip is measured
/// against the whole window rather than against the active part of it,
/// idle time dilutes evidence instead of concentrating it. Without that,
/// this series (every retained tick is stalled) would trip immediately.
#[test]
fn idle_stretches_dilute_rather_than_concentrate() {
    let mut r = Rig::new();
    r.healthy(120);
    for _ in 0..50 {
        r.stalled(2);
        r.idle(10);
    }
    assert!(
        r.trips.is_empty(),
        "every retained tick was stalled, but they were 10 s apart"
    );
}

#[test]
fn a_wholly_idle_daemon_never_trips() {
    let mut r = Rig::new();
    assert!(!r.idle(3600));
    assert!(r.trips.is_empty());
}

// ---------------------------------------- must NOT fire: the hard cases

/// The false positive this whole design is shaped around: a FAST healthy
/// download parks its workers almost continuously, because the channel
/// between fetch and decode is meant to fill. Blocked time alone would
/// pause a perfectly good download within one window.
#[test]
fn a_fast_download_that_parks_constantly_never_trips() {
    let mut r = Rig::new();
    assert!(!r.run(1800, 0.98, FAST), "parked at full speed is healthy");
    assert!(r.trips.is_empty());
}

/// The mirror image: goodput collapses but nothing is parked on the
/// write side. That is the network (or a 430 storm, or a provider gone
/// slow) and pausing for "storage" would be a lie.
#[test]
fn a_slow_network_never_trips() {
    let mut r = Rig::new();
    r.healthy(120);
    assert!(
        !r.run(1800, 0.02, FAST / 200.0),
        "a slow line is not a slow disk"
    );
    assert!(r.trips.is_empty());
}

/// Goodput at the bar but not under it, with everything parked: the
/// disk is the bottleneck and the pipeline is still delivering a fifth
/// of peak. That is slow, not stalled.
#[test]
fn degraded_but_delivering_never_trips() {
    let mut r = Rig::new();
    r.healthy(120);
    assert!(!r.run(600, 0.95, FAST * 0.25));
    assert!(r.trips.is_empty());
}

// --------------------------------------------------------- hysteresis

#[test]
fn one_bad_stretch_nominates_once() {
    let mut r = Rig::new();
    r.healthy(120);
    assert!(r.stalled(120));
    assert!(!r.stalled(600), "latched until the caller rearms");
    assert_eq!(r.trips.len(), 1);
}

#[test]
fn a_retrip_needs_a_whole_fresh_window() {
    let mut r = Rig::new();
    r.healthy(120);
    assert!(r.stalled(120));
    r.judge.rearm(r.at);
    assert!(
        !r.stalled(50),
        "rearm drops the history: a fresh window is required"
    );
    assert!(r.stalled(30), "and once a fresh window is full, it trips");
    assert_eq!(r.trips.len(), 2);
}

#[test]
fn too_few_samples_is_not_a_window() {
    // A window's worth of wall time, but only three ticks in it - a
    // watcher that was starved of scheduling has not observed minutes of
    // anything.
    let mut j = Judge::new(tune());
    let mut at = 1_000_000u64;
    let mut trips = 0;
    for _ in 0..40 {
        at += 30_000;
        let worker_ms = 30_000 * CONNS;
        if j.observe(Sample {
            at_ms: at,
            span_ms: 30_000,
            worker_ms,
            blocked_ms: worker_ms,
            bytes: 1,
        })
        .is_some()
        {
            trips += 1;
        }
    }
    // 60 s window / 30 s ticks = 2 samples in window, under min_samples.
    assert_eq!(trips, 0, "min_samples is the floor on evidence quantity");
}

#[test]
fn a_fleet_with_no_connections_contributes_nothing() {
    let mut j = Judge::new(tune());
    let ev = j.observe(Sample {
        at_ms: 1_000_000,
        span_ms: SPAN,
        worker_ms: 0,
        blocked_ms: 0,
        bytes: 0,
    });
    assert!(ev.is_none());
}

// -------------------------------------------------------------- tune

#[test]
fn settings_are_clamped_and_ordered() {
    let t = Tune::from_settings(&json!({
        "window_secs": 5,          // under the floor
        "blocked_pct": 9.0,        // over the ceiling
        "trip_pct": 0.0,           // under the floor
        "probe_healthy": 0,        // under the floor
        "norm_secs": 60,           // shorter than the window
    }));
    assert_eq!(t.window_secs, 30);
    assert_eq!(t.blocked_pct, 1.0);
    assert_eq!(t.trip_pct, 0.25);
    assert_eq!(t.probe_healthy, 1);
    assert!(
        t.norm_secs >= t.window_secs,
        "a stall must never be its own reference"
    );
    // Anything absent keeps the shipping default.
    assert_eq!(t.goodput_pct, Tune::default().goodput_pct);
    assert_eq!(Tune::from_settings(&json!({})), Tune::default());
    assert_eq!(Tune::from_settings(&Value::Null), Tune::default());
}

// -------------------------------------------------------------- probe

#[test]
fn the_probe_writes_fsyncs_and_cleans_up() {
    let dir = TmpDir::new("probe-clean");
    // A tmpdir is fast; 100 s is a bar no healthy volume reaches.
    let p = probe_write(dir.path(), 64 << 10, 100_000);
    assert!(matches!(p, Probe::Fast(_)), "{p:?}");
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(left.is_empty(), "the probe file must not survive the probe");
    // Back-to-back probes must not collide: a probe abandoned for
    // overrunning its budget is still writing on its own thread when the
    // next one starts, and two threads on one path would time each
    // other. Reaching in for the payload is the only way to see the
    // names, so drive it through a directory we can watch instead: two
    // probes, two distinct files, neither left behind.
    let watch = dir.path().join("seq");
    std::fs::create_dir_all(&watch).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            probe_write(&watch, 4 << 10, 100_000),
            Probe::Fast(_)
        ));
    }
    assert_eq!(std::fs::read_dir(&watch).unwrap().count(), 0);
}

/// A block of zeroes is what a compressing or deduping filesystem (ZFS
/// with lz4, btrfs, an SMB share in front of either) turns into a hole -
/// so a zero-filled probe would come back instantly on exactly the NAS
/// setups this feature exists for, and the pause would never fire. The
/// payload has to be incompressible.
#[test]
fn the_probe_payload_does_not_compress_away() {
    let v = probe_payload(64 << 10, 0);
    assert_eq!(v.len(), 64 << 10, "exact length, including a ragged tail");
    assert_eq!(probe_payload(7, 0).len(), 7);
    let mut hist = [0u32; 256];
    for b in &v {
        hist[*b as usize] += 1;
    }
    let top = *hist.iter().max().unwrap();
    assert!(
        top < (v.len() as u32) / 32,
        "no byte value may dominate: a run-length or lz4 pass would \
         swallow the write whole and the probe would time nothing \
         (top {top} of {})",
        v.len()
    );
    assert!(
        hist.iter().filter(|c| **c > 0).count() > 200,
        "the payload must span the byte range"
    );
    // Different per probe, so a deduping volume cannot answer the second
    // write from the first one's blocks.
    assert_ne!(probe_payload(4096, 0), probe_payload(4096, 1));
}

#[test]
fn the_probe_walks_up_to_a_directory_that_exists() {
    let dir = TmpDir::new("probe-walk");
    // The per-category output folder is made at job time and may not
    // exist yet; the volume underneath it is still the one to measure.
    let p = probe_write(&dir.path().join("tv").join("Some.Show"), 4 << 10, 100_000);
    assert!(matches!(p, Probe::Fast(_)), "{p:?}");
}

#[test]
fn a_zero_bar_makes_every_probe_slow() {
    let dir = TmpDir::new("probe-bar");
    let p = probe_write(dir.path(), 4 << 10, 0);
    assert!(matches!(p, Probe::Slow(_)), "{p:?}");
}

// ------------------------------------------- the daemon-side pause/resume

/// The integration leg: a synthetic evidence series through the judge's
/// real feed, the real pause path, and a healed probe resuming it.
#[test]
fn evidence_pauses_the_queue_and_a_healed_volume_resumes_it() {
    let dir = TmpDir::new("pause-resume");
    let d = crate::testutil::test_daemon(dir.path());
    d.slow_storage.set_tune(tune());
    let out = crate::naming::out_dir(&d).join("Some.Release");
    // One job on the wire, the way a storage stall finds the daemon.
    let job = mkjob("SABnzbd_nzo_slow1", &out);
    d.queue.lock_ok().push_back(job.clone());
    *d.active_dl.lock_ok() = Some("SABnzbd_nzo_slow1".into());

    let mut r = Rig::new();
    r.healthy(120);
    assert!(r.stalled(120), "the fixture must produce a nomination");
    let ev = r.trips[0].clone();

    // A probe that comes back FAST refuses the nomination: blocked_ms
    // covers everything downstream of the socket, so the window alone
    // cannot tell a slow disk from a wedged decoder.
    assert!(!engage(&d, &ev, &out, &Probe::Fast(4)));
    assert!(!d.paused.load(Ordering::Relaxed));
    assert!(!d.slow_storage.paused());
    // Nor does an errored probe - that is the ACUTE path's business.
    assert!(!engage(&d, &ev, &out, &Probe::Failed("ENOSPC".into())));
    assert!(!d.paused.load(Ordering::Relaxed));

    // Confirmed slow: pause.
    assert!(engage(&d, &ev, &out, &Probe::Slow(4_200)));
    assert!(d.paused.load(Ordering::Relaxed));
    assert_eq!(*d.pause_source.lock_ok(), "storage");
    assert!(
        job.lock_ok().suspended,
        "the running job must be wound down, not left transferring"
    );
    // Nothing was FAILED: a storage pause never reaches history, so the
    // give-up breaker and the auto-retry ladder never see it.
    assert!(d.history.lock_ok().is_empty());
    assert_eq!(job.lock_ok().state, JobState::Downloading);
    assert!(job.lock_ok().fail_message.is_empty());
    // ...and the wind-down thread can stop looking (the real tail parks
    // the job; this test has no pipeline to do it).
    job.lock_ok().suspended = false;

    let p = payload(&d);
    assert_eq!(p["nzo_id"], "SABnzbd_nzo_slow1");
    assert_eq!(p["probe_ms"], 4_200);
    assert_eq!(p["probes_needed"], 3);
    assert_eq!(p["path"], out.to_string_lossy().to_string());
    let why = p["evidence"].as_str().unwrap();
    assert!(why.starts_with("write stalls: "), "{why}");
    assert!(why.contains(&out.display().to_string()), "{why}");

    // Hysteresis: N CONSECUTIVE clean probes, and a slow one in the
    // middle sends the count back to zero.
    assert!(!heal(&d, &Probe::Fast(3)));
    assert!(!heal(&d, &Probe::Fast(3)));
    assert!(!heal(&d, &Probe::Slow(9_000)), "a flap is not a recovery");
    assert_eq!(payload(&d)["healthy_probes"], 0);
    assert!(d.paused.load(Ordering::Relaxed));
    assert!(!heal(&d, &Probe::Fast(3)));
    assert!(!heal(&d, &Probe::Failed("EIO".into())), "nor is an error");
    assert!(!heal(&d, &Probe::Fast(3)));
    assert!(!heal(&d, &Probe::Fast(3)));
    assert!(heal(&d, &Probe::Fast(3)), "three clean probes resume");
    assert!(!d.paused.load(Ordering::Relaxed));
    assert!(!d.slow_storage.paused());
    assert_eq!(payload(&d), Value::Null);
    // The queue is intact and nothing failed: this was a pause.
    assert_eq!(d.queue.lock_ok().len(), 1);
    assert!(d.history.lock_ok().is_empty());
}

/// A person (or a schedule) pausing on top of a storage pause has said
/// something the probe does not get to overrule.
#[test]
fn a_user_pause_takes_ownership_and_the_probe_stands_down() {
    let dir = TmpDir::new("user-owns");
    let d = crate::testutil::test_daemon(dir.path());
    d.slow_storage.set_tune(tune());
    let out = crate::naming::out_dir(&d);
    let ev = Evidence {
        stalled_secs: 50.0,
        window_secs: 60.0,
        goodput_bps: 1e6,
        norm_bps: 100e6,
    };
    assert!(engage(&d, &ev, &out, &Probe::Slow(3_000)));
    assert!(still_ours(&d));
    // The user pauses: `pause_source` moves, and the watcher's next tick
    // sees the pause is no longer its own.
    *d.pause_source.lock_ok() = "user";
    assert!(!still_ours(&d));
    release(&d, "handed over");
    assert!(
        d.paused.load(Ordering::Relaxed),
        "releasing our state must not lift someone else's pause"
    );
    assert!(!d.slow_storage.paused());
}

/// Every tick's gating, including the one that matters most: OFFLINE.
///
/// Going offline pauses the queue without touching `pause_source`, so a
/// queue already storage-paused stays reading "storage" while offline
/// holds it shut. A probe allowed to run there would find a healthy
/// volume, resume, and put the whole fleet back on an account the
/// operator had deliberately vacated - the TODO 65 hazard, from the
/// other direction. So offline is checked BEFORE ownership, and it
/// yields Idle: state kept, pause untouched.
#[test]
fn offline_stands_the_whole_feature_down() {
    let dir = TmpDir::new("offline");
    let d = crate::testutil::test_daemon(dir.path());
    assert_eq!(step(&d), Step::Watch, "armed and idle: watching");
    let ev = Evidence {
        stalled_secs: 50.0,
        window_secs: 60.0,
        goodput_bps: 1e6,
        norm_bps: 100e6,
    };
    assert!(engage(
        &d,
        &ev,
        &crate::naming::out_dir(&d),
        &Probe::Slow(3_000)
    ));
    assert_eq!(step(&d), Step::Probe, "our own pause: probe for recovery");

    d.offline.store(true, Ordering::Relaxed);
    assert_eq!(step(&d), Step::Idle, "offline outranks a healed volume");
    assert!(d.slow_storage.paused(), "and our state is KEPT");
    d.offline.store(false, Ordering::Relaxed);
    assert_eq!(step(&d), Step::Probe);

    // A user pause on top hands ownership over.
    *d.pause_source.lock_ok() = "user";
    assert!(matches!(step(&d), Step::Release(_)));
    *d.pause_source.lock_ok() = "storage";

    // Switching the feature off must RELEASE, not strand.
    d.slow_storage.set_enabled(false);
    assert!(matches!(step(&d), Step::Release(_)));
    release(&d, "off");
    assert!(!d.paused.load(Ordering::Relaxed));
    assert_eq!(step(&d), Step::Idle, "off with nothing held: nothing to do");
}

#[test]
fn releasing_our_own_pause_lifts_it() {
    let dir = TmpDir::new("release");
    let d = crate::testutil::test_daemon(dir.path());
    let out = crate::naming::out_dir(&d);
    let ev = Evidence {
        stalled_secs: 50.0,
        window_secs: 60.0,
        goodput_bps: 1e6,
        norm_bps: 100e6,
    };
    assert!(engage(&d, &ev, &out, &Probe::Slow(3_000)));
    release(&d, "recovered");
    assert!(!d.paused.load(Ordering::Relaxed));
    assert_eq!(payload(&d), Value::Null);
    // Idempotent: a second release is a no-op, not a second resume.
    d.paused.store(true, Ordering::Relaxed);
    release(&d, "recovered");
    assert!(d.paused.load(Ordering::Relaxed));
}

/// Every edge that moves the payload must move the REVISION with it.
///
/// This is the §129 1b staleness trap, and a storage pause walks
/// straight into it: the poll answers `"queue": null` to a client whose
/// revision matches unless something is actively transferring, and the
/// first thing this feature does is take the one running job off the
/// wire. So from the pause landing to the pause lifting there is nothing
/// active, and the revision is the only thing that can repaint the
/// header pill, the row sub-line and the drawer's recovery tally.
///
/// The tally is the visible half: it changes on every probe - 15 s apart
/// by default - and it is what tells a user watching a paused queue that
/// their volume is coming back. Frozen at "0 of 3" it says the opposite.
#[test]
fn every_payload_change_moves_the_queue_revision() {
    let dir = TmpDir::new("rev");
    let d = crate::testutil::test_daemon(dir.path());
    let out = crate::naming::out_dir(&d);
    let ev = Evidence {
        stalled_secs: 50.0,
        window_secs: 60.0,
        goodput_bps: 1e6,
        norm_bps: 100e6,
    };
    let rev = || d.queue_rev.load(Ordering::Relaxed);

    // A DECLINED nomination changes nothing on the payload, so it must
    // not churn the revision either - a volume that probes fine every
    // few minutes would otherwise hand every open dashboard a full
    // queue payload for nothing.
    let quiet = rev();
    assert!(!engage(&d, &ev, &out, &Probe::Fast(4)));
    assert_eq!(rev(), quiet, "a declined nomination is not a change");

    let before = rev();
    assert!(engage(&d, &ev, &out, &Probe::Slow(3_000)));
    assert!(rev() > before, "the pause itself must move the revision");

    // Each probe writes the tally and the last-probe duration.
    for expect in [1_u32, 2, 0] {
        let at = rev();
        let probe = match expect {
            0 => Probe::Slow(9_000),
            _ => Probe::Fast(3),
        };
        assert!(!heal(&d, &probe));
        assert_eq!(payload(&d)["healthy_probes"], expect);
        assert!(rev() > at, "probe {expect} must move the revision");
    }

    // And the resume, which is the one that strands a user: it happens
    // with a paused (therefore inactive) queue behind it, so nothing
    // else is going to move the payload afterwards.
    assert!(!heal(&d, &Probe::Fast(3)));
    assert!(!heal(&d, &Probe::Fast(3)));
    let at = rev();
    assert!(heal(&d, &Probe::Fast(3)));
    assert_eq!(payload(&d), Value::Null);
    assert!(rev() > at, "the resume must move the revision");
}

/// The numbers behind the evidence ride the payload, not just the
/// English sentence built here: the dashboard composes its own
/// translated line from them, and a pre-formatted sentence cannot be
/// translated at the display edge.
#[test]
fn the_payload_carries_the_evidence_as_numbers() {
    let dir = TmpDir::new("evnum");
    let d = crate::testutil::test_daemon(dir.path());
    let out = crate::naming::out_dir(&d);
    let ev = Evidence {
        stalled_secs: 148.6,
        window_secs: 180.0,
        goodput_bps: 1e6,
        norm_bps: 100e6,
    };
    assert!(engage(&d, &ev, &out, &Probe::Slow(3_000)));
    let p = payload(&d);
    assert_eq!(p["stalled_secs"], 149.0);
    assert_eq!(p["window_secs"], 180.0);
    // The English sentence stays too: it is what the log and the
    // notification said, and the tooltip of last resort.
    assert!(
        p["evidence"]
            .as_str()
            .unwrap()
            .starts_with("write stalls: "),
        "{p}"
    );
}

/// §108 option 2: the diagnostic latch. Nothing here pauses anything -
/// this is the opinion the "why is this slow?" panel reads when the
/// breaker has NOT tripped, so the bar is hysteresis and honesty rather
/// than the pause path's full ceremony.
#[test]
fn the_diagnostic_needs_consecutive_slow_probes_and_goes_stale() {
    let dir = TmpDir::new("diag");
    let d = crate::testutil::test_daemon(dir.path());
    let now = 1_000_000u64;

    // Nobody is asking: slowstore does not volunteer an opinion, and a
    // probe result arriving without a question cannot condemn anything.
    assert!(!d.slow_storage.suspect(now));
    assert!(!note_diag(&d, &Probe::Slow(4_000), now));
    assert!(!d.slow_storage.suspect(now), "no question, no verdict");

    // The whyslow core asks. Asking CLEARS whatever was latched: the
    // probes stopped because the fork stopped being reached, and the
    // volume's behaviour back then is not evidence about now.
    d.slow_storage.set_want_diag(true);
    assert!(!d.slow_storage.suspect(now), "asking is not answering");

    // One slow probe is not a verdict - the same reason one clean probe
    // is not a recovery.
    assert!(!note_diag(&d, &Probe::Slow(4_000), now));
    assert!(!d.slow_storage.suspect(now));
    assert!(note_diag(&d, &Probe::Slow(4_100), now + 60_000));
    assert!(d.slow_storage.suspect(now + 60_000));
    assert_eq!(d.slow_storage.diag_ms(), 4_100);

    // A fast probe clears it outright: the volume answered, so whatever
    // it was doing, it is not doing it now.
    assert!(!note_diag(&d, &Probe::Fast(6), now + 120_000));
    assert!(!d.slow_storage.suspect(now + 120_000));

    // An ERRORED probe is not evidence of slowness either. A write that
    // fails outright is the acute path's business and has its own
    // verdict; treating it as "slow" would put the wrong words on it.
    assert!(!note_diag(&d, &Probe::Slow(4_000), now + 180_000));
    assert!(!note_diag(&d, &Probe::Failed("EIO".into()), now + 240_000));
    assert!(!note_diag(&d, &Probe::Slow(4_000), now + 300_000));
    assert!(
        !d.slow_storage.suspect(now + 300_000),
        "the error reset the run, so this is only the first slow probe again"
    );
    assert!(note_diag(&d, &Probe::Slow(4_000), now + 360_000));
    assert!(d.slow_storage.suspect(now + 360_000));

    // Staleness: an opinion nobody is refreshing stops condemning. The
    // bound is three cadences, so ONE missed probe never drops a
    // standing verdict.
    let diag_secs = d.slow_storage.tune().diag_secs;
    assert!(d.slow_storage.suspect(now + 360_000 + diag_secs * 2_000));
    assert!(!d.slow_storage.suspect(now + 360_000 + diag_secs * 4_000));

    // And the question closing drops it immediately: the panel must not
    // keep naming a drive once the evidence that raised the question is
    // gone.
    d.slow_storage.set_want_diag(false);
    assert!(!d.slow_storage.suspect(now + 360_000));
}

/// The diagnostic must never be mistaken for the breaker. It is an
/// opinion; only `engage` is an action.
#[test]
fn the_diagnostic_never_pauses_anything() {
    let dir = TmpDir::new("diag-noact");
    let d = crate::testutil::test_daemon(dir.path());
    d.slow_storage.set_want_diag(true);
    for i in 0..10 {
        note_diag(&d, &Probe::Slow(9_000), 1_000_000 + i * 60_000);
    }
    assert!(d.slow_storage.suspect(1_000_000 + 9 * 60_000));
    assert!(!d.paused.load(Ordering::Relaxed), "no pause");
    assert!(!d.slow_storage.paused(), "no held state");
    assert_eq!(payload(&d), Value::Null, "nothing on the queue payload");
    assert_eq!(*d.pause_source.lock_ok(), "user", "source untouched");
}

/// `diag_secs` is the lighter of the two cadences by construction: the
/// diagnostic runs while the queue is still working, so a hand edit must
/// not be able to make it heavier than the paused one.
#[test]
fn the_diagnostic_cadence_can_never_undercut_the_paused_one() {
    let t = Tune::from_settings(&json!({"probe_secs": 30, "diag_secs": 5}));
    assert_eq!(t.probe_secs, 30);
    assert_eq!(t.diag_secs, 30, "clamped up to the paused cadence");
    let t = Tune::from_settings(&json!({"diag_secs": 600}));
    assert_eq!(t.diag_secs, 600);
    assert_eq!(Tune::default().diag_secs, 60);
}

/// The affected volume is the JOB's output directory - categories can
/// send jobs to different disks, and naming the wrong one sends the user
/// to check the wrong hardware.
#[test]
fn the_named_path_is_the_running_jobs_own_output_directory() {
    let dir = TmpDir::new("path");
    let d = crate::testutil::test_daemon(dir.path());
    assert_eq!(
        affected_path(&d),
        crate::naming::out_dir(&d),
        "no job: the output root"
    );
    let out = dir.path().join("nas").join("Films");
    d.queue
        .lock_ok()
        .push_back(mkjob("SABnzbd_nzo_slow2", &out));
    *d.active_dl.lock_ok() = Some("SABnzbd_nzo_slow2".into());
    assert_eq!(affected_path(&d), out);
}
