//! `StallTracker` state-machine tests, moved out of tasks.rs bodily
//! (TODO 106). Pure state machine - no daemon, no sockets.

use super::{StallEvent, StallTracker};
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(10);

fn tick(t0: Instant, secs: u64) -> Instant {
    t0 + Duration::from_secs(secs)
}

#[test]
fn opens_after_threshold_then_clears_on_bytes() {
    let t0 = Instant::now();
    let mut s = StallTracker::new(T);
    assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
    assert!(s.observe(tick(t0, 5), Some(("a", "job-a")), 100).is_none());
    let ev = s.observe(tick(t0, 12), Some(("a", "job-a")), 100);
    assert!(matches!(ev, Some(StallEvent::Opened { idle_secs: 12, .. })));
    // Still open: no repeat event while frozen.
    assert!(s.observe(tick(t0, 17), Some(("a", "job-a")), 100).is_none());
    let ev = s.observe(tick(t0, 40), Some(("a", "job-a")), 250);
    assert!(matches!(ev, Some(StallEvent::Cleared { idle_secs: 40 })));
    // Cleared for good: moving bytes stay quiet.
    assert!(s.observe(tick(t0, 45), Some(("a", "job-a")), 400).is_none());
}

#[test]
fn a_slow_but_moving_transfer_never_opens() {
    // The 31 Jul stall-watchdog lesson: slow is not stalled. Any byte
    // movement between samples resets the clock, however small.
    let t0 = Instant::now();
    let mut s = StallTracker::new(T);
    for i in 0..20u64 {
        assert!(
            s.observe(tick(t0, i * 5), Some(("a", "job-a")), 100 + i)
                .is_none(),
            "trickle sample {i} must not open an episode"
        );
    }
}

#[test]
fn job_end_mid_episode_reports_ended() {
    let t0 = Instant::now();
    let mut s = StallTracker::new(T);
    assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
    assert!(matches!(
        s.observe(tick(t0, 15), Some(("a", "job-a")), 100),
        Some(StallEvent::Opened { .. })
    ));
    let ev = s.observe(tick(t0, 20), None, 0);
    match ev {
        Some(StallEvent::Ended { idle_secs, name }) => {
            assert_eq!(idle_secs, 20);
            assert_eq!(name, "job-a");
        }
        other => panic!("expected Ended, got {}", kind(&other)),
    }
    // Fully reset afterwards.
    assert!(s.observe(tick(t0, 25), None, 0).is_none());
}

#[test]
fn job_switch_resets_the_baseline_and_ends_an_open_episode() {
    let t0 = Instant::now();
    let mut s = StallTracker::new(T);
    assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
    assert!(matches!(
        s.observe(tick(t0, 15), Some(("a", "job-a")), 100),
        Some(StallEvent::Opened { .. })
    ));
    // New job appears with an identical byte total (fresh pool also
    // starts at whatever it starts at): the old episode ends and the
    // new job's clock starts from this sample, not the stale one.
    assert!(matches!(
        s.observe(tick(t0, 20), Some(("b", "job-b")), 100),
        Some(StallEvent::Ended { .. })
    ));
    assert!(s.observe(tick(t0, 25), Some(("b", "job-b")), 100).is_none());
    assert!(matches!(
        s.observe(tick(t0, 31), Some(("b", "job-b")), 100),
        Some(StallEvent::Opened { .. })
    ));
}

fn kind(ev: &Option<StallEvent>) -> &'static str {
    match ev {
        None => "None",
        Some(StallEvent::Opened { .. }) => "Opened",
        Some(StallEvent::Cleared { .. }) => "Cleared",
        Some(StallEvent::Ended { .. }) => "Ended",
    }
}
