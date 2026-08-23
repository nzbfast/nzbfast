//! TODO 208 item 3: the drain rig - what the queue-dry tail actually costs,
//! and what the endgame depth taper buys back, on a line-bound link.
//!
//! **The finding this rig exists to hold.** A 1 Gbps tv4 leg logs
//! `run 62.68s - queue dry at 45.83s - drained at 62.61s`: 27% of the
//! leg runs after the work queue is empty. That stretch is the
//! in-flight set emptying, and its size is `conns x window` articles -
//! confirmed directly off the banked 1 GbE bench legs, where the payload
//! still to arrive at queue-dry is 1.13-1.62 GB on EVERY leg, invariant
//! across a 6.8x change in job size, a 4x change in line speed and both
//! connection profiles, because `360 x 4` never changed.
//!
//! **That stretch is not dead time**, and one thing here has to be read
//! with that in mind. On legs with the §202 saturation gate armed the
//! drain delivers its payload FASTER than the run's pre-dry rate, so
//! there is no line-idle slack in it. (Older legs look like they have
//! 15-19 s of it at 250 Mbit; that is duplicate bodies on the wire,
//! which the decoded-byte gauge cannot see, and §202 removed them.)
//!
//! These rigs therefore give the mock fleet a per-connection spread -
//! a binding line, half the sockets capped well under their fair share
//! - which stands in for what duplicate bytes were doing on the real
//! line. **So the wall figures below demonstrate the MECHANISM and do
//! not price a real payout**: they say the fleet reaches queue-dry one
//! article deep, that the drain shortens ~4x, and - the question that
//! actually gates the change - that shortening it costs the run
//! nothing.
//!
//! Wall-clock, so `#[ignore]`d like the payout rigs beside them.

use super::*;

/// One leg: run a full fetch and report the wall, the drain, and how
/// much of the job was still in flight when the queue ran dry.
struct DrainLeg {
    wall: Duration,
    /// Queue-dry to the last article - the tail this campaign is about.
    drain: Duration,
    /// Articles outstanding at the queue-dry latch. This is the
    /// quantity the analysis calls `L`; on the bench fleet it is 1,440.
    inflight_at_dry: usize,
    /// `Shared::taper_min` at the end of the run - the shallowest depth
    /// the taper handed out, `usize::MAX` if it never bit. The `[pool]`
    /// line prints it for the same reason the rig asserts it: a leg
    /// must be able to PROVE the arm took without reading the drain it
    /// is trying to measure.
    taper_min: usize,
    done: usize,
}

/// `conns` workers against one throttled mock, with `cfg`'s knobs.
///
/// The drain is sampled rather than read off `Shared` at the end: the
/// pool's last strong `Arc` dies with the fetch, so a `QueueControl`'s
/// `Weak` no longer upgrades by the time the caller could ask. A 5 ms
/// poll is well under the rig's article service time and costs the leg
/// nothing measurable.
async fn drain_leg(
    srv: &crate::mock::MockServer,
    ids: Vec<ArticleReq>,
    conns: usize,
    window: usize,
    taper: bool,
) -> DrainLeg {
    let mut sc = srv.server_config();
    sc.connections = conns as u32;
    let cfg = PoolConfig {
        connections: conns,
        window,
        ramp_delay: Duration::from_millis(0),
        tail_taper: taper,
        ..PoolConfig::shipped()
    };
    let servers = vec![(sc, cfg)];
    let ctl = Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(64);

    let ctl_fetch = ctl.clone();
    let t0 = Instant::now();
    let fetch =
        tokio::spawn(async move { fetch_all_multi_ctl(&servers, ids, tx, Some(&ctl_fetch)).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });

    // Sample the tail latch and what was outstanding when it fired.
    // `tail_pending` answers None both before the latch and after the
    // run is gone, so the reading is written out to the caller rather
    // than returned - the watcher is aborted, not joined.
    let seen: Arc<std::sync::Mutex<Option<(Instant, usize)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let taper_seen: Arc<std::sync::Mutex<usize>> = Arc::new(std::sync::Mutex::new(usize::MAX));
    let ctl_watch = ctl.clone();
    let seen_watch = seen.clone();
    let taper_watch = taper_seen.clone();
    let watch = tokio::spawn(async move {
        loop {
            if let Some(left) = ctl_watch.tail_pending() {
                *seen_watch.lock_ok() = Some((Instant::now(), left));
                // The taper has finished walking down by the latch:
                // `pending` only falls from here, so the minimum is
                // settled and the `Weak` is still upgradable, which it
                // will not be once the fetch returns.
                *taper_watch.lock_ok() = ctl_watch.taper_min();
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    tokio::time::timeout(Duration::from_secs(180), fetch)
        .await
        .expect("drain leg hung")
        .unwrap();
    let wall = t0.elapsed();
    let done = collect.await.unwrap();
    watch.abort();
    let reading = *seen.lock_ok();
    let (drain, inflight_at_dry) = match reading {
        Some((at, left)) => (wall.saturating_sub(at - t0), left),
        // The queue never ran dry with work outstanding: no tail at all.
        None => (Duration::ZERO, 0),
    };
    DrainLeg {
        wall,
        drain,
        inflight_at_dry,
        taper_min: *taper_seen.lock_ok(),
        done,
    }
}

/// A fleet whose sockets do NOT all get the same share of the line:
/// every other connection is capped to `slow_bps`, the rest take
/// whatever the line leaves. That asymmetry is the whole mechanism -
/// with a uniform fleet every pipeline drains together and the tail
/// costs nothing but its own bytes.
fn dispersed(line_bps: u64, slow_bps: u64) -> crate::mock::Chaos {
    crate::mock::Chaos {
        throttle: crate::mock::Throttle {
            line_bps,
            ..Default::default()
        },
        wan_conn_bps: vec![0, slow_bps],
        ..Default::default()
    }
}

/// The relation, measured: the in-flight set at queue-dry is
/// `conns x window`, so the tail's share of the run is
/// `conns x window / articles` - a property of the DIAL, not of
/// anything speculative. Two window settings on one fixture, and the
/// outstanding count must track the dial, not the job.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock drain rig (~30 s) - run with --ignored"]
async fn the_queue_dry_tail_is_the_dial_not_the_job() {
    let (articles, ids) = tail_corpus(600, 32_768);
    let srv = crate::mock::MockServer::start(articles, dispersed(6_000_000, 120_000)).await;
    let conns = 24;

    let deep = drain_leg(&srv, ids.clone(), conns, 4, false).await;
    let shallow = drain_leg(&srv, ids, conns, 1, false).await;

    eprintln!(
        "TAIL-DIAL  window 4: wall {:?} drain {:?} inflight-at-dry {}\n\
         TAIL-DIAL  window 1: wall {:?} drain {:?} inflight-at-dry {}",
        deep.wall,
        deep.drain,
        deep.inflight_at_dry,
        shallow.wall,
        shallow.drain,
        shallow.inflight_at_dry,
    );
    assert_eq!(deep.done, 600, "window-4 leg lost articles");
    assert_eq!(shallow.done, 600, "window-1 leg lost articles");

    // `conns x window`, within the sampler's own slack: articles keep
    // completing during the 5 ms poll, so the reading is a lower bound.
    let want = (conns * 4) as f64;
    let got = deep.inflight_at_dry as f64;
    assert!(
        got > want * 0.6 && got < want * 1.3,
        "in-flight at queue-dry should be ~conns x window = {want}, got {got}"
    );
    assert!(
        shallow.inflight_at_dry * 2 < deep.inflight_at_dry,
        "a 4x shallower dial did not shrink the in-flight set: \
         {} at window 1 vs {} at window 4",
        shallow.inflight_at_dry,
        deep.inflight_at_dry
    );
    assert!(
        shallow.drain * 2 < deep.drain,
        "a 4x shallower dial did not shorten the drain: {:?} vs {:?}",
        shallow.drain,
        deep.drain
    );
}

/// The mechanism, and the safety question that gates the change: the
/// taper reaches queue-dry with roughly one article per connection
/// instead of `window`, so the drain shortens - and, because the work
/// it did not park was left in the QUEUE where a fast socket could
/// still take it, the leg does not get slower to pay for it. The wall
/// assertion is the important half; see the module header for why the
/// drain reduction here is not a real-line payout.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock drain rig (~30 s) - run with --ignored"]
async fn the_taper_shortens_the_drain_without_paying_wall_for_it() {
    let (articles, ids) = tail_corpus(600, 32_768);
    let srv = crate::mock::MockServer::start(articles, dispersed(6_000_000, 120_000)).await;
    let conns = 24;

    let base = drain_leg(&srv, ids.clone(), conns, 4, false).await;
    let taper = drain_leg(&srv, ids, conns, 4, true).await;

    eprintln!(
        "TAIL-TAPER off: wall {:?} drain {:?} inflight-at-dry {} taper-min {}\n\
         TAIL-TAPER on:  wall {:?} drain {:?} inflight-at-dry {} taper-min {}",
        base.wall,
        base.drain,
        base.inflight_at_dry,
        base.taper_min,
        taper.wall,
        taper.drain,
        taper.inflight_at_dry,
        taper.taper_min,
    );
    assert_eq!(base.done, 600, "baseline leg lost articles");
    assert_eq!(taper.done, 600, "tapered leg lost articles");

    // The self-evidencing half. A leg that reads its own payout off the
    // drain cannot tell a real null result from a knob that never
    // arrived; this gauge can, and the `[pool]` line prints it for the
    // same reason.
    assert_eq!(
        base.taper_min,
        usize::MAX,
        "the disarmed leg reported a taper depth"
    );
    assert_eq!(
        taper.taper_min, 1,
        "the taper never reached depth 1 (reported {})",
        taper.taper_min
    );

    assert!(
        taper.inflight_at_dry * 2 < base.inflight_at_dry,
        "the taper did not shallow the fleet by queue-dry: {} vs {}",
        taper.inflight_at_dry,
        base.inflight_at_dry
    );
    assert!(
        taper.drain < base.drain,
        "the taper did not shorten the drain: {:?} vs {:?}",
        taper.drain,
        base.drain
    );
    // The safety half, and the one that matters most: shortening the
    // tail must not be bought with the run. A depth-1 pipeline pays one
    // round trip per completion; on a line-bound link that is noise,
    // and the band here is wide enough to say so without failing on it.
    assert!(
        taper.wall.as_secs_f64() < base.wall.as_secs_f64() * 1.05,
        "the taper cost wall: {:?} vs {:?}",
        taper.wall,
        base.wall
    );
}

/// SAFETY, and the constraint this whole change lives under: do not
/// regress the fast-link case, where deep pipelining is what earns the
/// margins. Same fixture and fleet with NO line cap at all - the client
/// is the bottleneck, which is the 10 GbE shape - and the taper must
/// cost nothing.
///
/// It is inert there for a structural reason, not a tuned one: the rule
/// does not move until the queue falls under `window x conns`, which on
/// a fast link is the last fraction of a second of the run. The banked
/// 10 GbE round makes the same point from the other side - 40 sockets
/// hold the same wall as 360 on apollo13, so the in-flight set that
/// becomes the tail is ~1 s of line time there against 16 s at 1 Gbps.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock drain rig (~20 s) - run with --ignored"]
async fn the_taper_costs_nothing_when_the_client_is_the_bottleneck() {
    let (articles, ids) = tail_corpus(1_200, 32_768);
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let conns = 24;

    let base = drain_leg(&srv, ids.clone(), conns, 4, false).await;
    let taper = drain_leg(&srv, ids, conns, 4, true).await;

    eprintln!(
        "TAIL-FAST  off: wall {:?} drain {:?} inflight-at-dry {}\n\
         TAIL-FAST  on:  wall {:?} drain {:?} inflight-at-dry {}",
        base.wall, base.drain, base.inflight_at_dry, taper.wall, taper.drain, taper.inflight_at_dry,
    );
    assert_eq!(base.done, 1_200, "baseline leg lost articles");
    assert_eq!(taper.done, 1_200, "tapered leg lost articles");
    assert!(
        taper.wall.as_secs_f64() < base.wall.as_secs_f64() * 1.05,
        "the taper cost wall on an uncapped link: {:?} vs {:?}",
        taper.wall,
        base.wall
    );
}

/// `n` articles of `seg` bytes, one file.
fn tail_corpus(
    n: usize,
    seg: usize,
) -> (std::collections::HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..(n * seg) as u32)
        .map(|i| (i * 31 % 251) as u8)
        .collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("tail.bin", &data, seg, "tr", &mut articles);
    let ids = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    (articles, ids)
}
