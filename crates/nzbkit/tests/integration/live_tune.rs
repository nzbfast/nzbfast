//! TODO 112: the live connection tuner, measured end to end.
//!
//! The pure decision rules are pinned in `livetune`'s unit tests; these
//! rigs ask the only question those cannot - does the whole loop hang
//! together against a REAL pool and a mock provider with a real
//! bandwidth shape (knee = line_bps / per_conn_bps)? Three rigs, per
//! the spec:
//!
//! 1. convergence - start mistuned in both directions; the controller
//!    must approach the knee, and the under-tuned leg must beat its
//!    mistuned wall.
//! 2. re-convergence - the line's capacity changes mid-run
//!    (`MockServer::set_line_bps`), the facts-changed case.
//! 3. no-oscillation - a flat healthy line at the knee; the fleet must
//!    hold steady. The noise-chasing gate: the offline tuner's history
//!    says this is where controllers fail.
//!
//! The conn-tuning design (8 Aug 2026) added three more:
//!
//! 4. shaping decay - the line decays 10x mid-corpus; the controller
//!    must walk down without oscillating, and the `shaping` detector
//!    must raise on its multi-stretch quorum, hold through one bad
//!    stretch, ignore a 20% dip, and clear on scripted recovery.
//! 5. warm start - a persisted seed re-converges measurably faster
//!    than cold, and a WRONG seed (both directions) escapes within a
//!    bounded epoch count - the structural James immunity, asserted.
//! 6. scan contamination - a header-pull-shaped disturbance flagged as
//!    scan_active mid-run; the cycle must abort and the target hold.
//!
//! Wall-clock measurements, so all are #[ignore]d - run with
//! `cargo test -p nzbkit --test live_tune -- --ignored`. Assertions are
//! deliberately wide: rung counts near the knee are a coin toss inside
//! the noise (the wave-6 lesson), so the rigs assert BANDS and wall
//! ratios, never exact rungs.

use nzbkit::config::ServerConfig;
use nzbkit::livetune::{EpochObs, ServerTuner};
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::pool::{ArticleReq, ConnTarget, FetchOutcome, LiveStats, PoolConfig, fetch_all_multi};
use nzbkit::shaping::{ShapeDetector, ShapeVerdict};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SEG: usize = 20_000;

fn corpus(total_bytes: usize) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    corpus_seg(total_bytes, SEG)
}

fn corpus_seg(total_bytes: usize, seg: usize) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..total_bytes as u32)
        .map(|i| (i * 17 % 253) as u8)
        .collect();
    let mut articles = HashMap::new();
    let segs = make_file_articles("live.bin", &data, seg, "lt", &mut articles);
    let ids = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    (articles, ids)
}

struct Leg {
    wall: Duration,
    /// The tuner's kept target when the run ended (== the fixed fleet
    /// size for untuned legs).
    final_target: usize,
    /// Every kept target sampled at epoch boundaries, for band checks.
    targets_seen: Vec<usize>,
    /// One row per epoch: (rate_bps, connected, clean) - what the
    /// daemon's glue would feed the shaping decay detector. `clean`
    /// here means busy, uncontaminated and fleet-met, the same
    /// definition the glue computes.
    samples: Vec<(f64, usize, bool)>,
}

/// Run one download leg. `spawn` workers are built; without a tuner the
/// fleet just runs at `start`, with one the controller moves the live
/// target from `start` as it decides. Each entry in `events` fires
/// once, roughly its fraction of the way through the corpus (rig 2's
/// re-provisioning, rig 4's decay, rig 6's scan window). While `scan`
/// is set and true, epochs are contaminated exactly the way the
/// daemon's glue contaminates them for an active index scan - OR'd
/// into the rate_limited flag.
async fn leg(
    srv: &MockServer,
    ids: Vec<ArticleReq>,
    spawn: usize,
    start: usize,
    tuned: bool,
    epoch: Duration,
    events: Vec<(f64, Box<dyn Fn() + Send>)>,
    scan: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Leg {
    let mut sc: ServerConfig = srv.server_config();
    sc.connections = spawn as u32;
    let target = ConnTarget::new(start);
    // `shipped()`, not `default()`: the tuner never runs alone in the
    // product - it reads a rate that the racing knobs are also spending,
    // and a dup racing a straggler is bytes the controller then sees as
    // capacity. A/B'd on rigs 1a and 3 before the switch (11 Aug 2026):
    // both cleared their bands either way, and the shipped arm landed
    // marginally closer to the knee of 12 (target 11 in 58.6 s against
    // 10 in 63.1 s) - inside the noise of a contended box, so read it as
    // "the controller is not fooled by dup spend", not as a payout.
    // Rigs 2 and 4-6 were re-run under the shipped posture and hold.
    //
    // Run these ONE AT A TIME. Four of them at once on a 20-core box
    // failed rig 2 outright (target stuck at 7, needs 10) - four mock
    // lines competing for real CPU means the re-provisioned capacity is
    // not there to be found, and the controller is right not to chase
    // it. That is a rig artefact and it looks exactly like a regression.
    let cfg = PoolConfig {
        connections: spawn,
        ramp_delay: Duration::ZERO,
        live_target: Some(target.clone()),
        ..PoolConfig::shipped()
    };
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let total = ids.len();
    let done = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let done2 = done.clone();
    let collect = tokio::spawn(async move {
        let mut n = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                n += 1;
                done2.store(n, Ordering::Relaxed);
            }
        }
        n
    });

    // The controller loop: one EpochObs per epoch off the live gauges,
    // exactly what the daemon's driver will do. The tuner stops being
    // fed once the queue is near its tail - a drying queue measures the
    // queue (the "never probe when the queue is near empty" rule; here
    // the whole epoch is discarded via busy=false).
    let mut tuner = ServerTuner::new(start, spawn, 1);
    let mut targets_seen = vec![tuner.target()];
    let mut samples = Vec::new();
    let mut fired = vec![false; events.len()];
    let mut last_bytes = 0u64;
    loop {
        target.set(if tuned { tuner.desired() } else { start });
        live.servers[0]
            .budget
            .store(target.get(), Ordering::Relaxed);
        tokio::time::sleep(epoch).await;
        if fetch.is_finished() {
            break;
        }
        let n = done.load(Ordering::Relaxed);
        for (k, (frac, f)) in events.iter().enumerate() {
            if !fired[k] && (n as f64) >= total as f64 * frac {
                f();
                fired[k] = true;
            }
        }
        let bytes = live.servers[0].bytes.load(Ordering::Relaxed);
        let rate = (bytes - last_bytes) as f64 / epoch.as_secs_f64();
        last_bytes = bytes;
        let connected = live.servers[0].connected.load(Ordering::Relaxed);
        // Near-tail epochs are dirty by construction: not enough queue
        // left to keep the fleet busy for a whole epoch.
        let busy = total - n > target.get() * 8;
        let scan_active = scan.as_ref().is_some_and(|s| s.load(Ordering::Relaxed));
        // Band, like the daemon glue: an epoch whose fleet ended above
        // its rung is still draining a down-step - its bytes belong to
        // a bigger fleet and must not judge the rung (rig 7's lesson).
        let fm_tgt = target.get();
        let fleet_met = connected >= fm_tgt && connected <= fm_tgt + (fm_tgt / 32).max(2);
        let obs = EpochObs {
            rate_bps: rate,
            busy,
            rate_limited: scan_active,
            capacity_pressure: false,
            fleet_met,
            // Single-server rigs: no share race to synchronize against
            // and no shared-link anchor - gate every epoch, never
            // saturated, which is exactly the pre-metronome cadence.
            cycle_gate: true,
            line_saturated: false,
        };
        samples.push((rate, connected, busy && !scan_active && fleet_met));
        if tuned {
            tuner.on_epoch(obs);
            targets_seen.push(tuner.target());
        }
    }
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("leg hung")
        .unwrap();
    let wall = t0.elapsed();
    let done = collect.await.unwrap();
    assert_eq!(done, total, "articles lost during live tuning");
    Leg {
        wall,
        final_target: tuner.target(),
        targets_seen,
        samples,
    }
}

fn throttled(per_conn: u64, line: u64) -> Chaos {
    Chaos {
        throttle: Throttle {
            per_conn_bps: per_conn,
            line_bps: line,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Rig 1a: under-tuned start. Knee 12 (line 1.8 MB/s / 150 KB/s), fleet
/// starts at 4. The controller must walk up toward the knee and the
/// wall must beat the mistuned baseline - the James shape (a fleet
/// pinned far below the line for no physical reason).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~2 min) - run with --ignored"]
async fn rig1_convergence_from_under_tuned_beats_the_mistuned_wall() {
    let (articles, ids) = corpus(60_000_000);
    let srv = MockServer::start(articles, throttled(150_000, 1_800_000)).await;
    let epoch = Duration::from_millis(1500);
    let base = leg(&srv, ids.clone(), 4, 4, false, epoch, vec![], None).await;
    let tuned = leg(&srv, ids, 20, 4, true, epoch, vec![], None).await;
    eprintln!(
        "RIG1a base {:?} tuned {:?} final target {} path {:?}",
        base.wall, tuned.wall, tuned.final_target, tuned.targets_seen
    );
    assert!(
        tuned.final_target >= 9,
        "never approached the knee of 12: stopped at {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.final_target <= 15,
        "overshot the knee of 12: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.wall.as_secs_f64() < base.wall.as_secs_f64() * 0.75,
        "no payout over the mistuned wall: tuned {:?} vs base {:?}",
        tuned.wall,
        base.wall
    );
}

/// Rig 1b: over-tuned start. Knee 10 (600 KB/s / 60 KB/s), fleet starts
/// at 16. The mock's line shares fairly, so over-asking costs wall
/// nothing HERE (the field penalty is a provider behaviour the model
/// deliberately does not invent) - the claim is convergence: the
/// controller must shed the sockets the line cannot use, one per cycle
/// (down-moves have no early-keep path on purpose), and must not be
/// slower than the baseline by more than the probing overhead. The
/// slow line is what buys the walk enough epochs to finish.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~3 min) - run with --ignored"]
async fn rig1_convergence_from_over_tuned_sheds_useless_sockets() {
    let (articles, ids) = corpus(60_000_000);
    let srv = MockServer::start(articles, throttled(60_000, 600_000)).await;
    let epoch = Duration::from_millis(1500);
    let base = leg(&srv, ids.clone(), 16, 16, false, epoch, vec![], None).await;
    let tuned = leg(&srv, ids, 16, 16, true, epoch, vec![], None).await;
    eprintln!(
        "RIG1b base {:?} tuned {:?} final target {} path {:?}",
        base.wall, tuned.wall, tuned.final_target, tuned.targets_seen
    );
    assert!(
        tuned.final_target <= 12,
        "kept sockets the line cannot use: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.final_target >= 8,
        "shed past the knee of 10: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.wall.as_secs_f64() < base.wall.as_secs_f64() * 1.2,
        "probing overhead ate the run: tuned {:?} vs base {:?}",
        tuned.wall,
        base.wall
    );
}

/// Rig 2: the facts change mid-run. Knee starts at 6 (360 KB/s line),
/// the provider re-provisions to 1.08 MB/s (knee 18, above the spawned
/// ceiling of 14) once a third of the corpus is down. The controller
/// must notice and climb - the whole reason a live tuner exists over
/// the offline snapshot.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~2 min) - run with --ignored"]
async fn rig2_reconverges_after_a_mid_run_capacity_change() {
    let (articles, ids) = corpus(50_000_000);
    let srv = MockServer::start(articles, throttled(60_000, 360_000)).await;
    let epoch = Duration::from_millis(1500);
    let line = srv.line_control();
    let tuned = leg(
        &srv,
        ids,
        14,
        6,
        true,
        epoch,
        vec![(
            0.33,
            Box::new(move || line.set_line_bps(1_080_000)) as Box<dyn Fn() + Send>,
        )],
        None,
    )
    .await;
    eprintln!(
        "RIG2 wall {:?} final target {} path {:?}",
        tuned.wall, tuned.final_target, tuned.targets_seen
    );
    assert!(
        tuned.final_target >= 10,
        "did not follow the line up after the re-provision: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
}

/// Rig 3, the SAFETY gate: a flat healthy line with the fleet already
/// at the knee. The controller may probe (that is its job) but the KEPT
/// target must hold - every sampled target stays inside one connection
/// of the knee for the whole run. This is the gate the offline tuner's
/// history says noise-chasers fail; it cleared the adaptive timeout's
/// jitter gate in the same spirit.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~2 min) - run with --ignored"]
async fn rig3_a_flat_healthy_line_holds_steady() {
    let (articles, ids) = corpus(45_000_000);
    let srv = MockServer::start(articles, throttled(60_000, 600_000)).await;
    let epoch = Duration::from_millis(1500);
    let tuned = leg(&srv, ids, 20, 10, true, epoch, vec![], None).await;
    eprintln!(
        "RIG3 wall {:?} final target {} path {:?}",
        tuned.wall, tuned.final_target, tuned.targets_seen
    );
    for (i, t) in tuned.targets_seen.iter().enumerate() {
        assert!(
            (9..=11).contains(t),
            "epoch {i}: the kept target walked to {t} on a flat line (path {:?})",
            tuned.targets_seen
        );
    }
}

/// Rig 7: the surplus-trim rig, the 10 Aug five-client re-cut in
/// miniature (BENCHMARKS 2026-08-10: 360 sockets vs 40 ran the same
/// wall on apollo13, at a ~50% cpu_s premium). Knee 20 (line 600 KB/s
/// / 30 KB/s per conn), fleet PINNED at 100 for the baseline and
/// started at 100 for the tuned leg. The claims:
///
/// - the controller sheds the ~80 surplus sockets within the run
///   (geometric walk - a +/-1 walk could not cross 80 sockets in any
///   corpus this suite could afford),
/// - the wall pays nothing for the trim (the sockets were surplus:
///   equal wall IS the evidence they bought nothing),
/// - the trim never dips below the knee band (the giganews guard: a
///   fleet whose sockets all carry rate must keep them).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~5 min) - run with --ignored"]
async fn rig7_a_surplus_fleet_is_trimmed_at_no_wall_cost() {
    // Small articles: a parked slot only frees after finishing its
    // article, and in the SURPLUS regime each of 100 sockets carries
    // line/100 = 6 KB/s, so a 20 KB article pins the park wave for
    // ~3 s. Production articles drain in ~0.2 s at real line rates; a
    // 4 KB article keeps the same ratio to a 2.5 s epoch here. At 20 KB
    // no down-step of any size could settle inside the epoch and the
    // fleet_met band (correctly) aborted every trim cycle.
    let (articles, ids) = corpus_seg(140_000_000, 4_000);
    let srv = MockServer::start(articles, throttled(30_000, 600_000)).await;
    let epoch = Duration::from_millis(2500);
    let base = leg(&srv, ids.clone(), 100, 100, false, epoch, vec![], None).await;
    let tuned = leg(&srv, ids, 100, 100, true, epoch, vec![], None).await;
    eprintln!(
        "RIG7 base {:?} tuned {:?} final target {} path {:?}",
        base.wall, tuned.wall, tuned.final_target, tuned.targets_seen
    );
    assert!(
        tuned.final_target <= 32,
        "kept {} sockets against a knee of 20 - the surplus was not trimmed (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.final_target >= 17,
        "trimmed past the knee of 20: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    // Never below the knee band at ANY sampled epoch: a trim verdict
    // that costs rate must fail, so the walk may touch the knee but
    // must not cut into it.
    for (i, t) in tuned.targets_seen.iter().enumerate() {
        assert!(
            *t >= 16,
            "epoch {i}: the kept target cut below the knee to {t} (path {:?})",
            tuned.targets_seen
        );
    }
    assert!(
        tuned.wall.as_secs_f64() < base.wall.as_secs_f64() * 1.15,
        "the trim cost wall time: tuned {:?} vs base {:?}",
        tuned.wall,
        base.wall
    );
}

/// Feed one leg's measured epochs to the decay detector as a single
/// download stretch, exactly as the daemon's glue would: clean epochs
/// only, per-connection rate = delivered rate / connected sockets.
/// Returns every verdict the stretch produced.
fn feed_stretch(
    det: &mut ShapeDetector,
    l: &Leg,
    reference: f64,
    stretch: u64,
) -> Vec<ShapeVerdict> {
    l.samples
        .iter()
        .filter(|(_, c, clean)| *clean && *c > 0)
        .map(|(rate, c, _)| det.on_epoch(rate / *c as f64, reference, stretch, true))
        .collect()
}

/// Median per-connection rate over a leg's clean epochs - what the
/// bucketed store would hold as `per_conn_bps` after the leg.
fn ref_per_conn(l: &Leg) -> f64 {
    let mut v: Vec<f64> = l
        .samples
        .iter()
        .filter(|(_, c, clean)| *clean && *c > 0)
        .map(|(rate, c, _)| rate / *c as f64)
        .collect();
    v.sort_by(|a, b| a.total_cmp(b));
    assert!(!v.is_empty(), "no clean epochs to build a reference from");
    v[v.len() / 2]
}

/// Rig 4: shaping decay (design §6). One provider, one story told in
/// legs: a healthy stretch builds the reference, a 20% dip must not
/// alarm, a 10x line decay must walk the controller DOWN without a
/// single up-move, the decay flag must hold through ONE bad stretch
/// and raise on the second, and scripted recovery must clear it on
/// the same quorum shape.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~3 min) - run with --ignored"]
async fn rig4_shaping_decay_raises_and_clears_on_quorum() {
    let (articles, ids) = corpus(60_000_000);
    let srv = MockServer::start(articles, throttled(150_000, 1_800_000)).await;
    let epoch = Duration::from_millis(1500);
    let line = srv.line_control();

    // Healthy stretch: fleet at the knee of 12, reference learned.
    let healthy = leg(&srv, ids.clone(), 20, 12, true, epoch, vec![], None).await;
    let reference = ref_per_conn(&healthy);
    eprintln!(
        "RIG4 healthy wall {:?} ref {:.0} bps/conn path {:?}",
        healthy.wall, reference, healthy.targets_seen
    );

    // A 20% dip is ordinary provider weather. Feed the same measured
    // stretch twice under different stretch ids: however many
    // stretches it spans, it must never raise.
    line.set_line_bps(1_440_000);
    let dip = leg(
        &srv,
        ids[..1500].to_vec(),
        20,
        12,
        true,
        epoch,
        vec![],
        None,
    )
    .await;
    let mut det20 = ShapeDetector::new(false);
    let mut v = feed_stretch(&mut det20, &dip, reference, 10);
    v.extend(feed_stretch(&mut det20, &dip, reference, 11));
    assert!(
        v.iter().all(|v| *v == ShapeVerdict::Hold) && !det20.shaped(),
        "a 20% dip must not read as shaping: {v:?}"
    );

    // The provider decays 10x. Two decayed stretches; the controller
    // walks down through both.
    line.set_line_bps(180_000);
    let mut det = ShapeDetector::new(false);
    let bad1 = leg(
        &srv,
        ids[..300].to_vec(),
        20,
        healthy.final_target,
        true,
        epoch,
        vec![],
        None,
    )
    .await;
    let v1 = feed_stretch(&mut det, &bad1, reference, 1);
    eprintln!(
        "RIG4 bad1 wall {:?} path {:?}",
        bad1.wall, bad1.targets_seen
    );
    assert!(
        v1.iter().all(|v| *v == ShapeVerdict::Hold) && !det.shaped(),
        "one bad stretch is one bad evening - the flag must wait for a second: {v1:?}"
    );
    let bad2 = leg(
        &srv,
        ids[..300].to_vec(),
        20,
        bad1.final_target,
        true,
        epoch,
        vec![],
        None,
    )
    .await;
    let v2 = feed_stretch(&mut det, &bad2, reference, 2);
    eprintln!(
        "RIG4 bad2 wall {:?} path {:?}",
        bad2.wall, bad2.targets_seen
    );
    assert!(
        v2.contains(&ShapeVerdict::Raised) && det.shaped(),
        "a second decayed stretch must fill the quorum: {v2:?}"
    );

    // Walk-down without oscillation: across both decayed legs the kept
    // target never moves UP - on a line this saturated an extra socket
    // cannot earn its keep, so any up-move would be noise-chasing.
    let walk: Vec<usize> = bad1
        .targets_seen
        .iter()
        .chain(bad2.targets_seen.iter())
        .copied()
        .collect();
    assert!(
        walk.windows(2).all(|w| w[1] <= w[0]),
        "the decayed walk must be monotone down: {walk:?}"
    );
    assert!(
        bad2.final_target < healthy.final_target,
        "10x decay must shed sockets: {} -> {}",
        healthy.final_target,
        bad2.final_target
    );

    // Scripted recovery: same quorum shape on the clear side (80% of
    // the reference it fell from), across two stretches.
    line.set_line_bps(1_800_000);
    let rec1 = leg(
        &srv,
        ids[..1500].to_vec(),
        20,
        bad2.final_target,
        true,
        epoch,
        vec![],
        None,
    )
    .await;
    let v3 = feed_stretch(&mut det, &rec1, reference, 3);
    assert!(
        det.shaped(),
        "one recovered stretch must not clear alone: {v3:?}"
    );
    let rec2 = leg(
        &srv,
        ids[..1000].to_vec(),
        20,
        rec1.final_target,
        true,
        epoch,
        vec![],
        None,
    )
    .await;
    let v4 = feed_stretch(&mut det, &rec2, reference, 4);
    eprintln!(
        "RIG4 recovery paths {:?} / {:?}",
        rec1.targets_seen, rec2.targets_seen
    );
    assert!(
        v4.contains(&ShapeVerdict::Cleared) && !det.shaped(),
        "recovery across two stretches must clear the flag: {v4:?}"
    );
}

/// Rig 5: warm start (design §5.1). A persisted seed must make the
/// second daemon run converge measurably faster than the cold one -
/// and a WRONG seed, in either direction, must be escaped within a
/// bounded epoch count. That bound is the structural James immunity:
/// with a seed-only store there is no state a bad sample can occupy
/// that outlives the next few clean epochs.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~3 min) - run with --ignored"]
async fn rig5_warm_start_reconverges_faster_and_escapes_wrong_seeds() {
    let (articles, ids) = corpus(130_000_000);
    let srv = MockServer::start(articles, throttled(150_000, 1_800_000)).await;
    let epoch = Duration::from_millis(1500);

    // Cold start at a low prior (a fresh install's configured-count
    // seed on a small account) - also the wrong-LOW seed case.
    let cold = leg(&srv, ids[..3000].to_vec(), 20, 4, true, epoch, vec![], None).await;
    let entry = |l: &Leg| l.targets_seen.iter().position(|t| *t >= 9);
    let cold_entry = entry(&cold).expect("cold leg never approached the knee");
    eprintln!(
        "RIG5 cold wall {:?} entry {} path {:?}",
        cold.wall, cold_entry, cold.targets_seen
    );
    assert!(cold_entry > 0, "a cold start cannot begin at the knee");
    assert!(
        cold_entry <= 40,
        "the wrong-LOW seed must be escaped within a bounded walk: {} ({:?})",
        cold_entry,
        cold.targets_seen
    );

    // Warm start: seeded from the cold leg's final belief, exactly what
    // the bucketed store hands the next daemon run.
    let warm = leg(
        &srv,
        ids[..3000].to_vec(),
        20,
        cold.final_target,
        true,
        epoch,
        vec![],
        None,
    )
    .await;
    let warm_entry = entry(&warm).expect("warm leg fell out of the band");
    eprintln!(
        "RIG5 warm wall {:?} entry {} path {:?}",
        warm.wall, warm_entry, warm.targets_seen
    );
    assert!(
        warm_entry < cold_entry,
        "a warm seed must reach the knee band faster than cold ({warm_entry} vs {cold_entry})"
    );
    assert!(
        (9..=15).contains(&warm.final_target),
        "warm run wandered off the knee: {} ({:?})",
        warm.final_target,
        warm.targets_seen
    );

    // Wrong-HIGH seed: a stale bucket claiming 18 against a knee of 12.
    // The down-walk has no fast path on purpose, so the bound is wider,
    // but it must still be a bound.
    let high = leg(&srv, ids.clone(), 20, 18, true, epoch, vec![], None).await;
    let escape = high.targets_seen.iter().position(|t| *t <= 14);
    eprintln!(
        "RIG5 high wall {:?} path {:?}",
        high.wall, high.targets_seen
    );
    let escape = escape.expect("the wrong-HIGH seed was never walked back");
    assert!(
        escape <= 50,
        "the wrong-HIGH seed must be escaped within a bounded walk: {} ({:?})",
        escape,
        high.targets_seen
    );
}

/// Rig 6: scan contamination (design §5.3). Mid-run, an index-scan
/// shaped disturbance arrives: the link loses most of its capacity to
/// a header pull while `scan_active` is flagged. The contaminated
/// epochs must ABORT the tuner's cycles rather than bend them - the
/// kept target holds through the window and after it, where an
/// unprotected controller would have shed real sockets chasing the
/// scan's traffic.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~2 min) - run with --ignored"]
async fn rig6_a_scan_contaminated_cycle_aborts_and_holds() {
    let (articles, ids) = corpus(60_000_000);
    let srv = MockServer::start(articles, throttled(150_000, 1_800_000)).await;
    let epoch = Duration::from_millis(1500);
    let scan = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let line_drop = srv.line_control();
    let line_back = srv.line_control();
    let scan_on = scan.clone();
    let scan_off = scan.clone();
    let tuned = leg(
        &srv,
        ids,
        20,
        12,
        true,
        epoch,
        vec![
            (
                0.30,
                Box::new(move || {
                    // The header pull takes 80% of the link...
                    line_drop.set_line_bps(360_000);
                    scan_on.store(true, Ordering::Relaxed);
                }) as Box<dyn Fn() + Send>,
            ),
            (
                0.50,
                Box::new(move || {
                    line_back.set_line_bps(1_800_000);
                    scan_off.store(false, Ordering::Relaxed);
                }) as Box<dyn Fn() + Send>,
            ),
        ],
        Some(scan.clone()),
    )
    .await;
    eprintln!(
        "RIG6 wall {:?} final target {} path {:?}",
        tuned.wall, tuned.final_target, tuned.targets_seen
    );
    // Uncontaminated, ~20 epochs at a line of 360k (knee 2.4) walk the
    // target well below the band; contaminated, every one of those
    // epochs aborts and the belief never moves off the knee.
    for (i, t) in tuned.targets_seen.iter().enumerate() {
        assert!(
            (11..=13).contains(t),
            "epoch {i}: the target moved to {t} during/after the scan window (path {:?})",
            tuned.targets_seen
        );
    }
}
