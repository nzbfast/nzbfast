//! M7b.2 steering + racing rig (§8 steps 2-4 of
//! research/DESIGN-PROVIDER-STEERING-RACING-2026-08-08.md): the shaped
//! provider shape in a box, the baseline every later step is priced
//! against, and the safety legs for depth steering (§4.1) and envelope
//! racing (§5.1/5.2/5.5).
//!
//! The shape mirrors the live specimen (memory
//! nzbfast-giganews-shaping): one server serves CORRECT bytes at 1/8th
//! of the healthy per-conn rate beside a full-speed twin. Nothing ever
//! faults, so every second of cost is per-article serve time on shaped
//! connections. Article size and per-conn rates are scaled so a shaped
//! article's serve time (~400 ms) matches the measured live shape
//! (~800 KB at ~15 Mbps = ~430 ms) while the corpus stays test sized.
//!
//! What each leg measures, in the design's own terms:
//!
//! - **wall**: the whole job.
//! - **tail seconds**: from the pool's own `tail` event (a primary
//!   found the queue dry with work still in flight) to run end. This
//!   is where every measured racing payout lives.
//! - **hostage bytes**: bytes the shaped server delivered AFTER the
//!   queue ran dry - what was parked behind its slow pipelines when
//!   the fast fleet went idle. The design's depth-steering target
//!   (~83 MB -> ~21 MB on the live 26-conn shape).
//! - **dup spend**: `LiveStats::race` - dups issued, wins, and the
//!   bytes of losing copies the hygiene cap bounds.
//!
//! Wall-clock legs are `#[ignore]`d (house rule for measurement rigs);
//! the structural legs run in CI and pin the invariants: a shaped
//! provider is never demoted (§129 3d), racing loses no data and
//! misfiles nothing against a desynced bare-refusing server (§5.5),
//! and the corrupt-storm refetch exemption holds under the new arming.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use nzbkit::config::ServerConfig;
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::pool::{
    ArticleReq, DecodeAck, DecodeReport, FetchOutcome, LiveStats, PoolConfig, QueueControl,
    fetch_all_multi_ctl,
};
use tokio::sync::mpsc;

/// Payload bytes per article: with the shaped per-conn rate below this
/// serves in ~400 ms on a shaped connection - the live shape's ~430 ms.
const ART: usize = 100_000;
/// Healthy per-connection ceiling, bytes/sec.
const FAST_BPS: u64 = 2_000_000;
/// Shaped per-connection ceiling: 1/8th of healthy (live specimen:
/// ~15 Mbps shaped against ~120-165 clean).
const SHAPED_BPS: u64 = 250_000;
/// Connections per server.
const CONNS: usize = 4;
/// Pipeline window - the default the daemon runs, and the depth the
/// hostage-byte measurement is ABOUT (window articles parked per slow
/// connection).
const WINDOW: usize = 4;

fn corpus(n: usize) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..(n * ART) as u32).map(|i| (i >> 3) as u8).collect();
    let mut articles = HashMap::new();
    let segs = make_file_articles("steer.bin", &data, ART, "sr", &mut articles);
    let reqs = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>").into(),
            age_days: 0,
            part: *part,
        })
        .collect();
    (articles, reqs)
}

fn throttled(bps: u64) -> Chaos {
    Chaos {
        throttle: Throttle {
            per_conn_bps: bps,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The daemon's race_stragglers-ON posture, which is what any A/B here
/// must hold still while steering knobs move.
///
/// The four knobs are `PoolConfig::shipped()`'s racing half, spelled
/// out rather than taken from it: `shipped()` also arms
/// `adaptive_timeout`, and every leg here runs against a deliberately
/// crawling mock, where the read budget would become a second moving
/// part. It is off in BOTH arms, so the steering comparison holds.
fn racing_cfg() -> PoolConfig {
    PoolConfig {
        connections: CONNS,
        window: WINDOW,
        ramp_delay: Duration::from_millis(0),
        tail_fanout: true,
        tail_fanout_early: true,
        hedge: true,
        recycle_slope: true,
        ..PoolConfig::default()
    }
}

/// The steering arm: the same racing posture with depth steering armed.
fn steered_cfg() -> PoolConfig {
    PoolConfig {
        steer_depth: true,
        ..racing_cfg()
    }
}

/// The full M7b.2 arm: depth steering + envelope racing + hygiene cap.
fn envelope_cfg() -> PoolConfig {
    PoolConfig {
        race_envelope: true,
        ..steered_cfg()
    }
}

fn server_for(srv: &MockServer, cfg: PoolConfig) -> (ServerConfig, PoolConfig) {
    let mut sc = srv.server_config();
    sc.connections = CONNS as u32;
    (sc, cfg)
}

/// One leg's price, in the design's currency.
struct Cost {
    label: String,
    wall: Duration,
    done: usize,
    /// Terminal Missing + Failed outcomes.
    lost: usize,
    /// Bodies the consumer OWNED that failed their yEnc CRC.
    owned_bad: usize,
    /// Bodies owned under the WRONG id (payload part disagrees) - a
    /// desync's silent-swap damage; no CRC can catch it.
    misfiled: usize,
    /// None = the queue never ran dry before the last article landed.
    tail: Option<Duration>,
    /// Per-server bytes delivered AFTER the tail latch.
    tail_bytes: Vec<u64>,
    /// Whole-run per-server bytes and dispatch counts.
    bytes: Vec<u64>,
    tried: Vec<u64>,
    /// `ServerLive::steered` at run end - the tuner's contamination
    /// bit, set while a server is depth-clamped.
    steered: Vec<bool>,
    /// The run-level racing gauges (dups issued, wins, losing bytes).
    dups: u64,
    dup_wins: u64,
    dup_lost: u64,
}

impl Cost {
    fn line(&self) -> String {
        format!(
            "{:<24} wall {:>5.2}s  tail {}  hostage {:>5.2} MB  split {:.1}/{:.1} MB  \
             dups {}({} won) lost {:.2} MB  done {}",
            self.label,
            self.wall.as_secs_f64(),
            self.tail
                .map(|t| format!("{:>5.2}s", t.as_secs_f64()))
                .unwrap_or_else(|| "  none".into()),
            self.tail_bytes.get(1).copied().unwrap_or(0) as f64 / 1e6,
            self.bytes.first().copied().unwrap_or(0) as f64 / 1e6,
            self.bytes.get(1).copied().unwrap_or(0) as f64 / 1e6,
            self.dups,
            self.dup_wins,
            self.dup_lost as f64 / 1e6,
            self.done,
        )
    }
}

/// Run one leg over prepared mocks and price it. The collector plays
/// the decode consumer (the crc_steer seam), verifying every owned
/// body's CRC and part identity; the tail watcher polls the pool's own
/// event ring for the `tail` phase marker and snapshots per-server
/// bytes at that moment.
async fn run(label: &str, mocks: Vec<(&MockServer, PoolConfig)>, reqs: Vec<ArticleReq>) -> Cost {
    let servers: Vec<(ServerConfig, PoolConfig)> = mocks
        .iter()
        .map(|(m, cfg)| server_for(m, cfg.clone()))
        .collect();
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let expected_part: HashMap<Arc<str>, u32> =
        reqs.iter().map(|r| (r.id.clone(), r.part)).collect();
    let ctl = Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let watcher = {
        let live = live.clone();
        tokio::spawn(async move {
            loop {
                let latched = live
                    .events
                    .lock()
                    .ok()
                    .map(|ring| ring.iter().any(|e| e.kind == "tail"))
                    .unwrap_or(false);
                if latched {
                    let at = Instant::now();
                    let snap: Vec<u64> = live
                        .servers
                        .iter()
                        .map(|s| s.bytes.load(Ordering::Relaxed))
                        .collect();
                    return Some((at, snap));
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    };
    let ctl_fetch = ctl.clone();
    let fetch =
        tokio::spawn(
            async move { fetch_all_multi_ctl(&servers, reqs, tx, Some(&ctl_fetch)).await },
        );
    let (mut done, mut lost, mut owned_bad, mut misfiled) = (0usize, 0usize, 0usize, 0usize);
    let mut scratch = Vec::new();
    while let Some(o) = rx.recv().await {
        match o {
            FetchOutcome::Done { id, raw } => {
                match nzbkit::yenc_simd::decode_into_integrity(&raw, &mut scratch, true) {
                    Err(_) => {
                        if ctl.note_decoded(
                            &id,
                            DecodeReport::Bad {
                                why: "yEnc decode/CRC failed",
                            },
                        ) == DecodeAck::Steered
                        {
                            continue;
                        }
                        done += 1;
                        owned_bad += 1;
                    }
                    Ok((meta, _)) => {
                        if ctl.note_decoded(&id, DecodeReport::Clean { part: meta.part })
                            == DecodeAck::Steered
                        {
                            continue;
                        }
                        if let (Some(want), Some(got)) = (expected_part.get(&*id), meta.part)
                            && *want != got
                        {
                            misfiled += 1;
                        }
                        done += 1;
                    }
                }
            }
            _ => lost += 1,
        }
    }
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .unwrap_or_else(|_| panic!("leg {label} hung"))
        .unwrap();
    let wall = t0.elapsed();
    watcher.abort();
    let snap = watcher.await.ok().flatten();
    let bytes: Vec<u64> = live
        .servers
        .iter()
        .map(|s| s.bytes.load(Ordering::Relaxed))
        .collect();
    let (tail, tail_bytes) = match snap {
        Some((at, at_bytes)) => (
            Some(wall.saturating_sub(at - t0)),
            bytes
                .iter()
                .zip(&at_bytes)
                .map(|(b, s)| b.saturating_sub(*s))
                .collect(),
        ),
        None => (None, vec![0; bytes.len()]),
    };
    Cost {
        label: label.to_string(),
        wall,
        done,
        lost,
        owned_bad,
        misfiled,
        tail,
        tail_bytes,
        tried: live
            .servers
            .iter()
            .map(|s| s.articles_tried.load(Ordering::Relaxed))
            .collect(),
        steered: live
            .servers
            .iter()
            .map(|s| s.steered.load(Ordering::Relaxed))
            .collect(),
        dups: live.race.dups_issued.load(Ordering::Relaxed),
        dup_wins: live.race.dup_wins.load(Ordering::Relaxed),
        dup_lost: live.race.dup_bytes_lost.load(Ordering::Relaxed),
        bytes,
    }
}

/// The standard fast+shaped pair (server 0 fast, server 1 shaped).
async fn shaped_leg(label: &str, n: usize, cfg: PoolConfig) -> Cost {
    let (articles, reqs) = corpus(n);
    let fast = MockServer::start(articles.clone(), throttled(FAST_BPS)).await;
    let shaped = MockServer::start(articles, throttled(SHAPED_BPS)).await;
    run(label, vec![(&fast, cfg.clone()), (&shaped, cfg)], reqs).await
}

/// CI structural leg: the work-conserving invariants hold against a
/// shaped provider with the racing machinery on. Small corpus, no
/// timing assertions - completion and attribution only.
#[tokio::test(flavor = "multi_thread")]
async fn shaped_provider_is_never_demoted_and_loses_nothing() {
    let n = 120;
    let c = shaped_leg("ci-shaped-structural", n, racing_cfg()).await;
    eprintln!("{}", c.line());
    assert_eq!(c.done, n, "every article must complete");
    assert_eq!(c.lost, 0, "a shaped (slow, correct) provider loses nothing");
    // §129 3d: a slow provider keeps fetching unique work. Zero bytes
    // from the shaped server means something demoted it.
    assert!(
        c.bytes[1] > 0,
        "the shaped server was effectively demoted (3d closed this): {}",
        c.line()
    );
    // Self-clocking: the fast fleet out-serves the shaped one.
    assert!(
        c.bytes[0] > c.bytes[1],
        "work-conservation should split load by realized rate: {}",
        c.line()
    );
}

/// CI structural leg for depth steering (§4.1): with the clamp armed,
/// the shaped server is the ONLY one clamped, it still fetches unique
/// work (never demoted - depth 1 is full participation at bounded
/// commitment), and nothing is lost. The `steered` bit is the tuner
/// contract (§4.3): it must be set on the clamped server and clear on
/// the fast one.
#[tokio::test(flavor = "multi_thread")]
async fn depth_steering_clamps_only_the_shaped_server_and_publishes_the_bit() {
    let n = 120;
    let c = shaped_leg("ci-steer-depth", n, steered_cfg()).await;
    eprintln!("{}", c.line());
    assert_eq!(c.done, n, "every article must complete");
    assert_eq!(c.lost, 0, "steering must not lose data");
    assert!(
        c.bytes[1] > 0,
        "a depth-clamped server still fetches unique work: {}",
        c.line()
    );
    assert!(
        c.steered[1],
        "the shaped server should end the run depth-clamped with its \
         steered bit published for the tuner: {}",
        c.line()
    );
    assert!(
        !c.steered[0],
        "the fast server must never read as steered - the ratio inverts: {}",
        c.line()
    );
}

/// CI structural leg for envelope racing: the full M7b.2 arm loses
/// nothing on the shaped shape and its dup spend stays a small
/// fraction of the hygiene cap's floor (the design's whole-tail
/// arithmetic: one tail round is at most a fleet's worth of articles).
#[tokio::test(flavor = "multi_thread")]
async fn envelope_racing_completes_clean_with_bounded_spend() {
    let n = 120;
    let c = shaped_leg("ci-envelope", n, envelope_cfg()).await;
    eprintln!("{}", c.line());
    assert_eq!(c.done, n, "every article must complete");
    assert_eq!(c.lost, 0, "racing must not lose data");
    assert_eq!(c.owned_bad, 0);
    assert_eq!(c.misfiled, 0);
    // The hygiene cap's job at this scale: losing bytes stay far under
    // the 32 MB floor - a whole tail round is ~a fleet of articles.
    assert!(
        c.dup_lost < 8 * (CONNS * WINDOW * ART) as u64,
        "dup spend blew past anything a tail can justify: {}",
        c.line()
    );
}

/// **The 5.5 safety leg**: a desynced, bare-refusing, SHAPED server
/// beside a clean fast twin, with envelope racing armed. Racing adds
/// answers to the 3g mix, so this pins its invariants: a raced hit
/// settles Done (never Missing), an un-echoed dup 430 is dropped never
/// merged, and positional desync never files a body under the wrong
/// id. Zero tolerance on all three.
#[tokio::test(flavor = "multi_thread")]
async fn raced_desync_never_creates_false_missing_or_misfiles() {
    let n = 240;
    let (articles, reqs) = corpus(n);
    let ids: Vec<Arc<str>> = reqs.iter().map(|r| r.id.clone()).collect();
    // 40% of the corpus absent ON THE DESYNCED SERVER ONLY (the twin
    // holds everything, so nothing may go terminally Missing), bare
    // refusals, one response in 5 silently withheld - an aggressive
    // desync dose (the shipped profile's default is 1-in-60).
    // The mock server is keyed by the wire id as a `String`, so the
    // absent set converts at that boundary; the pool side stays interned.
    let absent: std::collections::HashSet<String> = ids
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 5 < 2)
        .map(|(_, id)| id.to_string())
        .collect();
    let fast = MockServer::start(articles.clone(), throttled(FAST_BPS)).await;
    let desynced = MockServer::start(
        articles.clone(),
        Chaos {
            missing: absent.clone(),
            echo_missing_id: false,
            skip_nth_response: 5,
            throttle: Throttle {
                per_conn_bps: SHAPED_BPS,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        crc_steer: true,
        ..envelope_cfg()
    };
    let c = run(
        "ci-raced-desync",
        vec![(&fast, cfg.clone()), (&desynced, cfg)],
        reqs,
    )
    .await;
    eprintln!("{}", c.line());
    assert_eq!(
        c.lost, 0,
        "the twin holds every article - any Missing/Failed is a false \
         verdict minted by the desync + racing mix"
    );
    assert_eq!(c.done, n, "every article must complete");
    assert_eq!(
        c.misfiled, 0,
        "a body was filed under the wrong id - the desync leaked through \
         the racing paths"
    );
    assert_eq!(c.owned_bad, 0);
}

/// The corrupt-storm regression (design §7 leg 5): the tail-fanout
/// refetch dup-storm (33-43 dups, 0 won, on the old matrix) is the
/// standing example of a racing rule meeting the steer path badly. The
/// storm shape - one server corrupting every 3rd body, CRC steer
/// refetching each damaged article from the twin - must stay bounded
/// with the new arming active: at most one steer per id, byte-perfect
/// output.
#[tokio::test(flavor = "multi_thread")]
async fn corrupt_storm_stays_bounded_under_envelope_arming() {
    let n = 240;
    let (articles, reqs) = corpus(n);
    let fast = MockServer::start(articles.clone(), throttled(FAST_BPS)).await;
    let corrupting = MockServer::start(
        articles,
        Chaos {
            corrupt_every: 3,
            throttle: Throttle {
                per_conn_bps: FAST_BPS,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        crc_steer: true,
        ..envelope_cfg()
    };
    let c = run(
        "ci-corrupt-storm",
        vec![(&fast, cfg.clone()), (&corrupting, cfg)],
        reqs,
    )
    .await;
    eprintln!("{}", c.line());
    assert_eq!(c.done, n, "every article must complete");
    assert_eq!(
        c.owned_bad, 0,
        "the consumer must never own a corrupt body when a twin holds a \
         clean copy"
    );
    // The steer fires at most once per id (`crc_retried`), and racing
    // must not turn recovery fetches into a dup storm: the fleet-wide
    // dispatch overage stays within one steer per article plus the
    // racing tail's fleet-of-articles slack.
    let fleet: u64 = c.tried.iter().sum();
    let overage = fleet.saturating_sub(n as u64);
    assert!(
        overage <= n as u64 + (CONNS * WINDOW * 2) as u64,
        "{overage} extra dispatches for {n} articles - a refetch/racing \
         loop: {}",
        c.line()
    );
}

/// Baseline wall-clock measurement (step 2 of the build order): what
/// the shaped shape costs on current main, racing posture ON, before
/// depth steering exists. Run with --ignored and record the numbers.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock baseline measurement - run with --ignored"]
async fn baseline_shaped_tail_and_hostage_bytes() {
    let n = 400;
    let reps = 3;
    let mut lines = Vec::new();
    for r in 0..reps {
        let c = shaped_leg(&format!("baseline shaped r{r}"), n, racing_cfg()).await;
        assert_eq!((c.done, c.lost), (n, 0));
        lines.push(c.line());
    }
    eprintln!(
        "\nM7b.2 step 2 baseline ({n} articles x {ART} B, fast {FAST_BPS} B/s/conn x{CONNS}, shaped {SHAPED_BPS} B/s/conn x{CONNS}, window {WINDOW}):"
    );
    for l in &lines {
        eprintln!("  {l}");
    }
}

/// The step 3 A/B: depth steering off vs on, same shape, same racing
/// posture. The design's prediction: hostage bytes drop ~window-fold
/// and the tail with them. Run with --ignored.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock A/B measurement - run with --ignored"]
async fn depth_steering_ab_tail_and_hostage() {
    let n = 400;
    let reps = 3;
    let mut lines = Vec::new();
    for r in 0..reps {
        let c = shaped_leg(&format!("A steer-off r{r}"), n, racing_cfg()).await;
        assert_eq!((c.done, c.lost), (n, 0));
        lines.push(c.line());
    }
    for r in 0..reps {
        let c = shaped_leg(&format!("B steer-on  r{r}"), n, steered_cfg()).await;
        assert_eq!((c.done, c.lost), (n, 0));
        lines.push(c.line());
    }
    eprintln!(
        "\nM7b.2 step 3 depth-steering A/B ({n} articles x {ART} B, fast {FAST_BPS} x{CONNS}, shaped {SHAPED_BPS} x{CONNS}, window {WINDOW}):"
    );
    for l in &lines {
        eprintln!("  {l}");
    }
}

/// Envelope racing in isolation (depth steering OFF both arms): the
/// deep-pipeline case, where a shaped connection parks `window`
/// articles and the oldest crosses the age bound - the configuration
/// where the envelope race must carry the tail win alone. Run with
/// --ignored.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock A/B measurement - run with --ignored"]
async fn envelope_racing_solo_ab_deep_pipelines() {
    let n = 400;
    let reps = 3;
    let mut lines = Vec::new();
    for r in 0..reps {
        let c = shaped_leg(&format!("A race-off r{r}"), n, racing_cfg()).await;
        assert_eq!((c.done, c.lost), (n, 0));
        lines.push(c.line());
    }
    for r in 0..reps {
        let cfg = PoolConfig {
            race_envelope: true,
            ..racing_cfg()
        };
        let c = shaped_leg(&format!("B race-on  r{r}"), n, cfg).await;
        assert_eq!((c.done, c.lost), (n, 0));
        lines.push(c.line());
    }
    eprintln!(
        "\nM7b.2 step 4 envelope-racing SOLO A/B ({n} articles x {ART} B, fast {FAST_BPS} x{CONNS}, shaped {SHAPED_BPS} x{CONNS}, window {WINDOW}, steer_depth OFF both arms):"
    );
    for l in &lines {
        eprintln!("  {l}");
    }
}

/// The step 4 A/B (design §7 leg 2): depth steering held ON in both
/// arms, envelope racing off vs on. Prices the M7b.2 core: wall, tail,
/// dup spend against the hygiene budget, wins/losses. Run with
/// --ignored.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock A/B measurement - run with --ignored"]
async fn envelope_racing_ab_wall_and_spend() {
    let n = 400;
    let reps = 3;
    let mut lines = Vec::new();
    for r in 0..reps {
        let c = shaped_leg(&format!("A race-off r{r}"), n, steered_cfg()).await;
        assert_eq!((c.done, c.lost), (n, 0));
        lines.push(c.line());
    }
    for r in 0..reps {
        let c = shaped_leg(&format!("B race-on  r{r}"), n, envelope_cfg()).await;
        assert_eq!((c.done, c.lost), (n, 0));
        lines.push(c.line());
    }
    eprintln!(
        "\nM7b.2 step 4 envelope-racing A/B ({n} articles x {ART} B, fast {FAST_BPS} x{CONNS}, shaped {SHAPED_BPS} x{CONNS}, window {WINDOW}, steer_depth ON both arms):"
    );
    for l in &lines {
        eprintln!("  {l}");
    }
}
