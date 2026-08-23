//! The 430-ladder tail: how long a damaged post sits at zero
//! throughput AFTER its last payload byte is on disk.
//!
//! Measured on a 20-core ARM desktop over a 10 Gbps line (11 Aug 2026),
//! five real backbones, against a 6.6 GB REMUX with poisoned segments:
//! repair itself cost 0.69 s at damage 5 and 2.22 s at damage 60, but
//! the job's wall was 19 s and 31 s. The difference
//! is entirely a stall in front of repair - every payload byte
//! written, the wire idle, and articles reaching terminal Missing at
//! about six per second while the recovery volumes sat prefetched and
//! ready. Nothing was waiting on data; it was waiting on VERDICTS.
//!
//! A poisoned article is refused by every provider, and a terminal
//! Missing needs unanimity, so each one has to be asked of every
//! backbone. The cost was never the asking - it was that the pool
//! would only ask ONE question per connection at a time: in the
//! endgame a 430-laddering article was refused a place in a pipeline
//! that already held anything at all, so N articles across G backbones
//! cost N*G round trips divided by the connection count, and each
//! article's own G hops ran strictly one after another.
//!
//! This rig rebuilds that shape on loopback with mock providers whose
//! refusals carry a realistic delay, and reports the number that
//! matters: the gap between the last delivered body and the last
//! verdict. That gap IS the stall the progress line renders as
//! "0.0 MB/s, written 6.42 GB, (42 missing)".
//!
//! Both provider families are here on purpose. A non-echoing provider
//! (one whose "430 no such article" does not repeat the id back) is
//! asked twice for every article it does not have, because a bare
//! refusal is positional evidence only - see `Work::soft_430`. Three
//! of the five mocks echo and two do not, which is roughly what a real
//! five-provider fleet looks like.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use nzbkit::config::ServerConfig;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use nzbkit::pool::{
    ArticleReq, FetchOutcome, LiveStats, PoolConfig, QueueControl, fetch_all_multi,
    fetch_all_multi_ctl,
};
use tokio::sync::mpsc;

/// Payload bytes per healthy article.
const ART: usize = 8_000;
/// Backbones in the fleet, and connections on each - the shape of
/// the fleet the stall was measured on (5 providers, 20 connections).
const SERVERS: usize = 5;
const CONNS: usize = 4;
/// Healthy articles. Enough that the run has a real download phase to
/// finish before the ladder tail starts.
const N_GOOD: usize = 240;
/// A refusal's round trip. A real 430 is not free - the provider has
/// to fail to find the article - and this is the number that decides
/// how long a dead queue takes to drive to terminal. 40 ms is the
/// friendly end of what the real-provider legs saw.
const MISS_MS: u64 = 40;

/// What one leg cost.
struct Leg {
    label: String,
    wall: Duration,
    /// The stall: last delivered body to last terminal verdict. This is
    /// the quantity the fix is about.
    tail: Duration,
    done: usize,
    missing: usize,
    /// BODY commands the mocks logged, fleet-wide. The ladder's traffic
    /// bill - it may go UP when the tail gets shorter (asking three
    /// backbones at once costs the same questions, just not in series),
    /// but it must not explode.
    dispatched: u64,
}

impl Leg {
    fn line(&self) -> String {
        format!(
            "{:<28} wall {:>6.2}s   ladder tail {:>6.2}s   {} done, {} missing, \
             {} dispatches",
            self.label,
            self.wall.as_secs_f64(),
            self.tail.as_secs_f64(),
            self.done,
            self.missing,
            self.dispatched,
        )
    }
}

/// One leg: `n_dead` poisoned ids that every backbone refuses, mixed
/// into `N_GOOD` healthy ones, against a fleet built from `base`.
///
/// `base` is `PoolConfig::shipped()` everywhere that matters - the
/// endgame speculation layer this rig measures is the "Race slow
/// articles" setting, which is ON out of the box. The library's
/// `default()` arm survives only in the `--ignored` A/B table, as the
/// thing to compare against.
async fn ladder_leg(label: &str, n_dead: usize, base: PoolConfig) -> Leg {
    let data: Vec<u8> = (0..(ART * N_GOOD) as u32).map(|i| i as u8).collect();
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let segs = make_file_articles("payload.bin", &data, ART, "good", &mut articles);
    let dead: Vec<String> = (0..n_dead).map(|i| format!("<dead{i}@mock>")).collect();

    // Every backbone refuses every poisoned id. Three echo the id on
    // the refusal line, two answer bare - the split that decides
    // whether an article is asked once or twice per backbone.
    let mut mocks = Vec::new();
    for si in 0..SERVERS {
        let chaos = Chaos {
            missing: dead.iter().cloned().collect::<HashSet<String>>(),
            missing_delay_ms: MISS_MS,
            echo_missing_id: si % 2 == 0,
            ..Default::default()
        };
        mocks.push(MockServer::start(articles.clone(), chaos).await);
    }

    let servers: Vec<(ServerConfig, PoolConfig)> = mocks
        .iter()
        .map(|m| {
            let mut sc = m.server_config();
            sc.connections = CONNS as u32;
            (
                sc,
                PoolConfig {
                    connections: CONNS,
                    ramp_delay: Duration::from_millis(0),
                    ..base.clone()
                },
            )
        })
        .collect();
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();

    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    for id in &dead {
        reqs.push(ArticleReq::fresh(id.clone()));
    }

    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let collect = tokio::spawn(async move {
        let (mut done, mut missing) = (0usize, 0usize);
        // The two ends of the stall: when the payload stopped arriving,
        // and when the last verdict finally landed.
        let (mut last_done, mut last_missing) = (t0, t0);
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { .. } => {
                    done += 1;
                    last_done = Instant::now();
                }
                FetchOutcome::Missing { .. } => {
                    missing += 1;
                    last_missing = Instant::now();
                }
                FetchOutcome::Failed { .. } => {}
            }
        }
        (done, missing, last_done, last_missing)
    });
    tokio::time::timeout(Duration::from_secs(180), fetch)
        .await
        .expect("ladder leg hung")
        .unwrap();
    let wall = t0.elapsed();
    let (done, missing, last_done, last_missing) = collect.await.unwrap();
    let dispatched: u64 = mocks
        .iter()
        .map(|m| m.body_log.lock().unwrap().len() as u64)
        .sum();
    Leg {
        label: label.to_string(),
        wall,
        tail: last_missing.saturating_duration_since(last_done),
        done,
        missing,
        dispatched,
    }
}

/// THE CONTRACT, in two clauses that do not depend on how fast the box
/// is.
///
/// **More damage must never be FASTER.** The endgame begins when the
/// job's remainder drops to `ENDGAME_MAX` (64) articles, so damage 60
/// runs inside it and damage 120 starts outside. Above that count the
/// endgame rules are dark and laddering articles pipeline
/// freely; at or below it they were refused a place in any pipeline
/// that held anything at all, so the fleet could carry only one
/// outstanding verdict per connection. Damage 60 sat inside that
/// penalty box and damage 120 did not, and the rig measured exactly
/// that inversion: 6.28 s of tail against 4.69 s for twice the work.
/// A monotonic ladder is the signature of the box being gone, and it
/// says nothing about clock speed.
///
/// Both clauses are asserted against `PoolConfig::shipped()` - the
/// posture with "Race slow articles" and adaptive timeouts on, which is
/// what a user gets. They were first measured on `default()`, with that
/// whole layer dark, and they held there too: the shape being pinned is
/// the endgame's REFUSAL to pipeline verdicts, which the speculation
/// knobs do not create and cannot paper over. Run the `--ignored` table
/// for the A/B if a change here needs the difference.
///
/// **And the tail must stay near what the refusals themselves cost.**
/// Every question this fleet asks is one mock refusal, and the mocks
/// answer serially per connection, so the whole tail can never beat
/// `questions / connections * MISS_MS`. Landing within a small
/// multiple of that floor means the wall belongs to the provider and
/// not to the pool's own scheduling. The fixed shape measures ~1.1x;
/// the old one measured ~6.7x, because each article's five hops ran
/// strictly in series and each hop cost a whole queue rotation.
#[tokio::test(flavor = "multi_thread")]
async fn a_poisoned_tail_reaches_its_verdicts_in_round_trips_not_rotations() {
    let mid = ladder_leg("damage 60", 60, PoolConfig::shipped()).await;
    let big = ladder_leg("damage 120", 120, PoolConfig::shipped()).await;
    println!("\n430-ladder tail:\n  {}\n  {}", mid.line(), big.line());
    for (leg, dead) in [(&mid, 60), (&big, 120)] {
        assert_eq!(leg.done, N_GOOD, "{} lost healthy articles", leg.label);
        assert_eq!(
            leg.missing, dead,
            "{} left poisoned articles without a verdict",
            leg.label
        );
    }
    assert!(
        mid.tail < big.tail,
        "damage 60 is in a penalty box damage 120 escapes: {:?} of tail \
         against {:?} for twice the damage - the endgame is refusing to \
         pipeline verdicts again",
        mid.tail,
        big.tail,
    );
    // Refusals the fleet had to buy, and the wall they cannot beat.
    let questions = mid.dispatched.saturating_sub(N_GOOD as u64);
    let floor = Duration::from_millis(questions * MISS_MS / (SERVERS * CONNS) as u64);
    assert!(
        mid.tail < floor * 4,
        "the ladder tail is back: {:?} against a {:?} refusal floor for \
         {questions} questions",
        mid.tail,
        floor,
    );
    // The fan-out asks the same questions in parallel rather than more
    // of them: at most one per backbone per article, plus the single
    // confirming repeat each non-echoing provider still owes on the
    // refusal that arms its fence.
    let ceiling = 60 * 7;
    assert!(
        questions < ceiling,
        "ladder dispatches ran away: {questions} against a {ceiling} ceiling",
    );
}

/// §146 tail give-up: the whole ladder tail is OPTIONAL when parity
/// already covers the walkers - and this rig proves the pool half of
/// that bargain. A side task plays the runner's part: it polls
/// `verdict_walkers` (which answers only when every pending article is
/// refusal-tainted - the exact state the stall consists of) and commits
/// `give_up_covered` on whatever the census returns, exactly as the
/// runner does once the PAR2 arithmetic holds. The run must then end
/// within round trips of the last delivered body instead of walking 60
/// articles through five backbones' refusal charges - without losing a
/// single healthy article, and without fabricating a verdict for the
/// walkers it claimed: a given-up article gets NO outcome, because the
/// caller (repair) owns its bytes now.
#[tokio::test(flavor = "multi_thread")]
async fn a_covered_tail_ends_in_ticks_not_ladder_walks() {
    const N_DEAD: usize = 60;
    let data: Vec<u8> = (0..(ART * N_GOOD) as u32).map(|i| i as u8).collect();
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let segs = make_file_articles("payload.bin", &data, ART, "good", &mut articles);
    let dead: Vec<String> = (0..N_DEAD).map(|i| format!("<dead{i}@mock>")).collect();
    let mut mocks = Vec::new();
    for si in 0..SERVERS {
        let chaos = Chaos {
            missing: dead.iter().cloned().collect::<HashSet<String>>(),
            missing_delay_ms: MISS_MS,
            echo_missing_id: si % 2 == 0,
            ..Default::default()
        };
        mocks.push(MockServer::start(articles.clone(), chaos).await);
    }
    let servers: Vec<(ServerConfig, PoolConfig)> = mocks
        .iter()
        .map(|m| {
            let mut sc = m.server_config();
            sc.connections = CONNS as u32;
            (
                sc,
                // Same posture as `ladder_leg` above, and for the same
                // reason: the give-up bargain is struck in the endgame,
                // which is where the shipped speculation layer lives.
                PoolConfig {
                    connections: CONNS,
                    ramp_delay: Duration::from_millis(0),
                    ..PoolConfig::shipped()
                },
            )
        })
        .collect();
    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    for id in &dead {
        reqs.push(ArticleReq::fresh(id.clone()));
    }

    let ctl = Arc::new(QueueControl::default());
    let claimed = Arc::new(AtomicUsize::new(0));
    let runner = {
        let ctl = ctl.clone();
        let claimed = claimed.clone();
        tokio::spawn(async move {
            loop {
                if let Some(walkers) = ctl.verdict_walkers() {
                    claimed.fetch_add(ctl.give_up_covered(&walkers).len(), Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };

    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = {
        let ctl = ctl.clone();
        tokio::spawn(async move { fetch_all_multi_ctl(&servers, reqs, tx, Some(&ctl)).await })
    };
    let collect = tokio::spawn(async move {
        let (mut done, mut missing) = (0usize, 0usize);
        let mut last_done = t0;
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { .. } => {
                    done += 1;
                    last_done = Instant::now();
                }
                FetchOutcome::Missing { .. } => missing += 1,
                FetchOutcome::Failed { .. } => {}
            }
        }
        (done, missing, last_done)
    });
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("give-up leg hung")
        .unwrap();
    let sealed = Instant::now();
    runner.abort();
    let (done, missing, last_done) = collect.await.unwrap();
    let claimed = claimed.load(Ordering::Relaxed);
    let tail = sealed.saturating_duration_since(last_done);
    println!(
        "\ncovered-tail give-up: wall {:.2}s, tail {:.2}s, {done} done, \
         {missing} missing, {claimed} given up",
        t0.elapsed().as_secs_f64(),
        tail.as_secs_f64(),
    );
    assert_eq!(
        done, N_GOOD,
        "the give-up must never touch a healthy article"
    );
    assert_eq!(
        missing + claimed,
        N_DEAD,
        "every walker ends exactly once: a unanimity verdict it earned \
         early, or the give-up - never both, never neither"
    );
    assert!(
        claimed > 0,
        "the census never opened - the whole leg walked the ladder"
    );
    // The pure ladder cannot beat questions/connections round trips
    // (the floor the fixed shape measures ~1.1x of). The give-up owes
    // only the census latency: the last un-evidenced walkers' first
    // refusal, a poll tick, and the fleet's wind-down. Half the
    // ladder's floor is a generous, box-speed-independent bound.
    let floor = Duration::from_millis(
        N_DEAD as u64 * (SERVERS as u64 + 2) * MISS_MS / (SERVERS * CONNS) as u64,
    );
    assert!(
        tail < floor / 2,
        "a covered tail still walked the ladder: {tail:?} against a \
         {floor:?} full-ladder floor"
    );
}

/// §96 item 4 measurement: the CROSS-SERVER PIECING shape, where the
/// ladder's fan-out is not asking about a poisoned article but about one
/// that several backbones actually HAVE. Every racer that holds it
/// delivers a whole body and exactly one claim wins, so the rest are
/// paid for and thrown away. `n_hole` articles are refused by the first
/// `SERVERS - holders` backbones and served by the last `holders`.
///
/// `interleave` decides where the holes sit in the request order. A real
/// job's holes are spread through it; parking them all at the end is the
/// worst case, because the fan-out only fires once the endgame (or the
/// tail latch) is open and every hole is then inside it.
async fn hole_leg(
    label: &str,
    n_hole: usize,
    holders: usize,
    interleave: bool,
    base: PoolConfig,
) -> HoleLeg {
    let data: Vec<u8> = (0..(ART * N_GOOD) as u32).map(|i| i as u8).collect();
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let segs = make_file_articles("payload.bin", &data, ART, "good", &mut articles);
    // The hole articles are real payload - the same size as any other -
    // so a wasted copy costs exactly what a needed one does.
    let hdata: Vec<u8> = (0..(ART * n_hole) as u32).map(|i| (i >> 3) as u8).collect();
    let hole: Vec<String> = make_file_articles("hole.bin", &hdata, ART, "hole", &mut articles)
        .iter()
        .map(|(id, _, _)| format!("<{id}>"))
        .collect();
    let refusers = SERVERS - holders;
    let mut mocks = Vec::new();
    for si in 0..SERVERS {
        let chaos = Chaos {
            missing: if si < refusers {
                hole.iter().cloned().collect::<HashSet<String>>()
            } else {
                HashSet::new()
            },
            missing_delay_ms: MISS_MS,
            echo_missing_id: si % 2 == 0,
            ..Default::default()
        };
        mocks.push(MockServer::start(articles.clone(), chaos).await);
    }
    let servers: Vec<(ServerConfig, PoolConfig)> = mocks
        .iter()
        .map(|m| {
            let mut sc = m.server_config();
            sc.connections = CONNS as u32;
            (
                sc,
                PoolConfig {
                    connections: CONNS,
                    ramp_delay: Duration::from_millis(0),
                    ..base.clone()
                },
            )
        })
        .collect();
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();

    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    if interleave {
        let step = (reqs.len() / n_hole.max(1)).max(1);
        for (i, id) in hole.iter().enumerate() {
            let at = ((i + 1) * step).min(reqs.len());
            reqs.insert(at, ArticleReq::fresh(id.clone()));
        }
    } else {
        for id in &hole {
            reqs.push(ArticleReq::fresh(id.clone()));
        }
    }

    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let collect = tokio::spawn(async move {
        let (mut done, mut missing) = (0usize, 0usize);
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { .. } => done += 1,
                FetchOutcome::Missing { .. } => missing += 1,
                FetchOutcome::Failed { .. } => {}
            }
        }
        (done, missing)
    });
    tokio::time::timeout(Duration::from_secs(180), fetch)
        .await
        .expect("hole leg hung")
        .unwrap();
    let wall = t0.elapsed();
    let (done, missing) = collect.await.unwrap();
    let holeset: HashSet<&str> = hole.iter().map(String::as_str).collect();
    // A BODY reaching a HOLDER transfers a whole article; one reaching a
    // refuser is a one-line 430. Only the first kind can be wasted.
    let mut bodies = 0u64;
    let mut probes = 0u64;
    for (si, m) in mocks.iter().enumerate() {
        for id in m.body_log.lock().unwrap().iter() {
            if !holeset.contains(id.as_str()) {
                continue;
            }
            if si < refusers {
                probes += 1;
            } else {
                bodies += 1;
            }
        }
    }
    HoleLeg {
        label: label.to_string(),
        wall,
        done,
        missing,
        bodies,
        wasted: bodies.saturating_sub(n_hole as u64),
        probes,
        wire_bytes: mocks
            .iter()
            .map(|m| m.bytes_out.load(Ordering::Relaxed))
            .sum(),
        stats: mocks.iter().map(|m| m.stats.load(Ordering::Relaxed)).sum(),
    }
}

struct HoleLeg {
    label: String,
    wall: Duration,
    done: usize,
    missing: usize,
    /// Whole hole-article bodies transferred fleet-wide.
    bodies: u64,
    /// Of those, the copies nobody used.
    wasted: u64,
    /// 430s bought on the refusing backbones.
    probes: u64,
    /// Body bytes the whole fleet put on the wire.
    wire_bytes: u64,
    /// STAT commands answered fleet-wide.
    stats: u64,
}

impl HoleLeg {
    fn line(&self) -> String {
        format!(
            "{:<30} wall {:>6.2}s  {} done, {} missing, {:>3} hole bodies \
             ({:>2} WASTED), {:>3} refusals, {:>3} stats, {:.2} MB wire",
            self.label,
            self.wall.as_secs_f64(),
            self.done,
            self.missing,
            self.bodies,
            self.wasted,
            self.probes,
            self.stats,
            self.wire_bytes as f64 / 1e6,
        )
    }
}

/// §96 item 4, the two clauses the STAT verdict probe has to satisfy
/// for its A/B to mean anything. It is OFF in shipping fleets - the
/// measurement said the round trip it adds costs more than the bytes it
/// saves, and the write-up in TODO 96 has the table - but the knob is
/// live, so the path has to stay correct or the next person to re-open
/// the item measures a broken arm.
///
/// **A STAT refusal is worth exactly what a BODY refusal is worth.**
/// Same codes, same authority, same `handle_missing` - so a poisoned
/// tail must reach the same verdicts, for the same articles, with the
/// fan-out asking a different question. Anything else means the probe
/// path has grown its own idea of what "missing" means.
///
/// **And a probe never buys an article.** On the piecing shape - one
/// backbone lacks the article, four hold it - the body-racing fan-out
/// downloads a copy per holder and throws all but one away. With the
/// probe on, the fleet must put exactly the job's own payload on the
/// wire and not a byte more.
#[tokio::test(flavor = "multi_thread")]
async fn a_stat_probe_votes_like_a_body_and_never_buys_one() {
    let probing = PoolConfig {
        stat_probe: true,
        ..PoolConfig::shipped()
    };
    let poisoned = ladder_leg("damage 60 (STAT)", 60, probing.clone()).await;
    println!("\n{}", poisoned.line());
    assert_eq!(
        poisoned.done, N_GOOD,
        "the probe path lost healthy articles"
    );
    assert_eq!(
        poisoned.missing, 60,
        "a STAT refusal did not carry a BODY refusal's authority - the \
         poisoned tail ended with {} verdicts instead of 60",
        poisoned.missing
    );

    let pieced = hole_leg("60 holes tail, 4 hold (STAT)", 60, 4, false, probing).await;
    println!("{}", pieced.line());
    assert_eq!(pieced.missing, 0, "the probe path lost a servable article");
    assert_eq!(
        pieced.done,
        N_GOOD + 60,
        "the probe path did not deliver every article"
    );
    assert_eq!(
        pieced.wasted, 0,
        "a verdict probe bought {} whole articles nobody used",
        pieced.wasted
    );
    assert!(
        pieced.stats > 0,
        "no STAT was ever issued - the rig measured the body arm twice"
    );
}

/// The waste §96 item 4 is about, printed rather than asserted. Run with
/// `--ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement table - run with --ignored"]
async fn cross_server_piecing_duplicate_bodies() {
    let probing = PoolConfig {
        stat_probe: true,
        ..PoolConfig::shipped()
    };
    let mut table = Vec::new();
    for interleave in [false, true] {
        let where_ = if interleave { "spread" } else { "tail" };
        for holders in [4usize, 3, 2, 1] {
            // Three reps a cell, ALTERNATED: one leg of a 0.3 s run is
            // noise, and the quantity in dispute is a fraction of that.
            // Consecutive reps a side would hand any drift on the box
            // straight to whichever arm ran second.
            for rep in 0..3 {
                for (arm, cfg) in [("body", PoolConfig::shipped()), ("STAT", probing.clone())] {
                    table.push(
                        hole_leg(
                            &format!("{where_}, {holders} hold, {arm} #{rep}"),
                            60,
                            holders,
                            interleave,
                            cfg,
                        )
                        .await,
                    );
                }
            }
        }
    }
    println!("\ncross-server piecing, {SERVERS} backbones x {CONNS} connections:");
    for leg in &table {
        println!("  {}", leg.line());
    }
    for leg in &table {
        assert_eq!(leg.missing, 0, "{} lost a servable article", leg.label);
    }
}

/// The same shape across the damage ladder, printed rather than
/// asserted - the A/B table for a benchmark round. Run with
/// `--ignored --nocapture`.
///
/// Two postures per rung. `shipped` is the fleet a user runs; `default`
/// is `PoolConfig::default()`, with the speculation layer dark. The
/// second arm is here because it is what this rig USED to measure, and
/// because §146.2's hop-count lever will be tried on this rig first -
/// tuning it wants both numbers in front of it, not one of unknown
/// provenance.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock A/B table - run with --ignored"]
async fn ladder_tail_across_the_damage_ladder() {
    let probing = PoolConfig {
        stat_probe: true,
        ..PoolConfig::shipped()
    };
    let mut table = Vec::new();
    for n in [5usize, 20, 60, 120] {
        table.push(ladder_leg(&format!("damage {n} (shipped)"), n, PoolConfig::shipped()).await);
        table.push(ladder_leg(&format!("damage {n} (default)"), n, PoolConfig::default()).await);
        // TODO 96.4: the STAT verdict probe on the shape it cannot help
        // - a poisoned article is refused whatever you ask with, so this
        // arm exists to show it costs nothing either.
        table.push(ladder_leg(&format!("damage {n} (STAT)"), n, probing.clone()).await);
    }
    println!(
        "\n430-ladder tail, {SERVERS} backbones x {CONNS} connections, {MISS_MS} ms refusals:"
    );
    for leg in &table {
        println!("  {}", leg.line());
    }
    for leg in &table {
        assert_eq!(leg.done, N_GOOD, "{} lost healthy articles", leg.label);
    }
}
