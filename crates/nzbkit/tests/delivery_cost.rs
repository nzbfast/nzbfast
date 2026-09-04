//! N13 (steer/settle chain): what a delivered article actually costs on
//! the handoff path, measured rather than argued.
//!
//! R9 (message-id interning) measured its RETAINED half - the plan's id
//! holders - with `r9_plan_rss_at_field_scale`, and ARGUED the
//! per-article allocation half from the diff. This rig closes that gap
//! and prices the rest of the chain beside it, because the fusion half
//! of N13 is a behavioural change against the TODO 121.4 liveness
//! windows and nobody should trade those for an unmeasured lock hop.
//!
//! What the chain is, per delivered article, in the download pipeline's
//! posture (`crc_steer` on with a steer peer, `arrival_ack` always on):
//!
//! | where | hop |
//! |---|---|
//! | reactor thread, `handle_body` | `done_ok` lock: insert |
//! | reactor thread, `stash_handed` | `handed` lock: insert |
//! | decode thread, `note_decoded` | `QueueControl::shared` lock + `Weak::upgrade` |
//! | decode thread, `note_decoded` | `handed` lock: remove |
//! | decode thread, `note_settled` | `QueueControl::shared` lock + `Weak::upgrade` |
//! | decode thread, `note_settled` | `done_ok` lock: remove |
//!
//! `settle_handoff` returns without a lock under `crc_steer && delivered`,
//! so the reactor pays two hops, not three.
//!
//! Everything here is `#[ignore]`d: these are numbers, not gates, and
//! the wall-clock legs are the house's ignore rule. The bodies use only
//! the public pool API and `PoolConfig` fields that predate this work,
//! so the file drops onto a pre-fusion tree unchanged - the R9 rule.
//!
//! ```sh
//! cargo test -p nzbkit --release --features heavy-tests --test delivery_cost -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` matters: the legs measure process-wide CPU and
//! allocations, so two of them running at once measure each other. So
//! does an otherwise IDLE machine - a nextest sweep running beside this
//! swings the per-leg wall from 0.39 s to 0.57 s and turns the arm
//! deltas into noise of either sign. That is not a subtle effect and it
//! is easy to do by accident on a box running several lanes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nzbkit::config::ServerConfig;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use nzbkit::pool::{
    ArticleReq, DecodeAck, DecodeReport, FetchOutcome, PoolConfig, QueueControl,
    fetch_all_multi_ctl,
};
use tokio::sync::mpsc;

// ---------------------------------------------------------------- alloc

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

/// Pass-through allocator that counts. Deliberately Relaxed and
/// deliberately only on the alloc side: the question is how many
/// allocations a delivered article causes, and a free is not one.
/// `realloc` counts once at its NEW size rather than falling through to
/// the default alloc+copy+dealloc, which would count a grow as a fresh
/// allocation of the whole buffer AND leave the old size uncounted.
struct Counting;

// SAFETY: `GlobalAlloc`'s contract is that the implementation behaves as
// an allocator: every pointer it returns is either null or a fresh block
// fitting the requested `Layout`, and `dealloc`/`realloc` are given back
// exactly the (pointer, layout) pairs it handed out. This one delegates
// all three to `System`, which upholds all of that, and adds only
// relaxed atomic counter arithmetic - no allocation of its own, so it
// cannot re-enter, and no pointer is derived or altered here.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(l.size() as u64, Ordering::Relaxed);
        // SAFETY: `l` reaches `System` exactly as the caller passed it,
        // and the caller already owes `GlobalAlloc::alloc` its validity.
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(l.size() as u64, Ordering::Relaxed);
        // SAFETY: as in `alloc` - the layout is forwarded untouched.
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: every pointer this allocator ever returned is one
        // `System` produced under the same layout, so the (p, l) pair
        // handed back is `System`'s own.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new as u64, Ordering::Relaxed);
        // SAFETY: same provenance argument as `dealloc`, and `new` is
        // the caller's own size, forwarded unchanged.
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

fn allocs() -> (u64, u64) {
    (
        ALLOCS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

/// Process CPU (user, system). Process-wide rather than a thread clock:
/// the chain spans reactor threads and decode threads and the point is
/// the total the machine pays.
///
/// Via `nzbkit::mem` rather than a local `libc::getrusage`, which does
/// not exist on Windows - and `--all-targets` compiles this test target
/// there, so the local version held `windows-clippy` red. `mem` keeps
/// the user/system split this rig medians on, out of GetProcessTimes on
/// Windows.
fn cpu() -> (Duration, Duration) {
    let (user, sys) = nzbkit::mem::cpu_user_sys_secs().unwrap_or((0.0, 0.0));
    (Duration::from_secs_f64(user), Duration::from_secs_f64(sys))
}

// ---------------------------------------------------------------- corpus

/// Payload bytes per article. Small on purpose: the chain's cost is PER
/// ARTICLE, so the rig maximises articles per second of wire time. Real
/// bodies are ~700 KB, which makes the same chain ~350x rarer per byte -
/// that ratio is exactly what the write-up has to state.
const ART: usize = 2_000;
/// Articles in the corpus.
const N: usize = 40_000;
/// Connections per server.
const CONNS: usize = 8;
/// Runs per arm. Odd, so the median is a real leg.
const RUNS: usize = 5;
/// Consumer tasks sharing the one outcome channel - the shipped
/// `decode_consumer_loop` shape, where several decode threads contend
/// on the receiver mutex and then on the chain's locks behind it.
const DECODERS: usize = 4;

fn corpus() -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..(N * ART) as u32).map(|i| (i >> 3) as u8).collect();
    let mut articles = HashMap::new();
    let segs = make_file_articles("chain.bin", &data, ART, "dc", &mut articles);
    let reqs = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>").into(),
            age_days: 0,
            part: *part,
            file: u32::MAX,
        })
        .collect();
    (articles, reqs)
}

/// Which of the chain's three postures a leg runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Arm {
    /// Legacy: no consumer verdicts at all. The reactor inserts the
    /// `done_ok` entry and `settle_handoff` removes it. Two hops, one
    /// thread, no `Weak` upgrade.
    Plain,
    /// TODO 121.4 only: the consumer acks decode+write. The reactor
    /// inserts, `settle_handoff` leaves the entry standing, and
    /// `note_settled` removes it from the decode thread. Two hops plus
    /// one upgrade, and the entry now spans the channel buffer.
    Ack,
    /// The shipped multi-server download posture: `crc_steer` on top,
    /// so `stash_handed` runs on the reactor and `note_decoded` takes
    /// the verdict. Six hops, two upgrades.
    Full,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Arm::Plain => "plain (no verdicts)",
            Arm::Ack => "arrival_ack",
            Arm::Full => "arrival_ack + crc_steer",
        }
    }
}

struct Leg {
    wall: Duration,
    user: Duration,
    sys: Duration,
    allocs: u64,
    bytes: u64,
    done: usize,
}

/// One measured run of the whole delivery path against two loopback
/// mock servers, with a consumer shaped like `decode_consumer_loop`:
/// batch-drain the channel, decode each body (the real yEnc pass), and
/// ack in the same order the shipped consumer does - `note_decoded`
/// BEFORE the notional write, `note_settled` after it.
async fn leg(arm: Arm, decode: bool) -> Leg {
    let (arts_a, reqs) = corpus();
    let arts_b = arts_a.clone();
    let a = MockServer::start(arts_a, Chaos::default()).await;
    let b = MockServer::start(arts_b, Chaos::default()).await;
    // Production wires a BufPool (mem.rs sizes it); without one every
    // body read allocates a fresh 800 KB Vec, which would drown the
    // per-article allocation figure in the rig's own configuration.
    let bufs = nzbkit::pool::BufPool::new(CONNS * 2 * 8);
    let cfg = PoolConfig {
        connections: CONNS,
        window: 4,
        ramp_delay: Duration::from_millis(0),
        crc_steer: arm == Arm::Full,
        arrival_ack: arm != Arm::Plain,
        buf_pool: Some(bufs.clone()),
        ..PoolConfig::default()
    };
    let srv = |m: &MockServer| -> (ServerConfig, PoolConfig) {
        let mut sc = m.server_config();
        sc.connections = CONNS as u32;
        (sc, cfg.clone())
    };
    let servers = vec![srv(&a), srv(&b)];

    let ctl = Arc::new(QueueControl::default());
    let (tx, rx) = mpsc::channel(64);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let ctl_fetch = ctl.clone();

    // Everything above this line allocates the corpus; the measurement
    // starts here so the counters describe the RUN.
    let (a0, b0) = allocs();
    let (u0, s0) = cpu();
    let t0 = Instant::now();

    let fetch =
        tokio::spawn(
            async move { fetch_all_multi_ctl(&servers, reqs, tx, Some(&ctl_fetch)).await },
        );
    let collectors: Vec<_> = (0..DECODERS)
        .map(|_| {
            let (rx, ctl, bufs) = (rx.clone(), ctl.clone(), bufs.clone());
            tokio::spawn(async move {
                let mut done = 0usize;
                let mut scratch = Vec::new();
                loop {
                    let Some(o) = rx.lock().await.recv().await else {
                        break;
                    };
                    if let FetchOutcome::Done { id, raw } = o {
                        let raw = bufs.adopt(raw);
                        let part = if decode {
                            match nzbkit::yenc_simd::decode_into_integrity(&raw, &mut scratch, true)
                            {
                                Ok((meta, _)) => meta.part,
                                Err(_) => None,
                            }
                        } else {
                            None
                        };
                        if arm == Arm::Full
                            && ctl.note_decoded(&id, DecodeReport::Clean { part })
                                == DecodeAck::Steered
                        {
                            continue;
                        }
                        // The notional write lands between the two acks -
                        // that separation IS the liveness window TODO
                        // 121.4 bought, and why the two calls cannot
                        // simply be folded into one.
                        if arm != Arm::Plain {
                            ctl.note_settled(&id);
                        }
                        done += 1;
                    }
                }
                done
            })
        })
        .collect();
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("delivery-cost leg hung")
        .unwrap();
    let mut done = 0usize;
    for c in collectors {
        done += c.await.unwrap();
    }
    let wall = t0.elapsed();
    let (u1, s1) = cpu();
    let (a1, b1) = allocs();
    Leg {
        wall,
        user: u1 - u0,
        sys: s1 - s0,
        allocs: a1 - a0,
        bytes: b1 - b0,
        done,
    }
}

fn report(arm: Arm, decode: bool, l: &Leg) {
    let per = |n: u64| n as f64 / l.done.max(1) as f64;
    let cpu_ns = (l.user + l.sys).as_nanos() as f64 / l.done.max(1) as f64;
    println!(
        "  {:<26} decode={:<5} wall {:>6.3}s  {:>7.0} art/s  user {:>6.3}s  sys {:>6.3}s  \
         cpu/article {:>7.0}ns  allocs/article {:>5.2}  bytes/article {:>7.0}",
        arm.name(),
        decode,
        l.wall.as_secs_f64(),
        l.done as f64 / l.wall.as_secs_f64(),
        l.user.as_secs_f64(),
        l.sys.as_secs_f64(),
        cpu_ns,
        per(l.allocs),
        per(l.bytes),
    );
}

/// The headline: three postures x three runs, with and without the
/// consumer's real decode pass. The Plain->Full delta is the WHOLE
/// steer/settle chain's marginal price per delivered article; any
/// fusion can only ever win a fraction of that, so this number is what
/// a TODO 121.4 liveness-window risk would have to be worth.
///
/// Read the medians, not the first run of a group - the first leg of
/// the process pays page faults the rest do not.
///
/// The allocation columns include the in-process mock server's own
/// per-body work, so the absolute is a floor for "pool + mock", not for
/// the pool alone. The DELTA between arms is clean, and that delta is
/// the quantity R9 argued from the diff rather than measured: whether a
/// delivered article allocates anywhere on the steer/settle chain.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement: wall/CPU/allocations per delivered article"]
async fn n13_delivery_chain_cost() {
    println!(
        "N13 delivery chain: {N} articles x {ART} B, 2 servers x {CONNS} conns, {DECODERS} consumers"
    );
    for decode in [true, false] {
        let mut medians = Vec::new();
        for arm in [Arm::Plain, Arm::Ack, Arm::Full] {
            let mut legs = Vec::new();
            for _ in 0..RUNS {
                let l = leg(arm, decode).await;
                assert_eq!(l.done, N, "every article must be delivered");
                report(arm, decode, &l);
                legs.push(l);
            }
            // Median on USER cpu. System time is loopback syscall cost,
            // it is the larger half here, and the in-process mock owns
            // most of it - it swings several percent run to run and
            // would drown a per-article effect this size. User time is
            // where the chain's locks and hashing land.
            legs.sort_by_key(|l| l.user);
            medians.push((arm, legs.swap_remove(RUNS / 2)));
        }
        let base = &medians[0].1;
        for (arm, l) in &medians[1..] {
            let d =
                |a: Duration, b: Duration| (a.as_nanos() as f64 - b.as_nanos() as f64) / N as f64;
            println!(
                "  -> {:<24} decode={:<5} vs plain, per article: user {:>+5.0} ns  \
                 wall {:>+5.0} ns  allocs {:>+5.2}",
                arm.name(),
                decode,
                d(l.user, base.user),
                d(l.wall, base.wall),
                (l.allocs as f64 - base.allocs as f64) / N as f64,
            );
        }
    }
}

/// Attribution for the headline: what one hop of each kind costs at the
/// delivery path's own concurrency, measured standalone so the chain's
/// price can be checked against its parts rather than assumed.
///
/// Three shapes, matching the three the chain uses:
/// - a `Mutex<HashSet<Arc<str>>>` insert+remove pair (`done_ok`),
/// - a `Mutex<HashMap<Arc<str>, _>>` insert+remove pair (`handed`),
/// - a `Mutex<Option<Weak<T>>>` lock + `Weak::upgrade` (every
///   `QueueControl` call's preamble).
#[test]
#[ignore = "measurement: per-hop price of the chain's three lock shapes"]
fn n13_hop_prices() {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Mutex, Weak};

    const ITERS: usize = 200_000;
    // The delivery path's real shape: reactor threads inserting while
    // decode threads remove. Eight and four is the daemon's own posture
    // on a wide box.
    const REACTORS: usize = 8;
    const DECODERS: usize = 4;

    // Interned ids, the R9 shape: ~50 bytes bracketed.
    let ids: Vec<Arc<str>> = (0..ITERS)
        .map(|i| {
            Arc::from(format!(
                "<part000seg{i:06}.aBcDeFgHiJkLmNoPqRsT@powerpost.local>"
            ))
        })
        .collect();

    let set: Mutex<HashSet<Arc<str>>> = Mutex::new(HashSet::new());
    let map: Mutex<HashMap<Arc<str>, u64>> = Mutex::new(HashMap::new());
    let target = Arc::new(0u64);
    let weak: Mutex<Option<Weak<u64>>> = Mutex::new(Some(Arc::downgrade(&target)));

    let threads = REACTORS + DECODERS;
    let each = ITERS / threads;

    let time = |label: &str, f: &(dyn Fn(usize, &Arc<str>) + Sync)| {
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for t in 0..threads {
                let ids = &ids;
                let f = &f;
                s.spawn(move || {
                    for i in 0..each {
                        f(t, &ids[t * each + i]);
                    }
                });
            }
        });
        let el = t0.elapsed();
        println!(
            "  {label:<34} {:>7.1} ns/op over {} ops on {threads} threads",
            el.as_nanos() as f64 / (each * threads) as f64,
            each * threads
        );
    };

    println!("N13 hop prices ({REACTORS} + {DECODERS} threads, contended):");
    time("done_ok insert+remove", &|_, id| {
        set.lock().unwrap().insert(id.clone());
        set.lock().unwrap().remove(&**id);
    });
    time("handed insert+remove", &|_, id| {
        map.lock().unwrap().insert(id.clone(), 1);
        map.lock().unwrap().remove(&**id);
    });
    time("shared lock + Weak::upgrade", &|_, _| {
        let up = weak.lock().unwrap().as_ref().and_then(Weak::upgrade);
        std::hint::black_box(&up);
    });
    // The whole chain's six hops back to back, so the headline leg's
    // Plain->Full delta has something to be checked against.
    time("all six hops", &|_, id| {
        set.lock().unwrap().insert(id.clone());
        map.lock().unwrap().insert(id.clone(), 1);
        let _ = weak.lock().unwrap().as_ref().and_then(Weak::upgrade);
        map.lock().unwrap().remove(&**id);
        let _ = weak.lock().unwrap().as_ref().and_then(Weak::upgrade);
        set.lock().unwrap().remove(&**id);
    });
    std::hint::black_box(&target);
}
