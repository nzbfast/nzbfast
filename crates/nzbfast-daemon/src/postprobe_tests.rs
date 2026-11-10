//! TODO 358 item 1: the split burst and the parallel start sample,
//! against real sockets. Every server here is an in-process mock with a
//! per-article refusal delay (`Chaos::missing_delay_ms`), which is the
//! knob that models the slow 430 of the 13 Oct round: the mock answers
//! one command at a time per connection, so a refusal costs its delay
//! serially per session and in parallel across sessions - the shape
//! measured on four of the five live accounts.

use super::*;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// `n` articles of one file, and the mock-side article map.
fn post(tag: &str, n: usize) -> (HashMap<String, Vec<u8>>, Vec<(String, u64, u32)>) {
    let mut articles = HashMap::new();
    let data: Vec<u8> = (0..n * 2_000).map(|i| (i * 7) as u8).collect();
    let segs = make_file_articles(&format!("{tag}.bin"), &data, 2_000, tag, &mut articles);
    assert_eq!(segs.len(), n);
    (articles, segs)
}

/// The NZB for `segs`, posted `age_days` ago, written into `dir`.
fn nzb(dir: &std::path::Path, segs: &[(String, u64, u32)], age_days: i64) -> std::path::PathBuf {
    let date = unix_now() - age_days * 86_400;
    let mut x = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
         <file poster=\"x\" date=\"{date}\" subject=\"&quot;p.bin&quot; yEnc (1/{})\">\n    \
         <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in segs {
        x.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    x.push_str("    </segments>\n  </file>\n</nzb>\n");
    let p = dir.join("job.nzb");
    std::fs::write(&p, x).unwrap();
    p
}

fn bracketed(segs: &[(String, u64, u32)], keep: impl Fn(usize) -> bool) -> HashSet<String> {
    segs.iter()
        .enumerate()
        .filter(|(i, _)| keep(*i))
        .map(|(_, (id, _, _))| format!("<{id}>"))
        .collect()
}

async fn mock(
    articles: &HashMap<String, Vec<u8>>,
    missing: HashSet<String>,
    missing_delay_ms: u64,
    greet_delay_ms: u64,
    connections: u32,
) -> (MockServer, nzbkit::config::ServerConfig) {
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            missing,
            missing_delay_ms,
            greet_delay_ms,
            ..Default::default()
        },
    )
    .await;
    let mut sc = srv.server_config();
    sc.connections = connections;
    (srv, sc)
}

fn never() -> Stop {
    Arc::new(|| false)
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-postprobe-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// THE CAP DEFECT (`research/DEAD-POST-GIVEUP-NEVER-SEES-A-VERDICT-2026-10-12.md`
/// section 4.2), at a tenth of the scale. 64 dead ids at 150 ms a
/// refusal are 9.6 s of serial lookups on one connection - the live
/// fleet's 30-142 s against the old 20 s ceiling, scaled to a 3 s
/// deadline. The single-connection pass answers about a fifth of them,
/// so the verdict can never be unanimous; the same ids split over 16
/// connections are answered in about 0.6 s and the verdict is.
#[tokio::test(flavor = "multi_thread")]
async fn the_split_pass_reaches_the_verdict_the_single_connection_pass_cannot() {
    let dir = scratch("cap");
    let d = crate::testutil::test_daemon(&dir);
    let (articles, segs) = post("cap", crate::health::ESCALATE_K);
    let all = bracketed(&segs, |_| true);
    let (srv, sc) = mock(&articles, all.clone(), 150, 0, 17).await;
    let ids: Vec<String> = all.iter().cloned().collect();
    let deadline = Duration::from_secs(3);

    let t = Instant::now();
    let one = split_burst(
        &d,
        std::slice::from_ref(&sc),
        &ids,
        Spread {
            conns_max: 1,
            deadline,
        },
        never(),
    )
    .await;
    let one_took = t.elapsed();
    let v = crate::health::score(&one, 30, 0, 1).expect("it answered some");
    assert!(
        v.absent < 40,
        "the single connection was not cut short: {}",
        v.reason
    );
    assert!(!v.fails_job(segs.len()), "{}", v.reason);
    assert!(
        one_took >= deadline && one_took < deadline + Duration::from_secs(2),
        "{one_took:?}"
    );

    let before = srv.accepted.load(Ordering::Relaxed);
    let t = Instant::now();
    let split = split_burst(
        &d,
        std::slice::from_ref(&sc),
        &ids,
        Spread {
            conns_max: 16,
            deadline,
        },
        never(),
    )
    .await;
    let split_took = t.elapsed();
    let v = crate::health::score(&split, 30, 0, 1).unwrap();
    assert_eq!(v.absent, crate::health::ESCALATE_K as u32, "{}", v.reason);
    assert!(v.fails_job(segs.len()), "{}", v.reason);
    assert!(split_took < deadline, "split pass took {split_took:?}");
    // 17 configured, one left for the background samplers: 16.
    let opened = srv.accepted.load(Ordering::Relaxed) - before;
    assert_eq!(opened, 16, "connections opened");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The width is a ceiling bounded by the ACCOUNT: never past the
/// configured connections, less the download permits the hub's budget
/// has handed out on that account, and zero when the account is full -
/// at which point the server does not vote rather than being dialled
/// over its limit.
#[tokio::test(flavor = "multi_thread")]
async fn probe_width_never_dials_past_the_account() {
    let dir = scratch("width");
    let d = crate::testutil::test_daemon(&dir);
    let mut sc: nzbkit::config::ServerConfig =
        serde_json::from_value(serde_json::json!({"host": "news.example", "port": 119})).unwrap();
    sc.connections = 8;
    assert_eq!(
        probe_width(&d, &sc, 20).await,
        7,
        "idle: all but the sampler slot"
    );
    assert_eq!(
        probe_width(&d, &sc, 4).await,
        4,
        "never past what was asked for"
    );
    sc.connections = 1;
    assert_eq!(
        probe_width(&d, &sc, 20).await,
        1,
        "a one-connection account keeps its one"
    );
    sc.connections = 8;

    let budget = d
        .hub
        .conn_budget
        .get_or_init(nzbkit::pool::handoff::ConnBudget::new)
        .clone();
    let lease = budget.lease(&nzbkit::pool::handoff::ConnBudget::key(&sc), 8);
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(
            lease
                .acquire_as(nzbkit::pool::handoff::LeaseClass::PostProcess)
                .await,
        );
    }
    assert_eq!(
        probe_width(&d, &sc, 20).await,
        2,
        "5 of 8 held: 3 free, 1 kept back"
    );
    for _ in 0..3 {
        held.push(
            lease
                .acquire_as(nzbkit::pool::handoff::LeaseClass::PostProcess)
                .await,
        );
    }
    assert_eq!(
        probe_width(&d, &sc, 20).await,
        0,
        "a full account gets no probe"
    );
    drop(held);
    assert_eq!(probe_width(&d, &sc, 20).await, 7);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 9 Nov 2026 sweep: two probes at once share ONE account. The job-start
/// sample runs before `started_at` is set, so `download_idle` still says
/// idle and the idle prober (or the add-time preview) can burst the same
/// servers at the same moment. Each burst used to size itself off the
/// download's permits and the warm pool alone, never the other burst's
/// sessions, so an 8-connection account was dialled 7 + 7 = 14 times.
/// Both bursts here overlap (a slow 430 holds every session open for the
/// whole of the other's start), and together they must stay inside the
/// account's configured connections.
#[tokio::test(flavor = "multi_thread")]
async fn two_probes_at_once_never_dial_past_the_account_between_them() {
    let dir = scratch("twoprobes");
    let d = crate::testutil::test_daemon(&dir);
    let (articles, segs) = post("two", 16);
    let all = bracketed(&segs, |_| true);
    let (srv, sc) = mock(&articles, all.clone(), 800, 0, 8).await;
    let ids: Vec<String> = all.iter().cloned().collect();
    let spread = Spread {
        conns_max: 20,
        deadline: Duration::from_secs(10),
    };
    let one = split_burst(&d, std::slice::from_ref(&sc), &ids, spread, never());
    let two = split_burst(&d, std::slice::from_ref(&sc), &ids, spread, never());
    let (a, b) = tokio::join!(one, two);
    let opened = srv.accepted.load(Ordering::Relaxed);
    assert!(
        opened <= u64::from(sc.connections),
        "two overlapping probes opened {opened} sessions on an account of {}",
        sc.connections
    );
    // And the reservation is returned: the account is whole again after.
    assert_eq!(probe_width(&d, &sc, 20).await, 7);
    // Both still voted - the second burst is thinner, never silent while
    // the account had room.
    assert!(a[0].answered() && b[0].answered(), "{a:?} {b:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The stand-down survives the split: a download starting mid-burst
/// drops every session at once, and what was never answered stays
/// Unknown rather than becoming a miss.
#[tokio::test(flavor = "multi_thread")]
async fn a_download_starting_mid_burst_drops_every_session() {
    let dir = scratch("yield");
    let d = crate::testutil::test_daemon(&dir);
    let (articles, segs) = post("yield", crate::health::ESCALATE_K);
    let all = bracketed(&segs, |_| true);
    let (_srv, sc) = mock(&articles, all.clone(), 1_000, 0, 9).await;
    let ids: Vec<String> = all.iter().cloned().collect();
    let dd = d.clone();
    let stop: Stop = Arc::new(move || !download_idle(&dd));
    let d2 = d.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        *d2.started_at.lock_ok() = Some(std::time::Instant::now());
    });
    let t = Instant::now();
    let a = split_burst(&d, &[sc], &ids, Spread::START_WIDE, stop).await;
    assert!(
        t.elapsed() < Duration::from_millis(900),
        "yield took {:?}",
        t.elapsed()
    );
    let missing = a[0]
        .cells
        .iter()
        .filter(|c| **c == crate::health::Avail::Missing)
        .count();
    assert_eq!(
        missing, 0,
        "nothing was answered before the yield, so nothing may read missing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A' on a wholly dead post, two slow-430 servers: the verdict is the
/// full 64-wide unanimous red, inside the start sample's deadline.
/// 400 ms a refusal puts the OLD prober's escalation (one connection,
/// 64 x 0.4 s = 25.6 s) past its own 20 s ceiling, the 4.2 defect at
/// its real constant; here it is two short bursts.
#[tokio::test(flavor = "multi_thread")]
async fn start_sample_fails_a_dead_post_well_inside_its_deadline() {
    let dir = scratch("dead");
    let d = crate::testutil::test_daemon(&dir);
    let (articles, segs) = post("dead", 300);
    let all = bracketed(&segs, |_| true);
    let (_a, sa) = mock(&articles, all.clone(), 400, 100, 20).await;
    let (_b, sb) = mock(&articles, all, 400, 100, 20).await;
    let path = nzb(&dir, &segs, 30);
    let t = Instant::now();
    let r = start_sample(&d, &[sa, sb], &path).await;
    let took = t.elapsed();
    let StartSample::Gone(v) = r else {
        panic!("a dead post must fail: {r:?}");
    };
    assert_eq!(v.sampled, crate::health::ESCALATE_K as u32);
    assert_eq!((v.answered, v.servers), (2, 2));
    // k=8 over 8 connections: one refusal each (0.4 s). Then 64 over
    // 19 connections: four in series (1.6 s). Plus connects.
    assert!(took < Duration::from_secs(6), "dead post took {took:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The green path, at realistic latencies: half a second to connect and
/// authenticate (usenetexpress, the slowest measured) and present STATs
/// at mock speed (a live present STAT is 2-15 ms). One k=8 burst, never
/// escalated, and the job is held well under the 1-2 s budget.
#[tokio::test(flavor = "multi_thread")]
async fn start_sample_holds_a_healthy_post_for_well_under_two_seconds() {
    let dir = scratch("healthy");
    let d = crate::testutil::test_daemon(&dir);
    let (articles, segs) = post("ok", 300);
    let (a, sa) = mock(&articles, HashSet::new(), 2_200, 500, 50).await;
    let (b, sb) = mock(&articles, HashSet::new(), 2_200, 500, 50).await;
    let path = nzb(&dir, &segs, 400);
    let t = Instant::now();
    let r = start_sample(&d, &[sa, sb], &path).await;
    let took = t.elapsed();
    let StartSample::Pass(Some(v)) = r else {
        panic!("a healthy post must pass: {r:?}");
    };
    assert_eq!(v.bucket, crate::health::Bucket::Green, "{}", v.reason);
    assert!(
        took < Duration::from_millis(1_500),
        "healthy start held {took:?}"
    );
    // One k=8 burst per server and no escalation.
    assert_eq!(
        a.stats.load(Ordering::Relaxed),
        crate::health::SAMPLE_K as u64
    );
    assert_eq!(
        b.stats.load(Ordering::Relaxed),
        crate::health::SAMPLE_K as u64
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A young post is never probed: below the age gate no verdict can
/// reach red, so the dial would buy nothing. This is the everyday *arr
/// RSS grab.
#[tokio::test(flavor = "multi_thread")]
async fn start_sample_skips_a_post_below_the_age_gate() {
    let dir = scratch("young");
    let d = crate::testutil::test_daemon(&dir);
    let (articles, segs) = post("young", 50);
    let (a, sa) = mock(&articles, bracketed(&segs, |_| true), 0, 0, 10).await;
    let path = nzb(&dir, &segs, 1);
    let r = start_sample(&d, &[sa], &path).await;
    assert!(matches!(r, StartSample::Skipped("young")), "{r:?}");
    assert_eq!(a.accepted.load(Ordering::Relaxed), 0, "nothing dialled");
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE MISFIRE SUITE against real sockets: the damaged-but-repairable
/// torture shapes (tv4-dmg5/20/60 and worse) must download, never fail.
///
/// Each row is a fraction of the post missing on one server and a
/// different, overlapping fraction missing on the other, plus the row
/// where the same fraction is missing EVERYWHERE (short on the whole
/// fleet, which is what PAR2 repairs at the low end). The missing sets
/// are a scattered permutation rather than a block, so the stratified
/// sample meets them at every offset - the 90%-everywhere row is chosen
/// to make the k=8 burst read unanimous and force the escalation, which
/// then finds the present tenth.
#[tokio::test(flavor = "multi_thread")]
async fn start_sample_never_fails_a_damaged_but_suppliable_post() {
    let dir = scratch("misfire");
    let d = crate::testutil::test_daemon(&dir);
    let n = 400;
    let (articles, segs) = post("dmg", n);
    let scatter = |i: usize| (i * 37) % 100;
    let mut escalated = false;
    for (pct, everywhere) in [
        (5, false),
        (20, false),
        (60, false),
        (95, false),
        (5, true),
        (20, true),
        (60, true),
        (90, true),
    ] {
        let on_a = bracketed(&segs, |i| scatter(i) < pct);
        let on_b = if everywhere {
            on_a.clone()
        } else {
            // A different set, keeping one copy of every article.
            bracketed(&segs, |i| scatter(i) >= 100 - pct && scatter(i) >= pct)
        };
        let (a, sa) = mock(&articles, on_a, 20, 0, 20).await;
        let (b, sb) = mock(&articles, on_b, 20, 0, 20).await;
        let path = nzb(&dir, &segs, 400);
        let r = start_sample(&d, &[sa, sb], &path).await;
        assert!(
            matches!(r, StartSample::Pass(_)),
            "{pct}% damaged (everywhere: {everywhere}) must download: {r:?}"
        );
        if a.stats.load(Ordering::Relaxed) > crate::health::SAMPLE_K as u64 {
            escalated = true;
        }
        drop((a, b));
    }
    assert!(
        escalated,
        "no row reached the 64-wide pass, so the suite did not test it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
