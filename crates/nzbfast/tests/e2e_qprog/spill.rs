//! TODO 313 items 2-5 and 10, end to end: a head that cannot use its
//! fleet lends the unused part of it to the QUEUE, and the small jobs
//! behind it finish while it waits.
//!
//! **The shape is the study's, reproduced on a real daemon**
//! (`research/SECOND-JOB-OVERLAP-2026-08.md` section 11): a head whose
//! articles sit behind dead air, several small jobs queued behind it,
//! one account lease, and the same run with the switch on and off. The
//! rig that produced the 29-45% figure is a POOL-level A/B on
//! `nzbkit::mock` with no daemon in it at all - it can prove the
//! scheduler arithmetic and cannot prove that a daemon reallocates
//! anything. That is what this is for.
//!
//! **What it asserts is ORDER, and deliberately not wall time.** The
//! module beside this one says why at length: every figure here shifts
//! with load (a control row measured 0.8 s quiet and 1.5 s under a full
//! nextest sweep), so a wall-clock assertion is a flake generator. The
//! ordering claim is the one that carries the feature's whole meaning -
//! with the spill ON the jobs behind a stuck head finish BEFORE it, and
//! with it OFF they finish after it, which is the shipped serial queue
//! and the control arm for "nothing changed while the switch is off".
//! The wall times ARE printed all the same: a measurement has to come
//! from somewhere before it can be written down, and this is where the
//! numbers in the performance log come from.
//!
//! **TWO tests share this harness, and only one of them is a test.**
//! The regression test above runs [`SHIPPED`] and asserts ORDER.
//! [`qspill_study_scale_ab_measurement`] runs [`STUDY`] - section 11's
//! own `M9` shape, eight small jobs on a lease at cap 32 - and is
//! `#[ignore]`d scaffolding that no job executes: it is where the
//! `2026-09-02` queue-spill numbers in the performance log came from,
//! and it is kept in the tree because the question it answers (does
//! the study's 29-45% appear on a daemon, and should the switch
//! default on) is one that will be asked again. Its own doc comment
//! carries the command.
//!
//! Same discipline as its parent: the test owns a daemon on its own
//! port, `NZBFAST_NO_ENRICH=1` in the child's environment, and every
//! helper is `qspill_`-prefixed for `tools/par2-gate.py`, which
//! resolves helper names tree-wide.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use nzbkit::mock::{Chaos, MockServer};

use super::super::harness::serve;
use super::super::{Fixture, scratch};
use super::{qprog_http, qprog_upload};

/// One rig shape: a head, the jobs behind it, and the account the two
/// draw on.
///
/// A struct rather than a block of consts because there are now TWO
/// shapes and they differ in every number. The shipped regression test
/// runs [`SHIPPED`], which is what those consts said before this became
/// a struct and is deliberately unchanged. The measurement rig runs
/// [`STUDY`], which is section 11's own `M9` as closely as a real
/// daemon can be made to hold it - and the places it CANNOT are the
/// finding, so each one is named at its field.
struct Shape {
    /// Scratch-name discriminator, so two shapes in one process cannot
    /// share a temp directory.
    tag: &'static str,
    /// The head's articles, and how many of them answer only after dead
    /// air.
    ///
    /// Sized so the head is stuck for LONGER than the governor's window
    /// (twenty ticks of the daemon's one-second loop, twelve of which
    /// must agree) with room to spare. Nothing here compresses a
    /// shipped threshold - the governor runs at exactly the numbers it
    /// ships with, which is the lesson of the `_at_shipped_thresholds`
    /// group.
    head_articles: usize,
    head_silent: usize,
    head_art: usize,
    /// Dead air per silent article, ms.
    ///
    /// Long enough that the head is still stuck WELL past the
    /// governor's window - it needs twelve agreeing seconds before it
    /// will lend anything, and a lane then needs time to actually clear
    /// the jobs behind. Nothing here compresses a shipped threshold;
    /// the fault is made bigger instead, which is the honest direction.
    silence_ms: u64,
    /// Small jobs queued behind the head, and how big each one is.
    ///
    /// The article-bound shape the absorption rule exists for. The
    /// count is what separates "spill to the queue" from "spill to the
    /// next job": one lane chaining through all of them is the
    /// mechanism, and a single successor would pass a test that only
    /// proves the shipped hand-over works.
    smalls: usize,
    small_bytes: usize,
    small_art: usize,
    /// The account's connection cap - one lease, shared by the head and
    /// anything it lends to. `spill::lendable` is a QUARTER of this, so
    /// this number alone decides how many sockets a spilled lane can
    /// ever hold.
    connections: usize,
    /// Per-socket ceiling on the mock, bytes/s (0 = uncapped). The
    /// study's link model, and the same number the banked per-socket
    /// carry is seeded with, so a healthy head reads a useful fraction
    /// of about 1 and a silent one reads about 0.
    per_conn_bps: u64,
    /// A row that has not finished by here is reported, not asserted
    /// on.
    budget: Duration,
}

/// What the shipped regression test runs, unchanged since it was
/// written: eight connections, four small jobs, a head of 128 articles
/// with 96 behind 2.5 s of dead air, and no throttle at all.
const SHIPPED: Shape = Shape {
    tag: "s",
    head_articles: 128,
    head_silent: 96,
    head_art: 16_384,
    silence_ms: 2_500,
    smalls: 4,
    small_bytes: 96_000,
    small_art: 16_384,
    connections: 8,
    per_conn_bps: 0,
    budget: Duration::from_secs(180),
};

/// Section 11's `M9` at daemon scale: EIGHT small jobs of twelve
/// 384 KB articles each, one lease at cap 32, 2 MB/s a socket.
///
/// **Three departures, all forced and all load-bearing for how the
/// result reads.**
///
/// 1. **The head is bigger, and it has to be.** `M9`'s whole episode is
///    11.05 s and its head 5.21 s, where the shipped governor wants
///    twelve agreeing ticks inside a twenty-tick window before it lends
///    anything - so the study's own head is over before this daemon has
///    an opinion about it. The head here carries 384 silent articles at
///    2.5 s, which is about 30 s of dead air across 32 sockets: enough
///    for the window to close with roughly twenty seconds left for a
///    lane to work in. That is a change of TIME SCALE and not of
///    regime - the head is still a job that cannot use its own fleet.
/// 2. **The head's articles are 128 KB, not the study's 384 KB.** The
///    head is dead-air-bound (80% of its articles answer only after
///    silence), so its article SIZE moves nothing here, and 384 silent
///    384 KB articles would be a 170 MB fixture built six times a run.
///    The SMALL jobs keep the study's 384 KB exactly, because that is
///    the number `spill::articles_for` divides by.
/// 3. **One lane, not four.** `MAX_DOWNLOAD_PHASES` is 2 - the head
///    plus one spilled lane - because `active_dl`/`drain_dl` are this
///    daemon's two wire slots. The study's best arm was four lanes of
///    two sockets. What this rig CAN hold from that arm is its
///    important half, the split: `lendable(32)` is 8, so the head keeps
///    24 exactly as row 5 does.
const STUDY: Shape = Shape {
    tag: "m9",
    head_articles: 480,
    head_silent: 384,
    head_art: 131_072,
    silence_ms: 2_500,
    smalls: 8,
    small_bytes: 12 * 384_000,
    small_art: 384_000,
    connections: 32,
    per_conn_bps: 2_000_000,
    budget: Duration::from_secs(300),
};

/// What one arm measured.
struct Run {
    /// Seconds from resume to each small job's terminal state, in queue
    /// order.
    smalls: Vec<Option<f64>>,
    /// And the head's.
    head: Option<f64>,
    /// Everything terminal.
    total: f64,
    /// Did the daemon log say a spill happened?
    lent: bool,
    /// How many connections the head lent, off the daemon's own log
    /// line. The head keeps `cap - this`, which is the number the
    /// study says decides the head's cost.
    lent_conns: Option<usize>,
    /// Seconds from resume until two jobs first read `Downloading` at
    /// once - the governor's window plus whatever it took the runner to
    /// get a second phase onto the wire. Reported, never asserted: it
    /// is a count of TICKS and a loaded box does not deliver them at
    /// 1 Hz.
    two_phases_at: Option<f64>,
    /// Why the governor did what it did, in its own words - printed by
    /// the assertions so a failure carries its diagnosis instead of
    /// needing a repro.
    why: String,
    /// The most jobs seen reading `Downloading` at once.
    ///
    /// Two things at once: the PHASE CAP
    /// (`serve::spill::MAX_DOWNLOAD_PHASES`), and the queue row of a
    /// spilled lane reading as downloading rather than queued - a lane
    /// that is on the wire and shows as `Queued` is a bug report about
    /// a stuck queue.
    peak_downloading: usize,
}

impl Run {
    /// Did every small job reach a terminal state before the head did?
    /// `None` when something never finished at all.
    fn smalls_first(&self) -> Option<bool> {
        let head = self.head?;
        let last = self
            .smalls
            .iter()
            .copied()
            .collect::<Option<Vec<f64>>>()?
            .into_iter()
            .fold(0.0f64, f64::max);
        Some(last < head)
    }
}

/// The head: a post most of whose articles answer only after
/// `Shape::silence_ms` of silence. Returns the fixture and the chaos that
/// breaks it.
///
/// Dead air and not refusals, which is the whole point of the regime:
/// a 430 is CHEAP (the study measures refusal-clearing as dead linear
/// in socket count, so a partially-missing post finishes SOONER than a
/// whole one) and produces a fleet that is half-productive rather than
/// idle. Silence is the one shape where a job cannot use its own
/// sockets.
fn qspill_head(tag: &str, sh: &Shape) -> (Fixture, Chaos) {
    let mut fx = Fixture::new(tag);
    let data: Vec<u8> = (0..sh.head_articles * sh.head_art)
        .map(|i| (i >> 3) as u8)
        .collect();
    fx.add_file("QspillHead.bin", &data, sh.head_art);
    let mut slow = HashMap::new();
    // Keyed the way the wire spells it - `<id>` - which is what the
    // mock matches on. Bare ids simply never match, and the symptom is
    // a head that is not stuck at all.
    for (id, _, _) in fx.nzb_files[0].1.iter().take(sh.head_silent) {
        slow.insert(format!("<{id}>"), sh.silence_ms);
    }
    (
        fx,
        Chaos {
            slow_ttfb: slow,
            throttle: nzbkit::mock::Throttle {
                per_conn_bps: sh.per_conn_bps,
                ..Default::default()
            },
            ..Default::default()
        },
    )
}

/// One small job behind the head.
fn qspill_small(tag: &str, k: usize, sh: &Shape) -> Fixture {
    let mut fx = Fixture::new(tag);
    let data: Vec<u8> = (0..sh.small_bytes)
        .map(|i| (i as u8).wrapping_mul(k as u8 + 7))
        .collect();
    fx.add_file(&format!("QspillSmall{k}.bin"), &data, sh.small_art);
    fx
}

/// Names, in the order they are uploaded. The head first, so it is the
/// head.
fn qspill_names(sh: &Shape) -> (String, Vec<String>) {
    (
        "QspillHead.S01E01.1080p.WEB.h264-QS.nzb".to_string(),
        (0..sh.smalls)
            .map(|k| format!("QspillSmall{k}.S0{}E01.1080p.WEB.h264-QS.nzb", k + 2))
            .collect(),
    )
}

/// Terminal states, matching the parent module's rule: a job that
/// FAILED is finished too, and a row that only ever reports one of them
/// is a different bug from the one this test is about.
fn qspill_terminal(status: &str) -> bool {
    status == "Completed" || status == "Failed"
}

/// When did the history record a job whose name contains `frag`?
///
/// By NAME and never by nzo_id, for the reason the parent module's
/// `qprog_settled` gives: `nzbfast1` is a prefix of `nzbfast10`.
///
/// `payload` is already de-chunked - `qprog_http` handles that itself
/// now (`mod.rs::qprog_dechunk`), which is why this used to carry its
/// own copy of the de-chunker and no longer does.
fn qspill_done(payload: &str, frag: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
        return false;
    };
    v["history"]["slots"]
        .as_array()
        .map(|a| {
            a.iter().any(|s| {
                s["name"].as_str().unwrap_or_default().contains(frag)
                    && qspill_terminal(s["status"].as_str().unwrap_or_default())
            })
        })
        .unwrap_or(false)
}

/// How many queue rows read `Downloading` right now?
///
/// The word and not an inference from bytes: this is the string the
/// dashboard renders and every SABnzbd-compatible client reads, so it
/// is the thing a spilled lane has to get right.
fn qspill_downloading(payload: &str) -> usize {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
        return 0;
    };
    v["queue"]["slots"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|s| s["status"].as_str() == Some("Downloading"))
                .count()
        })
        .unwrap_or(0)
}

/// One arm: a daemon with the spill switch at `on`, a stuck head, four
/// small jobs behind it, and the times each of them finished.
async fn qspill_arm(on: bool, sh: &Shape, rep: usize) -> Run {
    let tag = format!(
        "{}{}{rep}",
        sh.tag,
        match on {
            true => "on",
            false => "off",
        }
    );
    let (head_fx, chaos) = qspill_head(&format!("qspill-head-{tag}"), sh);
    let smalls: Vec<Fixture> = (0..sh.smalls)
        .map(|k| qspill_small(&format!("qspill-small-{tag}-{k}"), k, sh))
        .collect();
    let mut articles = head_fx.articles.clone();
    for fx in &smalls {
        articles.extend(fx.articles.clone());
    }
    let head_xml = std::fs::read_to_string(head_fx.write_nzb()).unwrap();
    let small_xml: Vec<String> = smalls
        .iter()
        .map(|fx| std::fs::read_to_string(fx.write_nzb()).unwrap())
        .collect();

    let srv = MockServer::start(articles, chaos).await;
    let base = std::env::temp_dir().join(format!("nzbfast-qspill-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);
    std::fs::create_dir_all(&base).unwrap();
    let cfg = base.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":{}}}]}}",
            srv.addr.ip(),
            srv.addr.port(),
            sh.connections
        ),
    )
    .unwrap();
    // The switch, in the only home it has.
    std::fs::write(
        base.join("settings.json"),
        format!("{{\"queue_spill\":{on}}}\n"),
    )
    .unwrap();
    // TODO 275 item 1 part 2's per-socket carry, banked as if a job had
    // run here before. The trigger is a RATIO against this number and
    // has no opinion at all without one, so a fresh spool would leave
    // the mechanism correctly silent and the test measuring nothing.
    // 2 MB/s is the study's own per-socket ceiling.
    std::fs::create_dir_all(base.join(".spool")).unwrap();
    std::fs::write(
        base.join(".spool").join("linecarry.json"),
        "{\"carry_bps\":2000000,\"checked\":0}\n",
    )
    .unwrap();

    let d = serve(&base, |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1").env("NZBFAST_NO_ENRICH", "1");
        // The governor's once-a-second line is DEBUG, and without it a
        // failure here carries no reason at all - which is exactly what
        // both CI failures on 2 Sep 2026 carried. Narrow rather than
        // `debug`: the default stays info and only the `queue` target
        // opens up, so the log gains one line a second and not the
        // whole daemon's inner monologue.
        c.env("NZBFAST_LOG", "info,queue=debug");
        // **The storage class this rig is about, stated rather than
        // detected - and this is what made it red on 2 Sep 2026.**
        //
        // Rotational output is one of item 5's MANDATORY stand-downs:
        // `get::plan::clamp_concurrency` picks one decoder on a
        // spinning volume "so the article lanes stop being seek lanes",
        // that rule is per-JOB, and two concurrent downloads reinstate
        // exactly the seek pattern it removes. So a spill correctly
        // never happens there.
        //
        // `disk::rotational` is implemented on LINUX only (it reads
        // `queue/rotational` under `/sys/dev/block`) and stubs to `None`
        // everywhere else. Every job that failed this test runs on
        // `ubuntu-latest`, where a cloud VM's virtual disk reports
        // itself rotational; every box it passed on was a Mac, where
        // the answer is `Unknown`. That is why the failure was perfectly
        // deterministic in both directions, why both retries failed
        // identically, why the ON arm was indistinguishable from the
        // OFF arm, and why the head's own wall time was unchanged: the
        // governor was not slow, it had correctly declined.
        //
        // Pinning it is not compressing a threshold and not muting a
        // stand-down: the subject of this rig is the trigger and the
        // lane machinery, not the storage detector, and a test that
        // silently measures nothing on every Linux runner is worth
        // less than one that says which volume it is talking about.
        // Reproduced before the fix by forcing the opposite
        // (`NZBFAST_STORAGE=rotational` on this Mac), which turned a
        // passing run into the CI failure exactly, `rot=true` and all.
        c.env("NZBFAST_STORAGE", "ssd");
        c.arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(base.join("complete"))
            .arg("--min-free")
            .arg("0")
            .arg("--connections")
            .arg(sh.connections.to_string());
        c
    })
    .await;
    let port = d.port;

    // Paused first so the ORDER is ours and not a race between five
    // uploads and a runner that starts on the first one.
    let (head_name, small_names) = qspill_names(sh);
    let (hx, sx, sn) = (head_xml.clone(), small_xml.clone(), small_names.clone());
    tokio::task::spawn_blocking(move || {
        qprog_http(port, "/api?mode=pause&output=json", None);
        qprog_upload(port, &hx, &head_name);
        for (k, xml) in sx.iter().enumerate() {
            qprog_upload(port, xml, &sn[k]);
        }
        qprog_http(port, "/api?mode=resume&output=json", None);
    })
    .await
    .unwrap();

    let t0 = Instant::now();
    let mut small_at: Vec<Option<f64>> = vec![None; sh.smalls];
    let mut head_at: Option<f64> = None;
    let mut peak_downloading = 0usize;
    let mut two_phases_at: Option<f64> = None;
    let mut dump_log = false;
    while t0.elapsed() < sh.budget {
        let queue = tokio::task::spawn_blocking(move || {
            qprog_http(port, "/api?mode=queue&output=json", None)
        })
        .await
        .unwrap();
        let dl_now = qspill_downloading(&queue);
        if dl_now >= 2 && two_phases_at.is_none() {
            two_phases_at = Some(t0.elapsed().as_secs_f64());
        }
        peak_downloading = peak_downloading.max(dl_now);
        let hist = tokio::task::spawn_blocking(move || {
            qprog_http(port, "/api?mode=history&output=json", None)
        })
        .await
        .unwrap();
        for (k, _name) in small_names.iter().enumerate() {
            if small_at[k].is_none() && qspill_done(&hist, &format!("QspillSmall{k}")) {
                small_at[k] = Some(t0.elapsed().as_secs_f64());
            }
        }
        if head_at.is_none() && qspill_done(&hist, "QspillHead") {
            head_at = Some(t0.elapsed().as_secs_f64());
        }
        if head_at.is_some() && small_at.iter().all(Option::is_some) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let total = t0.elapsed().as_secs_f64();
    // A budget that expires with rows unfinished is the one outcome a
    // reader cannot diagnose from the numbers, so the queue is dumped
    // here rather than left to a re-run: what a stuck row READS is the
    // whole of the evidence, and the daemon is about to be stopped.
    if head_at.is_none() || small_at.iter().any(Option::is_none) {
        let queue = tokio::task::spawn_blocking(move || {
            qprog_http(port, "/api?mode=queue&output=json", None)
        })
        .await
        .unwrap();
        let hist = tokio::task::spawn_blocking(move || {
            qprog_http(port, "/api?mode=history&output=json&limit=0", None)
        })
        .await
        .unwrap();
        let names: Vec<String> = serde_json::from_str::<serde_json::Value>(&hist)
            .ok()
            .and_then(|v| {
                Some(
                    v["history"]["slots"]
                        .as_array()?
                        .iter()
                        .map(|s| {
                            format!(
                                "{}={}",
                                s["name"].as_str().unwrap_or("?"),
                                s["status"].as_str().unwrap_or("?")
                            )
                        })
                        .collect(),
                )
            })
            .unwrap_or_default();
        println!("[{tag}] BUDGET EXPIRED, history was: {names:?}");
        println!("[{tag}] BUDGET EXPIRED, queue was: {queue}");
        dump_log = true;
    }
    let log = d.stop();
    if dump_log {
        for l in log
            .text()
            .lines()
            .rev()
            .take(80)
            .collect::<Vec<_>>()
            .iter()
            .rev()
        {
            println!("[{tag}] LOGTAIL {l}");
        }
    }
    let lent = log.text().contains("of its connections - lending them");
    // The count off the daemon's own sentence rather than from
    // `lendable()` re-derived here: what the head actually walked down
    // to is the thing being measured, and re-deriving it would agree
    // with itself whatever the daemon did.
    let lent_conns = log.text().lines().find_map(|l| {
        let (_, rest) = l.split_once("this download is not using ")?;
        let (n, _) = rest.split_once(" of its connections")?;
        n.trim().parse::<usize>().ok()
    });
    // **The governor's own reasoning, kept for the assertion to print.**
    // Two CI failures on 2 Sep 2026 said only "a spill was owed" and
    // carried no reason at all, which cost two lanes a repro each
    // (runs 33612016239 and 33613046588). The once-a-second `spill
    // tick:` line already names every input the decision reads; what
    // was missing was any path from it to a failure message. The last
    // few are what matter - a stand-down that fired, or an input that
    // never arrived, is visible in the final state rather than in the
    // first tick of a warm-up.
    let ticks: Vec<String> = log
        .text()
        .lines()
        .filter(|l| l.contains("spill tick:") || l.contains("spill lease:"))
        .map(str::to_string)
        .collect();
    let why = match ticks.len() {
        0 => "the daemon logged no spill tick at all - the governor never               ran, so the switch was off or the ticker never fired"
            .to_string(),
        n => format!(
            "{n} spill ticks logged; the last three were:
      {}",
            ticks
                .iter()
                .rev()
                .take(3)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("
      ")
        ),
    };
    if std::env::var("NZBFAST_QSPILL_TRACE").is_ok() {
        for l in log.text().lines().filter(|l| {
            l.contains("spill")
                || l.contains("lending")
                || l.contains("not using")
                || l.contains("starting while")
                || l.contains("connections")
                || l.contains("Qspill")
        }) {
            println!("[{tag}] {l}");
        }
    }
    Run {
        smalls: small_at,
        head: head_at,
        total,
        lent,
        lent_conns,
        two_phases_at,
        peak_downloading,
        why,
    }
}

/// The A/B. One test rather than two, because the claim is a
/// COMPARISON: "the smalls finish first" means nothing without the arm
/// that shows they do not when the switch is off, and running the two
/// in one process is what makes the two arms comparable on a loaded
/// box.
/// `_at_shipped_thresholds`, so nextest runs it ALONE
/// (`threads-required = 'num-test-threads'`, `.config/nextest.toml`) and
/// the per-push e2e shards skip it for nightly's complement. It is that
/// class by its own account: the governor runs at the numbers it ships
/// with, and the assertion is that twelve agreeing ticks of the
/// daemon's one-second loop saw dead air inside a twenty-tick window.
/// The cadence of that loop is the part a shared box takes away: on a
/// 4-vCPU runner
/// sharing its shard with three other tests the window was lost twice
/// in a row (run 33612016239, 2 Sep 2026: both attempts 74 s, `on.lent`
/// false) while the same tip passed 2/2 at 75 s on an idle box.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn small_jobs_behind_a_stuck_head_finish_first_only_with_the_spill_on_at_shipped_thresholds()
{
    let off = qspill_arm(false, &SHIPPED, 0).await;
    println!(
        "QSPILL off  head={:?} smalls={:?} total={:.2}s lent={} peak_dl={}",
        off.head, off.smalls, off.total, off.lent, off.peak_downloading
    );
    let on = qspill_arm(true, &SHIPPED, 0).await;
    println!(
        "QSPILL on   head={:?} smalls={:?} total={:.2}s lent={} peak_dl={}",
        on.head, on.smalls, on.total, on.lent, on.peak_downloading
    );

    // The control arm, and it is the more important half: with the
    // switch off nothing about the queue may have changed. The head
    // runs alone and the jobs behind it wait, which is the shipped
    // serial queue.
    assert!(
        !off.lent,
        "the switch is off, so no connection may be lent to anything.\n  \
         The governor's own account: {}",
        off.why
    );
    assert_eq!(
        off.smalls_first(),
        Some(false),
        "with the spill off the head finishes first - that is the queue \
         nzbfast has always had, and this arm exists to prove the switch \
         changes nothing when it is off"
    );

    // And the feature.
    assert!(
        on.lent,
        "the head sat on dead air for longer than the governor's window \
         with four jobs queued behind it, so a spill was owed.\n  \
         The governor's own account: {}",
        on.why
    );
    assert_eq!(
        on.smalls_first(),
        Some(true),
        "with the spill on, the jobs behind a stuck head finish while it \
         waits - which is the whole claim"
    );

    // The phase cap, and the queue row. TWO jobs read Downloading at
    // once during a spill and never three: that is
    // `spill::MAX_DOWNLOAD_PHASES`, and it is this daemon's structural
    // bound (two wire slots) as much as a policy. A lane that showed as
    // `Queued` while it was on the wire would be a bug report about a
    // stuck queue, so the word is asserted rather than the bytes.
    assert_eq!(
        on.peak_downloading, 2,
        "a spilled lane reads as Downloading beside the head, and no \
         third phase ever runs"
    );
    assert!(
        off.peak_downloading <= 2,
        "the shipped hand-over already overlaps a drain with a start, so \
         two is the control arm's ceiling too"
    );
}

/// The 1-minute load average, or `None` where the box will not say.
///
/// Printed with every row because this rig is a wall-clock A/B and the
/// dev box runs up to a dozen other lanes' builds: a reader who cannot
/// see what else was on the machine cannot tell a result from a queue.
fn qspill_loadavg() -> Option<f64> {
    let out = Command::new("uptime").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (_, rest) = text.split_once("load average")?;
    rest.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find(|t| !t.is_empty())
        .and_then(|t| t.parse().ok())
}

/// TODO 313 item 10 AT THE STUDY'S OWN SCALE: is the 29-45% of total
/// wall real on a daemon, or is the order-only result of the shipped
/// regression test the whole of it?
///
/// **This is a MEASUREMENT RIG and no job runs it**, which is the door
/// it goes through and is said here rather than left to be discovered:
/// `#[ignore]`, so neither the per-push e2e shards nor nightly's
/// `cargo test --test e2e -- --test-threads=1` executes a second of it.
/// It is the rig behind the SECOND `2026-09-02` queue-spill entry in
/// the performance log (the one whose headline says 9.7%), kept in the
/// tree rather than pasted into an appendix because it is thirty lines
/// on top of a harness that already ships and because the question it
/// answers is the one anybody deciding the default will ask again.
///
/// **What it answered on 2 Sep 2026**, so a reader has the result at
/// the site: 42.10 s ON against 46.60 s OFF, three repeats, which is
/// -9.7% of total wall and not the study's 29-45%. All eight small
/// jobs clear at 13.2-21.9 s against a head at 42.0-42.3 s, so the
/// ORDER claim holds at the study's own count while the throughput one
/// does not. Three shipped facts account for the gap and TODO 313
/// item 10's stamp carries them.
///
/// **The third of those three was a DEFECT and this rig is what found
/// it** (item 12, fixed the same day): `serve::linecarry` re-trained
/// the trigger's denominator from the stuck head itself inside four
/// seconds, so every episode ended after about fifteen seconds whatever
/// the head was doing. With the denominator now frozen at the head's
/// pool build the eight-job answer is unchanged - eight jobs never
/// filled fifteen seconds - and the DEEP-queue answer roughly doubles,
/// from -7.8% to -15.5% with 24 of 24 clearing before the head instead
/// of 12-13. Which is why `NZBFAST_QSPILL_SMALLS=24` below is the arm
/// worth running, not a curiosity. Run it by hand:
///
/// ```text
/// cargo nextest run -p nzbfast --features heavy-tests --test e2e \
///   --run-ignored only -E 'test(qspill_study_scale)' --no-capture
/// ```
///
/// `NZBFAST_QSPILL_REPS` sets the repetition count (default 3). Each
/// repetition runs OFF then ON back to back, so a box that drifts
/// during the run drifts under both arms of the same pair.
///
/// `NZBFAST_QSPILL_SMALLS` overrides how many small jobs are queued
/// behind the head, and it is the knob the whole result turns on rather
/// than a convenience. The win a spill can buy is bounded by the share
/// of the serial wall the jobs behind it own, and the study's `M9` had
/// that share at 53% because its head was 5.21 s long. This daemon's
/// head cannot be 5.21 s long - the governor wants twelve agreeing
/// ticks first - so at the study's own EIGHT jobs the share is small
/// and so is the win. Running the same head against a DEEPER queue is
/// how you find out whether the mechanism or the shape is the limit.
///
/// **It asserts almost nothing on purpose.** The measuring module this
/// lives in says why at length: the output is a table, a row that
/// surprises you is a table entry, and a rig that turns into a fix
/// loses the table. The one thing it does insist on is that the two
/// arms are the arms they claim to be - the switch off lends nothing,
/// the switch on lends something - because a pair of identical arms
/// would produce a beautiful and meaningless number.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "wall-clock A/B measurement rig, ~6 min at three reps; run by hand"]
async fn qspill_study_scale_ab_measurement() {
    let reps: usize = std::env::var("NZBFAST_QSPILL_REPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let shape = Shape {
        smalls: std::env::var("NZBFAST_QSPILL_SMALLS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(STUDY.smalls),
        budget: std::env::var("NZBFAST_QSPILL_BUDGET_S")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(STUDY.budget),
        ..STUDY
    };
    println!(
        "M9D shape head={}art/{}silent@{}ms art={}B smalls={}x{}B/{}B conns={} percon={}B/s reps={}",
        shape.head_articles,
        shape.head_silent,
        shape.silence_ms,
        shape.head_art,
        shape.smalls,
        shape.small_bytes,
        shape.small_art,
        shape.connections,
        shape.per_conn_bps,
        reps
    );
    // Total wall per arm, OFF then ON for each repetition.
    let mut wins: Vec<f64> = Vec::new();
    for r in 0..reps {
        for on in [false, true] {
            let load = qspill_loadavg();
            let run = qspill_arm(on, &shape, r).await;
            let done = run.smalls.iter().filter(|s| s.is_some()).count();
            let before = run
                .smalls
                .iter()
                .filter(|s| match (s, run.head) {
                    (Some(t), Some(h)) => *t < h,
                    _ => false,
                })
                .count();
            let (head, total, lent_conns, two_at, peak, times) = (
                run.head,
                run.total,
                run.lent_conns,
                run.two_phases_at,
                run.peak_downloading,
                &run.smalls,
            );
            let want = shape.smalls;
            println!(
                "M9D rep={r} spill={on} load1={load:?} head={head:?} total={total:.2}s \
                 smalls_done={done}/{want} smalls_before_head={before} \
                 lent={lent_conns:?} two_phases_at={two_at:?} peak_dl={peak} \
                 smalls={times:?}"
            );
            wins.push(run.total);
            // The arms are the arms they claim to be, or the number
            // below compares a thing to itself.
            if on {
                assert!(run.lent, "rep {r}: the spill was on and nothing was lent");
            } else {
                assert!(
                    !run.lent,
                    "rep {r}: the spill was off and something was lent"
                );
            }
        }
    }
    for (r, pair) in wins.chunks(2).enumerate() {
        let (off, on) = (pair[0], pair[1]);
        println!(
            "M9D rep={r} off={off:.2}s on={on:.2}s delta={:+.1}%",
            (on - off) / off * 100.0
        );
    }
    let offs: Vec<f64> = wins.iter().step_by(2).copied().collect();
    let ons: Vec<f64> = wins.iter().skip(1).step_by(2).copied().collect();
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    println!(
        "M9D MEAN off={:.2}s on={:.2}s delta={:+.1}%",
        mean(&offs),
        mean(&ons),
        (mean(&ons) - mean(&offs)) / mean(&offs) * 100.0
    );
}
