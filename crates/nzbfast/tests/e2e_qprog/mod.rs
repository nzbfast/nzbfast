//! Queue progress under fault: does a broken job at the HEAD of the
//! queue block the healthy jobs behind it?
//!
//! A new AXIS on the TODO 283 fault matrix (`e2e_faults`), not a new
//! rig. That matrix has fourteen numbered shapes and every one of them
//! runs against a queue of exactly ONE job, through the `get` CLI - so
//! the whole of it answers "can this job recover" and none of it
//! answers "do the jobs behind it still finish". Verified mechanically
//! on 26 Aug 2026: fourteen `#[tokio::test]` in `e2e_faults/mod.rs`,
//! not one of which enqueues a second job, and `grep -rn
//! "head.of.line\|head_of_line\|blocks_the_queue" crates/` returning
//! two hits that are both about ARTICLE pipelining inside one
//! connection fleet.
//!
//! **This is a MEASUREMENT rig and its output is a table.** The
//! assertions pin only what has to hold for a row to mean anything -
//! the daemon came up, the broken job really was at the head, the
//! control really did drain. What each shape DOES is reported, in
//! `research/QUEUE-PROGRESS-UNDER-FAULT-2026-08-26.md`. A shape that
//! holds the line is a product defect that gets its own TODO section,
//! never a fix inside this module: a measurement round that turns into
//! a fix loses the table, which is the deliverable.
//!
//! **And, since TODO 306, FIVE REGRESSION tests beside the table.**
//! Round A's finding F4 was that no demotion arm can fire inside ~69 s,
//! so a dead post that grinds itself out faster than that holds the
//! queue for its whole run - measured here at 16.7 s against a 1.0 s
//! control, `set aside never`. The fix is an early post-is-gone arm
//! gated on run-cumulative evidence rather than on elapsed time
//! (`tasks/stall.rs::gone_evidence`), with a PARTIAL twin for the
//! takedown that lands some bytes first
//! (`tasks/stall.rs::partial_gone_defer`);
//! [`a_dead_head_is_set_aside_at_shipped_thresholds`] and
//! [`a_partial_head_is_set_aside_at_shipped_thresholds`] are the only
//! tests anywhere that pin them AT THE SHIPPED THRESHOLDS, and
//! [`a_dead_provider_sets_the_head_aside_and_the_queue_drains`] closes
//! F7's other half, the outage arm that had no coverage of any kind.
//! That distinction is
//! the entire point: F7 measured that all seven pre-existing
//! `NZBFAST_DEFER_WARMUP_SECS` overrides under `crates/nzbfast/tests/`
//! compress the warmup to 1-2 s, so this mechanism's whole coverage ran
//! in a regime the product never ships in. They ASSERT rather than
//! reporting, and they are a handful of tests rather than a sweep, so
//! the measuring rows above keep their character: a row that surprises
//! you is still a table entry and still gets its own TODO section.
//!
//! The fifth is TODO 308's and is the only one whose subject is a
//! DRAINING predecessor rather than the hub owner:
//! [`a_draining_head_behind_a_dead_provider_is_set_aside_and_the_queue_drains`].
//! Round A found that row on the way to F7 and filed it - a head that
//! hands over while still holding articles only an unreachable server
//! could serve held all four queued jobs, with no terminal row anywhere
//! for the whole 150 s budget. Measured at the SHIPPED provider
//! thresholds on 27 Aug 2026 it is not a wedge but a 613.7 s wait, the
//! pool's own consecutive bounce ladder being the only thing that ever
//! releases it. The fix is one line and no new detector: `watched`
//! already prefers a draining predecessor and already carries that
//! job's own gauges, and the outage arm reached past them to the hub -
//! which after a hand-over belongs to the successor. See
//! `serve/outage.rs::outages_in`.
//!
//! **Why the daemon and not `run_get`.** Every mechanism in question is
//! the daemon's - `pick_job`'s ordering key in `crates/nzbfast-daemon/src/daemon.rs`, the
//! five mid-flight demotion arms in `tasks/stall.rs`, and the
//! idle-server sidecar beside them. The CLI has no queue at all, which
//! is why the existing matrix could not have asked this question
//! however it was written.
//!
//! **The fault reaches ONE job, by construction.** `Chaos::missing` and
//! its siblings are sets of message-ids, and each fixture mints its own
//! ids off its own file names, so a chaos set built from the broken
//! post's `FaultPlan` cannot name a healthy peer's article even though
//! one mock server serves all of them. Two shapes are the exception and
//! say so in their own row: `brownout_after` and `delay_ms` are
//! properties of the SERVER, so shapes 7 and 11 are fleet-wide faults
//! and their rows answer a different question.
//!
//! These are HEAVY - a real daemon, a real mock fleet and four real
//! downloads per row - so they live in the `e2e` target, build-gated
//! behind `heavy-tests` (§116b) and serialized by the `e2e-serial`
//! group in `.config/nextest.toml`.

// Every free function here carries a `qprog_` prefix, and that is not
// house style - it is `tools/par2-gate.py`. That gate resolves helper
// names TREE-WIDE (its own header says why: the `e2e_*/` directories are
// `mod` children of one file sharing a namespace), and it marks any
// function that transitively reaches `par2 create` as a sink. A helper
// in here called `row` therefore makes every `.row(` in every suite a
// par2 sink: measured 26 Aug 2026 at 25 sinks before and 238 after, with
// 382 tests across the whole tree reported unguarded. Keep the prefix on
// anything this module reaches par2 through.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

use nzbkit::faultplan::Role;
use nzbkit::mock::{Chaos, MockServer};

use super::e2e_faults::{
    RECOVERY_YIELD_ART, matrix_post, matrix_post_art, matrix_post_vols, plan, rename_par2_posts,
};
use super::harness::serve;
use super::{Fixture, have_par2, unix_now};
use crate::payloads;

// TODO 313 items 2-5 and 10: the queue spill's own end-to-end A/B. A
// sibling module rather than more of this file - it shares the daemon
// helpers above and nothing else, and this file is already the largest
// e2e module in the tree.
mod spill;

/// Healthy jobs queued BEHIND the broken head.
///
/// Three rather than one: a single peer cannot tell "the queue moved"
/// from "the queue moved once", and three puts a peer behind the peer
/// that the watchdog's `others_waiting` test finds - which is what the
/// demotion arms and the sidecar actually reorder against.
const HEALTHY: usize = 3;

/// One healthy peer's payload size and article size.
///
/// Big enough that a completion is a real download rather than one
/// article, small enough that the control row is seconds.
const PEER_BYTES: usize = 600_000;
const PEER_ART: usize = 40_000;

/// How long a row may take before the harness stops polling.
///
/// A row that hits this is REPORTED as stranded rather than failing the
/// test: "the queue never drained" is the most interesting answer this
/// rig can produce and it has to reach the table rather than dying in
/// an assertion message.
const ROW_BUDGET: Duration = Duration::from_secs(150);

/// The watchdog thresholds every row runs with.
///
/// Production is 45 s of warmup and a 30 s window, so no mid-flight
/// demotion can fire inside the first ~75 s of a job whatever it is
/// doing. Compressing them is what makes fourteen rows affordable, and
/// the table states the production equivalent beside every compressed
/// figure: the MECHANISM is what this rig measures, and the wall at
/// production thresholds is `warmup + window` plus what the compressed
/// row measured.
///
/// `NZBFAST_DEFER_GONE_MIN_MISSES` is compressed for that reason and
/// one more. The shipped floor is 64 refusals inside ONE window, and
/// these fixtures are tens of articles, so at the shipped figure the
/// post-is-gone arm cannot fire on a fixture this size however dead the
/// post is. A row reporting "no demotion" against an uncompressed floor
/// would be reporting the fixture rather than the product.
const DEFER_ENV: &[(&str, &str)] = &[
    ("NZBFAST_DEFER_WARMUP_SECS", "3"),
    ("NZBFAST_DEFER_WINDOW_SECS", "5"),
    ("NZBFAST_DEFER_GONE_MIN_MISSES", "8"),
];

/// What a refusal COSTS on the wire.
///
/// The matrix this axis extends runs at localhost speed, where a 430 is
/// free, and its own shape-11 header says in as many words that this
/// "keeps every other test at localhost speed and makes every other
/// test blind to the cost of driving a dead queue to terminal". A
/// head-of-line measurement taken with free refusals is that blindness
/// exactly: §282's incident was FORTY-SIX MINUTES of asking a provider
/// for data it would not serve, and at zero cost per refusal that same
/// post reaches its verdict in about a second. So every shape is
/// measured twice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arm {
    /// The matrix's own conditions: refusals are free.
    Free,
    /// A measured cold-provider tier - a 430 is a full transatlantic
    /// round trip, and the provider does not echo the id, so it is
    /// asked up to TWICE for every article it does not have
    /// (`Chaos::echo_missing_id`). Both figures are shape 11's, which
    /// is where they were measured.
    ///
    /// This charges REFUSALS and not bodies, and that is what keeps the
    /// arm job-scoped: `missing_delay_ms` is a property of the server,
    /// but it is only ever paid on an id in `chaos.missing`, and the
    /// only ids in there are the broken post's. A healthy peer sharing
    /// the same mock pays nothing.
    Charged,
}

impl Arm {
    fn tag(self) -> &'static str {
        match self {
            Arm::Free => "free",
            Arm::Charged => "charged",
        }
    }

    fn apply(self, chaos: &mut Chaos) {
        if self == Arm::Charged {
            chaos.missing_delay_ms = 50;
            chaos.echo_missing_id = false;
        }
    }
}

/// Which watchdog thresholds the daemon runs with.
///
/// [`DEFER_ENV`] says why the compressed set exists. The SHIPPED set is
/// the row that answers what any of this costs a real user, and it is
/// cheap to run precisely because of what it measures: at 45 s of
/// warmup and a 30 s window, the demotion arms in
/// `tasks/stall.rs` that still take an elapsed-time gate cannot
/// be reached before about 69 s of one job (`warmup`, then a window at
/// least 80% full), and the WINDOWED post-is-gone arm additionally
/// wants 64 refusals answered inside one window with not a byte
/// arriving.
///
/// That was true of all of them until TODO 306, which is what made a
/// broken job that grinds itself out in under a minute hold the queue
/// for its whole run - and it is still true of the outage and
/// single-server-bound arms, deliberately, because a job that is
/// starting slowly must not be benched for it. The two post-is-gone
/// arms are the exception. The EARLY one reads the run, and speaks only
/// for a post that has landed NOTHING, which is S5. The PARTIAL one
/// reads a FLATLINE inside the window rather than the whole of it, and
/// is what speaks for S6, whose first third arrives - both twins fire
/// with no warmup, and each is bounded by its own evidence instead.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Watchdog {
    Compressed,
    Shipped,
}

impl Watchdog {
    fn tag(self) -> &'static str {
        match self {
            Watchdog::Compressed => "",
            Watchdog::Shipped => "@shipped",
        }
    }

    fn env(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Watchdog::Compressed => DEFER_ENV,
            Watchdog::Shipped => &[],
        }
    }
}

/// One measured row.
#[derive(Debug, Default)]
struct Row {
    shape: String,
    /// Wall from the unpause to the FIRST healthy peer's terminal
    /// history row.
    first_healthy: Option<Duration>,
    /// Wall to the LAST of them.
    all_healthy: Option<Duration>,
    /// Wall to the broken job's own terminal row, if it reached one.
    broken_settled: Option<Duration>,
    /// The broken job's terminal status, or where the poll left it.
    broken_end: String,
    /// Every `[defer]` line the run emitted, in order - one per
    /// mid-flight demotion, carrying its own stated reason.
    defers: Vec<String>,
    /// What a demoted job's RERUN found already on disk - the whole
    /// claim the mid-flight demotion rests on. Empty when the job never
    /// restarted, or restarted with nothing to resume from.
    resumed: String,
    /// A sidecar ran while the head job still held the runner.
    sidecar: bool,
    /// Peers with no terminal row inside [`ROW_BUDGET`].
    stranded: usize,
    /// How many times the head job STARTED. Two or more means it was
    /// set aside mid-flight and picked up again.
    head_runs: usize,
    /// Set when the fault is a property of the SERVER rather than of
    /// one post, so the row is not a head-of-line measurement.
    fleetwide: Option<&'static str>,
}

/// The body [`qprog_http`] read, de-chunked when `head` says
/// `Transfer-Encoding: chunked`.
///
/// tiny_http switches to chunked once a response passes its threshold,
/// and every prior version of the caller-side helper (`spill.rs`'s
/// `qspill_json`, moved here) handed back the raw chunked wire text -
/// `<hexlen>\r\n{json}...` - which every `serde_json::from_str` on it
/// failed to parse. A history page crosses that threshold at about
/// EIGHTEEN rows. Measured 2 Sep 2026: a 24-job queue read as seventeen
/// jobs finished and then a dead queue for the rest of the budget, with
/// the daemon's own log showing all twenty-four completing normally - a
/// rig fault indistinguishable from a wedged queue at the only place
/// anybody looks.
///
/// The decision is read from the HEADER rather than guessed from the
/// body's shape, because `qprog_http` also serves `qprog_upload`'s POST
/// responses and non-JSON bodies: a heuristic that misread a plain body
/// as chunked would corrupt every caller, which is worse than the fault
/// this exists to fix.
fn qprog_dechunk(head: &str, body: &str) -> String {
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        let l = l.trim_start();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if !chunked {
        return body.to_string();
    }
    let mut out = String::new();
    let mut rest = body;
    while let Some((len, tail)) = rest.split_once("\r\n") {
        let Ok(n) = usize::from_str_radix(len.trim(), 16) else {
            break;
        };
        if n == 0 {
            break;
        }
        // Byte indices, because a chunk length is a byte count. `get`
        // rather than a slice so a chunk that lands mid-codepoint gives
        // up instead of panicking.
        let Some(chunk) = tail.get(..n) else { break };
        out.push_str(chunk);
        let Some(next) = tail.get(n + 2..) else { break };
        rest = next;
    }
    out
}

/// A daemon request, headers read and stripped.
///
/// A local copy rather than a shared helper, and that is the state of
/// the house rather than a shortcut: `daemon.rs`, `queue_soak.rs` and
/// `http_wedge.rs` each carry their own, and hoisting all of them into
/// `harness/mod.rs` is a change to six suites with nothing to do with
/// this round. A refused connection is retried; an answer that started
/// arriving is returned as it arrived, because a truncated response
/// must never be retried away. The body is de-chunked through
/// [`qprog_dechunk`] before it is handed back, so every caller sees the
/// body it asked for whether or not tiny_http chunked it.
fn qprog_http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for _ in 0..40 {
        let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let head = match body {
            Some((ctype, b)) => format!(
                "POST {req} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {ctype}\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                b.len()
            ),
            None => format!("GET {req} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        };
        if s.write_all(head.as_bytes()).is_err() {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        if let Some((_, b)) = body
            && s.write_all(b).is_err()
        {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let mut out = String::new();
        if s.read_to_string(&mut out).is_err() {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        last = match out.split_once("\r\n\r\n") {
            Some((head, b)) => qprog_dechunk(head, b),
            None => out,
        };
        return last;
    }
    last
}

/// Upload one NZB under `name`.
fn qprog_upload(port: u16, xml: &str, name: &str) {
    let boundary = "----qprogb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; \
             filename=\"{name}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = qprog_http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "addfile {name} refused: {r}");
}

/// Distinct bytes per peer, so two peers can never be confused for one
/// another on disk or in a chaos set.
fn peer_payload(k: usize) -> Vec<u8> {
    payloads::unique_payload(PEER_BYTES, 0x0026_0826_0000_0000 ^ k as u64)
}

/// A healthy post nothing in any chaos set can name.
///
/// The file-name prefix is what makes that true rather than likely:
/// `Fixture::add_file` mints every message-id off the file name, and
/// every chaos set here is resolved from the BROKEN post's own
/// `FaultPlan`, so no id this post owns can appear in one.
fn healthy_fixture(tag: &str, k: usize) -> Fixture {
    let mut fx = Fixture::new(tag);
    fx.add_file(&format!("peer{k}.bin"), &peer_payload(k), PEER_ART);
    fx
}

/// The broken head of a row: a post, the chaos that breaks it, and how
/// the fleet in front of it is arranged.
struct Broken {
    fx: Fixture,
    chaos: Chaos,
    /// Healthy peer SERVERS behind the faulted one (shape 10's fleet-5
    /// arm). Zero everywhere else.
    peer_servers: usize,
    /// UNREACHABLE servers appended to the fleet: they accept TCP and
    /// tear the connection down before the greeting, forever, and carry
    /// no articles at all. Zero everywhere but `W1-refused-plus-dead`.
    ///
    /// A separate count from [`Broken::peer_servers`] because the
    /// difference is the whole of W1: a healthy peer server ANSWERS, so
    /// a fleet built out of them can always reach a verdict, while one
    /// of these can neither serve nor refuse - the pool has to wait out
    /// its own outage ladder before it can say anything about an
    /// article only this server might have held.
    down_servers: usize,
    /// Extra JSON fields for each server object in the daemon's config,
    /// by FLEET INDEX - 0 is the faulted server, 1.. are the
    /// [`Broken::peer_servers`] behind it. An entry that is empty, or
    /// missing entirely, leaves that server at host/port/tls alone,
    /// which is what every shape but `U1-unprobed-server` wants.
    ///
    /// It exists because one shape's whole fault is a SETTING rather
    /// than a message-id: a `retention_days` short enough to rule the
    /// head's post out is how a server ends up up, healthy and never
    /// asked, which is the one fleet the windowed post-is-gone arm has
    /// to itself.
    server_extra: Vec<String>,
    /// Daemon environment this shape needs on top of [`DEFER_ENV`].
    env: Vec<(&'static str, &'static str)>,
    /// Why this shape's fault cannot be scoped to one post.
    fleetwide: Option<&'static str>,
}

impl Broken {
    fn new(fx: Fixture, chaos: Chaos) -> Broken {
        Broken {
            fx,
            chaos,
            peer_servers: 0,
            down_servers: 0,
            server_extra: Vec::new(),
            env: Vec::new(),
            fleetwide: None,
        }
    }
}

/// Build the broken head for `shape`, or `None` when this box cannot
/// (no `par2` binary).
///
/// The geometries are the matrix's own, reached through
/// `e2e_faults`'s builders rather than restated: a row is only
/// comparable with TODO 283's verdict for the same shape if it is
/// literally the same post and the same damage.
fn broken_for(shape: &str, arm: Arm, wd: Watchdog) -> Option<Broken> {
    let par2 = have_par2();
    Some(match shape {
        // Shape 1: the recovery set is dead, the payload is healthy.
        "1-dead-recovery" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-deadrec-{}{}", arm.tag(), wd.tag()));
            matrix_post_art(&mut fx, 40, 65_536, 8, None, RECOVERY_YIELD_ART);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .fraction(0.008)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            p.role(Role::Par2Volumes)
                .fraction(0.93)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 2: the recovery volume arrives in PART, and repairs.
        "2-partial-volume" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-partvol-{}{}", arm.tag(), wd.tag()));
            matrix_post_vols(&mut fx, 40, 65_536, 8, Some(1));
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .evenly(1)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            let vol = p.role(Role::Par2Volume(0)).expect_nonempty(&p);
            let tail: Vec<String> = vol.ids()[vol.len() / 2..].to_vec();
            chaos.missing.extend(tail);
            Broken::new(fx, chaos)
        }
        // Shape 3: the payload is dead and the recovery is healthy.
        "3-dead-payload" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-deadpay-{}{}", arm.tag(), wd.tag()));
            matrix_post(&mut fx, 40, 65_536, 8);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .fraction(0.5)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 4: one block PAST the recovery count - the leg of the
        // boundary that fails, which is the only one of the three that
        // can hold a queue.
        "4-past-the-boundary" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-edge-{}{}", arm.tag(), wd.tag()));
            matrix_post(&mut fx, 40, 65_536, 8);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .evenly(9)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 5: a ONE-day-old post that 430s everywhere. The fresh
        // arm rather than the old one: a post called gone is filed and
        // gone, where a post still propagating is the one the product
        // deliberately keeps hoping for.
        "5-fresh-430s" => {
            let mut fx = Fixture::new(&format!("qprog-fresh-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(90);
            fx.add_file("fresh.bin", &data, 40_000);
            fx.date = unix_now() - 86_400;
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Everything)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 6: takedown by replacement - every body fails its CRC.
        "6-replaced-post" => {
            let mut fx = Fixture::new(&format!("qprog-replaced-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(91);
            fx.add_file("taken.bin", &data, 40_000);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Everything)
                .expect_nonempty(&p)
                .corrupt(&mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 7: stalled AND holding real 430s. FLEET-WIDE by
        // construction - `brownout_after` mutes the frontend for every
        // job on it, so this row is not a head-of-line measurement.
        "7-stall-and-430s" => {
            let mut fx = Fixture::new(&format!("qprog-both-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(92);
            fx.add_file("both.bin", &data, 40_000);
            let p = plan(&fx);
            let mut chaos = Chaos {
                brownout_after: 6,
                ..Default::default()
            };
            p.role(Role::Payload)
                .fraction(0.2)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            let mut b = Broken::new(fx, chaos);
            b.env.push(("NZBFAST_STALL_ABORT_SECS", "8"));
            b.fleetwide = Some("brownout_after mutes the SERVER, not the post");
            b
        }
        // Shape 8: a `.vol-NN.par2` set - deferred, and still repairs.
        "8-vol-dash-naming" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-voldash-{}{}", arm.tag(), wd.tag()));
            matrix_post(&mut fx, 40, 65_536, 8);
            rename_par2_posts(&mut fx, |i| {
                if i == 0 {
                    "release.par2".to_string()
                } else {
                    format!("release.vol-{i:02}.par2")
                }
            });
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .evenly(1)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 9: recovery volumes under junk names, found by packet
        // magic - repairs.
        "9-junk-named-par2" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-junkpar2-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(93);
            fx.add_file("junk.bin", &data, 65_536);
            if !fx.add_par2_obfuscated(20, &["junk.bin"], 65_536) {
                return None;
            }
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Named("junk.bin".into()))
                .evenly(1)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 10: shape 1's fault with four healthy backbones behind
        // the faulted one. The job repairs; the row is about what that
        // costs the peers.
        "10-second-backbone" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-fleet5-{}{}", arm.tag(), wd.tag()));
            matrix_post(&mut fx, 40, 65_536, 8);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .evenly(1)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            p.role(Role::Par2Volumes)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            let mut b = Broken::new(fx, chaos);
            b.peer_servers = 4;
            b
        }
        // Shape 11: a refusal that costs a real round trip. The delays
        // are the SERVER's, so the peers pay them too - stated in the
        // row rather than hidden.
        "11-cold-latency" => {
            let mut fx = Fixture::new(&format!("qprog-cold-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(94);
            fx.add_file("cold.bin", &data, 40_000);
            fx.date = unix_now() - 30 * 86_400;
            let p = plan(&fx);
            let mut chaos = Chaos {
                delay_ms: 44,
                missing_delay_ms: 50,
                echo_missing_id: false,
                ..Default::default()
            };
            p.role(Role::Everything)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            let mut b = Broken::new(fx, chaos);
            b.fleetwide = Some("delay_ms and missing_delay_ms are the SERVER's, so peers pay too");
            b
        }
        // Shape 12: split brain - the right id, the wrong article.
        "12-split-brain" => {
            let mut fx = Fixture::new(&format!("qprog-splitbrain-{}{}", arm.tag(), wd.tag()));
            let a = peer_payload(95);
            let b = peer_payload(96);
            fx.add_file("alpha.bin", &a, 40_000);
            fx.add_file("beta.bin", &b, 40_000);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            let alpha = p.role(Role::Named("alpha.bin".into())).expect_nonempty(&p);
            let beta = p.role(Role::Named("beta.bin".into())).expect_nonempty(&p);
            alpha.swap_with(&beta, &mut chaos);
            Broken::new(fx, chaos)
        }
        // Shape 13: a bootstrap volume AND a refused repair fetch.
        "13-bootstrap-and-refusal" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-bothclauses-{}{}", arm.tag(), wd.tag()));
            matrix_post_art(&mut fx, 40, 65_536, 8, Some(8), RECOVERY_YIELD_ART);
            fx.nzb_files
                .retain(|(n, _)| nzbkit::faultplan::role_of(n) != nzbkit::nzb::FileKind::Par2Main);
            let p = plan(&fx);
            let boot = p.files_in(Role::SmallestVolume)[0].name.clone();
            let others: Vec<String> = p
                .files_in(Role::Par2Volumes)
                .iter()
                .map(|f| f.name.clone())
                .filter(|n| *n != boot)
                .collect();
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .evenly(1)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            p.role(Role::SmallestVolume)
                .without_heads(&p, Role::SmallestVolume)
                .evenly(1)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            for n in &others {
                p.role(Role::Named(n.clone()))
                    .expect_nonempty(&p)
                    .missing(&mut chaos);
            }
            Broken::new(fx, chaos)
        }
        // Shape 14: the escalation's own ask, refused.
        "14-refused-escalation" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-lastask-{}{}", arm.tag(), wd.tag()));
            matrix_post_vols(&mut fx, 40, 65_536, 20, Some(20));
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .evenly(1)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            p.role(Role::Par2Volumes)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // ---- The two AT-SCALE rows. ----
        //
        // Every shape above is the matrix's own geometry, which is tens
        // of articles - and a head-of-line question is about DURATION,
        // so a fixture that cannot take long cannot answer it. These
        // two are the live incidents in miniature: the same faults, at
        // an article count where driving them to terminal is measured
        // in tens of seconds rather than in one.
        //
        // They are also the only rows that can reach the mid-flight
        // demotions at all. `tasks/stall.rs` gates three of its
        // four arms on `now - t0 >= warmup` AND a full window of
        // samples, and the fourth on two watchdog ticks of confirmed
        // evidence, so a job that ends in a second is gone before the
        // watchdog has taken its second reading, whatever it was doing.

        // §282's incident, reduced: a payload that arrived nearly whole
        // over a recovery set the provider will not serve. Live, 24 Aug
        // 2026, that was 46 minutes of asking.
        "S1-dead-recovery-at-scale" => {
            if !par2 {
                return None;
            }
            let mut fx = Fixture::new(&format!("qprog-s1-{}{}", arm.tag(), wd.tag()));
            // 80 recovery blocks posted at 512 bytes an article is
            // 1280 recovery articles, and 93% of them refused at a
            // transatlantic round trip asked twice each is about half a
            // minute of grinding PER LADDER ROUND. That is the point of
            // the geometry: §282's 46 minutes were spent in the repair
            // ladder, not in the download, and no row here can say
            // whether the watchdog can even SEE a job in that state
            // unless the state lasts longer than a window.
            matrix_post_art(&mut fx, 600, 8_192, 80, None, 512);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Payload)
                .fraction(0.008)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            p.role(Role::Par2Volumes)
                .fraction(0.93)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // The 14 Aug 2026 incident, reduced: two 21-day-old releases
        // whose every article was taken down held the queue for ten
        // minutes each at 0.0 MB/s while other jobs waited. That is the
        // case `tasks/stall.rs`'s post-is-gone arm was written
        // for, and this is the only row in this module that can reach
        // it - 1200 articles, every one refused.
        "S5-dead-post-at-scale" => {
            let mut fx = Fixture::new(&format!("qprog-s5-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(97);
            let mut big = Vec::with_capacity(4_800_000);
            while big.len() < 4_800_000 {
                big.extend_from_slice(&data);
            }
            big.truncate(4_800_000);
            fx.add_file("dead.bin", &big, 4_000);
            fx.date = unix_now() - 21 * 86_400;
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Everything)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            Broken::new(fx, chaos)
        }
        // The journal question, which nothing else here can ask. §283's
        // matrix has no shape where a job lands real bytes and is THEN
        // set aside, and the mid-flight demotion's whole claim is that
        // it is cheap because "the journal keeps everything already
        // landed, so the eventual rerun fetches only what is still
        // missing" (`daemon_park.rs`). `S5` cannot test that: it
        // lands zero bytes, so a rerun that refetched everything and one
        // that resumed perfectly are the same run.
        //
        // The first third of the post arrives and the rest is refused,
        // which is what a partial takedown looks like from the client
        // and which puts a zero-byte window with hundreds of refusals in
        // it AFTER real progress - the only way into the post-is-gone
        // arm that leaves anything to resume.
        //
        // THREE TIMES `S5`'s article count, and that is a measurement
        // rather than a round number (TODO 306, 26 Aug 2026). What this
        // row has to make observable is a FLATLINE, and at the shipped
        // thresholds the watchdog samples every 5 s - so the earliest
        // any flatline arm can speak is one tick of phase plus its own
        // minimum, and nothing shorter than about 15 s of flatline can
        // be seen at all. At 1200 articles this post ground itself out
        // in 10.7 s TOTAL with roughly 8 s of flatline in it, which is
        // inside the rig's own sampling noise: the row would have
        // reported `set aside` or `never` depending on where the
        // daemon's tick phase happened to fall. The arriving third is
        // still 1200 articles, which is `S5` entire, so the two rows
        // stay readable against each other.
        "S6-dead-tail-at-scale" => {
            let mut fx = Fixture::new(&format!("qprog-s6-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(98);
            let mut big = Vec::with_capacity(14_400_000);
            while big.len() < 14_400_000 {
                big.extend_from_slice(&data);
            }
            big.truncate(14_400_000);
            fx.add_file("tail.bin", &big, 4_000);
            fx.date = unix_now() - 21 * 86_400;
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            let sel = p.role(Role::Payload).expect_nonempty(&p);
            let ids = sel.ids();
            chaos.missing.extend(ids[ids.len() / 3..].to_vec());
            Broken::new(fx, chaos)
        }
        // ---- The OUTAGE row. ----
        //
        // The one shape here whose fault is not a message-id at all,
        // and the one demotion arm round A's F7 measured as having no
        // end-to-end coverage of ANY kind: grepping
        // `has had no usable connection for` over `crates/` finds it
        // only at its definition in `tasks/stall.rs`, and until
        // this row nothing anywhere set `NZBFAST_SERVER_DOWN_SECS`
        // either. The other two windowed arms have regressions in
        // `crates/nzbfast/tests/daemon.rs`; this is the arm that stops
        // one unreachable provider starving a whole queue, and it is
        // the one that had nothing. Its incident is 11-12 Aug 2026, two
        // soak jobs holding the queue for 25 minutes.
        //
        // **The post is HEALTHY and that is the whole point.** Every
        // other shape in this module breaks the head; this one breaks
        // the PROVIDER and leaves the head alone, which is what makes
        // the outage arm the only one that can speak:
        //
        // * not a byte arrives, so the `single-server-bound` arm's
        //   `total == 0` bail takes it before it looks at anything;
        // * nothing is REFUSED - a server granting no connection
        //   answers nothing at all - so `articles_missing` stays 0 on
        //   every server, `gone_evidence` finds `probed == 0` and both
        //   post-is-gone arms stand down by construction rather than by
        //   a compressed threshold;
        // * the pool cannot dispatch a single article, so the job's
        //   work queue never runs dry and the runner never hands over
        //   to its successor - which is what keeps the head the ACTIVE
        //   job the watchdog is watching.
        //
        // That last one is not a detail. A head that hands over stops
        // being `d.active_dl` (`tasks/worker.rs`), and no
        // mid-flight demotion arm watches a job that has handed over,
        // correctly - its successor is already downloading, so it is no
        // longer what the queue is waiting on.
        //
        // **The outage is held by the TEST, not by a clock.** See
        // `Chaos::outage`: `refuse_connect_ms` runs from the mock's own
        // start, and this rig starts the mock, spawns a daemon, waits
        // for it to bind, uploads four jobs and only then resumes, so a
        // fixed window would have to be guessed long enough to outlive
        // all of that on the slowest box it ever runs on. The research
        // file's own provenance note measures every figure in its table
        // shifting by about 2x under a full nextest sweep, which is
        // exactly the margin such a guess would be betting. `qprog_row`
        // releases this one on the first `[defer]` line instead.
        //
        // `NZBFAST_SERVER_DOWN_SECS` is compressed for the same reason
        // the watchdog thresholds are, and it is the only threshold
        // this row moves: shipped is 60 s and the arm wants
        // `o.secs >= max(span, that)`, so at 60 s no row in this module
        // could reach the arm at all. The wall a real user pays is that
        // 60 s plus what this row reports.
        "O1-provider-outage" => {
            let mut fx = Fixture::new(&format!("qprog-o1-{}{}", arm.tag(), wd.tag()));
            fx.add_file("stranded.bin", &peer_payload(99), PEER_ART);
            let mut b = Broken::new(
                fx,
                Chaos {
                    outage: true,
                    ..Default::default()
                },
            );
            b.env = vec![("NZBFAST_SERVER_DOWN_SECS", "2")];
            b.fleetwide = Some(
                "the provider is gone, so the peers cannot run either \
                 until it is back - what the row measures is that the \
                 head does not keep the runner through the outage and \
                 is behind them when it ends",
            );
            b
        }
        // ---- The UNPROBED-SERVER row. ----
        //
        // The fleet the WINDOWED post-is-gone arm has to itself, and
        // the only shape in this module built out of a SETTING rather
        // than a message-id or a socket.
        //
        // Round A's finding F12 measured that arm the way F7 measured
        // the outage one: grepping `came back missing and not a byte
        // arrived` over `crates/` found it at its own definition in
        // `tasks/stall.rs`, in `demotion_arm` below, and in a
        // unit test asserting the three sentences do not collide -
        // nowhere asserting it FIRES. Mutating it off outright
        // (`if false && total == 0 && ...`) left
        // `gone_post_defers_so_the_queue_moves_on` passing unchanged
        // and every row in this module byte-identical, arm column
        // included. It could have been deleted and nothing in the tree
        // would have noticed.
        //
        // Neither step that got it there was wrong, which is why the
        // answer is a new shape rather than a repair. TODO 306 gave the
        // post-is-gone verdict two faster twins, and at every threshold
        // set this rig runs one of them reaches it first: the EARLY arm
        // takes it off the run before the window bookkeeping, and the
        // PARTIAL arm off a flatline inside a window that need not be
        // full. So on any fleet where both twins are ELIGIBLE, the
        // windowed arm is unreachable by construction and no row can
        // pin it.
        //
        // **What the twins ask that this one does not** is
        // `fleet_answered`: every server must have itself answered a
        // refusal, or be granting no connection at all. A server that
        // is up and has simply never been asked stands both of them
        // down forever - it might be the one holding the post - while
        // the windowed arm has no such condition and speaks off the
        // window alone.
        //
        // `retention_days` is how a real install produces that server,
        // and it produces it deliberately rather than by accident: a
        // provider configured with a retention window shorter than the
        // post's age is seeded into every article's `tried_430` at
        // queue-build time (`nzbkit::pool::retention_mask`), so it is
        // never dispatched to, never refuses anything, and never goes
        // down. A shallow primary in front of a deep secondary is an
        // ordinary fleet, and this is what it costs when the deep one
        // has been taken down.
        //
        // The second server holds the head's articles and would SERVE
        // them if it were ever asked, which is deliberate: if retention
        // exclusion ever stopped working, this row fails by the head
        // COMPLETING rather than by quietly re-routing onto a twin.
        //
        // COMPRESSED thresholds, and that is a decision rather than a
        // saving. Its two siblings run at the shipped set because their
        // claim IS a clock - TODO 306 made a demotion reachable inside
        // 69 s, which is only meaningful at 45 s of warmup and a 30 s
        // window. This arm makes no such claim: it is the slow one, by
        // design, and what has to be pinned is that it SPEAKS for the
        // fleet its twins cannot. The gates are the same gates at
        // smaller numbers.
        //
        // 900 articles at a charged refusal is the article count, and
        // it is a MEASURED floor rather than a round number. The
        // windowed arm cannot speak before `warmup` (3 s here) or
        // before a window 80% full (4 s), so a head that grinds itself
        // out in five seconds reports `never` and says nothing about
        // the arm at all. Measured 27 Aug 2026 with the arm mutated off
        // - which is how long the head holds the runner when nothing
        // demotes it - 600 articles grind for 8.7 s and 900 for 12.7 s,
        // against a verdict that lands by 5.4 s. The margin is the
        // point of the larger figure, and it only ever grows: the grind
        // is a wall-clock quantity (the mock SLEEPS `missing_delay_ms`
        // per refusal, so a faster box does not shorten it) while a
        // loaded one stretches it, and the two gates it has to outlive
        // are fixed seconds. That is the direction the research file's
        // provenance note asks for, every figure in its table moving by
        // about 2x under a full nextest sweep.
        "U1-unprobed-server" => {
            let mut fx = Fixture::new(&format!("qprog-u1-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(100);
            let mut big = Vec::with_capacity(3_600_000);
            while big.len() < 3_600_000 {
                big.extend_from_slice(&data);
            }
            big.truncate(3_600_000);
            fx.add_file("unprobed.bin", &big, 4_000);
            // Older than the shallow server's window below, and the
            // same 21 days as `S5`/`S6` so the three at-scale takedown
            // rows stay readable against each other.
            fx.date = unix_now() - 21 * 86_400;
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Everything)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            let mut b = Broken::new(fx, chaos);
            b.peer_servers = 1;
            b.server_extra = vec![
                // The deep server: unlimited retention, refuses every
                // article of the head's post.
                String::new(),
                // The shallow one: healthy, dialled, and ruled out of
                // this post by its own retention window. It is what
                // `fleet_answered` returns `None` on.
                "\"retention_days\":7".to_string(),
            ];
            b.fleetwide = Some(
                "the second server's retention window is a property of \
                 the SERVER, so a peer post older than 7 days would be \
                 ruled out of it too - the peers here are undated, so \
                 they are not",
            );
            b
        }
        // ---- The W1 row: a REFUSING server and an UNREACHABLE one. ----
        //
        // TODO 308. The one shape in this module whose fault is neither
        // a message-id nor a socket but the PAIR of them, and the only
        // one that has ever held the whole queue rather than the head.
        //
        // Round A found it on the way to `O1-provider-outage` and filed
        // it rather than fixing it: two configured providers, one up
        // and refusing every article of the head's post, one accepting
        // TCP and closing before the greeting. Peer0 fetched every byte
        // of its payload and its JOB never finished, peers 1 and 2
        // never started, and the head sat in `Downloading` for the
        // whole 150 s budget.
        //
        // **Why it is not `O1` with an extra server.** O1's provider
        // grants no connection AT ALL, so the pool cannot dispatch a
        // single article, the head's work queue never runs dry, the
        // runner never hands over, and the head stays `d.active_dl` -
        // which is exactly what leaves it demotable. Here the live
        // server DOES answer: it refuses everything, the dispatchable
        // work runs out, and the runner hands over
        // (`tasks/worker.rs`) while the head still holds articles
        // that only the unreachable server could ever have served. A
        // job that has handed over is nobody's to demote by design, so
        // no arm in `tasks/stall.rs` can speak for it - and the
        // runner then parks on that head's network drain before it will
        // settle ANY successor, which is why peer0 downloaded its bytes
        // and still never reached a terminal row.
        //
        // **The dead server carries no articles**, which is what makes
        // it different in kind from every other fleet in this module: a
        // peer server ANSWERS, so a fleet of them always reaches a
        // verdict. This one can neither serve nor refuse, so the only
        // thing that can ever release the head's last articles is the
        // pool's own outage ladder giving up on it.
        //
        // `NZBFAST_SERVER_OUTAGE_MINS` is that ladder's control and is
        // the one threshold this row moves. Shipped is 15 minutes of
        // accumulated no-session time per server per run, above a
        // consecutive bounce horizon of about ten
        // (`nzbkit::pool::OUTAGE_BUDGET`, `CAP_PROBE_BOUNCES`), so at
        // shipped figures no row in this module could reach the far end
        // of it: the wall a real user pays is what this row reports
        // plus the difference between that horizon and this one.
        "W1-refused-plus-dead" => {
            let mut fx = Fixture::new(&format!("qprog-w1-{}{}", arm.tag(), wd.tag()));
            let data = peer_payload(101);
            fx.add_file("wedged.bin", &data, PEER_ART);
            let p = plan(&fx);
            let mut chaos = Chaos::default();
            p.role(Role::Everything)
                .expect_nonempty(&p)
                .missing(&mut chaos);
            let mut b = Broken::new(fx, chaos);
            b.down_servers = 1;
            b.env = vec![
                // The outage arm's own gate, compressed exactly as
                // `O1-provider-outage` compresses it and for the same
                // reason: shipped is 60 s and no row in this module
                // lives that long.
                ("NZBFAST_SERVER_DOWN_SECS", "2"),
                // The pool's give-up ladder, and the one threshold this
                // row moves that O1 does not. It is what bounds the row
                // when NOTHING demotes: the head's last articles are
                // parked on a server only that ladder can retire, so at
                // the shipped 15 minutes a row with the arm off does not
                // fail, it TIMES OUT - and "stranded" is a much worse
                // failure message than "set aside never". Compressed to
                // one minute, the un-demoted row terminates at ~61 s,
                // well inside [`ROW_BUDGET`] and four times the ~5 s the
                // arm takes, so the two verdicts cannot be confused.
                ("NZBFAST_SERVER_OUTAGE_MINS", "1"),
            ];
            b.fleetwide = Some(
                "the unreachable server is a property of the FLEET, so                  the peers are behind it too - what the row measures is                  that they are behind the HEAD as well, which is the                  defect",
            );
            b
        }
        other => panic!("unknown shape {other:?}"),
    })
}

/// Which of the mid-flight demotion arms in `tasks/stall.rs`
/// wrote this `[defer]` line.
///
/// FIVE since TODO 306: post-is-gone has an EARLY twin that reads the
/// run rather than a rolling window, and a PARTIAL twin that reads a
/// flatline inside it, and the three are kept apart here because which
/// one spoke is the whole of what that section changed. The two twins
/// are tested first: all three sentences say "came back missing", which
/// is deliberate (the 14 Aug regression in
/// `crates/nzbfast/tests/daemon.rs` asserts on that phrase to
/// distinguish a refusal verdict from a dead-server one), so only the
/// clause around it separates them.
///
/// Classified by the REASON the arm composes, because the log line
/// carries no arm name and the three carry different remedies: a
/// server that grants no connection is an outage, a post every server
/// refuses is a takedown or propagation, and one host carrying 90% of
/// the bytes is a routing problem. Read by the phrase each arm builds
/// its sentence from rather than by a whole line, so a reword that
/// keeps the meaning keeps the classification; an arm this cannot place
/// is reported as unclassified rather than silently folded into one of
/// the three.
fn demotion_arm(line: &str) -> &'static str {
    if line.contains("has had no usable connection for") {
        "server-outage"
    } else if line.contains("answered so far came back missing") {
        "post-is-gone-early"
    } else if line.contains("carries what is left of this post") {
        "post-is-gone-partial"
    } else if line.contains("came back missing and not a byte arrived") {
        "post-is-gone"
    } else if line.contains("the other servers had nothing for this job") {
        "single-server-bound"
    } else {
        "UNCLASSIFIED"
    }
}

/// Terminal statuses in the SAB-compatible history payload.
fn qprog_terminal(s: &str) -> bool {
    s == "Completed" || s == "Failed"
}

/// The history row for a job whose name contains `frag`, if it has
/// reached a terminal state.
///
/// Matched on the NAME, and the nzo ids are deliberately not
/// substring-searched over the payload at all: they are minted off a
/// plain counter, so `...nzbfast1` is a strict prefix of
/// `...nzbfast10`, and the queue payload's whyslow block names the last
/// job's own id - the 24 Aug 2026 sweep behind
/// `tools/payload-id-gate.py`. Every name here is unique by
/// construction.
fn qprog_settled(payload: &str, frag: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    let slots = v["history"]["slots"].as_array()?;
    slots.iter().find_map(|s| {
        let name = s["name"].as_str().unwrap_or_default();
        let status = s["status"].as_str().unwrap_or_default();
        (name.contains(frag) && qprog_terminal(status)).then(|| status.to_string())
    })
}

/// Run one row and report it. `shape` of `"control"` runs the same K
/// peers behind a HEALTHY head, which is the row every other row is
/// read against.
async fn qprog_row(shape: &str, arm: Arm, wd: Watchdog) -> Option<Row> {
    let broken = if shape == "control" {
        None
    } else {
        Some(broken_for(shape, arm, wd)?)
    };
    let label = format!("{shape}{}/{}", wd.tag(), arm.tag());

    // Every article the mock will ever serve: the broken post's and the
    // peers'. One server, one union - which is what makes "the fault
    // reaches one job" a property of the ID SETS rather than of the
    // topology.
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let mut peers = Vec::new();
    for k in 0..HEALTHY {
        let fx = healthy_fixture(
            &format!("qprog-peer{k}-{shape}-{}{}", arm.tag(), wd.tag()),
            k,
        );
        articles.extend(fx.articles.clone());
        peers.push(fx);
    }
    // The control's head is a fourth peer, so its queue is the same
    // LENGTH as every other row's and the three posts behind the head
    // are the same three posts.
    let control_head;
    let head: &Fixture = match &broken {
        Some(b) => {
            articles.extend(b.fx.articles.clone());
            &b.fx
        }
        None => {
            control_head =
                healthy_fixture(&format!("qprog-head-{shape}-{}{}", arm.tag(), wd.tag()), 90);
            articles.extend(control_head.articles.clone());
            &control_head
        }
    };
    let head_xml = std::fs::read_to_string(head.write_nzb()).unwrap();
    let peer_xml: Vec<String> = peers
        .iter()
        .map(|fx| std::fs::read_to_string(fx.write_nzb()).unwrap())
        .collect();

    let mut chaos = broken.as_ref().map(|b| b.chaos.clone()).unwrap_or_default();
    arm.apply(&mut chaos);
    let mut servers = vec![MockServer::start(articles.clone(), chaos).await];
    for _ in 0..broken.as_ref().map(|b| b.peer_servers).unwrap_or(0) {
        servers.push(MockServer::start(articles.clone(), Chaos::default()).await);
    }
    // The unreachable tail of the fleet. EMPTY article map on purpose:
    // this server never answers anything, so what it holds is
    // unobservable, and handing it the union would make a later reader
    // think the fault was scoped by id like every other shape's.
    for _ in 0..broken.as_ref().map(|b| b.down_servers).unwrap_or(0) {
        servers.push(
            MockServer::start(
                HashMap::new(),
                Chaos {
                    refuse_connect_ms: 86_400_000,
                    ..Default::default()
                },
            )
            .await,
        );
    }
    // `Broken::server_extra` by fleet index, so a shape whose fault is
    // a SETTING can express it. Read by position rather than zipped, so
    // a shape naming an extra for server 1 alone still says nothing
    // about server 0.
    let extra = broken
        .as_ref()
        .map(|b| b.server_extra.clone())
        .unwrap_or_default();
    let addrs: Vec<String> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let more = match extra.get(i) {
                Some(e) if !e.is_empty() => format!(",{e}"),
                _ => String::new(),
            };
            format!(
                "{{\"host\":\"{}\",\"port\":{},\"tls\":false{more}}}",
                s.addr.ip(),
                s.addr.port()
            )
        })
        .collect();

    // The daemon's own tree, never a fixture's: a fixture directory
    // holds the posted files `par2 create` was run over, and handing it
    // to the daemon as an output root would let a job "find" its own
    // payload.
    let base = std::env::temp_dir().join(format!(
        "nzbfast-qprog-{shape}-{}{}-{}",
        arm.tag(),
        wd.tag(),
        std::process::id()
    ));
    let _scratch = super::scratch::ScratchDir::attach(&base);
    std::fs::create_dir_all(&base).unwrap();
    let cfg = base.join("config.json");
    std::fs::write(&cfg, format!("{{\"servers\":[{}]}}", addrs.join(","))).unwrap();

    let env: Vec<(&str, &str)> = wd
        .env()
        .iter()
        .copied()
        .chain(broken.as_ref().map(|b| b.env.clone()).unwrap_or_default())
        .collect();
    let d = serve(&base, |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1").env("NZBFAST_NO_ENRICH", "1");
        for (k, v) in &env {
            c.env(k, v);
        }
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
            .arg("4");
        c
    })
    .await;
    let port = d.port;

    // Paused first, so the ORDER is ours rather than a race between
    // four uploads and a runner that starts on the first one.
    let head_name = "QprogHead.S01E01.1080p.WEB.h264-QP.nzb";
    let peer_names: Vec<String> = (0..HEALTHY)
        .map(|k| format!("QprogPeer{k}.S0{}E01.1080p.WEB.h264-QP.nzb", k + 2))
        .collect();
    let (hx, px, pn) = (head_xml.clone(), peer_xml.clone(), peer_names.clone());
    let queue_json = tokio::task::spawn_blocking(move || {
        qprog_http(port, "/api?mode=pause&output=json", None);
        qprog_upload(port, &hx, head_name);
        for (k, xml) in px.iter().enumerate() {
            qprog_upload(port, xml, &pn[k]);
        }
        qprog_http(port, "/api?mode=queue&output=json", None)
    })
    .await
    .unwrap();
    // The premise of every row: the broken post really is the head.
    let q: serde_json::Value = serde_json::from_str(&queue_json).unwrap();
    let order: Vec<String> = q["queue"]["slots"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|s| s["filename"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        order.len(),
        HEALTHY + 1,
        "{shape}: all four jobs must be queued before the run starts, got {order:?}"
    );
    assert!(
        order[0].contains("QprogHead"),
        "{shape}: the broken post must be at the HEAD, got {order:?}"
    );

    // The test's hold on the provider, for the shapes whose fault IS
    // the provider. Released on the first `[defer]` line rather than on
    // a wall clock - `O1-provider-outage`'s own comment carries why -
    // so the row measures where the head ENDS UP relative to the peers
    // and never how fast this box booted a daemon.
    let outage_ctl = broken
        .as_ref()
        .filter(|b| b.chaos.outage)
        .map(|_| servers[0].outage_control());
    let log_path = d.log_path();

    let t0 = Instant::now();
    let names = peer_names.clone();
    let observed = tokio::task::spawn_blocking(move || {
        let mut outage_ctl = outage_ctl;
        qprog_http(port, "/api?mode=resume&output=json", None);
        let mut done: Vec<Option<Duration>> = vec![None; HEALTHY];
        let mut head_at: Option<(Duration, String)> = None;
        loop {
            let h = qprog_http(port, "/api?mode=history&output=json", None);
            for (k, n) in names.iter().enumerate() {
                if done[k].is_none() && qprog_settled(&h, n.trim_end_matches(".nzb")).is_some() {
                    done[k] = Some(t0.elapsed());
                }
            }
            if head_at.is_none()
                && let Some(st) = qprog_settled(&h, "QprogHead.S01E01")
            {
                head_at = Some((t0.elapsed(), st));
            }
            if done.iter().all(Option::is_some) && head_at.is_some() {
                break;
            }
            // The provider comes back the moment the watchdog has
            // spoken. Not before - the whole row is about what it says
            // - and not later than that, because the peers are behind
            // the same dead provider and would be set aside in their
            // turn, which would leave the ORDER this row asserts on to
            // whichever deferred job `pick_job` reaches first. The
            // watchdog's own thresholds give this poll about seven
            // seconds of slack to land in.
            if let Some(ctl) = &outage_ctl
                && std::fs::read_to_string(&log_path)
                    .unwrap_or_default()
                    .contains("[defer]")
            {
                ctl.end_outage();
                outage_ctl = None;
            }
            if t0.elapsed() > ROW_BUDGET {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let tail = qprog_http(port, "/api?mode=queue&output=json", None);
        (done, head_at, tail)
    })
    .await
    .unwrap();
    let (done, head_at, tail_queue) = observed;

    let mut r = Row {
        shape: label.clone(),
        fleetwide: broken.as_ref().and_then(|b| b.fleetwide),
        ..Default::default()
    };
    r.stranded = done.iter().filter(|d| d.is_none()).count();
    r.first_healthy = done.iter().flatten().min().copied();
    r.all_healthy = (r.stranded == 0)
        .then(|| done.iter().flatten().max().copied())
        .flatten();
    match head_at {
        Some((at, st)) => {
            r.broken_settled = Some(at);
            r.broken_end = st;
        }
        None => {
            let v: serde_json::Value =
                serde_json::from_str(&tail_queue).unwrap_or(serde_json::Value::Null);
            let still = v["queue"]["slots"]
                .as_array()
                .and_then(|a| {
                    a.iter()
                        .find(|s| {
                            s["filename"]
                                .as_str()
                                .unwrap_or_default()
                                .contains("QprogHead")
                        })
                        .map(|s| s["status"].as_str().unwrap_or_default().to_string())
                })
                .unwrap_or_else(|| "in neither store".to_string());
            r.broken_end = format!("unsettled ({still})");
        }
    }

    let log = d.log();
    // These rows assert on outcomes, so a row that surprises you leaves
    // nothing to read. This is how you read it without editing the
    // module to get it - the same escape hatch `e2e_faults::trace` is,
    // for the same reason.
    if std::env::var_os("NZBFAST_QPROG_TRACE").is_some() {
        eprintln!("--- {label} daemon log ---\n{log}\n--- end {label} ---");
    }
    r.defers = log
        .lines()
        .filter(|l| l.contains("[defer]"))
        .map(|l| demotion_arm(l).to_string())
        .collect();
    // How many times the head's own plan banner was printed. Two means
    // it was set aside and started again, which is what a demotion
    // costs and what the journal is supposed to make cheap.
    r.head_runs = log
        .lines()
        .filter(|l| l.contains("[get]") && l.contains("QprogHead") && l.contains(" eager of "))
        .count();
    // `get/plan.rs`'s own resume banner, which is the only place the
    // split between kept and refetched articles is stated. Read off the
    // COUNTS rather than off the presence of the line: "0 already on
    // disk" is a rerun that resumed nothing, and it reads exactly like
    // a healthy resume to a `contains` test.
    r.resumed = log
        .lines()
        .find(|l| l.contains("already on disk,"))
        .and_then(|l| l.split_once("[resume] ").map(|(_, t)| t.trim().to_string()))
        .unwrap_or_default();
    r.sidecar = log.contains("[sidecar]");
    let _log = d.stop();
    Some(r)
}

/// One row's line, printed as it is measured so a row that panics still
/// leaves the rows before it in the output.
fn print_qprog_row(r: &Row) {
    let ms = |d: Option<Duration>| match d {
        Some(d) => format!("{:.1}s", d.as_secs_f64()),
        None => "-".to_string(),
    };
    println!(
        "QPROG | {:<34} | first {:>6} | all {:>6} | head {:>6} = {:<10} | \
         set aside {:<20} | starts {} | resume {:<34} | sidecar {:<3} | stranded {}{}",
        r.shape,
        ms(r.first_healthy),
        ms(r.all_healthy),
        ms(r.broken_settled),
        r.broken_end,
        if r.defers.is_empty() {
            "never".to_string()
        } else {
            r.defers.join(",")
        },
        r.head_runs,
        if r.resumed.is_empty() {
            "-".to_string()
        } else {
            r.resumed.clone()
        },
        if r.sidecar { "yes" } else { "no" },
        r.stranded,
        match r.fleetwide {
            Some(w) => format!(" | FLEET-WIDE: {w}"),
            None => String::new(),
        },
    );
}

/// Measure `shapes`, asserting only what makes a row readable.
async fn qprog_measure(shapes: &[&str]) {
    qprog_measure_at(shapes, Watchdog::Compressed, &[Arm::Free, Arm::Charged]).await;
}

/// [`measure`] over an explicit threshold set and arm list.
async fn qprog_measure_at(shapes: &[&str], wd: Watchdog, arms: &[Arm]) {
    for s in shapes {
        for arm in arms.iter().copied() {
            match qprog_row(s, arm, wd).await {
                Some(r) => print_qprog_row(&r),
                None => println!(
                    "QPROG | {:<34} | skipped: par2 not installed",
                    format!("{s}{}/{}", wd.tag(), arm.tag())
                ),
            }
        }
    }
}

/// The control, and the shapes whose fault is the RECOVERY set.
#[tokio::test(flavor = "multi_thread")]
async fn queue_progress_control_and_recovery_faults() {
    // Asked in the TEST body, which is where `tools/par2-gate.py` wants
    // it and where it belongs: some shapes below build a real recovery
    // set and report as skipped without par2, which is a green run with
    // silently reduced coverage.
    if !have_par2() {
        println!("QPROG | par2 not installed - the recovery-set shapes will report as skipped");
    }
    qprog_measure(&[
        "control",
        "1-dead-recovery",
        "2-partial-volume",
        "13-bootstrap-and-refusal",
        "14-refused-escalation",
    ])
    .await;
}

/// The shapes whose fault is the PAYLOAD.
#[tokio::test(flavor = "multi_thread")]
async fn queue_progress_payload_faults() {
    // Asked in the TEST body, which is where `tools/par2-gate.py` wants
    // it and where it belongs: some shapes below build a real recovery
    // set and report as skipped without par2, which is a green run with
    // silently reduced coverage.
    if !have_par2() {
        println!("QPROG | par2 not installed - the recovery-set shapes will report as skipped");
    }
    qprog_measure(&[
        "3-dead-payload",
        "4-past-the-boundary",
        "5-fresh-430s",
        "6-replaced-post",
        "12-split-brain",
    ])
    .await;
}

/// The shapes that repair, and the two whose fault is the SERVER.
#[tokio::test(flavor = "multi_thread")]
async fn queue_progress_repairing_and_fleetwide_faults() {
    // Asked in the TEST body, which is where `tools/par2-gate.py` wants
    // it and where it belongs: some shapes below build a real recovery
    // set and report as skipped without par2, which is a green run with
    // silently reduced coverage.
    if !have_par2() {
        println!("QPROG | par2 not installed - the recovery-set shapes will report as skipped");
    }
    qprog_measure(&[
        "8-vol-dash-naming",
        "9-junk-named-par2",
        "10-second-backbone",
        "7-stall-and-430s",
        "11-cold-latency",
    ])
    .await;
}

/// The at-scale rows at the SHIPPED watchdog thresholds - what a real
/// install does with the same posts.
#[tokio::test(flavor = "multi_thread")]
async fn queue_progress_at_shipped_thresholds() {
    // par2-gate: both rows here are wholly-refused posts with no PAR2
    // set at all - `S5-dead-post-at-scale` and `S6-dead-tail-at-scale`
    // are the only two shapes in this module that never call `par2
    // create`. The gate resolves helper names tree-wide, so it sees
    // `qprog_measure_at` reaching par2 through the shapes it does NOT
    // run here; a probe in this body would be asking a question this
    // test's answer cannot depend on.
    qprog_measure_at(
        &["S5-dead-post-at-scale", "S6-dead-tail-at-scale"],
        Watchdog::Shipped,
        &[Arm::Charged],
    )
    .await;
}

/// TODO 306's regression, and the only test in the tree that pins a
/// mid-flight demotion at the thresholds the product actually SHIPS.
///
/// Round A measured this exact row holding three healthy jobs for its
/// entire 16.7 s run with `set aside never`, against a 1.0 s control,
/// because `tasks/stall.rs` could not reach any demotion arm
/// inside ~69 s (45 s of warmup, then a rolling window at least 80%
/// full). The early post-is-gone arm reads the RUN instead - not a byte
/// has ever arrived, every server has itself answered a refusal, and
/// the refusal floor is cleared - so it is bounded by its own
/// arm-then-fire confirmation rather than by that clock.
///
/// **What it asserts and what it deliberately does not.** The pins are
/// the early arm SPOKE, the head really did go round again, and every
/// peer drained - all three of which are false on the tree this fixes.
/// There is no wall-clock assertion anywhere in it: the research file's
/// own provenance note says every figure in that table shifts with load
/// (control 0.8 s quiet, 1.5 s under a full nextest sweep) and that the
/// RATIOS are what it is for. So the ordering claim is the one that
/// carries the meaning - a healthy peer finished BEFORE the broken head
/// reached its own terminal row, which is what "the queue moved" means
/// and which no amount of load inverts.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_head_is_set_aside_at_shipped_thresholds() {
    // par2-gate: `S5-dead-post-at-scale` is a wholly-refused post with
    // no PAR2 set at all - one of only two shapes in this module that
    // never call `par2 create`. The gate resolves helper names
    // tree-wide, so it sees `qprog_row` reaching par2 through the
    // shapes this test does NOT build; a probe in this body would be
    // asking a question this test's answer cannot depend on.
    let r = qprog_row("S5-dead-post-at-scale", Arm::Charged, Watchdog::Shipped)
        .await
        .expect("S5 needs no par2 binary, so every box can run this row");
    print_qprog_row(&r);
    assert!(
        r.defers.iter().any(|a| a == "post-is-gone-early"),
        "the early post-is-gone arm must set a wholly-dead head aside at \
         SHIPPED thresholds - a demotion that cannot fire inside 69 s is \
         TODO 306's defect, whatever the compressed rows say. defers={:?} \
         head={} first={:?}",
        r.defers,
        r.broken_end,
        r.first_healthy
    );
    assert!(
        r.head_runs >= 2,
        "set aside means it went to the BACK and was picked up again, \
         which is the second plan banner: head_runs={} defers={:?}",
        r.head_runs,
        r.defers
    );
    assert_eq!(
        r.stranded, 0,
        "every healthy peer must reach a terminal row: {} stranded, end={}",
        r.stranded, r.broken_end
    );
    let first = r.first_healthy.expect("a peer completed");
    let head = r.broken_settled.expect("the head reached a terminal row");
    assert!(
        first < head,
        "a healthy job behind the dead head must finish BEFORE it, or the \
         queue never moved: first={first:?} head={head:?} defers={:?}",
        r.defers
    );
}

/// TODO 306's SECOND regression: the partial takedown, at the shipped
/// thresholds, and the only test anywhere that pins the flatline arm.
///
/// Its sibling above covers the head that lands NOTHING, which the
/// early arm can judge off run-cumulative evidence with no clock in it
/// at all. This is the shape that arm correctly stands down on: the
/// first third of the post arrives, so "not a byte since this job
/// started" is false by construction and only a FLATLINE can speak.
/// Round A measured this row holding the queue for its whole run at
/// these thresholds, `set aside never`, because the windowed arm needs
/// 45 s of warmup and a window 80% full and the job is over long
/// before.
///
/// **What it asserts and what it deliberately does not**, which is its
/// sibling's list with one addition. The pins are the PARTIAL arm
/// spoke - not merely that something demoted the job, because the
/// distinction between the two twins is the whole of what this section
/// added - the head went round again, every peer drained, and a peer
/// finished before the head reached its own terminal row. There is no
/// wall-clock assertion: the research file's provenance note says every
/// figure in that table shifts with load and the RATIOS are what it is
/// for.
///
/// The RESUME line is pinned too, and it is the one thing this row can
/// say that no other test in the tree can. The mid-flight demotion's
/// whole claim is that it is cheap because the journal keeps what
/// landed; S5 lands zero bytes, so a rerun that refetched everything
/// and one that resumed perfectly look identical there. Here the
/// arriving third has to come back off disk.
#[tokio::test(flavor = "multi_thread")]
async fn a_partial_head_is_set_aside_at_shipped_thresholds() {
    // par2-gate: `S6-dead-tail-at-scale` is a partly-refused post with
    // no PAR2 set at all - one of only two shapes in this module that
    // never call `par2 create`. The gate resolves helper names
    // tree-wide, so it sees `qprog_row` reaching par2 through the
    // shapes this test does NOT build; a probe in this body would be
    // asking a question this test's answer cannot depend on.
    let r = qprog_row("S6-dead-tail-at-scale", Arm::Charged, Watchdog::Shipped)
        .await
        .expect("S6 needs no par2 binary, so every box can run this row");
    print_qprog_row(&r);
    assert!(
        r.defers.iter().any(|a| a == "post-is-gone-partial"),
        "the PARTIAL post-is-gone arm must set a half-refused head aside \
         at SHIPPED thresholds - the early arm cannot, because bytes \
         arrived, and the windowed one cannot inside 69 s. defers={:?} \
         head={} first={:?}",
        r.defers,
        r.broken_end,
        r.first_healthy
    );
    assert!(
        r.head_runs >= 2,
        "set aside means it went to the BACK and was picked up again, \
         which is the second plan banner: head_runs={} defers={:?}",
        r.head_runs,
        r.defers
    );
    assert_eq!(
        r.stranded, 0,
        "every healthy peer must reach a terminal row: {} stranded, end={}",
        r.stranded, r.broken_end
    );
    let first = r.first_healthy.expect("a peer completed");
    let head = r.broken_settled.expect("the head reached a terminal row");
    assert!(
        first < head,
        "a healthy job behind the half-dead head must finish BEFORE it, \
         or the queue never moved: first={first:?} head={head:?} defers={:?}",
        r.defers
    );
    assert!(
        r.resumed.contains("article(s) already on disk") && !r.resumed.starts_with('0'),
        "the rerun must resume from the journal rather than start over - \
         that is the whole claim a mid-flight demotion rests on: \
         resume={:?}",
        r.resumed
    );
}

/// The AT-SCALE rows - the only ones that run long enough for a
/// mid-flight demotion to be reachable at all.
///
/// Its own test because it is the slow one: the charged arm of
/// `S5-dead-post-at-scale` pays 1200 refusals at a transatlantic round
/// trip, asked up to twice each, which is the whole point of it.
#[tokio::test(flavor = "multi_thread")]
async fn queue_progress_at_scale() {
    // Asked in the TEST body, which is where `tools/par2-gate.py` wants
    // it and where it belongs: some shapes below build a real recovery
    // set and report as skipped without par2, which is a green run with
    // silently reduced coverage.
    if !have_par2() {
        println!("QPROG | par2 not installed - the recovery-set shapes will report as skipped");
    }
    qprog_measure(&[
        "S1-dead-recovery-at-scale",
        "S5-dead-post-at-scale",
        "S6-dead-tail-at-scale",
    ])
    .await;
}

/// TODO 306's second box: the `server-outage` demotion arm, driven end
/// to end for the first time.
///
/// Round A's finding F7 measured this as the one arm in
/// `tasks/stall.rs` with no coverage of any kind. Its reason text
/// appears nowhere in `crates/` but at its own definition, no test
/// anywhere drove a server that grants no connection while another job
/// waited, and nothing set `NZBFAST_SERVER_DOWN_SECS`, which is the
/// gate that decides whether it may speak at all. The other two
/// windowed arms have regressions in `crates/nzbfast/tests/daemon.rs`.
/// This is the arm whose job is to stop one unreachable provider
/// starving a whole queue - the 11-12 Aug 2026 soak, two jobs holding
/// the queue for 25 minutes - and it had nothing.
///
/// **It is a SINGLE-provider row, deliberately, and that is the answer
/// to F8.** That finding is a code reading: with one configured
/// provider and any byte flow at all, no arm is reachable. True, and
/// routinely read one step too far, as "a single-provider install has
/// no demotion at all". It does not follow and it is false. The gates
/// that shut on one provider are the ones that need somewhere ELSE to
/// route to - `single-server-bound` bails on `deltas.len() < 2` because
/// with one server there is nothing to route around, which is the
/// code's own comment. The two arms that speak for a job getting
/// NOTHING do not care how many servers there are: this row fires the
/// outage arm on a fleet of one, and
/// [`a_dead_head_is_set_aside_at_shipped_thresholds`] already fires the
/// early post-is-gone arm on a fleet of one at SHIPPED thresholds
/// (`S5-dead-post-at-scale` sets no `peer_servers`, so its whole fleet
/// is the one mock it faults). So TODO 306's fix reaches the
/// single-provider install, which is most of them, and what F8 really
/// says is narrower: the arm a one-provider user never gets is the one
/// about routing, and the mitigation they do get is for the job that is
/// taking nothing at all.
///
/// **What it asserts and what it deliberately does not.** No wall-clock
/// figure appears anywhere in it, for the reason the research file's
/// own provenance note gives: every second in that table shifts by
/// about 2x under a full nextest sweep, and the RATIOS are what it is
/// for. The pins are that the outage arm SPOKE, that the head went
/// round again, that every peer drained, and that a peer finished
/// before the head did - an ordering claim no amount of load inverts,
/// and the one that means "the queue moved". All four are false if the
/// arm stops firing: without it the head keeps the runner for the whole
/// outage and is first through the moment it lifts.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_provider_sets_the_head_aside_and_the_queue_drains() {
    // par2-gate: `O1-provider-outage` posts one file and builds no
    // recovery set at all. `qprog_row` reaches `par2 create` only
    // through the shapes this test does not build, and the gate
    // resolves helper names tree-wide.
    let r = qprog_row("O1-provider-outage", Arm::Free, Watchdog::Compressed)
        .await
        .expect("O1 builds no recovery set, so every box can run this row");
    print_qprog_row(&r);
    assert!(
        r.defers.iter().any(|a| a == "server-outage"),
        "a head that can reach no provider at all must be set aside by \
         the server-outage arm - it is the only arm that can speak for \
         this shape, since nothing is refused and no byte arrives. \
         defers={:?} head={} first={:?}",
        r.defers,
        r.broken_end,
        r.first_healthy
    );
    assert!(
        r.head_runs >= 2,
        "set aside means it went to the BACK and was picked up again, \
         which is the second plan banner: head_runs={} defers={:?}",
        r.head_runs,
        r.defers
    );
    assert_eq!(
        r.stranded, 0,
        "every healthy peer must drain once the provider is back: {} \
         stranded, head={}",
        r.stranded, r.broken_end
    );
    let first = r.first_healthy.expect("a peer completed");
    let head = r.broken_settled.expect("the head reached a terminal row");
    assert!(
        first < head,
        "the head was set aside FIRST, so a peer must finish before it \
         - a head that came back ahead of the queue it was moved behind \
         was never really set aside: first={first:?} head={head:?} \
         defers={:?}",
        r.defers
    );
}

/// TODO 306's residue, and the only test anywhere that pins the
/// WINDOWED post-is-gone arm.
///
/// Round A's finding F12 measured that arm exactly as F7 measured the
/// outage one above: its reason text appears in `crates/` only at its
/// own definition, in [`demotion_arm`], and in a unit test asserting
/// the three post-is-gone sentences do not collide. Mutating it off -
/// `if false && total == 0 && ...` - left
/// `gone_post_defers_so_the_queue_moves_on` passing in 5.6 s and every
/// row in this module byte-identical, arm column included. It could
/// have been deleted and nothing in the tree would have noticed.
///
/// **Why it had drifted out of reach, which is the part worth reading
/// before touching this row.** Neither step that got it there was
/// wrong. Its own regression asserts on `came back missing`, which all
/// three post-is-gone arms share deliberately (that is what tells a
/// refusal verdict from a dead-server one, the 14 Aug 2026 incident),
/// so it cannot say which arm spoke; and TODO 306 then gave the verdict
/// two faster twins, either of which reaches it first on any fleet
/// where both are ELIGIBLE. The EARLY arm is evaluated before the
/// window bookkeeping and takes the verdict off the run; the PARTIAL
/// arm reads a flatline inside a window that need not be full. The
/// windowed arm asks for a FULL window and a warmup on top of it, so it
/// is last by construction and unreachable wherever its twins can
/// speak.
///
/// **So the row is built out of the one condition the twins have and it
/// does not**: `fleet_answered`. Both twins require every server to
/// have itself answered a refusal, or to be granting no connection at
/// all; a server that is up and has simply never been asked stands both
/// of them down forever, because it might be the one holding the post.
/// `U1-unprobed-server` is that fleet, produced the way a real install
/// produces it - a shallow provider whose `retention_days` cannot cover
/// a 21-day-old post, in front of a deep one that refuses every article
/// of it.
///
/// **What it asserts, and the one assertion that is the deliverable.**
/// The pins are that the WINDOWED arm spoke, that neither twin did -
/// which is what makes this a test OF that arm rather than of the
/// verdict, and is the assertion the `if false &&` mutation has to
/// break - that the head went round again, that every peer drained, and
/// that a peer finished before the head reached its own terminal row.
/// No wall-clock figure appears anywhere in it, for the reason the
/// research file's provenance note gives: every second in that table
/// moves by about 2x under a full nextest sweep, and the ORDERING claim
/// is the one that means "the queue moved" and that no amount of load
/// inverts.
///
/// It runs at COMPRESSED thresholds where its two siblings run at the
/// shipped ones, and that is a decision. Their claim IS a clock - TODO
/// 306 made a demotion reachable inside 69 s - which is only meaningful
/// at 45 s of warmup and a 30 s window. This arm makes no such claim:
/// it is the slow one by design, and what needs pinning is that it
/// speaks at all for the fleet its twins cannot.
#[tokio::test(flavor = "multi_thread")]
async fn an_unprobed_server_leaves_the_windowed_arm_to_speak() {
    // par2-gate: `U1-unprobed-server` posts one file and builds no
    // recovery set at all. `qprog_row` reaches `par2 create` only
    // through the shapes this test does not build, and the gate
    // resolves helper names tree-wide.
    let r = qprog_row("U1-unprobed-server", Arm::Charged, Watchdog::Compressed)
        .await
        .expect("U1 builds no recovery set, so every box can run this row");
    print_qprog_row(&r);
    assert!(
        r.defers.iter().any(|a| a == "post-is-gone"),
        "the WINDOWED post-is-gone arm must set aside a head whose only \
         answering server refuses everything while a second is up and \
         unasked - it is the only arm that can speak for this fleet. \
         defers={:?} head={} first={:?}",
        r.defers,
        r.broken_end,
        r.first_healthy
    );
    assert!(
        !r.defers
            .iter()
            .any(|a| a == "post-is-gone-early" || a == "post-is-gone-partial"),
        "neither faster twin may speak here, or this row is testing the \
         VERDICT and not the arm: both ask `fleet_answered` for every \
         server to have refused something itself, and the shallow \
         server never gets asked at all. A twin in this list means the \
         retention exclusion stopped holding. defers={:?}",
        r.defers
    );
    assert!(
        r.head_runs >= 2,
        "set aside means it went to the BACK and was picked up again, \
         which is the second plan banner: head_runs={} defers={:?}",
        r.head_runs,
        r.defers
    );
    assert_eq!(
        r.stranded, 0,
        "every healthy peer must reach a terminal row: {} stranded, end={}",
        r.stranded, r.broken_end
    );
    let first = r.first_healthy.expect("a peer completed");
    let head = r.broken_settled.expect("the head reached a terminal row");
    assert!(
        first < head,
        "a healthy job behind the dead head must finish BEFORE it, or \
         the queue never moved: first={first:?} head={head:?} \
         defers={:?}",
        r.defers
    );
}

/// TODO 308: the outage arm, asked about the job it is JUDGING rather
/// than about whatever the hub happens to own.
///
/// The one row in this module that has ever held the whole queue rather
/// than the head, and the only regression here whose subject is a
/// DRAINING predecessor. Round A measured it and filed it: two
/// providers, one up and refusing every article of the head's post, one
/// accepting TCP and closing before the greeting. Peer0 fetched every
/// byte of its payload and its JOB never reached a terminal row, peers
/// 1 and 2 never started, and the head sat in `Downloading` for the
/// whole 150 s budget - zero of four jobs settled, three runs the same.
///
/// **Why no arm spoke, which is the part worth reading before touching
/// this.** Nothing here was missing. `watched` already prefers a
/// draining predecessor over the hub owner, and carries that job's own
/// gauges and stop handles precisely because "the hub's are the
/// successor's by now"; the outage arm then reached PAST them to
/// `server_outages(&d)`, which reads the hub. So for the one job the
/// queue was waiting on, the arm asked the SUCCESSOR's fleet whether
/// the predecessor's provider was down - and the successor was
/// downloading happily off the healthy server, so the answer was no,
/// forever. `serve/outage.rs::outages_in` is the same census over named
/// gauges and is what the arm asks now.
///
/// **And why the twins cannot cover it.** Both post-is-gone arms want
/// refusals to still be LANDING (`early_gone_defer` arms on one tick
/// and requires more misses on the next; `partial_gone_defer` reads a
/// flatline with bytes already in). This head's refusals all land in
/// the first fraction of a second and the fleet then goes silent
/// waiting on a socket, which is the outage arm's shape by
/// construction and is what its own comment says: "the pool is waiting
/// on a socket, the retry logic has nothing to retry".
///
/// **What it asserts, and the one assertion that is the deliverable.**
/// The pins are that the OUTAGE arm spoke, that the head went round
/// again, that every peer drained, and that a peer finished before the
/// head reached its own terminal row. No wall-clock figure appears in
/// any of them, for the reason the research file's provenance note
/// gives - every second in that table moves by about 2x under a full
/// nextest sweep - and the ORDERING claim is the one that means "the
/// queue moved" and that no amount of load inverts. All four are false
/// with the fix reverted: measured 27 Aug 2026, the reverted row
/// reports `set aside never`, `starts 1`, and a first peer settling at
/// the same instant as the head because nothing settles until the
/// pool's own ladder retires the dead provider.
#[tokio::test(flavor = "multi_thread")]
async fn a_draining_head_behind_a_dead_provider_is_set_aside_and_the_queue_drains() {
    // par2-gate: `W1-refused-plus-dead` posts one file and builds no
    // recovery set at all. `qprog_row` reaches `par2 create` only
    // through the shapes this test does not build, and the gate
    // resolves helper names tree-wide.
    let r = qprog_row("W1-refused-plus-dead", Arm::Free, Watchdog::Compressed)
        .await
        .expect("W1 builds no recovery set, so every box can run this row");
    print_qprog_row(&r);
    assert!(
        r.defers.iter().any(|a| a == "server-outage"),
        "a head that has HANDED OVER and still holds articles only an \
         unreachable server could serve must be set aside by the \
         server-outage arm - it is the only arm that can speak for this \
         shape, the refusals having all landed before the first tick. \
         An empty list means the arm is reading the hub's gauges again, \
         which after a hand-over are the successor's. defers={:?} \
         head={} first={:?}",
        r.defers,
        r.broken_end,
        r.first_healthy
    );
    assert!(
        r.head_runs >= 2,
        "set aside means it went to the BACK and was picked up again, \
         which is the second plan banner: head_runs={} defers={:?}",
        r.head_runs,
        r.defers
    );
    assert_eq!(
        r.stranded, 0,
        "every healthy peer must reach a terminal row: {} stranded, end={}",
        r.stranded, r.broken_end
    );
    let first = r.first_healthy.expect("a peer completed");
    let head = r.broken_settled.expect("the head reached a terminal row");
    assert!(
        first < head,
        "a healthy job behind the wedged head must finish BEFORE it, or \
         the queue never moved - peer0 downloading every byte of its \
         payload and still not settling is this defect's own \
         fingerprint: first={first:?} head={head:?} defers={:?}",
        r.defers
    );
}

#[cfg(test)]
mod qprog_dechunk_tests {
    use super::qprog_dechunk;

    /// A plain, non-chunked body must pass through unchanged - the
    /// dispatch is header-driven, and a body that merely looks like a
    /// chunk stream (starts with hex digits) must never be touched.
    #[test]
    fn plain_body_passes_through() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json";
        let body = "{\"a\":1}";
        assert_eq!(qprog_dechunk(head, body), body);
    }

    /// A chunked body, multiple chunks and the trailing zero-chunk, is
    /// reassembled into the JSON it carried.
    #[test]
    fn chunked_body_is_reassembled() {
        let head =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json";
        let json = "{\"history\":{\"slots\":[]}}";
        let (first, second) = json.split_at(6);
        let body = format!(
            "{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
            first.len(),
            second.len()
        );
        assert_eq!(qprog_dechunk(head, &body), json);
        assert!(serde_json::from_str::<serde_json::Value>(&qprog_dechunk(head, &body)).is_ok());
    }

    /// The header check is case-insensitive and tolerant of the other
    /// headers tiny_http sends alongside it.
    #[test]
    fn header_match_is_case_insensitive() {
        let head = "HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\nServer: tiny_http";
        let body = "5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(qprog_dechunk(head, body), "hello");
    }
}
