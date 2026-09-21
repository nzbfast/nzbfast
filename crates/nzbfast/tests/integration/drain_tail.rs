//! The drain tail priced at one socket
//! (`research/DRAIN-TAIL-ONE-SOCKET-REPRO-2026-09-20.md`): a two-server
//! loopback rig in which the predecessor's last articles exist on ONE
//! server only, so the hand-over's per-server floor of one live worker
//! decides what that tail costs.
//!
//! **The shape.** Two mock servers, both level 0, both six connections.
//! Server A carries every article of job 1 EXCEPT its last `TAIL_ARTS`;
//! server B carries all of them. So A runs out of work while B still
//! owes the tail - which is the moment `note_idle_after_dry` latches
//! the run's `HandoffSignal` and the runner starts job 2 on the
//! connections A is shedding. Job 2 then parks on B's lease too, and
//! `Shared::handoff_room` lets job 1 shed B's workers down to ONE. The
//! tail is B-only, so from that instant it is priced at one socket.
//!
//! **What is measured, and why it is a rate and not a clock.** Each
//! arm reads the `[pool]` summary line the run prints - `queue dry at
//! X` and `drained at Y` - and divides the tail's BYTES by `Y - X`.
//! Against a mock whose `Throttle::per_conn_bps` is a known per-socket
//! ceiling, that quotient IS the socket count: the tail moving at one
//! `per_conn_bps` means one socket carried it, at six it means six.
//! That is the same arithmetic the handoff used on the real incident
//! ("one socket last measured at 5.7 Mbit" against a tail that crept at
//! 0.71 MB/s), and it is why this rig needs no new instrumentation in
//! `crates/`.
//!
//! **It is `#[ignore]`d, and it must stay that way.** It is a
//! measurement rig, not a gate: its quantity is a wall-clock ratio, and
//! `research/TEST-TIMING-MARGIN-CENSUS-2026-09-17.md` is the standing
//! argument against letting one of those decide a push. Run it by name
//! on a box whose load you have looked at:
//!
//! ```sh
//! cargo nextest run -p nzbfast -E 'binary(integration) and test(drain_tail)' \
//!   --run-ignored all --no-capture
//! ```
//!
//! The fix lane's acceptance test is the same three arms with the
//! `overlap` arm's socket count required to be above one; see the
//! findings doc beside the handoff.

use crate::harness::serve;
use crate::scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};

/// One rig SHAPE. Four were measured on 20 Sep 2026 and they do not
/// agree, which is the finding: what the successor's start costs the
/// predecessor depends on WHEN the B-only work reaches B, not on how
/// much of it there is. The numbers each one produced, and what each
/// rules in or out, are in
/// `research/DRAIN-TAIL-ONE-SOCKET-REPRO-2026-09-20.md`.
#[derive(Debug, Clone, Copy)]
struct Shape {
    /// Article payload size: small enough to keep the corpus in RAM,
    /// large enough that the per-socket throttle rather than
    /// per-request overhead decides the tail's wall.
    art: usize,
    job1_arts: usize,
    /// Job 1's last N articles, which only server B carries.
    tail_arts: usize,
    job2_arts: usize,
    /// Every Nth article of job 2 is B-only too, so the successor has a
    /// standing demand on B's lease for the whole of job 1's tail. 0
    /// means none: job 2 then runs entirely on A, never parks on B, and
    /// job 1 keeps its B fleet - a real answer about a different rig.
    job2_fill_every: usize,
    /// Per-socket ceilings, bytes/sec.
    a_bps: u64,
    b_bps: u64,
    conns_a: u32,
    conns_b: u32,
    /// B's tier. 0 races A for every article; 1 makes B a FILL server
    /// that is only asked for what A has already missed, which is the
    /// incident's economics (giganews carried 59.8 GB of 66).
    b_level: u32,
    /// How long server A sits on a 430 for an article it does not
    /// carry. A real backbone charges 79 ms to 2,239 ms for one (the
    /// census at `chaos_serve::Cli::miss_delay_ms`), and what a LARGE
    /// value buys the rig is ORDER: it decides whether B learns about
    /// the tail before or after its own workers have gone idle.
    miss_delay_ms: u64,
}

/// The tail is B-only from the first seconds and B's workers are busy
/// with it throughout. This is the shape whose arithmetic is clean -
/// nothing staggers the arrivals, so the rate B sustains IS its socket
/// count - and it is the default.
const EARLY: Shape = Shape {
    art: 100_000,
    job1_arts: 100,
    tail_arts: 40,
    job2_arts: 600,
    job2_fill_every: 0,
    a_bps: 200_000,
    b_bps: 100_000,
    conns_a: 6,
    conns_b: 6,
    b_level: 0,
    miss_delay_ms: 0,
};

/// EARLY with A sitting on its refusals, so the tail reaches B part-way
/// through rather than at once.
const DELAYED: Shape = Shape {
    job1_arts: 200,
    miss_delay_ms: 3_000,
    ..EARLY
};

/// B demoted to a fill tier, so it carries the tail and nothing else -
/// the incident's server economics.
const FILL: Shape = Shape {
    art: 50_000,
    job1_arts: 200,
    job2_arts: 1_500,
    job2_fill_every: 5,
    a_bps: 2_000_000,
    b_bps: 50_000,
    b_level: 1,
    miss_delay_ms: 2_000,
    ..EARLY
};

/// FILL with A's refusals held long enough that job 1's B workers have
/// gone idle and shed BEFORE the tail reaches them - the one shape in
/// which the per-server floor of one worker can bite at all. It cannot
/// be read as a socket count: A releases the tail a few articles at a
/// time, so B is one-deep whatever the fleet size. See the findings.
const LATE: Shape = Shape {
    tail_arts: 8,
    b_bps: 10_000,
    conns_a: 24,
    miss_delay_ms: 25_000,
    ..FILL
};

fn shape() -> Shape {
    match std::env::var("DRAIN_TAIL_SHAPE")
        .unwrap_or_default()
        .as_str()
    {
        "" | "early" => EARLY,
        "delayed" => DELAYED,
        "fill" => FILL,
        "late" => LATE,
        other => panic!("unknown DRAIN_TAIL_SHAPE {other:?}: early|delayed|fill|late"),
    }
}

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
        .collect()
}

fn http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req, body) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, req: &str, body: Option<(&str, &[u8])>) -> std::io::Result<String> {
    let mut request = Vec::new();
    match body {
        None => write!(
            request,
            "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap(),
        Some((ctype, data)) => {
            write!(
                request,
                "POST {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
                data.len()
            )
            .unwrap();
            request.extend_from_slice(data);
        }
    }
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.write_all(&request)?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

fn add_nzb(port: u16, name: &str, xml: &str) -> String {
    let boundary = "----nzbfastboundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{name}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let ctype = format!("multipart/form-data; boundary={boundary}");
    let r = http(
        port,
        "/api?mode=addfile&apikey=sekrit&output=json",
        Some((&ctype, &body)),
    );
    assert!(r.contains("nzo_ids"), "{r}");
    r
}

fn nzb_xml(subject: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{subject}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

/// One arm's reading: the `[pool]` summary line's own two stamps, plus
/// the B-only stretch measured on the MOCK's arrival clock.
#[derive(Debug, Clone, Copy)]
struct Reading {
    sh: Shape,
    dry_s: f64,
    drained_s: f64,
    /// First and last arrival, at server B, of an article only B has -
    /// seconds from the first job-1 request anywhere.
    tail_first_s: f64,
    tail_last_s: f64,
    tail_served: usize,
    /// First arrival of a JOB 2 article anywhere: when the successor
    /// actually started pulling, on the same clock.
    succ_first_s: Option<f64>,
}

impl Reading {
    /// The wall of the B-only stretch. The last article is still being
    /// paid for when its request lands, so one article's service time
    /// at one socket is added: without it a one-article tail reads as
    /// instantaneous.
    fn tail_wall(&self) -> f64 {
        (self.tail_last_s - self.tail_first_s) + (self.sh.art as f64 / self.sh.b_bps as f64)
    }

    /// The whole measurement: the B-only bytes divided by their wall,
    /// expressed in units of ONE of server B's sockets. Against a mock
    /// whose per-socket ceiling is known this quotient IS the socket
    /// count - the same arithmetic the handoff used on the real
    /// incident, where a tail creeping at 0.71 MB/s against a 5.7 Mbit
    /// socket said "one".
    fn tail_sockets(&self) -> f64 {
        let bytes = (self.tail_served * self.sh.art) as f64;
        (bytes / self.tail_wall().max(0.001)) / self.sh.b_bps as f64
    }
}

/// Job 1's summary line is the FIRST `queue dry at` the daemon prints:
/// the runner starts one job at a time and job 1 is the first to reach
/// a tail. A run with no tail at all prints `no tail` instead and there
/// is nothing here to read - which is itself a finding, so say so
/// rather than returning a zero.
fn first_pool_line(log: &str) -> (f64, f64) {
    let line = log
        .lines()
        .find(|l| l.contains("queue dry at"))
        .unwrap_or_else(|| {
            panic!(
                "no `[pool]` line with a tail in the daemon log - job 1 never had one.\n\
                 pool lines seen: {:?}",
                log.lines()
                    .filter(|l| l.contains("run ") && l.contains("dups"))
                    .collect::<Vec<_>>()
            )
        });
    let grab = |after: &str| -> f64 {
        let rest = line
            .split(after)
            .nth(1)
            .unwrap_or_else(|| panic!("no {after:?} in {line}"));
        rest.trim_start()
            .trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.')
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect::<String>()
            .trim_end_matches('s')
            .parse()
            .unwrap_or_else(|e| panic!("unparseable {after:?} in {line}: {e}"))
    };
    (grab("queue dry at "), grab("drained at "))
}

/// `solo` queues job 1 alone (the control arm the handoff asks for),
/// `overlap` queues job 2 behind it, `serial` does the same with
/// `NZBFAST_QUEUE_HANDOFF=0`.
async fn arm(sh: Shape, name: &str, with_successor: bool, handoff: bool) -> (Reading, u64, u64) {
    // The ids only server B has - the quantity every number below is
    // about. Filled once the corpus is built.
    let mut tail_ids: Vec<String> = Vec::new();
    let dir = std::env::temp_dir().join(format!("nzbfast-draintail-{name}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let j1 = payload(sh.job1_arts * sh.art, 11);
    let j2 = payload(sh.job2_arts * sh.art, 29);
    let mut all = HashMap::new();
    let segs1 = make_file_articles("Drain.One.2026.mkv", &j1, sh.art, "d1", &mut all);
    let segs2 = make_file_articles("Drain.Two.2026.mkv", &j2, sh.art, "d2", &mut all);

    // Server A's map is everything MINUS job 1's last TAIL_ARTS. An id
    // that is not in a mock's map is answered `430 no such article`,
    // which is exactly "this backbone does not carry it".
    let mut a_map = all.clone();
    for (id, _, _) in segs1.iter().rev().take(sh.tail_arts) {
        let id = format!("<{id}>");
        a_map.remove(&id);
        tail_ids.push(id);
    }
    let mut j2_fill = 0usize;
    if sh.job2_fill_every > 0 {
        for (id, _, _) in segs2
            .iter()
            .skip(sh.job2_fill_every - 1)
            .step_by(sh.job2_fill_every)
        {
            a_map.remove(&format!("<{id}>"));
            j2_fill += 1;
        }
    }
    assert_eq!(
        a_map.len(),
        all.len() - sh.tail_arts - j2_fill,
        "tail removal from A"
    );

    let per_conn = |bps, miss_ms| Chaos {
        throttle: Throttle {
            per_conn_bps: bps,
            ..Default::default()
        },
        missing_delay_ms: miss_ms,
        ..Default::default()
    };
    // A SITS ON ITS REFUSALS, and that is the incident's shape rather
    // than a flourish. A backbone answers a 430 in 79 ms at best and
    // 2,239 ms at worst (the census quoted at `Cli::miss_delay_ms`), and
    // what that buys the rig is ORDER: A holds job 1's last articles
    // while B's workers run out of shared work, go idle after queue-dry,
    // and hand their connections to the successor. The tail then lands
    // on B - requeued, not newly discovered - with whatever B has left.
    // Without the delay A refuses at once, the tail is known from the
    // first seconds, and B works it alongside everything else: measured
    // that way the overlap arm is FASTER than solo, which is the rig
    // measuring its own shape and not the defect.
    let a = MockServer::start(a_map, per_conn(sh.a_bps, sh.miss_delay_ms)).await;
    let b = MockServer::start(all, per_conn(sh.b_bps, 0)).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[\
             {{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":{},\"pin_connections\":true,\"level\":0}},\
             {{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":{},\"pin_connections\":true,\"level\":{}}}]}}",
            a.addr.ip(),
            a.addr.port(),
            sh.conns_a,
            b.addr.ip(),
            b.addr.port(),
            sh.conns_b,
            sh.b_level,
        ),
    )
    .unwrap();

    let xml1 = nzb_xml("Drain.One.2026.mkv", &segs1);
    let xml2 = nzb_xml("Drain.Two.2026.mkv", &segs2);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_QUEUE_HANDOFF", if handoff { "1" } else { "0" })
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg(sh.conns_a.to_string());
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        add_nzb(port, "Drain.One.2026", &xml1);
        if with_successor {
            add_nzb(port, "Drain.Two.2026", &xml2);
        }
    })
    .await
    .unwrap();

    // Poll the daemon's own log for job 1's summary line.
    let (dry_s, drained_s) = {
        let deadline = std::time::Instant::now() + Duration::from_secs(600);
        loop {
            let log = d.log();
            if log.contains("queue dry at") {
                break first_pool_line(&log);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "arm {name}: job 1 never printed a `[pool]` tail line in 600 s"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let served = (
        a.served.load(std::sync::atomic::Ordering::Relaxed),
        b.served.load(std::sync::atomic::Ordering::Relaxed),
    );

    // The wire clock. `t0` is the first job-1 BODY asked of ANY server,
    // so every offset below is on the mocks' own arrival record and
    // none of it is stamped by this thread - the discipline
    // `queue_handoff.rs` sets out at length for `BodyLog`.
    let (a_log, b_log) = (a.body_log.lock().unwrap(), b.body_log.lock().unwrap());
    let base = [&a_log, &b_log]
        .iter()
        .filter_map(|l| {
            l.first_matching(|id| id.starts_with("<d1-"))
                .map(|(_, at)| at)
        })
        .min()
        .expect("no job-1 body was ever asked for");
    let tail_at: Vec<f64> = b_log
        .timeline(base)
        .into_iter()
        .filter(|(id, _)| tail_ids.contains(id))
        .map(|(_, d)| d.as_secs_f64())
        .collect();
    let succ_first_s = [&a_log, &b_log]
        .iter()
        .filter_map(|l| {
            l.first_matching(|id| id.starts_with("<d2-"))
                .map(|(_, at)| at)
        })
        .min()
        .map(|at| at.saturating_duration_since(base).as_secs_f64());
    let reading = Reading {
        sh,
        dry_s,
        drained_s,
        tail_first_s: tail_at.first().copied().unwrap_or_default(),
        tail_last_s: tail_at.last().copied().unwrap_or_default(),
        // DISTINCT ids, not requests: a hedge duplicate of a tail
        // article is a second request for bytes already paid for, and
        // counting it would inflate the rate this rig divides by.
        tail_served: {
            let mut seen: Vec<&String> = b_log.iter().filter(|id| tail_ids.contains(id)).collect();
            seen.sort();
            seen.dedup();
            seen.len()
        },
        succ_first_s,
    };
    (reading, served.0, served.1)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement rig: a wall-clock ratio, run it by name on a box you have looked at"]
async fn the_drain_tail_is_priced_at_one_socket_when_only_one_server_carries_it() {
    let sh = shape();
    println!("shape {sh:?}");
    let solo = arm(sh, "solo", false, true).await;
    let overlap = arm(sh, "overlap", true, true).await;
    let serial = arm(sh, "serial", true, false).await;

    for (name, (r, a_served, b_served)) in
        [("solo   ", solo), ("overlap", overlap), ("serial ", serial)]
    {
        println!(
            "{name}  dry {:6.2}s drained {:6.2}s | B-only stretch {:6.2}s -> {:6.2}s \
             ({} arts, wall {:6.2}s, SOCKETS {:5.2}) | successor first body {} \
             | A bodies {a_served} B bodies {b_served}",
            r.dry_s,
            r.drained_s,
            r.tail_first_s,
            r.tail_last_s,
            r.tail_served,
            r.tail_wall(),
            r.tail_sockets(),
            match r.succ_first_s {
                Some(s) => format!("{s:6.2}s"),
                None => "  never".to_string(),
            },
        );
    }
}
