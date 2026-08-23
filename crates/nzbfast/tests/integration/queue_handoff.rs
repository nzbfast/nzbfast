//! The cross-job connection hand-over (`nzbkit::pool::handoff`,
//! `serve/tasks/worker.rs`): job N+1's first article is requested while
//! job N is still draining, N's connections are handed over one at a
//! time inside the connection cap, and N's tail still reaches the
//! post-processing lane before N+1's.
//!
//! That last one is an ordering of the LANE'S INBOX and not of history.
//! The lane runs tails concurrently (`postproc_jobs`, default 2), so
//! which of two overlapping jobs is FILED first is whichever tail
//! finishes first - see the note at `finishing_seq` for the 23 Aug 2026
//! CI failure that came of asserting otherwise.
//!
//! The witness is the mock server's own request log. Job A's last
//! article answers after five seconds of dead air on every request, so
//! A's queue runs dry at once and its fleet goes idle with that one
//! article (and at most its hedge duplicate) still pending. A daemon
//! that waits for A's drain cannot ask for a B article until that dead
//! air ends; a daemon that hands over asks within a fraction of a
//! second of it. The bound is the mock's sleep, not a poll cadence, so
//! the assertion has no timing window to flake in.
//!
//! The second half of the file is the other side of the same overlap:
//! STEERING the job that is draining behind the active one. See the
//! banner above `drain_rig`.
//!
//! Same discipline as postproc_lane.rs: the test owns a daemon on its
//! own port, NZBFAST_NO_ENRICH=1 in the child's environment.

// The shared daemon launcher (free_port / KillOnDrop / DaemonLog /
// serve / wait_ready) and the scratch-dir guard, both declared once in
// main.rs because this file is a module of the merged binary.
use crate::scratch;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::harness::serve;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

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
    s.write_all(&request)?;
    let mut out = String::new();
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

/// Returns the job's `nzo_id` - the drain tests steer both jobs by id,
/// which is the whole point of `fire_drain`'s `want` predicate.
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
    serde_json::from_str::<serde_json::Value>(&r)
        .ok()
        .and_then(|v| v["nzo_ids"][0].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("no nzo_id in {r}"))
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

fn history_slots(port: u16) -> Vec<serde_json::Value> {
    let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
    serde_json::from_str::<serde_json::Value>(&h)
        .ok()
        .and_then(|v| v["history"]["slots"].as_array().cloned())
        .unwrap_or_default()
}

/// The sequence number of a job's `job.finishing` lifecycle event -
/// the instant its tail was handed to the post-processing lane, stamped
/// inside `PostprocLane::submit` on the runner's own task. The runner
/// is a single loop, so these numbers order the lane's inbox exactly,
/// which is the ordering the hand-over is responsible for. History
/// order is a different quantity (when each tail FINISHED) and this is
/// deliberately not it.
fn finishing_seq(port: u16, name: &str) -> u64 {
    life_events(port)
        .iter()
        .find(|e| e["kind"] == "job.finishing" && e["name"] == name)
        .and_then(|e| e["seq"].as_u64())
        .unwrap_or_else(|| panic!("no job.finishing event for {name}"))
}

/// The §129 1b lifecycle ring, oldest first, as the dashboard serves it.
fn life_events(port: u16) -> Vec<serde_json::Value> {
    let dash = http(
        port,
        "/api?mode=dashboard&events=0&apikey=sekrit&output=json",
        None,
    );
    let v: serde_json::Value = serde_json::from_str(&dash)
        .unwrap_or_else(|e| panic!("mode=dashboard did not answer JSON: {e}: {dash}"));
    v["events"].as_array().cloned().unwrap_or_default()
}

/// The seq of the first event of `kind`, at or after `after`.
fn seq_of(events: &[serde_json::Value], kind: &str, after: u64) -> Option<u64> {
    events
        .iter()
        .filter(|e| e["kind"] == kind)
        .filter_map(|e| e["seq"].as_u64())
        .find(|seq| *seq >= after)
}

/// Dead air on job A's last article. Long enough that a serial daemon
/// provably cannot ask for a B article before it ends, short enough to
/// keep the test quick.
const DEAD_AIR_MS: u64 = 5_000;

#[tokio::test(flavor = "multi_thread")]
async fn the_next_job_s_first_article_is_asked_while_the_previous_one_drains() {
    let dir = std::env::temp_dir().join(format!("nzbfast-handoff-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let a_bytes = payload(480_001, 11);
    let b_bytes = payload(320_001, 29);
    let mut articles = HashMap::new();
    let segs_a = make_file_articles("Handoff.A.2026.mkv", &a_bytes, 40_000, "ha", &mut articles);
    let segs_b = make_file_articles("Handoff.B.2026.mkv", &b_bytes, 40_000, "hb", &mut articles);
    // The LAST article of A is the slow one: A's queue is dry the
    // moment it is handed out, and every other connection then goes
    // idle with nothing to do but wait for it (or race it once).
    let slow_id = format!("<{}>", segs_a.last().unwrap().0);
    let srv = MockServer::start(
        articles,
        Chaos {
            slow_ttfb: HashMap::from([(slow_id.clone(), DEAD_AIR_MS)]),
            ..Chaos::default()
        },
    )
    .await;
    let body_log = srv.body_log.clone();

    let xml_a = nzb_xml("Handoff.A.2026.mkv", &segs_a);
    let xml_b = nzb_xml("Handoff.B.2026.mkv", &segs_b);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":4}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
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
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let dir2 = dir.clone();

    tokio::task::spawn_blocking(move || {
        add_nzb(port, "Handoff.A.2026", &xml_a);
        add_nzb(port, "Handoff.B.2026", &xml_b);

        // Watch the request log: when was A's slow article first asked
        // for, and when was the first B article asked for?
        let mut slow_asked: Option<Instant> = None;
        let mut b_asked: Option<Instant> = None;
        let t0 = Instant::now();
        while b_asked.is_none() && t0.elapsed() < Duration::from_secs(60) {
            {
                let log = body_log.lock().unwrap();
                if slow_asked.is_none() && log.contains(&slow_id) {
                    slow_asked = Some(Instant::now());
                }
                if log.iter().any(|id| id.starts_with("<hb-")) {
                    b_asked = Some(Instant::now());
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let slow_asked = slow_asked.expect("A's slow article was never requested");
        let b_asked = b_asked.expect("no B article was requested within 60 s");
        // The proof. A's slow article cannot be served before its dead
        // air ends, so a daemon that waits for A's drain cannot ask for
        // B before `slow_asked + DEAD_AIR_MS`. Asking well inside that
        // window means B started on A's idle connections.
        let gap = b_asked.saturating_duration_since(slow_asked);
        assert!(
            gap < Duration::from_millis(DEAD_AIR_MS / 2),
            "B's first article was asked {gap:?} after A's slow one - the \
             hand-over did not happen (a serial queue waits the full \
             {DEAD_AIR_MS} ms of dead air)"
        );

        // Both complete and byte-identical. WHICH ONE FILES FIRST IS
        // NOT ASSERTED - see `finishing_seq` below for the ordering
        // claim this test is entitled to make, and why this is not it.
        let mut slots = Vec::new();
        for _ in 0..600 {
            slots = history_slots(port);
            let done = slots.iter().filter(|s| s["status"] == "Completed").count();
            if done == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(slots.len(), 2, "both jobs should be in history: {slots:?}");
        for s in &slots {
            assert_eq!(s["status"], "Completed", "{s}");
        }
        // The real ordering guarantee, and the one the hand-over owes:
        // job A's TAIL reaches the post-processing lane before job B's.
        // The runner submits a drained run and only then looks at its
        // successor's signals (`serve/tasks/worker.rs`), and
        // `job.finishing` is emitted inside `PostprocLane::submit` on
        // that same single task - so the two sequence numbers are
        // ordered by construction, with no timing window at all. A
        // hand-over that filed B's tail ahead of A's fails here.
        //
        // This USED to be an assertion on history order ("history order
        // must be queue order"), which is a claim about PARK order, and
        // park order is not the lane's inbox order: the lane runs tails
        // concurrently (`postproc_jobs`, default 2), so two jobs whose
        // tails overlap file in whichever order they finish. On this
        // fixture they park about 15 ms apart - A first on a quiet box,
        // either way on a loaded one - and a 4-vCPU CI runner duly took
        // the other side on 23 Aug 2026 (ci-private linux-tests shard
        // 2, both nextest retries, same runner). Nothing was wrong with
        // the daemon: a fast job whose predecessor is still repairing
        // is SUPPOSED to reach history first, which is what §129's lane
        // overlap is for, and that has been true since long before the
        // hand-over existed.
        let a_seq = finishing_seq(port, "Handoff.A.2026");
        let b_seq = finishing_seq(port, "Handoff.B.2026");
        assert!(
            a_seq < b_seq,
            "A's tail must reach the lane before B's (job.finishing seq {a_seq} vs {b_seq})"
        );

        // The other ordering the overlap owes, and this one IS an
        // invariant rather than a race: `queue.idle` says the queue ran
        // dry, so it cannot precede the `job.completed` of a job that
        // was still in the post-processing lane when it was said.
        //
        // It could, and did. `park_gen` retains the row out of the
        // queue a hundred lines before it pushes the record into
        // history, and ends with `note_queue_idle`, whose scan asked
        // only the QUEUE - so A's park, landing inside B's window, saw
        // an empty queue and announced the drain with B in neither
        // list. The ring off this very fixture read `job.completed A`,
        // `queue.idle`, `job.completed B` (23 Aug 2026). A subscriber
        // that reads history for what just finished - the webhook, the
        // queue-finished script - was told the queue was done and could
        // not see B anywhere.
        //
        // Polled, because the edge is owed by the LAST lane ticket to
        // drop and that is after both records reach history; the
        // assertion below is on ORDER, so the wait is for the event to
        // exist at all and not for a window to open.
        let mut events = Vec::new();
        let mut idle = None;
        let t1 = Instant::now();
        while idle.is_none() && t1.elapsed() < Duration::from_secs(60) {
            events = life_events(port);
            idle = seq_of(&events, "queue.idle", a_seq);
            if idle.is_none() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let idle = idle.unwrap_or_else(|| {
            panic!("the queue drained but queue.idle was never said: {events:?}")
        });
        let completed = |name: &str| -> u64 {
            events
                .iter()
                .find(|e| e["kind"] == "job.completed" && e["name"] == name)
                .and_then(|e| e["seq"].as_u64())
                .unwrap_or_else(|| panic!("no job.completed for {name}: {events:?}"))
        };
        for name in ["Handoff.A.2026", "Handoff.B.2026"] {
            let done = completed(name);
            assert!(
                done < idle,
                "queue.idle (seq {idle}) was said before {name} completed (seq {done}) - \
                 the drain was announced over a tail still in the lane"
            );
        }
        let row = |name: &str| -> &serde_json::Value {
            slots
                .iter()
                .find(|s| s["name"] == name)
                .unwrap_or_else(|| panic!("{name} is not in history: {slots:?}"))
        };
        for (s, want, len) in [
            (row("Handoff.A.2026"), &a_bytes, 480_001u64),
            (row("Handoff.B.2026"), &b_bytes, 320_001u64),
        ] {
            let job_dir = std::path::PathBuf::from(s["storage"].as_str().unwrap());
            assert!(job_dir.starts_with(dir2.join("complete")), "{job_dir:?}");
            let file = std::fs::read_dir(&job_dir)
                .expect("job dir")
                .flatten()
                .map(|e| e.path())
                .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() == len))
                .unwrap_or_else(|| panic!("no {len}-byte payload in {job_dir:?}"));
            assert_eq!(&std::fs::read(&file).unwrap(), want, "{file:?} differs");
        }
        // Every A article was asked for; the hand-over never starved
        // the draining job of its own work.
        let log = body_log.lock().unwrap();
        for (id, _, _) in &segs_a {
            let want = format!("<{id}>");
            assert!(log.contains(&want), "A's {want} was never requested");
        }
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `NZBFAST_QUEUE_HANDOFF=0` is the strictly serial queue of before:
/// the same two jobs, and B's first article waits for A's drain.
#[tokio::test(flavor = "multi_thread")]
async fn with_the_handoff_off_the_queue_is_serial() {
    let dir = std::env::temp_dir().join(format!("nzbfast-handoff-off-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let a_bytes = payload(200_001, 5);
    let b_bytes = payload(120_001, 7);
    let mut articles = HashMap::new();
    let segs_a = make_file_articles("Serial.A.2026.mkv", &a_bytes, 40_000, "sa", &mut articles);
    let segs_b = make_file_articles("Serial.B.2026.mkv", &b_bytes, 40_000, "sb", &mut articles);
    let slow_id = format!("<{}>", segs_a.last().unwrap().0);
    let srv = MockServer::start(
        articles,
        Chaos {
            slow_ttfb: HashMap::from([(slow_id.clone(), 2_000)]),
            ..Chaos::default()
        },
    )
    .await;
    let body_log = srv.body_log.clone();
    let xml_a = nzb_xml("Serial.A.2026.mkv", &segs_a);
    let xml_b = nzb_xml("Serial.B.2026.mkv", &segs_b);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":4}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_QUEUE_HANDOFF", "0")
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
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        add_nzb(port, "Serial.A.2026", &xml_a);
        add_nzb(port, "Serial.B.2026", &xml_b);
        let mut slow_asked: Option<Instant> = None;
        let mut b_asked: Option<Instant> = None;
        let t0 = Instant::now();
        while b_asked.is_none() && t0.elapsed() < Duration::from_secs(60) {
            {
                let log = body_log.lock().unwrap();
                if slow_asked.is_none() && log.contains(&slow_id) {
                    slow_asked = Some(Instant::now());
                }
                if log.iter().any(|id| id.starts_with("<sb-")) {
                    b_asked = Some(Instant::now());
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let gap = b_asked
            .expect("B never asked")
            .saturating_duration_since(slow_asked.expect("slow never asked"));
        assert!(
            gap >= Duration::from_millis(2_000),
            "with the hand-over off, B must wait for A's drain; it was asked after {gap:?}"
        );
        for _ in 0..600 {
            if history_slots(port)
                .iter()
                .filter(|s| s["status"] == "Completed")
                .count()
                == 2
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("both jobs should complete");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The slow-job watchdog keeps judging a predecessor that is DRAINING
/// behind the active job. Slow job S lives only on a 250 ms/article
/// server; F1 and F2 queue behind it on the fast server. S's idle
/// fast-server connection is handed to F1, which finishes at once - but
/// F2 still waits behind S (the runner files S before it looks at F1),
/// so the verdict fires on S off the gauges the runner detached for it,
/// S is moved to the back, F2 runs, and S finishes afterwards from its
/// journal.
#[tokio::test(flavor = "multi_thread")]
async fn a_draining_predecessor_is_still_deferred_when_a_job_waits_behind_it() {
    let dir = std::env::temp_dir().join(format!("nzbfast-handoff-defer-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let s_bytes = payload(3_000_000, 31);
    let f1_bytes = payload(1_600_000, 33);
    let f2_bytes = payload(1_600_000, 35);
    let mut slow_articles = HashMap::new();
    let s_segs = make_file_articles("slowjob.bin", &s_bytes, 20_000, "hs", &mut slow_articles);
    let mut fast_articles = HashMap::new();
    // The session-best rate the verdict compares against comes from a
    // COMPLETED job's average, and a successor's only reaches the ledger
    // once it is filed - which is when its own tail parks, long after
    // the verdict window on the job it overlapped has opened. So the
    // reference is seeded by a warm-up job, exactly as the serial-model
    // test does it.
    let w_bytes = payload(8_000_000, 37);
    let w_segs = make_file_articles("warm.bin", &w_bytes, 40_000, "hw", &mut fast_articles);
    let f1_segs = make_file_articles("fast1.bin", &f1_bytes, 40_000, "hf", &mut fast_articles);
    let f2_segs = make_file_articles("fast2.bin", &f2_bytes, 40_000, "hg", &mut fast_articles);
    let fast_srv = MockServer::start(
        fast_articles,
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let slow_srv = MockServer::start(
        slow_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}},{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            fast_srv.addr.ip(),
            fast_srv.addr.port(),
            slow_srv.addr.ip(),
            slow_srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
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
            .arg("2");
        c
    })
    .await;
    let port = d.port;
    let (w_xml, s_xml, f1_xml, f2_xml) = (
        nzb_xml("warm.bin", &w_segs),
        nzb_xml("slowjob.bin", &s_segs),
        nzb_xml("fast1.bin", &f1_segs),
        nzb_xml("fast2.bin", &f2_segs),
    );
    tokio::task::spawn_blocking(move || {
        let queue = || http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        add_nzb(port, "warm", &w_xml);
        for _ in 0..300 {
            if history_slots(port)
                .iter()
                .any(|s| s["name"] == "warm" && s["status"] == "Completed")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        add_nzb(port, "slowjob", &s_xml);
        for _ in 0..100 {
            if queue().contains("Downloading") {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        add_nzb(port, "fast1", &f1_xml);
        add_nzb(port, "fast2", &f2_xml);
        // The watchdog defers S while F2 waits behind it (warm-up 2 s +
        // window 3 s after S started).
        let mut deferred = false;
        for _ in 0..300 {
            if queue().contains("\"deferred\":true") {
                deferred = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(
            deferred,
            "the draining slow job was never deferred:\n{}",
            queue()
        );
        // F2 completes while S is still in the queue, then S completes.
        let mut f2_done = false;
        for _ in 0..300 {
            let slots = history_slots(port);
            if slots
                .iter()
                .any(|s| s["name"] == "fast2" && s["status"] == "Completed")
            {
                f2_done = true;
                assert!(
                    !slots.iter().any(|s| s["name"] == "slowjob"),
                    "S must not be in history before F2: {slots:?}"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(f2_done, "fast2 never completed");
        for _ in 0..600 {
            let slots = history_slots(port);
            if slots
                .iter()
                .any(|s| s["name"] == "slowjob" && s["status"] == "Completed")
            {
                assert_eq!(slots.len(), 4, "{slots:?}");
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "the deferred slow job never completed: {:?}",
            history_slots(port)
        );
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/slowjob/slowjob.bin")).unwrap(),
        s_bytes
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Steering the DRAINING predecessor: pause and delete (Codex F-04).
//
// `owns_hub` answers for the ACTIVE transfer alone, so from the instant
// the successor claims the hub every pause and delete aimed at the
// predecessor declined forever - its `abort` / `queue_ctl` had moved
// into `drain_dl` and only the slow-job watchdog ever read them. Pause
// was a no-op that answered success; a deleted job's metered traffic ran
// to its own end. `Daemon::fire_drain` / `owns_wire` (serve/wire.rs) are
// the fix, and until now only `serve/wire_tests.rs` covered them - unit
// tests over a hand-built `DrainSlot`, with nothing exercising the real
// hand-over. `tests/daemon_delete/mod.rs` pins `NZBFAST_QUEUE_HANDOFF=0`,
// so no delete test has ever run against a populated drain slot at all.
//
// The rig below leaves the hand-over ON and gives the predecessor a long
// drain to be caught in the middle of.
// ---------------------------------------------------------------------

/// Per-body delay on the server that holds A's articles. A is the job
/// we want to catch mid-drain, so its server is the slow one.
const DRAIN_SLOW_MS: u64 = 200;
/// ...and on the one that holds B's. B only has to keep visibly moving
/// for as long as A's half of each test takes.
const DRAIN_FAST_MS: u64 = 60;
/// 20 KB articles, 400 each. A is therefore ~80 s of slow server (~40 s
/// across its two connections) - long enough that a predecessor nobody
/// stopped is still fetching when every assertion below has run.
const DRAIN_ART: usize = 20_000;
const DRAIN_ARTICLES: usize = 400;
/// A's message-id tag, as it appears on the wire.
const DRAIN_A_TAG: &str = "<da-";

/// What the rig hands the blocking half of a test. The two mock servers,
/// the daemon and the scratch guard are held only to keep them alive for
/// the test's lifetime.
struct DrainRig {
    port: u16,
    dir: PathBuf,
    log_path: PathBuf,
    a_xml: String,
    b_xml: String,
    b_bytes: Vec<u8>,
    /// The request log of the server that HOLDS A's articles: A's wire,
    /// read through `asked_for`, which filters it (the successor asks
    /// this server for its own articles too and is refused).
    a_wire: Arc<Mutex<Vec<String>>>,
    _slow: MockServer,
    _fast: MockServer,
    _d: crate::harness::Daemon,
    _scratch: scratch::ScratchDir,
}

/// Two jobs, two servers, hand-over ON.
///
/// A's articles live ONLY on the slow server and B's ONLY on the fast
/// one. A's connections to the FAST server run its queue dry on 430s in
/// a fraction of a second and then go idle, which is exactly the
/// condition [`nzbkit::pool::handoff::HandoffSignal`] latches on - so B
/// claims the hub while A still has nearly all of its own bytes to fetch
/// from the slow server. That is the populated `drain_dl` the unit tests
/// build by hand, produced by the real runner.
///
/// A single server with its tail articles held in dead air was tried
/// first and cannot prove the pause half: a graceful drain lets in-flight
/// reads finish, so a held tail is exactly what BOTH the fixed and the
/// unfixed daemon go on to fetch. The predecessor has to have real work
/// left that a wind-down can take away from it, and the hand-over only
/// fires once its queue is dry - which is why the work has to be on a
/// server the successor is not racing it for. Same two-server shape as
/// `a_draining_predecessor_is_still_deferred_when_a_job_waits_behind_it`
/// above.
async fn drain_rig(tag: &str) -> DrainRig {
    let dir = std::env::temp_dir().join(format!("nzbfast-drain-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let a_bytes = payload(DRAIN_ART * DRAIN_ARTICLES, 41);
    let b_bytes = payload(DRAIN_ART * DRAIN_ARTICLES, 43);
    let mut slow_articles = HashMap::new();
    let a_segs = make_file_articles("drainA.bin", &a_bytes, DRAIN_ART, "da", &mut slow_articles);
    let mut fast_articles = HashMap::new();
    let b_segs = make_file_articles("drainB.bin", &b_bytes, DRAIN_ART, "db", &mut fast_articles);
    let fast = MockServer::start(
        fast_articles,
        Chaos {
            delay_ms: DRAIN_FAST_MS,
            ..Chaos::default()
        },
    )
    .await;
    let slow = MockServer::start(
        slow_articles,
        Chaos {
            delay_ms: DRAIN_SLOW_MS,
            ..Chaos::default()
        },
    )
    .await;
    let a_wire = slow.body_log.clone();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":2}},{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":2}}]}}",
            fast.addr.ip(),
            fast.addr.port(),
            slow.addr.ip(),
            slow.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
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
            .arg("2");
        c
    })
    .await;
    DrainRig {
        port: d.port,
        log_path: d.log_path(),
        a_xml: nzb_xml("drainA.bin", &a_segs),
        b_xml: nzb_xml("drainB.bin", &b_segs),
        b_bytes,
        a_wire,
        dir,
        _slow: slow,
        _fast: fast,
        _d: d,
        _scratch,
    }
}

/// Poll `cond` at 100 ms until it holds, or panic with `what` after 60 s.
fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting: {what}");
}

fn queue_slots(port: u16) -> Vec<serde_json::Value> {
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    serde_json::from_str::<serde_json::Value>(&q)
        .ok()
        .and_then(|v| v["queue"]["slots"].as_array().cloned())
        .unwrap_or_default()
}

fn queue_slot(port: u16, id: &str) -> Option<serde_json::Value> {
    queue_slots(port).into_iter().find(|s| s["nzo_id"] == id)
}

/// Megabytes this job has decoded, as the queue reports them - which for
/// a job on the wire is `Daemon::wire_counters`, the active hub's
/// counters or the drain slot's. `f64::MAX` once the job has left the
/// queue for history, so a caller comparing two samples of a job that
/// finished in between still reads it as progress.
fn decoded_mb(port: u16, id: &str) -> f64 {
    let num = |s: &serde_json::Value, k: &str| {
        s[k].as_str()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    queue_slot(port, id).map_or(f64::MAX, |s| num(&s, "mb") - num(&s, "mbleft"))
}

/// Distinct A articles this server has been asked for.
///
/// Deduplicated because a hedge duplicate is the same article twice, and
/// filtered by A's own id tag because the successor asks THIS server for
/// its articles too: they are not here, so they are refused instantly,
/// and counting them made A's wire look like it was serving hundreds of
/// bodies a second and never falling silent.
fn asked_for(wire: &Arc<Mutex<Vec<String>>>) -> usize {
    wire.lock()
        .unwrap()
        .iter()
        .filter(|id| id.starts_with(DRAIN_A_TAG))
        .collect::<HashSet<_>>()
        .len()
}

/// Enqueue A, then B, and return once B owns the hub with A draining
/// behind it: the runner says so in its own log, and B is moving bytes.
fn arm_handoff(port: u16, log_path: &Path, a_xml: &str, b_xml: &str) -> (String, String) {
    let a_id = add_nzb(port, "drainA", a_xml);
    wait_until("A never started downloading", || {
        queue_slot(port, &a_id).is_some_and(|s| s["status"] == "Downloading")
    });
    let b_id = add_nzb(port, "drainB", b_xml);
    let handed = format!("{b_id} starting while {a_id} drains");
    wait_until("the hand-over never happened", || {
        std::fs::read_to_string(log_path)
            .unwrap_or_default()
            .contains(&handed)
    });
    // ...and B is really on the wire, not merely nominated for it: its
    // decoded-byte counter has moved. From here A can only be reported
    // from `drain_dl`.
    wait_until("B never decoded a byte", || decoded_mb(port, &b_id) > 0.0);
    (a_id, b_id)
}

/// Wait for A's wire to fall silent, and return how many distinct
/// articles it was ever asked for.
///
/// `quiet` is deliberately longer than one slow body: a graceful drain
/// admits nothing new but lets the in-flight window (three per
/// connection by default) finish, so the last few requests trickle in
/// after the signal lands. A predecessor nobody stopped never goes quiet
/// at all - it has ~40 s of slow server left - so the bound below is
/// what that failure trips.
fn wait_for_quiet_wire(wire: &Arc<Mutex<Vec<String>>>) -> usize {
    let quiet = Duration::from_secs(2);
    let mut last = asked_for(wire);
    let mut since = Instant::now();
    let t0 = Instant::now();
    loop {
        let n = asked_for(wire);
        if n != last {
            last = n;
            since = Instant::now();
        }
        if since.elapsed() >= quiet {
            return n;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(25),
            "A's wire never went quiet - {n} of {DRAIN_ARTICLES} articles asked for and \
             still climbing, so the signal never reached the drain slot"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// How much of A a stopped predecessor may have fetched. It is mid-drain
/// when the signal lands, so it has fetched whatever the arm-up cost
/// (tens of articles, the slow server being capped at five per second
/// per connection) plus its in-flight window. Half the set is a wide
/// margin over that and still nowhere near the whole set an unstopped
/// predecessor fetches.
const DRAIN_CUT_SHORT: usize = DRAIN_ARTICLES / 2;

/// Pausing the DRAINING predecessor stops its transfer, leaves the
/// successor alone, and returns it to the queue suspended.
#[tokio::test(flavor = "multi_thread")]
async fn pausing_a_draining_predecessor_stops_its_wire_and_leaves_the_successor_running() {
    let rig = drain_rig("pause").await;
    let (port, dir, wire) = (rig.port, rig.dir.clone(), rig.a_wire.clone());
    let (log_path, a_xml, b_xml) = (rig.log_path.clone(), rig.a_xml.clone(), rig.b_xml.clone());
    let b_bytes = rig.b_bytes.clone();
    tokio::task::spawn_blocking(move || {
        let (a_id, b_id) = arm_handoff(port, &log_path, &a_xml, &b_xml);
        let b_before = decoded_mb(port, &b_id);

        let r = http(
            port,
            &format!("/api?mode=queue&name=pause&value={a_id}&apikey=sekrit&output=json"),
            None,
        );
        assert!(
            r.contains("\"status\": true") || r.contains("\"status\":true"),
            "{r}"
        );

        // A's wire stops. B's does not.
        let a_seen = wait_for_quiet_wire(&wire);
        assert!(
            a_seen <= DRAIN_CUT_SHORT,
            "the pause did not cut A's transfer short: {a_seen} of {DRAIN_ARTICLES} articles"
        );
        assert!(
            decoded_mb(port, &b_id) > b_before,
            "the successor stopped too - the pause was aimed at the whole wire, not at A"
        );

        // A comes back to the queue suspended, and never reaches history.
        wait_until("A never returned to the queue paused", || {
            queue_slot(port, &a_id).is_some_and(|s| s["status"] == "Paused")
        });
        assert!(
            !history_slots(port).iter().any(|s| s["nzo_id"] == a_id),
            "a paused job must not be filed in history"
        );

        // B finishes, byte-identical, with A still sitting paused.
        wait_until("B never completed", || {
            history_slots(port)
                .iter()
                .any(|s| s["nzo_id"] == b_id && s["status"] == "Completed")
        });
        let slots = history_slots(port);
        assert!(
            !slots.iter().any(|s| s["nzo_id"] == a_id),
            "the paused predecessor reached history: {slots:?}"
        );
        assert!(
            queue_slot(port, &a_id).is_some_and(|s| s["status"] == "Paused"),
            "A must still be in the queue, paused"
        );
        let b_slot = slots.iter().find(|s| s["nzo_id"] == b_id).unwrap();
        let job_dir = PathBuf::from(b_slot["storage"].as_str().unwrap());
        assert!(job_dir.starts_with(dir.join("complete")), "{job_dir:?}");
        assert_eq!(std::fs::read(job_dir.join("drainB.bin")).unwrap(), b_bytes);
    })
    .await
    .unwrap();
}

/// Deleting the DRAINING predecessor stops its metered traffic, and the
/// successor still completes.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_draining_predecessor_stops_its_wire_and_leaves_the_successor_running() {
    let rig = drain_rig("delete").await;
    let (port, dir, wire) = (rig.port, rig.dir.clone(), rig.a_wire.clone());
    let (log_path, a_xml, b_xml) = (rig.log_path.clone(), rig.a_xml.clone(), rig.b_xml.clone());
    let b_bytes = rig.b_bytes.clone();
    tokio::task::spawn_blocking(move || {
        let (a_id, b_id) = arm_handoff(port, &log_path, &a_xml, &b_xml);
        let b_before = decoded_mb(port, &b_id);

        let r = http(
            port,
            &format!("/api?mode=queue&name=delete&value={a_id}&apikey=sekrit&output=json"),
            None,
        );
        assert!(
            r.contains("\"removed\": 1") || r.contains("\"removed\":1"),
            "{r}"
        );
        assert!(
            queue_slot(port, &a_id).is_none(),
            "a deleted job must leave the queue at once"
        );

        // The record going is not the point - the bytes stopping is.
        let a_seen = wait_for_quiet_wire(&wire);
        assert!(
            a_seen <= DRAIN_CUT_SHORT,
            "the delete did not stop A's metered traffic: {a_seen} of {DRAIN_ARTICLES} articles"
        );
        assert!(
            decoded_mb(port, &b_id) > b_before,
            "the successor stopped too - the delete was aimed at the whole wire, not at A"
        );

        wait_until("B never completed", || {
            history_slots(port)
                .iter()
                .any(|s| s["nzo_id"] == b_id && s["status"] == "Completed")
        });
        let slots = history_slots(port);
        assert!(
            !slots.iter().any(|s| s["nzo_id"] == a_id),
            "a deleted job must never appear in history: {slots:?}"
        );
        assert!(
            queue_slot(port, &a_id).is_none(),
            "A came back to the queue"
        );
        let b_slot = slots.iter().find(|s| s["nzo_id"] == b_id).unwrap();
        let job_dir = PathBuf::from(b_slot["storage"].as_str().unwrap());
        assert!(job_dir.starts_with(dir.join("complete")), "{job_dir:?}");
        assert_eq!(std::fs::read(job_dir.join("drainB.bin")).unwrap(), b_bytes);
    })
    .await
    .unwrap();
}
