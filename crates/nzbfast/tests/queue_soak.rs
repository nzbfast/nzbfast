//! M14 cross-job soak: several queued jobs run back-to-back with job N's
//! tail overlapping job N+1's download. Correctness gate: every job
//! completes byte-identical, states/history stay sane, no
//! cross-contamination between overlapping jobs.

mod harness;
mod scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

use harness::Daemon;

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
        .collect()
}

/// Response body of a request to the daemon (headers stripped).
///
/// A connection REFUSED before it produced a single byte is retried. That
/// is not the same as tolerating a bad answer: tiny_http's honest reply
/// when it cannot start a thread for a new connection is to drop the
/// socket unread, and with our request still in its receive buffer the
/// kernel turns that into an RST - which arrives here as ECONNRESET. A
/// full `cargo test` runs these suites in parallel, each test with a whole
/// daemon behind it, so `thread::Builder::spawn` really does hit EAGAIN,
/// and a test then failed on a refusal to serve rather than on anything it
/// asserts. Once a byte has come back it is an answer, and it is returned
/// (or fails) exactly as it arrived - a truncated response must never be
/// retried away.
fn http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req, body) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

/// One attempt. Returns Err ONLY when the daemon produced nothing at all;
/// a partial or malformed response is data, and is handed back for the
/// caller's assertions to judge.
fn http_once(port: u16, req: &str, body: Option<(&str, &[u8])>) -> std::io::Result<String> {
    let mut request = Vec::new();
    match body {
        None => {
            write!(
                request,
                "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
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
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
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

/// Launch a daemon under `dir` and return once OUR daemon is serving.
///
/// `build` is handed the port to serve on and returns the fully
/// configured command; it may be called again on a fresh port, so it must
/// not consume anything.
async fn serve(dir: &Path, build: impl Fn(u16) -> Command) -> Daemon {
    harness::serve(dir, |port| {
        let mut cmd = build(port);
        // The `min_free` floor (2 GB by default) is measured against the
        // HOST's free disk, not against anything this soak writes, so a
        // CI box run down near full holds every job before it starts and
        // the soak reports "queue never drained" - a download bug's
        // symptom with a housekeeping cause (nightly, 15 Aug 2026). The
        // fixtures here are kilobytes; the floor is not this target's
        // subject. `crates/nzbfast/tests/daemon.rs` carries the same
        // default for the same reason.
        cmd.arg("--min-free").arg("0");
        cmd
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn three_jobs_back_to_back_all_byte_identical() {
    let dir = std::env::temp_dir().join(format!("nzbfast-qsoak-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Three distinct ~1.5 MB posts on one mock server.
    let mut articles = HashMap::new();
    let payloads: Vec<Vec<u8>> = (0..3).map(|i| payload(1_500_000, 40 + i as u8)).collect();
    let all_segs: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(i, data)| {
            make_file_articles(
                &format!("f{i}.bin"),
                data,
                60_000,
                &format!("qs{i}"),
                &mut articles,
            )
        })
        .collect();
    let srv = MockServer::start(articles, Chaos::default()).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        // The daemon mints an API key on a genuinely first run (see
        // serve::first_run_apikey). These suites drive it keyless on purpose,
        // so they take the same deliberate opt-out an operator would.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            // Loopback only. These suites never need LAN reach, and binding
            // 0.0.0.0 makes the macOS firewall raise a prompt for every freshly
            // built test binary, which is a new path on every run.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Enqueue all three at once - transitions exercise the overlap.
        for (i, segs) in all_segs.iter().enumerate() {
            let mut xml = String::from(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
            );
            xml.push_str(&format!(
                "  <file poster=\"x\" date=\"0\" subject=\"&quot;f{i}.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
                segs.len()
            ));
            for (id, bytes, num) in segs {
                xml.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            xml.push_str("    </segments>\n  </file>\n</nzb>\n");
            let boundary = "----qsoakb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"job{i}.nzb\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
        }

        // All three must land Completed.
        let mut done = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.matches("\"Completed\"").count() >= 3 {
                assert!(!h.contains("\"Failed\""), "{h}");
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "queue never drained to 3 Completed");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"noofslots\":0"), "{q}");
    })
    .await
    .unwrap();

    // Byte-identical outputs - the overlap must never cross-contaminate.
    for (i, data) in payloads.iter().enumerate() {
        let out = dir.join(format!("complete/job{i}/f{i}.bin"));
        assert_eq!(&std::fs::read(&out).unwrap(), data, "job{i} differs");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The NZB xml the addfile tests post, from `make_file_articles` output.
fn nzb_xml(inner_name: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{inner_name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

fn addfile(port: u16, filename: &str, xml: &str) {
    let boundary = "----qsoakb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{filename}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
}

/// BUG (HIGH, 31 Jul queue soak): a COMPLETED and auto-RENAMED job
/// re-queued itself and downloaded the whole release a second time into
/// the renamed directory.
///
/// The shape: job N's tail stalls on disk work (in the field, a headless
/// Finder-trash timeout), so job N+1 finishes its network phase but sits
/// `Downloading` in the queue while the runner waits on that tail. The
/// slow-job watchdog reads the drained pool over its window as "≥90% from
/// one host at a fraction of the session-best rate, with others waiting"
/// and demotes it - firing an abort at a pipeline that has already won.
/// The fetch returns Ok, post-processing renames the directory, and
/// park()'s demote arm then silently re-queued the finished job.
///
/// This test rebuilds that stage: two servers (one holding nothing, so
/// the busy one's share is 100%), a first job whose finalize is held open
/// by the test-only stall hook, a middle job slow enough for the watchdog
/// window (per-article delay), auto-rename renaming its folder, and a
/// third job waiting so `others_waiting` holds. The watchdog runs at
/// test-compressed warmup/window. Each job must download exactly once.
#[tokio::test(flavor = "multi_thread")]
async fn a_completed_renamed_job_never_requeues() {
    let dir = std::env::temp_dir().join(format!("nzbfast-qrerun-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Server A holds every article, throttled so the middle job's network
    // phase spans several watchdog ticks. Server B holds nothing and
    // answers 430 - a live pool member contributing zero bytes, which is
    // what pushes A's share to 100%.
    let mut articles = HashMap::new();
    let stall_payload = payload(1_000_000, 11);
    let movie_payload = payload(45_000_000, 22);
    let tail_payload = payload(300_000, 33);
    let stall_segs = make_file_articles("first.bin", &stall_payload, 60_000, "qr0", &mut articles);
    let movie_segs = make_file_articles("video.mkv", &movie_payload, 60_000, "qr1", &mut articles);
    let tail_segs = make_file_articles("last.bin", &tail_payload, 60_000, "qr2", &mut articles);
    let srv_a = MockServer::start(
        articles,
        Chaos {
            delay_ms: 40,
            ..Chaos::default()
        },
    )
    .await;
    let srv_b = MockServer::start(HashMap::new(), Chaos::default()).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}},{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv_a.addr.ip(),
            srv_a.addr.port(),
            srv_b.addr.ip(),
            srv_b.addr.port()
        ),
    )
    .unwrap();
    let logdir = dir.clone();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // Compressed watchdog timeline (the env hooks the watchdog
            // documents for tests) plus the finalize stall that models
            // the field's Finder-trash timeout.
            .env("NZBFAST_DEFER_WARMUP_SECS", "1")
            .env("NZBFAST_DEFER_WINDOW_SECS", "4")
            .env("NZBFAST_TEST_STALL_FINALIZE_MS", "26000")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // No idle-server prefetch: its sidecar would suppress the defer
        // verdict while it runs, and this test wants the verdict itself
        // deterministic.
        let r = http(
            port,
            "/api?mode=config&name=auto_prefetch&value=0&output=json",
            None,
        );
        assert!(r.contains("true"), "{r}");
        addfile(port, "first-job.nzb", &nzb_xml("first.bin", &stall_segs));
        addfile(
            port,
            "Test.Movie.2023.1080p.x264-BUG.nzb",
            &nzb_xml("video.mkv", &movie_segs),
        );
        addfile(port, "last-job.nzb", &nzb_xml("last.bin", &tail_segs));

        // All three must land Completed - through the stalled tails this
        // takes a while, so the deadline is generous. A run that trips
        // the bug still gets here (the re-download completes too); the
        // banner count below is what convicts it.
        let mut done = false;
        for _ in 0..900 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.matches("\"Completed\"").count() >= 3 {
                assert!(!h.contains("\"Failed\""), "{h}");
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "queue never drained to 3 Completed");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"noofslots\":0"), "{q}");

        // Single download per job: the runner prints one start banner
        // ("<spool nzb>: N files ...") per pipeline launch, so a job
        // whose banner appears twice downloaded twice. Give the daemon a
        // beat first - the buggy re-queue happened AFTER history already
        // showed the job Completed.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let log = std::fs::read_dir(&logdir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("daemon-") && n.ends_with(".log"))
            })
            .map(|p| std::fs::read_to_string(p).unwrap_or_default())
            .collect::<String>();
        for stem in [
            "first-job.nzb:",
            "test.movie.2023.1080p.x264-bug.nzb:",
            "last-job.nzb:",
        ] {
            let starts = log
                .to_ascii_lowercase()
                .matches(&stem.to_ascii_lowercase())
                .count();
            assert_eq!(
                starts, 1,
                "{stem} started {starts} downloads - a completed job re-queued\n--- log ---\n{log}"
            );
        }
        // The rename leg really ran: the movie job's folder left under
        // its release name would mean the bug shape was never exercised.
        assert!(
            log.contains("[smart] renamed"),
            "auto-rename never renamed the movie folder\n--- log ---\n{log}"
        );
    })
    .await
    .unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}
