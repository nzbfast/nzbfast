//! M14g gate: pool-level speed limiter - a capped download takes the wall
//! clock it must, the cap is visible in mode=queue, and mode=config lifts
//! it live without a restart.

use crate::scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Instant;

use crate::harness::serve;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
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

fn nzb_xml(name: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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

fn addfile(port: u16, fname: &str, xml: &str) -> String {
    let boundary = "----throttleb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    )
}

/// Poll history until it holds `n` Completed entries; returns the elapsed
/// time since call start, or panics after the budget. (Counting, not name
/// matching - every nzo_id contains the substring "fast".)
fn wait_n_completed(port: u16, n: usize, budget_ms: u64) -> std::time::Duration {
    let t0 = Instant::now();
    while t0.elapsed().as_millis() < budget_ms as u128 {
        let h = http(port, "/api?mode=history&output=json", None);
        if h.matches("\"Completed\"").count() >= n {
            return t0.elapsed();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("history never reached {n} Completed within {budget_ms} ms");
}

#[tokio::test(flavor = "multi_thread")]
async fn speedlimit_paces_and_lifts_live() {
    let dir = std::env::temp_dir().join(format!("nzbfast-throttle-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Two ~2 MB posts on one mock server.
    let slow_data = payload(2_000_000, 5);
    let fast_data = payload(2_000_000, 9);
    let mut articles = HashMap::new();
    let slow_segs = make_file_articles("slow.bin", &slow_data, 100_000, "sl", &mut articles);
    let fast_segs = make_file_articles("fast.bin", &fast_data, 100_000, "fa", &mut articles);
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
            .arg("2")
            .arg("--speedlimit")
            .arg("500K");
        c
    })
    .await;
    let port = d.port;

    let slow_xml = nzb_xml("slow.bin", &slow_segs);
    let fast_xml = nzb_xml("fast.bin", &fast_segs);
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // The CLI-set cap is visible before anything downloads. A
        // STRING since issue #34: SABnzbd sends this field as one, and
        // our own mode=status always did - the queue body was the odd
        // one out.
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"speedlimit_abs\":\"500000\""), "{q}");

        // ~2 MB (≈2.05 MB raw yEnc actually charged) at 500 KB/s must take
        // ≥ 4 s of reading - assert a generous ≥ 3 s lower bound only.
        let r = addfile(port, "slow.nzb", &slow_xml);
        assert!(r.contains("\"status\":true"), "{r}");
        let took = wait_n_completed(port, 1, 60_000);
        assert!(
            took >= std::time::Duration::from_secs(3),
            "throttled download finished suspiciously fast: {took:?}"
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/slow/slow.bin")).unwrap(),
            payload(2_000_000, 5),
            "throttled payload corrupt"
        );

        // Lift the cap live via the SAB-shaped config endpoint.
        let r = http(
            port,
            "/api?mode=config&name=speedlimit&value=0&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"speedlimit_abs\":\"0\""), "{q}");

        // Bad values are rejected without touching the cap.
        let r = http(
            port,
            "/api?mode=config&name=speedlimit&value=junk&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"speedlimit_abs\":\"0\""), "{q}");

        // Uncapped, the same-sized post completes fast (loose bound - this
        // took ≥ 4 s while capped).
        let r = addfile(port, "fast.nzb", &fast_xml);
        assert!(r.contains("\"status\":true"), "{r}");
        let took = wait_n_completed(port, 2, 30_000);
        assert!(
            took < std::time::Duration::from_secs(3),
            "uncapped download still slow: {took:?}"
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/fast/fast.bin")).unwrap(),
            payload(2_000_000, 9),
            "uncapped payload corrupt"
        );
    })
    .await
    .unwrap();
}

/// M14g3 smoke: with the governor on (localhost RTT ≈ base, so it only
/// ever climbs), downloads complete untouched, the toggle round-trips
/// via the API, and turning it off restores the ceiling.
#[tokio::test(flavor = "multi_thread")]
async fn auto_speed_governor_smoke() {
    let dir = std::env::temp_dir().join(format!("nzbfast-autospeed-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(1_000_000, 17);
    let mut articles = HashMap::new();
    let segs = make_file_articles("as.bin", &data, 100_000, "as", &mut articles);
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
            .arg("2")
            .arg("--auto-speed");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"auto_speed\":true"), "{q}");

        addfile(port, "as.nzb", &nzb_xml("as.bin", &segs));
        wait_n_completed(port, 1, 30_000);
        assert_eq!(
            std::fs::read(dir2.join("complete/as/as.bin")).unwrap(),
            data
        );

        // Toggle off: rate returns to the (unlimited) ceiling.
        let r = http(
            port,
            "/api?mode=config&name=auto_speed&value=0&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"auto_speed\":false"), "{q}");
        assert!(q.contains("\"speedlimit_abs\":\"0\""), "{q}");
        // And back on.
        let r = http(
            port,
            "/api?mode=config&name=auto_speed&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
    })
    .await
    .unwrap();
}
