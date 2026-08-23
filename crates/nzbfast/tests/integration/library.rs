//! Metadata-only library mode tests (M14i gate): a job added under a
//! library category is availability-checked (STAT only - no payload),
//! parked Completed with a .strm pointer, and downloaded for real only
//! when /stream/<nzo_id> is first played. Missing content parks Failed.

use crate::scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::{Daemon, serve};
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
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
    let out = String::from_utf8_lossy(&raw_once(port, &request)?).to_string();
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

/// GET returning (headers, raw body bytes) - for binary /stream responses.
/// Refusals are retried on the same terms as `http`.
fn http_raw(port: u16, req: &str, extra_hdrs: &str) -> (String, Vec<u8>) {
    let mut request = Vec::new();
    write!(
        request,
        "GET {req} HTTP/1.1\r\nHost: x\r\n{extra_hdrs}Connection: close\r\n\r\n"
    )
    .unwrap();
    let raw = self::raw(port, &request);
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => (
            String::from_utf8_lossy(&raw[..p]).to_string(),
            raw[p + 4..].to_vec(),
        ),
        None => (String::from_utf8_lossy(&raw).to_string(), Vec::new()),
    }
}

fn raw(port: u16, request: &[u8]) -> Vec<u8> {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match raw_once(port, request) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    let line = String::from_utf8_lossy(request)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    panic!("daemon on :{port} never answered {line:?}: {last}");
}

fn raw_once(port: u16, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(request)?;
    let mut out = Vec::new();
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
    let read = s.read_to_end(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out)
}

fn nzo_id(resp: &str) -> String {
    let i = resp.find("SABnzbd_nzo_").expect("nzo id in response");
    resp[i..].chars().take_while(|c| *c != '"').collect()
}

/// Single-file NZB XML from make_file_articles segments.
fn nzb_xml(name: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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

fn multipart(xml: &str) -> (String, Vec<u8>) {
    let boundary = "----libraryb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn launch(dir: &Path, srv: &MockServer) -> Daemon {
    launch_with_key(dir, srv, None).await
}

async fn launch_with_key(dir: &Path, srv: &MockServer, apikey: Option<&str>) -> Daemon {
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
    serve(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        // The daemon mints an API key on a genuinely first run (see
        // serve::first_run_apikey). These suites drive it keyless on purpose,
        // so they take the same deliberate opt-out an operator would.
        cmd.env("NZBFAST_OPEN", "1");
        cmd.env("NZBFAST_NO_ENRICH", "1")
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
            .arg("3")
            .arg("--library-cats")
            .arg("library,stream");
        if let Some(k) = apikey {
            cmd.arg("--apikey").arg(k);
        }
        cmd
    })
    .await
}

fn poll_history(port: u16, status: &str, tries: usize) -> Option<String> {
    poll_history_keyed(port, status, tries, "")
}

/// `key` is a raw query-string suffix, e.g. "&apikey=sesame".
fn poll_history_keyed(port: u16, status: &str, tries: usize, key: &str) -> Option<String> {
    for _ in 0..tries {
        let h = http(port, &format!("/api?mode=history&output=json{key}"), None);
        if h.contains(&format!("\"{status}\"")) {
            return Some(h);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn library_job_completes_without_downloading() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lib1-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(400_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("movie.mkv", &data, 40_000, "lib1", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let d = launch(&dir, &srv).await;
    let port = d.port;

    let xml = nzb_xml("movie.mkv", &segs);
    let served = srv.served.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let (ctype, body) = multipart(&xml);
        let r = http(
            port,
            "/api?mode=addfile&cat=library&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = nzo_id(&r);

        // Parks Completed fast (STAT sweep, not a download)…
        let h = poll_history(port, "Completed", 40).expect("library job never completed");
        assert!(h.contains("movie"), "{h}");
        // …and the mock never served a single BODY (preflight is STAT-only).
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "library check must not fetch article bodies"
        );

        // The .strm pointer for Jellyfin/Emby, with the on-demand URL -
        // carrying the per-job stream token that authorizes the trigger.
        let strm = dir2.join("complete/library/movie/movie.strm");
        let content = std::fs::read_to_string(&strm)
            .unwrap_or_else(|e| panic!("missing {}: {e}", strm.display()));
        let prefix = format!("http://127.0.0.1:{port}/stream/{id}?t=");
        assert!(
            content.starts_with(&prefix) && content.ends_with('\n'),
            "{content}"
        );
        assert!(
            content.trim_end().len() > prefix.len(),
            "empty stream token: {content}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_of_library_job_triggers_download() {
    // Store-mode rar'd mkv (the M11 fixture shape): the library check parks
    // it, then GET /stream/<id> kicks off the real download and must return
    // the movie's exact first bytes once the writers appear.
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-lib2-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(6_000_000, 7);
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 6_000_000, &inner[..2_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "movie.mkv",
                6_000_000,
                &inner[2_000_000..4_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 6_000_000, &inner[4_000_000..], true, false)],
            2,
        ),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("lib2v{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    let srv = MockServer::start(articles, Chaos::default()).await;
    let d = launch(&dir, &srv).await;
    let port = d.port;

    let served = srv.served.clone();
    let inner2 = inner.clone();
    tokio::task::spawn_blocking(move || {
        let (ctype, body) = multipart(&xml);
        let r = http(
            port,
            "/api?mode=addfile&cat=library&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = nzo_id(&r);
        poll_history(port, "Completed", 40).expect("library check never completed");
        assert_eq!(served.load(std::sync::atomic::Ordering::Relaxed), 0);

        // First play: the endpoint itself waits for the forced download's
        // writers, so a single request must come back 206 with real bytes.
        let (head, got) = http_raw(port, &format!("/stream/{id}"), "Range: bytes=0-99999\r\n");
        assert!(head.contains("206"), "{head}");
        assert_eq!(got.len(), 100_000, "range length");
        assert_eq!(&got[..], &inner2[..100_000], "streamed head bytes differ");
        assert!(
            served.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "no BODY fetched"
        );

        // The job re-parks Completed in history once the download finishes.
        poll_history(port, "Completed", 100).expect("forced download never completed");

        // Unknown ids 404 immediately.
        let (head, _) = http_raw(port, "/stream/SABnzbd_nzo_nope", "");
        assert!(head.contains("404"), "{head}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_stream_cannot_start_parked_job() {
    // With an apikey set, /stream/<id> on a parked library job is a state
    // mutation (force-start past a pause) and must be rejected without the
    // key or the per-job token; /m3u is the authenticated token mint.
    let dir = std::env::temp_dir().join(format!("nzbfast-lib4-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(400_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("movie.mkv", &data, 40_000, "lib4", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let d = launch_with_key(&dir, &srv, Some("sesame")).await;
    let port = d.port;

    let xml = nzb_xml("movie.mkv", &segs);
    let served = srv.served.clone();
    tokio::task::spawn_blocking(move || {
        let (ctype, body) = multipart(&xml);
        let r = http(
            port,
            "/api?mode=addfile&cat=library&output=json&apikey=sesame",
            Some((&ctype, &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = nzo_id(&r);
        poll_history_keyed(port, "Completed", 40, "&apikey=sesame")
            .expect("library job never completed");
        assert_eq!(served.load(std::sync::atomic::Ordering::Relaxed), 0);

        // Keyless + tokenless: 401, and the job must stay parked.
        let (head, _) = http_raw(port, &format!("/stream/{id}"), "");
        assert!(
            head.contains("401"),
            "unauthenticated /stream must be rejected: {head}"
        );
        // Wrong token: same.
        let (head, _) = http_raw(port, &format!("/stream/{id}?t=deadbeef"), "");
        assert!(
            head.contains("401"),
            "bad-token /stream must be rejected: {head}"
        );
        // State unchanged: still parked Completed in history, not queued,
        // and not a single article body fetched.
        let q = http(port, "/api?mode=queue&output=json&apikey=sesame", None);
        assert!(
            !q.contains(&id),
            "job must not be queued by unauthenticated /stream: {q}"
        );
        let h = http(port, "/api?mode=history&output=json&apikey=sesame", None);
        assert!(h.contains(&id) && h.contains("\"Completed\""), "{h}");
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "unauthenticated /stream must not start the download"
        );

        // /m3u without the key must not mint a token…
        let (head, _) = http_raw(port, &format!("/m3u/{id}"), "");
        assert!(
            head.contains("401"),
            "keyless /m3u must be rejected: {head}"
        );
        // …with it, the playlist carries the tokened stream URL.
        let (head, m3u) = http_raw(port, &format!("/m3u/{id}?apikey=sesame"), "");
        assert!(head.contains("200"), "{head}");
        let m3u = String::from_utf8_lossy(&m3u);
        let marker = format!("/stream/{id}?t=");
        let tpos = m3u
            .find(&marker)
            .unwrap_or_else(|| panic!("no tokened URL in {m3u}"));
        let tok: String = m3u[tpos + marker.len()..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        assert!(!tok.is_empty(), "empty token in {m3u}");

        // The tokened URL is the play trigger: fire it (the response only
        // arrives once writers appear, so poll the mock for the download
        // actually starting instead of waiting on it).
        let url = format!("/stream/{id}?t={tok}");
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(|| http_raw(port, &url, "Range: bytes=0-999\r\n"));
        });
        for _ in 0..100 {
            if served.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            served.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "tokened /stream never started the download"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn library_job_with_missing_articles_fails() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lib3-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(400_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("gone.mkv", &data, 40_000, "lib3", &mut articles);
    let chaos = Chaos {
        missing: segs.iter().map(|(id, _, _)| format!("<{id}>")).collect(),
        ..Chaos::default()
    };
    let srv = MockServer::start(articles, chaos).await;
    let d = launch(&dir, &srv).await;
    let port = d.port;

    let xml = nzb_xml("gone.mkv", &segs);
    tokio::task::spawn_blocking(move || {
        let (ctype, body) = multipart(&xml);
        let r = http(
            port,
            "/api?mode=addfile&cat=library&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let h = poll_history(port, "Failed", 40).expect("impossible job never parked Failed");
        assert!(h.contains("pre-flight"), "{h}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A download that has FINISHED is served from disk, not from the live
/// pipeline. Before this, /stream/<id> on a completed job waited 30 s for
/// writers that would never appear and then 404'd - so the wall's "play
/// the copy you have" could only open the file in the daemon's own
/// player, which a remote viewer never sees.
#[tokio::test(flavor = "multi_thread")]
async fn stream_of_a_finished_download_serves_it_from_disk() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-done-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(2_000_000, 11);
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 2_000_000, &inner[..1_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 2_000_000, &inner[1_000_000..], true, false)],
            1,
        ),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("d.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("done{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    let srv = MockServer::start(articles, Chaos::default()).await;
    let d = launch(&dir, &srv).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let (ctype, body) = multipart(&xml);
        // No category: an ordinary download, not a library entry.
        let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");
        let id = nzo_id(&r);
        poll_history(port, "Completed", 200).expect("download never completed");

        // Whole file: 200, exact bytes, from the output folder.
        let (head, got) = http_raw(port, &format!("/stream/{id}"), "");
        assert!(head.contains("200 OK"), "{head}");
        assert!(head.contains("Accept-Ranges: bytes"), "{head}");
        assert_eq!(got.len(), inner.len(), "served length");
        assert_eq!(got, inner, "served bytes differ from the download");

        // A player's seek: 206 with the right slice and Content-Range.
        let (head, got) = http_raw(port, &format!("/stream/{id}"), "Range: bytes=1000-1999\r\n");
        assert!(head.contains("206"), "{head}");
        assert!(
            head.contains(&format!("Content-Range: bytes 1000-1999/{}", inner.len())),
            "{head}"
        );
        assert_eq!(got, &inner[1000..2000], "range bytes differ");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
