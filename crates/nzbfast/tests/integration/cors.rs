//! §141 (issue #33): CORS on the SAB-compatible API.
//!
//! We sent no `Access-Control-*` header anywhere, so Firefox blocked the
//! NZB Unity extension's requests against us while SABnzbd on the same
//! box worked. Real SAB answers `Access-Control-Allow-Origin: *` on its
//! API, and §105.4's rule is that anything real SAB sends and we omit is
//! our bug - a client cannot tell a missing feature from a broken
//! daemon.
//!
//! These tests pin the whole shape end to end, over the real socket,
//! because that is the only place the headers exist: the status line and
//! the header block are exactly what the browser judges, and the unit
//! tests beside `cors_headers` cannot see either.
//!
//! Three properties, one per test:
//!
//!  1. the default is permissive and covers BOTH `/api` exits - the
//!     answer and the 403 refusal (a browser extension that cannot read
//!     "API Key Incorrect" reports a mistyped key as an unreachable
//!     daemon), and the preflight is answered above the key check;
//!  2. `cors_origin` narrows it to a named origin, and a stranger gets
//!     no header at all;
//!  3. the header stays OFF the routes that hand out a user's own files.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::Daemon;

const KEY: &str = "sekrit";

/// A whole response - status line, headers and body - because the
/// headers ARE the subject here.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    /// Header values are case-insensitive by NAME; a missing header and
    /// an empty one are different answers, so this returns an Option.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Send a hand-written request and keep everything that comes back.
///
/// Retried only when the daemon produced no byte at all: under a full
/// parallel run tiny_http can fail to spawn a worker thread and drop the
/// socket unread, which arrives as ECONNRESET. Any byte is an answer and
/// is judged as it came.
fn send(port: u16, request: &str) -> Reply {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match send_once(port, request) {
            Ok(r) => return r,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    let line = request.lines().next().unwrap_or("");
    panic!("daemon on :{port} never answered {line:?}: {last}");
}

fn send_once(port: u16, request: &str) -> std::io::Result<Reply> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    let read = s.read_to_end(&mut raw);
    if raw.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(Reply {
        status,
        headers,
        body: body.to_string(),
    })
}

/// A GET carrying the `Origin` a browser extension would stamp on it.
fn get_from(port: u16, path: &str, origin: Option<&str>) -> Reply {
    let o = origin
        .map(|o| format!("Origin: {o}\r\n"))
        .unwrap_or_default();
    send(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{o}\r\n"),
    )
}

/// Set a live setting through the SAB config surface.
fn set(port: u16, name: &str, value: &str) -> Reply {
    let enc: String = value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    get_from(
        port,
        &format!("/api?output=json&apikey={KEY}&mode=config&name={name}&value={enc}"),
        None,
    )
}

fn scratch(name: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-cors-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{}").unwrap();
    dir
}

fn serve(dir: &Path) -> Daemon {
    crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            .current_dir(dir)
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            // Loopback only: this suite needs no LAN reach, and binding
            // 0.0.0.0 raises a macOS firewall prompt for every freshly
            // built test binary.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg(KEY)
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"));
        cmd
    })
}

/// Out of the box the SAB API answers a browser exactly as SABnzbd does,
/// on every exit, and answers the preflight before asking for a key.
#[test]
fn the_sab_api_answers_cors_the_way_sabnzbd_does() {
    let dir = scratch("default");
    let d = serve(&dir);
    let ext = "moz-extension://11111111-2222-3333-4444-555555555555";

    // The answer to a real, authenticated call.
    let r = get_from(
        d.port,
        &format!("/api?output=json&apikey={KEY}&mode=version"),
        Some(ext),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.header("Access-Control-Allow-Origin"),
        Some("*"),
        "the SAB API answered no Access-Control-Allow-Origin - this IS \
         issue #33: headers {:?}",
        r.headers
    );
    // `*` is the same answer for everyone, so nothing may claim it
    // varies by Origin - a shared cache would have to re-fetch per
    // origin for no reason.
    assert_eq!(r.header("Vary"), None, "headers {:?}", r.headers);
    // Never with `*`: the pair is illegal, and our credential is an
    // explicit key rather than a cookie, so nothing wants it.
    assert_eq!(r.header("Access-Control-Allow-Credentials"), None);

    // The refusal too. Without the header here a browser extension
    // cannot read "API Key Incorrect" either, and a mistyped key
    // presents as an unreachable daemon.
    let r = get_from(
        d.port,
        "/api?output=json&apikey=wrong&mode=version",
        Some(ext),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    assert!(r.body.contains("API Key Incorrect"), "{}", r.body);
    assert_eq!(r.header("Access-Control-Allow-Origin"), Some("*"));

    // The preflight, which a browser sends WITHOUT credentials. A 403
    // here and Firefox never sends the real request at all.
    let r = send(
        d.port,
        &format!(
            "OPTIONS /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Origin: {ext}\r\nAccess-Control-Request-Method: POST\r\n\
             Access-Control-Request-Headers: x-api-key\r\n\r\n"
        ),
    );
    assert_eq!(
        r.status, 204,
        "preflight was not answered: {} {:?}",
        r.status, r.headers
    );
    assert_eq!(r.header("Access-Control-Allow-Origin"), Some("*"));
    let methods = r.header("Access-Control-Allow-Methods").unwrap_or_default();
    assert!(methods.contains("POST"), "{methods}");
    assert!(methods.contains("GET"), "{methods}");
    let allowed = r
        .header("Access-Control-Allow-Headers")
        .unwrap_or_default()
        .to_ascii_lowercase();
    // The three ways a key reaches us off the query string, plus the
    // content type that makes a browser preflight in the first place.
    for h in ["x-api-key", "authorization", "content-type"] {
        assert!(allowed.contains(h), "{h} not allowed: {allowed}");
    }
    assert!(r.header("Access-Control-Max-Age").is_some());

    // A trailing slash is the same route (issue #22), and the preflight
    // is the one request a client cannot retry without one.
    let r = get_from(
        d.port,
        &format!("/api/?output=json&apikey={KEY}&mode=version"),
        Some(ext),
    );
    assert_eq!(r.header("Access-Control-Allow-Origin"), Some("*"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// `cors_origin` narrows the default for anyone who wants it tighter
/// than SAB's, and the narrowing is real: a stranger gets nothing.
#[test]
fn cors_origin_restricts_who_may_read_the_api() {
    let dir = scratch("restrict");
    let d = serve(&dir);
    let mine = "https://nzb.example.com";
    let theirs = "https://evil.example.net";

    // The default is what SABnzbd sends, and it is what get_config says.
    let r = get_from(
        d.port,
        &format!("/api?output=json&apikey={KEY}&mode=get_config"),
        None,
    );
    assert!(
        r.body.contains("\"cors_origin\":\"*\""),
        "get_config does not report the default: {}",
        r.body
    );

    // Narrow it to one origin.
    let r = set(d.port, "cors_origin", mine);
    assert!(r.body.contains("\"status\":true"), "{}", r.body);

    // The named origin is answered - with its own name, never `*`.
    let r = get_from(
        d.port,
        &format!("/api?output=json&apikey={KEY}&mode=version"),
        Some(mine),
    );
    assert_eq!(r.header("Access-Control-Allow-Origin"), Some(mine));
    // The answer now depends on the request's Origin, so a shared cache
    // must not serve one origin's permission to another.
    assert_eq!(r.header("Vary"), Some("Origin"));

    // Anyone else gets no header, which is what makes the browser
    // refuse to hand them the body.
    let r = get_from(
        d.port,
        &format!("/api?output=json&apikey={KEY}&mode=version"),
        Some(theirs),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.header("Access-Control-Allow-Origin"), None);
    assert_eq!(r.header("Vary"), Some("Origin"));

    // ...including at the preflight, so the real request is never sent.
    let r = send(
        d.port,
        &format!(
            "OPTIONS /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Origin: {theirs}\r\nAccess-Control-Request-Method: POST\r\n\r\n"
        ),
    );
    assert_eq!(r.status, 204);
    assert_eq!(r.header("Access-Control-Allow-Origin"), None);

    // A list is accepted, and every member of it is answered.
    let both = format!("{mine},{theirs}");
    assert!(
        set(d.port, "cors_origin", &both)
            .body
            .contains("\"status\":true")
    );
    for o in [mine, theirs] {
        let r = get_from(
            d.port,
            &format!("/api?output=json&apikey={KEY}&mode=version"),
            Some(o),
        );
        assert_eq!(r.header("Access-Control-Allow-Origin"), Some(o));
    }

    // Empty means no header at all - the state the daemon shipped in
    // before this existed, kept reachable on purpose.
    assert!(
        set(d.port, "cors_origin", "")
            .body
            .contains("\"status\":true")
    );
    let r = get_from(
        d.port,
        &format!("/api?output=json&apikey={KEY}&mode=version"),
        Some(mine),
    );
    assert_eq!(r.header("Access-Control-Allow-Origin"), None);
    assert_eq!(r.header("Vary"), None);

    // A value that could smuggle a second header into the response is
    // refused at the setting, not at the emit site: tiny_http header
    // values are ASCII and CR/LF are ASCII too.
    let r = set(d.port, "cors_origin", "https://x.example\r\nX-Evil: 1");
    assert!(r.body.contains("\"status\":false"), "{}", r.body);
    // ...and the refusal left the previous value alone.
    let r = get_from(
        d.port,
        &format!("/api?output=json&apikey={KEY}&mode=get_config"),
        None,
    );
    assert!(r.body.contains("\"cors_origin\":\"\""), "{}", r.body);

    // Restored across a restart, empty included: an empty cors_origin is
    // a deliberate setting, not a missing one.
    let _log = d.stop();
    let d = serve(&dir);
    let r = get_from(
        d.port,
        &format!("/api?output=json&apikey={KEY}&mode=get_config"),
        None,
    );
    assert!(
        r.body.contains("\"cors_origin\":\"\""),
        "cors_origin reverted across a restart: {}",
        r.body
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The header rides the SAB surface and nothing else.
///
/// CORS is not the authentication layer and none of these are readable
/// without a key anyway - but they hand out a user's own files and their
/// own spooled NZBs, they are ours rather than SABnzbd's, and no
/// extension asks for them from a page. Nothing here needs the header,
/// so nothing here gets it.
#[test]
fn the_header_stays_off_everything_outside_the_sab_surface() {
    let dir = scratch("scope");
    let d = serve(&dir);
    let ext = "moz-extension://11111111-2222-3333-4444-555555555555";

    for path in [
        "/",
        &format!("/jobnzb/nzo_missing?apikey={KEY}"),
        &format!("/m3u/nzo_missing?apikey={KEY}"),
        &format!("/stream/nzo_missing?apikey={KEY}"),
    ] {
        let r = get_from(d.port, path, Some(ext));
        assert_eq!(
            r.header("Access-Control-Allow-Origin"),
            None,
            "{path} answered a CORS header: {:?}",
            r.headers
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
