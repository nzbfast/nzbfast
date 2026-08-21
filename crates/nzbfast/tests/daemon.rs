//! Daemon API test (M5 gate): a Sonarr-style cycle - version probe,
//! addfile upload, queue polling, history with final storage path - all
//! against the real binary + mock NNTP servers.

// What each credential may do - full key, add-only nzbkey, bootstrap
// hatch (sibling dir, size gate).
mod daemon_authkey;
// §123 chip-6 fault x lifecycle cross product (sibling dir, size gate).
mod daemon_chip6;
// Queue-finished actions: the once-per-drain edge and its refusals
// (sibling dir, size gate).
mod daemon_finish;
// §138 opt-in give-up legs (sibling dir, size gate).
mod daemon_health;
// The four NZBGet delete verbs and the prefetch-delete leg (sibling
// dir, size gate).
mod daemon_delete;
// A finished AND a failed job must hold no output handles (sibling dir,
// size gate).
mod daemon_handles;
// §129 4a pre-queue hook legs (sibling dir, size gate).
mod daemon_hooks;
// §154 zero-configured-servers hold (sibling dir, size gate).
mod daemon_noservers;
// Passworded archives end to end (sibling dir, size gate).
mod daemon_password;
// §100 retry-without-refetch after a failed unpack (sibling dir, gate).
mod daemon_retry;
// Passwords attached mid-download, and the prefer_external_unrar switch:
// moved to a child module by TODO 106. Declared here, so they still run in
// this binary against these fixtures.
mod daemon_unpackroute;
// §76 fast-job media chip regression (sibling dir, size gate).
mod daemon_mediafast;
mod playback_contract;
// §73 phase 3 remux endpoint (sibling dir, size gate).
mod preview_media;
mod scratch;
// M11 playback rigs (sibling dir, size gate).
mod stream_chaos;
mod stream_live;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

/// OS-assigned free port for a daemon under test. The old pid-derived
/// scheme (`BASE + pid % M`, mixed moduli) collided for whole pid windows
/// - e.g. pid ∈ [80000,81000) gave two tests the same port, killing
/// whichever daemon bound second - and could also land on the ephemeral
/// range the suites' own client sockets draw from.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Response body of a request to the daemon (headers stripped).
///
/// A connection REFUSED before it produced a single byte is retried. That
/// is not the same as tolerating a bad answer: tiny_http's honest reply
/// when it cannot start a thread for a new connection is to drop the
/// socket unread, and with our request still in its receive buffer the
/// kernel turns that into an RST - which arrives here as ECONNRESET. This
/// suite runs 24 tests in parallel, each with a full daemon behind it, so
/// `thread::Builder::spawn` really does hit EAGAIN, and a test then failed
/// on a refusal to serve rather than on anything it asserts. Once a byte
/// has come back it is an answer, and it is returned (or fails) exactly as
/// it arrived - a truncated response must never be retried away.
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

/// A hand-written request whose response headers are KEPT - /stream,
/// /m3u, /watch and JSON-RPC, where the test reads the status line or a
/// binary body itself. Refusals are retried on the same terms as `http`.
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

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        // ...and reap it. kill() alone leaves a zombie holding its pid
        // for the rest of the binary's run, and this suite starts two
        // dozen daemons.
        let _ = self.0.wait();
    }
}

/// A daemon under test: killed and reaped on drop, with its stdout and
/// stderr captured to `log` so the test can read what it printed.
struct Daemon {
    _child: KillOnDrop,
    port: u16,
    log: PathBuf,
}

impl Daemon {
    /// The child's pid, for the tests that must ask the OS about the
    /// daemon rather than the daemon about itself.
    fn pid(&self) -> u32 {
        self._child.0.id()
    }
}

/// Launch a daemon under `dir` and return once OUR daemon is serving.
///
/// `build` is handed the port to serve on and returns the fully
/// configured command; it may be called again on a fresh port, so it must
/// not consume anything.
async fn serve(dir: &Path, build: impl Fn(u16) -> Command) -> Daemon {
    for attempt in 0..3 {
        let port = free_port();
        let log = dir.join(format!("daemon-{port}.log"));
        let out = std::fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = build(port);
        // Central log isolation for every case in this file. These tests
        // assert on - and synchronize on - the daemon's own INFO markers,
        // and `logging.rs` honours RUST_LOG, so a shell (or CI runner) with
        // RUST_LOG=warn exported filtered the markers away: three cases
        // completed every functional assertion and then failed on the
        // marker, and the prefetch and stream cases, which use a marker as
        // a barrier, timed out. Five red tests, no product defect (Codex
        // sweep 12 Aug). `info` IS the default filter, so this pins the
        // behaviour the tests were written against rather than changing it -
        // the same isolation tests/watch_dedupe.rs already applies per case.
        cmd.env("NZBFAST_LOG", "info").env_remove("RUST_LOG");
        // Central disk-guard isolation, for the same reason as the log
        // filter above: `min_free` defaults to 2 GB and the runner it is
        // measured against is the HOST's, not anything this suite writes.
        // A CI box that had run itself down to 1.3 GB free (nightly,
        // 15 Aug 2026) therefore held EVERY job in the queue before it
        // ever started, and 50-odd cases each spent their full poll
        // budget waiting for a download that was never going to be
        // picked - dozens of unrelated 30 s timeouts with one cause, and
        // nothing in any panic message naming disk. The fixtures here
        // are kilobytes; the floor is not this suite's subject, so turn
        // it off and let the one case that IS about it say so.
        // `disk_guard_holds_queue` passes its own `--min-free`, and any
        // case that does keeps it - this only supplies the default.
        if !cmd
            .get_args()
            .any(|a| a.to_string_lossy().starts_with("--min-free"))
        {
            cmd.arg("--min-free").arg("0");
        }
        cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
        let child = KillOnDrop(cmd.spawn().unwrap());
        let logfile = log.clone();
        // The readiness wait blocks; keep it off the runtime's workers,
        // where this test's own mock server is running.
        let (child, ready) = tokio::task::spawn_blocking(move || {
            let mut child = child;
            let ready = wait_ready(&mut child, port, &logfile);
            (child, ready)
        })
        .await
        .unwrap();
        if ready {
            return Daemon {
                _child: child,
                port,
                log,
            };
        }
        // The daemon exited instead of binding: `free_port()` handed
        // :port to a parallel test between our bind(:0) and the daemon's
        // bind, and that test's daemon won it. Try a fresh port.
        let tail = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(
            attempt < 2,
            "daemon exited without binding :{port}\n--- log ---\n{tail}"
        );
    }
    unreachable!()
}

/// Wait for OUR daemon's own listener banner, not for "something answers
/// on :port". A bare connect cannot tell the two apart, and under a full
/// parallel run they diverge: `free_port()` can hand :port to a second
/// test between our bind(:0) and our daemon's bind, that test's daemon
/// wins the port, ours exits, and a plain connect then succeeds against
/// the OTHER daemon. The test would run against a stranger and, when that
/// stranger's owner finished and killed it, fail mid-request with
/// ConnectionReset. The banner is read from this daemon's own log, so it
/// can only be ours. (The bind itself happens near the top of startup -
/// see serve()'s note beside spool_dir - so the banner, printed once
/// startup is genuinely finished, is the readiness signal, not the bind.)
///
/// False means the child exited first (the port race above); a genuine
/// hang panics with the log.
fn wait_ready(child: &mut KillOnDrop, port: u16, log: &Path) -> bool {
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if std::fs::read_to_string(log)
            .unwrap_or_default()
            .contains(&banner)
            && TcpStream::connect(("127.0.0.1", port)).is_ok()
        {
            return true;
        }
        if child.0.try_wait().ok().flatten().is_some() {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let tail = std::fs::read_to_string(log).unwrap_or_default();
    panic!("daemon never came up on :{port}\n--- log ---\n{tail}");
}

/// Seed the settings.json beside `cfg` so the daemon this test spawns
/// deletes permanently instead of moving to the Trash.
///
/// `smart::TRASH` defaults ON everywhere except a `cfg(test)` build, and
/// these suites drive the REAL binary: the child is a normal build, so the
/// default it picks up is the user-facing one. Every fixture its cleanup
/// sweeps or its watch poller delete therefore landed in the DEVELOPER's
/// own ~/.Trash, once per `cargo test` run, with nothing to tell them
/// apart from files they deleted themselves.
///
/// settings.json is the only lever that reaches the child - there is no
/// flag for this - and the daemon applies the key on startup (see serve's
/// `delete_to_trash` arm). Call it after writing the config and before
/// `serve`, for any daemon that will delete a fixture. Merges rather than
/// overwrites, so a test that seeds settings of its own keeps them.
///
/// The file existing at all is itself a signal the daemon reads: a
/// settings.json carrying anything but the wizard's own answers means
/// "existing install" (serve::settings_beyond_setup_answers), which flips
/// the two rename-punctuation defaults to the pre-upgrade shape. So on a
/// first run - no spool beside the config yet - the fresh-install values
/// are pinned back explicitly, and this helper changes exactly the one
/// behaviour it is for. A second launch against the same directory has a
/// spool, so the daemon reaches the same verdict with or without us.
fn delete_without_the_trash(cfg: &Path) {
    let path = cfg.with_file_name("settings.json");
    let mut saved = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    saved.insert(
        "delete_to_trash".to_string(),
        serde_json::Value::Bool(false),
    );
    if !cfg.with_file_name(".spool").exists() {
        for key in ["rename_year_parens", "rename_quality_brackets"] {
            saved.entry(key).or_insert(serde_json::Value::Bool(false));
        }
    }
    std::fs::write(&path, serde_json::Value::Object(saved).to_string()).unwrap();
}

/// Why the post-proc hook produced nothing, gathered at the moment of
/// failure. `ScratchDir` removes the whole directory on unwind, so a bare
/// "hook never ran" leaves NOTHING to post-mortem - the daemon log, the
/// script and hook.out are all gone by the time the panic is printed, and
/// answering it means re-running with the removal disabled.
///
/// The three questions, in the order they discriminate:
///
///  - Did the daemon reach `run_script`? It warns on every non-success -
///    a launch failure (`failed to launch`), a non-zero exit, and the
///    deadline kill - so the absence of any `[script]` line means the
///    hook was never invoked at all (resolve_scripts said none, or the
///    post-job hooks never fired) rather than invoked and broken. The
///    success line is `info`, which the default level drops.
///  - Is the script still on disk and executable? A hook the daemon
///    cannot exec is the one failure mode that leaves the download
///    itself, and every other assert in this test, perfectly healthy.
///  - What, if anything, reached hook.out - absent, empty (created and
///    truncated by the redirect, never written) or partial.
fn hook_diag(hook: &Path, dir: &Path, port: u16) -> String {
    let log = std::fs::read_to_string(dir.join(format!("daemon-{port}.log"))).unwrap_or_default();
    let script: Vec<&str> = log.lines().filter(|l| l.contains("[script]")).collect();
    let script = if script.is_empty() {
        "(none - the daemon never logged a script line)".to_string()
    } else {
        script.join("\n")
    };
    let meta = match std::fs::metadata(hook) {
        Ok(m) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                format!("{} bytes, mode {:o}", m.len(), m.permissions().mode())
            }
            #[cfg(not(unix))]
            {
                format!("{} bytes", m.len())
            }
        }
        Err(e) => format!("MISSING: {e}"),
    };
    let out = match std::fs::read_to_string(dir.join("hook.out")) {
        Ok(s) if s.is_empty() => "(exists, empty)".to_string(),
        Ok(s) => s,
        Err(e) => format!("(absent: {e})"),
    };
    let tail: Vec<&str> = log.lines().rev().take(40).collect();
    format!(
        "\n--- script lines ---\n{script}\n--- {} ---\n{meta}\n--- hook.out ---\n{out}\n--- daemon log tail ---\n{}",
        hook.display(),
        tail.into_iter().rev().collect::<Vec<_>>().join("\n"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn sonarr_style_cycle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-daemon-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Content on the mock server.
    let data = payload(400_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("episode.bin", &data, 40_000, "ep", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    // NZB to upload.
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;episode.bin&quot; yEnc (1/11)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    // Daemon config + launch.
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
    // Post-proc hook (M14d): records SAB-contract args + env for assert.
    //
    // Written in the host's own script language, because `run_script` spawns
    // the file directly and a `#!/bin/sh` shebang means nothing on Windows -
    // there is no /bin/sh to honour it, so the hook simply never ran and this
    // suite reported "hook never ran" the first time it was run there. Rust
    // CAN spawn a .cmd (std applies cmd.exe's own argument escaping to
    // .bat/.cmd since the BatBadBut fix), so the Windows leg exercises the
    // real post-processing contract rather than skipping it.
    #[cfg(unix)]
    let hook = {
        let hook = dir.join("hook.sh");
        std::fs::write(
            &hook,
            "#!/bin/sh\nprintf 'args:%s|%s|%s|%s\\nenv:%s|%s|%s\\n' \"$1\" \"$3\" \"$5\" \"$7\" \"$SAB_PP_STATUS\" \"$SAB_FINAL_NAME\" \"$SAB_CAT\" > \"$(dirname \"$0\")/hook.out\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        hook
    };
    #[cfg(windows)]
    let hook = {
        let hook = dir.join("hook.cmd");
        // `%~dp0` carries its own trailing separator. `|` is a pipe to cmd
        // even inside a parenthesised block, hence `^|`, and `%~1` strips the
        // quotes Windows leaves around a path argument containing spaces.
        std::fs::write(
            &hook,
            "@echo off\r\n> \"%~dp0hook.out\" (\r\n\
             echo args:%~1^|%~3^|%~5^|%~7\r\n\
             echo env:%SAB_PP_STATUS%^|%SAB_FINAL_NAME%^|%SAB_CAT%\r\n\
             )\r\n",
        )
        .unwrap();
        hook
    };
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--script")
            .arg(&hook)
            .arg("--connections")
            .arg("3");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    let hook2 = hook.clone();
    tokio::task::spawn_blocking(move || {
        // Bad API key rejected.
        let r = http(port, "/api?mode=version&apikey=wrong&output=json", None);
        assert!(r.contains("API Key Incorrect"), "{r}");
        // Version probe (Sonarr's connection test).
        let r = http(port, "/api?mode=version&apikey=sekrit&output=json", None);
        assert!(r.contains("version"), "{r}");
        // KEYLESS mode=version is answered on a keyed daemon (SAB parity).
        // The container HEALTHCHECK and the tray/.app probe both curl it
        // with no key; requiring one meant every keyed Docker install
        // logged its own healthcheck as a rejected key from loopback,
        // forever. Only the truly keyless call passes - the wrong-key
        // rejection above is the other half of this contract.
        let r = http(port, "/api?mode=version&output=json", None);
        assert!(r.contains("\"nzbfast\""), "keyless version probe refused: {r}");
        assert!(!r.contains("API Key"), "keyless version probe refused: {r}");
        // ...but keyless anything-else is still refused, with the
        // no-key phrasing the *arrs match on.
        let r = http(port, "/api?mode=queue&output=json", None);
        assert!(r.contains("API Key Required"), "{r}");
        // Issue #22: SABnzbd answers `/api/` exactly as it answers `/api`,
        // and clients written against "the SABnzbd API" lean on that -
        // Homepage's sabnzbd widget appends the slash and got our flat
        // 404, which reads as a broken API rather than a picky one. The
        // 404 body is the bare word nzbfast, so these assert on the
        // payload rather than on the product name.
        let r = http(port, "/api/?mode=version&output=json", None);
        assert!(r.contains("version"), "trailing slash 404'd the SAB facade: {r}");
        let r = http(port, "/api/?mode=queue&apikey=sekrit&output=json", None);
        assert!(
            r.contains("queue") && !r.contains("API Key"),
            "trailing slash broke an authenticated call: {r}"
        );
        // The same miss hit the newznab facade, i.e. an *arr pointing an
        // indexer here rather than a download client. Caps and the
        // indexer-off refusal are both XML, so this pins the ROUTE
        // without depending on whether the index is switched on.
        // Slim builds compile the facade out entirely, so the route
        // check only exists with the indexer.
        #[cfg(feature = "indexer")]
        {
            let r = http(port, "/newznab/api/?t=caps&apikey=sekrit", None);
            assert!(
                r.contains("<?xml"),
                "trailing slash 404'd the newznab facade: {r}"
            );
        }
        // SAB-compat: browser addons (NZBDonkey, NZB Unity) send mode and
        // apikey as POST form fields with an EMPTY query string. Both form
        // encodings must authenticate - these used to log "[auth] rejected
        // key for api" because only the query string was parsed.
        let r = http(
            port,
            "/api",
            Some((
                "application/x-www-form-urlencoded",
                b"mode=version&apikey=sekrit&output=json".as_slice(),
            )),
        );
        assert!(r.contains("version"), "urlencoded form auth failed: {r}");
        let fb = "----fieldsboundary";
        let mut fbody = Vec::new();
        for (n, v) in [("mode", "queue"), ("apikey", "sekrit"), ("output", "json")] {
            fbody.extend_from_slice(
                format!(
                    "--{fb}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n"
                )
                .as_bytes(),
            );
        }
        fbody.extend_from_slice(format!("--{fb}--\r\n").as_bytes());
        let fctype = format!("multipart/form-data; boundary={fb}");
        let r = http(port, "/api", Some((&fctype, &fbody)));
        assert!(!r.contains("API Key"), "multipart form auth failed: {r}");
        assert!(r.contains("queue"), "multipart form mode ignored: {r}");
        // The query still wins on conflict: a wrong key in the body must
        // not override a valid one in the query.
        let r = http(
            port,
            "/api?mode=version&apikey=sekrit&output=json",
            Some((
                "application/x-www-form-urlencoded",
                b"apikey=wrong".as_slice(),
            )),
        );
        assert!(r.contains("version"), "query key must win: {r}");
        // The form-shaped pre-read above DRAINS the body - a handler that
        // then reads the socket again gets nothing. server_test used to do
        // exactly that, so `curl -d '{json}'` (curl's default content type
        // is form-urlencoded) always tested a Null body and answered
        // "server needs a host" no matter what was sent. Handlers must
        // consume the drained copy (api_body) instead. The listener drops
        // every connection at accept, so a SEEN body fails fast with a
        // refusal classification; a LOST body never dials at all.
        let nntp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let nntp_port = nntp.local_addr().unwrap().port();
        std::thread::spawn(move || for _ in nntp.incoming() {});
        let body = format!(
            r#"{{"server": {{"host": "127.0.0.1", "port": {nntp_port}, "tls": false, "connections": 1}}}}"#
        );
        let r = http(
            port,
            "/api?mode=server_test&apikey=sekrit&output=json",
            Some(("application/x-www-form-urlencoded", body.as_bytes())),
        );
        assert!(
            !r.contains("server needs a host"),
            "form-encoded POST body was drained before server_test read it: {r}"
        );
        assert!(
            r.contains("refusal"),
            "server_test never dialed the host given in the body: {r}"
        );
        // Issue #4: the key may ride a header instead of the query string
        // (X-Api-Key, or Authorization: Bearer), which keeps it out of
        // reverse-proxy access logs - the dashboard now sends it this way.
        let hget = |path: &str, hdr: &str| {
            let req =
                format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{hdr}\r\n\r\n");
            let out = raw(port, req.as_bytes());
            String::from_utf8_lossy(&out)
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("")
                .to_string()
        };
        let r = hget("/api?mode=queue&output=json", "X-Api-Key: sekrit");
        assert!(
            r.contains("queue") && !r.contains("API Key"),
            "X-Api-Key header refused: {r}"
        );
        let r = hget("/api?mode=queue&output=json", "Authorization: Bearer sekrit");
        assert!(
            r.contains("queue") && !r.contains("API Key"),
            "Bearer header refused: {r}"
        );
        // RFC 7235 makes the scheme token case-insensitive, and an auth
        // proxy that normalizes headers sends BEARER.
        let r = hget("/api?mode=queue&output=json", "Authorization: BEARER sekrit");
        assert!(
            r.contains("queue") && !r.contains("API Key"),
            "uppercase Bearer refused: {r}"
        );
        let r = hget("/api?mode=queue&output=json", "X-Api-Key: wrong");
        assert!(r.contains("API Key Incorrect"), "wrong header key accepted: {r}");
        // An empty multipart boundary is not a form. `boundary=` with
        // nothing after it makes the delimiter `--`, so a body of
        // hyphens used to split once every two bytes into a vector
        // holding a fat pointer per segment - allocated BEFORE auth,
        // and outside the body budget that bounds the read. The
        // request must be answered like any other malformed one, and
        // the daemon must still be serving afterwards.
        let junk = b"--".repeat(512 * 1024); // 1 MiB of delimiters
        let r = http(
            port,
            "/api?mode=version&output=json",
            Some(("multipart/form-data; boundary=", junk.as_slice())),
        );
        assert!(
            r.contains("\"nzbfast\""),
            "empty-boundary POST was not answered: {r}"
        );
        let r = http(port, "/api?mode=version&apikey=sekrit&output=json", None);
        assert!(r.contains("version"), "daemon unhealthy after the flood: {r}");
        // The query still wins on conflict, same rule as the body merge.
        let r = hget(
            "/api?mode=version&apikey=sekrit&output=json",
            "X-Api-Key: wrong",
        );
        assert!(r.contains("version"), "query key must win over header: {r}");
        let r = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(r.contains("complete_dir"), "{r}");

        // addfile (multipart, category tv).
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"episode.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&cat=tv&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("nzo_ids"), "{r}");
        assert!(r.contains("\"status\":true"), "{r}");

        // Poll until it lands in history as Completed.
        let mut done = false;
        for _ in 0..100 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                assert!(h.contains("episode"), "{h}");
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "download never completed");

        // Payload extracted to the category dir, byte-identical.
        let out = dir2.join("complete/tv/episode/episode.bin");
        assert!(out.exists(), "output missing at {}", out.display());

        // Post-proc hook ran with the SAB contract (async - poll briefly).
        //
        // Poll for the CONTENT, not for the file. The hook redirects with
        // `> hook.out`, and the shell creates/truncates that file before
        // printf writes a byte into it - so `exists()` goes true while the
        // file is still empty. On a loaded machine (every test binary in
        // parallel) the scheduler fits the whole poll into that window and
        // the read returns "", which is the §16i flake: it failed on the
        // first assert with an empty record, never on "hook never ran".
        // `env:` is the second of the two printf lines, so seeing it means
        // the write finished.
        //
        // The five-second budget is DELIBERATELY left where it is, and
        // it is no longer even close: the daemon now finishes the
        // post-processing script BEFORE `park` files the job into
        // history, so the "Completed" observed above already implies
        // the write this loop is waiting for, and only the shell's own
        // create-then-write window is left.
        //
        // It did not always. The hook used to be dispatched to
        // `spawn_blocking` while `park` filed the row anyway, with
        // nothing ordering the two - 105-313 ms of daylight over 80
        // runs at 20-way parallelism, and nothing bounding it on a
        // busier box - and that race is
        // where this case's "hook never ran" intermittent came from
        // (16 Aug 2026). Widening the margin was the obvious reflex and
        // would have hidden a contract the *arrs actually rely on:
        // Sonarr imports on the word Completed, and a pp-script is the
        // step most likely to still be moving the payload. The
        // ordering is pinned directly, on a script that sleeps, by
        // `daemon_hooks::the_post_processing_script_finishes_before_history_says_completed`.
        //
        // So the rule that produced that fix still stands for whatever
        // comes next: a margin widened without a diagnosis has buried
        // three real product bugs in this suite now. `hook_diag` below
        // is the alternative - make the next failure say WHY, then
        // widen only what the answer justifies.
        let hook_out = dir2.join("hook.out");
        let mut rec = String::new();
        for _ in 0..50 {
            rec = std::fs::read_to_string(&hook_out).unwrap_or_default();
            if rec.contains("env:") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            !rec.is_empty(),
            "hook never ran{}",
            hook_diag(&hook2, &dir2, port)
        );
        assert!(rec.contains("|episode|tv|0"), "{rec}"); // clean name, cat, pp=OK
        assert!(rec.contains("env:0|episode|tv"), "{rec}");
        // $1 final dir, separator-normalised: the daemon hands the script a
        // NATIVE path, so this is "complete\\tv\\episode" on Windows.
        assert!(rec.replace('\\', "/").contains("complete/tv/episode"), "{rec}");
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/tv/episode/episode.bin")).unwrap(),
        data
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Live repro 2026-07-20 (Seinfeld S08E05, 12,109 segments): a plain
/// single-file NZB with SYNTHESIZED segment numbering - the NZB's
/// "segment 1" is not the yEnc offset-0 article; the real offset-0 sits
/// arbitrarily deep in the queue (here: dead last). Pre-fix, every
/// decoded span piled into unclassified-slot holds for the whole run:
/// no data file on disk, stats files[] empty, nothing journaled. The
/// per-slot spill must flip the slot Plain mid-download, so the file
/// appears on disk long before the last article, and the job completes
/// byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn scrambled_segment_numbering_single_file() {
    let dir = std::env::temp_dir().join(format!("nzbfast-scramble-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // 12 MB plain file; --mem-limit 64M puts the per-slot spill budget at
    // ~7.2 MB (holds_cap 28.8 MB / 4), so the scramble trips it mid-run.
    let data = payload(12_000_000, 6);
    let mut articles = HashMap::new();
    let segs = make_file_articles("video.bin", &data, 40_000, "sc", &mut articles);
    let total_arts = segs.len();
    // Slow the mock slightly so the download is long enough to observe.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 5,
            ..Chaos::default()
        },
    )
    .await;

    // Synthesized numbering: NZB order is scrambled, part 1 (the yEnc
    // offset-0 article) goes LAST, and the <segment number=> attributes
    // are renumbered 1..N in the new order - numbering and subject lie,
    // exactly like the live post (obfuscated subject: no filename hint).
    let mut order: Vec<usize> = (1..total_arts).collect();
    let mut state = 0x5eed_u64;
    for i in (1..order.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        order.swap(i, (state >> 33) as usize % (i + 1));
    }
    order.push(0); // offset-0 article dead last
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"29a1f0b3c4d5e6f7 [1/1] yEnc\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (pos, &si) in order.iter().enumerate() {
        let (id, bytes, _) = &segs[si];
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{}\">{id}</segment>\n",
            pos + 1
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--mem-limit")
            .arg("64M")
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
            .arg("3");
        c
    })
    .await;
    let port = d.port;

    let served = srv.served.clone();
    let body_log = srv.body_log.clone();
    let out_root = dir.join("complete");
    let find_video = move |root: &std::path::Path| -> Option<std::path::PathBuf> {
        fn walk(d: &std::path::Path, out: &mut Option<std::path::PathBuf>) {
            let Ok(rd) = std::fs::read_dir(d) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.file_name().is_some_and(|n| n == "video.bin") {
                    *out = Some(p);
                }
            }
        }
        let mut found = None;
        walk(root, &mut found);
        found
    };

    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"scrambled.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
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
        assert!(r.contains("\"status\":true"), "{r}");

        // THE regression assertion: the data file must hit the disk while
        // the download is still fetching (spill fired), not only at the
        // end-of-run settle. Record how many articles the mock had served
        // when the file first appeared.
        let mut served_at_file: Option<u64> = None;
        let mut done = false;
        for _ in 0..1200 {
            if served_at_file.is_none() && find_video(&out_root).is_some() {
                served_at_file = Some(served.load(std::sync::atomic::Ordering::Relaxed));
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(done, "download never completed");
        let at = served_at_file.expect("video.bin never appeared on disk");
        assert!(
            at + 10 < total_arts as u64,
            "file only appeared at settle ({at}/{total_arts} articles served) - \
             the unclassified slot never spilled"
        );

        // Scramble sanity: the offset-0 article really was fetched late -
        // otherwise this test isn't reproducing synthesized numbering.
        let log = body_log.lock().unwrap();
        let pos = log
            .iter()
            .position(|id| id == "<sc-1@mock>")
            .expect("offset-0 article never fetched");
        assert!(
            pos > log.len() / 2,
            "offset-0 article fetched at {pos}/{} - scramble ineffective",
            log.len()
        );


        find_video(&out_root).expect("output file vanished after completion")
    })
    .await
    .map(|out| assert_eq!(std::fs::read(&out).unwrap(), data, "output not byte-identical"))
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14a/b: the extended SABnzbd facade - two-tier keys, priorities
/// (incl. Force-runs-while-paused and add-paused), park-to-history,
/// retry, failed_only, pagination, del_files.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_priorities_and_retry() {
    let dir = std::env::temp_dir().join(format!("nzbfast-facade-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("good.bin", &data, 40_000, "gd", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };
    let good_xml = nzb_for("good.bin", &segs);
    // Articles that don't exist on the server → the job must fail and park.
    let ghost_segs: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("ghost{n}@x"), 40_000, n))
        .collect();
    let bad_xml = nzb_for("bad.bin", &ghost_segs);

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--nzbkey")
            .arg("addonly")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, extra: &str| -> String {
            let boundary = "----facadeb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                &format!("/api?mode=addfile&output=json{extra}"),
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll_history = |pred: &dyn Fn(&str) -> bool, what: &str| {
            for _ in 0..150 {
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&h) {
                    return h;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // Two-tier keys: the NZB key may add but not read.
        let r = http(port, "/api?mode=queue&apikey=addonly&output=json", None);
        assert!(r.contains("API Key Incorrect"), "{r}");
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        assert!(r.contains("\"tv\""), "{r}");

        // Pause the whole queue, then add: bad (normal prio, via NZB key),
        // good (Force via priority change) - Force must run while paused.
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        let bad_id = upload(&bad_xml, "&apikey=addonly");
        let good_id = upload(&good_xml, "&apikey=sekrit&cat=tv");
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={good_id}&value2=2&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let h = poll_history(&|h: &str| h.contains("Completed"), "force job while paused");
        assert!(h.contains(&good_id), "{h}");
        // The bad job must still be queued: the queue is paused.
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains(&bad_id), "{q}");
        assert!(q.contains("\"priority\":\"Normal\""), "{q}");

        // Resume: the bad job runs, fails, parks in history.
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        let h = poll_history(&|h: &str| h.contains("Failed"), "bad job to fail");
        assert!(h.contains(&bad_id), "{h}");

        // failed_only filters the completed one out.
        let h = http(port, "/api?mode=history&failed_only=1&apikey=sekrit&output=json", None);
        assert!(h.contains(&bad_id) && !h.contains(&good_id), "{h}");
        // Pagination: limit=1 returns one slot but reports both.
        let h = http(port, "/api?mode=history&start=0&limit=1&apikey=sekrit&output=json", None);
        assert!(h.contains("\"noofslots\":2"), "{h}");
        assert_eq!(h.matches("nzo_id").count(), 1, "{h}");

        // Retry sends it back through the queue; it fails again and the
        // history entry now records the attempt.
        let r = http(
            port,
            &format!("/api?mode=retry&value={bad_id}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // The COUNT is `retries`; `retry` is SABnzbd's boolean "this one
        // can be asked for again" (issue #34).
        let h = poll_history(
            &|h: &str| h.contains("\"retries\":1") && h.contains("Failed"),
            "retried job to fail again",
        );
        assert!(h.contains(&bad_id), "{h}");

        // add-paused (priority -2) holds the job until per-job resume.
        let paused_id = upload(&good_xml, "&apikey=sekrit&priority=-2");
        std::thread::sleep(std::time::Duration::from_millis(600));
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains("\"Paused\""), "{q}");
        http(
            port,
            &format!("/api?mode=queue&name=resume&value={paused_id}&apikey=sekrit&output=json"),
            None,
        );
        poll_history(&|h: &str| h.matches("Completed").count() >= 2, "paused job after resume");

        // History delete with del_files removes the storage dir.
        let out_dir = dir2.join("complete/tv/j");
        assert!(out_dir.exists(), "expected {}", out_dir.display());
        http(
            port,
            &format!("/api?mode=history&name=delete&value={good_id}&del_files=1&apikey=sekrit&output=json"),
            None,
        );
        assert!(!out_dir.exists(), "del_files should remove {}", out_dir.display());
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Issue #34: the SAB facade's queue and history bodies carry the whole
/// shape real SABnzbd sends, not just the keys our own dashboard reads.
///
/// The reporter's phone remote (NZB360) sat at "Connecting" for both
/// Queue and History on v1.0.21 while `mode=addfile` - which reads
/// neither body - worked throughout, so auth and the add route were
/// never the problem. The precedent is SAB's own: sabnzbd/sabnzbd#872,
/// where SAB 2.0 trimmed these same header fields, NZB360's history
/// stopped working, and the fix was to put `version` back. That issue
/// also carries a debug log of NZB360's actual traffic, which is the
/// exact pair replayed at the bottom of this test.
///
/// Every key is checked with the TYPE SAB sends, because a missing key
/// and a wrongly-typed one fail a strongly-typed client identically -
/// `retry` went out as our try COUNT under the name SAB uses for a
/// boolean, which is a parse error before it is a wrong number.
///
/// Field names and formats come from sabnzbd/api.py (`build_header`,
/// `build_queue`, `_api_history_default`) and sabnzbd/database.py
/// (`unpack_history_info`), read at the source rather than from the
/// wiki - §105.4's own rule for this class.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_carries_sabnzbds_own_queue_and_history_shape() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabshape-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("shape.bin", &data, 40_000, "sh", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;shape.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
        use serde_json::Value;

        // What SAB's own JSON says a key is. `Str` and friends are what
        // a client's declared field type would be; `Null` is a key SAB
        // sends as null with the feature off, and a client that reads
        // it must still FIND it.
        #[derive(Clone, Copy, PartialEq, Debug)]
        enum Ty {
            Str,
            Num,
            Bool,
            Arr,
            Null,
        }
        let check = |obj: &Value, where_: &str, want: &[(&str, Ty)]| {
            let m = obj
                .as_object()
                .unwrap_or_else(|| panic!("{where_} is not an object: {obj}"));
            for (key, ty) in want {
                let v = m
                    .get(*key)
                    .unwrap_or_else(|| panic!("{where_}: SAB sends `{key}` and we do not: {obj}"));
                let ok = match ty {
                    Ty::Str => v.is_string(),
                    Ty::Num => v.is_number(),
                    Ty::Bool => v.is_boolean(),
                    Ty::Arr => v.is_array(),
                    Ty::Null => v.is_null(),
                };
                assert!(ok, "{where_}: `{key}` should be {ty:?}, got {v}: {obj}");
            }
        };
        let get = |q: &str| -> Value {
            let body = http(port, &format!("/api?{q}"), None);
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
        };

        // A slot to describe: pause first so the job stays in the queue
        // long enough to be read.
        http(port, "/api?mode=pause&output=json", None);
        let boundary = "----shapeb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"shape.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json&cat=tv",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // --- the queue body -------------------------------------------
        let q = get("mode=queue&output=json");
        let queue = &q["queue"];
        check(
            queue,
            "queue",
            &[
                // build_header()
                ("version", Ty::Str),
                ("paused", Ty::Bool),
                ("paused_all", Ty::Bool),
                ("pause_int", Ty::Str),
                ("diskspace1", Ty::Str),
                ("diskspace2", Ty::Str),
                ("diskspace1_norm", Ty::Str),
                ("diskspace2_norm", Ty::Str),
                ("diskspacetotal1", Ty::Str),
                ("diskspacetotal2", Ty::Str),
                ("speedlimit", Ty::Str),
                ("speedlimit_abs", Ty::Str),
                ("have_warnings", Ty::Str),
                ("finishaction", Ty::Null),
                ("quota", Ty::Str),
                ("have_quota", Ty::Bool),
                ("left_quota", Ty::Str),
                ("cache_art", Ty::Str),
                ("cache_size", Ty::Str),
                // build_queue()
                ("kbpersec", Ty::Str),
                ("speed", Ty::Str),
                ("mb", Ty::Str),
                ("mbleft", Ty::Str),
                ("size", Ty::Str),
                ("sizeleft", Ty::Str),
                ("noofslots", Ty::Num),
                ("noofslots_total", Ty::Num),
                ("start", Ty::Num),
                ("limit", Ty::Num),
                ("finish", Ty::Num),
                ("status", Ty::Str),
                ("timeleft", Ty::Str),
                ("slots", Ty::Arr),
            ],
        );
        assert_eq!(queue["version"], "4.5.0", "{q}");
        let slots = queue["slots"].as_array().expect("slots array");
        assert_eq!(slots.len(), 1, "one paused job should be listed: {q}");
        check(
            &slots[0],
            "queue slot",
            &[
                ("index", Ty::Num),
                ("nzo_id", Ty::Str),
                ("unpackopts", Ty::Str),
                ("priority", Ty::Str),
                ("script", Ty::Str),
                ("filename", Ty::Str),
                ("labels", Ty::Arr),
                ("password", Ty::Str),
                ("cat", Ty::Str),
                ("mb", Ty::Str),
                ("mbleft", Ty::Str),
                ("size", Ty::Str),
                ("sizeleft", Ty::Str),
                ("percentage", Ty::Str),
                ("mbmissing", Ty::Str),
                ("direct_unpack", Ty::Null),
                ("status", Ty::Str),
                ("avg_age", Ty::Str),
                ("time_added", Ty::Num),
                ("timeleft", Ty::Str),
            ],
        );
        // The password itself never leaves the daemon (M24), so SAB's
        // slot field is present and empty rather than absent.
        assert_eq!(slots[0]["password"], "", "{q}");

        // --- the history body -----------------------------------------
        http(port, "/api?mode=resume&output=json", None);
        let h = (0..150)
            .find_map(|_| {
                let h = get("mode=history&output=json");
                h["history"]["slots"]
                    .as_array()
                    .filter(|s| s.first().is_some_and(|r| r["status"] == "Completed"))
                    .is_some()
                    .then_some(h)
                    .or_else(|| {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        None
                    })
            })
            .expect("timed out waiting for the job to complete");
        let hist = &h["history"];
        check(
            hist,
            "history",
            &[
                ("version", Ty::Str),
                ("total_size", Ty::Str),
                ("month_size", Ty::Str),
                ("week_size", Ty::Str),
                ("day_size", Ty::Str),
                ("slots", Ty::Arr),
                ("ppslots", Ty::Num),
                ("noofslots", Ty::Num),
                ("last_history_update", Ty::Num),
            ],
        );
        assert_eq!(hist["version"], "4.5.0", "{h}");
        check(
            &hist["slots"][0],
            "history slot",
            &[
                ("completed", Ty::Num),
                ("name", Ty::Str),
                ("nzb_name", Ty::Str),
                ("category", Ty::Str),
                ("pp", Ty::Str),
                ("script", Ty::Str),
                ("report", Ty::Str),
                ("url", Ty::Str),
                ("status", Ty::Str),
                ("nzo_id", Ty::Str),
                ("storage", Ty::Str),
                ("path", Ty::Str),
                ("script_line", Ty::Str),
                ("download_time", Ty::Num),
                ("postproc_time", Ty::Num),
                ("stage_log", Ty::Arr),
                ("downloaded", Ty::Num),
                ("completeness", Ty::Num),
                ("fail_message", Ty::Str),
                ("url_info", Ty::Str),
                ("bytes", Ty::Num),
                ("size", Ty::Str),
                ("meta", Ty::Null),
                ("series", Ty::Str),
                ("duplicate_key", Ty::Str),
                ("md5sum", Ty::Str),
                ("password", Ty::Str),
                ("action_line", Ty::Str),
                ("loaded", Ty::Bool),
                ("retry", Ty::Bool),
                ("archive", Ty::Bool),
                ("time_added", Ty::Num),
                // Ours, and the reason `retry` could change type: the
                // attempt count keeps its meaning under its own name.
                ("retries", Ty::Num),
            ],
        );
        // A Completed job cannot be retried, which is what SAB's boolean
        // says here.
        assert_eq!(hist["slots"][0]["retry"], false, "{h}");
        // SAB's own suffix convention (to_units + "B"), not a bare MB.
        let size = hist["slots"][0]["size"].as_str().unwrap_or_default();
        assert!(
            size.ends_with('B') && size.contains(' '),
            "history size should be SAB-shaped: {size}"
        );

        // --- NZB360's literal traffic ---------------------------------
        // From the SAB debug log in sabnzbd/sabnzbd#872: `output` arrives
        // TWICE and the queue call carries `start` with no `limit`.
        let q = get("output=json&output=json&mode=queue&start=0");
        assert!(q["queue"]["slots"].is_array(), "{q}");
        let h = get("output=json&output=json&limit=20&mode=history&start=0");
        assert_eq!(h["history"]["slots"].as_array().map(Vec::len), Some(1), "{h}");

        // --- casing, settled at each dialect's source -----------------
        // SAB reads `mode` and looks it up with no normalisation
        // (sabnzbd/api.py: `mode = kwargs.get("mode", "")`, then an exact
        // `_api_table` lookup), so an uppercase mode is NOT the same
        // call. §105.4 left this open rather than lowercasing on a
        // hunch; matching SAB means leaving it case-sensitive, and this
        // pins that so nobody "fixes" it later.
        let up = get("mode=QUEUE&output=json");
        assert!(
            up.get("queue").is_none(),
            "an uppercase mode must not be treated as the lowercase one: {up}"
        );
        // NZBGet is the opposite, and its source says so: every method
        // name in XmlRpcProcessor::CreateCommand is compared with
        // strcasecmp. So the JSON-RPC facade lowercases first, and a
        // mixed-case method IS the call - the other half of §105.4's
        // "the NZBGet dialect's equivalents".
        let mixed = http(
            port,
            "/jsonrpc",
            Some((
                "application/json",
                b"{\"method\":\"ListGroups\",\"params\":[],\"id\":7}".as_slice(),
            )),
        );
        let mixed: Value = serde_json::from_str(&mixed).unwrap_or(Value::Null);
        assert!(
            mixed.get("result").is_some(),
            "NZBGet matches methods case-insensitively (strcasecmp): {mixed}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14f: a queued duplicate is held as ALTERNATIVE and auto-promoted
/// when the original fails.
///
/// "Fails" means FINALLY fails. A first missing-article failure is parked
/// with an M32 automatic retry armed, and promoting the alternative there
/// would download the same title twice in parallel - the retry is about
/// to fetch the very gaps that failed. So this runs with a 5 s cooldown
/// and checks both halves: held while the retry is pending, promoted once
/// it has been spent.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_held_then_promoted() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dupe-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("ep.bin", &data, 40_000, "dp", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let seg_xml = |segs: &[(String, u64, u32)]| {
        let mut x = String::new();
        for (id, bytes, num) in segs {
            x.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        x
    };
    let wrap = |inner: &str| {
        format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;ep.bin&quot; yEnc (1/9)\">\n    <groups><group>g</group></groups>\n    <segments>\n{inner}    </segments>\n  </file>\n</nzb>\n"
        )
    };
    let ghost: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("dghost{n}@x"), 40_000, n))
        .collect();
    let bad_xml = wrap(&seg_xml(&ghost)); // 720p "original" - will fail
    let good_xml = wrap(&seg_xml(&segs)); // 1080p duplicate - must take over

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
            // Short M32 cooldown instead of the 20 min default: the promotion
            // waits for the automatic retry to be spent, and the test needs to
            // see both sides of that within its own lifetime.
            .env("NZBFAST_AUTO_RETRY_SECS", "5")
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
        let upload = |xml: &str, fname: &str| {
            let boundary = "----dupeb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
        };
        // Pause so both jobs sit in the queue when the dupe check runs.
        http(port, "/api?mode=pause&output=json", None);
        upload(&bad_xml, "Show.Name.S01E02.720p.WEB.nzb");
        upload(&good_xml, "Show.Name.S01E02.1080p.WEB.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"Duplicate\""), "{q}");
        assert!(q.contains("show name/s1e2"), "{q}");

        // Resume: 720p fails → 1080p ALTERNATIVE must promote and finish.
        http(port, "/api?mode=resume&output=json", None);

        // FIRST failure: an automatic retry is armed, so the alternative
        // is still held. park decides this synchronously with the history
        // push, so the queue may be read as soon as Failed appears.
        let mut held = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Failed\"") {
                let q = http(port, "/api?mode=queue&output=json", None);
                assert!(
                    q.contains("\"Duplicate\""),
                    "promoted while an automatic retry was pending: {q}"
                );
                held = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(held, "the original never failed");

        // The retry runs, fails again (retries == 1, no longer eligible),
        // and THAT failure promotes the alternative.
        let mut ok = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") && h.contains("\"Failed\"") {
                assert!(h.contains("1080p"), "{h}");
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(ok, "alternative was never promoted/completed");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// UX audit 3 Aug (#10): the held-duplicate row has told the user to
/// "raise its priority to download it anyway" since M14f, and that
/// instruction did nothing.
///
/// A hold is a PAUSE at priority -3. `pick_job` skips a paused job at
/// any priority, and the priority arm wrote the number without touching
/// `paused` - so the drawer's priority select, the one control the
/// tooltip pointed at, left the job exactly as parked as before while
/// answering `"status":true`. Raising the priority now releases the hold
/// the same way the failed-original promotion does (paused=false), and
/// only for -3: an ordinary paused job re-prioritised by a client stays
/// paused, which is what every SAB caller expects.
///
/// Codex sweep 2, 3 Aug M4 extends it to the NZBGet `/jsonrpc` facade,
/// which kept its own copy of the priority write and never got the hold
/// release - so which client type the user happened to configure in
/// Sonarr decided whether the one documented escape from a duplicate
/// hold worked at all. Both paths now go through
/// `api::queue::apply_priority`, and this drives one held duplicate
/// down each of them.
#[tokio::test(flavor = "multi_thread")]
async fn raising_a_held_duplicates_priority_releases_it() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dupeprio-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    // Both copies are REAL: the point of the test is that the held one
    // actually downloads once its priority is raised.
    let a = make_file_articles("a.bin", &payload(120_000, 17), 40_000, "dq", &mut articles);
    let b = make_file_articles("b.bin", &payload(120_000, 19), 40_000, "dq", &mut articles);
    let c = make_file_articles("c.bin", &payload(120_000, 23), 40_000, "dq", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb = |file: &str, segs: &[(String, u64, u32)]| {
        let mut x = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            x.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        x.push_str("    </segments>\n  </file>\n</nzb>\n");
        x
    };
    let first_xml = nzb("a.bin", &a);
    let held_xml = nzb("b.bin", &b);
    let held2_xml = nzb("c.bin", &c);

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
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----dqb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(|s| format!("SABnzbd_nzo_{s}"))
                .expect("addfile returned no nzo_id")
        };
        let qslot = |q: &str, id: &str| -> serde_json::Value {
            let v: serde_json::Value =
                serde_json::from_str(q).unwrap_or_else(|e| panic!("bad queue JSON: {e}\n{q}"));
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };

        // Paused so both land in the queue before the duplicate check runs.
        http(port, "/api?mode=pause&output=json", None);
        let _first_id = upload(&first_xml, "Show.Name.S03E04.720p.WEB.nzb");
        let held_id = upload(&held_xml, "Show.Name.S03E04.1080p.WEB.nzb");
        let held2_id = upload(&held2_xml, "Show.Name.S03E04.2160p.WEB.nzb");

        let q = http(port, "/api?mode=queue&output=json", None);
        for id in [&held_id, &held2_id] {
            let held = qslot(&q, id);
            assert_eq!(held["priority"], "Duplicate", "not held: {q}");
            assert_eq!(held["status"], "Paused", "a hold is a pause: {q}");
        }

        // The drawer's priority select, exactly as the page sends it.
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={held_id}&value2=1&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // The same instruction through the NZBGet facade - Sonarr with
        // its client type set to NZBGet reaches only this one.
        // NZBGet addresses jobs by the numeric tail of the nzo_id.
        let nzbid: i64 = held2_id
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap_or_else(|e| panic!("no numeric id in {held2_id}: {e}"));
        let body = format!(
            "{{\"method\":\"editqueue\",\"params\":[\"GroupSetPriority\",\"100\",[{nzbid}]],\"id\":3}}"
        );
        let r = http(port, "/jsonrpc", Some(("application/json", body.as_bytes())));
        assert!(r.contains("true"), "GroupSetPriority refused: {r}");

        let q = http(port, "/api?mode=queue&output=json", None);
        assert_eq!(qslot(&q, &held_id)["priority"], "High", "{q}");
        for id in [&held_id, &held2_id] {
            assert_ne!(
                qslot(&q, id)["status"],
                "Paused",
                "the priority write left the hold in place for {id}: {q}"
            );
        }

        // ...and the scheduler agrees: both download.
        http(port, "/api?mode=resume&output=json", None);
        let mut ran = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
            let done = |id: &str| {
                v["history"]["slots"].as_array().is_some_and(|a| {
                    a.iter()
                        .any(|s| s["nzo_id"] == id && s["status"] == "Completed")
                })
            };
            if done(&held_id) && done(&held2_id) {
                ran = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            ran,
            "a released duplicate never downloaded - the jsonrpc leg is the \
             one that used to answer success and change nothing"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14k: RSS automation - the daemon polls a feed, filters with rules,
/// fetches the accepted item's NZB over HTTP, downloads it, and never
/// re-grabs a seen guid.
#[tokio::test(flavor = "multi_thread")]
async fn rss_feed_auto_grabs() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rss-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(150_000, 13);
    let mut articles = HashMap::new();
    let segs = make_file_articles("r.bin", &data, 40_000, "rs", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut nzb_xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;r.bin&quot; yEnc (1/9)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        nzb_xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    nzb_xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    // Indexer stand-in: /rss (feed with one 1080p item + one 480p item)
    // and /grab (the NZB). Counts grabs to prove seen-dedupe.
    let web = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let web_port = web.server_addr().to_ip().unwrap().port();
    let grabs = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let grabs2 = grabs.clone();
    let nzb_body = nzb_xml.clone();
    std::thread::spawn(move || {
        for req in web.incoming_requests() {
            let url = req.url().to_string();
            let body = if url.starts_with("/rss") {
                format!(
                    r#"<?xml version="1.0"?><rss><channel>
<item><title>Grab.Me.S01E01.1080p.WEB</title><guid>want-1</guid>
<enclosure url="http://127.0.0.1:{web_port}/grab" length="150000"/></item>
<item><title>Skip.Me.S01E01.480p.WEB</title><guid>skip-1</guid>
<enclosure url="http://127.0.0.1:{web_port}/grab-bad" length="150000"/></item>
</channel></rss>"#
                )
            } else if url.starts_with("/grab-bad") {
                panic!("rejected item was fetched");
            } else {
                grabs2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                nzb_body.clone()
            };
            let _ = req.respond(tiny_http::Response::from_string(body));
        }
    });

    let feeds = dir.join("feeds.json");
    std::fs::write(
        &feeds,
        format!(
            r#"[{{"url":"http://127.0.0.1:{web_port}/rss","interval_secs":1,"category":"tv","rules":["Reject: *480p*","Accept: *1080p*"]}}]"#
        ),
    )
    .unwrap();

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--feeds")
            .arg(&feeds)
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The 1080p item must be auto-grabbed and complete.
        let mut done = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") {
                assert!(h.contains("Grab.Me.S01E01.1080p.WEB"), "{h}");
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "rss item never downloaded");
        // Give the poller 2 more cycles: seen-guid dedupe must hold the
        // grab count at 1 (the /grab-bad panic guards the reject rule).
        std::thread::sleep(std::time::Duration::from_millis(2500));
        assert_eq!(grabs.load(std::sync::atomic::Ordering::Relaxed), 1);
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(!q.contains("Grab.Me"), "re-queued a seen item: {q}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A spent quota holds the queue, SAYS SO on the wire, and still lets a
/// Force job through (SAB semantics).
///
/// The hold itself is old behaviour; what is pinned here is that the
/// reason crosses the API. Before this, `guard_reason` was a local in
/// the download worker: the queue sat still, the pill read "idle", and
/// the only account of why lived in the daemon log.
#[tokio::test(flavor = "multi_thread")]
async fn quota_hold_is_on_the_wire_and_force_still_runs() {
    let dir = std::env::temp_dir().join(format!("nzbfast-quota-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(60_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("q.bin", &data, 30_000, "qq", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;q.bin&quot; yEnc (1/2)\">\n    <groups><group>q</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    // Seed the period's ledger BEFORE the daemon opens it: the guard
    // needs bytes already spent, and downloading 500 GB to get them is
    // not a test. Same file and shape QuotaLedger::save writes; `start`
    // is this period's UTC midnight, or `open` treats it as a stale
    // window and zeroes the count.
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    let midnight = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400
        * 86_400;
    std::fs::write(
        spool.join("quota.json"),
        format!("{{\"start\":{midnight},\"bytes\":9000000000}}"),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        // The quota period follows the daemon's LOCAL calendar since
        // issue #25; pin the daemon to UTC so the UTC-midnight `start`
        // seeded above stays valid on any test machine.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("TZ", "UTC")
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
        // A quota smaller than what the ledger already says was spent.
        let set = http(port, "/api?mode=config&name=quota&value=1G&output=json", None);
        assert!(set.contains("\"status\":true"), "{set}");

        let boundary = "----quotab";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"q.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let added = http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        let nzo = added
            .split("\"nzo_ids\":[\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_else(|| panic!("no nzo_id in {added}"))
            .to_string();

        // The guard runs on the worker's own pass, so give it a few.
        let mut q = String::new();
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(150));
            q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"hold\"") && !q.contains("\"hold\":null") {
                break;
            }
        }
        // The reason, and both numbers, named - not just a hold flag.
        assert!(q.contains("\"kind\":\"quota\""), "{q}");
        assert!(q.contains("\"reason\":\"quota\""), "{q}");
        assert!(q.contains("\"spent_gb\":9.0"), "{q}");
        assert!(q.contains("\"cap_gb\":1.0"), "{q}");
        // Held, not paused: nothing touched the pause flag, so the
        // pill's "held" wording is the only thing that can explain it.
        assert!(q.contains("\"paused\":false"), "{q}");
        assert!(q.contains("\"pause_source\":null"), "{q}");
        assert!(q.contains("\"Queued\""), "{q}");
        assert!(
            http(port, "/api?mode=history&output=json", None).contains("\"noofslots\":0"),
            "the held job must not have run"
        );

        // Force walks past a spent quota - SAB semantics, and what the
        // banner now tells the user to do.
        http(
            port,
            &format!("/api?mode=queue&name=priority&value={nzo}&value2=2&output=json"),
            None,
        );
        let mut done = false;
        for _ in 0..80 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            if http(port, "/api?mode=history&output=json", None).contains("\"Completed\"") {
                done = true;
                break;
            }
        }
        assert!(done, "Force did not run under a spent quota");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14g: an absurd --min-free threshold must hold every job in the queue.
#[tokio::test(flavor = "multi_thread")]
async fn disk_guard_holds_queue() {
    let dir = std::env::temp_dir().join(format!("nzbfast-guard-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(100_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("g.bin", &data, 40_000, "gg", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;g.bin&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--min-free")
            .arg("1000T")
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let boundary = "----guardb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"g.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        // No disk headroom → the job must still be Queued (not started,
        // not failed) after plenty of scheduler wakeups.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"Queued\""), "{q}");
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(h.contains("\"noofslots\":0"), "{h}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Queue/history persistence: job records survive a daemon kill -9.
/// A completed job must come back in history, a paused queued job must
/// come back queued (still paused), and resuming it after the restart
/// must download the payload byte-identically.
#[tokio::test(flavor = "multi_thread")]
async fn queue_survives_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-persist-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let keeper_data = payload(200_000, 7);
    let later_data = payload(160_000, 11);
    let mut articles = HashMap::new();
    let keeper_segs = make_file_articles("keeper.bin", &keeper_data, 40_000, "kp", &mut articles);
    let later_segs = make_file_articles("later.bin", &later_data, 40_000, "lt", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };
    let keeper_xml = nzb_for("keeper.bin", &keeper_segs);
    let later_xml = nzb_for("later.bin", &later_segs);

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
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
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
    };
    let upload = |port: u16, xml: &str, extra: &str| -> String {
        let boundary = "----persistb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            &format!("/api?mode=addfile&apikey=sekrit&output=json{extra}"),
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        r.split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap()
    };
    let poll_history = |port: u16, pred: &dyn Fn(&str) -> bool, what: &str| {
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if pred(&h) {
                return h;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("timed out waiting for {what}");
    };

    // Daemon A: complete one job, add a second paused, then kill -9.
    let a = serve(&dir, &build).await;
    let port_a = a.port;
    let (keeper_id, later_id) = tokio::task::spawn_blocking(move || {
        let keeper_id = upload(port_a, &keeper_xml, "&cat=tv");
        poll_history(port_a, &|h: &str| h.contains("Completed"), "keeper job");
        // priority -2 = add paused: stays Queued so it's still in the
        // queue when the daemon dies.
        let later_id = upload(port_a, &later_xml, "&priority=-2");
        let q = http(port_a, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains(&later_id) && q.contains("\"Paused\""), "{q}");
        (keeper_id, later_id)
    })
    .await
    .unwrap();
    // kill -9 (KillOnDrop kills and reaps): persistence must not depend
    // on a graceful shutdown.
    drop(a);

    // Daemon B on a fresh port, same spool: both records must be back.
    let b = serve(&dir, &build).await;
    let port_b = b.port;
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let q = http(port_b, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains(&later_id), "queued job lost across restart: {q}");
        assert!(
            q.contains("\"Paused\""),
            "per-job pause lost across restart: {q}"
        );
        let h = http(port_b, "/api?mode=history&apikey=sekrit&output=json", None);
        assert!(h.contains(&keeper_id), "history lost across restart: {h}");
        assert!(h.contains("\"Completed\""), "{h}");
        // The restored category survives too (out_dir under complete/tv).
        // Compared with the separator normalised: the daemon reports NATIVE
        // paths, so on Windows this reads "complete\\tv\\j" (JSON-escaped)
        // and a literal "complete/tv/j" could never match.
        assert!(h.replace("\\\\", "/").contains("complete/tv/j"), "{h}");

        // Resume the restored job - it must actually download.
        http(
            port_b,
            &format!("/api?mode=queue&name=resume&value={later_id}&apikey=sekrit&output=json"),
            None,
        );
        poll_history(
            port_b,
            &|h: &str| h.contains(&later_id) && h.matches("Completed").count() >= 2,
            "restored job after resume",
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/j/later.bin")).unwrap(),
            later_data,
            "restored job payload differs"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// mode=restart_daemon re-execs the process in place, and the launchers
/// (the Mac app, the Windows tray) hand the daemon its stdout already
/// pointed at daemon.log. The log tee dup2s a pipe over fds 1/2, so an
/// exec that did not first restore them handed the replacement image the
/// DEAD pipe as stdout: after a dashboard restart the file never grew
/// again while mode=log looked healthy (observed 7 Aug 2026). The
/// harness pipes stdout to a file the same way the launchers do, so the
/// re-exec'd daemon's startup banner landing in that file is exactly the
/// property that was broken.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn restart_daemon_keeps_logging_to_the_same_file() {
    let dir = std::env::temp_dir().join(format!("nzbfast-relog-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();

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
    let port = d.port;
    let log = d.log.clone();
    let banner = format!("open the dashboard at  http://localhost:{port}/");

    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=restart_daemon&apikey=sekrit&output=json",
            Some(("application/x-www-form-urlencoded", b"")),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // The restart is deliberately delayed (~400 ms) so the answer
        // above reaches us, then wind-down + exec + full startup. The
        // banner is printed once startup is genuinely finished, so a
        // SECOND banner in the same file is proof the re-exec'd image
        // kept the launcher's log fd.
        for _ in 0..600 {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.matches(&banner).count() >= 2 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let tail: String = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "re-exec'd daemon never wrote its banner back to the launcher's log file\n--- log tail ---\n{tail}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M21: the NZBGet JSON-RPC facade - a remote-control app's whole
/// session: version, append (base64 NZB), listgroups, pause/resume via
/// status, editqueue GroupDelete, rate.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_jsonrpc_facade_cycle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jsonrpc-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("show.bin", &data, 40_000, "jr", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;show.bin&quot; yEnc (1/6)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    // Simple std base64 encoder for the append payload.
    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in data.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let rpc = |method: &str, params: String| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":7}}");
            http(
                port,
                "/jsonrpc",
                Some(("application/json", body.as_bytes())),
            )
        };
        // version
        let v = rpc("version", "[]".into());
        assert!(v.contains("21.0"), "{v}");
        // append (v13 param order), paused via priority 0 - it will start
        // downloading from the mock; that's fine.
        let ap = rpc(
            "append",
            format!(
                "[\"show.nzb\",\"{}\",\"tv\",0,false,false,\"\",0,\"SCORE\"]",
                b64(xml.as_bytes())
            ),
        );
        let nzbid: i64 = serde_json::from_str::<serde_json::Value>(&ap)
            .ok()
            .and_then(|v| v.get("result").and_then(|r| r.as_i64()))
            .unwrap_or(0);
        assert!(nzbid > 0, "append failed: {ap}");
        // listgroups sees it (or it may already be in history if tiny+fast;
        // poll both).
        let mut seen = false;
        for _ in 0..50 {
            let lg = rpc("listgroups", "[]".into());
            let hi = rpc("history", "[]".into());
            if lg.contains("show.nzb")
                || lg.contains("\"NZBID\"") && lg.contains(&nzbid.to_string())
                || hi.contains(&format!("\"NZBID\":{nzbid}"))
            {
                seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(seen, "job never visible via listgroups/history");
        // pause / status / resume
        rpc("pausedownload", "[]".into());
        let st = rpc("status", "[]".into());
        assert!(st.contains("\"DownloadPaused\":true"), "{st}");
        rpc("resumedownload", "[]".into());
        let st = rpc("status", "[]".into());
        assert!(st.contains("\"DownloadPaused\":false"), "{st}");
        // rate limit round-trip
        rpc("rate", "[2500]".into());
        let st = rpc("status", "[]".into());
        assert!(
            st.contains(&format!("\"DownloadLimit\":{}", 2500 * 1024)),
            "{st}"
        );
        rpc("rate", "[0]".into());
        // history cleanup op is exercised by HistoryDelete once done.
        for _ in 0..100 {
            let hi = rpc("history", "[]".into());
            if hi.contains(&format!("\"NZBID\":{nzbid}")) {
                let del = rpc("editqueue", format!("[\"HistoryDelete\",\"\",[{nzbid}]]"));
                assert!(del.contains("true"), "{del}");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("download never completed into history");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir2);
}

/// The NZBGet JSON-RPC facade announces the idle edge (Codex sweep
/// 14 Aug M4). GroupPause on the sole runnable job and a non-active
/// GroupDelete each idle the queue with no park, and the REST arms have
/// said `queue.idle` for both since the 10 Aug sweep - this facade
/// answered true and said nothing, so which client type the user
/// configured decided whether lifecycle hooks heard about it. Global
/// pause keeps the jobs Queued (and Queued-unpaused is NOT idle), so
/// each edge here is exactly the job-level transition under test.
#[tokio::test(flavor = "multi_thread")]
async fn jsonrpc_pause_and_delete_announce_the_idle_edge() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jridle-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(80_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("idle.bin", &data, 40_000, "jri", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let nzb_for = |name: &str| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let xml_a = nzb_for("Alpha.Idle.Test");
    let xml_b = nzb_for("Beta.Idle.Test");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        fn b64(data: &[u8]) -> String {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for c in data.chunks(3) {
                let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                out.push(A[(n >> 18) as usize & 63] as char);
                out.push(A[(n >> 12) as usize & 63] as char);
                out.push(if c.len() > 1 {
                    A[(n >> 6) as usize & 63] as char
                } else {
                    '='
                });
                out.push(if c.len() > 2 {
                    A[n as usize & 63] as char
                } else {
                    '='
                });
            }
            out
        }
        let rpc = |method: &str, params: String| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":9}}");
            http(
                port,
                "/jsonrpc",
                Some(("application/json", body.as_bytes())),
            )
        };
        let append = |name: &str, xml: &str| -> i64 {
            let ap = rpc(
                "append",
                format!(
                    "[\"{name}\",\"{}\",\"\",0,false,false,\"\",0,\"SCORE\"]",
                    b64(xml.as_bytes())
                ),
            );
            let id = serde_json::from_str::<serde_json::Value>(&ap)
                .ok()
                .and_then(|v| v.get("result").and_then(|r| r.as_i64()))
                .unwrap_or(0);
            assert!(id > 0, "append failed: {ap}");
            id
        };
        // Idle events since the cursor, in ring order.
        let idles = |since: u64| -> Vec<u64> {
            let body = http(
                port,
                &format!("/api?mode=dashboard&events={since}&output=json"),
                None,
            );
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            v["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["kind"] == "queue.idle")
                .filter_map(|e| e["seq"].as_u64())
                .collect()
        };
        let wait_idles = |since: u64, want: usize| -> Vec<u64> {
            for _ in 0..50 {
                let got = idles(since);
                if got.len() >= want {
                    return got;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("never saw {want} queue.idle event(s) past seq {since}");
        };
        let seq0 = {
            let body = http(port, "/api?mode=dashboard&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            v["events_seq"].as_u64().expect("events_seq")
        };
        // Global pause first, so the appended jobs stay Queued and
        // unpaused - runnable, hence NOT idle - instead of downloading.
        rpc("pausedownload", "[]".into());

        // Edge 1: GroupPause on the sole runnable job.
        let a = append("alpha-idle.nzb", &xml_a);
        let r = rpc("editqueue", format!("[\"GroupPause\",\"\",[{a}]]"));
        assert!(r.contains("true"), "{r}");
        let after_pause = wait_idles(seq0, 1);
        assert_eq!(
            after_pause.len(),
            1,
            "GroupPause must announce exactly one idle edge: {after_pause:?}"
        );

        // Edge 2: a non-active delete. The add of B re-arms the latch;
        // deleting B (A still paused) idles the queue again.
        let b = append("beta-idle.nzb", &xml_b);
        let r = rpc("editqueue", format!("[\"GroupDelete\",\"\",[{b}]]"));
        assert!(r.contains("true"), "{r}");
        let after_delete = wait_idles(seq0, 2);
        assert_eq!(
            after_delete.len(),
            2,
            "GroupDelete must announce exactly one more idle edge: {after_delete:?}"
        );

        // Still a transition: a paused queue poked again stays silent.
        let r = rpc("editqueue", format!("[\"GroupPause\",\"\",[{a}]]"));
        assert!(r.contains("true"), "{r}");
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert_eq!(idles(seq0).len(), 2, "the latch must keep repeats silent");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir2);
}

/// M23 Smart Folders + cleanup rules, end to end: rules set live via the
/// config API route an UNcategorized upload to its category, junk files
/// are deleted after completion, and the finished job is filed as
/// [Show]/Season NN/ with the video renamed "Show - S01E02.ext".
#[tokio::test(flavor = "multi_thread")]
async fn smart_folders_and_cleanup() {
    let dir = std::env::temp_dir().join(format!("nzbfast-smart-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Two files on the mock server: the episode video + an .sfv the
    // cleanup rule should delete.
    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    let video = payload(300_000, 7);
    let junk = payload(20_000, 9);
    let mut articles = HashMap::new();
    let vsegs = make_file_articles(&format!("{stem}.mkv"), &video, 40_000, "vid", &mut articles);
    let jsegs = make_file_articles(&format!("{stem}.sfv"), &junk, 40_000, "junk", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in [
        (format!("{stem}.mkv"), &vsegs),
        (format!("{stem}.sfv"), &jsegs),
    ] {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs.iter() {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");

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
    // The .sfv below is a real delete by the real binary: keep it out of
    // the developer's Trash.
    delete_without_the_trash(&cfg);
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // %-encode a config value for the query string.
        let pct = |s: &str| -> String {
            s.bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect()
        };
        // Live settings via the config API: a rule (regex + size floor,
        // first-match-wins is unit-tested) and the cleanup list.
        let rule = r#"[{"name":"myshow","match":"^My\\.Show\\.","not_match":"720p","min_size":"100K","category":"tv","tv_sort":true}]"#;
        let r = http(
            port,
            &format!("/api?mode=config&name=smart_folders&value={}&apikey=sekrit&output=json", pct(rule)),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let r = http(
            port,
            &format!("/api?mode=config&name=cleanup_exts&value={}&apikey=sekrit&output=json", pct("par2, sfv")),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // Upload WITHOUT a category - the smart rule must pick "tv".
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // Filed as [Show]/Season NN/ under the rule's category, with the
        // video renamed and the .sfv cleaned up; the original job dir is
        // gone and history reports the final storage path. Auto-rename is
        // on by default and adds the " 1080p" quality tag to the episode -
        // unbracketed, since rename_quality_brackets defaults off.
        let dest = dir2.join("complete/tv/My Show/Season 01");
        assert_eq!(
            std::fs::read(dest.join("My Show - S01E02 1080p.mkv")).expect("renamed video"),
            payload(300_000, 7)
        );
        let left: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".sfv"))
            .collect();
        assert!(left.is_empty(), "sfv survived cleanup: {left:?}");
        assert!(
            !dir2.join(format!("complete/tv/{stem}")).exists(),
            "original job dir should be gone"
        );
        assert!(hist.contains("Season 01"), "history path not updated: {hist}");

        // N7: Play on this finished row must serve THIS episode. A filed
        // job's out_dir is the SHARED season folder, and the completed
        // branch used to serve "the biggest media file in out_dir" - so a
        // larger sibling sitting beside it (the user's own E03 here) was
        // what came back when you pressed play on E02.
        let sibling = dest.join("My Show - S01E03 1080p.mkv");
        std::fs::write(&sibling, payload(900_000, 13)).unwrap();
        let id = hist
            .split("\"nzo_id\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_else(|| panic!("no nzo_id in history: {hist}"))
            .to_string();
        let resp = raw(
            port,
            format!("GET /stream/{id}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        let cut = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("no headers") + 4;
        let (head, served) = resp.split_at(cut);
        let head = String::from_utf8_lossy(head).to_string();
        assert!(head.contains("200 OK"), "{head}");
        assert_eq!(
            served.len(),
            300_000,
            "served the wrong file - {} bytes is the sibling episode",
            served.len()
        );
        assert_eq!(served, &payload(300_000, 7)[..], "served bytes are not this episode's");
        assert!(sibling.exists(), "playing must not disturb the sibling");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 78: episode titles in TV renames, end to end.
///
/// The lookup is CACHE-ONLY - it reads the `eplist:` blob the watchlist's
/// calendar refresher leaves in the index, and makes no request of its
/// own - so the test seeds that blob directly and runs the daemon with
/// `NZBFAST_NO_ENRICH=1` like every other one here. What it proves is
/// the whole chain: the opt-in setting, the cache read inside
/// `finalize_names`, the title in the filed name, and the job's own
/// record of what it wrote being good enough to play the episode back
/// out of a shared season folder afterwards.
#[cfg(feature = "indexer")]
#[tokio::test(flavor = "multi_thread")]
async fn episode_titles_reach_a_filed_tv_rename() {
    let dir = std::env::temp_dir().join(format!("nzbfast-eptitle-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    let video = payload(200_000, 11);
    let mut articles = HashMap::new();
    let vsegs = make_file_articles(&format!("{stem}.mkv"), &video, 40_000, "vid", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{stem}.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        vsegs.len()
    ));
    for (id, bytes, num) in vsegs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    // The cache the rename reads, written the way the calendar refresher
    // writes it: one blob per show, keyed by the normalised title.
    let db = dir.join("index.db");
    {
        let ix = nzbkit::index::Index::open(&db).unwrap();
        let key = format!("eplist:{}", nzbkit::release::norm_title("My Show"));
        let blob = r#"{"fetched":1,"show_id":1,"episodes":[
            {"season":1,"episode":1,"name":"Pilot","airdate":"2026-01-01"},
            {"season":1,"episode":2,"name":"The Ceremony","airdate":"2026-01-08"}]}"#;
        ix.kv_set(&key, blob).unwrap();
    }

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
    // The index has to be ON for the cache to be readable at all, and the
    // titles setting is opt-in - it is off for everyone who does not ask.
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_enabled\": true, \"rename_episode_titles\": true}",
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--index-db")
            .arg(&db)
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let pct = |s: &str| -> String {
            s.bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect()
        };
        let rule = r#"[{"name":"myshow","match":"^My\\.Show\\.","category":"tv","tv_sort":true}]"#;
        let r = http(
            port,
            &format!(
                "/api?mode=config&name=smart_folders&value={}&apikey=sekrit&output=json",
                pct(rule)
            ),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // The setting survived the restart replay and reads back on.
        let cfgjson = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(
            cfgjson.contains("\"rename_episode_titles\":true"),
            "setting not live: {cfgjson}"
        );

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
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

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // The episode's own name is in the filename, between the episode
        // base and the quality tag. Bracketed here because a settings.json
        // already on disk reads as an existing install, which keeps the
        // pre-1.0.10 punctuation - see `legacy_rename_punctuation`.
        let dest = dir2.join("complete/tv/My Show/Season 01");
        let filed = dest.join("My Show - S01E02 - The Ceremony [1080p].mkv");
        assert_eq!(
            std::fs::read(&filed).unwrap_or_else(|e| panic!(
                "no titled episode ({e}); folder holds {:?}",
                std::fs::read_dir(&dest)
                    .map(|rd| rd.flatten().map(|x| x.file_name()).collect::<Vec<_>>())
            )),
            payload(200_000, 11)
        );

        // ...and the record of it is good enough to serve the episode
        // back out of the shared season folder. A sibling sitting beside
        // it must not be what comes back.
        std::fs::write(
            dest.join("My Show - S01E03 - Doors [1080p].mkv"),
            payload(400_000, 13),
        )
        .unwrap();
        let id = hist
            .split("\"nzo_id\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("nzo_id")
            .to_string();
        let resp = raw(
            port,
            format!("GET /stream/{id}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        let cut = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("no headers") + 4;
        let (head, served) = resp.split_at(cut);
        let head = String::from_utf8_lossy(head).to_string();
        assert!(head.contains("200 OK"), "play refused the titled episode: {head}");
        assert_eq!(
            served,
            &payload(200_000, 11)[..],
            "served the sibling, not the episode this job filed"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reported against 1.0.9: an F1 round finished as
/// "1fRbH6e0eX8v5hv7fSyXgBb.mkv" with every rename option ticked. The
/// smart renamer declines event posts on purpose (every round would
/// reduce to "Formula1 (2026)" and collide), but the decline must not
/// leave an obfuscated stem sitting inside a perfectly named folder.
#[tokio::test(flavor = "multi_thread")]
async fn obfuscated_event_release_still_gets_named() {
    let dir = std::env::temp_dir().join(format!("nzbfast-obf-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // The job carries the real release name; the article inside does not.
    let rel = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR";
    let inner = "1fRbH6e0eX8v5hv7fSyXgBb";
    let video = payload(200_000, 21);
    let mut articles = HashMap::new();
    let vsegs = make_file_articles(
        &format!("{inner}.mkv"),
        &video,
        40_000,
        "obf",
        &mut articles,
    );
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{inner}.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        vsegs.len()
    ));
    for (id, bytes, num) in vsegs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Pin the de-obfuscation fallback specifically: with extra words
        // ON (the default) this release is named from its own event
        // words instead, which obfuscated_event_release_keeps_its_words
        // covers.
        let r = http(
            port,
            "/api?mode=config&name=rename_extra_words&value=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{rel}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // The folder keeps the release name (it always did); the point of
        // the fix is that the VIDEO now does too, instead of staying
        // "1fRbH6e0eX8v5hv7fSyXgBb.mkv".
        let job = dir2.join("complete").join(rel);
        assert_eq!(
            std::fs::read(job.join(format!("{rel}.mkv"))).expect("video renamed to the release"),
            payload(200_000, 21)
        );
        assert!(
            !job.join(format!("{inner}.mkv")).exists(),
            "obfuscated stem survived"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the F1 report: with rename_extra_words on (the
/// default) the event is named from the words that distinguish it, so a
/// whole season does not collapse onto one folder.
#[tokio::test(flavor = "multi_thread")]
async fn obfuscated_event_release_keeps_its_words() {
    let dir = std::env::temp_dir().join(format!("nzbfast-evw-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let rel = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR";
    let inner = "1fRbH6e0eX8v5hv7fSyXgBb";
    let video = payload(200_000, 21);
    let mut articles = HashMap::new();
    let vsegs = make_file_articles(
        &format!("{inner}.mkv"),
        &video,
        40_000,
        "evw",
        &mut articles,
    );
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{inner}.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        vsegs.len()
    ));
    for (id, bytes, num) in vsegs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(cfg.contains("\"rename_extra_words\":true"), "should default on: {cfg}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{rel}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        let tidy = "Formula1 2026 Round11 Hungary Race F1TV 2160p";
        let job = dir2.join("complete").join(tidy);
        assert!(
            job.is_dir(),
            "expected the event named from its own words; complete/ holds {:?}",
            std::fs::read_dir(dir2.join("complete"))
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::read(job.join(format!("{tidy}.mkv"))).expect("video matches the folder"),
            payload(200_000, 21)
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Drag-to-reorder: `mode=queue&name=switch&value=<nzo_id>&value2=<pos>`
/// moves a queued job to that index (SAB parity for the dashboard's drag
/// handles). Out-of-range positions clamp; unknown ids are refused.
#[tokio::test(flavor = "multi_thread")]
async fn queue_switch_reorders() {
    let dir = std::env::temp_dir().join(format!("nzbfast-switch-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // No articles needed - the queue stays paused, nothing downloads.
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);

        let upload = |name: &str| -> String {
            let xml = format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"1000\" number=\"1\">{name}@x</segment>\n    </segments>\n  </file>\n</nzb>\n"
            );
            let boundary = "----switchb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{name}.nzb\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let a = upload("sw-a.bin");
        let b = upload("sw-b.bin");
        let c = upload("sw-c.bin");

        let order = |q: &str| {
            let mut ids: Vec<(usize, &str)> = [&a, &b, &c]
                .iter()
                // Quote-anchored: nzo ids are sequential, so a bare find
                // of ...nzbfast1 would also match inside ...nzbfast10.
                .map(|id| (q.find(&format!("{id}\"")).expect("id in queue"), id.as_str()))
                .collect();
            ids.sort();
            ids.into_iter().map(|(_, id)| id.to_string()).collect::<Vec<_>>()
        };

        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(order(&q), vec![a.clone(), b.clone(), c.clone()], "{q}");

        // Move c to the front.
        let r = http(
            port,
            &format!("/api?mode=queue&name=switch&value={c}&value2=0&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true") && r.contains("\"position\":0"), "{r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(order(&q), vec![c.clone(), a.clone(), b.clone()], "{q}");

        // Out-of-range position clamps to the end.
        let r = http(
            port,
            &format!("/api?mode=queue&name=switch&value={c}&value2=99&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true") && r.contains("\"position\":2"), "{r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(order(&q), vec![a.clone(), b.clone(), c.clone()], "{q}");

        // Unknown id is refused.
        let r = http(
            port,
            "/api?mode=queue&name=switch&value=SABnzbd_nzo_nope&value2=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");

        // §96 (AltMount audit, item 6): a move to the FRONT means "run
        // this next" - nzb360 sends value2=0 expecting that. Position
        // only breaks ties within a priority, so the moved job adopts
        // the highest priority present among the other queued jobs
        // (capped at High - a reorder never mints Force). A move
        // anywhere else changes no priority.
        let prio_of = |q: &str, id: &str| -> String {
            let v: serde_json::Value = serde_json::from_str(q).unwrap();
            v["queue"]["slots"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["nzo_id"] == id)
                .unwrap()["priority"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={b}&value2=1&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // c (Normal) to the end first: no bump anywhere but the front.
        let r = http(
            port,
            &format!("/api?mode=queue&name=switch&value={c}&value2=99&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(prio_of(&q, &c), "Normal", "{q}");
        // c to the front: it adopts b's High so it genuinely runs next.
        let r = http(
            port,
            &format!("/api?mode=queue&name=switch&value={c}&value2=0&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true") && r.contains("\"position\":0"), "{r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(order(&q), vec![c.clone(), a.clone(), b.clone()], "{q}");
        assert_eq!(prio_of(&q, &c), "High", "{q}");
        assert_eq!(prio_of(&q, &a), "Normal", "{q}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Slow-job watchdog: a job whose articles live only on one SLOW server
/// (the other server 430s everything) is auto-deferred to the back of
/// the queue while a fast job waits - the fast job completes first, and
/// the deferred one then resumes from its journal and finishes too.
#[tokio::test(flavor = "multi_thread")]
async fn slow_single_server_job_deferred() {
    let dir = std::env::temp_dir().join(format!("nzbfast-defer-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Fast server: warmup + fast job articles, tiny per-article delay so
    // completed-job averages are measured over a real span. Slow server:
    // ONLY the slow job's articles, 250 ms per article (~160 KB/s at 2
    // connections vs multi-MB/s fast → far under the 40% threshold).
    let mut fast_articles = HashMap::new();
    // Big enough that its network phase lasts ≥0.5 s (the guard for
    // recording a completed-job average into the session-best rate).
    let warm_segs = make_file_articles(
        "warm.bin",
        &payload(8_000_000, 7),
        40_000,
        "wm",
        &mut fast_articles,
    );
    let fastj_segs = make_file_articles(
        "fastjob.bin",
        &payload(1_600_000, 9),
        40_000,
        "fj",
        &mut fast_articles,
    );
    let mut slow_articles = HashMap::new();
    let slow_segs = make_file_articles(
        "slowjob.bin",
        &payload(3_000_000, 11),
        20_000,
        "sj",
        &mut slow_articles,
    );
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

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };

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

    let (warm_xml, fast_xml, slow_xml) = (
        nzb_for("warm.bin", &warm_segs),
        nzb_for("fastjob.bin", &fastj_segs),
        nzb_for("slowjob.bin", &slow_segs),
    );
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----deferb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // Warmup on the fast server establishes the session-best rate.
        let warm_id = upload(&warm_xml, "warm.nzb");
        poll(&|_q, h| h.contains(&warm_id) && h.contains("Completed"), "warmup completion");

        // Slow job starts (only candidate); fast job queues behind it.
        let slow_id = upload(&slow_xml, "slowjob.nzb");
        poll(&|q, _h| q.contains(&slow_id) && q.contains("Downloading"), "slow job start");
        let fast_id = upload(&fast_xml, "fastjob.nzb");

        // The watchdog defers the slow job (warmup 2 s + window 3 s).
        let (q, _) = poll(
            &|q, _h| q.contains("\"deferred\":true"),
            "watchdog deferral of the slow job",
        );
        assert!(q.contains(&slow_id), "{q}");
        assert!(q.contains("defer_reason"), "{q}");

        // The fast job overtakes and completes while the slow one is
        // still pending.
        let (_, h) = poll(
            &|_q, h| h.contains(&fast_id) && h.contains("Completed"),
            "fast job completion",
        );
        assert!(
            !h.contains(&slow_id),
            "slow job should still be queued when the fast one lands: {h}"
        );

        // The deferred job then runs (only candidate left), resumes from
        // its journal, and completes.
        poll(
            &|_q, h| h.contains(&slow_id) && h.matches("Completed").count() >= 3,
            "deferred job eventual completion",
        );
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/slowjob/slowjob.bin")).unwrap(),
        payload(3_000_000, 11),
        "deferred job payload differs after journal resume"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A taken-down post must not hold the queue. Every article of the
/// "gone" job 430s, so not a byte arrives and the byte-share defer
/// verdict never applies (it bails at `total == 0`, treating a refusal
/// ladder as progress). The refusal counter is what separates this from
/// a wedged server - answers arrived, every one of them "no such
/// article" - and the watchdog defers on it so the healthy job behind it
/// runs.
///
/// Regression for 14 Aug 2026: two 21-day-old releases whose articles
/// were all taken down each held the queue 10+ minutes at 0.0 MB/s.
#[tokio::test(flavor = "multi_thread")]
async fn gone_post_defers_so_the_queue_moves_on() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gonedefer-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // The server holds ONLY the good job's articles. The gone job's ids
    // are never inserted, so the mock 430s every one of them.
    let mut articles = HashMap::new();
    let good_segs = make_file_articles(
        "goodjob.bin",
        &payload(1_600_000, 31),
        40_000,
        "gd",
        &mut articles,
    );
    let mut absent = HashMap::new();
    let gone_segs = make_file_articles(
        "gonejob.bin",
        &payload(4_000_000, 33),
        20_000,
        "gn",
        &mut absent,
    );
    // Enough segments that one window clears the refusal floor set below
    // several times over, with retries on top.
    assert!(gone_segs.len() >= 100, "{} segments", gone_segs.len());
    // `missing_delay_ms` is what makes this a queue-holding job rather
    // than a fast failure: refused instantly, 200 segments are gone in
    // well under the warmup and the watchdog never gets to judge. Real
    // refusals cost a round trip, and the releases this regression comes
    // from carried ~15k segments - so pace the 430s and let the job sit
    // there being useless, which is the situation under test.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 10,
            missing_delay_ms: 120,
            ..Chaos::default()
        },
    )
    .await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };

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
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
            .env("NZBFAST_DEFER_GONE_MIN_MISSES", "8")
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

    let (gone_xml, good_xml) = (
        nzb_for("gonejob.bin", &gone_segs),
        nzb_for("goodjob.bin", &good_segs),
    );
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----goneb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // The gone job starts first (only candidate); the good one
        // queues behind it and would wait forever without the defer.
        let gone_id = upload(&gone_xml, "gonejob.nzb");
        poll(&|q, _h| q.contains(&gone_id) && q.contains("Downloading"), "gone job start");
        let good_id = upload(&good_xml, "goodjob.nzb");

        let (q, _) = poll(
            &|q, _h| q.contains("\"deferred\":true"),
            "watchdog deferral of the gone job",
        );
        assert!(q.contains(&gone_id), "the GONE job is the one to defer: {q}");
        assert!(
            q.contains("came back missing"),
            "defer must be attributed to refusals, not to a slow/dead server: {q}"
        );

        // The point of the whole arm: the healthy job behind it runs and
        // finishes while the gone one is still parked.
        let (_, h) = poll(
            &|_h, h| h.contains(&good_id) && h.contains("Completed"),
            "good job completion while the gone job is deferred",
        );
        assert!(
            !h.contains("gonejob"),
            "the gone job must not have completed: {h}"
        );
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/goodjob/goodjob.bin")).unwrap(),
        payload(1_600_000, 31),
        "the job that overtook the gone post should be byte-exact"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Idle-server prefetch: while job A grinds on the slow server (the fast
/// server 430s all its articles), the idle fast server starts queued job
/// B in a sidecar pipeline - B completes while A is still downloading,
/// and A still finishes normally afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn idle_servers_prefetch_next_job() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prefetch-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Slow server: ONLY job A's articles, 250 ms each (~160 KB/s at 2
    // conns → A runs ~19 s). Fast server: ONLY job B's articles.
    let mut slow_articles = HashMap::new();
    let a_segs = make_file_articles(
        "slowa.bin",
        &payload(3_000_000, 21),
        20_000,
        "sa",
        &mut slow_articles,
    );
    let mut fast_articles = HashMap::new();
    let b_segs = make_file_articles(
        "fastb.bin",
        &payload(2_000_000, 23),
        40_000,
        "fb",
        &mut fast_articles,
    );
    let slow_srv = MockServer::start(
        slow_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;
    // Mildly delayed so the sidecar run spans a few poll ticks - the test
    // wants to OBSERVE the transient "prefetching" flag, and an instant
    // localhost transfer finishes between two 200 ms polls.
    let fast_srv = MockServer::start(
        fast_articles,
        Chaos {
            delay_ms: 100,
            ..Chaos::default()
        },
    )
    .await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };

    let cfg = dir.join("config.json");
    // Distinct HOST STRINGS for the two loopback mocks ("localhost"
    // resolves to 127.0.0.1, and the connector prefers IPv4): host is
    // server identity throughout (exclusions, usage, stats), and the
    // sidecar's busy-host exclusion must not catch the idle server.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false}}]}}",
            slow_srv.addr.port(),
            fast_srv.addr.port()
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

    let (a_xml, b_xml) = (nzb_for("slowa.bin", &a_segs), nzb_for("fastb.bin", &b_segs));
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----prefb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // A starts (only job); B queues behind it.
        let a_id = upload(&a_xml, "slowa.nzb");
        poll(&|q, _| q.contains(&a_id) && q.contains("Downloading"), "job A start");
        let b_id = upload(&b_xml, "fastb.nzb");

        // The fast server is idle for A → sidecar starts B; the queue
        // reports it as prefetching.
        let (q, _) = poll(&|q, _| q.contains("\"prefetching\":true"), "sidecar start");
        assert!(q.contains(&b_id), "{q}");

        // B completes entirely on the idle server WHILE A still runs.
        let (q, h) = poll(
            &|_, h| h.contains(&b_id) && h.contains("Completed"),
            "B completion via sidecar",
        );
        assert!(
            q.contains(&a_id) && q.contains("Downloading"),
            "A should still be downloading when B lands: {q}"
        );
        assert!(!h.contains(&a_id), "{h}");

        // A still finishes normally on its slow server.
        poll(
            &|_, h| h.contains(&a_id) && h.matches("Completed").count() >= 2,
            "A eventual completion",
        );
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/fastb/fastb.bin")).unwrap(),
        payload(2_000_000, 23),
        "sidecar-completed payload differs"
    );
    assert_eq!(
        std::fs::read(dir.join("complete/slowa/slowa.bin")).unwrap(),
        payload(3_000_000, 21),
        "slow job payload differs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Connection borrowing when the ONLY idle server is dead: one healthy
/// server carries job A while the second rejects authentication. The
/// dead server moves no bytes, so by the byte test it looks idle - but a
/// sidecar built on it alone prefetches nothing (seen live in a
/// queue soak, 31 Jul, where this cost 34% line-idle), and simply
/// skipping the spawn loses the tail-overlap entirely (49 s line-idle of
/// a 144 s queue in that state). The monitor must instead borrow a
/// BOUNDED slice of the healthy busy server - here 2 of the account's
/// 8-connection headroom next to the active job's 4 - never the dead
/// one, and B completes on that slice while A still downloads at its
/// own full fleet.
#[tokio::test(flavor = "multi_thread")]
async fn prefetch_borrows_from_the_busy_server_when_no_healthy_idle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prefdead-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Healthy server: A's AND B's articles, 250 ms each so A's run is
    // wide enough for the monitor's warmup+window to elapse. Dead
    // server: no articles, rejects every AUTHINFO.
    let mut articles = HashMap::new();
    let a_segs = make_file_articles(
        "slowa.bin",
        &payload(4_000_000, 71),
        20_000,
        "da",
        &mut articles,
    );
    let b_segs = make_file_articles(
        "afterb.bin",
        &payload(400_000, 73),
        40_000,
        "db",
        &mut articles,
    );
    let good_srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;
    let dead_srv = MockServer::start(
        HashMap::new(),
        Chaos {
            auth_rejected: true,
            ..Chaos::default()
        },
    )
    .await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };

    let cfg = dir.join("config.json");
    // Credentials on the dead server so the client actually sends the
    // AUTHINFO the mock refuses; distinct host strings as elsewhere.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false,\"username\":\"u\",\"password\":\"wrong\"}}]}}",
            good_srv.addr.port(),
            dead_srv.addr.port()
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
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let log_path = d.log.clone();

    let (a_xml, b_xml) = (
        nzb_for("slowa.bin", &a_segs),
        nzb_for("afterb.bin", &b_segs),
    );
    let b_id = tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----prefd";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // A starts (only job); B queues behind it.
        let a_id = upload(&a_xml, "slowa.nzb");
        poll(&|q, _| q.contains(&a_id) && q.contains("Downloading"), "job A start");
        let b_id = upload(&b_xml, "afterb.nzb");

        // The monitor notes the dead idle server and borrows from the
        // busy one instead - the log carries both decisions.
        for i in 0..300 {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("borrowing from the busy server(s) instead") {
                break;
            }
            assert!(i < 299, "the monitor never noted the refused idle server:\n{log}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let borrow_line = log
            .lines()
            .find(|l| l.contains("borrowing connection(s) from busy server(s)"))
            .unwrap_or_else(|| panic!("no borrow spawn in the log:\n{log}"))
            .to_string();
        // The slice is bounded (2 = headroom cap, not the fleet's 4) and
        // built ONLY on the healthy busy host - never the refused one.
        assert!(borrow_line.contains("127.0.0.1 x2"), "wrong borrow slice: {borrow_line}");
        assert!(!borrow_line.contains("localhost"), "borrowed the dead server: {borrow_line}");

        // B completes on the borrowed slice WHILE A still downloads.
        let (q, _) = poll(
            &|_, h| h.contains(&b_id) && h.contains("Completed"),
            "B completion via borrowed sidecar",
        );
        assert!(
            q.contains(&a_id) && q.contains("Downloading"),
            "A should still be downloading when B lands: {q}"
        );

        // A still completes normally at its own pace: the borrow must
        // not have cost A its fleet. 200 articles at 250 ms over 4
        // connections is ~12.5 s connection-bound; a sidecar that stole
        // half the fleet would push A toward 25 s. Generous margin for
        // connect overhead and a loaded CI box, but well under starved.
        let (_, h) = poll(
            &|_, h| h.contains(&a_id) && h.matches("Completed").count() >= 2,
            "A completion",
        );
        // Keys serialize alphabetically, so a slot's elapsed_secs sits
        // BEFORE its nzo_id: the last one preceding A's id is A's.
        let a_elapsed: f64 = h
            .split(&a_id)
            .next()
            .and_then(|s| s.rsplit("\"elapsed_secs\":").next())
            .and_then(|s| s.trim().split(',').next())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| panic!("no elapsed_secs for A in history: {h}"));
        assert!(
            a_elapsed < 19.0,
            "active job slowed to {a_elapsed:.1}s (ideal ~12.5s) - the borrow starved it"
        );
        b_id
    })
    .await
    .unwrap();

    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        log.contains(&format!(
            "[prefetch] {b_id} completed entirely on borrowed connections"
        )),
        "B was not finished by the borrowed sidecar:\n{log}"
    );
    // The budget never double-counted: the healthy server saw the active
    // job's 4 connections plus at most the 2 borrowed ones - a sidecar
    // that built a FULL second fleet (or a primary re-run of B) would
    // push this to 8+.
    let conns = good_srv.accepted.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        (4..=7).contains(&conns),
        "healthy server saw {conns} connections, want the 4-conn fleet + ≤2 borrowed + slack"
    );
    assert_eq!(
        std::fs::read(dir.join("complete/afterb/afterb.bin")).unwrap(),
        payload(400_000, 73),
        "B payload differs"
    );
    assert_eq!(
        std::fs::read(dir.join("complete/slowa/slowa.bin")).unwrap(),
        payload(4_000_000, 71),
        "A payload differs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// M23e: pause stops the ACTIVE transfer, not just new jobs. The
/// in-flight job aborts and suspends back to Queued (never into history
/// as Failed), and resume finishes it from the article journal -
/// byte-identical output.
#[tokio::test(flavor = "multi_thread")]
async fn pause_suspends_active_download() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pause-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // 2 MB at a 250 KB/s cap ≈ 8 s of transfer - a wide pause window.
    let data = payload(2_000_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("suspend.bin", &data, 40_000, "pz", &mut articles);
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--speedlimit")
            .arg("250K")
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;suspend.bin&quot; yEnc (1/50)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"suspend.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");

        // Wait for the transfer to actually start.
        // Slot-level status only: the queue-level "status" reads
        // "Downloading" whenever ANY slot exists. This used to anchor on
        // the rendered pair `"status":"Downloading","timeleft"`, which
        // depended on nothing ever sorting between those two keys -
        // issue #34's SAB field parity added `time_added` and broke it.
        // Read the slot instead.
        let slot_status = |q: &str, want: &str| {
            serde_json::from_str::<serde_json::Value>(q)
                .ok()
                .and_then(|v| v["queue"]["slots"].as_array().cloned())
                .is_some_and(|s| s.iter().any(|s| s["status"] == want))
        };
        let slot_downloading = |q: &str| slot_status(q, "Downloading");
        let mut started = false;
        for _ in 0..50 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if slot_downloading(&q) {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(started, "download never started");

        // PAUSE: the active job must leave Downloading and go back to
        // Queued - and must NOT appear in history as Failed.
        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        // IMMEDIATE feedback: the suspended slot reads Paused within a
        // second of the pause ack (not Downloading until the pipeline
        // finishes unwinding).
        let mut fast = false;
        for _ in 0..5 {
            let q = http(port, "/api?mode=queue&output=json", None);
            // Slot state, read rather than pattern-matched on rendered
            // key order - see `slot_downloading` above.
            if slot_status(&q, "Paused") {
                fast = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(fast, "pause not reflected as Paused within 1 s");
        let mut suspended = false;
        for _ in 0..50 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"paused\":true") && !slot_downloading(&q) && q.contains("suspend") {
                suspended = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(suspended, "pause did not suspend the active download");
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(
            !h.contains("Failed") && !h.contains("Completed"),
            "suspended job leaked into history: {h}"
        );
        // Still suspended a moment later (nothing restarted it).
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(!slot_downloading(&q), "job restarted while paused: {q}");

        // RESUME: finishes from the journal.
        let r = http(port, "/api?mode=resume&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let mut done = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(!h.contains("\"Failed\""), "resume failed: {h}");
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "resumed download never completed");
    })
    .await
    .unwrap();

    assert_eq!(
        std::fs::read(dir.join("complete/suspend/suspend.bin")).unwrap(),
        data,
        "resumed output not byte-identical"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Live settings changed via mode=config must survive a daemon restart:
/// each set persists to settings.json immediately, and startup restores
/// it. (The auto_* bools plus update_checks/update_url/index_deepen/
/// bench_interval used to be set-but-never-restored - a restart silently
/// reverted them to defaults while settings.json still showed the
/// user's choice.)
#[tokio::test(flavor = "multi_thread")]
async fn live_settings_survive_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-liveset-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A server entry is required by config load; nothing connects to it
    // in this test (no jobs are queued), so a dead port is fine.
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
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
            .arg(dir.join("complete"));
        c
    };

    // Every value differs from its startup default. update_url set to
    // empty exercises the meaningful-empty case (= checks disabled).
    let sets: &[(&str, &str)] = &[
        ("auto_speed", "0"),
        ("auto_defer", "0"),
        ("auto_prefetch", "0"),
        ("auto_connections", "0"),
        ("update_checks", "0"),
        ("update_url", ""),
        ("index_deepen", "123456"),
        ("bench_interval", "6"),
        // TODO 101: the volume-eating unpack mode. A string setting, so
        // `settings_survive_a_restart` (which discovers booleans off the
        // live response) does not cover it - this list is where its
        // three places are held together.
        ("unpack_eat_volumes", "low_disk"),
        // The pre feed's two capacity knobs. They were constants until
        // 2 Aug 2026; the reason they are settings is that the PRUNE and
        // the seed IMPORTER have to agree on the cap, and a constant the
        // importer could not see meant importing rows the prune ate.
        #[cfg(feature = "indexer")]
        ("predb_max_rows", "400000"),
        #[cfg(feature = "indexer")]
        ("predb_seed_days", "90"),
        // 24D user categories: URL-encoded
        // [{"slug":"formula-1","name":"Formula 1","match":"formula1","base":"movie"}]
        (
            "custom_categories",
            "%5B%7B%22slug%22%3A%22formula-1%22%2C%22name%22%3A%22Formula%201%22%2C%22match%22%3A%22formula1%22%2C%22base%22%3A%22movie%22%7D%5D",
        ),
        // Opt-in indexing: the interest keys the user chose. Unknown
        // keys are dropped, so what comes back is exactly the offered
        // set they asked for and nothing else.
        #[cfg(feature = "indexer")]
        ("index_interests", "linux%2Csports%2Cnot-a-thing"),
        // 24D: a watchlist entry targeting that category - kind is the
        // slug, and a year pin is legal on it (an event post's year is
        // its season).
        // §151: an external list source. The url is a CREDENTIAL - a
        // Plex watchlist address is a bearer capability - so what goes
        // in here must not come back out of get_config, and it must
        // still be there after the restart. URL-encoded
        // [{"id":9,"name":"my plex","kind":"plex","mode":"rss",
        //   "url":"https://rss.plex.tv/secret-token","enabled":true,
        //   "interval_secs":21600,"min_quality":"720p",
        //   "target_quality":"1080p","category":"tv","upgrade":true,
        //   "series_scope":"new"}]
        (
            "list_sources",
            "%5B%7B%22id%22%3A9%2C%22name%22%3A%22my%20plex%22%2C%22kind%22%3A%22plex%22%2C%22mode%22%3A%22rss%22%2C%22url%22%3A%22https%3A%2F%2Frss.plex.tv%2Fsecret-token%22%2C%22enabled%22%3Atrue%2C%22interval_secs%22%3A21600%2C%22min_quality%22%3A%22720p%22%2C%22target_quality%22%3A%221080p%22%2C%22category%22%3A%22tv%22%2C%22upgrade%22%3Atrue%2C%22series_scope%22%3A%22new%22%7D%5D",
        ),
        (
            "watchlist",
            "%5B%7B%22id%22%3A1%2C%22kind%22%3A%22formula-1%22%2C%22title%22%3A%22Formula1%22%2C%22year%22%3A2026%2C%22seasons%22%3A%22%22%2C%22episodes%22%3A%22%22%2C%22min_quality%22%3A%22any%22%2C%22target_quality%22%3A%221080p%22%2C%22upgrade%22%3Atrue%2C%22delete_old%22%3Afalse%2C%22category%22%3A%22sport%22%2C%22enabled%22%3Atrue%7D%5D",
        ),
    ];
    let expect: &[&str] = &[
        "\"auto_speed\":false",
        "\"auto_defer\":false",
        "\"auto_prefetch\":false",
        "\"auto_connections\":false",
        "\"update_checks\":false",
        "\"update_url\":\"\"",
        "\"index_deepen\":123456",
        "\"bench_interval\":6",
        #[cfg(feature = "indexer")]
        "\"predb_max_rows\":400000",
        #[cfg(feature = "indexer")]
        "\"predb_seed_days\":90",
        "\"slug\":\"formula-1\"",
        "\"base\":\"movie\"",
        "\"kind\":\"formula-1\"",
        "\"title\":\"Formula1\"",
        #[cfg(feature = "indexer")]
        "\"index_interests\":\"linux,sports\"",
        "\"unpack_eat_volumes\":\"low_disk\"",
        // §151: the source survives, and the UI learns only that an
        // address is stored. `remove_missing` is the EFFECTIVE answer,
        // and false is the public promise for an RSS source - it
        // truncates at fifty titles, so falling off the end of it is
        // indistinguishable from being taken off the list.
        "\"name\":\"my plex\"",
        "\"has_url\":true",
        "\"remove_missing\":false",
    ];

    let a = serve(&dir, &build).await;
    let port_a = a.port;
    tokio::task::spawn_blocking(move || {
        for (name, value) in sets {
            let r = http(
                port_a,
                &format!("/api?mode=config&name={name}&value={value}&apikey=sekrit&output=json"),
                None,
            );
            assert!(r.contains("\"status\":true"), "set {name}: {r}");
        }
        // Applied live before any restart.
        let c = http(port_a, "/api?mode=get_config&apikey=sekrit&output=json", None);
        for e in expect {
            assert!(c.contains(e), "live after set, missing {e}: {c}");
        }
        // TODO 101: an unknown mode is refused outright rather than
        // quietly falling back to "off" - the three values decide
        // whether downloaded volumes get deleted mid-extraction, and a
        // typo must not be answered with a guess.
        let r = http(
            port_a,
            "/api?mode=config&name=unpack_eat_volumes&value=sometimes&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");
        // ...and the per-job consent is refused for an nzo_id nobody
        // holds, rather than silently reporting success. (It is offered
        // at all only because the mode above is `low_disk`.)
        let r = http(
            port_a,
            "/api?mode=eat_volumes&value=no-such-job&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("unknown nzo_id"), "{r}");
        // The capacity knobs clamp rather than refuse: a number outside
        // the sane range is a typo, and a typo must not leave the feed
        // table with a cap of 1. The write reply only says "saved", so
        // the clamp is read back from the config. Slim builds have no
        // pre feed and refuse the setting outright.
        #[cfg(feature = "indexer")]
        {
            for (name, value) in [("predb_max_rows", "1"), ("predb_seed_days", "9999")] {
                http(
                    port_a,
                    &format!("/api?mode=config&name={name}&value={value}&apikey=sekrit&output=json"),
                    None,
                );
            }
            let c = http(port_a, "/api?mode=get_config&apikey=sekrit&output=json", None);
            assert!(
                c.contains("\"predb_max_rows\":10000"),
                "predb_max_rows floor not applied: {c}"
            );
            assert!(
                c.contains("\"predb_seed_days\":366"),
                "predb_seed_days ceiling not applied: {c}"
            );
            // Put the round-trip values back for the restart half.
            for (name, value) in [("predb_max_rows", "400000"), ("predb_seed_days", "90")] {
                http(
                    port_a,
                    &format!("/api?mode=config&name={name}&value={value}&apikey=sekrit&output=json"),
                    None,
                );
            }
        }
        // 24D: a category slug shadowing a built-in kind is refused, and
        // the refusal must not clobber the saved list.
        let r = http(
            port_a,
            "/api?mode=config&name=custom_categories&value=%5B%7B%22slug%22%3A%22movie%22%2C%22match%22%3A%22x%22%7D%5D&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("built-in"), "reserved slug accepted: {r}");
        let c = http(port_a, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(c.contains("\"slug\":\"formula-1\""), "saved list clobbered: {c}");
        // §151: the watchlist address never comes back out. get_config
        // is a read anyone holding the API key can make from a browser,
        // and having that address IS reading the user's Plex watchlist.
        assert!(!c.contains("secret-token"), "the list address leaked: {c}");
        // ...and a blank one on the next save keeps the stored one
        // rather than erasing it, which is what the round-trip of a
        // masked field looks like. Matched on the id, so a RENAME does
        // not move a credential between sources.
        let r = http(
            port_a,
            "/api?mode=config&name=list_sources&value=%5B%7B%22id%22%3A9%2C%22name%22%3A%22renamed%22%2C%22kind%22%3A%22plex%22%2C%22mode%22%3A%22rss%22%2C%22url%22%3A%22%22%2C%22series_scope%22%3A%22new%22%7D%5D&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let c = http(port_a, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(c.contains("\"has_url\":true"), "blank erased the address: {c}");
        assert!(!c.contains("secret-token"), "{c}");
        // A kind we cannot read is refused outright rather than fetched
        // blindly, and the refusal must not clobber what is saved.
        let r = http(
            port_a,
            "/api?mode=config&name=list_sources&value=%5B%7B%22id%22%3A9%2C%22kind%22%3A%22trakt%22%2C%22mode%22%3A%22rss%22%7D%5D&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "unknown kind accepted: {r}");
        // Put the round-trip name back for the restart half.
        let r = http(
            port_a,
            "/api?mode=config&name=list_sources&value=%5B%7B%22id%22%3A9%2C%22name%22%3A%22my%20plex%22%2C%22kind%22%3A%22plex%22%2C%22mode%22%3A%22rss%22%2C%22url%22%3A%22%22%2C%22series_scope%22%3A%22new%22%7D%5D&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
    })
    .await
    .unwrap();
    // kill -9 (KillOnDrop kills and reaps): persistence must not depend
    // on a graceful shutdown.
    drop(a);

    let b = serve(&dir, &build).await;
    let port_b = b.port;
    tokio::task::spawn_blocking(move || {
        let c = http(
            port_b,
            "/api?mode=get_config&apikey=sekrit&output=json",
            None,
        );
        for e in expect {
            assert!(c.contains(e), "lost across restart, missing {e}: {c}");
        }
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon that cannot have the port it was given must leave the data
/// directory exactly as it found it.
///
/// The bind used to be the LAST step of startup, so a losing daemon had
/// already minted a first-run API key, created `.spool` and written
/// settings.json before it discovered the port was taken. Those writes
/// are not incidental clutter - they ARE the answer to "is this a fresh
/// install?" that `legacy_rename_punctuation` and `first_run_apikey`
/// read. A failed start therefore rewrote the question for the next one.
///
/// That was a live flake rather than a theoretical one: `serve()` above
/// re-launches on a fresh port when it loses the race for an OS-assigned
/// one, and under `cargo test --workspace` (many suites, many daemons,
/// all racing for ports) attempt 1's corpse told attempt 2 it was an
/// upgrade. `obfuscated_event_release_keeps_its_words` then filed its
/// download as `Formula1 (2026) ... [2160p]` - the pre-upgrade
/// punctuation shape - and nothing about the failure looked like a port
/// problem. The second half of this test is that exact sequence.
///
/// ONE DELIBERATE EXCEPTION, which this test does not exercise: the bind
/// sits AFTER first_run_apikey, so a losing start on a genuine first run
/// still leaves the minted `apikey` file. That is intentional. The key
/// gate has to run first - it is what refuses to start on a broken
/// credential, and binding ahead of it would report a lost port where an
/// operator must be told the key file is unreadable (firstrun_key.rs
/// pins that). The orphan key is harmless: `legacy_rename_punctuation`
/// consults settings.json and `.spool` only, so the key feeds no
/// fresh-vs-existing verdict, and the next start reuses it correctly -
/// and MintDisclosure fires on that exit, so the user is told the key
/// exists. runtime.json cannot be an artefact either: it is written only
/// after the listener exists, just before the readiness banner.
/// This test runs keyless (NZBFAST_OPEN=1), so nothing is minted and the
/// directory must come out completely untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_loses_its_port_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bindfail-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();

    // Squat the port for real, and keep holding it while the daemon
    // tries: a closed listener would let the daemon win.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = squatter.local_addr().unwrap().port();

    let out = tokio::task::spawn_blocking({
        let cfg = cfg.clone();
        let dir = dir.clone();
        move || {
            Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .env("NZBFAST_NO_ENRICH", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(taken.to_string())
                .arg("--out")
                .arg(dir.join("complete"))
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(
        !out.status.success(),
        "the daemon claimed a port that was taken"
    );
    let said =
        String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    assert!(
        said.contains(&format!("bind 127.0.0.1:{taken}")),
        "a lost port must say so plainly: {said}"
    );

    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["config.json".to_string()],
        "a daemon that never bound touched the data directory: {left:?}"
    );

    // ...and because it touched nothing, the next start still reads the
    // directory as the fresh install it actually is.
    drop(squatter);
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let body = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let cfg = &v["config"]["nzbfast"];
        for key in ["rename_year_parens", "rename_quality_brackets"] {
            assert_eq!(
                cfg[key], false,
                "a failed start upgraded a fresh install behind our back - {key}: {cfg}"
            );
        }
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pause is a deliberate act, and a restart used to undo it silently:
/// the queue came back at full speed with nothing on screen saying the
/// user's choice had been dropped. An update, a crash or a reboot all hit
/// this, and a metered connection pays for it.
///
/// Four cases, because the naive fix breaks two of them:
///  - a plain pause survives a kill -9 (persistence cannot depend on a
///    graceful shutdown - a crash is exactly when it matters);
///  - a resume is not "no news", it clears the pause for good;
///  - a timed pause whose deadline passed while the daemon was down comes
///    back RUNNING - "pause for 30 minutes" is a statement about when
///    downloading may start again, not a fresh 30 minutes on every boot;
///  - `mode=shutdown` pauses the queue as part of winding down, and that
///    internal pause must NOT be recorded, or every clean quit would come
///    back paused.
#[tokio::test(flavor = "multi_thread")]
async fn pause_survives_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pausep-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Nothing connects to it (no jobs are queued), so a dead port is fine.
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    };
    let settings = dir.join("settings.json");
    let paused_now = |port: u16| {
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"paused\":"), "no queue paused flag: {q}");
        q.contains("\"paused\":true")
    };

    // 1. PAUSE, then kill -9.
    let a = serve(&dir, &build).await;
    let port_a = a.port;
    tokio::task::spawn_blocking(move || {
        let r = http(port_a, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(paused_now(port_a), "pause did not take effect");
    })
    .await
    .unwrap();
    drop(a);

    // Still paused on the next boot - the whole point.
    let b = serve(&dir, &build).await;
    let port_b = b.port;
    tokio::task::spawn_blocking(move || {
        assert!(paused_now(port_b), "pause was lost across a restart");
        // 2. RESUME, so the next boot must come back running.
        let r = http(port_b, "/api?mode=resume&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(!paused_now(port_b), "resume did not take effect");
    })
    .await
    .unwrap();
    drop(b);
    let s = std::fs::read_to_string(&settings).unwrap_or_default();
    assert!(!s.contains("\"paused\""), "resume left a pause behind: {s}");

    let c = serve(&dir, &build).await;
    let port_c = c.port;
    tokio::task::spawn_blocking(move || {
        assert!(!paused_now(port_c), "came back paused after a resume");
        // 3. A timed pause, forced to look like one that fell due while
        // the daemon was down. Set it live so the deadline is written by
        // the daemon, then wind the deadline back on disk.
        let r = http(port_c, "/api?mode=pause&value=30&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(paused_now(port_c), "timed pause did not take effect");
    })
    .await
    .unwrap();
    drop(c);
    let s = std::fs::read_to_string(&settings).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let deadline = v["pause_until_unix"]
        .as_i64()
        .expect("timed pause wrote no deadline");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        deadline > now + 25 * 60 && deadline <= now + 30 * 60,
        "deadline is not ~30 min out ({deadline} vs now {now}) - stored as an interval?"
    );
    v["pause_until_unix"] = serde_json::json!(now - 5);
    std::fs::write(&settings, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let d = serve(&dir, &build).await;
    let port_d = d.port;
    tokio::task::spawn_blocking(move || {
        assert!(
            !paused_now(port_d),
            "an expired timed pause came back paused"
        );
        // 4. A clean shutdown pauses internally; that must not be saved.
        let r = http(
            port_d,
            "/api?mode=shutdown&output=json",
            Some(("text/plain", b"")),
        );
        assert!(r.contains("\"status\":true"), "{r}");
    })
    .await
    .unwrap();
    // Let the daemon finish exiting before reading what it left on disk.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    drop(d);
    let s = std::fs::read_to_string(&settings).unwrap_or_default();
    assert!(
        !s.contains("\"paused\""),
        "a clean shutdown recorded its own internal pause: {s}"
    );

    let e = serve(&dir, &build).await;
    let port_e = e.port;
    tokio::task::spawn_blocking(move || {
        assert!(
            !paused_now(port_e),
            "came back paused after a clean shutdown"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The two rename-punctuation toggles replaced behaviour that used to be
/// hard-coded ON. Fresh installs get the new default, but an install that
/// already has state has to keep the old shape: history cleanup recomputes
/// a filed episode's name from these settings, so flipping them under an
/// existing library orphans every file already named the old way.
///
/// The predicate is unit-tested; what is pinned here is that the daemon
/// actually starts its two flags from it. Both halves are asserted,
/// because a default that is unconditionally ON passes the upgrade case
/// on its own.
#[tokio::test(flavor = "multi_thread")]
async fn rename_punctuation_defaults_split_fresh_installs_from_upgrades() {
    let root = std::env::temp_dir().join(format!("nzbfast-renamedef-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&root);

    // Only a wizard answer on disk: still a fresh install.
    // Anything else: an install that has already been used.
    for (name, settings, want) in [
        ("fresh", r#"{"index_interests":"linux"}"#, false),
        ("upgrade", r#"{"index_deepen":123456}"#, true),
    ] {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.json");
        std::fs::write(
            &cfg,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                free_port()
            ),
        )
        .unwrap();
        std::fs::write(dir.join("settings.json"), settings).unwrap();
        let out = dir.join("complete");
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
                .arg(&out);
            c
        })
        .await;
        let port = d.port;
        tokio::task::spawn_blocking(move || {
            let body = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let cfg = &v["config"]["nzbfast"];
            for key in ["rename_year_parens", "rename_quality_brackets"] {
                assert_eq!(
                    cfg[key], want,
                    "{name} install: {key} must start {want} - an upgrade keeps the \
                     naming its library already uses, a fresh install gets the new \
                     default: {cfg}"
                );
            }
        })
        .await
        .unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// M32: a FIRST failure with missing articles gets
/// exactly ONE automatic retry after the cooldown. The retried run fails
/// again (articles still ghosts) and must NOT reschedule - the retry
/// counter stays at 1 and the job stays Failed.
#[tokio::test(flavor = "multi_thread")]
async fn auto_retry_fires_once_after_cooldown() {
    let dir = std::env::temp_dir().join(format!("nzbfast-autoretry-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // No articles on the server at all → every segment is a ghost and the
    // job fails with "download incomplete" (the transient shape).
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
    let ghost_segs: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("aghost{n}@x"), 40_000, n))
        .collect();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;ar.bin&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &ghost_segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .env("NZBFAST_AUTO_RETRY_SECS", "2")
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

    tokio::task::spawn_blocking(move || {
        let boundary = "----autoretryb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"ar.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json&apikey=sekrit",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let poll = |pred: &dyn Fn(&str) -> bool, what: &str| {
            for _ in 0..150 {
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&h) {
                    return h;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // First failure parks with retry count 0…
        let h = poll(&|h: &str| h.contains("Failed"), "first failure");
        // …and SAYS SO on the wire. Everything the daemon had already
        // decided about this row used to stop at its own log line: the
        // user was shown a hard FAILURE for something scheduled to fix
        // itself, and then watched the row vanish from History.
        assert!(
            h.contains("\"auto_retry_at\":") && !h.contains("\"auto_retry_at\":null"),
            "an armed retry must ship its due time: {h}"
        );
        // What it is waiting for - which is also what chose the delay.
        let why = if h.contains("\"auto_retry_why\":\"transport\"") {
            "transport"
        } else {
            assert!(
                h.contains("\"auto_retry_why\":\"propagation\""),
                "an armed retry must ship its reason token: {h}"
            );
            "propagation"
        };
        // The reason token and the classifier must agree: a transport
        // cooldown is the SHORT one precisely because the post is not
        // implicated, so disagreeing here would mis-caption the wait.
        assert_eq!(
            why == "transport",
            h.contains("\"fail_kind\":\"transport\""),
            "auto_retry_why must follow fail_kind: {h}"
        );
        // ...and the drawer's single remedy rides along. This fixture's
        // post carries NO PAR2, which the message says outright ("nothing
        // can rebuild them"), so the sub-cause outranks the kind and the
        // offered action is another release - even though the daemon
        // still spends its one free retry first. The two are not in
        // conflict: the retry is the daemon's own last look, and `search`
        // is what is left for the user when it comes back empty.
        assert!(
            h.contains("\"fail_hint\":\"nopar2\"") && h.contains("\"fail_action\":\"search\""),
            "a post with no parity is answered by another release: {h}"
        );
        // …then the auto retry fires after ~2 s, runs, and fails again.
        let h = poll(
            &|h: &str| h.contains("\"retries\":1") && h.contains("Failed"),
            "the automatic retry to run and fail",
        );
        assert!(h.contains("Failed"), "{h}");
        // The requeue itself is announced. Without this ring the row the
        // user was told had FAILED simply left History and a download
        // nobody asked for appeared in the queue.
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(
            q.contains("\"auto_retried\":[{") && q.contains("\"nzo_id\":\"SABnzbd_nzo_nzbfast1\""),
            "the requeue must reach the dashboard as an event: {q}"
        );
        // The consumed stamp is cleared with its reason, so the row
        // cannot go on advertising a retry that already happened.
        assert!(
            h.contains("\"auto_retry_at\":null") && h.contains("\"auto_retry_why\":null"),
            "a spent retry clears both halves: {h}"
        );

        // One shot only: well past another cooldown, no third attempt.
        std::thread::sleep(std::time::Duration::from_secs(5));
        let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
        assert!(
            h.contains("\"retries\":1") && !h.contains("\"retries\":2"),
            "auto-retry must fire exactly once: {h}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A zip post whose container cannot be READ (here: zip magic over
/// bytes that are not an archive) - the shape a user reported as "it
/// downloaded and there was nothing there". Store/deflate zips now
/// unpack natively (see `zip_payload_post_unpacks_natively` below); this
/// pins what happens when one still cannot be produced.
///
/// Three things have to hold at once, and each of them was broken:
/// the queue warns BEFORE the download (the NZB's file list is enough
/// to know), the job FAILS with a reason naming the archive rather than
/// reporting a green "Completed" an *arr would act on by giving up, and
/// the archive is still on disk afterwards - the keep-media-only
/// tidy-up used to delete the one file we had just told the user to
/// unpack by hand.
#[tokio::test(flavor = "multi_thread")]
async fn zip_payload_post_fails_with_a_reason() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zip-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A movie-shaped release whose payload is one zip. Real local file
    // header magic so the on-disk detectors see a container, not just a
    // suggestive name.
    let stem = "Some.Movie.2019.1080p.BluRay.x264-TEST";
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&payload(200_000, 11));
    let mut articles = HashMap::new();
    let segs = make_file_articles(&format!("{stem}.zip"), &zip, 40_000, "zip", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{stem}.zip&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Keep-media-only ON: the setting that used to delete the zip.
        let r = http(
            port,
            "/api?mode=config&name=rename_media_only&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        // The warning is available from the queue, before a byte lands.
        // (A fast mock can finish first, so accept the history side too.)
        let mut warned = false;
        for _ in 0..150 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if q.contains("\"zip_packed\":true") {
                warned = true;
                break;
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") || h.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // Failed, not Completed. Every byte arrived, but the payload is
        // still packed, so the release delivered nothing importable -
        // and Completed is a verdict an *arr acts on by never looking
        // again. Failed is what makes it blocklist and grab a usable
        // release instead.
        assert!(hist.contains("\"Failed\""), "a zip payload must fail the job: {hist}");
        assert!(
            hist.contains("could not be unpacked"),
            "history must say why, not just that it failed: {hist}"
        );
        assert!(warned || hist.contains("\"zip_packed\":true"), "no zip warning anywhere: {hist}");

        // The whole point: the archive is still there. Auto-rename gives
        // the folder its tidy name, so find it rather than assume it.
        let out = std::fs::read_dir(dir2.join("complete"))
            .expect("complete dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir())
            .expect("job output dir");
        let left: Vec<String> = std::fs::read_dir(&out)
            .expect("output dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            left.iter().any(|n| n.ends_with(".zip")),
            "keep-media-only deleted the only copy of the payload: {left:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half, and the behaviour change: a REAL store+deflate zip
/// payload now unpacks natively, so the job COMPLETES with the payload
/// on disk instead of failing with the archive left for the user.
///
/// Keep-media-only is on, as in the failing twin - the sweep must keep
/// the extracted media and must not trip over the container it replaced.
#[tokio::test(flavor = "multi_thread")]
async fn zip_payload_post_unpacks_natively() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zipok-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let stem = "Some.Movie.2021.1080p.BluRay.x264-TEST";
    let movie: Vec<u8> = (0..300_000u32)
        .map(|i| (i as u8).wrapping_mul(37))
        .collect();
    let zip = nzbkit::zip::fixtures::zip_of(&[
        nzbkit::zip::fixtures::Spec::deflated("Some.Movie.2021.mkv", &movie),
        nzbkit::zip::fixtures::Spec::stored("readme.nfo", b"scene info"),
    ]);
    let mut articles = HashMap::new();
    let segs = make_file_articles(&format!("{stem}.zip"), &zip, 40_000, "zipok", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{stem}.zip&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    // This job COMPLETES, so it is the one zip test that reaches
    // post-processing, and keep-media-only below really deletes the
    // extracted `readme.nfo` through the real binary. Without this the
    // delete goes to the developer's Trash via Finder/AppleScript, which
    // on macOS is a SYNCHRONOUS call that blocks until Finder answers -
    // up to the ~2 minute AppleEvent timeout (see smart::remove_user_file,
    // whose latch only engages AFTER the first call returns). A job is not
    // filed to history until its cleanup returns, so a slow Finder blew
    // this test's 40 s history poll and looked exactly like a wedged job.
    // The failing twin never needs this: a failed job skips finalize.
    delete_without_the_trash(&cfg);
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=rename_media_only&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..200 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "a store/deflate zip must complete: {hist}");

        let out = std::fs::read_dir(dir2.join("complete"))
            .expect("complete dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir())
            .expect("job output dir");
        // The payload landed, byte-exact, and the container it came from
        // is gone (its bytes are the payload now). The auto-renamer gives
        // the media file the release name, so match on the extension.
        let mkv = walk_find_ext(&out, "mkv").unwrap_or_else(|| {
            panic!("no extracted payload under {}", out.display())
        });
        assert_eq!(std::fs::read(&mkv).unwrap(), movie, "extracted bytes differ");
        let left: Vec<String> = std::fs::read_dir(&out)
            .expect("output dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !left.iter().any(|n| n.ends_with(".zip")),
            "the container should be gone once its payload landed: {left:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Find a file by EXTENSION anywhere under `root`. The auto-renamer both
/// renames the payload to the release name and may tidy it into a
/// subfolder, so neither the name nor the depth is fixed.
fn walk_find_ext(root: &std::path::Path, ext: &str) -> Option<std::path::PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).ok()?.flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == ext) {
                return Some(p);
            }
        }
    }
    None
}

/// The other half of the zip story: a zip that is NOT the payload.
///
/// A `Subs/subs.zip`-style sidecar beside a feature that landed fine
/// must not fail anything - the user got what they came for. But it is
/// the case where the cleanup actually runs, and keep-media-only used to
/// delete every non-video file, destroying the one archive we had just
/// told the user to unpack by hand. So: Completed, the archive still on
/// disk, and the job carrying a note that names it.
#[tokio::test(flavor = "multi_thread")]
async fn zip_sidecar_is_noted_and_survives_cleanup() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zipside-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let stem = "Other.Movie.2021.1080p.BluRay.x264-TEST";
    let video = payload(300_000, 13);
    let mut extras = b"PK\x03\x04".to_vec();
    extras.extend_from_slice(&payload(50_000, 17));
    let mut articles = HashMap::new();
    let vsegs = make_file_articles(
        &format!("{stem}.mkv"),
        &video,
        40_000,
        "vid2",
        &mut articles,
    );
    let zsegs = make_file_articles(
        &format!("{stem}.zip"),
        &extras,
        40_000,
        "zip2",
        &mut articles,
    );
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in [
        (format!("{stem}.mkv"), &vsegs),
        (format!("{stem}.zip"), &zsegs),
    ] {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs.iter() {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Keep-media-only ON: the setting that used to eat the archive.
        let r = http(
            port,
            "/api?mode=config&name=rename_media_only&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            hist.contains("\"Completed\""),
            "a sidecar zip must not fail a job whose payload landed: {hist}"
        );
        assert!(
            hist.contains(&format!("\"unpack_blocked_by\":\"{stem}.zip\"")),
            "history must name the sidecar it left packed: {hist}"
        );

        // The feature was renamed and kept, and the archive survived the
        // non-media sweep that runs only on a successful job.
        let out = std::fs::read_dir(dir2.join("complete"))
            .expect("complete dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir())
            .expect("job output dir");
        let left: Vec<String> = std::fs::read_dir(&out)
            .expect("output dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            left.iter().any(|n| n.ends_with(".zip")),
            "keep-media-only deleted the archive again: {left:?}"
        );
        assert!(left.iter().any(|n| n.ends_with(".mkv")), "feature missing: {left:?}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn archive_shape_is_live_in_the_queue_and_kept_in_history() {
    // TODO §25: the extractor works out what a set is the moment the
    // first volume's headers parse. The queue payload must carry that
    // WHILE the job downloads (the dashboard badge), and the same tag
    // must survive onto the history entry once it finishes.
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-shape-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(12_000_000, 11);
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 12_000_000, &inner[..6_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 12_000_000, &inner[6_000_000..], true, false)],
            1,
        ),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("s.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("sh{i}"), &mut articles);
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            // Keep the download window open long enough to observe the
            // queue mid-flight.
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let boundary = "----shapeb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Live: the badge appears while the job is still Downloading.
        let mut live = String::new();
        for _ in 0..200 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"archive_shape\":\"rar5 store one-pass\"") {
                live = q;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            live.contains("\"status\":\"Downloading\""),
            "shape must show up while the job is still running: {live}"
        );

        // Latched: the finished entry keeps it for the history view.
        let mut hist = String::new();
        for _ in 0..400 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"status\":\"Completed\"") {
                hist = h;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            hist.contains("\"archive_shape\":\"rar5 store one-pass\""),
            "history entry lost the shape: {hist}"
        );
    })
    .await
    .unwrap();
    // The same fact reaches the log (and so `nzbfast get`'s console),
    // folded into the volume line rather than printed on its own.
    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        log.contains("extracting in-stream [RAR5 · stored · one-pass]"),
        "shape missing from the volume line:\n{log}"
    );
    // Folded into ONE volume line however many volumes land (the other
    // occurrence is the end-of-job summary, which is meant to carry it).
    assert_eq!(
        log.matches("extracting in-stream [").count(),
        1,
        "the shape must not repeat on every volume line:\n{log}"
    );
    assert!(
        log.contains("volumes never touched disk [RAR5 · stored · one-pass]:"),
        "shape missing from the final summary:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A retry must never be aimed at a directory another job has taken.
///
/// A Failed history record does not claim its output folder, so a re-add
/// of the same name is handed exactly that folder. Retrying the original
/// then put two live jobs in one directory - and once the re-add had
/// COMPLETED, the retry downloaded straight over its verified payload,
/// which is the collision a completed job's claim exists to prevent.
///
/// Both halves are pinned: an ordinary failed retry still reuses its own
/// folder in place (retrying a flaky post must not climb .2/.3/.4), and a
/// retry whose folder now holds someone else's finished download re-homes
/// beside it.
#[tokio::test(flavor = "multi_thread")]
async fn retry_re_homes_off_a_completed_re_adds_folder() {
    let dir = std::env::temp_dir().join(format!("nzbfast-retryhome-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 31);
    let mut articles = HashMap::new();
    let segs = make_file_articles("keeper.bin", &data, 40_000, "rh", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |file: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let ghost: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("rhghost{n}@x"), 40_000, n))
        .collect();
    let ghost_xml = nzb_for("gone.bin", &ghost);
    let good_xml = nzb_for("keeper.bin", &segs);

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
            // No M32 automatic retry: this test drives the retries itself.
            .env("NZBFAST_AUTO_RETRY_SECS", "0")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----rhb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        // The history slot for one job, once `pred` holds for it.
        let slot = |id: &str, pred: &dyn Fn(&serde_json::Value) -> bool, what: &str| -> serde_json::Value {
            for _ in 0..200 {
                let raw = http(port, "/api?mode=history&output=json", None);
                let v: serde_json::Value = serde_json::from_str(&raw)
                    .unwrap_or_else(|e| panic!("bad history JSON: {e}\n{raw}"));
                let hit = v["history"]["slots"]
                    .as_array()
                    .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned());
                match hit {
                    Some(s) if pred(&s) => return s,
                    _ => std::thread::sleep(std::time::Duration::from_millis(200)),
                }
            }
            panic!("timed out waiting for {what}");
        };
        // The storage path's last component - the whole question here is
        // whether it is the shared "alpha" or a private "alpha.2", and
        // comparing whole paths would only compare temp-dir symlinks.
        let folder = |s: &serde_json::Value| {
            Path::new(s["storage"].as_str().unwrap_or_default())
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default()
        };
        let failed = |s: &serde_json::Value| s["status"] == "Failed";

        // The original fails: nobody else is in its folder.
        let a_id = upload(&ghost_xml, "alpha.nzb");
        let s = slot(&a_id, &failed, "the first failure");
        assert_eq!(folder(&s), "alpha", "{s}");

        // Retried with the folder still its own: it must be reused in
        // place, or every retry of a flaky post would climb .2, .3, .4.
        let r = http(port, &format!("/api?mode=retry&value={a_id}&output=json"), None);
        assert!(r.contains("\"status\":true"), "{r}");
        let s = slot(&a_id, &|s| failed(s) && s["retries"] == 1, "the retried failure");
        assert_eq!(folder(&s), "alpha", "an ordinary failed retry must reuse its own folder: {s}");
        assert!(
            !dir2.join("complete/alpha.2").exists(),
            "a plain retry climbed to alpha.2"
        );

        // Same name added again. The failed record does not hold the
        // folder, so this one takes it - and finishes there.
        let b_id = upload(&good_xml, "alpha.nzb");
        let s = slot(&b_id, &|s| s["status"] == "Completed", "the re-add to complete");
        assert_eq!(folder(&s), "alpha", "{s}");
        assert_eq!(
            std::fs::read(dir2.join("complete/alpha/keeper.bin")).unwrap(),
            payload(200_000, 31),
            "the re-add did not land its payload"
        );

        // NOW retry the original. Its old folder is another job's verified
        // payload, so this download must go somewhere else.
        let r = http(port, &format!("/api?mode=retry&value={a_id}&output=json"), None);
        assert!(r.contains("\"status\":true"), "{r}");
        let s = slot(&a_id, &|s| failed(s) && s["retries"] == 2, "the second retried failure");
        assert_eq!(
            folder(&s),
            "alpha.2",
            "the retry was aimed at the completed job's folder: {s}"
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/alpha/keeper.bin")).unwrap(),
            payload(200_000, 31),
            "the retry wrote over the completed payload"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cancelling a download must not start the copy of it that was being
/// held back.
///
/// M14f parks a second grab of the same episode as an ALTERNATIVE and
/// promotes it when the original FAILS. A user delete aborts the transfer,
/// which arrives at the same place as a failure - so cancelling a download
/// unpaused its held duplicate and immediately started downloading the
/// very title the user had just cancelled. Genuine failures must still
/// promote, so both outcomes are driven here through one daemon.
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_a_download_leaves_its_duplicate_held() {
    let dir = std::env::temp_dir().join(format!("nzbfast-canceldupe-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    // The cancelled original is deliberately long (250 ms an article, 2
    // connections → ~6 s) so the delete lands mid-transfer.
    let orig = make_file_articles(
        "orig.bin",
        &payload(2_000_000, 51),
        40_000,
        "cd",
        &mut articles,
    );
    let held = make_file_articles(
        "held.bin",
        &payload(400_000, 53),
        40_000,
        "cd",
        &mut articles,
    );
    let alt = make_file_articles(
        "alt.bin",
        &payload(400_000, 55),
        40_000,
        "cd",
        &mut articles,
    );
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;

    let nzb_for = |file: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let ghost: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("cdghost{n}@x"), 40_000, n))
        .collect();
    let (orig_xml, held_xml) = (nzb_for("orig.bin", &orig), nzb_for("held.bin", &held));
    let (dead_xml, alt_xml) = (nzb_for("dead.bin", &ghost), nzb_for("alt.bin", &alt));

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
            // No M32 automatic retry: it holds the alternative back on a
            // first failure, and this test is about the promotion itself.
            .env("NZBFAST_AUTO_RETRY_SECS", "0")
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
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----cdb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&output=json", None);
                let h = http(port, "/api?mode=history&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };
        // ONE queue slot. The payload carries a queue-wide "status" of its
        // own, so a substring search for "Downloading" says nothing about
        // the job being asked about.
        let qslot = |q: &str, id: &str| -> serde_json::Value {
            let v: serde_json::Value = serde_json::from_str(q)
                .unwrap_or_else(|e| panic!("bad queue JSON: {e}\n{q}"));
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };
        // ONE history slot - the same rule as `qslot`, for a sharper
        // reason. A FAILED record carries `fail_detail`: that job's
        // console block, snapshotted out of the daemon's log ring. The
        // ring is a GLOBAL tee of stdout, so every line any other lane
        // printed while the failing job held the floor is in there too -
        // including `[queue] added <nzo_id> as ALTERNATIVE (duplicate
        // held)` for a job added mid-download. `h.contains(&id)`
        // therefore answers "is this id mentioned ANYWHERE in history",
        // which is not the question any assertion below asks.
        //
        // Not hypothetical: it is what made this test flaky under
        // `cargo test --workspace` (2 Aug 2026 - 7 failures in 10 loaded
        // runs, every one captured with history holding a single slot).
        // The runner picks a queued job on a 500 ms tick, so the dead job
        // could open its log bracket BEFORE the test's next upload
        // landed, and a loaded box is exactly what makes that upload slow
        // enough to lose that race. The poll then matched the
        // ALTERNATIVE's id inside the dead job's `fail_detail` and
        // returned before the alternative had downloaded at all.
        let hslot = |h: &str, id: &str| -> serde_json::Value {
            let v: serde_json::Value = serde_json::from_str(h)
                .unwrap_or_else(|e| panic!("bad history JSON: {e}\n{h}"));
            v["history"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };

        // Paused so both land in the queue before the duplicate check runs.
        http(port, "/api?mode=pause&output=json", None);
        let orig_id = upload(&orig_xml, "Show.Name.S01E02.720p.WEB.nzb");
        let held_id = upload(&held_xml, "Show.Name.S01E02.1080p.WEB.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert_eq!(qslot(&q, &held_id)["priority"], "Duplicate", "not held: {q}");
        http(port, "/api?mode=resume&output=json", None);

        // Cancel the original while it is actually transferring.
        poll(
            &|q, _| qslot(q, &orig_id)["status"] == "Downloading",
            "the original to start",
        );
        let r = http(
            port,
            &format!("/api?mode=queue&name=delete&value={orig_id}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // A GENUINE failure of an unrelated title, used both as the other
        // half of the guard and as the marker that the cancelled job's
        // tail has long since run.
        let dead_id = upload(&dead_xml, "Other.Show.S05E01.720p.WEB.nzb");
        let alt_id = upload(&alt_xml, "Other.Show.S05E01.1080p.WEB.nzb");
        let (q, h) = poll(
            &|_, h| !hslot(h, &dead_id).is_null() && !hslot(h, &alt_id).is_null(),
            "the failed original and its promoted alternative",
        );
        // Which job took which outcome, not merely that both words are
        // somewhere in the payload: the old pair of substring searches
        // passed just as happily with the two swapped.
        assert_eq!(hslot(&h, &dead_id)["status"], "Failed", "{h}");
        assert_eq!(hslot(&h, &alt_id)["status"], "Completed", "{h}");

        // The cancelled title's alternative is still held, and nothing
        // about the cancelled job reached history.
        assert_eq!(
            qslot(&q, &held_id)["priority"],
            "Duplicate",
            "the cancelled download promoted its held duplicate: {q}"
        );
        assert!(
            hslot(&h, &held_id).is_null(),
            "the held duplicate downloaded anyway: {h}"
        );
        assert!(
            hslot(&h, &orig_id).is_null(),
            "a cancelled job must not reach history: {h}"
        );
    })
    .await
    .unwrap();
    // Rig check: the delete really did land on a live transfer (the whole
    // point - a job cancelled before it started never reaches park()).
    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        log.contains("[queue] active download stopped by user"),
        "the delete did not hit a running download:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §44: an API-added job records WHICH client sent it, not just that
/// some automation did. The Sonarr string here is one a real Sonarr
/// sent during download-client certification, captured off a live
/// test rather than assumed.
///
/// The browser leg matters as much as the Sonarr one: our own dashboard
/// uploads to this very endpoint, so a UA that names no automation must
/// leave the old parameter heuristic untouched.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_that_added_a_job_is_named() {
    let dir = std::env::temp_dir().join(format!("nzbfast-origin-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Nothing is ever fetched - the daemon is paused throughout - so an
    // empty server is enough to satisfy startup.
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
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
        let xml = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
             <file poster=\"x\" date=\"0\" subject=\"&quot;o.rar&quot; yEnc (1/1)\">\n    \
             <groups><group>g</group></groups>\n    <segments>\n      \
             <segment bytes=\"100\" number=\"1\">nosuchseg</segment>\n    \
             </segments>\n  </file>\n</nzb>\n";
        // `http` cannot set a User-Agent, and the header IS the evidence
        // under test, so the request is written out by hand.
        let add = |ua: &str, fname: &str| -> String {
            let boundary = "----originb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let mut request = Vec::new();
            write!(
                request,
                "POST /api?mode=addfile&output=json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
                 User-Agent: {ua}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\n\
                 Content-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(&body);
            String::from_utf8_lossy(&raw(port, &request)).to_string()
        };

        // Paused, so both jobs are still in the queue to be read back.
        http(port, "/api?mode=pause&output=json", None);
        let r = add("Sonarr/4.0.19.2979 (macos 10.0)", "Named.Client.S01E01.nzb");
        assert!(r.contains("\"status\":true"), "{r}");
        let r = add(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Browser.Upload.S01E02.nzb",
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"origin\":\"arr:sonarr\""), "the client was not named: {q}");
        assert!(
            q.contains("\"origin\":\"dashboard\""),
            "a browser upload was misread as an automation: {q}"
        );
        // The bare `arr` bucket is what this replaces for a named client.
        assert!(!q.contains("\"origin\":\"arr\""), "{q}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Categories are configuration, not a side effect of what has been
/// downloaded.
///
/// They used to live only in memory as "the built-ins plus whatever an
/// add call happened to carry", rebuilt at startup from the categories
/// still present in queue.json. Two consequences, both of which meet a
/// user before they can download anything: a fresh install offered only
/// `tv` and `movies`, and Sonarr/Radarr REFUSE to connect when their
/// configured category is missing from the list ("Category does not
/// exist"), so the category could never be registered by the add that
/// would have registered it. And a category did not outlive the last job
/// carrying it - clear history, lose the category.
#[tokio::test(flavor = "multi_thread")]
async fn categories_are_configurable_and_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cats-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let launch = {
        let cfg = cfg.clone();
        let dir = dir.clone();
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
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
                .arg(dir.join("complete"));
            c
        }
    };
    let d = serve(&dir, &launch).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Out of the box we answer for the *arr family's OWN defaults -
        // Sonarr tv, Radarr movies, Lidarr music, Readarr books - so a
        // default install of any of them passes its connection test
        // against a default install of ours.
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        for c in ["tv", "movies", "music", "books"] {
            assert!(r.contains(&format!("\"{c}\"")), "default category {c} missing: {r}");
        }

        // A user whose Sonarr is set to a category of its own can add it,
        // with no job needed to teach us the name.
        let r = http(
            port,
            "/api?mode=config&name=categories&value=sonarr,%20radarr&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        assert!(r.contains("\"sonarr\""), "{r}");
        assert!(r.contains("\"radarr\""), "{r}");
        // The built-ins are a floor: editing the list cannot strand a
        // client that was already configured against one of them.
        assert!(r.contains("\"tv\""), "editing the list dropped a built-in: {r}");

        // The NZBGet facade's category table is what Sonarr's nzbget-mode
        // Test validates against, so it must agree with get_cats.
        let body = br#"{"method":"config","params":[],"id":1}"#;
        let mut request = Vec::new();
        write!(
            request,
            "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic eDpzZWtyaXQ=\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        request.extend_from_slice(body);
        let r = String::from_utf8_lossy(&raw(port, &request)).to_string();
        assert!(r.contains("sonarr"), "nzbget config table has no sonarr category: {r}");
    })
    .await
    .unwrap();

    // Restart: the category must still be there. Nothing was ever
    // downloaded, so the old queue-derived list would have lost it.
    drop(d);
    let d = serve(&dir, &launch).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        assert!(
            r.contains("\"sonarr\""),
            "category did not survive the restart: {r}"
        );
        assert!(r.contains("\"radarr\""), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The NZBGet facade answers with NZBGet's own vocabulary.
///
/// Two gaps this pins. Every failure used to report `FAILURE/PAR` with
/// `ParStatus: FAILURE` - one bit, so "needs a password", "the disk
/// filled up" and "the post is missing articles" were indistinguishable
/// to a client, and all three were blamed on a repair that in two of the
/// three cases never ran. And an unimplemented method returned a null
/// RESULT, which on the wire is what "succeeded, nothing to report"
/// looks like, so a client could not tell the two apart.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_facade_reports_real_statuses_and_real_errors() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nzbgstat-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let rpc = |method: &str, params: &str| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":1}}");
            let mut request = Vec::new();
            write!(
                request,
                "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic eDpzZWtyaXQ=\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(body.as_bytes());
            String::from_utf8_lossy(&raw(port, &request)).to_string()
        };

        // A method we do not implement is an ERROR, not an empty success.
        let r = rpc("makecoffee", "[]");
        assert!(r.contains("\"error\""), "{r}");
        assert!(r.contains("no such method"), "{r}");
        assert!(!r.contains("\"error\":null"), "unknown method answered as success: {r}");

        // Same for an editqueue command we do not implement - `false`
        // was also the answer for "that job does not exist".
        let r = rpc("editqueue", "[\"GroupSetDupeKey\",\"x\",[1]]");
        assert!(r.contains("unsupported editqueue command"), "{r}");

        // Implemented ones still answer as results, error null.
        let r = rpc("version", "[]");
        assert!(r.contains("\"error\":null"), "{r}");
        let r = rpc("status", "[]");
        assert!(r.contains("\"error\":null"), "{r}");
        // Including the ones that are honest no-ops for us: we have one
        // pause covering the whole pipeline, not a separate post queue.
        let r = rpc("pausepost", "[]");
        assert!(r.contains("\"error\":null"), "{r}");

        // Sonarr rejects a client reporting KeepHistory 0, so the config
        // dump must keep carrying a non-zero one.
        let r = rpc("config", "[]");
        assert!(r.contains("KeepHistory"), "{r}");
        assert!(!r.contains("\"Value\":\"0\""), "KeepHistory went to 0, which Sonarr refuses: {r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The SAB surface a remote app and an *arr actually poll.
///
/// Four gaps, each one a thing a client asks for and used to be told
/// nothing about: `mode=warnings` was a permanent empty list, so "no
/// server configured" was invisible in every app that has a warnings
/// pane; there was no `mode=status` or `mode=get_scripts` at all, which
/// is what the mobile remotes poll rather than `fullstatus`; and
/// `change_cat` existed only on the NZBGet side, so which client type
/// the user picked decided whether recategorizing a queued job worked.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_status_warnings_and_change_cat() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabstat-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    // A config with NO servers: the first-run state, and the one a user
    // wiring up Sonarr is most likely to be sitting in.
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The condition is real and currently stopping all work, so it
        // must reach a client that shows warnings.
        let r = http(port, "/api?mode=warnings&apikey=sekrit&output=json", None);
        assert!(r.contains("No Usenet server"), "warnings stayed empty: {r}");

        // mode=status carries the same warning, plus what a remote app
        // badges: the count, the pause state, free space.
        let r = http(port, "/api?mode=status&apikey=sekrit&output=json", None);
        assert!(r.contains("\"have_warnings\":\"1\""), "{r}");
        assert!(r.contains("No Usenet server"), "{r}");
        assert!(r.contains("\"paused\""), "{r}");
        assert!(r.contains("\"diskspace1\""), "{r}");
        assert!(r.contains("\"completedir\""), "{r}");

        // An empty script list makes a client show no dropdown at all,
        // so "None" is the honest floor.
        let r = http(port, "/api?mode=get_scripts&apikey=sekrit&output=json", None);
        assert!(r.contains("\"None\""), "{r}");

        // Pause before queueing, and it has to be before: "no server, so
        // it never starts" is not true. With an empty server list the job
        // IS picked up, fails "config has no servers" inside half a
        // second, and parks to history. In isolation the three round
        // trips below beat that; under the full suite's load they did not,
        // and the queue read found an empty slot list perhaps one run in
        // six. A paused queue is never picked from, so the job stays
        // Queued for as long as this test needs it.
        let r = http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        assert!(r.contains("\"status\":true"), "pause refused: {r}");

        // Queue a job and move it to another category. Nothing has been
        // written, so this re-derives the output directory rather than
        // moving files.
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;chg.bin&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments><segment bytes=\"100\" number=\"1\">&lt;a@x&gt;</segment></segments>\n  </file>\n</nzb>\n";
        let body = format!(
            "--BB\r\nContent-Disposition: form-data; name=\"nzbfile\"; filename=\"Chg.Show.S01E01.1080p.nzb\"\r\nContent-Type: application/xml\r\n\r\n{nzb}\r\n--BB--\r\n"
        );
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&cat=tv&output=json",
            Some(("multipart/form-data; boundary=BB", body.as_bytes())),
        );
        let id = r
            .split("\"nzo_ids\":[\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("no nzo_id in addfile response")
            .to_string();

        let r = http(
            port,
            &format!("/api?mode=change_cat&value={id}&value2=movies&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "change_cat refused: {r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains("\"cat\":\"movies\""), "category did not change: {q}");

        // An unknown id is an error, not a silent success.
        let r = http(
            port,
            "/api?mode=change_cat&value=nope&value2=tv&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Post-download synthesised naming is ON out of the box, is visible in
/// the config the dashboard reads, and survives a restart once turned
/// off.
///
/// Default-on is only defensible because the ladder's acceptance gate
/// renames on certainty rather than on a best guess. A user who would
/// rather nothing at all reached the network after a download must be
/// able to turn it off and have that stick - a toggle that silently came
/// back on at the next restart would be worse than no toggle.
#[tokio::test(flavor = "multi_thread")]
async fn synthesised_naming_defaults_on_and_its_off_switch_persists() {
    let dir = std::env::temp_dir().join(format!("nzbfast-identify-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let launch = {
        let cfg = cfg.clone();
        let dir = dir.clone();
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
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
                .arg(dir.join("complete"));
            c
        }
    };
    let d = serve(&dir, &launch).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(
            cfg.contains("\"rename_identify\":true"),
            "should default on: {cfg}"
        );
        let r = http(
            port,
            "/api?mode=config&name=rename_identify&value=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(cfg.contains("\"rename_identify\":false"), "{cfg}");
    })
    .await
    .unwrap();

    drop(d);
    let d = serve(&dir, &launch).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(
            cfg.contains("\"rename_identify\":false"),
            "the off switch did not survive the restart: {cfg}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The container Title rung of the identity ladder, end to end and
/// entirely offline: a post whose subject line says nothing carries the
/// real release name inside the Matroska header, and the finished job
/// is both LABELLED with it and RENAMED off it.
///
/// The interesting half is that the posted name stays on the record.
/// History reports `name` exactly as submitted - every SAB client and
/// every *arr matches on it - with the discovered name in its own field
/// beside it.
#[tokio::test(flavor = "multi_thread")]
async fn an_obfuscated_post_is_named_by_its_own_container() {
    let dir = std::env::temp_dir().join(format!("nzbfast-ident-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // What the poster called it: nothing at all.
    let stem = "a4f9c2e1b7d048395166cf20";
    // What the muxer called it, repacker credit and all.
    const REAL: &str = "Example.Movie.2019.1080p.BluRay.x264-GRP";
    let mut video = nzbkit::mkv::test_mux_titled(
        Some(5400.0),
        Some((1920, 1080)),
        Some(&format!("{REAL}, RMZ.cr")),
    );
    // Void padding, the way a real mux carries it, to a plausible size.
    while video.len() < 200_000 {
        video.extend(nzbkit::mkv::el(&[0xEC], &vec![0u8; 8000]));
    }

    let mut articles = HashMap::new();
    let vsegs = make_file_articles(&format!("{stem}.mkv"), &video, 40_000, "vid", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{stem}.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        vsegs.len()
    ));
    for (id, bytes, num) in vsegs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
        // NO_ENRICH keeps the two networked rungs (srrdb, xREL) off the
        // wire; the container rung is local and runs regardless, which
        // is the whole point of gating them separately.
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&cat=movies&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // The discovered name is recorded, attributed, and beside - not
        // instead of - the name the job was submitted under.
        assert!(
            hist.contains(&format!("\"identity_name\":\"{REAL}\"")),
            "container name not recorded: {hist}"
        );
        assert!(hist.contains("\"identity_src\":\"mkv-title\""), "{hist}");
        assert!(hist.contains(&format!("\"name\":\"{stem}\"")), "posted name was overwritten: {hist}");

        // …and the payload on disk is filed under it, which is what the
        // user actually sees. Auto-rename is on by default, so the movie
        // folder and its video both take the discovered title.
        let root = dir2.join("complete/movies");
        let found: Vec<String> = std::fs::read_dir(&root)
            .expect("category dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            found.iter().any(|f| f.starts_with("Example Movie")),
            "payload was not filed under the discovered name: {found:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Going offline stops the download that is ALREADY RUNNING, not just the
/// ones that have not started.
///
/// "Offline" is the instant sibling of the idle-release timeout: its whole
/// reason to exist is to stop occupying the provider account so the
/// operator can use it from somewhere else. Its own doc comment, its log
/// line ("queue paused, provider connections closing") and the dashboard's
/// confirm ("Every connection to your providers is closed") all promise
/// that. Setting `paused` does not deliver it: `paused` is a start-time
/// gate read by `pick_job`, and nothing samples it inside a running fetch.
/// So the header control turned the dot red, answered `{"offline":true}`,
/// printed the log line - and the fleet kept transferring for as long as
/// the job had left to run, which on a 40 GB job is hours of exactly the
/// occupancy the operator pressed the control to end.
///
/// Driven end to end because the flag is not the behaviour: a job is
/// started against a deliberately slow mock, `mode=offline` is called
/// while it is genuinely on the wire, and this asserts BOTH halves - the
/// job leaves Downloading, and the mock stops being asked for articles.
#[tokio::test(flavor = "multi_thread")]
async fn going_offline_winds_down_the_running_download() {
    let dir = std::env::temp_dir().join(format!("nzbfast-offline-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    // 100 articles at 250 ms over 2 connections is ~12 s of transfer, so
    // the offline call lands with most of the job still to fetch and the
    // "did it stop?" question has a real answer either way.
    let segs = make_file_articles(
        "long.bin",
        &payload(4_000_000, 61),
        40_000,
        "of",
        &mut articles,
    );
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;long.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    let served = srv.served.clone();
    let daemon_log = d.log.clone();

    tokio::task::spawn_blocking(move || {
        let boundary = "----offb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"long.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap();

        // ONE queue slot: the payload carries a queue-wide "status" of its
        // own, so a substring search says nothing about THIS job.
        let qslot = |id: &str| -> serde_json::Value {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value =
                serde_json::from_str(&q).unwrap_or_else(|e| panic!("bad queue JSON: {e}\n{q}"));
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };

        // Wait for it to be genuinely on the wire, not merely picked.
        let mut on_the_wire = false;
        for _ in 0..300 {
            if qslot(&id)["status"] == "Downloading" && served.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                on_the_wire = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(on_the_wire, "the job never started transferring");

        let r = http(port, "/api?mode=offline&output=json", None);
        assert!(r.contains("\"offline\":true"), "{r}");

        // The job must leave Downloading. Reaching history instead is the
        // bug: it means the transfer ran to completion with the operator
        // locked out of their account for the whole of it.
        let mut parked = false;
        for _ in 0..240 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(
                !h.contains(&id),
                "went offline mid-transfer and the job ran to COMPLETION anyway - \
                 the provider fleet was never wound down\n{h}"
            );
            if qslot(&id)["status"] == "Paused" {
                parked = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(parked, "the running job never wound down after going offline\n--- log ---\n{log}");

        // ...and the fleet must actually stop asking for articles. A
        // graceful wind-down lets the in-flight window land first, so
        // settle before measuring.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let at_rest = served.load(std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            at_rest,
            "articles were still being fetched after going offline"
        );
        // Rig check: this really did land mid-transfer.
        assert!(
            at_rest < segs.len() as u64,
            "the mock served the whole job ({at_rest} articles) - offline never landed mid-transfer"
        );

        // The wind-down is graceful, so what landed is journalled and the
        // job is PARKED, not failed: coming back online finishes it.
        let r = http(port, "/api?mode=online&output=json", None);
        assert!(r.contains("\"offline\":false"), "{r}");
        http(port, "/api?mode=resume&output=json", None);
        let mut done = false;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(!h.contains("\"Failed\""), "the wound-down job failed instead of resuming\n{h}");
            if h.contains(&id) && h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(done, "the job never finished after coming back online\n--- log ---\n{log}");
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/long/long.bin")).unwrap(),
        payload(4_000_000, 61),
        "payload differs after the offline wind-down and journal resume"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 65: "offline" is a promise the product makes in absolute terms -
/// the confirm dialog says every connection is closed "so you can use the
/// account from another machine", and the daemon logs "touching no
/// provider" on restart. Force priority used to walk straight through it.
///
/// That is worse than it sounds. `pick_job` skipped only
/// `queue_paused && priority < 2`, and NOTHING on the download path read
/// `offline` at all, so the fleet reopened while the header still said
/// Offline - and the operator's OTHER machine got refused at the account's
/// connection cap, with no reason to suspect this daemon. Force is not
/// even always a user's choice: the retry/start path hard-codes
/// `priority = 2`.
///
/// Three ways in, all closed by one gate, all pinned here:
///   1. a Force-priority job added while offline;
///   2. NZBGet `resumedownload`, which clears `paused`;
///   3. SAB `mode=resume`, which used to clear `offline` outright.
/// Plus the escape hatch: coming back online really does release it.
#[tokio::test(flavor = "multi_thread")]
async fn offline_outranks_force_and_a_client_resume() {
    let dir = std::env::temp_dir().join(format!("nzbfast-offforce-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(300_000, 71);
    let mut articles = HashMap::new();
    let segs = make_file_articles("forced.bin", &data, 40_000, "off2", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let served = srv.served.clone();

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;forced.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    let daemon_log = d.log.clone();

    tokio::task::spawn_blocking(move || {
        // Offline FIRST, with nothing running: this is about job START,
        // not about winding a transfer down.
        let r = http(port, "/api?mode=offline&output=json", None);
        assert!(r.contains("\"offline\":true"), "{r}");

        // Route 1: a Force-priority job, which is one click away in the
        // SAB facade and is what the retry path sets by itself.
        let boundary = "----offf";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"forced.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&priority=2&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap();

        let offline_now = |tag: &str| {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value =
                serde_json::from_str(&q).unwrap_or_else(|e| panic!("bad queue JSON at {tag}: {e}\n{q}"));
            v["queue"]["offline"].as_bool().unwrap_or(false)
        };
        let idle = |tag: &str, secs: u64| {
            for _ in 0..(secs * 4) {
                let h = http(port, "/api?mode=history&output=json", None);
                assert!(
                    !h.contains(&id),
                    "{tag}: the job reached history while the daemon reported itself OFFLINE - \
                     the provider fleet reopened behind the operator's back\n{h}"
                );
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        };

        idle("force", 3);
        assert!(offline_now("force"), "offline was cleared by adding a Force job");
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "articles were fetched from the provider while offline"
        );

        // Route 2: NZBGet resumedownload. Clears `paused`; must not
        // smuggle the queue past `offline`.
        let rpc = http(
            port,
            "/jsonrpc",
            Some((
                "application/json",
                br#"{"method":"resumedownload","params":[]}"#.as_ref(),
            )),
        );
        assert!(rpc.contains("\"result\":true"), "{rpc}");
        idle("nzbget-resume", 3);
        assert!(offline_now("nzbget-resume"), "NZBGet resumedownload cleared offline");

        // Route 3: SAB mode=resume. This USED to call set_offline(false),
        // which let any *arr take the operator back online silently - the
        // one remaining way to reopen the account from a remote client.
        // With a real gate it no longer has to: the queue unpauses and
        // simply does not start, so nothing fails against a provider we
        // promised not to touch.
        let r = http(port, "/api?mode=resume&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        idle("sab-resume", 3);
        assert!(
            offline_now("sab-resume"),
            "SAB mode=resume cleared offline: a remote client can still reopen the account"
        );
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "articles were fetched after a client resume while offline"
        );

        // The escape hatch: coming back online is the operator's act, and
        // it must actually release the job rather than stranding it.
        let r = http(port, "/api?mode=online&output=json", None);
        assert!(r.contains("\"offline\":false"), "{r}");
        let mut done = false;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(!h.contains("\"Failed\""), "the job failed after coming back online\n{h}");
            if h.contains(&id) && h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(done, "the job never ran after coming back online\n--- log ---\n{log}");
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/forced/forced.bin")).unwrap(),
        data,
        "payload differs after the offline hold"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §73 phase 1: `/preview/probe/{nzo_id}` tells the dashboard what the
/// downloaded file actually IS - container, tracks, codecs, languages -
/// so a user can confirm it is the right release without opening it in a
/// player. The whole point of the feature is that this answer is
/// available from the bytes themselves, not from the filename a poster
/// chose, so the fixture is a real Matroska mux and the assertions are
/// on what is INSIDE it.
#[tokio::test(flavor = "multi_thread")]
async fn preview_probe_reports_what_the_file_is() {
    let dir = std::env::temp_dir().join(format!("nzbfast-preview-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A genuine Matroska header with a payload cluster behind it.
    let data = nzbkit::mediaprobe::testmux::mkv_padded(400_000);
    let mut articles = HashMap::new();
    let segs = make_file_articles("movie.mkv", &data, 40_000, "pv", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;movie.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    delete_without_the_trash(&cfg);
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
    let port = d.port;
    let daemon_log = d.log.clone();

    tokio::task::spawn_blocking(move || {
        let boundary = "----previewb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Wait for it to finish, then ask what it is.
        let mut nzo = String::new();
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"")
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&h)
                && let Some(slot) = v["history"]["slots"].get(0)
                && let Some(id) = slot["nzo_id"].as_str()
            {
                nzo = id.to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(!nzo.is_empty(), "the job never completed\n--- log ---\n{log}");

        // Inspecting a download takes the same credentials as playing
        // it: nzo_ids are enumerable, so an open probe would hand any
        // LAN host the shape of the user's library a guess at a time.
        let r = raw(
            port,
            format!("GET /preview/probe/{nzo} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        let head = String::from_utf8_lossy(&r).to_string();
        assert!(head.starts_with("HTTP/1.1 401"), "unauthenticated probe was served: {head}");

        let body = http(
            port,
            &format!("/preview/probe/{nzo}?apikey=sekrit"),
            None,
        );
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
        assert_eq!(v["source"], "disk", "{body}");
        // The renamer owns the final name (it reads the container's own
        // Title, which this fixture carries), so the probe is asked only
        // that it found the media file - not what it ended up called.
        assert!(
            v["file"].as_str().is_some_and(|f| f.ends_with(".mkv")),
            "{body}"
        );
        let m = &v["media"];
        assert_eq!(m["container"], "mkv", "{body}");
        assert_eq!(m["duration_ms"], 60_000, "{body}");
        // The codecs are read out of the container, not out of the name.
        assert_eq!(m["video"][0]["codec"], "h264", "{body}");
        assert_eq!(m["video"][0]["width"], 1920, "{body}");
        assert_eq!(m["audio"][0]["codec"], "aac", "{body}");
        assert_eq!(m["audio"][0]["lang"], "en", "{body}");
        assert_eq!(m["subtitles"][0]["codec"], "srt", "{body}");
        assert_eq!(m["playback"], "Remux", "{body}");
        assert_eq!(m["complete"], true, "{body}");
        // §73 phase 2: the string the page asks the browser about. It is
        // spelled out of the container's own configuration record, which
        // is why the panel can tell High 10 (which no browser plays)
        // from High (which every one of them does).
        assert_eq!(m["video"][0]["codec_rfc6381"], "avc1.640029", "{body}");
        assert_eq!(m["audio"][0]["codec_rfc6381"], "mp4a.40.2", "{body}");

        // The setting gates the endpoint, not just the panel: "off"
        // stops the daemon reading the file for anybody.
        let set = http(
            port,
            "/api?mode=config&name=preview&value=off&apikey=sekrit&output=json",
            None,
        );
        assert!(set.contains("\"status\": true") || set.contains("\"status\":true"), "{set}");
        let r = raw(
            port,
            format!("GET /preview/probe/{nzo}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        let head = String::from_utf8_lossy(&r).to_string();
        assert!(head.starts_with("HTTP/1.1 403"), "preview=off still probed: {head}");
        // A value that is not one of the three is refused outright,
        // rather than quietly landing as something else.
        let bad = http(
            port,
            "/api?mode=config&name=preview&value=sometimes&apikey=sekrit&output=json",
            None,
        );
        assert!(bad.contains("off, metadata-only or full"), "{bad}");
        // Back on, and the mode rides the queue payload the dashboard
        // already polls - the panel and the player are drawn from that,
        // not from a get_config the page only fetches in Settings.
        http(
            port,
            "/api?mode=config&name=preview&value=full&apikey=sekrit&output=json",
            None,
        );
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        let qv: serde_json::Value = serde_json::from_str(&q).unwrap_or_else(|e| panic!("{e}: {q}"));
        assert_eq!(qv["queue"]["preview"], "full", "{q}");
        let body = http(port, &format!("/preview/probe/{nzo}?apikey=sekrit"), None);
        assert!(body.contains("\"container\""), "{body}");

        // An nzo_id nobody has is a 404, not a probe of somebody else's
        // download.
        let r = raw(
            port,
            b"GET /preview/probe/SABnzbd_nzo_nope?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let head = String::from_utf8_lossy(&r).to_string();
        assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same probe WHILE the download is still running - which is the
/// whole point of the feature. The file is throttled so the window stays
/// open, and the assertion is that the answer comes from the live writer
/// (`source: "live"`) with the container already parsed: the metadata is
/// at the front of any real mux, so it is readable long before the bytes
/// behind it are.
#[tokio::test(flavor = "multi_thread")]
async fn preview_probe_answers_while_the_file_is_still_downloading() {
    let dir = std::env::temp_dir().join(format!("nzbfast-preview-live-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Big enough that the throttle keeps it downloading for several
    // seconds, so the probe really is answering mid-flight.
    let data = nzbkit::mediaprobe::testmux::mkv_padded(12_000_000);
    let mut articles = HashMap::new();
    let segs = make_file_articles("movie.mkv", &data, 300_000, "lv", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;movie.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    delete_without_the_trash(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3")
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
    let daemon_log = d.log.clone();

    tokio::task::spawn_blocking(move || {
        let boundary = "----previewlive";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Find the job the moment it is queued, then keep probing it.
        let mut nzo = String::new();
        for _ in 0..200 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&q)
                && let Some(slot) = v["queue"]["slots"].get(0)
                && let Some(id) = slot["nzo_id"].as_str()
            {
                nzo = id.to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(!nzo.is_empty(), "the job never reached the queue");

        let mut live = None;
        for _ in 0..400 {
            let b = http(port, &format!("/preview/probe/{nzo}"), None);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&b)
                && v["source"] == "live"
                && v["media"]["container"] == "mkv"
            {
                live = Some(v);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        let v = live.unwrap_or_else(|| {
            panic!("the probe never answered from the live download\n--- log ---\n{log}")
        });
        // Read from the writer, not from a finished file on disk.
        assert_eq!(v["source"], "live", "{v}");
        assert!(v["coverage"]["head_bytes"].as_u64().unwrap_or(0) > 0, "{v}");
        let m = &v["media"];
        assert_eq!(m["video"][0]["codec"], "h264", "{v}");
        assert_eq!(m["video"][0]["width"], 1920, "{v}");
        assert_eq!(m["audio"][0]["lang"], "en", "{v}");
        assert_eq!(m["duration_ms"], 60_000, "{v}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Files the process `pid` currently holds open, or `None` on a box that
/// cannot be asked (no `/proc`, no `lsof`, Windows).
///
/// Deliberately a whole-process question. The bug this pins was a handle
/// the daemon held from the download pipeline, and nothing inside the
/// daemon reports its own descriptors - only the OS knows.
fn open_files(pid: u32) -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        // A deleted-but-open file reads back as "/path/to/it (deleted)",
        // which is exactly the state that keeps the blocks allocated - so
        // callers match on a substring, never on equality.
        let rd = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        Some(
            rd.flatten()
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        // -Fn: one field per line, names prefixed with 'n'. The exit
        // status is not checked - lsof reports a non-zero status for
        // perfectly ordinary partial answers - so an empty stdout is what
        // reads as "could not ask".
        let out = Command::new("/usr/sbin/lsof")
            .arg("-p")
            .arg(pid.to_string())
            .arg("-Fn")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if text.is_empty() {
            return None;
        }
        Some(
            text.lines()
                .filter_map(|l| l.strip_prefix('n'))
                .map(str::to_string)
                .collect(),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// TODO §77 pre-flight post health: the failure diagnostics, run
/// backwards. A few of a queued job's articles are STATed across every
/// server before a byte is spent and the verdict is hung on the queue
/// row - and, crucially, it is ADVISORY: the job downloads exactly as it
/// would have.
///
/// The mock answers every STAT with 430 while serving bodies normally
/// (`stat_miss`), which is precisely the shape that separates "the
/// sample said no" from "the download failed": nothing here is allowed
/// to turn the first into the second.
///
/// Both halves of the propagation guard are pinned in one daemon: the
/// 30-day post is RED, the 1-day post is only AMBER, and a 430 from
/// every server means different things about the two. That is the trap
/// this feature exists next to - see memory
/// `nzbfast-retry-propagation-trap`.
#[tokio::test(flavor = "multi_thread")]
async fn preflight_health_badges_the_row_and_downloads_the_job_anyway() {
    let dir = std::env::temp_dir().join(format!("nzbfast-health-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let old_data = payload(120_000, 5);
    let new_data = payload(120_000, 9);
    let old_segs = make_file_articles("aged.bin", &old_data, 20_000, "aged", &mut articles);
    let new_segs = make_file_articles("fresh.bin", &new_data, 20_000, "fresh", &mut articles);
    // Every STAT is refused; every BODY is served. A sample that says
    // "gone" over a post that downloads perfectly is the whole point.
    let chaos = Chaos {
        post: nzbkit::mock::PostChaos {
            stat_miss: 1_000_000,
            ..Default::default()
        },
        ..Default::default()
    };
    let srv = MockServer::start(articles, chaos).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let nzb = |file: &str, date: i64, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"{date}\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let old_xml = nzb("aged.bin", now - 30 * 86_400, &old_segs);
    let new_xml = nzb("fresh.bin", now - 86_400, &new_segs);

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
            .env("NZBFAST_HEALTH_TICK_SECS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Paused so the prober gets its idle window before the runner
        // takes the queue: the probe deliberately stands down while a
        // download is active.
        http(port, "/api?mode=pause&output=json", None);
        let old_id = upload_nzb(port, &old_xml, "aged.nzb");
        let new_id = upload_nzb(port, &new_xml, "fresh.nzb");

        let health = |id: &str| -> serde_json::Value {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .map(|s| s["health"].clone())
                .unwrap_or(serde_json::Value::Null)
        };
        let wait_health = |id: &str| -> serde_json::Value {
            for _ in 0..200 {
                let h = health(id);
                if h.get("bucket").is_some() {
                    return h;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("{id} was never probed");
        };

        let aged = wait_health(&old_id);
        assert_eq!(
            aged["bucket"], "red",
            "a 30-day post 430ing everywhere: {aged}"
        );
        assert_eq!(
            aged["absent"], aged["sampled"],
            "every sampled article was refused: {aged}"
        );
        assert!(
            aged["sampled"].as_u64().unwrap_or(0) >= 2,
            "the sample must disclose a real size: {aged}"
        );
        assert_eq!(aged["answered"], 1, "one server answered: {aged}");

        // The binding constraint. Same evidence, younger post, and the
        // verdict must NOT be red: propagation looks exactly like this.
        let fresh = wait_health(&new_id);
        assert_eq!(
            fresh["bucket"], "amber",
            "a 1-day post 430ing everywhere is still propagating: {fresh}"
        );

        // ADVISORY. Neither job was failed, paused or removed by the
        // verdict, and both download normally once the queue runs.
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(
            q.contains(&old_id) && q.contains(&new_id),
            "a job left the queue: {q}"
        );
        assert!(!q.contains("\"Failed\""), "a verdict failed a job: {q}");

        http(port, "/api?mode=resume&output=json", None);
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(
                !h.contains("\"Failed\""),
                "a job failed despite serving bodies\n{h}"
            );
            if h.contains(&old_id) && h.contains(&new_id) && h.matches("\"Completed\"").count() >= 2
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("the red-badged jobs never completed");
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/aged/aged.bin")).unwrap(),
        old_data,
        "the red-badged payload differs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §77 discipline: no probe traffic while a download is running, and one
/// probe per job however often the queue is rendered.
///
/// Asserted from the SERVER's side. STAT transfers no body, so it leaves
/// no mark in `body_log` and the only honest observer is the mock's own
/// STAT counter (memory `nzbfast-idle-connection-holders`: assert on
/// sockets and commands, not on internal state).
#[tokio::test(flavor = "multi_thread")]
async fn the_health_probe_stands_down_while_a_download_runs() {
    let dir = std::env::temp_dir().join(format!("nzbfast-healthidle-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let slow_data = payload(800_000, 2);
    let next_data = payload(60_000, 4);
    let slow_segs = make_file_articles("slow.bin", &slow_data, 20_000, "slow", &mut articles);
    let next_segs = make_file_articles("next.bin", &next_data, 20_000, "next", &mut articles);
    // Slow enough that the first job is still running while the second
    // sits queued, which is the window the prober must sit out.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 200,
            ..Default::default()
        },
    )
    .await;
    let stats = srv.stats.clone();

    let nzb = |file: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let slow_xml = nzb("slow.bin", &slow_segs);
    let next_xml = nzb("next.bin", &next_segs);

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
            .env("NZBFAST_HEALTH_TICK_SECS", "1")
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
            .arg("1");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        use std::sync::atomic::Ordering;
        let slot = |id: &str| -> serde_json::Value {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };

        let slow_id = upload_nzb(port, &slow_xml, "slow.nzb");
        let mut started = false;
        for _ in 0..300 {
            if slot(&slow_id)["status"] == "Downloading" {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(started, "the slow job never started");
        let next_id = upload_nzb(port, &next_xml, "next.nzb");
        let before = stats.load(Ordering::Relaxed);

        // Several prober ticks pass with a download in flight. Not one
        // STAT may go out, and the queued job stays unbadged.
        for _ in 0..8 {
            std::thread::sleep(std::time::Duration::from_millis(400));
            if slot(&slow_id)["status"] != "Downloading" {
                break;
            }
            assert_eq!(
                stats.load(Ordering::Relaxed),
                before,
                "the prober STATed while a download was running"
            );
            assert!(
                slot(&next_id)["health"].is_null(),
                "the queued job was probed while a download was running"
            );
        }

        // Free the line without finishing the job: a queue pause parks
        // the active download back in the queue, so both jobs are
        // Queued, nothing is downloading, and the prober's idle window
        // opens with the second job still there to probe.
        http(port, "/api?mode=pause&output=json", None);
        // Wait for BOTH jobs to be badged, not just the second one. The
        // pause parks the running job back into the queue unpaused, so it
        // is queued-and-unsampled too, and the prober takes one job per
        // tick. Sampling the counter with work still on its list leaves
        // its own next tick free to land inside the render window below,
        // where it reads as a probe the rendering caused.
        for _ in 0..300 {
            if slot(&slow_id)["health"].get("bucket").is_some()
                && slot(&next_id)["health"].get("bucket").is_some()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let h = slot(&next_id)["health"].clone();
        assert_eq!(h["bucket"], "green", "an intact post on a live server: {h}");
        assert!(
            slot(&slow_id)["health"].get("bucket").is_some(),
            "the parked job never got badged, so the prober still has work \
             and the window below cannot attribute a STAT to rendering"
        );
        let after_probe = stats.load(Ordering::Relaxed);
        assert!(after_probe > before, "the idle prober never ran");
        for _ in 0..6 {
            http(port, "/api?mode=queue&output=json", None);
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        assert_eq!(
            stats.load(Ordering::Relaxed),
            after_probe,
            "rendering the queue re-probed the job"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// §77 optional auto-defer: a red verdict may REORDER the queue and
/// nothing else. The red job stays queued, a force overrides the sink,
/// and when it does eventually fail its summary carries the pre-flight
/// evidence ("it was already short when you added it").
#[tokio::test(flavor = "multi_thread")]
async fn health_auto_defer_reorders_and_never_removes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-healthdefer-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let dead_data = payload(80_000, 6);
    let good_data = payload(80_000, 7);
    let dead_segs = make_file_articles("dead.bin", &dead_data, 20_000, "dead", &mut articles);
    let good_segs = make_file_articles("good.bin", &good_data, 20_000, "good", &mut articles);
    // The dead post is genuinely gone: 430 to STAT and to BODY alike.
    let missing: std::collections::HashSet<String> = dead_segs
        .iter()
        .map(|(id, _, _)| format!("<{id}>"))
        .collect();
    // The healthy job is deliberately slow to fetch: the assertion below
    // needs a window in which "good is running and dead is not" is
    // unambiguous. The runner starts the NEXT job while the previous
    // one's post-processing tail still runs, so with both jobs finishing
    // instantly there is no such window and the test races itself.
    // `delay_ms` covers successful bodies only - the dead post's 430s
    // (and every STAT) are answered at full speed.
    let srv = MockServer::start(
        articles,
        Chaos {
            missing,
            delay_ms: 300,
            ..Default::default()
        },
    )
    .await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let nzb = |file: &str, segs: &[(String, u64, u32)]| {
        let date = now - 30 * 86_400;
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"{date}\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let dead_xml = nzb("dead.bin", &dead_segs);
    let good_xml = nzb("good.bin", &good_segs);

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
            .env("NZBFAST_HEALTH_TICK_SECS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=post_health_defer&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // The dead post fails `Gone`, which never auto-retries; this
        // just keeps the test honest if that classification ever moves.
        http(
            port,
            "/api?mode=config&name=auto_retry_mins&value=0&output=json",
            None,
        );
        http(port, "/api?mode=pause&output=json", None);
        // Dead FIRST in queue order, so only the sink can reverse them.
        let dead_id = upload_nzb(port, &dead_xml, "dead.nzb");
        let good_id = upload_nzb(port, &good_xml, "good.nzb");

        let slot = |id: &str| -> serde_json::Value {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };
        let wait_bucket = |id: &str, want: &str| {
            for _ in 0..200 {
                if slot(id)["health"]["bucket"] == want {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("{id} never scored {want}: {}", slot(id));
        };
        wait_bucket(&dead_id, "red");
        wait_bucket(&good_id, "green");
        assert_eq!(
            slot(&dead_id)["health"]["sunk"],
            true,
            "the red job should report that it is being held back"
        );

        http(port, "/api?mode=resume&output=json", None);
        // The green job jumps the queue; the red one is still THERE,
        // just later - reorder only.
        let mut good_first = false;
        for _ in 0..600 {
            let s = slot(&good_id);
            let h = http(port, "/api?mode=history&output=json", None);
            // Anything but Queued means the runner has picked it: a
            // finished job reports its post-processing tail as "Moving"
            // and only reaches history once that tail is done, and the
            // runner has started the NEXT job by then.
            if s.is_null() || s["status"] != "Queued" || h.contains(&good_id) {
                good_first = true;
                break;
            }
            assert_eq!(
                slot(&dead_id)["status"],
                "Queued",
                "the red job was picked ahead of the healthy one"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(good_first, "the healthy job never overtook the red one");
        assert!(
            !slot(&dead_id).is_null()
                || http(port, "/api?mode=history&output=json", None).contains(&dead_id),
            "the red job was removed from the queue"
        );

        // It runs anyway once nothing healthier is left, and its failure
        // summary cites what pre-flight already knew.
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains(&dead_id) {
                assert!(
                    h.contains("a pre-flight sample when this job was added"),
                    "the failure summary dropped the pre-flight evidence\n{h}"
                );
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("the red job never ran at all - the sink must reorder, not remove");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Upload one NZB through the SAB addfile endpoint and return its id.
fn upload_nzb(port: u16, xml: &str, fname: &str) -> String {
    let boundary = "----healthup";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
    r.split("SABnzbd_nzo_")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| format!("SABnzbd_nzo_{s}"))
        .expect("addfile returned no nzo_id")
}

/// §76: the queue row's quality chip, and the fake catcher behind it.
///
/// The fixture is a genuine 1920x1080 h264 mux with a stereo AAC track,
/// posted under a name claiming 2160p / x265 / DDP - which is exactly
/// the shape of an upscale sold as a UHD release. Nothing else we run
/// catches that: every article arrives, the mux is valid, the job
/// completes green. The only witness is the container's own header, and
/// the assertion is that the daemon reads it WHILE the download runs and
/// says so on the record the queue is built from.
///
/// Both passes are covered: the live one off the still-writing file, and
/// the latch that carries the answer into history.
#[tokio::test(flavor = "multi_thread")]
async fn the_queue_row_says_what_the_file_is_and_flags_a_mislabelled_one() {
    let dir = std::env::temp_dir().join(format!("nzbfast-mediachip-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Padded so the write throttle keeps the download open for several
    // seconds: the chip has to appear DURING it, not after.
    let data = nzbkit::mediaprobe::testmux::mkv_padded(12_000_000);
    let mut articles = HashMap::new();
    let segs = make_file_articles("movie.mkv", &data, 300_000, "mc", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;movie.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    delete_without_the_trash(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3")
            // The prober's own cadence, compressed so the test does not
            // sit through the production five seconds.
            .env("NZBFAST_MEDIA_TICK_MS", "300")
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
    let daemon_log = d.log.clone();

    tokio::task::spawn_blocking(move || {
        // The lie is in the NZB's own filename, which becomes the job
        // name every client matches on.
        let boundary = "----mediachip";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Example.Movie.2019.2160p.BluRay.x265.DDP5.1-GRP.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Pass 1: the chip lands on the QUEUE slot, mid-download.
        let mut chip = None;
        for _ in 0..400 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&q)
                && let Some(slot) = v["queue"]["slots"].get(0)
                && slot["media"].is_object()
                && slot["status"] == "Downloading"
            {
                chip = Some(slot["media"].clone());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        let m = chip.unwrap_or_else(|| {
            panic!("the queue row never gained a media chip\n--- log ---\n{log}")
        });

        // What the row shows: the bytes, never the name.
        assert_eq!(m["res"], "1080p", "{m}");
        assert_eq!(m["vcodec"], "H.264", "{m}");
        assert_eq!(m["audio"], "AAC 2.0", "{m}");
        assert_eq!(m["container"], "mkv", "{m}");
        assert!(m["hdr"].is_null(), "an untagged encode carries no format: {m}");

        // ...and every claim the name made that those bytes deny.
        let by = |field: &str| -> serde_json::Value {
            m["mismatch"]
                .as_array()
                .expect("mismatch must be an array")
                .iter()
                .find(|x| x["field"] == field)
                .unwrap_or_else(|| panic!("no {field} mismatch in {m}"))
                .clone()
        };
        assert_eq!(by("resolution")["claimed"], "2160p", "{m}");
        assert_eq!(by("resolution")["actual"], "1080p", "{m}");
        assert_eq!(by("video")["claimed"], "x265", "{m}");
        assert_eq!(by("video")["actual"], "H.264", "{m}");
        assert_eq!(by("audio")["claimed"], "DDP", "{m}");
        assert_eq!(by("audio")["actual"], "AAC 2.0", "{m}");

        // Pass 2: the answer is latched, so it survives the move into
        // history - where the writer it was read from no longer exists.
        let mut hist = None;
        for _ in 0..400 {
            let h = http(port, "/api?mode=history&output=json", None);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&h)
                && let Some(slot) = v["history"]["slots"].get(0)
                && slot["status"] == "Completed"
                && slot["media"].is_object()
            {
                hist = Some(slot["media"].clone());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        let h = hist.unwrap_or_else(|| {
            panic!("history lost the media chip\n--- log ---\n{log}")
        });
        assert_eq!(h["res"], "1080p", "{h}");
        assert_eq!(h["vcodec"], "H.264", "{h}");
        assert_eq!(h["mismatch"].as_array().map(Vec::len), Some(3), "{h}");
        // A completed file has been read end to end, so the chip is
        // final rather than "what has arrived so far".
        assert_eq!(h["complete"], true, "{h}");
        // And the contradiction is in the log, where a user chasing "why
        // is this amber" can find it without the dashboard.
        assert!(
            log.contains("the file contradicts its name"),
            "the mismatch was never logged\n--- log ---\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The pre feed end to end: a real relay socket to a stored row.
///
/// `nzbkit::predb`'s unit tests already pin every wire format against
/// the 2026 survey's verbatim lines. What they cannot see is the chain
/// AROUND the parser - connect, IRC handshake, JOIN, the listener's
/// pending buffer, the 20 s drain tick, `predb_store` - because every
/// link of it lives in the daemon. A regression anywhere along that
/// chain looks exactly like a quiet feed, and so does a feed with
/// nothing to say.
///
/// So this drives the real binary against a fake relay speaking the
/// three PLAIN formats the survey found live (pipe, `PRE:` prefix,
/// parenthesised) plus two chatter lines that must NOT become rows. The
/// row count is the assertion, and it only comes out right if all three
/// parsed and neither of the other two did.
///
/// The TLS-first connect is exercised too: the relay hangs up on the
/// ClientHello, so the daemon takes the plaintext fallback, which only
/// exists when `NZBFAST_PREDB_ALLOW_PLAINTEXT=1`.
#[cfg(feature = "indexer")]
#[tokio::test]
async fn the_three_plain_relay_formats_reach_the_feed_table() {
    /// Three announcements in the three plain shapes, colour codes and
    /// all - on predataba.se the code lands inside the section field.
    const ANNOUNCEMENTS: &[&str] = &[
        "pre |\x032 X264-HD | Relay.Format.One.2026.1080p.BluRay.x264-ONE",
        "\x0314PRE:\x03 [\x0314X264\x03] Relay.Format.Two.2026.1080p.WEB.H264-TWO",
        "(PRE) (X264-HD) Relay.Format.Three.2026.1080p.WEB.H264-THREE",
    ];
    /// Lines that open like announcements and are not.
    const CHATTER: &[&str] = &[
        "PRE: the bot is back up",
        "stats | 34512 pres | today: 1204",
    ];

    fn serve_irc(sock: &mut std::net::TcpStream) -> std::io::Result<()> {
        use std::io::BufRead;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        let mut out = sock.try_clone()?;
        let mut nick = String::from("nzbfast");
        for line in std::io::BufReader::new(sock).lines() {
            let Ok(line) = line else { return Ok(()) };
            let mut parts = line.split_whitespace();
            match parts.next().unwrap_or("").to_ascii_uppercase().as_str() {
                "NICK" => nick = parts.next().unwrap_or("nzbfast").to_string(),
                // 001 is the "registered" reply the listener waits for
                // before it dares JOIN.
                "USER" => {
                    write!(out, ":relay 001 {nick} :Welcome\r\n")?;
                    out.flush()?;
                }
                "JOIN" => {
                    let ch = parts.next().unwrap_or("#pre").to_string();
                    write!(out, ":{nick}!u@h JOIN :{ch}\r\n")?;
                    // After the JOIN, never before: the listener only
                    // reads a channel it has joined, so sending early
                    // would test nothing and pass anyway.
                    for l in ANNOUNCEMENTS.iter().chain(CHATTER) {
                        write!(out, ":bot!u@h PRIVMSG {ch} :{l}\r\n")?;
                    }
                    out.flush()?;
                }
                "QUIT" => return Ok(()),
                _ => {}
            }
        }
        Ok(())
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { continue };
            // A TLS ClientHello opens with handshake record type 0x16.
            // Hanging up on it beats waiting out the 20 s handshake
            // timeout, and the fallback is what we want next anyway.
            let mut first = [0u8; 1];
            if sock.peek(&mut first).is_ok() && first[0] == 0x16 {
                continue;
            }
            let _ = serve_irc(&mut sock);
        }
    });

    let dir = std::env::temp_dir().join(format!("nzbfast-predbfeed-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // The fallback under test. Without it the daemon correctly
            // refuses to speak plain text to an unauthenticated relay.
            .env("NZBFAST_PREDB_ALLOW_PLAINTEXT", "1")
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
            .arg("--index-db")
            .arg(dir.join("index.db"));
        c
    };

    let d = serve(&dir, &build).await;
    let port = d.port;
    let want = ANNOUNCEMENTS.len() as u64;
    let saw = tokio::task::spawn_blocking(move || {
        // Order matters twice over: a server change only takes effect
        // on connect, so enabling the feed LAST is what makes the first
        // connect use it - and the feed is gated on the indexer being
        // on as well (`predb_feed_on`), because a feed with nowhere to
        // put what it hears is a socket held open for nothing. Indexing
        // is opt-in, so the test opts in.
        for (name, value) in [
            ("index_enabled", "1".to_string()),
            ("predb_server", format!("127.0.0.1:{relay}")),
            ("predb_channels", "%23pre".to_string()),
            ("predb_enabled", "1".to_string()),
        ] {
            let r = http(
                port,
                &format!("/api?mode=config&name={name}&value={value}&apikey=sekrit&output=json"),
                None,
            );
            assert!(r.contains("\"status\":true"), "set {name}: {r}");
        }
        // The drain runs on the feed task's 20 s tick and the listener
        // reconnects once on the way (the TLS attempt is a failed
        // connect from its point of view), so the budget is several
        // ticks wide.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let mut last = String::new();
        while std::time::Instant::now() < deadline {
            last = http(
                port,
                "/api?mode=predb_stats&apikey=sekrit&output=json",
                None,
            );
            if last.contains(&format!("\"lines\":{want}")) {
                return last;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        last
    })
    .await
    .unwrap();

    assert!(
        saw.contains(&format!("\"lines\":{want}")),
        "expected exactly the {want} announcements and neither chatter line: {saw}"
    );
    // The plain formats carry a name and no posted filename, which is
    // the whole reason correlation exists. A nameable row here would
    // mean a parser invented a filename.
    assert!(
        saw.contains("\"nameable\":0"),
        "plain-format lines must never look nameable: {saw}"
    );

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Nested zip through the DAEMON, on a REAL archive pair.
///
/// The unit and e2e coverage for the depth lift builds its containers
/// from nzbkit's own fixtures, which is the right call there (they pin
/// exact byte layouts). This one is the other half: Info-ZIP writes the
/// zip and WinRAR writes the store volume around it, so the bytes are a
/// real posting toolchain's rather than ours, and the whole thing goes
/// in through `addfile` and comes out of the history the way a job from
/// Sonarr does.
///
/// Skips when `rar` is absent - it is not in CI's image, and the same
/// shape is covered without it by `zip_nested_in_store_rar_extracts_one_pass`
/// (nzbkit) and `store_rar_wrapped_zip_extracts_one_pass` (e2e).
#[tokio::test(flavor = "multi_thread")]
async fn nested_zip_in_a_real_store_rar_extracts_through_the_daemon() {
    if Command::new("rar")
        .arg("-inul")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping: rar not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-nestedzip-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let build = dir.join("build");
    std::fs::create_dir_all(&build).unwrap();

    // Incompressible, like real payload: a stored zip entry is the
    // dominant shape and the one the copy path exists for.
    let movie = payload(600_000, 7);
    std::fs::write(build.join("movie.mkv"), &movie).unwrap();
    // Info-ZIP, stored (-0), junking paths so the entry is a bare name.
    let ok = Command::new("zip")
        .current_dir(&build)
        .args(["-0", "-q", "-j", "inner.zip", "movie.mkv"])
        .status()
        .unwrap()
        .success();
    assert!(ok, "zip failed to build the fixture");
    // WinRAR, STORE mode (-m0): the outer is a mapping, not a codec, so
    // the chase reads the zip straight out of the volume.
    let ok = Command::new("rar")
        .current_dir(&build)
        .args(["a", "-m0", "-ep", "-inul", "outer.rar", "inner.zip"])
        .status()
        .unwrap()
        .success();
    assert!(ok, "rar failed to build the fixture");
    let outer = std::fs::read(build.join("outer.rar")).unwrap();
    let inner_len = std::fs::metadata(build.join("inner.zip")).unwrap().len();
    assert!(
        outer.len() as u64 > inner_len,
        "store RAR should carry the zip whole"
    );

    let mut articles = HashMap::new();
    let segs = make_file_articles("outer.rar", &outer, 60_000, "nz", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;outer.rar&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    let nzb = dir.join("nested-zip.nzb");
    std::fs::write(&nzb, &xml).unwrap();

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
    delete_without_the_trash(&cfg);

    let complete = dir.join("complete");
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
            .arg(&complete)
            .arg("--connections")
            .arg("3");
        c
    })
    .await;
    let port = d.port;

    // Multipart, exactly as Sonarr posts one.
    let boundary = "----nzbfastboundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"nested-zip.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let ctype = format!("multipart/form-data; boundary={boundary}");
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("\"status\":true"), "addfile refused: {r}");

        let mut done = false;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            if h.contains("\"Failed\"") {
                panic!("job failed: {h}");
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(done, "download never completed");
    })
    .await
    .unwrap();

    // Every file the job produced. Walked rather than named: the daemon
    // renames a job's single video to the job's own name, which is a
    // different subject from whether the two archive layers unwrapped.
    fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, into);
            } else {
                into.push(p);
            }
        }
    }
    let mut produced = Vec::new();
    walk(&complete, &mut produced);
    let names: Vec<String> = produced
        .iter()
        .map(|p| p.strip_prefix(&complete).unwrap().display().to_string())
        .collect();

    // The payload, byte-exact, out of two archive layers - and it is the
    // ONLY thing the job produced.
    assert_eq!(produced.len(), 1, "expected just the payload: {names:?}");
    assert!(
        std::fs::read(&produced[0]).unwrap() == movie,
        "payload bytes differ ({names:?})"
    );
    // The point of the lift: NEITHER layer touches the output directory.
    for stray in [".rar", ".zip"] {
        assert!(
            !names.iter().any(|n| n.ends_with(stray)),
            "an intermediate {stray} was materialized - produced {names:?}"
        );
    }
    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        !log.contains("nested fallback"),
        "the nested chase demoted:\n{log}"
    );

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex H5: `mode=change_cat` validated the job was Queued, released
/// every lock, derived the new directory, then wrote `category` and
/// `out_dir` WITHOUT revalidating - so a job the scheduler started in
/// that window downloaded into its OLD directory while the record named
/// the new one. The daemon runs with a test hook holding that window
/// open; the change must refuse once the job is Downloading.
#[tokio::test(flavor = "multi_thread")]
async fn change_cat_refuses_a_job_that_started_inside_its_window() {
    let dir = std::env::temp_dir().join(format!("nzbfast-ccrace-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Slow articles so the job is still Downloading when the stalled
    // change_cat wakes up.
    let data = payload(600_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("slow.bin", &data, 40_000, "cc", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 400,
            ..Chaos::default()
        },
    )
    .await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;slow.bin&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            // Hold change_cat open for 8 s between its Queued snapshot
            // and its out_dir publish.
            .env("NZBFAST_TEST_STALL_CHANGE_CAT_MS", "8000")
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
            .arg("1");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Pause, add: the job sits Queued.
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        let boundary = "----ccrace";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"slow.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap();

        // change_cat snapshots the Queued job, then stalls inside its
        // window on the test hook.
        let cc = std::thread::spawn(move || {
            http(
                port,
                &format!("/api?mode=change_cat&value={id}&value2=movies&apikey=sekrit&output=json"),
                None,
            )
        });
        // Give the request time to take its snapshot, then start the job.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        let mut started = false;
        for _ in 0..30 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if q.contains("\"status\":\"Downloading\"") {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(started, "the job never started inside the stall window");

        let r = cc.join().unwrap();
        assert!(
            r.contains("\"status\":false"),
            "change_cat must refuse a job that started inside its window: {r}"
        );
        // And the running job keeps its real category/directory: the
        // record must not name a directory the bytes never went to.
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(
            !q.contains("\"cat\":\"movies\""),
            "the started job was refiled anyway: {q}"
        );
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// §96.3 give-up breaker, end to end: an *arr-originated job whose grab
/// FINALLY fails trips the per-target counter at the configured
/// threshold, and the daemon reaches into the configured *arr to
/// unmonitor the target. The mock *arr answers with an already-swept
/// queue, so this also exercises the parse fallback - the race with the
/// *arr's own poll that the unmonitor-first ordering exists to survive
/// (the ordering itself is pinned by the giveup module's unit tests).
#[tokio::test(flavor = "multi_thread")]
async fn giveup_breaker_unmonitors_after_final_failure() {
    let dir = std::env::temp_dir().join(format!("nzbfast-giveup-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A news server that has NONE of the job's articles: the download
    // fails with missing articles, and NZBFAST_AUTO_RETRY_SECS=0 below
    // makes that first failure final.
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;

    // Mock Sonarr: log every request; queue is empty (its poll already
    // swept the record), parse resolves the release to episode 7.
    let arr_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let arr_url = format!("http://{}", arr_listener.local_addr().unwrap());
    let arr_seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    {
        let seen = arr_seen.clone();
        std::thread::spawn(move || {
            for sock in arr_listener.incoming() {
                let Ok(mut sock) = sock else { return };
                sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();
                // Drain the WHOLE request - headers, then the declared
                // body - before answering, the way the giveup.rs unit
                // mock does. A single read() answered as soon as the
                // headers landed and then closed the socket (Connection:
                // close below), so a PUT whose body arrived in a second
                // segment had it written into a closed pipe. ureq
                // surfaced that as an error, the give-up worker read
                // "the remote call failed" and released the action latch
                // it had already set - and this test failed on
                // `actioned` being false, at whichever assertion the
                // race happened to reach first.
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                let head_end = loop {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break raw.len(),
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                    if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let want: usize = head
                    .to_ascii_lowercase()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                while raw.len() < head_end + want {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let line = head.lines().next().unwrap_or_default().to_string();
                let body: String = if line.starts_with("GET /api/v3/history") {
                    // Ownership evidence: this instance sent the grab,
                    // which is what licenses the parse fallback below.
                    //
                    // The record must carry the downloadId that was ASKED
                    // for, the way a real *arr's filtered history does.
                    // It used to carry none at all and still counted as
                    // ownership, because the gate only asked whether any
                    // record came back - so this fixture was asserting
                    // nothing about whose grab it was.
                    let id = line
                        .split("downloadId=")
                        .nth(1)
                        .and_then(|s| s.split(['&', ' ']).next())
                        .unwrap_or_default();
                    format!(r#"{{"records": [{{"eventType": "grabbed", "downloadId": "{id}"}}]}}"#)
                } else if line.starts_with("GET /api/v3/queue") {
                    r#"{"records": []}"#.to_string()
                } else if line.starts_with("GET /api/v3/parse") {
                    r#"{"episodes": [{"id": 7}]}"#.to_string()
                } else {
                    "{}".to_string()
                };
                seen.lock().unwrap().push(line);
                let _ = sock.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
    }

    let cfg = dir.join("config.json");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    // Threshold 1: the first final failure trips. The instance points at
    // the mock *arr above.
    std::fs::write(
        dir.join("settings.json"),
        format!(
            "{{\"arr_giveup_threshold\": 1, \"arr_instances\": [{{\
             \"name\":\"mock\",\"kind\":\"sonarr\",\"url\":\"{arr_url}\",\
             \"apikey\":\"k\",\"enabled\":true}}]}}"
        ),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_AUTO_RETRY_SECS", "0")
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

    let spool = dir.join(".spool");
    let dbg_log = d.log.clone();
    let seen = arr_seen.clone();
    tokio::task::spawn_blocking(move || {
        // Ghost articles the news server does not carry.
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;ep.bin&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        );
        for n in 1..=3 {
            xml.push_str(&format!(
                "      <segment bytes=\"40000\" number=\"{n}\">ghost{n}@x</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");

        // nzbname is what marks the add as *arr-originated (origin_of),
        // and it is the name the target is parsed from.
        let boundary = "----giveupb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json&nzbname=Giveup.Show.S01E02.720p.WEB.x264-TEST",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        for _ in 0..150 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("Failed") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // The breaker fires on a thread after park: poll for the *arr
        // calls rather than reading once.
        let mut calls = Vec::new();
        for _ in 0..50 {
            calls = seen.lock().unwrap().clone();
            if calls.iter().any(|c| c.starts_with("PUT /api/v3/episode/monitor")) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            calls.iter().any(|c| c.starts_with("GET /api/v3/queue")),
            "the breaker never asked the *arr's queue: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("PUT /api/v3/episode/monitor")),
            "the target was never unmonitored: {calls:?}"
        );

        // And the evidence persists: the counter store names the episode.
        let state = std::fs::read_to_string(spool.join("giveup-state.json"))
            .expect("giveup-state.json written");
        assert!(state.contains("s01e02"), "{state}");
        assert!(
            state.contains("\"actioned\": true"),
            "{state}\nCALLS {calls:?}\nLOG {}",
            std::fs::read_to_string(&dbg_log).unwrap_or_default()
        );

        // Bundle D: all of that used to happen with no endpoint that
        // would even name it. `giveup_status` is what the Watchlist
        // card's "Given up on" list reads.
        let st = http(port, "/api?mode=giveup_status&apikey=sekrit&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&st).unwrap();
        assert_eq!(v["on"], true, "{st}");
        assert_eq!(v["threshold"], 1, "{st}");
        let row = &v["targets"][0];
        assert_eq!(row["label"], "Giveup Show S01E02", "{st}");
        assert_eq!(row["tripped"], true, "{st}");
        assert_eq!(row["actioned"], true, "{st}");
        assert_eq!(row["stems"], 1, "{st}");
        assert_eq!(
            row["last_stem"], "Giveup.Show.S01E02.720p.WEB.x264-TEST",
            "{st}"
        );

        // The trip also rides the queue payload the dashboard already
        // polls every second - that is what toasts the moment.
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        let qv: serde_json::Value = serde_json::from_str(&q).unwrap();
        let ev = &qv["queue"]["giveup_tripped"][0];
        assert_eq!(ev["name"], "Giveup.Show.S01E02.720p.WEB.x264-TEST", "{q}");
        assert_eq!(ev["count"], 1, "{q}");

        // "Try again" forgets the counters, so nothing is given up any
        // more (and the latch is re-armed - see clear_target).
        let key: String = row["key"]
            .as_str()
            .unwrap()
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        let r = http(
            port,
            &format!("/api?mode=giveup_reset&apikey=sekrit&output=json&value={key}"),
            None,
        );
        assert!(r.contains("\"cleared\":true"), "{r}");
        let after = http(port, "/api?mode=giveup_status&apikey=sekrit&output=json", None);
        let av: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert!(
            av["targets"].as_array().unwrap().is_empty(),
            "the target should be gone: {after}"
        );
        // ...and that survives the daemon's own restart of the store.
        let state = std::fs::read_to_string(spool.join("giveup-state.json")).unwrap();
        assert!(!state.contains("s01e02"), "{state}");
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The queue payload's `activity` field (the "what is happening right
/// now" sub-line): empty while a job is queued, and a fetch-family
/// token once the runner starts it. Driven against a dead server so
/// the fetch sits in its connect ladder for the whole observation -
/// no timing dependence on a mock's serving speed.
#[tokio::test(flavor = "multi_thread")]
async fn queue_activity_field_reports_the_fetch_phase() {
    let dir = std::env::temp_dir().join(format!("nzbfast-activity-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // A port with nothing listening: bind, read it back, drop it.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{dead_port},\"tls\":false}}]}}"),
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
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let xml = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"act.bin (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"10000\" number=\"1\">actseg1@test</segment>\n    </segments>\n  </file>\n</nzb>\n";
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"act.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");

        // Paused first: a queued slot must say nothing.
        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        let slot = &v["queue"]["slots"][0];
        assert_eq!(slot["activity"], "", "queued slot must be silent: {q}");

        // Resumed: the runner picks it up and the row must report a
        // fetch-family token while the pool grinds its connect ladder.
        let r = http(port, "/api?mode=resume&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let mut seen = String::new();
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap();
            if let Some(a) = v["queue"]["slots"][0]["activity"].as_str() {
                seen = a.to_string();
                if matches!(a, "connecting" | "reconnecting" | "fetching" | "waiting") {
                    // The detail rides along for the phrases that name a
                    // server; `connecting` carries the host.
                    if a == "connecting" {
                        assert_eq!(
                            v["queue"]["slots"][0]["activity_detail"], "127.0.0.1",
                            "{q}"
                        );
                    }
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no fetch-family activity token appeared; last seen: {seen:?}");
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// §129 4b: the queue payload's `whyslow` block - null while nothing
/// owns the wire, and an object naming the job (with a valid layer
/// token and its evidence numbers) once a download is running. Driven
/// against a dead server, same as the activity test above, so the
/// fetch holds the wire for the whole observation.
#[tokio::test(flavor = "multi_thread")]
async fn whyslow_block_rides_the_queue_payload() {
    let dir = std::env::temp_dir().join(format!("nzbfast-whyslow-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{dead_port},\"tls\":false}}]}}"),
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
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Idle: no job owns the wire, the block must be null - never
        // an empty object, never a stale verdict.
        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        assert!(v["queue"]["whyslow"].is_null(), "idle must be null: {q}");

        let xml = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"why.bin (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"10000\" number=\"1\">whyseg1@test</segment>\n    </segments>\n  </file>\n</nzb>\n";
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"why.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");

        // The engine ticks once a second; the block appears as soon as
        // the runner publishes the wire owner.
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap();
            let w = &v["queue"]["whyslow"];
            if w.is_object() {
                assert!(
                    w["nzo_id"].as_str().is_some_and(|s| !s.is_empty()),
                    "the verdict must name its job: {q}"
                );
                let layer = w["layer"].as_str().unwrap_or("");
                assert!(
                    matches!(
                        layer,
                        "limit"
                            | "line"
                            | "disk"
                            | "cpu"
                            | "client"
                            | "provider"
                            | "missing"
                            | "unknown"
                    ),
                    "unexpected layer token {layer:?}: {q}"
                );
                // The receipts ride along, whatever the verdict.
                assert!(w["achieved_bps"].is_u64(), "{q}");
                assert!(w["servers"].is_array(), "{q}");
                assert!(w["timeline"].is_array(), "{q}");
                // ...including the post-verdict working, which the
                // panel reads unconditionally: the post's own date (0 =
                // none), the fleet miss rate, and how many unrelated
                // backbones are seeing it.
                assert!(w["post_unix"].is_i64(), "{q}");
                assert!(w["missing_pct"].is_number(), "{q}");
                assert!(w["missing_backbones"].is_u64(), "{q}");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("whyslow never appeared for a running job");
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// SAB's binary `to_units` output, back to bytes: "998 B", "417 KB",
/// "1.2 MB", "1.2 GB". None for anything else.
fn sab_size_bytes(s: &str) -> Option<f64> {
    let (num, unit) = s.trim().split_once(' ')?;
    let mult = match unit.trim() {
        "B" => 1.0,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some(num.parse::<f64>().ok()? * mult)
}

/// Bundle B: the post-download tail tells the truth, and one job's
/// progress never appears on another job's row.
///
/// Two things used to go wrong at the seam between jobs, both of them
/// because the record has exactly one state - `Downloading` - for the
/// whole span from the first article to the last extracted byte.
///
/// 1. The scheduler deliberately starts job N+1 while job N's disk tail
///    runs, and every `Downloading` slot answered its percentage from
///    ONE pair of daemon-global counters. So the moment N+1 zeroed them,
///    the finishing job's bar fell from ~98% to 0 and then climbed again
///    with a download that was not its own.
/// 2. The finishing job went on calling itself a download at 100% with
///    the speed at zero, which is exactly what a dead pool looks like.
///
/// Sampled hard while two real jobs run through a mock server. The
/// monotonicity assertion is the one that would have caught the bleed:
/// a percentage that goes backwards is the bug, whatever caused it.
#[tokio::test(flavor = "multi_thread")]
async fn the_finishing_tail_is_named_and_never_borrows_the_next_job_s_bar() {
    let dir = std::env::temp_dir().join(format!("nzbfast-tailtruth-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Two posts, big enough that the settle read-back after net-drain is
    // wider than the poll interval below, and slow enough on the wire
    // that job A is still finishing when job B starts.
    let mut articles = HashMap::new();
    let mut nzb = |name: &str, seed: u8| {
        let data = payload(6_000_000, seed);
        let segs = make_file_articles(name, &data, 100_000, name, &mut articles);
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/60)\">\n    <groups><group>g</group></groups>\n    <segments>\n"
        );
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let xml_a = nzb("alpha.bin", 3);
    let xml_b = nzb("bravo.bin", 7);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 12,
            ..Chaos::default()
        },
    )
    .await;

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

    tokio::task::spawn_blocking(move || {
        let add = |xml: &str, name: &str| {
            let b = "----tailboundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{b}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{name}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={b}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "addfile refused: {r}");
        };
        add(&xml_a, "alpha");
        add(&xml_b, "bravo");

        // Every (status, percentage) this queue ever showed, per job, in
        // the order it showed them.
        let mut seen: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        let mut tails: Vec<(String, u64, String)> = Vec::new();
        // §91: every poll's header `sizeleft` beside the sum of the
        // `mbleft` values it is the total of.
        let mut header_vs_rows: Vec<(f64, f64)> = Vec::new();
        for _ in 0..4000 {
            let body = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            let v: serde_json::Value = match serde_json::from_str(
                body.split("\r\n\r\n").nth(1).unwrap_or(&body),
            ) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let slots = v["queue"]["slots"].as_array().cloned().unwrap_or_default();
            for s in &slots {
                let id = s["nzo_id"].as_str().unwrap_or_default().to_string();
                let st = s["status"].as_str().unwrap_or_default().to_string();
                let pct: u64 = s["percentage"].as_str().unwrap_or("0").parse().unwrap_or(0);
                if matches!(
                    st.as_str(),
                    "Verifying" | "Repairing" | "Extracting" | "Moving"
                ) {
                    tails.push((
                        st.clone(),
                        pct,
                        s["mbleft"].as_str().unwrap_or_default().to_string(),
                    ));
                }
                seen.entry(id).or_default().push((st, pct));
            }
            // No category filter and no start/limit on this poll, so the
            // slots ARE the whole queue and their remainders are exactly
            // what the header totals.
            let rows: f64 = slots
                .iter()
                .map(|s| {
                    s["mbleft"]
                        .as_str()
                        .unwrap_or("0")
                        .parse::<f64>()
                        .unwrap_or(0.0)
                        * 1024.0
                        * 1024.0
                })
                .sum();
            if let Some(hdr) = sab_size_bytes(v["queue"]["sizeleft"].as_str().unwrap_or("")) {
                header_vs_rows.push((hdr, rows));
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.matches("\"Completed\"").count() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(4));
        }

        assert_eq!(seen.len(), 2, "both jobs should have been observed: {seen:?}");
        // (1) No row's bar ever went backwards. This is the bleed, and
        // it failed loudly before the owner tag: the finishing job's
        // percentage dropped to whatever the next download had reached.
        for (id, samples) in &seen {
            let mut high = 0;
            for (st, pct) in samples {
                assert!(
                    *pct >= high,
                    "{id} went backwards to {pct}% (status {st}) after reaching {high}% \
                     - that is another job's progress on this job's row.\nsamples: {samples:?}"
                );
                high = *pct;
            }
        }
        // (2) The tail was named rather than reported as a download.
        assert!(
            tails
                .iter()
                .any(|(st, _, _)| st == "Verifying" || st == "Repairing" || st == "Extracting"),
            "no verify/repair/unpack phase ever reached the queue payload; \
             a finishing job still calls itself Downloading. observed: {tails:?}"
        );
        // (3) ...and a named tail reports its own bytes as all in.
        for (st, pct, mbleft) in &tails {
            assert_eq!(*pct, 100, "{st} reported {pct}%, not 100");
            assert_eq!(mbleft, "0.00", "{st} reported {mbleft} MB left, not 0");
        }
        // (4) §91: the header's total agrees with the rows it totals.
        //
        // `sizeleft` and the per-row `mbleft` used to be two separate
        // walks over the same queue, the header's running first - a
        // second lock on every job with the live counters re-read in
        // between, so the total described one instant and its parts
        // another. They are one walk now, and the total is summed from
        // the very numbers the rows print.
        //
        // The tolerance is deliberately loose: `sizeleft` is SAB's
        // two-significant-digit string ("1.2 MB"), not a byte count, so
        // exact equality is not available at this seam. What it catches
        // is the failure that matters - a whole job's bytes on one side
        // of the payload and not the other.
        // ...and it saw a queue with bytes actually outstanding, so the
        // comparison below is not 0 against 0 for every sample.
        assert!(
            header_vs_rows.iter().any(|(_, rows)| *rows > 0.0),
            "no queue payload ever had bytes left to fetch, so nothing was compared"
        );
        for (hdr, rows) in &header_vs_rows {
            let tol = hdr.max(*rows) * 0.06 + 64.0 * 1024.0;
            assert!(
                (hdr - rows).abs() <= tol,
                "queue sizeleft is {hdr:.0} B but its own slots have {rows:.0} B left \
                 between them - the header and the rows are describing different instants"
            );
        }
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// UX §18: `move_completed` and the split-move field it introduced.
///
/// A relocation that stops part way leaves the payload in TWO
/// directories, and the mover knew it and threw the fact away - so
/// history painted the job green and its `storage` named exactly one of
/// the two folders. `move_split` is the record of the other one.
///
/// This pins the whole-move path, which is the one that must NOT claim a
/// split: the job's files reach the destination, `storage` follows them,
/// and the field stays empty so no green download is ever slandered as
/// half-moved. (The split branch itself is decided by counting the
/// source directory before and after, in `relocate_completed`.)
#[tokio::test(flavor = "multi_thread")]
async fn a_completed_move_reports_its_destination_and_no_split() {
    let dir = std::env::temp_dir().join(format!("nzbfast-movesplit-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("moved-payload.bin", &data, 40_000, "mv", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;moved-payload.bin&quot; yEnc (1/5)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    // The destination is a sibling of the download folder, so the move is
    // a plain same-filesystem one - the merge path, which is exactly the
    // one that can split.
    let dest = dir.join("library");
    std::fs::create_dir_all(&dest).unwrap();
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
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let dest2 = dest.clone();

    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            &format!(
                "/api?mode=config&name=move_completed&value={}&output=json",
                urlenc(&dest2.to_string_lossy())
            ),
            None,
        );
        assert!(r.contains("true"), "move_completed was not accepted: {r}");

        let boundary = "----movesplitb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"moved.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");
        // C: the row completes BEFORE the move settles - the relocation
        // runs on the mover worker so a NAS copy cannot stall the next
        // download. Poll until the record follows the bytes.
        let mut slot = serde_json::Value::Null;
        for _ in 0..150 {
            let v: serde_json::Value =
                serde_json::from_str(&http(port, "/api?mode=history&output=json", None)).unwrap();
            slot = v["history"]["slots"][0].clone();
            let storage = slot["storage"].as_str().unwrap_or("");
            if storage.contains("library") && slot["move_pending"] != true {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let slot = &slot;
        // The record follows the bytes...
        let storage = slot["storage"].as_str().unwrap_or("");
        assert!(
            storage.contains("library"),
            "the record did not follow the move: {slot}"
        );
        // ...and says nothing about a split, because there was none.
        assert_eq!(slot["move_split"], "", "a whole move claimed a split: {slot}");
        // The payload really is at the destination and gone from the
        // download folder - a green row over a half-moved job is the
        // exact thing the field exists to prevent.
        let moved = walk_files(&dest2);
        assert!(
            moved.iter().any(|p| p.ends_with("moved-payload.bin")),
            "payload never reached the destination: {moved:?}"
        );
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Raising the Connections setting must beat a stored auto-tune knee.
///
/// The v1.0.14 field case: a single idle ladder measured 6 sockets for
/// the tester's provider and wrote it to conntune.json. Every job from
/// then on ran at 6 - about 25 MB/s on a 900 Mbps line - and nothing he
/// could type made any difference. He set 22, then 24, restarted the
/// app, tried a fresh NZB: still 6, with the Providers card reporting a
/// flat "6/6". The guard added later only ran at RECORD time, so it
/// could not help a knee already on disk.
///
/// Two wirings are pinned here, because the logic being right is not the
/// same as it being called: the live settings write, and the boot sweep
/// that reaches files written by older builds.
#[tokio::test(flavor = "multi_thread")]
async fn raising_connections_reopens_a_stored_low_knee() {
    let dir = std::env::temp_dir().join(format!("nzbfast-conntune-reopen-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    // A provider whose account allows 24. Nothing ever connects to it -
    // this test is about the state file, not about downloading.
    let write_cfg = || {
        std::fs::write(
            &cfg,
            br#"{"servers":[{"host":"news.example.invalid","port":119,"tls":false,
                 "username":"u","password":"p","connections":24}]}"#,
        )
        .unwrap()
    };
    // Exactly what v1.0.14 wrote: no `suspect`, no `limit`, no `v`.
    let write_v0_knee = || {
        std::fs::write(
            cfg.with_file_name("conntune.json"),
            br#"{"news.example.invalid":{"connections":6,"granted":6,"gbps":0.24,
                 "checked":1754000000,"source":"auto"}}"#,
        )
        .unwrap()
    };
    let knee = || {
        let raw = std::fs::read_to_string(cfg.with_file_name("conntune.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["news.example.invalid"].clone()
    };
    write_cfg();
    write_v0_knee();

    // Phase 1: the boot sweep reaches a file written by an older build.
    // Under SCHEMA 1 a knee of 6 against the default ceiling of 8 was
    // the tuner agreeing with the user and stood; since SCHEMA 2 every
    // pre-v2 knee was measured on the synthetic probe group (17x wrong
    // on a real provider) and is RETIRED on sight instead - suspect, so
    // jobs stop applying it, and queued for an immediate re-probe on
    // real articles.
    fn boot(cfg: PathBuf, out: PathBuf, conns: &'static str) -> impl Fn(u16) -> Command {
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string())
                .arg("--apikey")
                .arg("sekrit")
                .arg("--connections")
                .arg(conns)
                .arg("--out")
                .arg(&out);
            c
        }
    }
    let out = dir.join("complete");
    let d = serve(&dir, boot(cfg.clone(), out.clone(), "8")).await;
    let port = d.port;
    let k = knee();
    assert_eq!(
        k["suspect"], true,
        "a probe-group knee must retire at boot even at the ceiling in force"
    );
    assert_eq!(k["checked"], 0, "retired knee not queued for a re-probe");
    // Stamped: the entry has now been judged against a ceiling of 8 and
    // carries the current schema, which is what makes the sweep one-time.
    assert_eq!(k["limit"], 8);
    assert_eq!(
        k["connections"], 0,
        "a retired probe-group number must not survive as the yardstick the \
         next real-article ladder gets corroborated against"
    );

    // Phase 2: the ceiling-raise wiring, on an entry the CURRENT schema
    // wrote. A settled v2 knee of 6 under a ceiling of 8 stands; then
    // the user types 24, the way the dashboard sends it, and the live
    // settings write must reopen it without waiting for a restart.
    std::fs::write(
        cfg.with_file_name("conntune.json"),
        br#"{"news.example.invalid":{"connections":6,"granted":6,"gbps":0.24,
             "checked":1754000000,"source":"auto","suspect":false,
             "limit":8,"v":2}}"#,
    )
    .unwrap();
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=connections&value=24&apikey=sekrit",
            None,
        );
        assert!(r.contains("\"status\":true") || r.contains("24"), "{r}");
    })
    .await
    .unwrap();
    let k = knee();
    assert_eq!(k["suspect"], true, "24 asked for, knee of 6 still applied");
    assert_eq!(k["checked"], 0, "reopened knee not queued for a re-probe");
    assert_eq!(k["limit"], 24);
    assert_eq!(k["connections"], 6, "the measurement itself must survive");
    drop(d);

    // Phase 3: the same install, restarted. A tester who has ALREADY set
    // 24 gets no settings write to hang the fix on, so the boot sweep is
    // the only thing that can reach their file - it is the whole reason
    // the pre-guard entries on disk are recoverable at all.
    write_v0_knee();
    let d = serve(&dir, boot(cfg.clone(), out.clone(), "24")).await;
    let k = knee();
    assert_eq!(k["suspect"], true, "boot did not sweep a pre-guard knee");
    assert_eq!(k["limit"], 24);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Percent-encode a filesystem path for an API query value.
fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Every regular file under `root`, recursively.
fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk_files(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// #20: a finished download comes out with the configured permissions,
/// and so do the directories an *arr has to rename it out of.
///
/// The unit tests in `smart.rs` pin what `apply_out_umask` does to a
/// tree. This pins that it is REACHED - that the call sits after
/// everything which creates files (unpack, the rename passes, the
/// relocation) rather than before, where the payload would be re-created
/// underneath it.
///
/// Unix only: mode bits are the whole subject.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_download_carries_the_configured_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("nzbfast-outperm-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("perm-payload.bin", &data, 40_000, "pm", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;perm-payload.bin&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    let out_root = dir.join("complete");
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
            .arg("--out")
            .arg(&out_root);
        c
    })
    .await;
    let port = d.port;
    let out_root2 = out_root.clone();

    tokio::task::spawn_blocking(move || {
        // 0o007 rather than the recommended 0o002: it makes the expected
        // modes (770 / 660) impossible to confuse with anything the
        // process umask would have produced on its own, so a pass here
        // cannot be the default leaking through.
        let r = http(
            port,
            "/api?mode=config&name=out_umask&value=007&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "out_umask rejected: {r}");

        let boundary = "----outpermb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"perm.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("nzo_ids"), "{r}");

        // Wait for it to reach history.
        let mut hist = String::new();
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(150));
            hist = http(port, "/api?mode=history&output=json", None);
            if hist.contains("\"status\":\"Completed\"") {
                break;
            }
        }
        assert!(hist.contains("\"status\":\"Completed\""), "{hist}");

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let files = walk_files(&out_root2);
        assert!(!files.is_empty(), "nothing landed under {out_root2:?}");
        for f in &files {
            assert_eq!(mode(f), 0o660, "file {f:?} did not get the configured mode");
        }
        // The job's own directory...
        let job_dir = files[0].parent().unwrap();
        assert_eq!(mode(job_dir), 0o770, "job dir {job_dir:?}");
        // ...and the download root, which is the one an *arr needs write
        // on in order to rename the job out of it.
        assert_eq!(mode(&out_root2), 0o770, "download root");
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 97's "Clear queue" button, from the daemon's side: the wildcard
/// the dashboard posts (`value=all`) empties the queue in one call, and
/// says how many rows it took.
///
/// The count is the point of the assertion. `status` is a boolean and
/// always was; the button's toast reports a number, and a number the
/// daemon did not actually produce is exactly the kind of lie an
/// undoable-looking action must not tell. Asserted alongside the two
/// promises the confirm dialog makes on its behalf: nothing is filed to
/// history (a cleared job is dropped, not recorded), and without
/// `del_files` nothing on disk is touched - which for a job that never
/// ran means its output directory survives, payload and all.
///
/// Driven against a dead server, paused, so all three rows sit in the
/// queue for the whole test instead of racing a mock to failure.
#[tokio::test(flavor = "multi_thread")]
async fn clear_queue_empties_every_row_and_counts_them() {
    let dir = std::env::temp_dir().join(format!("nzbfast-qclear-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{dead_port},\"tls\":false}}]}}"),
    )
    .unwrap();
    let out = dir.join("complete");
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
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let upload = |stem: &str| {
            let xml = format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"{stem}.bin (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"10000\" number=\"1\">{stem}seg1@test</segment>\n    </segments>\n  </file>\n</nzb>\n"
            );
            let boundary = "----nzbfastboundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let ctype = format!("multipart/form-data; boundary={boundary}");
            let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
            assert!(r.contains("\"status\":true"), "{r}");
        };

        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        for stem in ["alpha", "bravo", "charlie"] {
            upload(stem);
        }
        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        assert_eq!(v["queue"]["slots"].as_array().map(Vec::len), Some(3), "{q}");

        // A directory the clear must NOT remove: the queue delete the
        // button posts carries no del_files, exactly like the per-row ✕.
        let kept = out.join("alpha-payload");
        std::fs::create_dir_all(&kept).unwrap();
        std::fs::write(kept.join("part.bin"), b"still here").unwrap();

        let r = http(
            port,
            "/api?mode=queue&name=delete&value=all&output=json",
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["status"], true, "{r}");
        assert_eq!(v["removed"], 3, "the clear must count what it took: {r}");

        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        assert_eq!(v["queue"]["slots"].as_array().map(Vec::len), Some(0), "{q}");

        // Dropped, not filed: a cleared job leaves no history record to
        // retry from, which is what the confirm dialog promises.
        let h = http(port, "/api?mode=history&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&h).unwrap();
        assert_eq!(
            v["history"]["slots"].as_array().map(Vec::len),
            Some(0),
            "a cleared queue must not file anything to history: {h}"
        );
        assert!(
            kept.join("part.bin").exists(),
            "the clear deleted files it never promised to touch"
        );

        // An empty queue is a no-op, and says so with both fields.
        let r = http(
            port,
            "/api?mode=queue&name=delete&value=all&output=json",
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["status"], false, "{r}");
        assert_eq!(v["removed"], 0, "{r}");
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// §129 2b (decision 5): the *arr add contract against real
/// per-category behavior - a category's default priority applies to a
/// default-priority add, pp=/script= are recorded on the job instead of
/// silently dropped, and get_config reports the category's REAL
/// dir/priority/script instead of the old static placeholders.
#[tokio::test(flavor = "multi_thread")]
async fn arr_category_contract_priority_pp_and_script_are_honored() {
    let dir = std::env::temp_dir().join(format!("nzbfast-catmeta-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    // Paused queue: the added job must stay inspectable, and with no
    // servers configured nothing could download anyway.
    http(port, "/api?mode=pause&output=json", None);
    // Real per-category behavior, as the settings UI saves it.
    let r = http(
        port,
        &format!(
            "/api?mode=config&name=cat_meta&value={}&output=json",
            urlenc(r#"{"tv":{"dir":"series","priority":1,"script":"/scripts/tv.py"}}"#)
        ),
        None,
    );
    assert!(r.contains("\"status\":true"), "{r}");

    // The Sonarr-shaped add: category + pp + per-job script, priority
    // left at the default so the category's own must fill it.
    let xml = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
               <file poster=\"x\" date=\"0\" subject=\"&quot;e.bin&quot; yEnc (1/1)\">\
               <groups><group>g</group></groups><segments>\
               <segment bytes=\"1000\" number=\"1\">catmeta@x</segment>\
               </segments></file></nzb>";
    let boundary = "----catmeta";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Show.S01E02.nzb\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&cat=tv&pp=1&script=None&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");

    let q = http(port, "/api?mode=queue&output=json", None);
    assert!(
        q.contains("\"priority\":\"High\""),
        "the category's default priority (1 = High) must fill a default add\n{q}"
    );
    assert!(
        q.contains("\"sab_pp\":1"),
        "the requested pp level must be recorded, not dropped\n{q}"
    );
    assert!(
        q.contains("\"script_override\":\"None\""),
        "the per-job script= must be recorded\n{q}"
    );

    // get_config: the categories block reports the REAL values.
    let c = http(port, "/api?mode=get_config&output=json", None);
    assert!(
        c.contains("\"dir\":\"series\""),
        "cat dir must be the configured subfolder\n{c}"
    );
    assert!(
        c.contains("\"script\":\"/scripts/tv.py\""),
        "cat script must be the configured one\n{c}"
    );

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}
