//! Sweep 8 M4, the PRODUCTION path: a live `/stream` range response held
//! open on a repair target while the EXTERNAL par2 runs.
//!
//! The unit half of M4 lives in `nzbkit::disk`'s
//! `a_revoked_reader_lets_the_external_tool_in`, and it simulates the
//! player with a thread that holds a `ReadLease` and polls `revoked()`.
//! Nothing drove the real route - a daemon, an HTTP range response, a
//! damaged set, par2cmdline as the child - so the wiring between
//! `serve_range`'s lease and `park_outputs_for_repair` was never proven
//! end to end on the platform the whole fix exists for.
//!
//! **What holds the response open, and why it is not a parked read.**
//! A first cut parked the reader on the refused article's span, on the
//! theory that a hole nobody can deliver blocks forever. It does not: a
//! terminally-missing article leaves a zero-filled hole that counts as
//! covered, so the read wakes with zeros and the response completes
//! before par2 is ever spawned. What holds the inode in the field is an
//! ordinary player: a range over the whole file, consumed at playback
//! rate, still open when the download drains and postproc starts. That
//! is what these legs drive - a paced client, released to full speed
//! once the repair has been observed so the suite does not pay for the
//! pacing.
//!
//! Three legs. The first two are `/stream` ranges; leg 3 drives the
//! REMUX route (`/preview/media`) over the same shape, because
//! `LiveSource` polls the lease itself and shares no code with
//! `LiveRangeReader` above it.
//!
//! The platforms differ on purpose (see `disk::ReadCustody`):
//!
//! - **Windows** enforces sharing and par2cmdline opens its targets with
//!   share mode 0, so the response must END. The repair then succeeds.
//! - **Unix** does not enforce sharing, so the response KEEPS its fd
//!   straight through the repair and must go on to serve the repaired
//!   bytes - that is what M5's coverage publication is for, and killing
//!   the response there would be a regression traded for nothing.
//!
//! **WHICH par2 decides whether the lockout exists at all - measured 22
//! Aug 2026 on x86-64 Windows 11, holding a reader handle with Rust's
//! default share flags while `par2 repair` runs on a damaged target:**
//!
//! | par2cmdline | verdict                             |
//! |-------------|-------------------------------------|
//! | 0.8.1       | **"Repair Failed.", exit 5**        |
//! | 1.2.0       | repairs fine, exit 0                |
//! | 1.3.0       | repairs fine, exit 0                |
//!
//! So the share-mode-0 sentence above, and the same claim in
//! `disk::ReadCustody` and `repair::run_external_par2`, is TRUE OF 0.8.1
//! and no longer true of a current par2. Read that the right way round:
//! the revoke is still correct, because a Windows user installs whatever
//! par2 they have and 0.8.1 is still out there - it is simply no longer
//! load-bearing against an up-to-date one. **Do not test this fix
//! against par2 1.3.0, watch it pass either way, and conclude the
//! custody machinery is dead code.** Leg 1 was run with 0.8.1 on PATH
//! precisely to get a pass that means something.
//!
//! Every leg asserts the repair itself succeeded and the payload is
//! byte-correct, which is the half that was broken on Windows: par2
//! reported a repairable target as MISSING and declined.
//!
//! `par2` is a real dependency here, not a fixture tool: with native
//! repair switched off it IS the repair. A box without one covers
//! nothing, so `NZBFAST_REQUIRE_PAR2=1` turns its absence into a failure
//! rather than a green skip - set it for any run that is meant to be
//! evidence.

// The shared daemon launcher (free_port / KillOnDrop / DaemonLog /
// serve / wait_ready) and the scratch-dir guard, both declared once in
// main.rs because this file is a module of the merged binary.
use crate::scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::harness::{Daemon, serve};
use nzbkit::mock::{BodyLog, Chaos, MockServer, make_file_articles};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
        .collect()
}

/// Response body of a request to the daemon (headers stripped). Retries
/// only a connection that produced zero bytes - see queue_soak.rs.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
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

fn post_multipart(port: u16, req: &str, ctype: &str, data: &[u8]) -> String {
    let mut request = Vec::new();
    write!(
        request,
        "POST {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
        data.len()
    )
    .unwrap();
    request.extend_from_slice(data);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(&request).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

fn add_nzb(port: u16, name: &str, xml: &str) {
    let boundary = "----streamrepair";
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
    let r = post_multipart(
        port,
        "/api?mode=addfile&apikey=sekrit&output=json",
        &ctype,
        &body,
    );
    assert!(r.contains("nzo_ids"), "{r}");
}

/// Multi-file NZB (a release with its payload and its par2 set).
fn nzb_xml(files: &[(String, Vec<(String, u64, u32)>)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (subject, segs) in files {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{subject}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    xml
}

/// par2 is the REPAIR here, not a fixture convenience - see the module
/// header. `NZBFAST_REQUIRE_PAR2` makes a box without one red instead of
/// quietly green.
fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - with native \
         repair switched off there would be no repair at all, and this suite \
         would have looked green while proving nothing"
    );
    ok
}

/// The provider freeze all three legs run their handshake inside.
///
/// WHAT IT IS FOR. Every leg here asserts the same fixture invariant -
/// the player is open and reading, and the repair has NOT run yet -
/// and then holds the response open across par2. That ordering was
/// established by nothing but relative speed: the provider is paced at
/// 50 ms an article, and the test races it with a poll loop of HTTP
/// round trips to the same daemon. On an idle box the test wins. Under
/// load it does not, because the pacing is the mock's own wall clock
/// and does not slow down while the daemon's HTTP does.
///
/// MEASURED 31 Aug 2026, eight concurrent copies of the integration
/// binary on an 18-core box already at load 25:
/// `an_external_repair_gets_its_target_from_a_live_range_response`
/// failed THREE of eight at "the repair had already finished before
/// the player was reading" - and that is the leg the 30 Aug handoff
/// did NOT list, so the class is all three and not the two that were
/// seen. Six concurrent copies were green 18 of 18, which is why the
/// recipe in that handoff says eight.
///
/// WHY A FREEZE RATHER THAN A LONGER DEADLINE. A bigger threshold does
/// not fix an ordering test, it moves where the ambiguity starts. The
/// download cannot COMPLETE while the provider is not serving, so
/// postproc cannot start, so par2 cannot run - the invariant becomes a
/// property of the fixture rather than of how fast the box is. It is
/// `stream_live`'s own idiom (freeze the world, land the thing at a
/// known point in `body_log`, release), and its comment there is the
/// argument in one line: while the world is frozen, waiting longer is
/// free.
///
/// WHERE IT ARMS, and this is the part that had to be measured twice.
/// Legs 1 and 2 arm on the DAMAGED article being asked for - the one
/// moment each fixture already names, and late enough that the live
/// writer certainly exists. Leg 3 cannot: the remux will not OPEN until
/// the container's index has landed, and in Matroska that lives at the
/// END of the file, which is why `preview_media_request` prefetches the
/// tail before it builds a session at all. So leg 3 arms on the media
/// file's LAST article instead. Arming leg 3 at the damaged article was
/// tried first and hangs outright: frozen at 72% of the file, the
/// preview answers 425 for ever and the test waits out its own bound.
///
/// AND WHY EVERY LEG ALSO SLOWS ITS 430. The arming point alone is not
/// enough, which the first cut proved rather than assumed: with the
/// freeze armed at the damaged article and nothing else changed, leg 1
/// still failed 1 of 8 at eight-way load and leg 2 failed 1 of 8 - the
/// freeze simply arrived after the download had finished. There is not
/// much room to arrive in. MEASURED 31 Aug 2026 on an IDLE box: leg 3's
/// whole job, first byte to `repair complete`, is FOUR SECONDS, and
/// `[repair] need 1 block(s) → fetching 2 volume(s)` to `fetched 0.6 MB
/// of recovery data` is 278 ms; leg 1 freezes with 19 of 80 articles
/// left, which is 475 ms of provider pacing. A 25 ms poll has that much
/// to arm in, and a loaded box takes it away.
///
/// `missing_delay_ms` buys the margin. The damaged article is the last
/// thing the job waits on, so delaying its 430 holds the download short
/// of complete for as long as the delay, while everything else lands.
/// A real 430 IS a full round trip like any other body, which is what
/// that knob is for; and because this mock does not echo the id, the
/// pool asks twice, so the window is two of them rather than one.
///
/// WHAT LEG 2 FAILED ON, which is not the assertion below at all: its
/// `wait_stream_live`. That poll is looking for a file postproc TAKES
/// AWAY - this set demotes to "materializing volumes for repair" and
/// UNLINKS `movie.mkv`, which FINDING (b) at the foot of that leg
/// explains at length - so once the job reaches postproc there is no
/// live file left and the poll cannot succeed however long it runs. It
/// then spends its whole 60 s budget and fails. Reproduced here with
/// the freeze armed too late: `[repair] materializing volumes for
/// repair` in the daemon log, `/stream never served the head of the
/// live file` in the test. Held short of complete, the job never
/// reaches postproc while the poll is running.
struct Freeze {
    pause: Arc<AtomicBool>,
    log: Arc<Mutex<BodyLog>>,
    /// Every message-id in the fixture. `assert_held` holds the DISTINCT
    /// ids asked against this, which is what tells a freeze that stopped
    /// the world short of the end from one that arrived after the last
    /// article was already down.
    posted: usize,
    armed: bool,
}

impl Freeze {
    fn new(srv: &MockServer, posted: usize) -> Freeze {
        Freeze {
            pause: srv.pause.clone(),
            log: srv.body_log.clone(),
            posted,
            armed: false,
        }
    }

    /// Block until the provider has been asked for `id`, then stop it
    /// serving.
    fn arm(&mut self, id: &str) {
        let (log, want) = (self.log.clone(), id.to_string());
        crate::harness::wait_until(
            &format!("the download to reach {want}"),
            Duration::from_secs(180),
            || log.lock().unwrap().contains(&want),
        );
        self.pause.store(true, Ordering::Release);
        self.armed = true;
    }

    /// A GREEN RUN CANNOT TELL A WORKING FREEZE FROM AN INERT ONE, which
    /// is the whole reason this is an assertion and not a comment. If
    /// `pause` ever stops holding, every leg here quietly goes back to
    /// racing the provider and nothing says so.
    ///
    /// Two questions, because either alone can be satisfied by a broken
    /// freeze. IS THE WORLD STOPPED RIGHT NOW - measured by watching the
    /// log over a window rather than by comparing against a snapshot
    /// taken at `arm`, deliberately: the mock checks `pause` at the top
    /// of its command loop, so a command already read still lands, and
    /// an exact match against an arming snapshot would be asserting on
    /// how many microseconds that took on a loaded box. That is the
    /// wall-clock reasoning this whole struct exists to remove, and it
    /// would have made the freeze its own flake. AND DID IT STOP THE
    /// WORLD SHORT OF THE END - a freeze armed after the last article
    /// was already served is perfectly stable and holds nothing back.
    fn assert_held(&self) {
        assert!(self.armed, "the freeze was never armed");
        let len = || self.log.lock().unwrap().len();
        let before = len();
        std::thread::sleep(Duration::from_millis(300));
        let after = len();
        assert_eq!(
            before,
            after,
            "the provider served {} more article(s) in 300 ms - the freeze is \
             inert and this leg is racing the download again",
            after.saturating_sub(before)
        );
        let asked: std::collections::HashSet<String> =
            self.log.lock().unwrap().iter().cloned().collect();
        assert!(
            asked.len() < self.posted,
            "all {} of the fixture's articles had been asked for by the time the \
             freeze armed, so it is holding nothing back",
            self.posted
        );
    }

    /// Let the download finish, so postproc and par2 can run.
    fn release(&self) {
        self.pause.store(false, Ordering::Release);
    }
}

/// `par2 create` over files already written into `dir`, returning the
/// recovery files as (name, bytes) and removing them from the staging
/// directory (they travel in the NZB, not on disk).
fn par2_files(dir: &Path, redundancy: u32, slice: usize, names: &[&str]) -> Vec<(String, Vec<u8>)> {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg(format!("-s{slice}"))
        .arg("-q")
        .arg("relset")
        .args(names)
        .current_dir(dir)
        .status()
        .expect("run par2");
    assert!(st.success(), "par2 create failed in {}", dir.display());
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    par2s
        .iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let data = std::fs::read(p).unwrap();
            std::fs::remove_file(p).unwrap();
            (name, data)
        })
        .collect()
}

/// Bytes a paced read asks for at a time, and the gap between them:
/// ~640 KB/s, an unhurried playback rate. Slow enough that a multi-MB
/// range is still being served when postproc starts, and that the socket
/// buffers cannot swallow the whole response behind the test's back.
const PACE_CHUNK: usize = 64 * 1024;
const PACE_GAP: Duration = Duration::from_millis(100);
/// How long one socket read waits before the loop looks at its flags,
/// and the outer bound on a response that never ends.
const POLL: Duration = Duration::from_secs(2);
const POLL_CAP: Duration = Duration::from_secs(300);

/// A held `/stream` range response, driven from its own thread.
///
/// The daemon writes the headers before it pulls a byte from
/// `LiveRangeReader`, so "headers arrived" is exactly "the response owns
/// a handle on the inode" - which is the state this whole fix is about.
#[derive(Default)]
struct HeldState {
    headers: Option<String>,
    body: Vec<u8>,
    done: Option<Result<(), String>>,
}

struct Held {
    st: Arc<Mutex<HeldState>>,
    fast: Arc<AtomicBool>,
    /// A second handle on the same socket, and the flag that goes with
    /// it, so the test can hang up on a response the daemon is never
    /// going to end (see leg 2).
    sock: Arc<Mutex<Option<TcpStream>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Held {
    /// Open `GET /stream` with `range` and keep reading, at playback
    /// pace, until the daemon ends the response.
    fn open(port: u16, range: &str) -> Held {
        Held::open_req(port, "/stream", &format!("Range: {range}\r\n"))
    }

    /// The same held-and-paced client over any request. Leg 3 drives
    /// `/preview/media`, which takes no `Range` and answers chunked.
    fn open_req(port: u16, path: &str, extra: &str) -> Held {
        let st = Arc::new(Mutex::new(HeldState::default()));
        let fast = Arc::new(AtomicBool::new(false));
        let sock: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let (mine, my_fast, my_sock, my_stop) =
            (st.clone(), fast.clone(), sock.clone(), stop.clone());
        let (path, extra) = (path.to_string(), extra.to_string());
        let thread = std::thread::spawn(move || {
            let run = || -> std::io::Result<()> {
                let mut s = TcpStream::connect(("127.0.0.1", port))?;
                *my_sock.lock().unwrap() = Some(s.try_clone()?);
                write!(
                    s,
                    "GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n"
                )?;
                // Short poll rather than one long block: a `shutdown`
                // from another thread does not reliably unblock a
                // blocked `recv` on Windows, so the hang-up is a flag
                // this loop checks between reads. `POLL_CAP` is the
                // outer bound - a wedged response must fail the test,
                // not hang the suite.
                s.set_read_timeout(Some(POLL))?;
                let t0 = Instant::now();
                let mut raw = Vec::new();
                let mut head_done = false;
                let mut buf = vec![0u8; PACE_CHUNK];
                loop {
                    if my_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let n = match s.read(&mut buf) {
                        Ok(n) => n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            if t0.elapsed() > POLL_CAP {
                                return Err(e);
                            }
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    if n == 0 {
                        break;
                    }
                    let mut g = mine.lock().unwrap();
                    if head_done {
                        g.body.extend_from_slice(&buf[..n]);
                    } else {
                        raw.extend_from_slice(&buf[..n]);
                        if let Some(cut) = find_headers_end(&raw) {
                            g.headers = Some(String::from_utf8_lossy(&raw[..cut]).to_string());
                            g.body = raw[cut + 4..].to_vec();
                            head_done = true;
                        }
                    }
                    drop(g);
                    if !my_fast.load(Ordering::Relaxed) {
                        std::thread::sleep(PACE_GAP);
                    }
                }
                Ok(())
            };
            let out = run().map_err(|e| e.to_string());
            mine.lock().unwrap().done = Some(out);
        });
        Held {
            st,
            fast,
            sock,
            stop,
            thread: Some(thread),
        }
    }

    /// Block until the response headers are on the wire - i.e. until the
    /// handle is genuinely open - and return the status line.
    fn wait_headers(&self, within: Duration) -> String {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            if let Some(h) = self.st.lock().unwrap().headers.clone() {
                return h;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("/stream never sent its response headers within {within:?}");
    }

    /// Wait until the player has actually consumed some of the body -
    /// the reader is now inside `LiveRangeReader::read`, which is where
    /// a revoked lease is noticed.
    fn wait_reading(&self, within: Duration) {
        let t0 = Instant::now();
        while self.st.lock().unwrap().body.is_empty() {
            assert!(
                t0.elapsed() < within,
                "the response sent headers but never a byte of body within {within:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn body_len(&self) -> usize {
        self.st.lock().unwrap().body.len()
    }

    /// The body as it stands right now, for an assertion about what the
    /// player has been served SO FAR rather than in the end.
    fn body_so_far(&self) -> Vec<u8> {
        self.st.lock().unwrap().body.clone()
    }

    /// Stop pacing - the point of the pacing was to still be here when
    /// the repair ran, and it has been.
    fn release(&self) {
        self.fast.store(true, Ordering::Relaxed);
    }

    /// Did the response end by itself within `within`?
    fn ended_within(&self, within: Duration) -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            if self.finished() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// Hang up. For a response the daemon will not end on its own -
    /// waiting out `LiveRangeReader`'s five-minute span timeout would
    /// cost the suite five minutes to learn nothing.
    fn close(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(s) = self.sock.lock().unwrap().as_ref() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    fn finished(&self) -> bool {
        self.st.lock().unwrap().done.is_some()
    }

    /// What the response looks like right now - for failure messages.
    fn describe(&self) -> String {
        let g = self.st.lock().unwrap();
        format!(
            "status={:?} body={} zeros={} head={:02x?} done={:?}",
            g.headers.as_deref().and_then(|h| h.lines().next()),
            g.body.len(),
            g.body.iter().filter(|b| **b == 0).count(),
            &g.body[..g.body.len().min(8)],
            g.done
        )
    }

    /// Wait for the response to end, then hand back its body and outcome.
    fn join(mut self, within: Duration) -> (Vec<u8>, Result<(), String>) {
        self.release();
        let t0 = Instant::now();
        while t0.elapsed() < within && !self.finished() {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            self.finished(),
            "the held /stream response never ended within {within:?} - on Windows \
             the lease was not revoked, on Unix the repaired coverage never \
             reached the reader: {}",
            self.describe()
        );
        let _ = self.thread.take().unwrap().join();
        let g = self.st.lock().unwrap();
        (g.body.clone(), g.done.clone().unwrap())
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.release();
        self.close();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn find_headers_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The daemon under test: native repair OFF so par2cmdline is the
/// repair, zero-fill OFF so a reader parked on the damaged span stays
/// parked (degraded playback would let it walk past the hole and drop
/// its handle before the repair ever started, which is the one way this
/// test could pass without testing anything).
fn daemon_cmd(cfg: &Path, out: &Path, port: u16) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    c.env("NZBFAST_OPEN", "1")
        .env("NZBFAST_NO_ENRICH", "1")
        .env("NZBFAST_NO_NATIVE_REPAIR", "1")
        .env("NZBFAST_STREAM_ZEROFILL", "0")
        // The external-repair tests wait on nzbfast's own lowercase INFO
        // "repair complete" wrapper event - deliberately, it is the
        // repaired-coverage barrier - and the child falls back to
        // ambient RUST_LOG when NZBFAST_LOG is unset, so a parent shell
        // exporting RUST_LOG=warn timed three of them out with the
        // repair done (Codex sweep 24 Aug, F-22). Pin INFO at the child.
        .env("NZBFAST_LOG", "info")
        .env_remove("RUST_LOG")
        .arg("--config")
        .arg(cfg)
        .arg("serve")
        .arg("--connections")
        .arg("2")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--apikey")
        .arg("sekrit")
        .arg("--out")
        .arg(out);
    c
}

fn write_config(dir: &Path, srv: &MockServer) -> PathBuf {
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
    cfg
}

/// Wait for the job to leave the queue, then for its output to exist.
fn wait_done(port: u16, within: Duration) -> String {
    let t0 = Instant::now();
    let mut last = String::new();
    while t0.elapsed() < within {
        last = http(port, "/api?mode=history&apikey=sekrit&output=json");
        if last.contains("\"status\":\"Completed\"") || last.contains("\"status\":\"Failed\"") {
            return last;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("the job never reached history within {within:?}: {last}");
}

/// Wait for `needle` to appear in the daemon's log.
fn wait_log(d: &Daemon, needle: &str, within: Duration) -> String {
    let t0 = Instant::now();
    loop {
        let log = d.log();
        if log.contains(needle) {
            return log;
        }
        assert!(
            t0.elapsed() < within,
            "{needle:?} never reached the daemon log within {within:?}:\n{log}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The biggest `.mkv` under `root`. The job is filed and auto-renamed by
/// the time it reaches history, and par2 leaves the damaged original
/// beside the repaired file as `<name>.1`, so neither the folder nor the
/// leaf name is predictable - the payload is.
fn find_mkv(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "mkv")
                && best.as_ref().is_none_or(|(n, _)| md.len() > *n)
            {
                best = Some((md.len(), p));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Every `<name>.<digits>` file under `root` - the shape par2cmdline
/// renames a damaged target aside as (`.1`, then `.2` if that is taken).
/// A repaired job must publish none of them; see FINDING (a) in leg 2.
fn leftover_par2_backups(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            // A recoverable cleanup delete is PARKED in a hidden
            // `.nzbfast-trash` beside the swept directory before the
            // background worker disposes of it (smart.rs), so a file in
            // one is already out of the user's output. It should not be
            // under `root` at all - the park is beside the incomplete
            // job dir - but reading a purged file back out of the
            // staging folder would be a race, not a finding.
            if name.starts_with('.') {
                continue;
            }
            if e.metadata().is_ok_and(|md| md.is_dir()) {
                stack.push(p);
                continue;
            }
            if let Some((_, ordinal)) = name.rsplit_once('.')
                && !ordinal.is_empty()
                && ordinal.bytes().all(|c| c.is_ascii_digit())
            {
                found.push(p);
            }
        }
    }
    found
}

/// Block until `/stream` serves the head of the live file - i.e. until
/// there is a live media writer to hold a handle on.
fn wait_stream_live(port: u16) {
    for _ in 0..600 {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(
            s,
            "GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1023\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        if String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 206") {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("/stream never served the head of the live file");
}

/// par2cmdline's own words for the failure this fix exists to prevent.
/// They arrive on the daemon's stdout, so the log is the oracle.
fn assert_par2_was_not_locked_out(log: &str) {
    for needle in [
        "used by another process",
        "Repair is not possible",
        "Could not open",
    ] {
        assert!(
            !log.contains(needle),
            "par2 was locked out of its target - {needle:?} in the daemon log. \
             That is the M4 finding, unfixed:\n{log}"
        );
    }
}

/// The verdict both legs share, taken once the job has reached history.
fn assert_repaired_externally(hist: &str, log: &str) {
    assert!(
        hist.contains("\"status\":\"Completed\""),
        "the job did not complete:\n{hist}\n--- log ---\n{log}"
    );
    assert!(
        log.contains("repair complete"),
        "the set was never repaired:\n{log}"
    );
    assert!(
        !log.contains("(native"),
        "native repair ran - this only means anything through par2cmdline:\n{log}"
    );
    assert!(
        log.contains("Repair complete."),
        "par2cmdline never reported a repair - was this really the external \
         path?:\n{log}"
    );
    assert_par2_was_not_locked_out(log);
}

// ---------------------------------------------------------------------------

/// Leg 1, the sharp one: the streamed file IS a par2 target.
///
/// A plain `.mkv` posted with its own recovery set (an ordinary un-rar'd
/// posting), one article refused forever, and a range response parked on
/// exactly that hole when the external repair starts. par2cmdline must
/// open `movie.mkv` for WRITE to repair it, so on Windows a surviving
/// reader handle is not a warning, it is the whole repair: the target
/// reports missing and par2 declines.
#[tokio::test(flavor = "multi_thread")]
async fn an_external_repair_gets_its_target_from_a_live_range_response() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const ART: usize = 200_000;
    const SIZE: usize = 16_000_000;
    // Article 61 covers [12 MB, 12.2 MB). The damage sits far beyond
    // anything the paced player - or a socket buffer running ahead of it
    // - can have reached by the time the repair runs, so on Unix the
    // bytes eventually served there are necessarily the REPAIRED ones.
    const HOLE: usize = 60 * ART;

    let dir = std::env::temp_dir().join(format!("nzbfast-streamrepair-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();

    let inner = payload(SIZE, 5);
    std::fs::write(stage.join("movie.mkv"), &inner).unwrap();
    let recovery = par2_files(&stage, 10, ART, &["movie.mkv"]);
    assert!(!recovery.is_empty(), "par2 produced no recovery files");

    let mut articles = HashMap::new();
    let mut files = vec![(
        "movie.mkv".to_string(),
        make_file_articles("movie.mkv", &inner, ART, "mv", &mut articles),
    )];
    for (i, (name, data)) in recovery.iter().enumerate() {
        let segs = make_file_articles(name, data, ART, &format!("p{i}"), &mut articles);
        files.push((name.clone(), segs));
    }
    let xml = nzb_xml(&files);

    // Paced provider: two connections and 50 ms an article puts a couple
    // of seconds between the first byte and the repair, which is the
    // window the player has to be reading in. Unpaced, this whole job -
    // download, verify, external repair - took 300 ms and the reader
    // could not be shown to have been there at all.
    //
    // `missing_delay_ms` is the freeze's margin, not the player's - see
    // `Freeze`. It holds the job short of complete while the freeze
    // arms, which pacing alone does not.
    let chaos = Chaos {
        missing: ["<mv-61@mock>".to_string()].into(),
        missing_delay_ms: 6_000,
        delay_ms: 50,
        ..Default::default()
    };
    let posted = articles.len();
    let srv = MockServer::start(articles, chaos).await;
    let cfg = write_config(&dir, &srv);
    let out = dir.join("complete");
    let d = serve(&dir, |port| daemon_cmd(&cfg, &out, port)).await;
    let port = d.port;

    let mut freeze = Freeze::new(&srv, posted);
    let (held, freeze) = tokio::task::spawn_blocking(move || {
        add_nzb(port, "Stream.Repair.2026", &xml);
        // Freeze the provider on the damaged article, so the handshake
        // below cannot lose a race with the download - see `Freeze`.
        freeze.arm("<mv-61@mock>");
        wait_stream_live(port);
        // The response under test: the whole file, consumed at playback
        // pace. A bare `GET /stream` is only ever served from the live
        // pipeline (the on-disk path needs an nzo_id), so its 206 means
        // a `FileWriter::open_read` handle and the lease that goes with
        // it.
        let held = Held::open(port, "bytes=0-");
        let status = held.wait_headers(Duration::from_secs(60));
        assert!(
            status.starts_with("HTTP/1.1 206"),
            "the held range response is not a 206:\n{status}"
        );
        held.wait_reading(Duration::from_secs(60));
        (held, freeze)
    })
    .await
    .unwrap();

    // The fixture's teeth: the response is open, reading, and nowhere
    // near done at the moment the external repair starts. Without them
    // the player could have come and gone before par2 was ever spawned,
    // and the test would pass having proved nothing.
    freeze.assert_held();
    assert!(
        !held.finished(),
        "the response ended before the repair: {}",
        held.describe()
    );
    assert!(
        !d.log().contains("repair complete"),
        "the repair had already finished before the player was reading"
    );
    freeze.release();
    wait_log(&d, "repair complete", Duration::from_secs(180));
    assert!(
        held.body_len() < SIZE,
        "the whole span was served before the repair even started"
    );

    held.release();
    let hist = tokio::task::spawn_blocking(move || wait_done(port, Duration::from_secs(180)))
        .await
        .unwrap();
    assert_repaired_externally(&hist, &d.log());

    let (body, outcome) = tokio::task::spawn_blocking(move || held.join(Duration::from_secs(120)))
        .await
        .unwrap();

    // The repaired file on disk is the first thing par2's exit 0 claims.
    let done = find_mkv(&out).unwrap_or_else(|| panic!("no .mkv under {}", out.display()));
    let got = std::fs::read(&done).unwrap();
    assert_eq!(got.len(), inner.len(), "the repaired output is short");
    assert!(got == inner, "the repaired output differs from the payload");

    if cfg!(windows) {
        // The lease was revoked mid-read and the response ended, which
        // is what let par2 rename and rewrite the target at all.
        assert!(
            body.len() < SIZE,
            "the response served its whole span on Windows, so it held the \
             inode across the repair: {} of {SIZE} bytes",
            body.len()
        );
        let _ = outcome;
    } else {
        // No revocation, by design: the reader keeps its fd and its
        // response, and must not be killed for a repair that Unix does
        // not need it to get out of the way of.
        outcome.expect("the held response failed instead of finishing");
        assert_eq!(
            body.len(),
            SIZE,
            "the response did not serve its whole span"
        );

        // The whole point of M5's coverage publication, and the one
        // place it is visible: the response that held its handle across
        // the repair must serve the REPAIRED bytes over the repaired
        // span, not the damaged ones.
        //
        // Found false here on 22 Aug 2026 and fixed as sweep 8 M5b.
        // par2cmdline does not repair a damaged target in place: it
        // renames it to `<name>.1` and writes the repaired data to a NEW
        // inode. The writer survived that all along (`unpark` reopens by
        // `current_path`); the live response did not - its fd was still
        // on the old inode, so the coverage publication told it the
        // bytes were good and it served the zero-filled hole off the
        // orphaned file. `LiveRangeReader::rebind` now reopens at
        // `current_path` mid-response, on the same lease and at the same
        // offset, the first time it reads after a repair completes
        // (`ReadLease::needs_reopen`).
        //
        // Windows never saw it - the lease is revoked and the response
        // ends before par2 runs - which is exactly why the platform
        // split hid it, and why this assertion lives in the Unix arm.
        // The rebind really fired, rather than the response having
        // been served the right bytes by some other route.
        assert!(
            d.log().contains("an external repair rewrote the file"),
            "the response never reopened, so any correct bytes below are \
             luck:\n{}",
            d.log()
        );
        // Compared by first mismatch, not with `assert_eq!` on the
        // slices: the span is 200 KB and a failure would otherwise
        // print all of it twice.
        let bad = (HOLE..HOLE + ART).find(|&i| body[i] != inner[i]);
        assert!(
            bad.is_none(),
            "the held response served STALE bytes over the repaired span \
             (first mismatch at {:?}, {} instead of {}): its handle is still \
             on the inode par2 renamed away",
            bad,
            body[bad.unwrap()],
            inner[bad.unwrap()]
        );
    }
}

/// Leg 2, the task's literal shape: a damaged MULTI-VOLUME store RAR set,
/// with the range response held on the extracted media file.
///
/// Here the par2 targets are the VOLUMES, and the extracted `movie.mkv`
/// is not a par2 target, not an extra file, and not on disk at all by
/// the time par2 runs: the set demotes to "materializing volumes for
/// repair" first, and that demote unlinks it. So nothing parks or
/// revokes it - the custody machinery leg 1 exercises has no part to
/// play here. What must hold instead is that the repair completes with
/// the extracted payload byte-correct, and that the response the player
/// is holding on that vanished output ENDS rather than waiting out the
/// five-minute span timeout (FINDING (b) below).
#[tokio::test(flavor = "multi_thread")]
async fn an_external_repair_of_a_volume_set_still_admits_the_child() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    use nzbkit::rar::fixtures;
    const ART: usize = 200_000;
    const SIZE: usize = 12_000_000;

    let dir = std::env::temp_dir().join(format!("nzbfast-streamrepair-v-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();

    let inner = payload(SIZE, 9);
    // Odd split points so no volume boundary aligns with an article or a
    // par2 slice.
    let cut1 = 4_000_003;
    let cut2 = 8_000_005;
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", SIZE as u64, &inner[..cut1], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", SIZE as u64, &inner[cut1..cut2], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", SIZE as u64, &inner[cut2..], true, false)],
            2,
        ),
    ];
    let names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        std::fs::write(stage.join(name), vol).unwrap();
    }
    let recovery = par2_files(&stage, 10, ART, &names);
    assert!(!recovery.is_empty(), "par2 produced no recovery files");

    let mut articles = HashMap::new();
    let mut files = Vec::new();
    for (i, (name, vol)) in names.iter().zip(&vols).enumerate() {
        let segs = make_file_articles(name, vol, ART, &format!("v{i}"), &mut articles);
        files.push((name.to_string(), segs));
    }
    for (i, (name, data)) in recovery.iter().enumerate() {
        let segs = make_file_articles(name, data, ART, &format!("p{i}"), &mut articles);
        files.push((name.clone(), segs));
    }
    let xml = nzb_xml(&files);

    // One article of the LAST volume, refused forever: the damage lands
    // near the end of the extracted file, well past the paced player.
    let victim = articles
        .keys()
        .find(|k| k.starts_with("<v2-8@mock"))
        .expect("the third volume has at least 8 articles")
        .clone();
    // `missing_delay_ms`: the freeze's margin - see `Freeze`.
    let chaos = Chaos {
        missing: [victim.clone()].into(),
        missing_delay_ms: 6_000,
        delay_ms: 50,
        ..Default::default()
    };
    let posted = articles.len();
    let srv = MockServer::start(articles, chaos).await;
    let cfg = write_config(&dir, &srv);
    let out = dir.join("complete");
    let d = serve(&dir, |port| daemon_cmd(&cfg, &out, port)).await;
    let port = d.port;

    // What this leg fails ON under load is not the assertion below but
    // `wait_stream_live` itself - see `Freeze`, WHAT LEG 2 FAILED ON.
    let mut freeze = Freeze::new(&srv, posted);
    let damaged = victim;
    let (held, freeze) = tokio::task::spawn_blocking(move || {
        add_nzb(port, "Stream.Repair.Vols.2026", &xml);
        freeze.arm(&damaged);
        wait_stream_live(port);
        let held = Held::open(port, "bytes=0-");
        let status = held.wait_headers(Duration::from_secs(60));
        assert!(
            status.starts_with("HTTP/1.1 206"),
            "the held range response is not a 206:\n{status}"
        );
        held.wait_reading(Duration::from_secs(60));
        (held, freeze)
    })
    .await
    .unwrap();

    freeze.assert_held();
    assert!(
        !held.finished(),
        "the response ended before the repair: {}",
        held.describe()
    );
    assert!(
        !d.log().contains("repair complete"),
        "the repair had already finished before the player was reading"
    );
    freeze.release();
    wait_log(&d, "repair complete", Duration::from_secs(240));

    held.release();
    let hist = tokio::task::spawn_blocking(move || wait_done(port, Duration::from_secs(240)))
        .await
        .unwrap();
    let log = d.log();
    assert!(
        log.contains("repair complete"),
        "the volume set was never repaired:\n{log}"
    );
    assert!(
        !log.contains("(native"),
        "native repair ran - this only means anything through par2cmdline:\n{log}"
    );
    assert!(
        log.contains("Repair complete."),
        "par2cmdline never reported a repair:\n{log}"
    );
    assert_par2_was_not_locked_out(&log);
    assert!(
        log.contains("re-extracting") && log.contains("movie.mkv"),
        "the repaired volumes were never re-extracted:\n{log}"
    );

    // FINDING (b), FIXED - and these two are the assertions that hold it
    // fixed. The held response used to be STRANDED here on BOTH
    // platforms (measured 22 Aug 2026 on macOS arm64 and on an x86-64
    // Windows 11 laptop): a player hung for five minutes on a job that
    // repaired fine.
    //
    // The mechanism, confirmed by probe rather than assumed. This set
    // demotes to "materializing volumes for repair" BEFORE par2 runs,
    // and `movie.mkv` is a ROUTED inner file - a CHILD slot's writer,
    // not one of this level's `inner_writers`. The demote runs
    // `fallback_group` -> `delete_group_out_files` -> `abandon_slot`
    // over it, which TAKES the writer out of the child's slot and
    // unlinks the file. `Extractor::each_output` walks `inner_writers` +
    // slot writers + the child, so by the time
    // `park_outputs_for_repair` runs there is nothing left to claim:
    // the probe showed it claiming `r.part1-3.rar` and `relset.par2`
    // and nothing else, with the output directory holding no
    // `movie.mkv` at all. Nothing revoked the player's lease and
    // nothing moved its custody generation, so the reader parked on a
    // frontier that would never move again and died of
    // `LiveRangeReader`'s five-minute span timeout.
    //
    // `FileWriter::abandon` is the fix: the demote marks the writer, and
    // the two live pollers (`LiveRangeReader::abandoned` and
    // `LiveSource::abandoned`) end the response on every platform - this
    // is not a sharing question, the file is simply gone. The log line
    // is asserted as well as the end, for leg 1's reason: a response
    // that ended for some OTHER reason would green a bare `ended`.
    //
    // Note what this leg therefore does NOT prove, and never did: the
    // stranded response never BLOCKED this repair. par2's targets here
    // are the volumes, and `movie.mkv` is not on disk when par2 runs -
    // it is not even passed as an extra file. Measured separately
    // against par2cmdline 0.8.1 (the one version a held handle defeats):
    // the lockout is TARGET-specific - par2 opens a target for WRITE and
    // renames it aside, which a held handle defeats, while an extra file
    // it only reads and that open succeeds with another handle on it. An
    // earlier guess - that par2 opens extras only when it needs
    // unmatched blocks - is REFUTED by that same run: it opened the
    // extra either way. Do not revive it.
    assert!(
        held.ended_within(Duration::from_secs(5)),
        "the held response was STRANDED after the repair - it is waiting out \
         `LiveRangeReader`'s five-minute span timeout on a frontier that will \
         never move again: {}",
        held.describe()
    );
    assert!(
        d.log().contains("the extractor abandoned this output"),
        "the response ended without ever noticing the abandoned output, so it \
         ended for some other reason and proves nothing:\n{}",
        d.log()
    );
    let (body, _outcome) = tokio::task::spawn_blocking(move || held.join(Duration::from_secs(60)))
        .await
        .unwrap();
    assert!(!body.is_empty(), "the player never got any bytes at all");
    assert!(
        body.len() < SIZE,
        "the response served its whole span, so it was never ended at all: {} \
         of {SIZE} bytes",
        body.len()
    );

    let done = find_mkv(&out).unwrap_or_else(|| panic!("no .mkv under {}", out.display()));
    let got = std::fs::read(&done).unwrap();
    assert!(got == inner, "the extracted payload differs after repair");

    // FINDING (a), FIXED - and this is the assertion that holds it
    // fixed. par2cmdline renames the damaged original aside as
    // `r.part3.rar.1` on EVERY version measured (0.8.1, 1.2.0, 1.3.0),
    // and nothing used to clear it: the post-unpack sweep collects
    // candidates by `Rar!` magic rather than by extension, so it read
    // the leftover as an obfuscated set of its own, could not unpack a
    // middle volume with no first part, and FAILED the whole job -
    // "an archive in the output directory could not be unpacked" - with
    // the correct 12 MB payload sitting right there. This leg used to
    // stop at the payload above and accept either outcome, because the
    // fix changes what gets deleted from a user's output directory and
    // that was not the verifying session's call to make.
    //
    // `repair::purge_par2_backups` now removes them, on a successful
    // external repair only. The status assertion is the regression
    // test: it is the ONLY leg in the suite that runs the sweep over a
    // directory par2 has renamed in.
    assert!(
        hist.contains("\"status\":\"Completed\""),
        "the repaired job did not complete. A leftover par2 backup \
         (`r.part3.rar.1`) reaching the post-unpack sweep is the known \
         way this fails - check for one before assuming anything \
         else:\n{hist}\n--- log ---\n{log}"
    );
    // Directly, so a job that completes for some other reason cannot
    // green this: nothing par2 renamed aside may survive in the output.
    let backups = leftover_par2_backups(&out);
    assert!(
        backups.is_empty(),
        "par2 backup file(s) left in the output directory: {backups:?}"
    );
}

// ---------------------------------------------------------------------------

/// Undo `Transfer-Encoding: chunked`. `/preview/media` has no length to
/// give - the remuxed bytes do not exist until they are produced - so
/// its body arrives chunked, and a search for a payload frame in the
/// raw socket bytes would miss any frame a chunk header happens to
/// split.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < body.len() {
        let Some(eol) = body[p..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let Ok(n) = usize::from_str_radix(String::from_utf8_lossy(&body[p..p + eol]).trim(), 16)
        else {
            break;
        };
        p += eol + 2;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&body[p..(p + n).min(body.len())]);
        p += n + 2;
    }
    out
}

/// The first offset at which `pat` occurs in `hay`.
fn find(hay: &[u8], pat: &[u8]) -> Option<usize> {
    if pat.is_empty() || hay.len() < pat.len() {
        return None;
    }
    hay.windows(pat.len()).position(|w| w == pat)
}

/// Leg 3: the same repair under the REMUX route.
///
/// Leg 1 proves the byte-serving reader - `/stream`, `LiveRangeReader`,
/// `LiveRangeReader::rebind`. `/preview/media` is a second reader over
/// the same file with the same duty and none of the same code above the
/// lease: `LiveSource::read_at_wait` polls `ReadLease::needs_reopen`
/// itself, and a session that read on through the pre-repair handle
/// would remux the DAMAGED bytes over a span the repair had already
/// fixed.
///
/// `preview.rs`'s own unit test builds a `LiveSource` by hand and moves
/// a file under it, which proves the poll and nothing above it. What
/// had never been driven at all - by this suite or by the daemon
/// suite's `/preview/media` test, which runs against a FINISHED job and
/// so gets a `DiskSource` - is the live arm of the handler: the lease
/// that `open_live_media` opens, threaded into the `LiveSource` the
/// remux session holds for the whole response. This leg is the only
/// coverage of it.
///
/// The oracle is the payload itself. A remux COPIES its elementary
/// streams, so a video frame in the source appears verbatim in the
/// `mdat` of the fragmented MP4. The frame this asserts on is the one
/// inside the article the mock refuses forever - so it exists in the
/// output only if the session read it off the file par2 REPAIRED,
/// rather than off the inode par2 renamed aside.
///
/// Verified red the way leg 1 was: with the `needs_reopen` poll backed
/// out of `LiveSource::read_at_wait`, this leg fails at the frame
/// assertion - the session walks into the zero-filled hole on the
/// orphaned inode, the cluster walk gives up there, and the response
/// ends 11.4 MB into a 16.1 MB file with the repaired frame nowhere in
/// it. So the failure is not subtle on this route: a viewer does not
/// see a damaged second, the picture stops.
///
/// **Windows:** the response is not expected to end, and the body is
/// not asserted on. `LiveSource` deliberately does not poll
/// `ReadLease::revoked` (it has no read loop to bail out of), so a
/// preview session holds its handle through `park`'s bounded drain
/// (`disk::REPAIR_DRAIN_WAIT`, 10 s - so the leg costs that much more
/// there) and the repair then proceeds anyway, which is the pre-lease
/// behaviour. That is fine against a par2 that does not lock out, and
/// pr-check's Windows job installs par2cmdline-turbo 1.4.0. Against
/// 0.8.1 it is not fine, and that gap is real but is NOT this leg's to
/// fix: the fix is one line in `read_at_wait` next to the `abandoned`
/// check, and it changes what a Windows viewer sees mid-repair, which
/// is not something to land untested from a Mac.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_preview_remux_follows_an_external_repair() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const ART: usize = 200_000;
    /// 75x the remux fixture is ~16 MB of real Matroska - the same size
    /// leg 1 posts, and for the same two reasons. The download has to
    /// take long enough for a player to be mid-response when postproc
    /// starts, and the remuxed output has to be far larger than any
    /// socket buffer, or the whole body would be written behind the
    /// paced client's back before the repair ever ran.
    const SCALE: usize = 75;
    /// The video frame the assertion is about - 208 of 288, far enough
    /// into the clusters that a 640 KB/s player cannot have reached it
    /// by repair time.
    ///
    /// Not any frame past halfway, though, and the runtime check below
    /// is why the constant is this one. A fixture frame is
    /// `tag ^ (i * 31)` with `tag = 0xA0 ^ index`, so it repeats every
    /// 256 bytes - and XOR by 0x80 is exactly a 128-byte shift of that
    /// cycle, which makes frame `index ^ 128` byte-for-byte the same
    /// filler. Whichever of the pair is LONGER contains the shorter
    /// one, so a target whose partner outruns it can be matched off
    /// undamaged bytes elsewhere in the file and the assertion at the
    /// end proves nothing. 208 is longer than 80; 200 is not longer
    /// than 72.
    const TARGET: usize = 208;

    let dir = std::env::temp_dir().join(format!("nzbfast-previewrepair-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();

    let inner = nzbkit::mediaprobe::testmux::mkv_remux_fixture_scaled(SCALE);
    let (video, _audio) = nzbkit::mediaprobe::testmux::mkv_remux_streams_scaled(SCALE);
    let target = video[TARGET].clone();
    let at = find(&inner, &target).expect("the target frame is not in the fixture");
    // Unique BEYOND its own span. `at` is the first occurrence, and a
    // frame's filler repeats every 256 bytes, so the pattern always
    // matches itself shifted - what must not exist is a second copy
    // somewhere else in the file, which would make the assertion at the
    // end of this leg satisfiable off undamaged bytes.
    assert_eq!(
        find(&inner[at + target.len()..], &target),
        None,
        "the target frame's bytes occur again outside its own span"
    );
    // The article that carries it, whole: a frame straddling two
    // articles would still be a fair test, but only one of its halves
    // would be the repaired one and the failure message would lie.
    let hole = at / ART;
    assert_eq!(
        (at + target.len() - 1) / ART,
        hole,
        "the target frame straddles articles - move TARGET"
    );
    std::fs::write(stage.join("movie.mkv"), &inner).unwrap();
    let recovery = par2_files(&stage, 10, ART, &["movie.mkv"]);
    assert!(!recovery.is_empty(), "par2 produced no recovery files");

    let mut articles = HashMap::new();
    let mut files = vec![(
        "movie.mkv".to_string(),
        make_file_articles("movie.mkv", &inner, ART, "pv", &mut articles),
    )];
    for (i, (name, data)) in recovery.iter().enumerate() {
        let segs = make_file_articles(name, data, ART, &format!("q{i}"), &mut articles);
        files.push((name.clone(), segs));
    }
    let xml = nzb_xml(&files);

    // Paced exactly as leg 1's provider is, and for the same reason:
    // unpaced, the whole job is over before a client can be shown to
    // have been there.
    //
    // `missing_delay_ms`: the freeze's margin - see `Freeze`, which also
    // says why THIS leg alone arms on the tail article rather than on
    // the damaged one.
    let chaos = Chaos {
        missing: [format!("<pv-{}@mock>", hole + 1)].into(),
        missing_delay_ms: 6_000,
        delay_ms: 50,
        ..Default::default()
    };
    let posted = articles.len();
    let srv = MockServer::start(articles, chaos).await;
    let cfg = write_config(&dir, &srv);
    let out = dir.join("complete");
    let d = serve(&dir, |port| daemon_cmd(&cfg, &out, port)).await;
    let port = d.port;

    let mut freeze = Freeze::new(&srv, posted);
    // The LAST article of the media file, not the damaged one - see
    // `Freeze`, WHERE IT ARMS.
    let tail_article = format!("<pv-{}@mock>", inner.len().div_ceil(ART));
    let (held, freeze) = tokio::task::spawn_blocking(move || {
        add_nzb(port, "Preview.Repair.2026", &xml);
        // The endpoint is gated at `metadata-only` as well as at `off`,
        // and metadata-only is the default: without this every request
        // below is a 403.
        http(
            port,
            "/api?mode=config&name=preview&value=full&apikey=sekrit&output=json",
        );
        // Freeze once the container's index is on its way: everything
        // below is a poll loop of HTTP round trips against the same
        // daemon the download is running in, and this is the leg that
        // lost that race first - see `Freeze`.
        freeze.arm(&tail_article);
        // There has to be a live media writer before there is anything
        // to preview, and `open_live_media` answers 404 - not 425 -
        // until there is.
        wait_stream_live(port);
        let nzo = wait_live_nzo(port);
        // Poll until the container header has landed. Before that the
        // handler answers 425 with no body and no lease held (and 404
        // while the job it names is not the live one yet), which is a
        // poll rather than a failure - so a rejected attempt is closed
        // and retried rather than asserted on.
        let t0 = Instant::now();
        loop {
            let held = Held::open_req(port, &format!("/preview/media/{nzo}?apikey=sekrit"), "");
            let status = held.wait_headers(Duration::from_secs(60));
            if status.starts_with("HTTP/1.1 200") {
                assert!(
                    status.contains("X-Nzbfast-Path: remux"),
                    "the live preview did not take the remux route:\n{status}"
                );
                held.wait_reading(Duration::from_secs(60));
                return (held, freeze);
            }
            assert!(
                status.starts_with("HTTP/1.1 425") || status.starts_with("HTTP/1.1 404"),
                "the live preview answered none of 200, 425 or 404:\n{status}"
            );
            assert!(
                t0.elapsed() < Duration::from_secs(120),
                "the live preview never got past {}",
                status.lines().next().unwrap_or_default()
            );
            drop(held);
            std::thread::sleep(Duration::from_millis(200));
        }
    })
    .await
    .unwrap();

    // The fixture's teeth, leg 1's to the letter: the response is open,
    // reading, and nowhere near the damaged span when the repair runs.
    freeze.assert_held();
    assert!(
        !held.finished(),
        "the remux ended before the repair: {}",
        held.describe()
    );
    assert!(
        !d.log().contains("repair complete"),
        "the repair had already finished before the player was reading"
    );
    freeze.release();
    wait_log(&d, "repair complete", Duration::from_secs(240));
    // And - the sharp form, in the coordinates the verdict is taken in -
    // the frame this leg ends by looking for has NOT been served yet. A
    // remux that had already emitted it would satisfy that verdict with
    // bytes it read long before par2 ran.
    assert!(
        find(&dechunk(&held.body_so_far()), &target).is_none(),
        "the player had already been served the frame at {at} ({} body \
         bytes) before the repair started",
        held.body_len()
    );

    held.release();
    let hist = tokio::task::spawn_blocking(move || wait_done(port, Duration::from_secs(240)))
        .await
        .unwrap();
    assert_repaired_externally(&hist, &d.log());

    // The repaired file on disk is the first thing par2's exit 0 claims.
    let done = find_mkv(&out).unwrap_or_else(|| panic!("no .mkv under {}", out.display()));
    let got = std::fs::read(&done).unwrap();
    assert!(got == inner, "the repaired output differs from the payload");

    if cfg!(windows) {
        // See the header: nothing revokes this reader, so the response
        // outlives the repair here too - but it was never the platform
        // the reopen path runs on, and a body assertion would be
        // asserting on the wrong mechanism.
        drop(held);
        return;
    }

    let (raw, outcome) = tokio::task::spawn_blocking(move || held.join(Duration::from_secs(180)))
        .await
        .unwrap();
    outcome.expect("the held remux failed instead of finishing");
    let body = dechunk(&raw);

    // The rebind really fired, rather than the frame below having
    // arrived by some other route.
    assert!(
        d.log().contains("an external repair rewrote the file"),
        "the remux session never reopened, so any correct bytes below \
         are luck:\n{}",
        d.log()
    );
    assert!(
        find(&body, &target).is_some(),
        "the frame inside the repaired span is not in the remuxed output \
         ({} bytes of fMP4 from a {} byte source): the session read it off \
         the inode par2 renamed away",
        body.len(),
        inner.len()
    );
}

/// The nzo_id of the job that is downloading right now.
fn wait_live_nzo(port: u16) -> String {
    let t0 = Instant::now();
    let mut last = String::new();
    while t0.elapsed() < Duration::from_secs(120) {
        last = http(port, "/api?mode=queue&apikey=sekrit&output=json");
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&last)
            && let Some(id) = v["queue"]["slots"]
                .get(0)
                .and_then(|s| s["nzo_id"].as_str())
        {
            return id.to_string();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("no job appeared in the queue: {last}");
}
