//! One daemon launcher for every integration suite that spawns
//! `nzbfast serve`, included by `mod harness;` the way `scratch/mod.rs`
//! already is.
//!
//! Written 22 Aug 2026 while porting `wall.rs`'s `DaemonLog` guard to
//! the rest of the suites. The copy-and-paste route was measured first:
//! stripping comments and blank lines from `struct KillOnDrop` through
//! the end of `wait_ready` in all sixteen suites that use the async
//! shape gave sixty lines that differ only in whether the local
//! variable is called `log` or `logfile`, plus three one-line extras (a
//! `pid` field, a `log` field, a `--min-free 0`). It was one launcher
//! written sixteen times, so it is one launcher now.
//!
//! Two things this file exists to hold, beyond the deduplication:
//!
//! 1. `DaemonLog`, so a failing test prints the daemon's own output
//!    next to the assertion instead of leaving it in $TMPDIR to be
//!    fished out by pid.
//! 2. The drop-order invariant that makes the guard actually fire. See
//!    `Daemon` below - it is subtle, it looked correct in a version
//!    that printed nothing, and it is the reason this is a type rather
//!    than a convention.
//!
//! Suite-specific launch policy stays in the suite. `serve` takes a
//! `build` closure, so a file that must pin `NZBFAST_LOG`, drop the
//! disk floor, or pass its own flags wraps this rather than forking it,
//! and the comment explaining why lives beside the tests it protects.

// One harness, six test binaries, each using a subset of it: an item
// this binary happens not to call is not dead code, it is code for the
// binary next door. Without this the clippy gate reddens on the first
// suite that does not read a log.
//
// `#[expect]` rather than `#[allow]` since 23 Aug 2026, and the
// multi-binary shape is the reason that needed measuring rather than
// assuming: this file is compiled into daemon, http_wedge,
// index_size_cap, leak_soak, queue_soak and integration, and the
// expectation has to be FULFILLED in every one of them or that binary
// goes red on `unfulfilled_lint_expectation`. It is - each of the six
// leaves at least one item unused - measured in default, default +
// `heavy-tests`, `--no-default-features` and
// `--target x86_64-pc-windows-gnu --features heavy-tests`. If a future
// binary grows to use ALL of this file, that is what will report, and
// the fix is to narrow the waiver, not to widen it back to `#[allow]`.
#![expect(dead_code)]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// OS-assigned free port for a daemon under test. The old pid-derived
/// scheme (`BASE + pid % M`, mixed moduli) collided for whole pid
/// windows - e.g. pid in [80000,81000) gave two tests the same port,
/// killing whichever daemon bound second - and could also land on the
/// ephemeral range the suites' own client sockets draw from.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A spawned child killed and reaped when it goes out of scope.
pub struct KillOnDrop(pub Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        // ...and reap it. kill() alone leaves a zombie holding its pid
        // for the rest of the binary's run, and the daemon suite starts
        // three dozen of them.
        let _ = self.0.wait();
    }
}

/// Lines of daemon log printed on a failure. Enough to cover a request
/// and the startup behind it, short enough not to bury the assertion
/// message it is there to explain.
const LOG_TAIL_LINES: usize = 40;

/// A daemon's captured stdout and stderr, printed on an unwind.
///
/// `ScratchDir` already keeps a panicking test's tree and says where it
/// is, but nothing pointed at the daemon's own log inside it.
/// Diagnosing the 22 Aug 2026 flake in
/// `a_wall_poll_seeds_its_page_without_disturbing_enriched_rows`
/// therefore cost several instrumented rebuilds: the sweep's output was
/// a tailed FAIL line, and the log had to be fished out of $TMPDIR by
/// pid. Printing it here puts it in the failing test's captured output,
/// beside the assertion that needs explaining.
///
/// It is a guard of its own, not a field `Daemon` prints in its own
/// Drop, because the two do not die together. A test that opens the
/// index database for itself must close the daemon first - the daemon
/// holds the write connection - so its assertions run AFTER the child
/// is gone, which is exactly the shape the flake above had. `Daemon::stop`
/// hands this back so the log outlives the daemon.
pub struct DaemonLog {
    port: u16,
    path: PathBuf,
}

impl DaemonLog {
    /// Where the log is on disk, for a test that wants to tail it from
    /// another thread.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Everything the daemon has written so far.
    pub fn text(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }
}

impl Drop for DaemonLog {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let text = self.text();
        let lines: Vec<&str> = text.lines().collect();
        let skipped = lines.len().saturating_sub(LOG_TAIL_LINES);
        // Every line carries the tag, not just the header: this lands
        // in the same captured stderr as the test's own panic message
        // and whatever else the case printed, so a line has to say
        // whose it is on its own.
        let tag = format!("daemon :{}", self.port);
        eprintln!("--- {tag} log tail: {} ---", self.path.display());
        if skipped > 0 {
            eprintln!("{tag} | ... {skipped} earlier line(s), in the file above");
        }
        if lines.is_empty() {
            eprintln!("{tag} | (empty or unreadable)");
        }
        for line in &lines[skipped..] {
            eprintln!("{tag} | {line}");
        }
    }
}

/// A daemon under test: killed and reaped on drop, with its stdout and
/// stderr captured to a log that is printed if the test unwinds.
///
/// No `Drop` of its own, deliberately, and both halves of that matter:
///
/// - The fields then drop in DECLARATION ORDER, so the child is killed
///   and reaped before `log` reads the file. The tail a failure prints
///   is the finished one, not one still being appended to. Do not
///   reorder these fields.
/// - `stop` below can move the log out. A type with a `Drop` impl
///   cannot be destructured, and the first version of this guard - a
///   plain `Drop` on the daemon that printed the tail - is exactly the
///   shape that printed NOTHING on a real reproduction of the flake it
///   was written for, because the cases that fail hardest are the ones
///   that close the daemon before they assert.
pub struct Daemon {
    child: KillOnDrop,
    pub port: u16,
    log: DaemonLog,
}

impl Daemon {
    /// The child's pid, for the tests that must ask the OS about the
    /// daemon rather than the daemon about itself.
    pub fn pid(&self) -> u32 {
        self.child.0.id()
    }

    /// Everything the daemon has written to stdout/stderr so far.
    pub fn log(&self) -> String {
        self.log.text()
    }

    /// Where that log is, for a test that hands the path to a thread or
    /// tails it after `stop`.
    pub fn log_path(&self) -> PathBuf {
        self.log.path.clone()
    }

    /// Block until `needle` appears in the daemon's own output, and
    /// return the log at that point. Panics with the whole log if it
    /// never arrives.
    pub fn wait_for(&self, needle: &str) -> String {
        for _ in 0..300 {
            let l = self.log();
            if l.contains(needle) {
                return l;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("never saw {needle:?}\n--- log ---\n{}", self.log());
    }

    /// Kill the daemon now and keep its log for the rest of the test.
    ///
    /// For the cases that must read `index.db` themselves: the daemon
    /// holds the write connection, so a second writer opening under a
    /// live one races the migrations. Hold the returned guard - `let
    /// _log = d.stop();` - and a later failure still prints the log.
    ///
    /// The child is reaped before this returns: `self.log` moves out,
    /// and what is left of `self` - the `KillOnDrop` - is dropped at
    /// the end of the call.
    pub fn stop(self) -> DaemonLog {
        self.log
    }
}

/// One launch attempt: pick a port, open its log, spawn the child.
///
/// Stdout and stderr are redirected here - a `build` that sets them will
/// have them overwritten.
fn spawn_one(dir: &Path, build: &impl Fn(u16) -> Command) -> (KillOnDrop, u16, PathBuf) {
    let port = free_port();
    // Per-port, so a restart in the same `dir` cannot read the previous
    // daemon's banner and call the new one ready.
    let path = dir.join(format!("daemon-{port}.log"));
    let out = std::fs::File::create(&path).unwrap();
    let err = out.try_clone().unwrap();
    let mut cmd = build(port);
    cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
    (KillOnDrop(cmd.spawn().unwrap()), port, path)
}

/// The daemon exited instead of binding: `free_port()` handed :port to a
/// parallel test between our bind(:0) and the daemon's bind, and that
/// test's daemon won it. Two more goes on a fresh port, then give up
/// with the log that says why.
fn assert_retryable(attempt: u32, port: u16, path: &Path) {
    let tail = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        attempt < 2,
        "daemon exited without binding :{port}\n--- log ---\n{tail}"
    );
}

/// Launch a daemon under `dir` and return once OUR daemon is serving.
///
/// `build` is handed the port to serve on and returns the fully
/// configured command; it may be called again on a fresh port, so it
/// must not consume anything.
///
/// The blocking half of `serve`, for the suites that are not `async`.
pub fn serve_blocking(dir: &Path, build: impl Fn(u16) -> Command) -> Daemon {
    for attempt in 0..3 {
        let (mut child, port, path) = spawn_one(dir, &build);
        if wait_ready(&mut child, port, &path) {
            return Daemon {
                child,
                port,
                log: DaemonLog { port, path },
            };
        }
        assert_retryable(attempt, port, &path);
    }
    unreachable!()
}

/// As `serve_blocking`, with the readiness wait off the runtime's
/// worker threads.
///
/// That wait blocks for as long as startup takes, and the caller's own
/// mock NNTP server is usually running on the same runtime. Only the
/// wait moves: `build` stays on this thread, so a closure may borrow
/// the caller's locals as every call site already does.
pub async fn serve(dir: &Path, build: impl Fn(u16) -> Command) -> Daemon {
    for attempt in 0..3 {
        let (child, port, path) = spawn_one(dir, &build);
        let logfile = path.clone();
        let (child, ready) = tokio::task::spawn_blocking(move || {
            let mut child = child;
            let ready = wait_ready(&mut child, port, &logfile);
            (child, ready)
        })
        .await
        .unwrap();
        if ready {
            return Daemon {
                child,
                port,
                log: DaemonLog { port, path },
            };
        }
        assert_retryable(attempt, port, &path);
    }
    unreachable!()
}

/// True once `text` carries THIS daemon's readiness banner for `port`,
/// whatever scheme it is serving.
///
/// The line is `nzbfast is running - open the dashboard at
/// {scheme}://localhost:{port}/`, and `{scheme}` is `https` under
/// `--tls-cert`/`--tls-key` - see the note beside the `println!` in
/// `crates/nzbfast/src/serve/startup.rs`, which says in as many words
/// that the scheme is load-bearing because harnesses match this line.
/// This matched the whole thing with `http` baked in until 23 Aug 2026,
/// so a TLS daemon that came up perfectly waited the full 60 s and then
/// panicked "daemon never came up on :PORT" - printing, as its
/// evidence, a log whose first screen holds the banner it had failed to
/// match. `integration/tls.rs` kept a private launcher for that reason
/// (TODO §242 item 5).
///
/// Split rather than made scheme-aware at the call site, because no
/// caller had to change and a suite that serves TLS should not have to
/// know the harness has a scheme at all. The two halves are chosen so
/// that neither is loose on its own: `http` stays on the prefix (it is
/// a prefix of `https` too, so it costs nothing and keeps the needle
/// anchored to a URL), and the tail carries the port, which is what
/// makes the line OURS rather than a stranger's on a recycled port.
/// Matched per LINE so the two cannot be satisfied by different lines -
/// the SABnzbd API line printed directly below this one is the same
/// shape with `/api` on the end.
fn banner_seen(text: &str, port: u16) -> bool {
    let tail = format!("://localhost:{port}/");
    text.lines()
        .any(|l| l.contains("open the dashboard at  http") && l.contains(&tail))
}

/// Wait for OUR daemon's own listener banner, not for "something
/// answers on :port". A bare connect cannot tell the two apart, and
/// under a full parallel run they diverge: `free_port()` can hand :port
/// to a second test between our bind(:0) and our daemon's bind, that
/// test's daemon wins the port, ours exits, and a plain connect then
/// succeeds against the OTHER daemon. The test would run against a
/// stranger and, when that stranger's owner finished and killed it,
/// fail mid-request with ConnectionReset. The banner is read from this
/// daemon's own log, so it can only be ours. (The bind itself happens
/// near the top of startup - see `serve`'s note beside spool_dir in
/// `crates/nzbfast/src/serve/startup.rs` - so the banner, printed once
/// startup is genuinely finished, is the readiness signal, not the
/// bind.)
///
/// False means the child exited first (the port race above); a genuine
/// hang panics with the log.
fn wait_ready(child: &mut KillOnDrop, port: u16, log: &Path) -> bool {
    for _ in 0..600 {
        if banner_seen(&std::fs::read_to_string(log).unwrap_or_default(), port)
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

/// One slot out of a SAB `mode=queue` or `mode=history` payload, found
/// by `nzo_id`; `Value::Null` when the job is not in that section.
///
/// This exists because `payload.contains(&nzo_id)` - the idiom this
/// replaced at 40-odd sites on 24 Aug 2026 - answers a different
/// question from the one every one of those sites was asking, and it
/// answers it wrong in two separate ways.
///
/// FIRST, the payload is more than its slots. `mode=queue` carries the
/// `whyslow` diagnostic block, and that block names the LAST job's own
/// `nzo_id` (`crates/nzbfast/src/serve/whyslow.rs`, the `"nzo_id":
/// owner` field), so `q.contains(&id)` reads TRUE against a queue whose
/// `slots` is `[]` and whose `noofslots` is 0. That is what bit
/// `daemon_bomb`'s `assert_refused_keeping` on 24 Aug 2026: its "the
/// min-free hold never requeued the job" assertion was really asking
/// "did this download run long enough to arm whyslow", and it failed 2
/// runs in 12 on the biggest fixture in that file. A history payload
/// has its own version of the same hazard - a Failed row carries
/// `fail_detail`, snapshotted out of the daemon's GLOBAL log ring, so
/// another job's `[queue] added <nzo_id> ...` line rides inside it. That
/// half is the older measurement of the two: it made
/// `cancelling_a_download_leaves_its_duplicate_held` flaky under `cargo
/// test --workspace` on 2 Aug 2026, at 7 failures in 10 loaded runs,
/// every one captured with history holding a single slot. The runner
/// picks a queued job on a 500 ms tick, so the dead job could open its
/// log bracket BEFORE the test's next upload landed - and a loaded box
/// is exactly what makes that upload slow enough to lose that race. The
/// poll then matched the ALTERNATIVE's id inside the dead job's
/// `fail_detail` and returned before the alternative had downloaded at
/// all.
///
/// SECOND, and this one breaks POSITIVE assertions and poll predicates
/// as well, nzo ids are minted `SABnzbd_nzo_nzbfast{n}` off a plain
/// incrementing counter (`crates/nzbfast/src/serve/daemon_enqueue.rs`,
/// and `daemon_persist.rs` on restore). `SABnzbd_nzo_nzbfast1` is a
/// strict PREFIX of `...nzbfast10` through `19`, and of `...100` up. A
/// suite that reaches ten jobs therefore has a `contains` that can be
/// satisfied by a job it never asked about.
///
/// Read the field it means: `queue_slot(&q, &id)["status"]` rather than
/// `q.contains(&id) && q.contains("Downloading")`, which two different
/// jobs can satisfy between them.
pub fn queue_slot(payload: &str, nzo: &str) -> serde_json::Value {
    section_slot(payload, "queue", nzo)
}

/// One slot out of a SAB `mode=history` payload. See [`queue_slot`].
pub fn history_slot(payload: &str, nzo: &str) -> serde_json::Value {
    section_slot(payload, "history", nzo)
}

/// Is this job in the queue's `slots` array? See [`queue_slot`] for why
/// this is not `payload.contains(&nzo)`.
pub fn queue_has(payload: &str, nzo: &str) -> bool {
    !queue_slot(payload, nzo).is_null()
}

/// Is this job in history's `slots` array? See [`queue_slot`].
pub fn history_has(payload: &str, nzo: &str) -> bool {
    !history_slot(payload, nzo).is_null()
}

/// The shared body of the four above. Panics with the whole payload on
/// unparseable JSON, which is the same bargain the callers' own
/// assertion messages make: printing the payload is what made the
/// original defect diagnosable, so a malformed one must not read as a
/// quiet `false`.
fn section_slot(payload: &str, section: &str, nzo: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(payload)
        .unwrap_or_else(|e| panic!("bad {section} JSON: {e}\n{payload}"));
    v[section]["slots"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["nzo_id"] == nzo).cloned())
        .unwrap_or(serde_json::Value::Null)
}
