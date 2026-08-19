//! Running a post-processing script: a child with a real deadline, its
//! pipes drained so it cannot wedge on a full buffer, and a bounded tail
//! of its stderr kept for the failure report.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Run a child to completion with a deadline, draining its pipes.
///
/// `Command::output()` has no timeout, so a post-processing script that
/// hung held its `spawn_blocking` thread for the life of the daemon, and
/// one per completed job after that. Returns `(None, _)` when the
/// deadline was hit and the child killed; `secs == 0` waits forever,
/// which is what someone running a multi-hour transcode wants.
///
/// stderr is drained by its own thread rather than polled: a child that
/// fills the 64 KB pipe buffer blocks on the write, so waiting on the
/// process alone would turn any chatty script into a timeout. stdout is
/// drained too, and thrown away - nothing reads it, and a script that
/// prints for a living should not be able to spend the daemon's memory
/// proving it.
///
/// Only the LAST [`SCRIPT_ERR_TAIL`] bytes of stderr are kept. The whole
/// stream used to accumulate in a `String`, so an accidental
/// `while true; do echo …; done` grew the daemon until it died - well
/// before any deadline could stop it.
///
/// Two things the deadline has to survive, both of them ordinary
/// post-script shapes rather than hostile ones:
///
///  - A script that backgrounds work (`transcode & `) and exits. The
///    descendant INHERITS stdout/stderr, so the pipes stay open after
///    the direct child is gone and a `join` on the drain threads blocked
///    until the descendant finished. That join ran on the daemon's
///    blocking pool, one leaked worker per completed job, and the pool
///    is finite. The drains are therefore never joined.
///
///    They are not abandoned either (§144 item 4). Never joining them
///    still left the thread, its 8 KB buffer and the pipe's read end
///    alive for as long as the descendant lived - forever, for a script
///    that daemonizes, and once per completed job. So on unix each
///    drain polls a stop flag; the flag is set once the direct child
///    has been reaped and the short grace below has passed, and the
///    thread returns and drops its read end within one poll interval.
///    The descendant is deliberately NOT killed: leaving a notifier or
///    a media-server scan kick running is a legitimate thing for a
///    post-script to do, and killing the process group on a CLEAN exit
///    would break it. It simply stops costing us a thread and two FDs.
///    A descendant that keeps writing gets EPIPE, which is what any
///    process writing into a pipe nobody reads gets. Windows keeps the
///    blocking drain - a pipe handle is not pollable without rewriting
///    the reads as overlapped I/O, which is a bigger change than this
///    fix warrants (the same reasoning as the kill path below).
///  - The same script when the deadline expires. `Child::kill` signals
///    the direct child alone, so on unix the child is given its own
///    process group and the whole group is signalled. Windows keeps the
///    single-process kill (a job object is the equivalent, and is a
///    bigger change than this fix warrants).
pub(super) fn run_capped(
    cmd: std::process::Command,
    secs: u64,
) -> std::io::Result<(Option<std::process::ExitStatus>, String)> {
    let (status, _, stderr) = run_capped_inner(cmd, secs, false)?;
    Ok((status, stderr))
}

/// §129 4a: `run_capped`, but the FIRST [`SCRIPT_OUT_HEAD`] bytes of
/// stdout are kept too - the pre-queue verdict is stdout's opening
/// lines, so the head is the interesting end (where stderr keeps its
/// tail: the last words before death). Everything past the head is
/// drained and dropped under the same never-join discipline.
pub(super) fn run_capped_capture(
    cmd: std::process::Command,
    secs: u64,
) -> std::io::Result<(Option<std::process::ExitStatus>, String, String)> {
    run_capped_inner(cmd, secs, true)
}

fn run_capped_inner(
    mut cmd: std::process::Command,
    secs: u64,
    capture_stdout: bool,
) -> std::io::Result<(Option<std::process::ExitStatus>, String, String)> {
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Own process group, so the deadline can reach what the script
    // spawned. Inherited by every descendant that does not deliberately
    // leave it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;
    let tail = Arc::new(Mutex::new(BoundedTail::default()));
    let head = Arc::new(Mutex::new(Vec::<u8>::new()));
    // Detached on purpose, and leashed: see the doc comment. Each thread
    // owns its pipe and exits when the last writer closes it OR when
    // this flag says we have stopped caring, whichever comes first.
    let stop = Arc::new(AtomicBool::new(false));
    if let Some(r) = child.stdout.take() {
        let (stop, g) = (stop.clone(), DrainGuard::new());
        if capture_stdout {
            let head = head.clone();
            std::thread::spawn(move || {
                let _g = g;
                drain_into_head(r, &stop, &head)
            });
        } else {
            std::thread::spawn(move || {
                let _g = g;
                drain_to_nowhere(r, &stop)
            });
        }
    }
    if let Some(r) = child.stderr.take() {
        let (stop, tail, g) = (stop.clone(), tail.clone(), DrainGuard::new());
        std::thread::spawn(move || {
            let _g = g;
            drain_into(r, &stop, &tail)
        });
    }
    let deadline = (secs > 0).then(|| Instant::now() + std::time::Duration::from_secs(secs));
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            #[cfg(unix)]
            unsafe {
                // Negative pid = the whole group. The direct child is
                // killed by the same signal, so no separate kill needed;
                // fall back to it if the group send fails.
                if libc::kill(-(child.id() as i32), libc::SIGKILL) != 0 {
                    let _ = child.kill();
                }
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    // The child is gone; its own writes are already in the ring or in
    // flight. A short grace collects the tail end without waiting on any
    // descendant that may still hold the pipe open - and then the drains
    // are released, because nothing reads what arrives after this point.
    std::thread::sleep(std::time::Duration::from_millis(50));
    stop.store(true, Ordering::Release);
    let stderr = tail.lock_ok().tail_text();
    let stdout = String::from_utf8_lossy(&head.lock_ok()).into_owned();
    Ok((status, stdout, stderr))
}

/// How much of a script's stderr is worth keeping. Enough for a stack
/// trace or a usage message, which is all the log line quotes.
pub(super) const SCRIPT_ERR_TAIL: usize = 8 << 10;

/// The last [`SCRIPT_ERR_TAIL`] bytes written to it, and nothing else.
#[derive(Default)]
pub(super) struct BoundedTail {
    pub(super) buf: std::collections::VecDeque<u8>,
    pub(super) dropped: usize,
}

impl BoundedTail {
    pub(super) fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
        while self.buf.len() > SCRIPT_ERR_TAIL {
            self.buf.pop_front();
            self.dropped += 1;
        }
    }

    /// The kept tail as text, prefixed with what was dropped. Not a
    /// `Display` impl: this is a lossy read-out of a byte ring for one
    /// log line, not a rendering of the value.
    pub(super) fn tail_text(&self) -> String {
        let text =
            String::from_utf8_lossy(&self.buf.iter().copied().collect::<Vec<u8>>()).into_owned();
        if self.dropped == 0 {
            text
        } else {
            // Say what was cut, or a truncated trace reads as the whole
            // story - the interesting line may be the one that went.
            format!("[…{} earlier bytes dropped…]{text}", self.dropped)
        }
    }
}

/// Drain threads alive right now, across every `run_capped` in flight.
///
/// The never-join discipline means nothing else can observe them, and
/// the §144 item 4 invariant - a script that has returned costs us
/// nothing, however long its descendants live - is exactly this coming
/// back to where it started. The regression test reads it; two relaxed
/// atomics per script run is what that costs.
pub(super) static DRAIN_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Counts one live drain thread for as long as it exists. Made by the
/// spawning side (so the count is never briefly wrong while a thread
/// starts up) and moved into the thread, which drops it on every exit
/// path.
pub(super) struct DrainGuard;

impl DrainGuard {
    fn new() -> Self {
        DRAIN_THREADS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        DRAIN_THREADS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The pipe end a drain thread owns. On unix it has to be pollable, so
/// the drain can come back to its stop flag between reads; on Windows
/// the drain is a plain blocking read and `Read` is all it needs.
#[cfg(unix)]
pub(super) trait PipeRead: std::io::Read + std::os::unix::io::AsRawFd {}
#[cfg(unix)]
impl<T: std::io::Read + std::os::unix::io::AsRawFd> PipeRead for T {}
#[cfg(not(unix))]
pub(super) trait PipeRead: std::io::Read {}
#[cfg(not(unix))]
impl<T: std::io::Read> PipeRead for T {}

/// How long a drain waits for the next byte before looking at its stop
/// flag again. Short enough that a finished script's thread and FD are
/// gone before anyone could observe them, long enough that an idle
/// drain costs 20 wakeups a second and nothing else.
#[cfg(unix)]
const DRAIN_POLL_MS: libc::c_int = 50;

/// Read `r` until EOF, an error, or `stop`, handing every chunk to
/// `sink`.
#[cfg(unix)]
fn drain(mut r: impl PipeRead, stop: &AtomicBool, mut sink: impl FnMut(&[u8])) {
    // `AsRawFd` comes in with `PipeRead`, which requires it on unix.
    let fd = r.as_raw_fd();
    // Non-blocking, so the loop always comes back to the flag: a read
    // that finds nothing returns WouldBlock instead of parking in the
    // kernel until a descendant we no longer own decides to speak.
    let pollable = unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        fl >= 0 && libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) >= 0
    };
    if !pollable {
        // fcntl on a pipe we opened ourselves does not fail in practice.
        // If it ever did, a thread that outlives its script is a much
        // better failure than one that spins on a non-blocking read.
        return drain_blocking(r, sink);
    }
    let mut buf = [0u8; 8192];
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        match r.read(&mut buf) {
            // Every writer closed: the ordinary end, and the only one
            // that happens while the direct child is still running.
            Ok(0) => return,
            Ok(n) => {
                sink(&buf[..n]);
                // Straight back to the read - a chatty script must not
                // pay a poll per 8 KB. The flag check at the top of the
                // loop still bounds a writer that never stops.
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // A failed poll needs no handling: the next iteration re-checks
        // the flag and re-reads, which is all a successful one buys.
        unsafe { libc::poll(&mut pfd, 1, DRAIN_POLL_MS) };
    }
}

/// The pre-§144 drain: ends only when the last writer closes the pipe.
/// Windows keeps it (see [`run_capped`]), and unix falls back to it if
/// the descriptor cannot be made non-blocking.
#[cfg(not(unix))]
fn drain(r: impl PipeRead, _stop: &AtomicBool, sink: impl FnMut(&[u8])) {
    drain_blocking(r, sink)
}

fn drain_blocking(mut r: impl std::io::Read, mut sink: impl FnMut(&[u8])) {
    let mut buf = [0u8; 8192];
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 {
            return;
        }
        sink(&buf[..n]);
    }
}

pub(super) fn drain_into(r: impl PipeRead, stop: &AtomicBool, tail: &Mutex<BoundedTail>) {
    drain(r, stop, |bytes| tail.lock_ok().push(bytes));
}

pub(super) fn drain_to_nowhere(r: impl PipeRead, stop: &AtomicBool) {
    drain(r, stop, |_| {});
}

/// How much of a captured stdout's HEAD is kept - the pre-queue verdict
/// is seven short lines, so this is generous, and everything past it is
/// drained to nowhere so a chatty script still cannot spend memory.
pub(super) const SCRIPT_OUT_HEAD: usize = 8 << 10;

pub(super) fn drain_into_head(r: impl PipeRead, stop: &AtomicBool, head: &Mutex<Vec<u8>>) {
    drain(r, stop, |bytes| {
        let mut h = head.lock_ok();
        let room = SCRIPT_OUT_HEAD.saturating_sub(h.len());
        h.extend_from_slice(&bytes[..bytes.len().min(room)]);
        // Past the head: keep draining (the drop above), never store.
    });
}

/// Which half of a record's generation a script run is fenced on.
///
/// Not a bool: `run_script(.., true)` at a call site says nothing about
/// what is being asked, and this exact distinction has now been got
/// wrong twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fence {
    /// The whole `(retries, move_seq)` pair. For callers that run BEFORE
    /// their own park.
    Generation,
    /// The retry half only. For the detached worker, whose caller parks
    /// the instant it has been spawned.
    RetriesOnly,
}

impl Daemon {
    /// M14d: post-processing hook with SABnzbd's contract - the 8
    /// positional args and SAB_* env vars that the existing script
    /// ecosystem (notifiers, sorters, library refreshers) expects.
    /// §129 4a adds the NZBGet side of the same ecosystem: NZBPP_* env
    /// and the 93/94/95 exit-code vocabulary, as a documented mapping
    /// (decision 5's rule - map, never silently ignore).
    ///
    /// `gen0` fences the whole snapshot. The record is read ONCE, and
    /// the generation is tested under that same hold, because the two
    /// questions "is this still my job" and "what are its argv and env"
    /// have to be answered against the same instant. The awaited caller
    /// (`run_post_job_hooks_before_park`) tested neither: `post_job_owed`
    /// checks the generation while it builds the plan, then the plan is
    /// handed to a `spawn_blocking` that reads the record again later,
    /// and `finalizing` has been cleared by then - so a delete plus a
    /// Retry landing in between ran the OLD job's script against the NEW
    /// generation's out_dir and name. The detached caller did test, but
    /// one statement earlier than the read it was guarding, which leaves
    /// the same gap a lock apart instead of a task apart. `None` is a
    /// caller that wants no fence (Codex sweep 4, M4b).
    ///
    /// `fence` says WHICH question to ask, and the two callers genuinely
    /// differ. The awaited one runs before its own `park`, so its
    /// `move_seq` half is still meaningful against a concurrent delete
    /// verb and it asks [`Fence::Generation`]. The DETACHED one is
    /// spawned and then its caller parks immediately - and `park` stamps
    /// a queue -> history move of its own, bumping `move_seq` - so the
    /// pair is guaranteed to differ by the time the worker runs, and
    /// asking it dropped the pp-script of every ordinary completion at
    /// random. That is the race `retried_since` was written for (see its
    /// doc block in hooks.rs); passing the whole pair down here
    /// re-introduced it for the script half alone, which is why the
    /// worker's own guard passing was not enough (18 Aug sweep).
    pub(super) fn run_script(
        &self,
        script: &std::path::Path,
        job: &Arc<Mutex<Job>>,
        gen0: Option<(u32, u64)>,
        fence: Fence,
    ) {
        let Some((
            out_dir,
            name,
            cat,
            status,
            fail_msg,
            nzo_id,
            bytes,
            failure_link,
            repaired,
            shape,
        )) = ({
            let j = job.lock_ok();
            let still_mine = match fence {
                Fence::Generation => Self::same_generation(&j, gen0),
                // Retries only: a finished job being filed into history
                // is not a change of custody, and this caller's own park
                // is what moves it.
                Fence::RetriesOnly => gen0.is_none_or(|(retries, _)| j.retries == retries),
            };
            if !still_mine {
                return;
            }
            Some((
                j.out_dir.clone(),
                j.name.clone(),
                j.category.clone(),
                // SAB pp-status: 0 = OK, 1 = failed verification.
                if j.state == JobState::Completed {
                    "0"
                } else {
                    "1"
                },
                j.fail_message.clone(),
                j.nzo_id.clone(),
                j.total_bytes,
                j.failure_link.clone(),
                j.bad_blocks.unwrap_or(0) > 0,
                j.archive_shape.clone(),
            ))
        })
        else {
            return;
        };
        let ok = status == "0";
        let mut cmd = std::process::Command::new(script);
        cmd.arg(&out_dir) // 1 final dir
            .arg(format!("{name}.nzb")) // 2 original nzb name
            .arg(&name) // 3 clean job name
            .arg("") // 4 indexer report number
            .arg(if cat.is_empty() { "*" } else { &cat }) // 5 category
            .arg("") // 6 group
            .arg(status) // 7 pp status
            // 8 failure URL. We have carried the X-DNZB failure link on
            // the job since the FailureLink work and were passing an
            // empty string here, so a SAB script that does its own dead-
            // post reporting had nothing to report to.
            .arg(&failure_link)
            .env("SAB_COMPLETE_DIR", &out_dir)
            .env("SAB_FINAL_NAME", &name)
            .env("SAB_FILENAME", format!("{name}.nzb"))
            .env("SAB_CAT", if cat.is_empty() { "*" } else { &cat })
            .env("SAB_PP_STATUS", status)
            .env(
                "SAB_STATUS",
                if status == "0" { "Completed" } else { "Failed" },
            )
            .env("SAB_FAIL_MSG", &fail_msg)
            .env("SAB_NZO_ID", &nzo_id)
            .env("SAB_BYTES", bytes.to_string())
            .env("SAB_URL", &failure_link)
            .env("SAB_VERSION", SAB_VERSION)
            // The NZBGet dialect of the same facts, so a VideoSort-class
            // extension script runs unmodified. PARSTATUS/UNPACKSTATUS
            // describe the one-pass engine in NZBGet's vocabulary:
            // repair and unpack happen inside the download, so a clean
            // completion says "0" (no par-check was owed) and a repaired
            // one says "2" (checked and repaired); unpack reports "2"
            // only when an archive was actually unpacked.
            .env("NZBPP_DIRECTORY", &out_dir)
            .env("NZBPP_FINALDIR", &out_dir)
            .env("NZBPP_NZBNAME", &name)
            .env("NZBPP_NZBFILENAME", format!("{name}.nzb"))
            .env("NZBPP_CATEGORY", &cat)
            .env("NZBPP_TOTALSTATUS", if ok { "SUCCESS" } else { "FAILURE" })
            .env(
                "NZBPP_STATUS",
                if ok { "SUCCESS/ALL" } else { "FAILURE/BAD" },
            )
            .env(
                "NZBPP_PARSTATUS",
                if !ok {
                    "1"
                } else if repaired {
                    "2"
                } else {
                    "0"
                },
            )
            .env(
                "NZBPP_UNPACKSTATUS",
                if ok && !shape.is_empty() { "2" } else { "0" },
            );
        let secs = self.script_timeout.load(Ordering::Relaxed);
        match run_capped(cmd, secs) {
            Ok((Some(st), _)) if st.success() => {
                info!(target: "script", "{} ok for {nzo_id}", script.display());
            }
            // NZBGet extension scripts answer in exit codes: 93 =
            // POSTPROCESS_SUCCESS, 95 = POSTPROCESS_NONE ("not for
            // me"). Neither is a failure; 94 (POSTPROCESS_ERROR) and
            // anything else falls through to the warn below.
            Ok((Some(st), _)) if st.code() == Some(93) => {
                info!(target: "script", "{} ok for {nzo_id} (exit 93, nzbget success)", script.display());
            }
            Ok((Some(st), _)) if st.code() == Some(95) => {
                info!(target: "script", "{} declined {nzo_id} (exit 95, nzbget none)", script.display());
            }
            Ok((Some(st), stderr)) => {
                warn!(
                    target: "script",
                    "{} exited {st} for {nzo_id}: {}",
                    script.display(),
                    stderr.trim()
                );
            }
            // No exit status = we killed it at the deadline.
            Ok((None, _)) => warn!(
                target: "script",
                "{} still running after {secs}s for {nzo_id} - killed. \
                 Raise or clear script_timeout_secs if it needs longer.",
                script.display()
            ),
            Err(e) => warn!(target: "script", "{} failed to launch: {e}", script.display()),
        }
    }
}
