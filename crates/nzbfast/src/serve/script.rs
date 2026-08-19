//! Running a post-processing script: a child with a real deadline, its
//! pipes drained so it cannot wedge on a full buffer, and a bounded tail
//! of its stderr kept for the failure report.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// What [`run_capped_inner`] does with the child's stdout. Three modes
/// because three callers want three different SLICES of it, and none of
/// them wants all of it: a script that prints for a living must not be
/// able to spend the daemon's memory proving it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StdoutMode {
    /// The first [`SCRIPT_OUT_HEAD`] bytes. The pre-queue verdict.
    Head,
    /// Only the NZBGet command-channel lines, wherever they appear. See
    /// [`super::nzbget_script::LineSieve`].
    Sieve,
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
    run_capped_inner(cmd, secs, StdoutMode::Head)
}

/// §192: `run_capped`, but the NZBGet `[NZB] ` command channel is sieved
/// out of stdout. One line per kept command, in the order the script
/// said them; see [`NzbCommands::parse`].
pub(super) fn run_capped_sieve(
    cmd: std::process::Command,
    secs: u64,
) -> std::io::Result<(Option<std::process::ExitStatus>, Vec<String>, String)> {
    let (status, out, stderr) = run_capped_inner(cmd, secs, StdoutMode::Sieve)?;
    Ok((status, out.lines().map(str::to_string).collect(), stderr))
}

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
fn run_capped_inner(
    mut cmd: std::process::Command,
    secs: u64,
    mode: StdoutMode,
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
    let sieve = Arc::new(Mutex::new(crate::serve::nzbget_script::LineSieve::default()));
    // Detached on purpose, and leashed: see the doc comment. Each thread
    // owns its pipe and exits when the last writer closes it OR when
    // this flag says we have stopped caring, whichever comes first.
    let stop = Arc::new(AtomicBool::new(false));
    if let Some(r) = child.stdout.take() {
        let (stop, g) = (stop.clone(), DrainGuard::new());
        match mode {
            StdoutMode::Head => {
                let head = head.clone();
                std::thread::spawn(move || {
                    let _g = g;
                    drain_into_head(r, &stop, &head)
                });
            }
            StdoutMode::Sieve => {
                let sieve = sieve.clone();
                std::thread::spawn(move || {
                    let _g = g;
                    drain_into_sieve(r, &stop, &sieve)
                });
            }
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
    let stdout = match mode {
        StdoutMode::Sieve => {
            let mut s = sieve.lock_ok();
            s.finish();
            if s.dropped > 0 {
                warn!(
                    target: "script",
                    "{} more command/log lines than the {} this daemon keeps were \
                     dropped - a post-processing script should say a handful, not \
                     a stream",
                    s.dropped, s.kept.len()
                );
            }
            s.kept.join("\n")
        }
        _ => String::from_utf8_lossy(&head.lock_ok()).into_owned(),
    };
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

pub(super) fn drain_into_sieve(
    r: impl PipeRead,
    stop: &AtomicBool,
    sieve: &Mutex<crate::serve::nzbget_script::LineSieve>,
) {
    drain(r, stop, |bytes| sieve.lock_ok().push(bytes));
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

/// Everything one chain run needs off the job record, read under ONE
/// hold so the whole chain describes one instant. See
/// [`Daemon::run_script_chain`] for why that matters.
pub(super) struct ScriptFacts {
    out_dir: PathBuf,
    name: String,
    cat: String,
    /// SAB pp-status: "0" = OK, "1" = failed verification.
    status: &'static str,
    fail_msg: String,
    nzo_id: String,
    bytes: u64,
    downloaded: u64,
    failure_link: String,
    repaired: bool,
    shape: String,
    nzb_path: PathBuf,
    dupe_key: String,
    pp_params: Vec<(String, String)>,
}

impl Daemon {
    /// M14d: post-processing hook with SABnzbd's contract - the 8
    /// positional args and SAB_* env vars that the existing script
    /// ecosystem (notifiers, sorters, library refreshers) expects.
    /// §129 4a added the NZBGet side of the same ecosystem: NZBPP_* env
    /// and the 93/94/95 exit-code vocabulary, as a documented mapping
    /// (decision 5's rule - map, never silently ignore). §192 completes
    /// it: the `NZBOP_*` option mirror, the full 92/93/94/95 vocabulary
    /// with its aggregate status, and this - an ordered CHAIN rather
    /// than one script.
    ///
    /// The chain runs in list order, sequentially, and DOES NOT ABORT ON
    /// FAILURE. That is NZBGet's contract, not a shortcut: its
    /// `PostScriptController` records each link's status and runs the
    /// next one regardless, and the catalogue is written against it -
    /// a notifier placed after a sorter still notifies when the sort
    /// failed, which is the case an operator most wants to hear about.
    /// The one thing that stops a chain there is a link asking for a
    /// par-check, which we cannot grant (see `analyse_exit`); we log the
    /// refusal and keep going rather than swallow the rest of the chain
    /// over a request that was never going to be honoured.
    ///
    /// `gen0` fences the whole snapshot. The record is read ONCE, for
    /// the WHOLE chain, and the generation is tested under that same
    /// hold, because the two questions "is this still my job" and "what
    /// are its argv and env" have to be answered against the same
    /// instant. The awaited caller (`run_post_job_hooks_before_park`)
    /// tested neither: `post_job_owed` checks the generation while it
    /// builds the plan, then the plan is handed to a `spawn_blocking`
    /// that reads the record again later, and `finalizing` has been
    /// cleared by then - so a delete plus a Retry landing in between ran
    /// the OLD job's script against the NEW generation's out_dir and
    /// name. The detached caller did test, but one statement earlier
    /// than the read it was guarding, which leaves the same gap a lock
    /// apart instead of a task apart. `None` is a caller that wants no
    /// fence (Codex sweep 4, M4b).
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
    pub(super) fn run_script_chain(
        &self,
        chain: &[PathBuf],
        job: &Arc<Mutex<Job>>,
        gen0: Option<(u32, u64)>,
        fence: Fence,
    ) {
        let Some(facts) = self.script_facts(job, gen0, fence) else {
            return;
        };
        let opts = self.nzbop_options();
        let secs = self.script_timeout.load(Ordering::Relaxed);
        // The chain's state, carried link to link. `final_dir` starts
        // empty because nothing has moved anything yet - NZBGet reports
        // NZBPP_FINALDIR empty until a script sets one, and a script
        // that tests it for emptiness is asking exactly that.
        let mut total = ScriptStatus::default();
        let mut final_dir = String::new();
        let mut directory = facts.out_dir.to_string_lossy().into_owned();
        let mut params = facts.pp_params.clone();
        for script in chain {
            let cmd = self.script_command(
                script, &facts, &opts, total, &final_dir, &directory, &params,
            );
            let (status, note, cmds) = match run_capped_sieve(cmd, secs) {
                Ok((st, lines, stderr)) => {
                    let code = st.and_then(|s| s.code());
                    // One-pass verified and repaired during the
                    // download, so a link asking for a par-check (92) is
                    // always asking for one that has already happened.
                    let (status, note) = analyse_exit(code, true);
                    let note = match st {
                        // We killed it at the deadline.
                        None => format!(
                            "still running after {secs}s - killed. Raise or clear \
                             script_timeout_secs if it needs longer."
                        ),
                        // Something else killed it: no exit code, so
                        // `analyse_exit` cannot tell this from our own
                        // kill and would say the wrong thing.
                        Some(st) if code.is_none() => format!("died: {st}"),
                        _ if status == ScriptStatus::Failure && !stderr.trim().is_empty() => {
                            format!("{note}: {}", stderr.trim())
                        }
                        _ => note,
                    };
                    (status, note, NzbCommands::parse(&lines))
                }
                // A launch failure is NZBGet's `-1` arm, which it also
                // calls a failure. The chain continues: one uninstalled
                // link must not silently cancel the ones after it.
                Err(e) => (
                    ScriptStatus::Failure,
                    format!("failed to launch: {e}"),
                    NzbCommands::default(),
                ),
            };
            let id = &facts.nzo_id;
            match status {
                ScriptStatus::Failure => {
                    warn!(target: "script", "{} {note} for {id}", script.display())
                }
                _ => info!(target: "script", "{} {note} for {id}", script.display()),
            }
            total = total.fold(status);
            self.apply_nzb_commands(
                script,
                id,
                cmds,
                &mut final_dir,
                &mut directory,
                &mut params,
            );
        }
        if chain.len() > 1 {
            info!(
                target: "script",
                "{}: script chain of {} finished with status {}",
                facts.nzo_id,
                chain.len(),
                total.as_str()
            );
        }
    }

    /// What a chain link said on its stdout, folded into the state the
    /// NEXT link sees. Only the commands that change what a later script
    /// would do are honoured; the rest is logged, because "my script
    /// printed a command and nothing happened" must be answerable from
    /// the daemon log alone.
    fn apply_nzb_commands(
        &self,
        script: &std::path::Path,
        nzo_id: &str,
        cmds: NzbCommands,
        final_dir: &mut String,
        directory: &mut String,
        params: &mut Vec<(String, String)>,
    ) {
        for m in &cmds.messages {
            warn!(target: "script", "{} for {nzo_id}: {m}", script.display());
        }
        if let Some(d) = cmds.final_dir.or(cmds.directory) {
            info!(
                target: "script",
                "{} for {nzo_id}: final dir is now {d} - later scripts in the \
                 chain see it as NZBPP_FINALDIR",
                script.display()
            );
            final_dir.clone_from(&d);
            directory.clone_from(&d);
        }
        for (k, v) in cmds.params {
            // Last writer wins, as NZBGet's parameter list does: a
            // script setting a parameter twice means the second one.
            match params.iter_mut().find(|(n, _)| *n == k) {
                Some(slot) => slot.1 = v,
                None => params.push((k, v)),
            }
        }
        if cmds.mark_bad {
            warn!(
                target: "script",
                "{} for {nzo_id}: asked to MARK=BAD, which this daemon does not \
                 implement - the history row keeps the status the download \
                 itself earned",
                script.display()
            );
        }
        for u in &cmds.unknown {
            warn!(
                target: "script",
                "{} for {nzo_id}: unsupported command [NZB] {u}",
                script.display()
            );
        }
    }
}

impl Daemon {
    /// The record, read ONCE and fenced under the same hold. `None` is
    /// "this is no longer my job" and the chain does not start.
    fn script_facts(
        &self,
        job: &Arc<Mutex<Job>>,
        gen0: Option<(u32, u64)>,
        fence: Fence,
    ) -> Option<ScriptFacts> {
        let j = job.lock_ok();
        let still_mine = match fence {
            Fence::Generation => Self::same_generation(&j, gen0),
            // Retries only: a finished job being filed into history is
            // not a change of custody, and this caller's own park is
            // what moves it.
            Fence::RetriesOnly => gen0.is_none_or(|(retries, _)| j.retries == retries),
        };
        if !still_mine {
            return None;
        }
        Some(ScriptFacts {
            out_dir: j.out_dir.clone(),
            name: j.name.clone(),
            cat: j.category.clone(),
            status: if j.state == JobState::Completed {
                "0"
            } else {
                "1"
            },
            fail_msg: j.fail_message.clone(),
            nzo_id: j.nzo_id.clone(),
            bytes: j.total_bytes,
            downloaded: j.downloaded_bytes,
            failure_link: j.failure_link.clone(),
            repaired: j.bad_blocks.unwrap_or(0) > 0,
            shape: j.archive_shape.clone(),
            nzb_path: j.nzb_path.clone(),
            dupe_key: j.dupe_key.clone().unwrap_or_default(),
            pp_params: j.pp_params.clone(),
        })
    }

    /// One chain link's argv and environment: SABnzbd's contract, then
    /// NZBGet's, then the chain state the previous links left behind.
    #[allow(clippy::too_many_arguments)]
    fn script_command(
        &self,
        script: &std::path::Path,
        f: &ScriptFacts,
        opts: &[NzbOpt],
        total: ScriptStatus,
        final_dir: &str,
        directory: &str,
        params: &[(String, String)],
    ) -> std::process::Command {
        let ok = f.status == "0";
        let cat = if f.cat.is_empty() { "*" } else { &f.cat };
        let mut cmd = std::process::Command::new(script);
        cmd.arg(directory) // 1 final dir
            .arg(format!("{}.nzb", f.name)) // 2 original nzb name
            .arg(&f.name) // 3 clean job name
            .arg("") // 4 indexer report number
            .arg(cat) // 5 category
            .arg("") // 6 group
            .arg(f.status) // 7 pp status
            // 8 failure URL. We have carried the X-DNZB failure link on
            // the job since the FailureLink work and were passing an
            // empty string here, so a SAB script that does its own dead-
            // post reporting had nothing to report to.
            .arg(&f.failure_link)
            .env("SAB_COMPLETE_DIR", directory)
            .env("SAB_FINAL_NAME", &f.name)
            .env("SAB_FILENAME", format!("{}.nzb", f.name))
            .env("SAB_CAT", cat)
            .env("SAB_PP_STATUS", f.status)
            .env("SAB_STATUS", if ok { "Completed" } else { "Failed" })
            .env("SAB_FAIL_MSG", &f.fail_msg)
            .env("SAB_NZO_ID", &f.nzo_id)
            .env("SAB_BYTES", f.bytes.to_string())
            .env("SAB_URL", &f.failure_link)
            .env("SAB_VERSION", SAB_VERSION)
            // The NZBGet dialect of the same facts, so a VideoSort-class
            // extension script runs unmodified. PARSTATUS/UNPACKSTATUS
            // describe the one-pass engine in NZBGet's vocabulary:
            // repair and unpack happen inside the download, so a clean
            // completion says "0" (no par-check was owed) and a repaired
            // one says "2" (checked and repaired); unpack reports "2"
            // only when an archive was actually unpacked.
            .env("NZBPP_DIRECTORY", directory)
            .env("NZBPP_FINALDIR", final_dir)
            .env("NZBPP_NZBNAME", &f.name)
            .env("NZBPP_NZBFILENAME", format!("{}.nzb", f.name))
            .env("NZBPP_QUEUEDFILE", &f.nzb_path)
            .env("NZBPP_CATEGORY", &f.cat)
            .env("NZBPP_NZBID", &f.nzo_id)
            // We hold no source URL for a job, and NZBGet's is the URL
            // an nzb was fetched FROM. Empty rather than absent: a
            // missing key is a KeyError, an empty one is "not from a
            // URL", which is the truth for an uploaded nzb.
            .env("NZBPP_URL", "")
            .env("NZBPP_TOTALSTATUS", if ok { "SUCCESS" } else { "FAILURE" })
            .env(
                "NZBPP_STATUS",
                if ok { "SUCCESS/ALL" } else { "FAILURE/BAD" },
            )
            .env(
                "NZBPP_PARSTATUS",
                if !ok {
                    "1"
                } else if f.repaired {
                    "2"
                } else {
                    "0"
                },
            )
            .env(
                "NZBPP_UNPACKSTATUS",
                if ok && !f.shape.is_empty() { "2" } else { "0" },
            )
            // NZBGet's health is per-mille of articles that arrived. We
            // count bytes, not articles, so this is the byte ratio - the
            // same question at a different granularity, and the answer
            // scripts actually branch on (1000 = nothing was missing).
            .env("NZBPP_HEALTH", per_mille(ok, f.downloaded, f.bytes))
            .env("NZBPP_CRITICALHEALTH", "0")
            .env("NZBPP_HEALTHDELETED", "0")
            .env("NZBPP_DUPEKEY", &f.dupe_key)
            .env("NZBPP_DUPESCORE", "0")
            .env("NZBPP_DUPEMODE", "SCORE")
            // The chain's aggregate SO FAR, which is the whole reason an
            // ordered list is different from a set: a notifier placed
            // last can say "the sort before me failed".
            .env("NZBPP_SCRIPTSTATUS", total.as_str());
        for (name, value) in opts {
            set_env_special(&mut cmd, "NZBOP", name, value);
        }
        // Post-processing parameters: the ones the add attached (an
        // *arr's `drone` GUID rides here) and any a previous link set
        // with `[NZB] NZBPR_<name>=<value>`.
        for (name, value) in params {
            set_env_special(&mut cmd, "NZBPR", name, value);
        }
        cmd
    }
}

/// NZBGet's health scale: 1000 = every article arrived. A finished job
/// has all of its bytes by definition, so success is flatly 1000 rather
/// than a ratio that rounding could put at 999.
fn per_mille(ok: bool, got: u64, total: u64) -> String {
    if ok || total == 0 {
        return "1000".to_string();
    }
    (got.min(total) * 1000 / total).to_string()
}
