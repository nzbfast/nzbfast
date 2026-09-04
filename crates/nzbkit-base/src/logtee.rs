//! Self-tee of stdout+stderr into an in-memory ring buffer, so the
//! daemon can serve its own recent log to the dashboard (mode=log) -
//! nothing to configure, works regardless of how the process was
//! launched. Unix: dup2 both fds onto a pipe; a capture thread keeps
//! the last `CAP` lines and hands each one to a separate echo thread
//! for the ORIGINAL stdout (so terminals/redirects still see it). Two
//! threads on purpose: the echo target is outside our control and can
//! stop accepting output (an exec-orphaned pipe, a launcher that quit
//! reading), and only the echo may ever block on it - the ring, and
//! the daemon's own printing, must not. On non-unix the tee is a no-op
//! and the ring stays empty (the dashboard says so) - but the SIZE CAP
//! still applies there, from the outside: `wincap` watches the file
//! stdout is already pointed at instead of interposing on the way past,
//! which is what keeps the one-stream invariant this whole module rests
//! on (`nzbfast::logging` writes to stdout precisely so that the
//! dashboard pane, the terminal and the packaging redirect are all one
//! copy; a second file opened here would make them three).

use crate::sync::MutexExt;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

/// Ring capacity, lines. Only the unix reader fills the ring, so off unix
/// this and the two line helpers below exist solely for their tests -
/// which still run on Windows, hence `test` rather than plain `cfg(unix)`.
#[cfg(any(unix, test))]
const CAP: usize = 2000;

/// Handshake line [`drain`] writes down the pipe. Control bytes, so it
/// cannot collide with anything a program or a child process prints; the
/// reader swallows it rather than echoing it or ringing it.
const DRAIN_MARK: &[u8] = b"\x01nzbfast-logtee-drain\x01";

/// Count of drain marks the reader has swallowed, plus the condvar it
/// notifies. Present only while the tee is installed.
static DRAIN: OnceLock<(Mutex<u64>, Condvar)> = OnceLock::new();

/// Longest [`drain`] waits for the reader to catch up. Echoing whatever
/// a pipe can hold takes microseconds; the cap only exists so a reader
/// thread that has already died cannot hold an exiting process open.
const DRAIN_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// M32: size cap for a REDIRECTED stdout log file, bytes.
/// Every packaging surface except the Mac app (which rotates its own
/// daemon.log at 5 MB) points stdout at a file - launchd plist, brew
/// services, the Windows installer - and none of them rotate, so an
/// error storm can fill the disk. When the echo target is a regular
/// file past the cap, it is truncated in place with a notice line.
/// NZBFAST_LOG_CAP_MB overrides (0 = uncapped).
///
/// Read by the unix echo thread and by the Windows watcher (`wincap`).
/// It was `#[cfg(unix)]` until 22 Aug 2026, and that is exactly why
/// Gary's tray install had NO runtime cap at all: 90 MB of daemon.log
/// in 27 h off a warning storm (TODO 165). The tray rotates the file
/// only when it SPAWNS the daemon, so a process that stays up through
/// the storm never reaches that rotation.
#[cfg(any(unix, windows))]
fn log_cap_bytes() -> u64 {
    cap_from(std::env::var("NZBFAST_LOG_CAP_MB").ok().as_deref())
}

/// The cap in bytes for a raw `NZBFAST_LOG_CAP_MB` value.
///
/// Split off the environment read so the parse can be tested without
/// mutating process env from a parallel suite. The fallback direction
/// is the point: a value we cannot read falls back to the DEFAULT, not
/// to uncapped, because the one thing this knob exists to prevent is a
/// full disk.
#[cfg(any(unix, windows, test))]
fn cap_from(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(50)
        .saturating_mul(1 << 20)
}

/// The line a truncation leaves behind, so a file that starts in the
/// middle of a session says why.
///
/// Shared by both platforms' truncation paths - the unix echo thread
/// writes it down the fd it just rewound, the Windows watcher through
/// the handle it reopened - because it is the string a user pastes into
/// a bug report, and two spellings of it would be two things to grep.
#[cfg(any(unix, windows, test))]
fn cap_notice(cap: u64) -> String {
    format!(
        "[log] size cap {} MB reached - file truncated (NZBFAST_LOG_CAP_MB overrides)\n",
        cap >> 20
    )
}

static RING: OnceLock<Arc<Mutex<VecDeque<String>>>> = OnceLock::new();

/// The pre-tee stdout, kept so [`restore_for_exec`] can put it back on
/// fds 1/2 before a re-exec. -1 until the tee is installed. The echo
/// thread owns the fd (its `File` closes it on queue disconnect, which
/// needs the capture thread gone first), but that can only happen after
/// both dup2s in `restore_for_exec` have already retired the pipe's
/// last write ends, so the value here never goes stale while anyone
/// still reads it.
#[cfg(unix)]
static ORIG_STDOUT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Lines the echo thread never got because its queue was full - which
/// only happens when the echo target itself has stopped accepting
/// output (a launcher that quit reading its pipe, a hung NFS log file).
/// The ring is not affected; this only counts what the OUTSIDE lost.
#[cfg(any(unix, test))]
static ECHO_DROPPED: AtomicU64 = AtomicU64::new(0);

/// What the capture thread hands the echo thread. The drain handshake
/// travels the same queue so it keeps its FIFO meaning: once the echo
/// thread reaches the mark, everything queued before it has been echoed.
#[cfg(any(unix, test))]
enum Echoed {
    // On a Windows TEST build this enum exists only because `capture` -
    // which the capture-path tests exercise everywhere - needs a channel
    // token to send. The reader of the line (the echo thread) and the
    // one Mark sender are both unix-only install code, so over there the
    // payload is "read" and Mark is constructed; on windows+test neither
    // happens and the lint is right that nothing looks at them.
    #[cfg_attr(all(test, not(unix)), expect(dead_code))]
    Line(Vec<u8>),
    #[cfg(unix)]
    Mark,
}

/// Echo queue depth, lines. Deep enough that a briefly slow terminal
/// never drops anything; shallow enough that a genuinely dead target
/// costs a bounded amount of memory, not the daemon. Unix-only, unlike
/// the enum above: no test sizes the queue.
#[cfg(unix)]
const ECHO_QUEUE: usize = 256;

/// Lines ever captured, counting the ones already evicted from the ring.
/// Monotonic, so a caller can bracket a span of output (see [`mark`] and
/// [`since`]) instead of guessing at a line count after the fact.
static SEEN: AtomicU64 = AtomicU64::new(0);

/// Last `n` captured lines, oldest first.
pub fn tail(n: usize) -> Vec<String> {
    match RING.get() {
        None => Vec::new(),
        Some(r) => {
            let g = r.lock_ok();
            g.iter().skip(g.len().saturating_sub(n)).cloned().collect()
        }
    }
}

/// A cursor into the captured output, to be paired with [`since`].
///
/// Taken BEFORE the work whose output a caller wants to keep. The ring is
/// global stdout, so a plain `tail(n)` after the fact is a guess at both
/// ends: too small a window truncates the block, too large a one drags in
/// whatever the daemon's background lanes happened to print first.
pub fn mark() -> u64 {
    SEEN.load(Ordering::Relaxed)
}

/// Lines captured since `mark`, oldest first, at most `max` of them
/// (keeping the LAST `max` - a failure block ends with its verdict).
///
/// Returns what survives: the ring holds only `CAP` lines, so a span that
/// outran it comes back short rather than wrong.
pub fn since(mark: u64, max: usize) -> Vec<String> {
    let Some(r) = RING.get() else {
        return Vec::new();
    };
    let g = r.lock_ok();
    let want = span_len(mark, SEEN.load(Ordering::Relaxed), g.len(), max);
    g.iter().skip(g.len() - want).cloned().collect()
}

/// How many of the ring's newest lines belong to the span `mark..seen`.
///
/// Split out because every term here can outrun another: a span longer
/// than `CAP` has already lost its front, a caller's `max` may be
/// smaller still, and a `mark` taken before a ring that has since been
/// re-created (or simply a nonsense value) must not underflow into
/// "everything". Clamped in that order, and never past what the ring
/// actually holds - the result indexes it.
fn span_len(mark: u64, seen: u64, held: usize, max: usize) -> usize {
    seen.saturating_sub(mark).min(held as u64).min(max as u64) as usize
}

/// Lines captured between two marks, oldest first, at most `max` of
/// them (keeping the LAST `max`, like [`since`]).
///
/// [`since`] runs a span to the present, which is right while the work
/// is still going and wrong once it has finished: a report assembled
/// minutes later would carry every line the daemon's background lanes
/// printed after the job ended, attributed to that job. Bracketing both
/// ends is what makes a per-job slice a slice rather than a tail.
///
/// `to` behind `from`, or either one from a previous process's ring,
/// yields nothing rather than a guess - the same clamping discipline
/// [`span_len`] documents, applied at both ends.
pub fn between(from: u64, to: u64, max: usize) -> Vec<String> {
    let Some(r) = RING.get() else {
        return Vec::new();
    };
    // Under the ring lock, like `since`: SEEN is bumped under it, so a
    // load taken outside can disagree with the held lines by however
    // many appends land in between - which shifts the whole (skip,
    // take) window that many lines newer, splicing another job's
    // output into this span's tail.
    let g = r.lock_ok();
    let seen = SEEN.load(Ordering::Relaxed);
    let (skip, take) = between_span(from, to, seen, g.len(), max);
    g.iter().skip(skip).take(take).cloned().collect()
}

/// Where the span `from..to` sits in a ring holding `held` newest lines,
/// as `(skip, take)`. Pure, and tested as such - the ring and the seen
/// counter are process-global, so arithmetic that could only be checked
/// by mutating them could not be checked in a suite that runs in
/// parallel (the same reason [`span_len`] is split out).
///
/// Every term can outrun another, and one more can here than in
/// [`span_len`]: `to` is a mark too, so it can also be nonsense. A
/// restart resets `SEEN` to 0 and it climbs again, so a mark kept from a
/// previous process really can name a span of somebody ELSE's output -
/// which is the one answer this must never give. Both ends are required
/// to be in the past of what has actually been captured; anything else
/// yields nothing.
fn between_span(from: u64, to: u64, seen: u64, held: usize, max: usize) -> (usize, usize) {
    if to <= from || from > seen || to > seen {
        return (0, 0);
    }
    // Lines printed after `to` are not this span's. Drop them first,
    // then take the span's own tail out of what is left.
    let after = span_len(to, seen, held, usize::MAX);
    let upto = held - after;
    let want = span_len(from, to, upto, max);
    (upto - want, want)
}

/// True when the tee is capturing on this platform.
pub fn active() -> bool {
    RING.get().is_some()
}

/// Trim one trailing CR/LF and lossily decode a raw captured line. A single
/// undecodable byte becomes U+FFFD - never a dropped line. (Bug sweep: the
/// old `lines()` reader returned Err on the first non-UTF-8 byte, which
/// killed the tee thread and silently took the daemon down with it.)
#[cfg(any(unix, test))]
fn ring_line(buf: &[u8]) -> String {
    String::from_utf8_lossy(trim_newline(buf)).into_owned()
}

/// Ring one captured line, then offer it to the echo thread without
/// ever waiting on it.
///
/// The order is the point, and it is the fix for a real death: the ring
/// used to be fed only AFTER a blocking echo write, so when the echo
/// target stopped accepting output the whole capture froze with it -
/// the dashboard log ended mid-download and, once the tee pipe filled
/// too, every thread in the daemon that printed blocked behind it
/// (seen live, 7 Aug 2026: four finished jobs whose [move] outcomes
/// vanished). The ring is the copy the daemon itself serves, so it gets
/// the line first and unconditionally; the echo is best-effort and a
/// full queue means the OUTSIDE copy loses the line, never the ring.
#[cfg(any(unix, test))]
fn capture(ring: &Mutex<VecDeque<String>>, tx: &std::sync::mpsc::SyncSender<Echoed>, buf: &[u8]) {
    let line = ring_line(buf);
    {
        let mut g = ring.lock_ok();
        if g.len() >= CAP {
            g.pop_front();
        }
        g.push_back(line);
        // Bumped under the ring lock so `since` cannot read a
        // count that disagrees with the lines it can see.
        SEEN.fetch_add(1, Ordering::Relaxed);
    }
    if tx.try_send(Echoed::Line(buf.to_vec())).is_err()
        && ECHO_DROPPED.fetch_add(1, Ordering::Relaxed) == 0
    {
        // Say so IN the ring, once: a launcher that stopped reading its
        // pipe is otherwise indistinguishable from a daemon that went
        // quiet, and the ring is the one place still listening.
        let mut g = ring.lock_ok();
        if g.len() >= CAP {
            g.pop_front();
        }
        g.push_back(
            "[log] stdout stopped accepting output - later lines reach only this log".to_string(),
        );
        SEEN.fetch_add(1, Ordering::Relaxed);
    }
}

/// One captured line without its trailing CR/LF.
#[cfg(any(unix, test))]
fn trim_newline(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    if end > 0 && buf[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && buf[end - 1] == b'\r' {
        end -= 1;
    }
    &buf[..end]
}

/// The Windows half of the size cap.
///
/// There is no tee over here: nothing dup2s the process's own stdio onto
/// a pipe, so no thread reads the log on its way past and the unix cap -
/// which rides on the echo thread - has nowhere to live. The cap is
/// applied from the OUTSIDE instead: a watcher checks the size of the
/// file stdout is already pointed at and truncates it in place. That is
/// the point rather than a compromise, because interposing here would
/// mean opening our own copy of the log, and the dashboard pane, the
/// terminal and the packaging redirect would stop being the same stream.
///
/// Truncating from outside is coherent with the tray's writer because
/// the tray opens daemon.log in APPEND mode (`spawn_daemon` in
/// crates/nzbtray/src/main.rs), and an append write lands at whatever
/// the end of the file is at that moment - so it needs no rewind after
/// the file shrinks under it. A plain `nzbfast serve > out.log` redirect
/// DOES carry a file position, and that one is rewound directly, exactly
/// the way the unix echo thread does it.
#[cfg(windows)]
mod wincap {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use std::mem::ManuallyDrop;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// How often the watcher looks. A couple of handle queries a tick
    /// and nothing else, so the poll itself costs nothing; the interval
    /// only bounds the overshoot, and at the storm rate behind Gary's
    /// 90 MB in 27 h (~55 KB/min) a tick is worth about 28 KB of slack
    /// against a 50 MB cap.
    const INTERVAL: Duration = Duration::from_secs(30);

    /// One watcher per process, like the unix tee's `RING` guard:
    /// [`super::install`] promises that a second call is a no-op.
    static STARTED: AtomicBool = AtomicBool::new(false);

    /// Start the watcher, if there is anything for it to watch.
    ///
    /// Returns without a thread when the cap is off or stdout and stderr
    /// are both a console or a pipe - the interactive case, where there
    /// is no file to grow and no reason to wake up every 30 s.
    pub(super) fn spawn() {
        let cap = super::log_cap_bytes();
        if cap == 0 || STARTED.swap(true, Ordering::Relaxed) {
            return;
        }
        if !handles().into_iter().any(is_disk_file) {
            return;
        }
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(INTERVAL);
                for h in handles() {
                    cap_one(h, cap);
                }
            }
        });
    }

    /// stdout and stderr, in that order.
    ///
    /// Resolved on every tick rather than captured once, because a
    /// `RawHandle` is a raw pointer and would not cross into the thread;
    /// they are process-global and do not move, so re-reading them is
    /// free and is the honest thing anyway.
    ///
    /// Both are checked. The tray points them at the SAME file (a
    /// `try_clone`, so one file object), where the second check simply
    /// sees the length the first one just reset - and a shell that sent
    /// them to two different files gets both capped.
    fn handles() -> [RawHandle; 2] {
        [
            std::io::stdout().as_raw_handle(),
            std::io::stderr().as_raw_handle(),
        ]
    }

    /// Borrow a handle as a `File` WITHOUT owning it - dropping the
    /// `File` would close the process's own stdout.
    fn borrow(h: RawHandle) -> ManuallyDrop<File> {
        // SAFETY: `from_raw_handle` requires a valid, open handle that
        // the new `File` may own. `h` always comes from `handles()`,
        // i.e. the process's own live stdout/stderr, so it is valid -
        // and the `ManuallyDrop` is what discharges the ownership half:
        // the `File` is never dropped, so it never closes the handle
        // out from under the process. See this function's own name.
        ManuallyDrop::new(unsafe { File::from_raw_handle(h) })
    }

    /// True when the handle names an ordinary file on disk.
    ///
    /// `GetFileType` and not just `metadata`: a console handle makes
    /// `GetFileInformationByHandle` fail, but a named pipe can answer it,
    /// and a pipe that reported a length would have this thread trying to
    /// truncate the tray's IPC channel.
    fn is_disk_file(h: RawHandle) -> bool {
        use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};
        // SAFETY: GetFileType takes a handle and returns a u32; it
        // touches no memory of ours, and a handle that is invalid is not
        // unsound - it answers FILE_TYPE_UNKNOWN, which this rejects.
        let kind = unsafe { GetFileType(h) };
        kind == FILE_TYPE_DISK && borrow(h).metadata().map(|m| m.is_file()).unwrap_or(false)
    }

    /// Truncate the file behind `h` if it has passed `cap`, leaving the
    /// notice line as the new first line. Lives apart from [`spawn`] so
    /// its two truncation routes can be tested on a scratch file.
    pub(super) fn cap_one(h: RawHandle, cap: u64) {
        if cap == 0 || !is_disk_file(h) {
            return;
        }
        let f = borrow(h);
        let mut w: &File = &f;
        if w.metadata().map(|m| m.len() <= cap).unwrap_or(true) {
            return;
        }
        // A redirect (`> out.log`) was opened for writing and carries a
        // file position: truncate through the handle and rewind it, the
        // unix move. An APPEND handle - what the tray hands us - was
        // opened WITHOUT `FILE_WRITE_DATA`, so Windows refuses `set_len`
        // on it and the truncation has to go through a second handle on
        // the same path. Nothing else is written through that second
        // handle: the appends that follow find the new end of file on
        // their own, which is why truncating under an append writer
        // leaves no hole.
        if w.set_len(0).is_ok() {
            let _ = w.seek(SeekFrom::Start(0));
            let _ = w.write_all(super::cap_notice(cap).as_bytes());
            return;
        }
        let Some(path) = final_path(h) else {
            return;
        };
        // The notice goes down `g` at offset 0, not down the append
        // handle: an append write would land AFTER whatever the daemon
        // printed in the microseconds since the truncation, and the
        // point of the line is to be the first thing in the file. A
        // print that does land in that window is overwritten - one
        // garbled line, once, against a log that would otherwise have
        // no explanation for starting where it does.
        if let Ok(mut g) = std::fs::OpenOptions::new().write(true).open(&path)
            && g.set_len(0).is_ok()
        {
            let _ = g.write_all(super::cap_notice(cap).as_bytes());
        }
    }

    /// The path the file behind `h` lives at, so a handle that may not
    /// truncate itself can be truncated through a second one.
    ///
    /// `VOLUME_NAME_DOS` gives the `\\?\C:\…` form, which every std path
    /// call accepts. Both flags are zero; they are spelled out so the
    /// call reads as what it asks for.
    fn final_path(h: RawHandle) -> Option<PathBuf> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
        };
        let mut buf = vec![0u16; 260];
        loop {
            // 0 is the only failure. Anything >= the buffer is the size
            // it wants (not counting the terminator), so grow and ask
            // again rather than guessing at MAX_PATH - the tray's data
            // dir sits under a user profile name of any length.
            // SAFETY: `buf` is a live `Vec<u16>` and the length passed
            // is its own `len()`, so the call cannot write past it. `h`
            // is the process's own stdout/stderr handle, valid for the
            // call. The wide string is only read back on the `n <
            // buf.len()` path, where the API guarantees it wrote `n`
            // units plus a terminator.
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    h,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            if n == 0 {
                return None;
            }
            if (n as usize) < buf.len() {
                buf.truncate(n as usize);
                return Some(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
            }
            buf = vec![0u16; n as usize + 1];
        }
    }
}

/// Install the tee. Call once, early; further calls are no-ops.
pub fn install() {
    #[cfg(unix)]
    {
        if RING.get().is_some() {
            return;
        }
        let ring: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
        // SAFETY: every call in this block is an fd syscall whose only
        // requirement is that the descriptors it names are live and that
        // any pointer argument is valid for the length the call writes.
        // `fds` is a live local array of exactly the two ints pipe(2)
        // fills; `rd`, `wr` and `orig` are fds this block itself just
        // created, and each is used only while open (`wr` is closed only
        // after both dup2 calls have copied it into 1 and 2, and the
        // early `return` paths leave the process with fds that are still
        // consistent, just untee'd). `File::from_raw_fd(orig)` takes
        // ownership of `orig` exactly once: it is moved into the echo
        // thread's closure, nothing else ever closes it, so the File's
        // Drop is that descriptor's only close.
        unsafe {
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return;
            }
            let (rd, wr) = (fds[0], fds[1]);
            // Keep a copy of the real stdout for the echo.
            let orig = libc::dup(1);
            if orig < 0 || libc::dup2(wr, 1) < 0 || libc::dup2(wr, 2) < 0 {
                return;
            }
            libc::close(wr);
            // The read end and the stashed original are this process's
            // plumbing, not part of the stdio contract: mark them
            // CLOEXEC so neither a spawned child nor a re-exec'd image
            // (mode=restart_daemon) inherits them. Without this the
            // fds leaked into every child, and across an exec they
            // kept the dead pipe alive in the replacement process.
            libc::fcntl(rd, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(orig, libc::F_SETFD, libc::FD_CLOEXEC);
            ORIG_STDOUT.store(orig, Ordering::Relaxed);
            // Only once the pipe is really in place: a drain with no
            // reader behind it would print its own handshake.
            let _ = DRAIN.set((Mutex::new(0), Condvar::new()));
            let (tx, rx) = std::sync::mpsc::sync_channel::<Echoed>(ECHO_QUEUE);
            // The echo thread: the only place that writes to the
            // original stdout, and the only thread a dead or wedged
            // echo target can stop. Blocking here is harmless - the
            // capture thread never waits on this queue.
            std::thread::spawn(move || {
                use std::io::Write;
                use std::os::unix::io::FromRawFd;
                let mut echo = std::fs::File::from_raw_fd(orig);
                // Size-cap bookkeeping for a redirected regular file:
                // fstat only every ~1 MB echoed, not per line.
                let cap = log_cap_bytes();
                let echo_is_file = cap > 0 && echo.metadata().map(|m| m.is_file()).unwrap_or(false);
                let mut since_check: u64 = 0;
                while let Ok(msg) = rx.recv() {
                    let buf = match msg {
                        Echoed::Mark => {
                            // A drain handshake, not output: everything
                            // queued before it has now been echoed.
                            if let Some((n, cv)) = DRAIN.get() {
                                *n.lock_ok() += 1;
                                cv.notify_all();
                            }
                            continue;
                        }
                        Echoed::Line(buf) => buf,
                    };
                    if echo_is_file {
                        since_check += buf.len() as u64;
                        if since_check >= 1 << 20 {
                            since_check = 0;
                            if echo.metadata().map(|m| m.len() > cap).unwrap_or(false) {
                                // Truncate in place: the fd is a plain
                                // redirect (not O_APPEND), and this thread
                                // is the file's only writer, so rewinding
                                // is safe. History is sacrificed to keep
                                // the disk alive - the ring still holds
                                // the recent tail for the dashboard.
                                use std::io::Seek;
                                let _ = echo.set_len(0);
                                let _ = echo.seek(std::io::SeekFrom::Start(0));
                                let _ = echo.write_all(cap_notice(cap).as_bytes());
                            }
                        }
                    }
                    // Echo the exact bytes so terminals/redirects still see
                    // byte-for-byte what was written (newline included).
                    let _ = echo.write_all(&buf);
                }
            });
            let ring2 = ring.clone();
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader};
                use std::os::unix::io::FromRawFd;
                let mut src = BufReader::new(std::fs::File::from_raw_fd(rd));
                // Read raw bytes, NOT `lines()`. `BufRead::lines()` yields
                // Err(InvalidData) on the first non-UTF-8 byte, and a
                // legacy-encoded RAR/PAR2 filename reaches here whenever a
                // child (unrar/par2, run with inherited stdio) prints one.
                // The old `let Ok(line) = line else { break }` then exited
                // this thread, closing the pipe's read end - so the
                // daemon's next print hit EPIPE and panicked, with the
                // panic message lost down the same dead pipe (silent death).
                // read_until only stops on EOF or a genuine read error.
                let mut buf: Vec<u8> = Vec::with_capacity(256);
                loop {
                    buf.clear();
                    match src.read_until(b'\n', &mut buf) {
                        Ok(0) | Err(_) => break, // pipe closed, or read error
                        Ok(_) => {}
                    }
                    if trim_newline(&buf) == DRAIN_MARK {
                        // Forward the handshake so it keeps its FIFO
                        // meaning; when the echo queue is refusing even
                        // the mark, waiting is pointless (the 500 ms cap
                        // in `drain` would expire anyway) - acknowledge
                        // now, the ring already holds everything.
                        if tx.try_send(Echoed::Mark).is_err()
                            && let Some((n, cv)) = DRAIN.get()
                        {
                            *n.lock_ok() += 1;
                            cv.notify_all();
                        }
                        continue;
                    }
                    capture(&ring2, &tx, &buf);
                }
            });
            // Every exit path drains, including the ones nobody writes:
            // a panic, a bail out of main, `process::exit` in a handler.
            // atexit runs on all of them (never on a signal, where there
            // is nothing to be done anyway).
            libc::atexit(drain_at_exit);
        }
        let _ = RING.set(ring);
    }
    // No tee off unix, but the SIZE CAP is not a unix concern: the tray
    // redirects stdout at daemon.log and rotates it only at spawn, so a
    // long-lived daemon in a warning storm grew it without bound (TODO
    // 165). The watcher caps that same file rather than opening one.
    #[cfg(windows)]
    {
        wincap::spawn();
    }
}

#[cfg(unix)]
extern "C" fn drain_at_exit() {
    drain();
}

/// Undo the tee ahead of an exec: drain, then put the ORIGINAL
/// stdout back on fds 1 and 2.
///
/// exec kills every thread but keeps fds 1/2 - which the tee has
/// pointed at its pipe, whose reader thread does not survive. The
/// replacement image then re-runs [`install`], dup(1)s what it finds
/// there, and echoes every line into a pipe nobody reads: a daemon the
/// launcher started with stdout on daemon.log stopped appending to it
/// forever after mode=restart_daemon - and one pipe buffer (64 KiB)
/// later the blocked echo froze the in-memory ring too, with the
/// daemon's printing threads next in line (seen live, 7 Aug 2026:
/// four finished jobs whose completed-move outcomes all vanished).
///
/// fd 2 first, then fd 1: only the second dup2 retires the pipe's last
/// write end, so the reader cannot see EOF (and close the fd this
/// copies from) between the two calls. dup2 leaves CLOEXEC clear on
/// the target, so the restored fds cross the exec - the whole point.
pub fn restore_for_exec() {
    #[cfg(unix)]
    {
        drain();
        let orig = ORIG_STDOUT.load(Ordering::Relaxed);
        if orig >= 0 {
            // SAFETY: dup2 takes two integers and touches no memory, so
            // soundness here is only that `orig` names a live descriptor.
            // It does: install() stashed the dup of the real stdout in
            // ORIG_STDOUT and nothing in this module ever closes it (it
            // is owned for the process lifetime by the echo thread's
            // File), and the `>= 0` above rejects the not-installed
            // sentinel. Overwriting fds 1 and 2 is the intent, not a
            // hazard - see this function's doc comment for why fd 2 goes
            // first.
            unsafe {
                libc::dup2(orig, 2);
                libc::dup2(orig, 1);
            }
        }
    }
}

/// Wait until the reader has echoed everything written to stdout/stderr
/// so far.
///
/// Without this the last thing a process says is the thing most likely to
/// be lost: the bytes sit in the pipe, unread, and exiting takes the
/// reader thread down with the process. A fatal error printed on the way
/// out (an empty API key file, a panic) reached the terminal only if the
/// reader happened to be scheduled in time - under load it usually was
/// not, so the user saw a failed start with no reason given.
pub fn drain() {
    use std::io::Write;
    // Ordinary buffered output first: it is not in the pipe yet.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let Some((count, cv)) = DRAIN.get() else {
        return;
    };
    // Read the count before the mark goes down the pipe. Nothing is held
    // across the write: a full pipe would block us there, and the reader
    // needs this lock to bump the count. A bump we miss in the gap is not
    // a lost wakeup either - the wait tests the counter, not an event.
    let before = *count.lock_ok();
    {
        let mut out = std::io::stdout().lock();
        if out.write_all(DRAIN_MARK).is_err() || writeln!(out).is_err() || out.flush().is_err() {
            return;
        }
    }
    // The pipe is FIFO: once the mark comes back, so has everything
    // written before it.
    let seen = count.lock_ok();
    let _ = cv.wait_timeout_while(seen, DRAIN_WAIT, |n| *n == before);
}

#[cfg(test)]
mod tests {
    use super::{
        CAP, ECHO_DROPPED, between_span, cap_from, cap_notice, capture, ring_line, span_len,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// The behavior that took a live daemon down on 7 Aug 2026: the echo
    /// target (an exec-orphaned pipe) stopped accepting output, and
    /// because the ring was fed only after a BLOCKING echo write, the
    /// dashboard log froze with it - four finished jobs' completed-move
    /// outcomes simply never appeared anywhere. Pin the fix: a wedged
    /// echo must cost only the echo, never the ring.
    #[test]
    fn a_wedged_echo_never_stops_the_ring() {
        let ring = Mutex::new(VecDeque::new());
        // Queue of 1 that nobody drains = the wedged echo thread. The
        // receiver stays alive so try_send fails with Full, not
        // Disconnected - the exact live shape.
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        capture(&ring, &tx, b"first\n");
        capture(&ring, &tx, b"second\n"); // echo queue now refuses
        capture(&ring, &tx, b"third\n");
        let g = ring.lock().unwrap();
        for want in ["first", "second", "third"] {
            assert!(
                g.iter().any(|l| l == want),
                "{want:?} must reach the ring even with the echo wedged"
            );
        }
        // The outside's loss is counted and announced in the ring once,
        // so a launcher that quit reading its pipe is diagnosable.
        assert!(ECHO_DROPPED.load(std::sync::atomic::Ordering::Relaxed) >= 2);
        assert_eq!(
            g.iter()
                .filter(|l| l.contains("stopped accepting output"))
                .count(),
            1
        );
    }

    /// The span a failed job snapshots has to survive every way its ends
    /// can disagree - the ring is global, bounded, and older than any one
    /// caller's mark.
    #[test]
    fn a_marked_span_never_outruns_the_ring() {
        // The ordinary case: 40 lines printed since the mark, all held.
        assert_eq!(span_len(100, 140, 500, 160), 40);
        // Longer than the ring: only what survives comes back, not a
        // count that would index past the front.
        assert_eq!(span_len(0, 10_000, CAP, 160), 160);
        assert_eq!(span_len(0, 10_000, CAP, 100_000), CAP);
        // The caller's own ceiling wins when it is the smallest.
        assert_eq!(span_len(100, 140, 500, 10), 10);
        // A mark from the future (a re-created ring, a bogus value)
        // saturates to zero instead of wrapping to "everything".
        assert_eq!(span_len(500, 140, 500, 160), 0);
        // Nothing printed since the mark: an empty snapshot, not the tail
        // of somebody else's job.
        assert_eq!(span_len(140, 140, 500, 160), 0);
    }

    /// The property the per-job report rests on. `since` runs its span
    /// to the present, which is right while the work is still going and
    /// wrong once it has finished: a report assembled minutes later
    /// would carry every line the daemon's background lanes printed
    /// after the job ended, filed under that job.
    #[test]
    fn a_bracketed_span_excludes_what_came_after_it() {
        // 7 lines held, job owns 2..5, two more printed since.
        assert_eq!(between_span(2, 5, 7, 7, 100), (2, 3));
        // The cap keeps the END of the span, like `since`: a run's
        // verdict and its server table are the last things it prints.
        assert_eq!(between_span(0, 4, 5, 5, 2), (2, 2));
        // A span whose front the ring has already evicted comes back
        // short rather than wrong - and shorter than the ring, because
        // 50 of the lines it does hold were printed after the span
        // ended and are not the span's to give.
        assert_eq!(between_span(0, 10_000, 10_050, CAP, 100_000), (0, CAP - 50));
    }

    /// Every way two marks can be nonsense yields nothing, never a slice
    /// of somebody else's output.
    #[test]
    fn nonsense_marks_yield_no_span() {
        assert_eq!(between_span(2, 1, 7, 7, 100), (0, 0), "to behind from");
        assert_eq!(between_span(1, 1, 7, 7, 100), (0, 0), "empty span");
        // Both of these are what a mark kept across a restart looks
        // like: SEEN went back to zero and has not climbed this far.
        assert_eq!(between_span(0, 99, 7, 7, 100), (0, 0), "to past capture");
        assert_eq!(between_span(99, 200, 7, 7, 100), (0, 0), "both past it");
        assert_eq!(between_span(0, 3, 7, 7, 0), (3, 0), "no room asked for");
    }

    #[test]
    fn ring_line_survives_non_utf8_and_trims_newline() {
        assert_eq!(ring_line(b"hello\n"), "hello");
        assert_eq!(ring_line(b"hello\r\n"), "hello");
        assert_eq!(ring_line(b"no newline"), "no newline");
        assert_eq!(ring_line(b""), "");
        // A legacy-encoded filename byte (0xFF) off an unrar/par2 line is
        // decoded lossily, NOT dropped - the line that used to kill the tee.
        let out = ring_line(b"unpacking \xFF.rar\n");
        assert!(out.starts_with("unpacking ") && out.ends_with(".rar"));
        assert!(out.contains('\u{FFFD}'));
    }

    /// The knob the disk's life depends on, and the direction it fails
    /// in. Parsed off a string rather than off the environment because
    /// the suite runs in parallel and `set_var` is process-global.
    #[test]
    fn an_unreadable_cap_falls_back_to_the_default_not_to_uncapped() {
        assert_eq!(cap_from(None), 50 << 20, "unset = the documented 50 MB");
        assert_eq!(cap_from(Some("200")), 200 << 20);
        // The documented escape hatch, and the ONE way to get no cap.
        assert_eq!(cap_from(Some("0")), 0);
        // Anything we cannot read is a typo, not a request for an
        // unbounded log: `50m`, an empty value, a negative.
        for bad in ["50m", "", " 50", "-1", "fifty"] {
            assert_eq!(cap_from(Some(bad)), 50 << 20, "{bad:?}");
        }
        // A value big enough to overflow the shift saturates rather than
        // wrapping to a tiny cap that would truncate the log constantly.
        assert_eq!(cap_from(Some(&u64::MAX.to_string())), u64::MAX);
    }

    /// Both platforms leave the SAME line behind, because it is what a
    /// user greps for after finding their log starts mid-session.
    #[test]
    fn the_truncation_notice_names_the_cap_and_the_override() {
        let n = cap_notice(50 << 20);
        assert_eq!(
            n,
            "[log] size cap 50 MB reached - file truncated (NZBFAST_LOG_CAP_MB overrides)\n"
        );
        // It is written as the file's first line, so it has to end one.
        assert!(n.ends_with('\n'));
        assert!(cap_notice(200 << 20).contains("200 MB"));
    }

    /// The Windows cap, on a scratch file standing in for a redirected
    /// stdout. Both routes are exercised, because they are not the same
    /// code and the one that matters in the field is the second: the
    /// tray opens daemon.log in APPEND mode, and an append handle has no
    /// `FILE_WRITE_DATA`, so `set_len` on it is refused and the
    /// truncation has to go through a freshly opened handle on the path.
    #[cfg(windows)]
    #[test]
    fn the_windows_cap_truncates_both_a_redirect_and_an_append_handle() {
        use std::io::Write;
        use std::os::windows::io::AsRawHandle;

        let cap: u64 = 1 << 20;
        for (n, append) in [(0u32, false), (1u32, true)] {
            let path =
                std::env::temp_dir().join(format!("nzbfast-logcap-{}-{n}.log", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(append)
                .write(!append)
                .open(&path)
                .expect("scratch log");
            f.write_all(&vec![b'x'; (cap as usize) + 4096])
                .expect("fill");
            f.flush().expect("flush");
            assert!(std::fs::metadata(&path).unwrap().len() > cap);

            super::wincap::cap_one(f.as_raw_handle(), cap);
            let after = std::fs::read_to_string(&path).expect("read back");
            assert!(
                after.starts_with("[log] size cap 1 MB reached"),
                "append={append}: {after:?}"
            );

            // And the writer keeps writing INTO the same file, at the new
            // end - an append handle finds it by itself, a redirect was
            // rewound. Either way there is no hole where the old bytes
            // were, which is the whole point of truncating in place.
            f.write_all(b"after\n").expect("write on");
            f.flush().expect("flush");
            let after = std::fs::read_to_string(&path).expect("read back");
            assert!(after.ends_with("after\n"), "append={append}: {after:?}");
            assert!(
                (after.len() as u64) < cap,
                "append={append}: {} bytes",
                after.len()
            );
            drop(f);
            let _ = std::fs::remove_file(&path);
        }
    }

    /// A cap of 0 is uncapped, and the truncation path has to honour
    /// that too - not only [`super::wincap::spawn`], which declines to
    /// start a watcher at all.
    #[cfg(windows)]
    #[test]
    fn a_zero_cap_never_truncates_on_windows() {
        use std::io::Write;
        use std::os::windows::io::AsRawHandle;

        let path =
            std::env::temp_dir().join(format!("nzbfast-logcap-zero-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut f = std::fs::File::create(&path).expect("scratch log");
        f.write_all(b"kept\n").expect("fill");
        f.flush().expect("flush");
        super::wincap::cap_one(f.as_raw_handle(), 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "kept\n");
        drop(f);
        let _ = std::fs::remove_file(&path);
    }
}
