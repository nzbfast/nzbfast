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
//! and the ring stays empty (the dashboard says so).

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
/// Read only by the unix reader thread, and unlike [`CAP`] it has no test
/// of its own, so off unix it is not compiled at all.
#[cfg(unix)]
fn log_cap_bytes() -> u64 {
    std::env::var("NZBFAST_LOG_CAP_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(50)
        .saturating_mul(1 << 20)
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
    #[cfg_attr(all(test, not(unix)), allow(dead_code))]
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

/// Install the tee. Call once, early; further calls are no-ops.
pub fn install() {
    #[cfg(unix)]
    {
        if RING.get().is_some() {
            return;
        }
        let ring: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
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
                                let _ = echo.write_all(
                                    format!(
                                        "[log] size cap {} MB reached - file truncated (NZBFAST_LOG_CAP_MB overrides)\n",
                                        cap >> 20
                                    )
                                    .as_bytes(),
                                );
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
    use super::{CAP, ECHO_DROPPED, between_span, capture, ring_line, span_len};
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
}
