#!/usr/bin/env python3
"""riglock_state.py - the ONE answer to "is ~/.parfast-rig.lock actually held?"

Imported by pdrv.RigLock, ladder.RigLock and mqueue.py so the three cannot
disagree. Deliberately imports NOTHING platform-specific at module scope -
ladder.py runs on Windows, where `fcntl` does not exist, so the flock probe is
imported inside the one function that uses it and is skipped entirely there.

WHY THIS EXISTS - both polarities of the same defect, one file, six hours,
16 Sep 2026 (an internal note):

  - THE ORPHAN. At 10:21Z `~/.parfast-rig.lock` on apple-m3-ultra existed at ZERO
    BYTES, mtime eight hours old, with no parfast/par2turbo/par2j/par2 process
    on the box and no holder in `lsof`. `mqueue.py`'s `busy()` was, in full,
    `if os.path.exists(LOCK): return "lock " + LOCK` - existence WAS the hold -
    so a round that dies between `open()` and the identity write blocks every
    round that respects the lock, forever, and identifies nobody. Two lanes
    reached that verdict independently inside two minutes and each had to
    decide on its own authority whether removing another round's lock was
    legitimate.

  - THE CLOBBER, 10:27Z. A lane had taken the lock at 10:21:09Z with a shell
    exclusive create (`set -o noclobber`) - no flock, because a shell has
    none. `nttwork.py` then took it through pdrv.RigLock, won the flock
    (nobody held one), truncated and wrote its own line over a LIVE round's.
    So the care taken on the take path is worth nothing while the takers
    disagree about what a hold IS.

THE RULE, and it is one sentence: LIVENESS COMES FROM THE HOLDER, NEVER FROM
THE CLOCK. A legitimate round can hold this box for hours - the 15 Sep
over-RAM create rounds and the flat-window grid both ran past an hour - so any
age bound short enough to clear the 02:17Z orphan is short enough to steal a
live round's box, which is strictly worse than the problem being fixed and is
the failure bench-suite item 0e exists to prevent. There is NO age bound here
and none may be added. A lock naming a pid that is alive on this box is HELD
at any age; a lock that cannot say who holds it is an orphan at any age.

  held   - a flock is held on it, OR its identity line names a live foreign
           pid. Wait. This is the answer for everything we cannot disprove.
  orphan - it parses to no pid (zero bytes, truncated, garbage), or names a
           pid that is not alive, or names a pid younger than the lock itself
           (a recycled number, not our holder). Provably nobody's.
  absent - no file.

No `--force` anywhere, on purpose: an orphan the tool can PROVE is one needs
no flag, and one it cannot prove is one is a human's call, not a flag's.

ORDER MATTERS in `lock_state`. The pid test runs FIRST and the flock probe
only when the pid test has already said "orphan", because the probe takes a
real LOCK_EX for the microseconds it is held, and a taker that calls take() in
that window would see a spurious LOCK-BUSY and exit 17. Asking the cheap
question first means the probe only runs on the rare path where we are about
to declare a file dead - where being slow and sure is exactly right.

The flock probe is still LOAD-BEARING and not belt-and-braces: a holder that
forked and exited leaves a live flock on an fd its child inherited under an
identity line naming the DEAD parent. That is held, and only the probe can
see it.
"""
import os
import subprocess
import time

LOCK = os.path.expanduser("~/.parfast-rig.lock")


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_holder(path=LOCK):
    """The identity line as a dict, or {} if there is nothing readable in it.

    Tolerant by design: the line is written `round=<r> pid=<n> started=<iso>`
    by pdrv/plib and `pid=<n> round=<r> started=<iso>` by ladder, and a
    half-written one is exactly the case this module has to survive.
    """
    try:
        with open(path) as fh:
            text = fh.read(4096)
    except OSError:
        return {}
    fields = {}
    for token in text.split():
        if "=" in token:
            k, _, v = token.partition("=")
            fields.setdefault(k, v)
    return fields


def holder_pid(path_or_fields=LOCK):
    fields = path_or_fields if isinstance(path_or_fields, dict) else read_holder(path_or_fields)
    try:
        pid = int(fields.get("pid", ""))
    except ValueError:
        return None
    return pid if pid > 0 else None


def _process_age_s(pid):
    """Seconds since `pid` started, or None if this box will not say.

    `etimes` is Linux-only (macOS `ps` rejects the keyword outright), so fall
    back to parsing `etime`'s [[dd-]hh:]mm:ss. None means "no answer", which
    every caller must read as "assume alive" - and that is the whole of the
    Windows behaviour, where there is no `ps` at all: the recycled-pid check is
    a POSIX-only tightening of a rule that is correct without it.
    """
    if os.name == "nt":
        return None
    for keyword, parse in (("etimes", lambda s: float(s)), ("etime", _parse_etime)):
        try:
            out = subprocess.run(["ps", "-p", str(pid), "-o", keyword + "="],
                                 capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
        if not out:
            continue
        try:
            return parse(out)
        except ValueError:
            continue
    return None


def _parse_etime(s):
    days = 0
    if "-" in s:
        d, _, s = s.partition("-")
        days = int(d)
    parts = [int(p) for p in s.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0)
    return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]


def _win_pid_alive(pid):
    """Windows liveness, read-only: OpenProcess for QUERY_LIMITED_INFORMATION
    and ask the kernel for the process's exit code. No signal, no terminate, no
    `tasklist` subprocess. Every unreadable answer resolves to ALIVE.

    GetExitCodeProcess, and NEVER WaitForSingleObject. This function asked
    "is the handle signalled yet?" until 16 Sep 2026, and it answered DEAD FOR
    EVERY PROCESS ON WINDOWS, live or not: waiting on a handle requires
    SYNCHRONIZE (0x00100000) access, which PROCESS_QUERY_LIMITED_INFORMATION
    does not carry, so the wait returned WAIT_FAILED (0xFFFFFFFF) with
    ERROR_ACCESS_DENIED rather than WAIT_TIMEOUT - and "not WAIT_TIMEOUT" was
    read as "exited". Every lock on a Windows box was therefore an orphan, and
    ladder.RigLock would hand a LIVE round's box to the next taker: the exact
    theft this module exists to prevent, arriving through the check meant to
    prevent it. Measured on intel-core-ultra-9-386h (Python 3.12.10) by the arm 3 failure
    in harness/windows_rig_lock_selftest.py; see
    an internal note.

    GetExitCodeProcess is satisfied by PROCESS_QUERY_LIMITED_INFORMATION, needs
    no SYNCHRONIZE, and is the documented way to ask this. Its one edge is
    benign HERE and must stay understood: a process that genuinely exits with
    code 259 is indistinguishable from STILL_ACTIVE and reads as alive - which
    is the safe direction, costing a wait rather than somebody's round.

    Types are declared rather than defaulted: ctypes' default restype is
    `c_int`, which would sign-truncate a HANDLE, and `use_last_error=True` puts
    GetLastError in ctypes' own storage where a later ctypes call cannot clobber
    it before we read it.
    """
    try:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (ImportError, AttributeError, OSError):
        return True
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    ERROR_INVALID_PARAMETER = 87          # no such pid
    STILL_ACTIVE = 259
    try:
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.GetExitCodeProcess.restype = ctypes.c_int
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        k32.CloseHandle.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    except (AttributeError, OSError, ValueError):
        return True
    if not handle:
        # ACCESS_DENIED means it EXISTS and is not ours - alive. Only
        # "invalid parameter" means there is no such process.
        return ctypes.get_last_error() != ERROR_INVALID_PARAMETER
    try:
        code = ctypes.c_uint32(0)
        if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == STILL_ACTIVE
    finally:
        k32.CloseHandle(handle)


def pid_alive(pid, started=None):
    """Is `pid` a live process on THIS box, and plausibly the one that wrote
    the lock?

    `started` is the lock's own `started=` stamp. When both it and the
    process's age are readable, a process that began AFTER the lock was
    written cannot be the holder - the number was recycled - and that is the
    one case where a live pid is still an orphan. Every unreadable input
    resolves to "alive", because being wrong in that direction costs a wait
    and being wrong in the other costs somebody's round.
    """
    if pid is None:
        return False
    if os.name == "nt":
        # NEVER os.kill(pid, 0) HERE. On POSIX signal 0 is the standard
        # existence probe and delivers nothing; on Windows CPython's os.kill
        # has no such case - it OpenProcess()es and calls TerminateProcess with
        # the signal as the EXIT CODE, so `os.kill(pid, 0)` KILLS the holder
        # and reports it as a clean exit. ladder.py runs on Windows, so that
        # line would have turned this orphan check into the loudest possible
        # version of the theft it exists to prevent.
        return _win_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # somebody else's process: alive, just not ours to signal
    except OSError:
        return True
    if not started:
        return True
    import calendar
    try:
        # `started` is UTC: calendar.timegm, NEVER time.mktime, which would
        # read it as local time and put the lock's age hours out on any box
        # that is not on UTC - every Mac on this fleet.
        lock_age = time.time() - calendar.timegm(time.strptime(started[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return True
    proc_age = _process_age_s(pid)
    if proc_age is None or lock_age < 0:
        return True
    # 120 s of slack: `started` has second resolution, the two clocks here are
    # the same clock, and a genuine holder is never within two minutes of its
    # own lock's age by the time anyone is asking.
    return proc_age + 120 >= lock_age


def _flock_free(path):
    """True if a non-blocking LOCK_EX succeeds (and is released immediately).

    Windows has no fcntl and needs none: `open(path, "x")` there is CreateFile
    with CREATE_NEW under a share mode that excludes FILE_SHARE_DELETE, so
    "exists" and "is open by somebody" are the same fact and the existence of
    the file is answered by the taker's own create.
    """
    try:
        import fcntl
    except ImportError:
        return True
    try:
        fh = open(path, "a")     # "a", NEVER "w" - "w" truncates a live holder's identity
    except OSError:
        return False
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    else:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return True
    finally:
        fh.close()


def lock_state(path=LOCK, probe_flock=True, self_pid=None):
    """('absent'|'held'|'orphan', description). See the module docstring.

    `probe_flock=False` is for a caller that has ALREADY won the flock on this
    file - take(), which knows no flock holder exists and must not ask again.
    `self_pid` defaults to this process: a lock naming US is our own leftover,
    never a foreign hold.
    """
    if self_pid is None:
        self_pid = os.getpid()
    if not os.path.exists(path):
        return "absent", "no lock file"
    fields = read_holder(path)
    line = " ".join("%s=%s" % (k, fields[k]) for k in ("round", "pid", "host", "started") if k in fields)
    pid = holder_pid(fields)
    if pid is not None and pid != self_pid and pid_alive(pid, fields.get("started")):
        return "held", line or ("pid=%d" % pid)
    if probe_flock and not _flock_free(path):
        return "held", "an flock is held on it by an unnamed process (%s)" % (line or "empty file")
    if not line:
        return "orphan", "zero bytes or no parseable identity - it names nobody"
    if pid is None:
        return "orphan", "no pid in its identity line (%s)" % line
    if pid == self_pid:
        return "orphan", "names THIS process (%s) - our own leftover" % line
    return "orphan", "names a dead pid (%s)" % line


def coordination_file():
    """The box's coordination file, or None if this box does not have exactly
    one. $BOXGATE_COORD wins (bench-suite item 0's own variable); otherwise a
    single ~/bench-out/COORDINATION-*.txt is unambiguous and two are not - and
    guessing which box we are on is how a NOTE lands on the wrong box's file.
    """
    env = os.environ.get("BOXGATE_COORD")
    if env:
        return env
    import glob
    hits = sorted(glob.glob(os.path.expanduser("~/bench-out/COORDINATION-*.txt")))
    return hits[0] if len(hits) == 1 else None


def announce_orphan(path, what, action, coord=None):
    """Say it OUT LOUD, on stdout and on the box's coordination file.

    Item 3 of the handoff: two lanes cleared this by hand on 16 Sep and
    neither left a trace, so the next lane re-derives the same judgement from
    scratch. A NOTE costs one line and makes the pattern visible. Best effort
    in both directions - a round must never die because a coordination file
    was unwritable.
    """
    print("RIG-LOCK-ORPHAN %s %s - was: %s" % (path, action, what), flush=True)
    if coord is None:
        coord = coordination_file()
    if not coord:
        return
    import socket
    note = ("NOTE %s (rig lock, %s) ORPHAN %s at %s - was: %s. Liveness came from the "
            "holder (dead or unnamed pid), never from the file's age.\n"
            % (utcnow(), socket.gethostname(), action, path, what))
    try:
        with open(coord, "a") as fh:
            try:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            except ImportError:
                pass
            fh.write(note)
            fh.flush()
    except OSError:
        pass
