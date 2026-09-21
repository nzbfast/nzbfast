#!/usr/bin/env python3
"""windows_rig_lock_selftest.py - exercises ladder.RigLock's IS_WIN branch on
a real Windows box, which rig_lock_selftest.py cannot do (it also imports
pdrv.RigLock, and pdrv.py imports fcntl unconditionally, which does not exist
on Windows).

Follow-up to claim parfast-rig-lock-unlink-safe-15sep (landed 32c9b3ef0,
an internal note). That fix's
Windows arm was reasoned about only, never run: ladder.RigLock.take() uses
`open(path, "x")` (CreateFile with CREATE_NEW) and its docstring claims
Python's default share mode on Windows excludes FILE_SHARE_DELETE, so "the
file exists" and "the file is locked" are the same fact there and the
POSIX-side inode re-check is unnecessary.

rig_lock_selftest.check() cannot be reused as-is: its setup step models a
"stale holder" by calling os.unlink(lock) directly on a path a live fd still
has open, which is exactly the operation Windows is claimed to refuse. Tried
verbatim first (see the incident note this script's HANDOFF references) -
it does refuse, with PermissionError/WinError 32, uncaught, which is actually
the claim being demonstrated but is not a clean assertion. So this script
tests the three properties natively instead:

  1. DELETION-PROTECTED: while a live holder's fd is open, nothing else -
     not even a direct os.remove() standing in for a rogue "stale releaser" -
     can delete or replace its lock file. (On POSIX this needs the
     flock+inode dance because unlink() and an open fd are decoupled; on
     Windows the OS itself refuses the delete, so this is the Windows-native
     shape of the same property the amd-epyc-vm incident was about.)
  2. BUSY: a second taker must see LOCK-BUSY (SystemExit) while the first
     still holds the lock, and must leave the holder's file and identity line
     untouched. Both takers are in THIS process, so this arm is proved by the
     delete refusal of property 1 rather than by the live-holder rule - read
     the note at the site, and read check_orphans() arm 3 for the live-holder
     rule tested properly, against a separate process.
  3. HANDOFF: once the holder releases, a fresh taker must succeed cleanly.

And since 16 Sep 2026, in check_orphans(), the three ORPHAN properties - a
zero-byte lock and a lock naming a dead pid are both takeable at any age, and
a lock naming a LIVE pid is refused at any age with its identity line
untouched. Read that function's docstring: the third is the one that matters,
and on Windows it is also what catches a future refactor reaching for
`os.kill(pid, 0)`, which TERMINATES the process it asks about there.

ARM 3 HAS ALREADY EARNED ITS KEEP, on this script's FIRST EVER EXECUTION
(intel-core-ultra-9-386h, Python 3.12.10, 16 Sep 2026): it failed, and the defect was real.
`riglock_state._win_pid_alive` asked `WaitForSingleObject(handle, 0) ==
WAIT_TIMEOUT` on a handle opened for PROCESS_QUERY_LIMITED_INFORMATION, which
does not carry SYNCHRONIZE, so the wait returned WAIT_FAILED with
ERROR_ACCESS_DENIED for EVERY pid and every live holder read as dead - every
Windows lock an orphan, every live round's box takeable. No amount of reasoning
on a Mac could have seen it; a forced-`IS_WIN` run there never reaches a kernel
handle. That is the argument for running this on real hardware rather than
reasoning about it, and it is why the arm asserts liveness AFTER the refusal
rather than only asserting the refusal.

Uses a tempfile.TemporaryDirectory() path throughout - never touches this
box's real lock file or any live round.

    python windows_rig_lock_selftest.py

Exit 0 and `WINDOWS-RIG-LOCK-SELFTEST-OK` on the last line means all three
pass; an AssertionError names which one failed.
"""
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _dead_pid():
    """A pid that is definitely NOT running: our own child, waited on."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _live_pid():
    """A pid that is definitely running. Killed BY PID by the caller, never by
    pattern (CLAUDE.md invariant 2a)."""
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])


def _write_lock(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def check_orphans():
    """The orphan arms (16 Sep 2026), Windows-native.

    `open(path, "x")` failing is NOT a hold: "exists" and "is locked" are the
    same fact only while the holder's HANDLE is open, and a holder that dies
    without releasing leaves the directory entry behind - after which CREATE_NEW
    refuses every round on this box forever, naming nobody. That is the
    apple-m3-ultra orphan of 16 Sep in its Windows spelling
    (an internal note).

    ARM 3 IS THE ONE THAT MATTERS, and it is why liveness may never come from
    the clock: a legitimate round holds this box for hours, so any age bound
    short enough to clear arm 1 is short enough to take arm 3's box - strictly
    worse than the eight hours being fixed. It also asserts the LIVE holder's
    identity line survives the refusal byte for byte (the 10:27:42Z clobber).

    This arm is also the one that catches `os.kill(pid, 0)` - the POSIX
    liveness idiom - being used here by a future refactor: on Windows that call
    TERMINATES the process it is asked about, so a passing arm 3 proves both
    that the live holder kept its lock and that it is still alive to hold it.
    """
    with tempfile.TemporaryDirectory() as d:
        lock = os.path.join(d, "rig.lock")
        # Pin the orphan NOTE at a file of our own: a selftest must not append
        # to this box's real coordination file, and pinning it is what lets
        # arm 1 assert the NOTE was written at all.
        os.environ["BOXGATE_COORD"] = os.path.join(d, "COORDINATION-selftest.txt")

        import ladder

        # --- 1. ZERO BYTES: release()'s own spelling for an ordinary
        # hand-over, not the 16 Sep crash-before-write case any more -
        # riglock_state.lock_state() tells them apart since 20 Sep 2026.
        # take() must still clear it, but SILENTLY (an internal note-
        # 20-RARKIT-DISPATCHER-4.md - folding this into "orphan" and
        # announcing it is what made an ordinary hand-over on apple-m3-ultra
        # print a false RIG-LOCK-ORPHAN).
        coord = os.environ["BOXGATE_COORD"]
        _write_lock(lock, "")
        a = ladder.RigLock("selftest-round", lock_path=lock)
        a.take()
        with open(lock) as fh:
            assert "pid=%d" % os.getpid() in fh.read(), \
                "FAIL: a released (zero-byte) lock did not hand over"
        a.release()
        assert not os.path.exists(coord), \
            "FAIL: an ordinary hand-over (zero bytes) announced an orphan"

        # --- 2. A DEAD PID, with an intact identity line and a deliberately
        # ancient `started` - age is NOT what decides, in either direction.
        # A genuine orphan, unlike arm 1: must be cleared AND announced.
        _write_lock(lock, "pid=%d round=ghost started=2026-09-16T02:17:45Z\n" % _dead_pid())
        b = ladder.RigLock("selftest-round", lock_path=lock)
        b.take()
        with open(lock) as fh:
            assert "pid=%d" % os.getpid() in fh.read(), \
                "FAIL: a lock naming a dead pid did not hand over"
        b.release()
        assert os.path.exists(coord), "FAIL: clearing a dead-pid orphan wrote no coordination NOTE"
        with open(coord) as fh:
            assert "ORPHAN" in fh.read(), "FAIL: the coordination NOTE does not name the orphan"

        # --- 3. A LIVE PID: refused, at any age, with its line untouched.
        sleeper = _live_pid()
        try:
            held_line = "pid=%d round=live-round started=%s\n" % (
                sleeper.pid, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            _write_lock(lock, held_line)
            c = ladder.RigLock("selftest-round", lock_path=lock)
            try:
                c.take()
            except SystemExit:
                pass
            else:
                c.release()
                raise AssertionError(
                    "FAIL: took the lock from a LIVE holder - this steals a running round's box")
            with open(lock) as fh:
                assert fh.read() == held_line, \
                    "FAIL: a refused taker rewrote the LIVE holder's identity line"
            assert sleeper.poll() is None, \
                "FAIL: the liveness check KILLED the live holder (os.kill(pid, 0) terminates on Windows)"
        finally:
            sleeper.kill()      # BY PID, our own child only
            sleeper.wait()
        os.environ.pop("BOXGATE_COORD", None)

    print("PASS ladder.RigLock orphan arms (Windows)")


def main():
    assert os.name == "nt", "this script only exercises the Windows arm; run it on a Windows box"

    import ladder
    assert ladder.IS_WIN, "ladder.IS_WIN is False on a Windows box - os.name != 'nt'?"

    with tempfile.TemporaryDirectory() as d:
        lock = os.path.join(d, "rig.lock")

        # --- 1. DELETION-PROTECTED: A holds the lock; a direct os.remove()
        # standing in for an external/rogue deleter (the Windows analogue of
        # the amd-epyc-vm "stale releaser") must be refused while A's fd is
        # open, and A's file must survive untouched.
        a = ladder.RigLock("selftest-round", lock_path=lock)
        a.take()
        try:
            os.remove(lock)
        except OSError:
            pass
        else:
            raise AssertionError("FAIL: an external os.remove() deleted a live holder's lock file")
        assert os.path.exists(lock), "FAIL: live holder's lock file is gone after a refused external delete"
        with open(lock) as fh:
            assert "round=" in fh.read(), "FAIL: live holder's lock content is gone"

        # --- 2. BUSY: B must be refused while A still holds the lock.
        #
        # READ WHAT THIS ARM ACTUALLY PROVES, BECAUSE IT IS NARROWER THAN ITS
        # NAME. A and B are both in THIS process, so the lock names our OWN pid
        # and riglock_state.lock_state correctly classifies it as our own
        # leftover rather than a live holder - B prints a RIG-LOCK-ORPHAN line
        # on its way to being refused. The refusal is real and the property
        # holds, but it comes from the Windows DELETE REFUSAL of arm 1 (B tries
        # to clear what it reads as an orphan, and cannot, because A's fd is
        # open), NOT from the live-holder rule the arm's name suggests.
        #
        # That is left as it is, deliberately, because the live-holder rule is
        # covered PROPERLY a few lines down: check_orphans() arm 3 plants a
        # lock naming a SEPARATE live process and asserts the taker is refused,
        # the identity line survives byte for byte, and the holder is still
        # alive afterwards. Duplicating that here would add a second, weaker
        # copy of an arm that already earned its keep on this script's first
        # execution. So this arm is the CREATE_NEW-plus-delete-protection arm,
        # and it is named BUSY because that is the behaviour a caller sees.
        #
        # What it must NOT be allowed to become is a refusal that damaged
        # something on the way, so the assertions after it are the arm's real
        # content: A's file is still there and still names A.
        b = ladder.RigLock("selftest-round", lock_path=lock)
        try:
            b.take()
        except SystemExit:
            pass
        else:
            b.release()
            raise AssertionError("FAIL: B took the lock while A still held it")
        assert os.path.exists(lock), \
            "FAIL: a refused taker removed the holder's lock file"
        with open(lock) as fh:
            assert "pid=%d" % os.getpid() in fh.read(), \
                "FAIL: a refused taker rewrote the holder's identity line"

        # --- 3. HANDOFF: A releases; B must now take it cleanly, and its
        # own release must leave nothing behind.
        a.release()
        assert not os.path.exists(lock), "FAIL: A's own release() left its file behind"
        b2 = ladder.RigLock("selftest-round", lock_path=lock)
        b2.take()
        assert os.path.exists(lock), "FAIL: B could not take the lock once A released it"
        b2.release()
        assert not os.path.exists(lock), "FAIL: B's release() left its file behind"

    print("PASS ladder.RigLock (Windows)")
    check_orphans()
    print("WINDOWS-RIG-LOCK-SELFTEST-OK")


if __name__ == "__main__":
    main()
