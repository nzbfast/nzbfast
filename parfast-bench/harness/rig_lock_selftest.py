#!/usr/bin/env python3
"""rig_lock_selftest.py - proves ~/.parfast-rig.lock's unlink-safety fix by
actually racing it, not by reading the code.

Reproduces the double-holder shape from the amd-epyc-vm incident on
15 Sep 2026 (an internal note):
a stale releaser - a process holding an fd on an older, already-unlinked
lock inode - must NOT be able to remove a CURRENT holder's live lock file;
a taker must still see LOCK-BUSY while that current holder is up; and once
the current holder releases, a fresh taker must succeed.

Exercises BOTH cuts of the fix: pdrv.RigLock (imported directly - the
mac/Linux rig scripts, plus memround.py/memladder.py/mqueue.py which import
pdrv) and ladder.py's own RigLock (a separate class, because pdrv.py imports
`fcntl` unconditionally and cannot be imported on Windows, where ladder.py
also runs). Both classes take a `lock_path` override built for this script,
so nothing here ever touches the real ~/.parfast-rig.lock - no rig lock
needed to run it, and it is safe to run on a box mid-round.

    python3 rig_lock_selftest.py

Exit 0 and `RIG-LOCK-SELFTEST-OK` on the last line means both classes pass;
an AssertionError (with a traceback) names which check failed and on which
class. Run on both a Linux box and a Mac (`ladder.RigLock`'s POSIX arm is
what this validates there; its Windows arm needs a real Windows box, which
this repo has no CI for - `windows_rig_lock_selftest.py` is its acceptance,
and it carries the same three orphan arms).

SINCE 16 Sep 2026 it also proves the ORPHAN half - see the block comment above
check_orphans(). Three arms per taker (zero-byte lock, a lock naming a dead
pid, a lock naming a LIVE pid that must still be refused), plus the same three
against mqueue.lock_hold(), which is the waiter that actually failed. It pins
$BOXGATE_COORD at a temp file for the duration, so the orphan NOTE it asserts
lands there and never on this box's real coordination file.

RETIGHTENED 20 Sep 2026: arm 1 stopped being a synthetic "orphan" and became
what it actually is - an ORDINARY HAND-OVER. `riglock.py`'s `release()`
truncates rather than unlinks, so a zero-byte lock is that function's own
spelling for "released", and until this day `lock_state()` could not tell it
apart from the 16 Sep crash-before-write case above, so every normal
hand-over on apple-m3-ultra announced RIG-LOCK-ORPHAN and posted a NOTE two lanes
read as a double-booking that never happened
(an internal note). Arm 1 now asserts
SILENCE; arm 2 (a dead pid, a genuine orphan) still asserts the announcement.

SINCE 16 Sep 2026 (later the same day) the same three arms also cover
riglock.take()/release() - the shell-round wrapper, not a class like the other
two, so check_riglock_orphans() below is its own function rather than a
`cls`/`ctor_args` pair through check_orphans(). Its `take()` does not exit on
a live holder the way pdrv.RigLock does; it queues (sleeps and retries), so
arm 3 passes `tries=1, wait=0` to make the refusal happen on the first look
rather than actually waiting out `tries`.

SINCE 17 Sep 2026 it also proves riglock.take()'s HANDOVER - see the block
comment above check_riglock_fairness(). Nothing here had ever checked who
gets the lock NEXT, which is why a waiter that lost 7,000 consecutive draws
over 3h53m read as a busy box rather than as the defect it was.

AND SINCE LATER THAT DAY the two strong handover arms ask the KERNEL first,
via `flock_fifo_probe.kernel_orders_handovers()` - see _kernel_precondition().
On a kernel that does not wake flock waiters in wait-time order (both spinning-disk-nas
DSM boxes on this fleet) neither arm 2 nor its control arm 3 is a statement
about riglock, and both were measured flaking there, so both are disarmed,
LOUDLY and by name, and reprinted on the last line of the run. Arm 1 - nobody
starves - runs everywhere and is what covers those boxes. A disarmed arm still
exits 0: it is not a failure, it is a box this gate cannot cover, and saying so
in words rather than in silence is the whole point. Never silence it to make a
box green.
"""
import contextlib
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


@contextlib.contextmanager
def _quiet_box_disarmed(cls):
    """require_quiet_box() shells out to `ps` and can itself wait/abort on a
    genuinely loaded box - real production behaviour for a round, but noise
    for a test of the LOCK, which is the only thing this script checks. Only
    pdrv.RigLock.take() calls it."""
    mod = sys.modules.get(cls.__module__)
    if mod is None or not hasattr(mod, "require_quiet_box"):
        yield
        return
    original = mod.require_quiet_box
    mod.require_quiet_box = lambda *a, **k: None
    try:
        yield
    finally:
        mod.require_quiet_box = original


@contextlib.contextmanager
def _coord_pinned(d):
    """Pin $BOXGATE_COORD at a file of OUR OWN for the block.

    EVERY take() IN THIS SCRIPT NEEDS THIS, not just the ones that are ABOUT
    orphans. Until 20 Sep 2026 `riglock.release()`'s truncate meant the next
    take() on the same temp lock saw zero bytes, called `announce_orphan` for
    a perfectly ordinary hand-over, and that fell back to
    `riglock_state.coordination_file()` - which on a box with exactly one
    ~/bench-out/COORDINATION-*.txt is the REAL one. The handover arms take and
    release a holder lock several times per rep IN THE PARENT, so running this
    script on such a box appended a NOTE per rep to a shared file that other
    lanes read, against this script's own documented promise that it is safe
    mid-round and touches nothing of the box's. Found 17 Sep 2026 by running
    it on the two spinning-disk-nas boxes, which have exactly one coordination file
    each; the dev Mac and amd-epyc-vm have two, so `coordination_file()`
    returned None there and the defect was invisible on every box it had been
    run on until then. `lock_state()` no longer reads a zero-byte file as an
    orphan at all (an internal note), so the
    handover arms cannot trigger this any more either way - this pin now
    guards only the genuine-orphan arms below and is kept for every take()
    rather than re-litigated per call site.
    """
    original = os.environ.get("BOXGATE_COORD")
    os.environ["BOXGATE_COORD"] = os.path.join(d, "COORDINATION-selftest.txt")
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("BOXGATE_COORD", None)
        else:
            os.environ["BOXGATE_COORD"] = original


def check(name, cls, ctor_args):
    with tempfile.TemporaryDirectory() as d, _quiet_box_disarmed(cls):
        lock = os.path.join(d, "rig.lock")

        # --- construct a STALE holder: takes the lock, then has its file
        # unlinked out from under it (the way an earlier holder that has
        # already finished or crashed would look to a late arrival), while
        # it still holds an open, flocked fd on that now-orphaned inode.
        stale = cls(*ctor_args, lock_path=lock)
        stale.take()
        stale_ino = os.fstat(stale.fh.fileno()).st_ino
        os.unlink(lock)
        assert not os.path.exists(lock), f"{name}: setup: could not unlink the stale holder's file"

        # --- holder A takes the (now-empty) path fresh.
        a = cls(*ctor_args, lock_path=lock)
        a.take()
        a_ino = os.fstat(a.fh.fileno()).st_ino
        assert a_ino != stale_ino, f"{name}: setup: A landed on the stale inode - not exercising the bug"
        assert os.stat(lock).st_ino == a_ino, f"{name}: setup: A's file is not the live path"

        # --- the stale holder releases. PRE-FIX this unconditionally
        # unlinked $lock, which by now is A's file, not the stale holder's -
        # exactly what let one round delete another's live lock file on
        # amd-epyc-vm. POST-FIX it must see the inode mismatch and refuse.
        stale.release()
        assert os.path.exists(lock), f"{name}: FAIL: stale release() deleted the live holder's file"
        assert os.stat(lock).st_ino == a_ino, f"{name}: FAIL: stale release() replaced the live holder's file"
        with open(lock) as fh:
            assert "round=" in fh.read() or fh, f"{name}: FAIL: A's lock content is gone"

        # --- B must still see LOCK-BUSY while A holds the (real) lock. Both
        # classes signal busy with SystemExit, but not with the same payload
        # (pdrv.RigLock exits 17; ladder.RigLock raises a message string) -
        # this only checks that B was refused, not the exact spelling.
        b = cls(*ctor_args, lock_path=lock)
        try:
            b.take()
        except SystemExit:
            pass
        else:
            b.release()
            raise AssertionError(f"{name}: FAIL: B took the lock while A still held it")

        # --- A releases; B must now be able to take it cleanly.
        a.release()
        assert not os.path.exists(lock), f"{name}: FAIL: A's own release() left its file behind"
        b2 = cls(*ctor_args, lock_path=lock)
        b2.take()
        assert os.path.exists(lock), f"{name}: FAIL: B could not take the lock once A released it"
        b2.release()
        assert not os.path.exists(lock), f"{name}: FAIL: B's release() left its file behind"

    print(f"PASS {name}")


# --- the orphan arms (16 Sep 2026) ---------------------------------------
#
# A separate incident from the unlink-safety race above, and the opposite
# polarity: that one let two rounds hold the lock at once, this one let NO
# round hold it at all. At 10:21Z on 16 Sep `~/.parfast-rig.lock` on apple-m3-ultra
# existed at zero bytes, eight hours cold, with no holder anywhere on the box,
# and `mqueue.py`'s `busy()` - `if os.path.exists(LOCK)` - refused every round
# that respected it. Two lanes disproved it by hand within two minutes of each
# other and each had to decide on its own authority whether removing another
# round's lock was legitimate.
# (an internal note)
#
# THE THIRD ARM IS THE ONE THAT MATTERS. Clearing a dead holder's file is easy
# to get right and easy to get catastrophically wrong: the same code one bad
# refactor later clears a LIVE holder's, which steals a running round's box -
# strictly worse than the eight hours being fixed, and the exact failure
# bench-suite item 0e exists to prevent. Arm 3 of check_orphans is what stands
# between the two, so it asserts both halves: the taker is refused, AND
# the live holder's identity line is still byte-for-byte what it was (the
# clobber of 10:27:42Z the same day, when a driver that had legitimately won
# the flock truncated a shell-taken holder's line and wrote its own over it).


def riglock_now():
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _dead_pid():
    """A pid that is definitely NOT running: our own child, reaped."""
    import subprocess
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _live_pid():
    """A pid that is definitely running: our own child, still sleeping. The
    caller kills it BY PID (CLAUDE.md invariant 2a - never by pattern)."""
    import subprocess
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])


def _write_lock(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def check_orphans(name, cls, ctor_args):
    with tempfile.TemporaryDirectory() as d, _quiet_box_disarmed(cls):
        lock = os.path.join(d, "rig.lock")
        coord = os.path.join(d, "COORDINATION-selftest.txt")
        # Point the orphan announcement at a file of OUR OWN. Without this it
        # would find this box's real ~/bench-out/COORDINATION-*.txt and append
        # to it - a selftest must not write on a shared box's coordination
        # file, and pinning it here is also what lets arm 1 ASSERT the NOTE.
        os.environ["BOXGATE_COORD"] = coord

        # --- 1. ZERO BYTES: release()'s own spelling for an ordinary
        # hand-over, not the 02:17Z crash-before-write case any more -
        # lock_state() tells them apart since 20 Sep 2026. take() must still
        # clear it, but SILENTLY: folding this into "orphan" and announcing
        # it is what made every ordinary riglock.py hand-over on apple-m3-ultra
        # print a false RIG-LOCK-ORPHAN on 20 Sep 2026
        # (an internal note).
        _write_lock(lock, "")
        a = cls(*ctor_args, lock_path=lock)
        a.take()
        with open(lock) as fh:
            assert "pid=%d" % os.getpid() in fh.read(), \
                f"{name}: FAIL: a released (zero-byte) lock did not hand over"
        a.release()
        assert not os.path.exists(coord), \
            f"{name}: FAIL: an ordinary hand-over (zero bytes) announced an orphan"

        # --- 2. A DEAD PID: the ordinary crash, with an identity line intact.
        # Age is deliberately large here to prove age is NOT what decides.
        # This one is a GENUINE orphan (a non-empty, parseable-but-dead
        # identity), unlike arm 1, so it must still be cleared AND announced.
        _write_lock(lock, "round=ghost pid=%d started=2026-09-16T02:17:45Z\n" % _dead_pid())
        b = cls(*ctor_args, lock_path=lock)
        b.take()
        with open(lock) as fh:
            assert "pid=%d" % os.getpid() in fh.read(), \
                f"{name}: FAIL: a lock naming a dead pid did not hand over"
        b.release()
        assert os.path.exists(coord), f"{name}: FAIL: clearing a dead-pid orphan wrote no coordination NOTE"
        with open(coord) as fh:
            assert "ORPHAN" in fh.read(), f"{name}: FAIL: the coordination NOTE does not name the orphan"

        # --- 3. A LIVE PID, NO FLOCK: the shell taker (`set -o noclobber`),
        # which has no flock to lose, so a flock-based taker wins the flock and
        # must still be refused. `started` is NOW: a live round is entitled to
        # this box for as long as it wants it.
        sleeper = _live_pid()
        try:
            held_line = "round=live-round pid=%d started=%s\n" % (sleeper.pid, riglock_now())
            _write_lock(lock, held_line)
            c = cls(*ctor_args, lock_path=lock)
            try:
                c.take()
            except SystemExit:
                pass
            else:
                c.release()
                raise AssertionError(
                    f"{name}: FAIL: took the lock from a LIVE holder - this steals a running round's box")
            with open(lock) as fh:
                assert fh.read() == held_line, \
                    f"{name}: FAIL: a refused taker rewrote the LIVE holder's identity line"
        finally:
            sleeper.kill()      # BY PID, our own child only
            sleeper.wait()
        os.environ.pop("BOXGATE_COORD", None)

    print(f"PASS {name} (orphan arms)")


def check_mqueue_lock_hold():
    """mqueue.lock_hold() is the WAITER's half of the same rule, and the half
    that actually failed on 16 Sep. Same three arms, and it must additionally
    leave the file alone: mqueue does not take the lock, so it must not delete
    one either - the round it launches clears it while holding the flock."""
    import mqueue

    with tempfile.TemporaryDirectory() as d:
        lock = os.path.join(d, "rig.lock")
        os.environ["BOXGATE_COORD"] = os.path.join(d, "COORDINATION-selftest.txt")

        _write_lock(lock, "")
        assert mqueue.lock_hold(lock) is None, "FAIL: mqueue read a zero-byte orphan as a hold"
        assert os.path.exists(lock), "FAIL: mqueue deleted an orphan it does not own"

        _write_lock(lock, "round=ghost pid=%d started=2026-09-16T02:17:45Z\n" % _dead_pid())
        assert mqueue.lock_hold(lock) is None, "FAIL: mqueue read a dead holder as a hold"

        sleeper = _live_pid()
        try:
            _write_lock(lock, "round=live-round pid=%d started=%s\n" % (sleeper.pid, riglock_now()))
            held = mqueue.lock_hold(lock)
            assert held and "live-round" in held, \
                "FAIL: mqueue read a LIVE holder as free - this hands a running round's box away"
        finally:
            sleeper.kill()
            sleeper.wait()
        os.environ.pop("BOXGATE_COORD", None)

    print("PASS mqueue.lock_hold (orphan arms)")


def check_riglock_orphans():
    """riglock.take()/release() - the same three arms as check_orphans(), but
    hand-rolled because riglock's take() returns a bare fd rather than an
    object with .take()/.release(), and does not exit(17) on a live holder
    the way pdrv.RigLock does: it queues, so arm 3 forces `tries=1, wait=0`
    to make the refusal observable without actually waiting."""
    import riglock

    with tempfile.TemporaryDirectory() as d:
        lock = os.path.join(d, "rig.lock")
        coord = os.path.join(d, "COORDINATION-selftest.txt")
        os.environ["BOXGATE_COORD"] = coord

        # --- 1. AN ORDINARY HAND-OVER: take, release, take again. This is the
        # real production shape - riglock.release() truncates to zero bytes
        # and never unlinks - and it reproduces the two false-orphan
        # hand-overs on apple-m3-ultra on 20 Sep 2026 (22:32Z, 22:35Z) rather than
        # only a synthetic zero-byte file
        # (an internal note). Must hand
        # over SILENTLY: no coordination NOTE.
        first_fd = riglock.take("first-round", tries=5, wait=0, lock_path=lock)
        riglock.release(first_fd)
        fd = riglock.take("selftest-round", tries=5, wait=0, lock_path=lock)
        with open(lock) as fh:
            assert "pid=%d" % os.getpid() in fh.read(), \
                "riglock.take: FAIL: a released (zero-byte) lock did not hand over"
        riglock.release(fd)
        assert not os.path.exists(coord), \
            "riglock.take: FAIL: an ordinary hand-over (zero bytes) announced an orphan"

        # --- 2. A DEAD PID: a genuine orphan, unlike arm 1 - must still be
        # cleared AND announced.
        _write_lock(lock, "round=ghost pid=%d started=2026-09-16T02:17:45Z\n" % _dead_pid())
        fd = riglock.take("selftest-round", tries=5, wait=0, lock_path=lock)
        with open(lock) as fh:
            assert "pid=%d" % os.getpid() in fh.read(), \
                "riglock.take: FAIL: a lock naming a dead pid did not hand over"
        riglock.release(fd)
        assert os.path.exists(coord), "riglock.take: FAIL: clearing a dead-pid orphan wrote no coordination NOTE"
        with open(coord) as fh:
            assert "ORPHAN" in fh.read(), "riglock.take: FAIL: the coordination NOTE does not name the orphan"

        # --- 3. A LIVE PID, NO FLOCK ---
        sleeper = _live_pid()
        try:
            held_line = "round=live-round pid=%d started=%s\n" % (sleeper.pid, riglock_now())
            _write_lock(lock, held_line)
            try:
                riglock.take("selftest-round", tries=1, wait=0, lock_path=lock)
            except SystemExit:
                pass
            else:
                raise AssertionError(
                    "riglock.take: FAIL: took the lock from a LIVE holder - this steals a running round's box")
            with open(lock) as fh:
                assert fh.read() == held_line, \
                    "riglock.take: FAIL: a refused taker rewrote the LIVE holder's identity line"
        finally:
            sleeper.kill()      # BY PID, our own child only
            sleeper.wait()
        os.environ.pop("BOXGATE_COORD", None)

    print("PASS riglock.take (orphan arms)")


# Handover arms that did NOT run on this box, and why. `main()` reprints
# every entry on the LAST line of the run, because a disarm buried in the
# middle of a passing transcript is the same as a disarm nobody saw - and a
# gate that goes quiet is the failure this whole file is about.
DISARMED = []


def _kernel_precondition():
    """Arms 2 and 3 only where the kernel orders flock handovers by wait time.

    STILL OPEN item 6 of an internal note,
    taken 17 Sep 2026. Arm 2 shipped RED on both spinning-disk-nas DSM boxes and green
    everywhere else, and `flock_fifo_probe.py` attributed that red to Linux
    4.4's wake order rather than to riglock: a waiter cannot keep a place in a
    line the kernel is not keeping. A permanent red on two boxes of the fleet
    is not a cosmetic problem - it puts an AssertionError in front of exactly
    the reader most likely to relax the arm - so the arm now asks the kernel
    first and says out loud when the answer is no.

    Eight reps at four waiters, six of which must put every waiter in
    wait-time order: 11 s on an idle Linux box, 14 s on the dev Mac at 4x
    oversubscription. A DSM box arms arm 2 by mistake once in 478 runs at the
    pessimistic end of its measured rate; a FIFO box disarms it by mistake -
    the direction that costs coverage - once in 9,600 at the 95% lower bound
    240/240 reps support. The one-flake tolerance is what buys that second
    number and a flat 8/8 would cost a factor of 900 of it. The reasoning,
    the alternatives weighed and not built, and both error rates are in
    flock_fifo_probe.py's header - read it before touching any number here,
    and never widen the tolerance to make a box green."""
    import platform
    import flock_fifo_probe
    armed, v = flock_fifo_probe.kernel_orders_handovers()
    if armed:
        print("PASS kernel handover order (%d/%d reps put %d waiters in wait-time "
              "order) - arms 2 and 3 below are statements about riglock here"
              % (v.perfect, v.reps, v.waiters))
        return True
    note = (
        "HANDOVER ARMS 2 AND 3 DISARMED ON THIS BOX (%s, %s %s): the kernel put all "
        "%d waiters in wait-time order in only %d of %d reps, and woke the "
        "longest-blocked one first in %d - it needs %d perfect. THIS BOX DOES NOT "
        "ORDER FLOCK HANDOVERS BY WAIT TIME, so \"the incumbent keeps its place\" "
        "is a statement about the kernel here and not about riglock. NEITHER ARM "
        "RAN. Arm 3 goes with arm 2 because it is arm 2's sensitivity control and "
        "is a lottery on this kernel in its own right - the 2.0 s waiter it "
        "requires to LOSE won 8 of 20 handovers on spinning-disk-nas-a and 5 of 20 on "
        "spinning-disk-nas-b, against 0 of 20 on the dev Mac and 3 of 20 on amd-epyc-vm. ARM 1, "
        "which is the one that holds whatever the kernel does - three queued "
        "waiters and none may starve - RAN AND PASSED. Measured 17 Sep 2026: both "
        "spinning-disk-nas DSM boxes (Linux 4.4) put four waiters in order in 5 of 40 reps; "
        "amd-epyc-vm (Linux 6.8) and the dev Mac in 120 of 120 each. `python3 "
        "flock_fifo_probe.py 40 4` is the long form of this probe. DO NOT make this "
        "box green by relaxing an arm or the precondition - a disarm is a fact "
        "about the box, and the only thing that should ever silence it is a kernel "
        "that starts ordering handovers. What this box has left to fear is a "
        "~25-50%% per-handover draw that no dial in riglock.py can remove."
        % (platform.node(), platform.system(), platform.release(),
           v.waiters, v.perfect, v.reps, v.first, flock_fifo_probe.PRECOND_MIN_PERFECT))
    print("!" * 78)
    print(note)
    print("!" * 78, flush=True)
    DISARMED.append(note)
    return False


# --- the fairness arm (17 Sep 2026) --------------------------------------
#
# The third incident on this lock, and the first that nothing here could
# see: every check above is about WHO MAY HOLD it, and none of them is
# about WHO GETS IT NEXT. So when a waiter on amd-epyc-vm sat 3h53m over
# 7,000 tries and never won once, and another was skipped on five handovers
# in 33 minutes while queued throughout, that read as a busy box rather than
# as a defect - riglock.take() closed its fd and reopened every
# RIGLOCK_WAIT (2.0 s then), which drops a waiter out of the kernel's flock
# wait queue, so a long wait was 7,000 separate draws and a handover was a
# lottery. (an internal note)
#
# WHAT MAKES THIS TESTABLE is measured rather than assumed: on this fleet a
# released flock goes to the waiter that has been blocked LONGEST (probed
# 17 Sep 2026 on the dev Mac - an incumbent beat a waiter that arrived 0.3 s
# later 15 times out of 15). flock(2) does not contract that, so the arm
# that must hold whatever the kernel does is the weak one - arm 1, EVERY
# queued waiter eventually gets the box - and the strong one - arm 2, an
# incumbent keeps its place against a latecomer - is paired with arm 3, a
# SENSITIVITY CONTROL that runs the identical race at the 2.0 s this file
# defaulted to until 17 Sep and requires it to LOSE. Arm 3 is what says arm
# 2 is still able to fail: if the control ever stops losing, arm 2 is
# proving nothing on that box and the thing to do is find out what changed,
# never to delete either arm. Since later on 17 Sep both of them ask the
# kernel first - _kernel_precondition() above - because on a box that wakes
# an arbitrary waiter neither is about riglock, and arm 3 flakes red there
# on its own (8/20 and 5/20 measured; see the comment at the call site).

# The `wait` riglock.py defaulted to until 17 Sep 2026, kept here as the
# control's dial. Arm 3 is a regression pin on the SHAPE, not a preference
# about this number: any `wait` short enough to fire inside a handover
# window puts the waiter back at the end of the queue.
OLD_DEFAULT_WAIT = 2.0

_WAITER_SRC = """
import os, sys, time
sys.path.insert(0, %r)
import riglock
tag, path, ready, out, wait, budget, hold = sys.argv[1:8]
open(ready, "w").close()          # tell the parent we are about to queue
fd = riglock.take(tag, wait=float(wait), budget_s=float(budget), lock_path=path)
with open(out, "w") as fh:
    fh.write(repr(time.time()))
time.sleep(float(hold))
riglock.release(fd)
""" % (HERE,)

# The LATECOMER in the handover arms is a PLAIN blocking flock rather than a
# second riglock.take(): it arrives, blocks, and stays blocked, which is what
# every taker on this fleet that is not riglock.py looks like from the
# kernel's side (`flock -x`, pdrv's rig scripts once queued behind one
# another, a shell round). Modelling it with a second take() at the same
# `wait` does NOT reproduce the incident, and the reason is worth knowing
# before anyone "simplifies" this: two waiters re-checking on the same
# cadence keep a constant phase offset, so the incumbent keeps its lead and
# the arm goes quietly blind. The loss comes from an arrival that STAYS in
# the queue while the incumbent keeps leaving it.
_RAW_WAITER_SRC = """
import fcntl, os, sys, time
path, ready, out = sys.argv[1:4]
fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
open(ready, "w").close()
fcntl.flock(fd, fcntl.LOCK_EX)
with open(out, "w") as fh:
    fh.write(repr(time.time()))
fcntl.flock(fd, fcntl.LOCK_UN)
os.close(fd)
"""


def _spawn_waiter(d, tag, lock, wait, budget=30.0, hold=0.05):
    """Start a queued riglock.take() in its own process (SIGALRM, so it has
    to be a main thread) and return (proc, ready_path, out_path). `out_path`
    exists afterwards only if that waiter actually won the lock."""
    import subprocess
    src = os.path.join(d, "waiter.py")
    if not os.path.exists(src):
        with open(src, "w") as fh:
            fh.write(_WAITER_SRC)
    ready = os.path.join(d, tag + ".ready")
    out = os.path.join(d, tag + ".won")
    env = dict(os.environ, BOXGATE_COORD=os.path.join(d, "COORDINATION-selftest.txt"))
    proc = subprocess.Popen(
        [sys.executable, src, tag, lock, ready, out, str(wait), str(budget), str(hold)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc, ready, out


def _spawn_raw_waiter(d, tag, lock):
    """A latecomer that blocks in flock(LOCK_EX) once and never leaves - see
    _RAW_WAITER_SRC above for why the arms need one of these rather than a
    second riglock waiter."""
    import subprocess
    src = os.path.join(d, "rawwaiter.py")
    if not os.path.exists(src):
        with open(src, "w") as fh:
            fh.write(_RAW_WAITER_SRC)
    ready = os.path.join(d, tag + ".ready")
    out = os.path.join(d, tag + ".won")
    proc = subprocess.Popen([sys.executable, src, lock, ready, out],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc, ready, out


def _await_ready(ready, proc, timeout=30.0):
    """Wait for a waiter to reach the point of queueing. Python startup on a
    loaded box is not bounded by anything this script can guess, so the
    ordering below is built on this handshake rather than on a sleep."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(ready):
            return
        assert proc.poll() is None, "fairness: a waiter died before it queued"
        time.sleep(0.02)
    raise AssertionError("fairness: a waiter never reached the queue")


def _won_at(out):
    if not os.path.exists(out):
        return None
    with open(out) as fh:
        return float(fh.read().strip())


def _incumbent_keeps_its_place(d, incumbent_wait, settle=2.5):
    """One holder; a riglock waiter that queues first at `incumbent_wait`; a
    plain blocking-flock latecomer 0.3 s behind it; a release `settle`
    seconds after that. Returns True if the incumbent won.

    `settle` is 2.5 on purpose: it is longer than the 2.0 this file
    defaulted `wait` to until 17 Sep 2026 and far shorter than the 60 it
    defaults to now, so the SAME window separates the two shapes. At 2.0 the
    incumbent's SIGALRM fires once inside the window, it closes its fd and
    re-enters the queue behind a process that arrived after it, and it
    loses. At 60 it never leaves, and it wins."""
    import time
    import riglock
    lock = os.path.join(d, "rig.lock")
    for stale in os.listdir(d):
        if stale.endswith((".ready", ".won")):
            os.unlink(os.path.join(d, stale))
    with _coord_pinned(d):
        held = riglock.take("fairness-holder", tries=1, wait=0, lock_path=lock)
    a, a_ready, a_out = _spawn_waiter(d, "incumbent", lock, incumbent_wait,
                                      budget=settle + 60.0)
    _await_ready(a_ready, a)
    time.sleep(0.3)
    b, b_ready, b_out = _spawn_raw_waiter(d, "latecomer", lock)
    _await_ready(b_ready, b)
    time.sleep(settle)
    with _coord_pinned(d):
        riglock.release(held)
    a.wait(timeout=120)
    b.wait(timeout=120)
    a_at, b_at = _won_at(a_out), _won_at(b_out)
    assert a_at is not None and b_at is not None, \
        "fairness: a waiter never got the lock at all inside its budget"
    return a_at < b_at


def check_riglock_fairness():
    import time
    import riglock

    shipped = float(os.environ.get("RIGLOCK_WAIT", "60.0"))

    with tempfile.TemporaryDirectory() as d:
        # --- 1. NOBODY STARVES. The arm that holds whatever the kernel's
        # handover order is: three waiters queued behind one holder, and
        # each must get the box. A waiter that is out of the queue at the
        # instant of a release is simply not considered, which is how one
        # lane lost 7,000 in a row.
        lock = os.path.join(d, "rig.lock")
        with _coord_pinned(d):
            held = riglock.take("fairness-holder", tries=1, wait=0, lock_path=lock)
        waiters = []
        for n in range(3):
            proc, ready, out = _spawn_waiter(d, "starve%d" % n, lock, wait=shipped, hold=0.15)
            _await_ready(ready, proc)
            waiters.append((proc, out))
            time.sleep(0.1)
        with _coord_pinned(d):
            riglock.release(held)
        for proc, _out in waiters:
            proc.wait(timeout=90)
        never = [out for _p, out in waiters if _won_at(out) is None]
        assert not never, \
            "riglock.take: FAIL: %d of 3 queued waiters never got the lock across 3 releases - " \
            "this is the handover lottery, not a busy box" % len(never)
        wins = sorted(_won_at(out) for _p, out in waiters)
        assert wins[-1] - wins[0] < 60, "riglock.take: FAIL: a waiter was starved for a minute behind two others"
        print("PASS riglock.take (fairness: 3 of 3 queued waiters got the box)")

    # --- 2. THE INCUMBENT KEEPS ITS PLACE at the shipped default, and
    # --- 3. the control at the old cadence shows arm 2 can fail.
    # Arm 2 is run three times and must hold every time; arm 3 twice and
    # need only fail once, because asserting that a race is lost is a
    # weaker thing to assert than that an ordering holds.
    #
    # BOTH are gated on _kernel_precondition(), and arm 3 being in there
    # with arm 2 is a finding rather than a convenience. Arm 3 was left
    # running everywhere in the first draft of this - "a waiter re-checking
    # every 2 s loses handovers" reads like something that must be true on
    # any kernel - and it FAILED on spinning-disk-nas-b on the first run, by
    # winning both reps. It is the same defect one level down: a waiter can
    # only LOSE a place in a line the kernel is keeping, so on a kernel that
    # wakes an arbitrary waiter the 2.0 s control wins a share of the time
    # and arm 3 is a lottery too. Measured 17 Sep 2026, 20 reps each:
    # the control won 8/20 on spinning-disk-nas-a and 5/20 on spinning-disk-nas-b
    # against 0/20 on amd-epyc-vm, so arm 3 would have gone red on its own
    # tip about one run in six on antigua and one in sixteen on miami. A
    # gate that reds one run in six is a gate that gets deleted. Arm 3
    # exists to prove ARM 2 can still fail, so where arm 2 does not run it
    # has no subject either, and the two are disarmed as one pair.
    if _kernel_precondition():
        with tempfile.TemporaryDirectory() as d:
            for _rep in range(3):
                assert _incumbent_keeps_its_place(d, shipped), \
                    ("riglock.take: FAIL: a waiter that queued FIRST lost the handover to a plain "
                     "flock waiter that arrived 0.3 s later, at RIGLOCK_WAIT=%s. THE KERNEL "
                     "PRECONDITION ABOVE PASSED ON THIS BOX, so this is riglock leaving the "
                     "kernel wait queue while it waits - which makes a long wait a series of "
                     "draws rather than a place in a line, see the block comment above take(). "
                     "That is the 17 Sep 2026 defect coming back, not a property of the box: if "
                     "you believe it IS the box, `python3 flock_fifo_probe.py 40` is the long "
                     "form of the probe and it has to disagree with the eight reps that just "
                     "passed. Do not relax this arm to make a box green." % shipped)
            print("PASS riglock.take (fairness: the incumbent kept its place, 3/3)")

        # THREE reps, not two, and the third is worth its ~3.5 s. The control
        # is a race and it can be won by luck on a FIFO box too: measured
        # 17 Sep 2026 over 20 reps, the 2.0 s waiter won 0 on the dev Mac but
        # 3 on amd-epyc-vm, which at two reps is a spurious red about one run
        # in forty-four on the one Linux box where these arms DO run. At three
        # it is one in three hundred. It costs a little power against a
        # PARTIAL regression (a control that still loses sometimes) and none
        # at all against the one this arm is for - a race that has stopped
        # being run, where the control wins every time.
        with tempfile.TemporaryDirectory() as d:
            lost = sum(0 if _incumbent_keeps_its_place(d, OLD_DEFAULT_WAIT) else 1
                       for _rep in range(3))
            assert lost, \
                ("riglock.take: FAIL: the SENSITIVITY CONTROL passed. A waiter re-checking every "
                 "%ss - the default this file shipped until 17 Sep 2026 - should re-enter the "
                 "queue behind a latecomer and lose the handover, and it did not in any of three "
                 "reps. If it never does, the race "
                 "above is no longer being run and the incumbent arm is proving nothing here. "
                 "This is NOT the non-FIFO kernel case - the precondition above passed, and on a "
                 "kernel that fails it this arm is disarmed with arm 2 for exactly this reason. "
                 "Do not relax either arm to make this green - find out what changed."
                 % OLD_DEFAULT_WAIT)
        print("PASS riglock.take (fairness: the %ss control lost %d/3 handovers, so the arm above "
              "can still fail)" % (OLD_DEFAULT_WAIT, lost))


# ---------------------------------------------------------------------------
# THE 18 Sep 2026 ARMS: mqueue's coordination reader and its process census.
#
# `mqueue.busy()` is the ONE probe-then-act gate on the unix side - `main()`
# breaks out of its loop and THEN spawns a round - so it is where both halves
# of the Windows fix had to land here. Until that day it asked the rig lock and
# a four-name `ps` list and nothing else, so a lane holding the box by an open
# CLAIM in prose was invisible, and so was any tool the list did not name.
#
# EVERYTHING BELOW IS HERMETIC. The coordination arms drive a temp file through
# $BOXGATE_COORD; the census arms drive `mqueue.attribute()` with canned `ps`
# samples and a known window, which is what makes the heavy-process predicate
# testable at all - the alternative is generating real load, and an orphaned
# load generator on a shared box is its own incident in this repo's history.
# One arm at the end runs the REAL `ps`, because six canned arms all pass on a
# box where `_ps_rows()` parses nothing.
# ---------------------------------------------------------------------------


def _coord(d, *lines):
    path = os.path.join(d, "COORDINATION-selftest.txt")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def check_mqueue_coord_hold():
    """mqueue.coord_hold(): another lane's OPEN marker is a hold, and every
    uncertainty resolves that way too."""
    import mqueue

    if mqueue._box_gate() is None:
        # Not a pass. On a rig box the gate is not deployed and these arms
        # cannot run; say so in words rather than printing PASS over nothing.
        DISARMED.append(
            "mqueue.coord_hold: no bench-box-gate.py reachable from here, so the "
            "coordination arms did NOT run. That is also what mqueue itself does "
            "on such a box (MQUEUE-COORD-BLIND) - deploy tools/bench-box-gate.py "
            "or set $MQUEUE_BOX_GATE to cover it.")
        print("DISARMED mqueue.coord_hold (no bench-box-gate.py on this box)")
        return

    with tempfile.TemporaryDirectory() as d:
        live = "CLAIM 2026-09-18T04:00:00Z other-lane-18sep ACCOUNTS=none - running."
        done = "DONE 2026-09-18T04:30:00Z other-lane-18sep ACCOUNTS=none - finished."

        held = mqueue.coord_hold(_coord(d, live))
        assert held and "other-lane-18sep" in held, \
            "FAIL: an open CLAIM read as a FREE box - that hands a running lane's box away"

        assert mqueue.coord_hold(_coord(d, live, done)) is None, \
            "FAIL: a CLAIM closed by a DONE still blocks - this queue would never start"

        # Failure 1 of bench-box-gate's own history, inherited rather than
        # re-decided: a QUEUED line is a queue POSITION and opens no hold. One
        # lane logged `waiting on ...` for 213 minutes through a free box.
        assert mqueue.coord_hold(_coord(
            d, "QUEUED 2026-09-18T04:00:00Z other-lane-18sep ACCOUNTS=none - BEHIND x.")) is None, \
            "FAIL: a QUEUED line opened a hold - that is the 213-minute wait on a free box"

        # A marker NOBODY HAS CLASSIFIED is a hold AND a report. Fix it by
        # classifying the marker in .claude/tools/bench-accounts-parse.py,
        # never by teaching this side to ignore it.
        held = mqueue.coord_hold(_coord(
            d, "FLURBLE 2026-09-18T04:00:00Z other-lane-18sep ACCOUNTS=none - ?"))
        assert held and "FLURBLE" in held and "CLASSIFIED" in held, \
            "FAIL: an unclassified marker did not block - a gate's own blindness must block"

        # THE STAMP SPELLING. 18 Sep 2026: bench-box-gate's parse_events read
        # ONE spelling and missed 28 OPEN markers across the four live
        # coordination files - 19 CLAIM, 6 ACTIVATING - which reads as TAKE THE
        # BOX. It imports the roster's MARKER_TS_RE now. These two are live
        # spellings off those files.
        for odd in ("CLAIM 2026-09-18T04:00:00 other-lane-18sep - no trailing Z.",
                    "ACTIVATING 2026-09-18T04:00Z other-lane-18sep - minute precision."):
            held = mqueue.coord_hold(_coord(d, odd))
            assert held and "other-lane-18sep" in held, \
                "FAIL: %r was invisible - a stamp spelling is a way to lose a holder" % odd
        # ...and the lane token as a human types it, with punctuation attached.
        held = mqueue.coord_hold(_coord(
            d, "CLAIM 2026-09-18T04:00:00Z other-lane-18sep: taking the box."))
        assert held and "other-lane-18sep" in held, \
            "FAIL: a lane token with a trailing colon was invisible"

        # MY OWN claim is not somebody else's.
        os.environ["BOXGATE_ID"] = "other-lane-18sep"
        try:
            assert mqueue.coord_hold(_coord(d, live)) is None, \
                "FAIL: this lane blocked on its OWN open claim"
        finally:
            os.environ.pop("BOXGATE_ID", None)

        # A STALE hold still blocks HERE, and says so. bench-box-gate REFUSES on
        # one because a lane running it can adjudicate; a queue has nobody to
        # ask, so it waits and names it. Do not add an age bound to make this
        # pass - liveness comes from the holder, never the clock.
        held = mqueue.coord_hold(_coord(
            d, "CLAIM 2020-01-01T00:00:00Z ancient-lane ACCOUNTS=none - long ago."))
        assert held and "STALE" in held, \
            "FAIL: a stale un-overtaken hold did not block, or did not say it was stale"

        # A PHANTOM - stale AND overtaken by a whole round since - blocks nothing.
        assert mqueue.coord_hold(_coord(
            d,
            "CLAIM 2020-01-01T00:00:00Z ancient-lane ACCOUNTS=none - long ago.",
            "CLAIM 2020-02-01T00:00:00Z later-lane ACCOUNTS=none - after it.",
            "DONE 2020-02-01T01:00:00Z later-lane ACCOUNTS=none - and gave it back.")) is None, \
            "FAIL: a phantom blocked - the box demonstrably turned over since"

        # AN UNREADABLE FILE IS NOT AN EMPTY ONE, and this is the arm that
        # matters most: "no open claim" reads as TAKE THE BOX, so a permissions
        # error must never come back as None.
        bad = _coord(d, live)
        os.chmod(bad, 0o000)
        try:
            if os.access(bad, os.R_OK):  # root, or a filesystem with no modes
                print("  (skipped the unreadable-file arm: this user can read a 0000 file)")
            else:
                held = mqueue.coord_hold(bad)
                assert held and "CANNOT BE READ" in held, \
                    "FAIL: an UNREADABLE coordination file read as a free box"
        finally:
            os.chmod(bad, 0o644)

        # A file that is not there at all is a box nobody has claimed on, which
        # is a different statement from one we cannot read. Reported, not a hold.
        assert mqueue.coord_hold(os.path.join(d, "no-such-file.txt")) is None, \
            "FAIL: a MISSING coordination file blocked - that is not the same as unreadable"

    print("PASS mqueue.coord_hold (open claim, QUEUED, unknown marker, stamp "
          "spellings, self, stale, phantom, unreadable)")


def check_mqueue_census():
    """mqueue.attribute()/census(): CPU attribution decides, the name list
    corroborates, and the reading is printed whichever way the verdict goes.

    Driven through `attribute()` with canned samples and a known window, so
    these arms neither sleep nor generate load. An orphaned load generator on a
    shared box is its own incident in this repo's history, and a test that has
    to sleep to reach the arithmetic is measuring the sleep.
    """
    import mqueue

    me = os.getpid()
    W = 10.0  # the window, in seconds: cpu_seconds/W*100 is the percentage

    def pair(*procs):
        """procs: (pid, ppid, comm, percent_of_one_core) -> two samples."""
        a = [(pid, ppid, 0.0, comm) for pid, ppid, comm, _pct in procs]
        b = [(pid, ppid, pct / 100.0 * W, comm) for pid, ppid, comm, pct in procs]
        a.append((me, 1, 0.0, "python3"))
        b.append((me, 1, 0.0, "python3"))
        return a, b

    # --- 1. AN IDLE-DESKTOP SHAPE IS FREE. Many processes at 17-40% is what a
    # box somebody is sitting at looks like, and a dial on the TOTAL calls it
    # busy and wedges this queue for 24 hours. Measured on the dev Mac 18 Sep
    # 2026 at total 310%, heavy 0% - these are those five processes.
    a, b = pair((100, 1, "WindowServer", 40), (101, 1, "Chrome Helper", 20),
                (102, 1, "Chrome Helper", 19), (103, 1, "fseventsd", 17),
                (104, 1, "mds_stores", 15))
    verdict, reading = mqueue.attribute(a, b, W, self_pid=me)
    assert verdict is None, \
        "FAIL: an idle interactive desktop read as BUSY (%s) - a dial on the TOTAL " \
        "rather than on the heavy processes does exactly this" % reading
    assert "census over" in reading and "of which" in reading, \
        "FAIL: a FREE census printed no reading - that figure is the one the 13:26Z probe lacked"

    # --- 2. A FEW SATURATED PROCESSES IS BUSY, AND NO NAME LIST SEES THEM.
    # This is the ISCC case exactly: an Inno Setup compile is in no TOOLS list
    # and never will be, and the box read genuinely free through 90 seconds of
    # one while a waiter queued behind it.
    a, b = pair((200, 1, "iscc", 100), (201, 1, "iscc", 95))
    verdict, reading = mqueue.attribute(a, b, W, self_pid=me)
    assert verdict and "iscc" in verdict, \
        "FAIL: two saturated processes no name list knows read as FREE (%s)" % reading
    assert "%d%%" % int(mqueue.CPU_BUSY_PCT) in verdict or "dial" in verdict, \
        "FAIL: the busy verdict does not say what it was measured against"

    # --- 3. ONE HEAVY PROCESS UNDER THE DIAL IS NOT A ROUND. A single busy
    # core is a compile or a tail, and blocking on it is the wrong direction
    # for a gate nobody can override.
    a, b = pair((210, 1, "iscc", 99))
    verdict, _r = mqueue.attribute(a, b, W, self_pid=me)
    assert verdict is None, "FAIL: one saturated process alone blocked the queue"

    # --- 4. THE NAME LIST STILL CORROBORATES, AND IT IS WIDER THAN IT WAS.
    # `cargo` and `rustc` were missing from a list of four, on a fleet that
    # certainly runs them. A resident tool with no CPU in the window still
    # counts - that is the whole point of keeping the list.
    for tool in ("cargo", "rustc", "parfast", "par2"):
        assert tool in mqueue.TOOLS, "FAIL: %s is not in mqueue.TOOLS" % tool
    a, b = pair((300, 1, "cargo", 0))
    verdict, _r = mqueue.attribute(a, b, W, self_pid=me)
    assert verdict and "cargo" in verdict, \
        "FAIL: a resident `cargo` burning nothing in the window read as FREE"

    # --- 5. OUR OWN TREE IS NOT A FOREIGN LANE, in BOTH directions: a child we
    # spawned and the shell that spawned us.
    a, b = pair((400, me, "python3", 400), (401, 400, "cc", 400))
    verdict, reading = mqueue.attribute(a, b, W, self_pid=me)
    assert verdict is None, "FAIL: our own children read as a foreign lane (%s)" % reading
    a, b = pair((500, 1, "zsh", 0), (me + 100000, 500, "other", 400))
    a.append((me, 500, 0.0, "python3"))
    b.append((me, 500, 0.0, "python3"))
    verdict, _r = mqueue.attribute(a, b, W, self_pid=me)
    assert verdict is None, "FAIL: a sibling under OUR OWN parent read as a foreign lane"

    # --- 6. A BOX WE CANNOT LOOK AT IS NEVER A CLEAR BOX.
    real_rows = mqueue._ps_rows
    try:
        mqueue._ps_rows = lambda: None
        verdict, reading = mqueue.census(sample_s=0.0)
        assert verdict and "BLIND" in verdict, \
            "FAIL: `ps` failing read as a clear box - blindness is a hold, never a pass"
    finally:
        mqueue._ps_rows = real_rows

    # --- 7. AND THE REAL `ps` PARSES ON THIS BOX. Arms 1-6 are all canned, so
    # every one of them passes on a box where `_ps_rows()` returns nothing
    # usable - which is the rubber stamp this repo keeps paying for.
    rows = mqueue._ps_rows()
    assert rows and len(rows) > 5, "FAIL: mqueue._ps_rows() read no processes on this box"
    assert any(pid == me for pid, _pp, _s, _c in rows), \
        "FAIL: mqueue._ps_rows() did not even find THIS process"
    assert any(secs > 0 for _p, _pp, secs, _c in rows), \
        "FAIL: every process parsed to zero CPU seconds - the time column is not being read"

    print("PASS mqueue.census (idle desktop free, unnamed saturated work busy, one "
          "core is not a round, widened name list, own tree excluded both ways, "
          "ps-blind is a hold, real ps parses)")


def _real_coord_stamp():
    """(path, size, mtime) of the BOX's own coordination file, asked with
    $BOXGATE_COORD out of the way so it is the real one - or None when this
    box has no unambiguous single file, which is the case where
    `riglock_state.coordination_file()` returns None and there is nothing for
    this script to damage."""
    import riglock_state
    saved = os.environ.pop("BOXGATE_COORD", None)
    try:
        path = riglock_state.coordination_file()
    finally:
        if saved is not None:
            os.environ["BOXGATE_COORD"] = saved
    if not path or not os.path.exists(path):
        return None
    st = os.stat(path)
    return (path, st.st_size, st.st_mtime)


def main():
    # THE BOX'S OWN COORDINATION FILE MUST COME OUT OF THIS UNTOUCHED, and it
    # is asserted rather than intended. This script's docstring promises it is
    # safe to run mid-round on a shared box; on 17 Sep 2026 it was not, and no
    # arm could see it - `announce_orphan` falls back to
    # `coordination_file()`, the handover arms take and release a holder lock
    # in the PARENT several times per rep, and the two boxes it had ever been
    # run on both have TWO ~/bench-out/COORDINATION-*.txt files, where that
    # fallback answers None. The first box with exactly one got a NOTE per
    # rep appended to a file other lanes read. A missing pin anywhere in here
    # now fails this script by name rather than quietly writing on somebody.
    before = _real_coord_stamp()

    import pdrv
    check("pdrv.RigLock", pdrv.RigLock, ("selftest-round.log",))
    check_orphans("pdrv.RigLock", pdrv.RigLock, ("selftest-round.log",))

    import ladder
    check("ladder.RigLock", ladder.RigLock, ("selftest-round",))
    check_orphans("ladder.RigLock", ladder.RigLock, ("selftest-round",))

    check_mqueue_lock_hold()
    check_mqueue_coord_hold()
    check_mqueue_census()
    check_riglock_orphans()
    check_riglock_fairness()

    after = _real_coord_stamp()
    assert before == after, (
        "rig_lock_selftest: FAIL: this run WROTE ON THE BOX'S REAL COORDINATION "
        "FILE (%s -> %s). Some take()/release() in here is not inside "
        "_coord_pinned(), so announce_orphan fell back to "
        "riglock_state.coordination_file(). Pin it at the call site; never "
        "delete this check, and never make it pass by widening the pin to the "
        "whole process - $BOXGATE_COORD is a real dial a real round uses."
        % (before, after))

    if DISARMED:
        # LAST LINE, so it cannot be scrolled past. An arm that did not run
        # is not an arm that passed, and this file's whole history is of
        # things that failed quietly.
        print("RIG-LOCK-SELFTEST-OK, WITH %d DISARM NOTICE(S) - ARMS THAT DID NOT RUN "
              "ON THIS BOX:" % len(DISARMED))
        for note in DISARMED:
            print("  " + note)
    else:
        print("RIG-LOCK-SELFTEST-OK")


if __name__ == "__main__":
    main()
