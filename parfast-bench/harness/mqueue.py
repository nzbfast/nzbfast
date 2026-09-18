#!/usr/bin/env python3
"""Sequential round runner for the Mac rigs.

Waits on the per-box rig lock AND on any of our tool binaries being up - a lock
only excludes rounds that agreed to take it, and on 11 Sep 2026 a round that
took none at all let a second round start a 23 GiB create beside a running
repair. Then runs each round in turn, one at a time, each to its own log.

It waits on the LOCK, never on a marker line in another round's log: a log
renamed when it is banked silently disarms every round waiting on it.

And it waits on the lock's HOLDER, never on the lock file's existence - see
lock_hold() below and riglock_state.py, which is the one place this fleet
decides what "held" means.
"""
import os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pdrv
import riglock_state

LOCK = os.path.expanduser("~/.parfast-rig.lock")
TOOLS = ("parfast", "par2turbo", "par2j", "par2")


def lock_hold(path=LOCK, announce=True):
    """The lock half of busy(): a string when the lock is really held, else None.

    This WAS `if os.path.exists(LOCK): return "lock " + LOCK` - existence as
    the hold - and on 16 Sep 2026 that held apple-m3-ultra for eight hours against a
    zero-byte file eight hours cold with no holder anywhere on the box, which
    two lanes each had to disprove by hand. Existence is not a hold; a live
    holder is. riglock_state answers that off the holder's pid and never off
    the file's age, because a legitimate round can own this box for hours and
    any age bound that clears the orphan would steal from one of those.

    It never UNLINKS the orphan. This process does not take the lock - the
    round it launches does, through pdrv.RigLock, which clears the file it
    proved dead while holding the flock on it. Deleting from here would be a
    second, unlocked deleter of a file we never held, which is the shape of
    the 15 Sep double-holder incident. Announcing is ours; removing is the
    taker's.
    """
    state, who = riglock_state.lock_state(path)
    if state == "held":
        return "lock %s held by: %s" % (path, who)
    if state == "orphan" and announce:
        riglock_state.announce_orphan(path, who, "ignored by mqueue (not removed - the round clears it)")
    return None


def busy():
    held = lock_hold()
    if held:
        return held
    out = subprocess.run(["ps", "-Ao", "pid=,comm="], capture_output=True, text=True).stdout
    for line in out.splitlines():
        f = line.split(None, 1)
        if len(f) < 2:
            continue
        if os.path.basename(f[1].strip()) in TOOLS:
            return "tool %s pid=%s" % (os.path.basename(f[1].strip()), f[0])
    return None


def main():
    rounds = sys.argv[1:]
    print("MQUEUE-START %s rounds=%s" % (pdrv.utcnow(), ",".join(rounds)), flush=True)
    waited = 0
    while True:
        held = busy()
        if not held:
            break
        if waited % 600 == 0:
            print("MQUEUE-WAIT held by %s (%dm)" % (held, waited // 60), flush=True)
        time.sleep(60)
        waited += 60
        if waited > 86400:
            print("MQUEUE-TIMEOUT %s still held after 24h" % held, flush=True)
            return 19
    # RESOLVE EVERY NAME BEFORE RUNNING ANYTHING, and FAIL if one does not
    # resolve. This check used to sit inside the loop, printing MQUEUE-MISSING,
    # continuing, and returning 0 - so a queue whose rounds were all misnamed
    # produced START / MISSING / DONE and exited zero, which reads exactly like
    # a queue that finished its work. That is the same shape that cost the
    # Windows queue a night when `-rounds a,b` bound one element named "a,b",
    # and it happened again on 11 Sep 2026 when a round was launched as
    # `mred.py` and the queue looked for `mred.py.py`.
    #
    # Up front rather than in the loop, because a typo in the THIRD round is
    # otherwise discovered after the first two have run for six hours, at which
    # point the box is free and nobody is watching.
    missing = [r for r in rounds if not os.path.exists(os.path.join(HERE, r + ".py"))]
    if missing:
        for r in missing:
            print("MQUEUE-MISSING %s" % os.path.join(HERE, r + ".py"), flush=True)
        print("MQUEUE-FAIL %d of %d round name(s) do not resolve: %s - NOTHING RAN"
              % (len(missing), len(rounds), ",".join(missing)), flush=True)
        print("MQUEUE-HINT rounds are named WITHOUT the .py suffix: `detach.py mred`, not `detach.py mred.py`",
              flush=True)
        return 21
    for r in rounds:
        script = os.path.join(HERE, r + ".py")
        log = os.path.join(HERE, r + ".log")
        print("MQUEUE-BEGIN %s %s" % (r, pdrv.utcnow()), flush=True)
        with open(log, "w") as fh:
            rc = subprocess.call([sys.executable, script], stdout=fh, stderr=subprocess.STDOUT)
        print("MQUEUE-END %s rc=%d %s" % (r, rc, pdrv.utcnow()), flush=True)
    print("MQUEUE-DONE %s" % pdrv.utcnow(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
