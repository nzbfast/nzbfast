#!/usr/bin/env python3
"""bare_waiter_selftest.py - acceptance for routing memround.py and spillnas.py
through riglock.take() (17 Sep 2026).

Runs the REAL scripts as child processes, not a stand-in for them - the same
method the 16 Sep anonymous-taker fix was accepted by.  $HOME is pinned at a
temp dir for the duration, so `~/.parfast-rig.lock` is a temp file and this
never touches the box's real rig lock; $BOXGATE_COORD is pinned too, so the
orphan NOTE lands in the temp dir and never on a shared box's coordination
file.  Each script is given just enough env to REACH its lock block and is
expected to die immediately after it on the missing fixture - what is asserted
is the lock state and the log, never an exit code.

    python3 bare_waiter_selftest.py [/path/to/an internal note]

Five arms per script:
  1 absent      - takes it and NAMES itself (round=<tag> pid=<child>)
  2 zero bytes  - an ORDINARY HAND-OVER: taken, and SILENTLY (see below)
  3 dead pid    - the ordinary crash: cleared and taken
  4 live pid, no flock - the `set -o noclobber` shell taker: REFUSED, and its
                  identity line left byte-for-byte intact.  NEW behaviour: the
                  bare flock appended underneath it.
  5 ORPHANED INODE - the wedge this change exists for.  A live holder keeps an
                  flock on an inode whose path has been unlinked; a bare
                  flock waiter blocks on it forever with nothing to wake it.
                  The re-check must escape inside `wait` and take the path.
"""
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

HARNESS = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
FAIL = []


def run(script, env_extra, timeout=90):
    env = dict(os.environ)
    env.update(env_extra)
    p = subprocess.Popen([sys.executable, os.path.join(HARNESS, script)],
                         env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True)
    try:
        out = p.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        p.kill()
        out = (p.communicate()[0] or "") + "\n<<TIMED OUT>>"
    return p.pid, out


def base_env(home, scratch):
    return {"HOME": home, "SCRATCH": scratch,
            "BOXGATE_COORD": os.path.join(home, "COORDINATION-selftest.txt"),
            "BIN_BASE": "/bin/true", "BIN_MAIN": "/bin/true",
            "BIN_BRANCH": "/bin/true", "UNCACHE": "/bin/true"}


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAIL.append(msg)


def lockfile(home):
    p = os.path.join(home, ".parfast-rig.lock")
    try:
        with open(p) as fh:
            return fh.read()
    except OSError:
        return None


def dead_pid():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def arms(script, tag):
    print("== %s" % script)
    with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as scratch:
        env = base_env(home, scratch)
        lp = os.path.join(home, ".parfast-rig.lock")

        # --- 1. absent
        pid, out = run(script, env)
        check("waiting for the rig lock" in out, "1 absent: logged the wait")
        text = lockfile(home) or ""
        check(("round=%s" % tag) in text, "1 absent: identity line names round=%s (%r)" % (tag, text.strip()))
        m = re.search(r"pid=(\d+)", text)
        check(m is not None and int(m.group(1)) == pid,
              "1 absent: identity line names the CHILD's pid")
        check("rig lock TAKEN" in out, "1 absent: announced the take")

        # --- 2. zero bytes
        #
        # RETIGHTENED 20 Sep 2026, the same day and for the same reason as
        # `rig_lock_selftest.py`'s arm 1 (`5402734b4`): this arm is not an
        # orphan at all. `riglock.py`'s `release()` TRUNCATES rather than
        # unlinks, so a zero-byte lock is that function's own spelling for
        # "released", and `lock_state()` could not tell it apart from the
        # crash-before-write case until it grew a distinct "released" state.
        # Every ordinary hand-over on apple-m3-ultra therefore announced a false
        # RIG-LOCK-ORPHAN and posted a coordination NOTE that two lanes read
        # as a double-booking that never happened.
        #
        # That commit fixed `rig_lock_selftest.py` and the windows one and
        # MISSED this script, which is the gate's OTHER subject - so the two
        # halves of `tools/riglock-selftest-gate.py` disagreed and the job
        # went red. Both directions stay pinned: silence here, and arm 3's
        # dead pid below is a GENUINE orphan that must still announce.
        open(lp, "w").close()
        pid, out = run(script, env)
        check("pid=%d" % pid in (lockfile(home) or ""), "2 zero bytes: handed over")
        check("RIG-LOCK-ORPHAN" not in out,
              "2 zero bytes: a released lock is an ordinary hand-over, announced NOTHING")
        coord = env["BOXGATE_COORD"]
        check(not os.path.exists(coord) or "ORPHAN" not in open(coord).read(),
              "2 zero bytes: wrote NO coordination NOTE")

        # --- 3. dead pid
        with open(lp, "w") as fh:
            fh.write("round=ghost pid=%d started=2026-09-16T02:17:45Z\n" % dead_pid())
        pid, out = run(script, env)
        check("pid=%d" % pid in (lockfile(home) or ""), "3 dead pid: handed over")

        # --- 4. LIVE pid, no flock - must be refused, line untouched
        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        try:
            held = "round=live-shell-round pid=%d started=%s\n" % (
                sleeper.pid, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            with open(lp, "w") as fh:
                fh.write(held)
            e4 = dict(env, RIGLOCK_BUDGET_S="4", RIGLOCK_WAIT="1")
            pid, out = run(script, e4, timeout=60)
            check("live non-flock taker" in out, "4 live holder: refused it by name")
            check("never got the rig lock" in out, "4 live holder: gave up rather than taking it")
            check(lockfile(home) == held, "4 live holder: left its identity line byte-for-byte")
        finally:
            sleeper.kill()          # BY PID, our own child only
            sleeper.wait()

        # --- 5. ORPHANED INODE, THE WEDGE THIS CHANGE EXISTS FOR, and the
        # ORDER is the whole arm: the waiter must ALREADY BE BLOCKED on the
        # inode when it is unlinked.  Unlinking first is a different and much
        # easier test - the path is then absent, O_CREAT makes a fresh inode
        # and any taker wins instantly - and it is what this arm did in its
        # first draft, passing in 0.1 s while proving nothing.
        #
        # A PLAIN `fcntl.flock(fd, LOCK_EX)` WAITER IS RUN ALONGSIDE AS THE
        # SENSITIVITY CONTROL - the exact shape these two files had until
        # today.  It must STILL BE BLOCKED after the patched script has won,
        # or this arm is not reproducing the wedge and proves nothing either.
        os.unlink(lp)
        holder_src = (
            "import fcntl, os, sys, time\n"
            "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o644)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "os.write(fd, b'round=wedger pid=%d started=2026-09-17T00:00:00Z\\n' % os.getpid())\n"
            "open(sys.argv[2], 'w').close()\n"
            "time.sleep(600)\n")
        bare_src = (
            "import fcntl, os, sys, time\n"
            "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o644)\n"
            "open(sys.argv[2], 'w').close()\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "open(sys.argv[3], 'w').close()\n"
            "time.sleep(600)\n")
        hsrc = os.path.join(scratch, "wedger.py")
        bsrc = os.path.join(scratch, "bare.py")
        with open(hsrc, "w") as fh:
            fh.write(holder_src)
        with open(bsrc, "w") as fh:
            fh.write(bare_src)
        ready = os.path.join(scratch, "wedger.ready")
        bready = os.path.join(scratch, "bare.ready")
        bwon = os.path.join(scratch, "bare.won")
        wedger = subprocess.Popen([sys.executable, hsrc, lp, ready])
        bare = None
        patched = None
        try:
            end_t = time.time() + 30
            while not os.path.exists(ready) and time.time() < end_t:
                time.sleep(0.02)
            check(os.path.exists(ready), "5 setup: the wedger took the flock")
            ino_before = os.stat(lp).st_ino

            # both waiters queue on the LIVE inode, before anything is unlinked
            bare = subprocess.Popen([sys.executable, bsrc, lp, bready, bwon])
            end_t = time.time() + 30
            while not os.path.exists(bready) and time.time() < end_t:
                time.sleep(0.02)
            check(os.path.exists(bready), "5 setup: the bare-flock control queued")
            e5 = dict(env, RIGLOCK_WAIT="5", RIGLOCK_BUDGET_S="90")
            penv = dict(os.environ)
            penv.update(e5)
            patched = subprocess.Popen(
                [sys.executable, os.path.join(HARNESS, script)], env=penv,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(2.0)         # both are blocked on inode X by now
            check(patched.poll() is None, "5 setup: the patched waiter is queued, not finished")

            os.unlink(lp)           # the releaser that unlinks without closing
            t0 = time.time()
            try:
                out = patched.communicate(timeout=90)[0]
            except subprocess.TimeoutExpired:
                patched.kill()
                out = (patched.communicate()[0] or "") + "\n<<TIMED OUT>>"
            dt = time.time() - t0
            check("<<TIMED OUT>>" not in out, "5 orphaned inode: the patched waiter did NOT wedge")
            check("pid=%d" % patched.pid in (lockfile(home) or ""),
                  "5 orphaned inode: it took the live path (%.1f s after the unlink)" % dt)
            check(os.path.exists(lp) and os.stat(lp).st_ino != ino_before,
                  "5 orphaned inode: on a NEW inode, not the dead one")
            check(bare.poll() is None and not os.path.exists(bwon),
                  "5 CONTROL: the bare-flock waiter is STILL blocked on the dead "
                  "inode - the wedge is real and this arm reproduces it")
        finally:
            for proc in (wedger, bare, patched):
                if proc is not None and proc.poll() is None:
                    proc.kill()     # BY PID, our own children only
                    proc.wait()


        # --- 6. THE INFINITE BUDGET. With no RIGLOCK_* dial set this must
        # queue indefinitely, the way the bare flock did: take()'s own default
        # gives up after 100 minutes and exits "never got the rig lock", and
        # these rounds are launched unattended behind queues that have run past
        # three hours, so that default would turn a long wait into a round that
        # never ran. Asserted by leaving it queued behind a live flock holder
        # and checking it is still there - a finite budget cannot be waited out
        # in a selftest, but a CRASH on float("inf") arithmetic would show here
        # instantly, and that is the other thing this arm is for.
        holder2 = subprocess.Popen([sys.executable, "-c",
                                    "import fcntl, os, sys, time\n"
                                    "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o644)\n"
                                    "fcntl.flock(fd, fcntl.LOCK_EX)\n"
                                    "time.sleep(600)\n", lp])
        queued = None
        try:
            time.sleep(1.0)
            penv = dict(os.environ)
            penv.update(env)
            for dial in ("RIGLOCK_TRIES", "RIGLOCK_BUDGET_S", "RIGLOCK_WAIT"):
                penv.pop(dial, None)
            queued = subprocess.Popen(
                [sys.executable, os.path.join(HARNESS, script)], env=penv,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(8.0)
            check(queued.poll() is None,
                  "6 infinite budget: still queued with no dial set (rc=%s)" % queued.poll())
        finally:
            for proc in (queued, holder2):
                if proc is not None and proc.poll() is None:
                    proc.kill()     # BY PID, our own children only
                    proc.wait()


arms("memround.py", "memround")
arms("spillnas.py", "spillnas")
print("FAILURES: %d" % len(FAIL))
for f in FAIL:
    print("  " + f)
sys.exit(1 if FAIL else 0)
