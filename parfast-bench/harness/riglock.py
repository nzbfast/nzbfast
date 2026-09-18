#!/usr/bin/env python3
"""riglock.py - take ~/.parfast-rig.lock, run a command under it, release it
WITHOUT unlinking.

Three things here are earned rather than obvious, from 15-16 Sep 2026 on
this fleet:

  - The inode re-check LOOPS. A `flock` can be won on an inode the path no
    longer resolves to, because a lane that releases by unlinking leaves
    every blocking waiter holding a lock on an orphan. A one-shot check then
    drops the waiter out of the queue silently, at exactly the handover. So:
    open, try the lock, compare the fd's inode against the path's, and on a
    mismatch close and go round again.
  - The release TRUNCATES and closes, and never unlinks. Unlinking is what
    let two rounds hold this lock at once on 15 Sep.
  - Winning the flock is not the same as the box being free. A shell round
    can take this same path with `set -o noclobber`, which is an exclusive
    CREATE and has no flock to lose - `harness/nttwork.py`, going
    through the same flock-only shape this file used to have, won the flock
    over exactly such a holder at 10:27:42Z on 16 Sep 2026 and clobbered its
    identity line mid-round. So before truncating anything this now asks
    `riglock_state.lock_state()` whether the identity already in the file
    names somebody still alive - the ONE rule
    `harness/riglock_state.py` documents, imported rather than
    re-derived, the same way `pdrv.RigLock.take()` uses it. A file that
    names nobody (zero bytes, no parseable pid, a dead pid) is cleared and
    announced; there is no age bound in that verdict and none may be added.

    python3 riglock.py <round-tag> -- <command> [args...]

Here rather than re-derived per runner because it HAS been re-derived per
runner, differently each time, and the weakest spellings are the ones that
cost rounds: `mqueue.py` above treats the file EXISTING as busy, which
cannot tell a live holder from a crashed one; several round runners poll
`flock -n`, which the 15 Sep queue measured losing four handovers to lanes
that queued later - a poller never wins while any blocking waiter exists,
because the kernel hands a released flock straight to whoever is already
blocked on it (`cg512.py`'s header has the mechanism). The form the
coordination notes converged on is a BLOCKING flock in a reopen-recheck
loop, and that is what `take()` below queues on: `fcntl.flock(fd,
LOCK_EX)` with a `SIGALRM`-based timeout standing in for the missing
timeout argument on `flock(2)`, so the wait is woken instantly on a real
release rather than after up to one poll interval, while still waking on
its own every `RIGLOCK_WAIT` seconds to reopen and re-check the inode - a
releaser that unlinks without ever closing its holding fd would otherwise
block a waiter on an orphaned inode forever. `RIGLOCK_WAIT<=0` (and the
orphan/held-by-non-flock-taker branches below, which have nothing to
block ON) keep the old non-blocking `LOCK_NB` shape.

    THAT PERIODIC RE-CHECK IS A QUEUE EXIT, NOT A FREE GLANCE, and it is
    the only thing in this file that decides whether a handover is a queue
    or a lottery. When the SIGALRM fires, `flock(2)` returns EINTR and the
    loop closes the fd: either alone takes the waiter OUT of the kernel's
    wait queue, so it re-enters as a newcomer with no accumulated position.
    At the 2.0 s this defaulted to until 17 Sep 2026 a waiter therefore
    left the queue 1,800 times an hour and a release went to whichever
    waiter happened to be blocked at that instant - which is why one lane
    on amd-epyc-vm lost 7,000 consecutive draws over 3h53m and another was
    skipped on five handovers in 33 minutes while queued throughout
    (an internal note). The default
    is 60 now; see the block comment above `take()` for why that number and
    why the re-check must not simply be removed.
"""
import fcntl
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import riglock_state  # noqa: E402

LOCK = os.path.expanduser("~/.parfast-rig.lock")


class _WaitTimedOut(Exception):
    """Raised out of the SIGALRM handler to abort a blocking flock() wait -
    see _take_blocking() below. Never escapes take()."""


def _alarm_handler(signum, frame):
    raise _WaitTimedOut()


def _take_blocking(fd, seconds):
    """Block on fcntl.flock(fd, LOCK_EX) for up to `seconds`, so a real
    release wakes us the instant it happens rather than after up to one poll
    interval, but still return (rather than hang forever) if nobody releases
    in that window - a waiter on an inode a releaser unlinked without ever
    closing its own fd would otherwise never be woken by the kernel at all.
    flock(2) takes no timeout argument; SIGALRM is the standard way round
    that. Returns True if the lock was won, False on timeout. Main-thread
    only (signal handlers are process-wide and only ever installed here)."""
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        signal.setitimer(signal.ITIMER_REAL, 0)  # won it - cancel before it can fire
        return True
    except _WaitTimedOut:
        return False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


# The queue can be DEEP on a busy box: on 16 Sep 2026 three rounds were
# stacked on this lock at once and the two ahead wanted ~110 minutes between
# them, which is past the 100 minutes the defaults below buy. A waiter that
# gives up is a lane that has to be relaunched by hand and can lose the gap
# while nobody is watching, so the budget is an env dial - not a bigger
# default, because a runaway waiter on an abandoned lock is the other failure.
#
# `RIGLOCK_WAIT` IS A FAIRNESS DIAL AND BIGGER IS FAIRER. That is the
# opposite of what this comment claimed between `7cc32f855` and 17 Sep 2026,
# and the inversion is the kind that costs afternoons: the ADVICE it gave
# ("leave `RIGLOCK_WAIT` alone") was sound, but the REASON it gave for it -
# that `wait` is merely how often an orphan re-check fires and so cannot
# affect who wins - reads as "this dial is not about fairness", when it is
# the only dial that IS. `take()` does block in `LOCK_EX`, and a release does
# reach a blocked waiter instantly; but only a waiter that IS blocked at that
# instant. Every `wait` seconds the SIGALRM fires, the `flock` returns EINTR
# and the loop closes the fd and reopens - both of which drop the waiter out
# of the kernel wait queue - so the whole wait is a series of draws and the
# fraction of time a lane is actually IN the queue is what sets its odds.
# At the old 2.0 that fraction was as low as this file can make it: a waiter
# on amd-epyc-vm lost 7,000 consecutive draws over 3h53m on 16 Sep 2026
# (7,000 x 2.0 s = 3.889 h = 3h53m - the same number twice, which is what
# identifies those tries as 7,000 separate draws rather than one long wait),
# and the lane that wrote it up was skipped on FIVE handovers between 14:13Z
# and 14:46Z on 17 Sep while queued the entire time, two of the winners
# taking the lock in the same second as the previous release.
# (an internal note)
#
# SO THE DEFAULT IS 60, and it is not larger because `wait` IS the orphan-
# detection latency - that tradeoff is the only thing to think about here.
# A releaser that unlinks without ever closing its holding fd leaves every
# waiter blocked on a dead inode with nothing left to wake them, and the
# re-check is the only thing that breaks that; 60 s leaves the queue 30x
# less often than 2.0 did (a waiter is blocked ~98% of the time rather than
# losing its place every two seconds) and still notices an orphaned inode
# inside a minute, against the EIGHT HOURS the 16 Sep orphan actually cost
# before anyone looked. Do not buy fairness by deleting the re-check: that
# trades a lottery for a hang, which is strictly worse.
#
# AND `wait` NO LONGER MULTIPLIES AGAINST `tries` FOR THE TOTAL BUDGET,
# which it did until 17 Sep and which is the arithmetic people got wrong.
# The budget is WALL CLOCK now, derived from `RIGLOCK_TRIES` at the 2.0 s
# per try that dial has always been implicitly priced in, so every caller
# that already sets it keeps the budget it meant rather than 30x it: the
# default 3000 is still 100 minutes, and the `RIGLOCK_TRIES=900` in
# an internal note is still the 30 minutes
# that lane intended and not fifteen hours. `RIGLOCK_BUDGET_S` says it in
# seconds directly and is the honest name. `tries` still bounds the loop in
# the `wait<=0` arm, which has nothing to block on and would otherwise spin.
#
# THE MEASUREMENT FROM THE OTHER SIDE OF THE CHANGE, kept because it is the
# cost of a SHAPE rather than of one lane - and it prices the OLD `LOCK_NB`
# poll that `7cc32f855` replaced, NOT the blocking loop above, so it is not
# evidence against the default this file now ships. Under that poll, a round
# that queued at 16:31Z on 16 Sep 2026 with `RIGLOCK_WAIT=20` - set to 20
# meaning to be a good neighbour on a busy box - lost FIVE consecutive
# handovers over two hours and twenty-five minutes to lanes polling at the
# default, each of which took the box within a second or two of the previous
# holder releasing it. A poll has no kernel queue and no fairness in it, so
# raising the interval bought nobody anything and simply entered that lane in
# fewer draws; it never yielded a slot, because under a poll nobody is
# waiting behind you in an order to yield to. If any runner on this fleet is
# ever taken back to `LOCK_NB`, that is what it costs.

# What one `RIGLOCK_TRIES` unit has always been worth in seconds: the old
# default `wait`. Only used to convert that dial into the wall-clock budget
# above - it is not a poll interval and nothing waits for this long.
TRY_UNIT_S = 2.0

def take(tag, tries=None, wait=None, lock_path=None, budget_s=None):
    # lock_path overrides the real per-box path - for rig_lock_selftest.py
    # only, so a test can race a holder over a temp file instead of the live
    # ~/.parfast-rig.lock. Every real caller leaves it unset.
    path = lock_path or LOCK
    tries = int(os.environ.get("RIGLOCK_TRIES", "3000")) if tries is None else tries
    wait = float(os.environ.get("RIGLOCK_WAIT", "60.0")) if wait is None else wait
    if budget_s is None:
        env_budget = os.environ.get("RIGLOCK_BUDGET_S")
        budget_s = float(env_budget) if env_budget else tries * TRY_UNIT_S
    deadline = time.monotonic() + budget_s
    # The branches below that cannot block - an orphaned inode, and a live
    # holder that took this file without an flock - are genuine POLLS, so
    # they keep the 2 s cadence rather than inheriting `wait`: raising `wait`
    # is about staying IN a queue, and in those two branches there is no
    # queue to stay in, only latency to add.
    repoll = min(wait, TRY_UNIT_S) if wait > 0 else 0
    i = 0
    last_note = None
    while True:
        if wait > 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
        elif i >= tries:
            # wait<=0 is the non-blocking arm and has no wall clock in it;
            # `tries` bounds it directly, exactly as it always did.
            break
        i += 1
        pre_existing = os.path.exists(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
        if wait > 0:
            # Never block past the budget: the last wait is short, not a
            # full `wait` of overshoot. Floored at 50 ms because setitimer()
            # treats a small enough interval as "never" and the alarm that
            # ends the wait would then never arrive.
            won = _take_blocking(fd, max(0.05, min(wait, remaining)))
        else:
            # wait<=0 has nothing to block for (rig_lock_selftest.py's
            # tries=1/wait=0 arm needs the refusal on the first look, not
            # after a wait) - keep the old immediate LOCK_NB shape.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                won = True
            except OSError:
                won = False
        if not won:
            os.close(fd)
            # Say so about once a minute. This used to be every 30th try,
            # which was the same cadence only because a try was 2 s; now that
            # a try is a whole `wait` the cadence has to be named in seconds
            # or the log goes quiet for half an hour.
            now = time.monotonic()
            if last_note is None or now - last_note >= 60:
                last_note = now
                try:
                    with open(path) as f:
                        holder = f.read().strip()[:120]
                except OSError:
                    holder = "(unreadable)"
                print("%s queued for the rig lock (held by: %s)"
                      % (time.strftime("%H:%M:%SZ", time.gmtime()), holder), flush=True)
            continue
        # ours - but is it still the lock the PATH names?
        try:
            if os.fstat(fd).st_ino != os.stat(path).st_ino:
                os.close(fd)
                print("won a lock on an orphaned inode, re-queueing", flush=True)
                time.sleep(repoll)
                continue
        except OSError:
            os.close(fd)
            time.sleep(repoll)
            continue
        # Winning the flock only proves nobody ELSE HOLDING A FLOCK is here -
        # a `set -o noclobber` shell taker has none to lose. Ask the one rule
        # whether the identity already in the file names somebody alive
        # before touching it (see the module docstring for why this is not
        # `probe_flock=True`: we already won the flock ourselves above, and
        # asking again would just be racing our own hold).
        state, who = riglock_state.lock_state(path, probe_flock=False)
        if state == "held":
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            print("%s rig lock held by a live non-flock taker: %s"
                  % (time.strftime("%H:%M:%SZ", time.gmtime()), who), flush=True)
            time.sleep(repoll)
            continue
        if state == "orphan" and pre_existing:
            riglock_state.announce_orphan(
                path, who, "cleared by round=%s pid=%d" % (tag, os.getpid()))
        os.ftruncate(fd, 0)
        os.write(fd, ("round=%s pid=%d started=%s\n"
                      % (tag, os.getpid(), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))).encode())
        os.fsync(fd)
        print("%s rig lock TAKEN by %s pid %d"
              % (time.strftime("%H:%M:%SZ", time.gmtime()), tag, os.getpid()), flush=True)
        return fd
    raise SystemExit("never got the rig lock")


def release(fd):
    try:
        os.ftruncate(fd, 0)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)  # never unlink: an unlinked lock can be held twice
    print("%s rig lock RELEASED (truncated, not unlinked)"
          % time.strftime("%H:%M:%SZ", time.gmtime()), flush=True)


def main():
    tag = sys.argv[1]
    cmd = sys.argv[sys.argv.index("--") + 1:]
    fd = take(tag)
    try:
        rc = subprocess.run(cmd).returncode
    finally:
        release(fd)
    sys.exit(rc)


if __name__ == "__main__":
    main()
