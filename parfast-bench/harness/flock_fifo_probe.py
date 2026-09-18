#!/usr/bin/env python3
"""flock_fifo_probe.py - does THIS box hand a released flock to the waiter
that has been blocked longest?

NO riglock in it, deliberately. One holder; waiter A blocks in
`fcntl.flock(fd, LOCK_EX)`; `gap` seconds later waiter B does the same (and C,
D, ... when more than two are asked for); the holder releases. No waiter ever
leaves the kernel's wait queue - there is no timeout, no re-check and no
reopen anywhere in this file - so the order they wake in is purely the
kernel's and nothing else.

    python3 flock_fifo_probe.py [reps] [waiters]   # default 15 reps, 2 waiters

WHY IT EXISTS, and when to reach for it. `rig_lock_selftest.py`'s handover
arm 2 asserts that a riglock waiter which queued FIRST keeps its place against
a plain flock latecomer. That assertion is only meaningful on a box whose
kernel orders handovers by wait time, and `flock(2)` does not contract that.
So when arm 2 fails, this probe is what says WHICH of the two things went
wrong: a high rate here and a failing arm 2 means riglock is leaving the queue
and that is a defect; a LOW rate here means the box itself does not order
handovers and arm 2 cannot hold there whatever riglock does. Run it before
touching either arm. Since 17 Sep 2026 `rig_lock_selftest.py` no longer waits
for a human to do that: it calls `kernel_orders_handovers()` below as a
PRECONDITION and disarms arm 2, loudly and by name, where the kernel fails it.

TWO SCORES, and the second is the one the precondition uses.

  - **first** - the longest-blocked waiter woke FIRST. This is the faithful
    model of arm 2, which races exactly one incumbent against exactly one
    latecomer, and it is what `probe()` and the two-waiter CLI report.
  - **perfect** - ALL the waiters woke in wait-time order, not just the
    winner. Only meaningful with three or more. It is a STRICTER property
    than arm 2 needs, and it is the precondition's predicate anyway, because
    it separates the two kernels roughly four times faster per second of
    wall clock (the table below). The cost of the proxy is stated where it
    is paid: a kernel that got the FIRST handover right and the rest wrong
    would be disarmed here although arm 2 could have held on it. No such
    kernel has been seen on this fleet - the two that fail `perfect` fail
    `first` too, and fail arm 2 in practice - and the disarm prints BOTH
    scores so a reader can see which way a future one went.

MEASURED 17 Sep 2026, four boxes, 220 reps each (60 at two waiters, 40 at
three, 120 at four), an internal note:

    box               kernel            first@2   perfect@3  perfect@4  s/rep@4
    dev Mac (M3 Ultra) Darwin 27.0.0    60/60     40/40      120/120    1.6-1.8
    amd-epyc-vm      Linux 6.8.0-137   60/60     40/40      120/120    1.4
    spinning-disk-nas-a  Linux 4.4.302     47/60     12/40        5/40     1.4
    spinning-disk-nas-b    Linux 4.4.302     34/60     10/40        5/40     1.4

So the fleet is split by kernel, the two DSM boxes are the ones where arm 2 is
not a statement about riglock at all, and at four waiters `perfect` is 0.125
on both of them against 1.000 on both FIFO boxes - a gap no threshold has to
be clever about. Neither FIFO box lost a single rep of 220, and the dev Mac's
column was taken at load average 105-153 on 32 cores, about 4x oversubscribed,
which is the load a selftest run here actually meets. The two DSM figures MOVE
and never approach 1: the 17 Sep first@2 rates were 31/40 and 28/40 on a
quieter afternoon against 47/60 and 34/60 here.

THE PRECONDITION'S NUMBERS, and the confidence they are chosen for. Eight reps
at four waiters, of which at least six must put every waiter in wait-time
order. About 11 s on an idle Linux box and 14 s on the loaded dev Mac.

  - A DSM box ARMS arm 2 by mistake - a red the reader would have to
    adjudicate - once in 11,700 runs at the measured 0.125, and once in 478
    at 0.215, the top of the 95% Wilson interval around the 10/80 pooled over
    both boxes.
  - A FIFO box DISARMS arm 2 by mistake - the direction that costs coverage,
    because a disarmed arm cannot catch a riglock regression - once in 9,600
    runs at 0.9875, which is the 95% lower bound 240/240 observed reps support
    by the rule of three, and once in 173 even at a pessimistic 0.95.
  - THE ONE-FLAKE TOLERANCE IS WHAT BUYS THE SECOND NUMBER, and it is the
    part to leave alone. A flat 8/8 would disarm a FIFO box once in TEN runs
    at that same 0.9875 lower bound, which on this fleet would read as "the
    gate is flaky" and get the whole precondition deleted. Six of eight costs
    a factor of 24 on the arming side and buys a factor of 900 here.
  - Both figures assume reps are independent. That was checked rather than
    assumed: lag-1 correlation on the four-waiter `perfect` sequence is -0.15
    on both DSM boxes - anti-clustered, so the independent model OVERSTATES
    the chance of a run of six - and the empirical sliding-window rate of six
    perfect reps in any window of eight is 0 of 33 windows on each -
    the most any window contained was TWO.

WHAT WAS WEIGHED AND NOT BUILT, so the next lane does not re-derive it. A
self-calibrating RATE arm (run arm 2's race N times at 60 s and N times at
2.0 s and require the incumbent to win strictly more often at 60) needs no
kernel model at all, which is genuinely attractive, but it prices its power
in riglock races at ~3.5 s each rather than probe reps at 1.4, and under a
real regression - where both waits behave alike - it passes on a coin flip
unless N is large. A version sniff on the kernel release is cheaper than
either and rots the first time a box is upgraded or a new kernel misbehaves.
Leaving arm 2 red on two boxes and writing it down was the incumbent option
and is what this replaces.

DO NOT tune `PRECOND_*` to make a box green. A box that starts failing the
precondition is telling you its kernel changed; a box that starts passing it
while arm 2 fails is telling you riglock regressed. Either is worth a claim.
"""
import collections
import fcntl
import os
import subprocess
import sys
import tempfile
import time

# The precondition `rig_lock_selftest.py` arms handover arm 2 on. Four
# waiters and six reps are measured choices, not round numbers - see THE
# PRECONDITION'S NUMBERS above.
PRECOND_WAITERS = 4
PRECOND_REPS = 8
PRECOND_MIN_PERFECT = 6

Verdict = collections.namedtuple("Verdict", "reps waiters first perfect orders")

_WAITER = """
import fcntl, os, sys, time
path, ready, out = sys.argv[1:4]
fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
open(ready, "w").close()
fcntl.flock(fd, fcntl.LOCK_EX)
open(out, "w").write(repr(time.time()))
fcntl.flock(fd, fcntl.LOCK_UN)
os.close(fd)
"""


def _await_ready(path, proc, timeout=60.0):
    """A waiter signals `ready` after open() and BEFORE it blocks, so the
    ordering below rests on this handshake plus the `gap`, never on a sleep
    chosen to cover Python startup on a loaded box."""
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(path):
            return
        assert proc.poll() is None, "a waiter died before it queued"
        time.sleep(0.01)
    raise AssertionError("a waiter never reached the queue")


def race(reps=15, waiters=2, gap=0.3, settle=0.4, verbose=False):
    """Run the race `reps` times and return a Verdict.

    `settle` only has to outlast the handshakes; there is no alarm and no
    re-check in this file for it to straddle, which is what makes this the
    kernel's answer rather than riglock's.
    """
    assert waiters >= 2, "a handover needs at least two waiters"
    tags = [chr(ord("A") + i) for i in range(waiters)]
    in_order = "".join(tags)
    first = perfect = 0
    orders = []
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "w.py")
        with open(src, "w") as fh:
            fh.write(_WAITER)
        for rep in range(reps):
            lock = os.path.join(d, "l%d" % rep)
            held = os.open(lock, os.O_RDWR | os.O_CREAT, 0o644)
            fcntl.flock(held, fcntl.LOCK_EX)
            procs, outs = [], []
            for i, tag in enumerate(tags):
                ready = os.path.join(d, "%d%s.ready" % (rep, tag))
                out = os.path.join(d, "%d%s.won" % (rep, tag))
                proc = subprocess.Popen([sys.executable, src, lock, ready, out],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                _await_ready(ready, proc)
                procs.append(proc)
                outs.append(out)
                if i < waiters - 1:
                    time.sleep(gap)
            time.sleep(settle)
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)
            for proc in procs:
                proc.wait(timeout=120)
            woke_at = []
            for out in outs:
                with open(out) as fh:
                    woke_at.append(float(fh.read()))
            order = "".join(tags[i] for i in sorted(range(waiters), key=lambda n: woke_at[n]))
            orders.append(order)
            first += order[0] == "A"
            perfect += order == in_order
            if verbose:
                print("rep %2d: %s woke first (order %s)"
                      % (rep, "A (blocked longest)" if order[0] == "A" else order[0] + " (a latecomer)",
                         order), flush=True)
    return Verdict(reps=reps, waiters=waiters, first=first, perfect=perfect, orders=orders)


def probe(reps=15, gap=0.3, settle=0.4, verbose=True):
    """The two-waiter race, scored the way arm 2 is: how many reps did the
    LONGEST-BLOCKED waiter win? Kept as the CLI's default and as the faithful
    model of arm 2; `kernel_orders_handovers()` is what the gate calls."""
    return race(reps, waiters=2, gap=gap, settle=settle, verbose=verbose).first


def kernel_orders_handovers(reps=PRECOND_REPS, waiters=PRECOND_WAITERS, verbose=False):
    """The PRECONDITION. Returns (armed, Verdict): `armed` is True when this
    kernel woke the waiters in wait-time order in at least PRECOND_MIN_PERFECT
    of `reps` reps, which is the condition under which arm 2 of
    rig_lock_selftest.py is a statement about riglock rather than about the
    kernel. Never widen the tolerance to make a box green - read the header."""
    v = race(reps, waiters=waiters, verbose=verbose)
    return v.perfect >= PRECOND_MIN_PERFECT, v


def main():
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    waiters = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    v = race(reps, waiters=waiters, verbose=True)
    print("FLOCK-FIFO %d/%d first - this box %s wake the longest-blocked waiter first"
          % (v.first, v.reps, "DOES" if v.first == v.reps else "does NOT reliably"))
    if waiters > 2:
        print("FLOCK-FIFO %d/%d perfect - %s put all %d waiters in wait-time order"
              % (v.perfect, v.reps, "DOES" if v.perfect == v.reps else "does NOT reliably",
                 v.waiters))
    return 0


if __name__ == "__main__":
    sys.exit(main())
