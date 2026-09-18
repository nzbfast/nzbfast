#!/usr/bin/env python3
"""nrd.py - NEON A/B for parfast-ntt-narrow-admits-unpriced-stripe-14sep.

A thin driver over harness/memladder.py's run_leg: four arms
interleaved per rung and rep so both dispatchers see the same box state -
fold, force (base binary), auto on the NEW binary, auto on the BASE binary
(recorded with tag=base / tag=new and written to separate jsonl files so
`memladder.py aa` compares their dispatch). -t4 -m128.

Holds ~/.parfast-rig.lock with an exclusive flock for the whole round, after
waiting for it AND for no parfast/par2 process (mqueue.py's rule).
"""
import fcntl, os, subprocess, sys, time

S = os.environ["SCRATCH"]
HARNESS = os.environ["HARNESS"]
BASE, NEW = os.environ["BASE_BIN"], os.environ["NEW_BIN"]
RUNGS = [int(x) for x in os.environ["RUNGS"].split(",")]
REPS = int(os.environ.get("REPS", "2"))
os.environ.setdefault("BIN", BASE)
sys.path.insert(0, HARNESS)


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def tools_up():
    out = subprocess.run(["ps", "-Ao", "pid=,comm="], capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if os.path.basename(l.split(None, 1)[-1].strip()) in ("parfast", "par2turbo", "par2j", "par2")]


lk = open(os.path.expanduser("~/.parfast-rig.lock"), "a+")
waited = 0
while True:
    try:
        fcntl.flock(lk.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        if waited % 600 == 0:
            print("NRD-WAIT lock held (%dm) %s" % (waited // 60, utc()), flush=True)
        time.sleep(30); waited += 30
        continue
    up = tools_up()
    if not up:
        break
    fcntl.flock(lk.fileno(), fcntl.LOCK_UN)
    if waited % 600 == 0:
        print("NRD-WAIT tools up: %s" % up[:2], flush=True)
    time.sleep(30); waited += 30
lk.seek(0); lk.truncate(); lk.write("round=ntt-narrow-neon pid=%d started=%s\n" % (os.getpid(), utc())); lk.flush()
print("NRD-LOCK %s" % utc(), flush=True)

import memladder as ml  # noqa: E402  (reads SCRATCH/BIN/FIX at import)
from pdrv import damage_picks  # noqa: E402

try:
    if not ml.gate():
        raise SystemExit("work copy is not pristine at start")
    for rep in range(1, REPS + 1):
        for m in RUNGS:
            picks = damage_picks(ml.WORK, ml.members, ml.SLICE, m, 1000 + m)
            for arm, binp, tag, out in (("fold", BASE, "base", "fold.jsonl"),
                                        ("force", BASE, "base", "force.jsonl"),
                                        ("auto", NEW, "new", "new.jsonl"),
                                        ("auto", BASE, "base", "base.jsonl")):
                ml.BIN, ml.TAG, ml.OUT = binp, tag, out
                ml.run_leg(m, rep, "128", arm, picks)
    print("NRD-DONE %s" % utc(), flush=True)
finally:
    lk.seek(0); lk.truncate(); lk.flush()
    fcntl.flock(lk.fileno(), fcntl.LOCK_UN)
