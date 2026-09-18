#!/usr/bin/env python3
"""spillnas.py - wall cost of the per-slab spill flush on a spinning disk, cold per leg.

Written for claim `parfast-spill-flush-spinning-disk-15sep`, the round owed by
an internal note addendum A.4: the
killed cell's shape PINNED (64 KiB, m = 4,096, `r -t4 -m192`, both budgets at
134217728, so 4 slabs of 16,384 B = 64 MiB each, output Spill) on a
twelve-spindle RAID6 NAS array (btrfs), three arms interleaved and rotated rep by rep:

    main     BIN_MAIN (origin/main the branch was cut from)
    flush1   BIN_BRANCH with NZBFAST_SPILL_FLUSH=1 (the ungated arm)
    flush0   BIN_BRANCH with NZBFAST_SPILL_FLUSH=0 (A/A against main)

Python 3.8 (DSM): no randbytes, no waitstatus_to_exitcode (pdrv carries both
fallbacks, and this file does not use either).

Per leg: remove parfast's `.N` backups, apply damage (pdrv.damage_picks, seed
1000 + m), `sync`, then the unprivileged POSIX_FADV_DONTNEED drop over every
member and par2 file (bench/component/uncache.c, built static elsewhere) and
REFUSE the leg unless mincore reads 0 resident pages after it. The dispatch
line is checked and the round STOPS on a different shape rather than timing
one. SHA-256 gate of all 16 members, then restore by slice and re-gate.

Load: /proc/stat busy jiffies over the leg minus the leg's own rusage CPU is
the FOREIGN CPU the leg ran beside. A leg over FOREIGN_MAX cores is recorded
with `discard` and rerun (at most RETRIES times). `uptime` before and after
every leg is kept verbatim.

FIXTURE: the driver writes it under the rig lock if absent (16 x 64 MiB os.urandom, par2, gold.sha).

RUN:    SCRATCH=/dir BIN_MAIN=.. BIN_BRANCH=.. UNCACHE=.. [REPS=5] spillnas.py
REDUCE: spillnas.py reduce round.jsonl
"""
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)

M = 4096
SLICE = 65536
SHAPE = "4096 block(s) at 65536 B in 4 slab(s) of 16384 B"
BUDGET = "134217728"
FOREIGN_MAX = float(os.environ.get("FOREIGN_MAX", "1.5"))  # cores
RETRIES = int(os.environ.get("RETRIES", "3"))
ARM_ORDER = ["main", "flush1", "flush0"]


def dur_s(v, unit):
    return float(v) * {"ns": 1e-9, "µs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}[unit]


FLUSH_RE = re.compile(r"spill flush \((\d+) B\): ([0-9.]+)(ns|µs|us|ms|s)\b")


def reduce(path):
    legs = [json.loads(x) for x in open(path)]
    kept = [r for r in legs if not r.get("discard")]
    print("legs %d, discarded %d" % (len(legs), len(legs) - len(kept)))
    med = {}
    for arm in ARM_ORDER:
        rs = [r for r in kept if r["arm"] == arm]
        if not rs:
            continue
        walls = sorted(r["wall"] for r in rs)
        cpus = [r["cpu"] for r in rs]
        med[arm] = statistics.median(walls)
        line = "%-7s n=%d wall %s median %.2f cpu median %.1f" % (
            arm, len(rs), ", ".join("%.2f" % w for w in walls), med[arm], statistics.median(cpus))
        if arm == "flush1":
            sums = sorted(r["flush_sum"] for r in rs)
            each = [t for r in rs for t in r["flush_s"]]
            line += " | flush sum %s median %.2f | per flush %.0f-%.0f ms (n=%d, median %.0f)" % (
                ", ".join("%.2f" % s for s in sums), statistics.median(sums),
                min(each) * 1e3, max(each) * 1e3, len(each), statistics.median(each) * 1e3)
        else:
            line += " | flush lines %s" % sorted({r["flush_n"] for r in rs})
        print(line)
        print("        foreign cores %s  ok %s  rc %s" % (
            ", ".join("%.2f" % r["foreign_cores"] for r in rs),
            all(r["ok"] for r in rs), sorted({r["rc"] for r in rs})))
    if "main" in med:
        for arm in ("flush0", "flush1"):
            if arm in med:
                d = med[arm] - med["main"]
                print("%s - main: %+.2f s (%+.1f%%)" % (arm, d, 100 * d / med["main"]))
    if "flush1" in med and "flush0" in med:
        d = med["flush1"] - med["flush0"]
        print("flush1 - flush0: %+.2f s (%+.1f%%)" % (d, 100 * d / med["flush0"]))


if len(sys.argv) > 1 and sys.argv[1] == "reduce":
    reduce(sys.argv[2])
    sys.exit(0)

import riglock  # noqa: E402
from pdrv import apply_damage, damage_picks, restore_slices  # noqa: E402

S = os.environ["SCRATCH"]
BINS = {"main": os.environ["BIN_MAIN"], "branch": os.environ["BIN_BRANCH"]}
UNCACHE = os.environ["UNCACHE"]
REPS = int(os.environ.get("REPS", "5"))
PRISTINE = os.path.join(S, "fix", "pristine")
WORK = os.path.join(S, "fix", "work")
LOGDIR = os.path.join(S, "legs")
OUT = os.path.join(S, os.environ.get("OUT", "round.jsonl"))
os.makedirs(LOGDIR, exist_ok=True)
ARMS = {
    "main": ("main", {}),
    "flush1": ("branch", {"NZBFAST_SPILL_FLUSH": "1"}),
    "flush0": ("branch", {"NZBFAST_SPILL_FLUSH": "0"}),
}
HZ = os.sysconf("SC_CLK_TCK")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def uptime():
    return subprocess.run(["uptime"], stdout=subprocess.PIPE, universal_newlines=True).stdout.strip()


def busy_jiffies():
    v = [int(x) for x in open("/proc/stat").readline().split()[1:]]
    return sum(v) - v[3] - v[4]  # minus idle and iowait


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


# THE ORPHAN ESCAPE, NOT JUST THE IDENTITY LINE. This queued with a bare
# `fcntl.flock(lock, fcntl.LOCK_EX)` until 17 Sep 2026. That is the FAIREST
# wait on this fleet and the reason it was left alone twice: it never leaves
# the kernel's wait queue, so it cannot lose a handover the way
# `riglock.take()` could at the 2 s re-check it defaulted to until 17 Sep
# (an internal note). It was also the
# only shape on this fleet with NO ESCAPE AT ALL from the other half of that
# tradeoff: a releaser that unlinks the lock without ever closing its own fd
# leaves a bare waiter blocked on a dead inode forever, with nothing left to
# wake it. That is the 16 Sep orphan and it cost apple-m3-ultra eight hours
# (an internal note).
#
# `take()` is that same blocking flock PLUS the escape, so this is not a
# third copy of the loop - it is the copy deleted. Three things come with it,
# all of them things this file used to do by hand or not at all: the identity
# line is written once in one place (the 16 Sep anonymous-taker fix, which
# was copied here verbatim); a lock held by a LIVE non-flock taker - the
# `set -o noclobber` shell round this file would have appended straight
# underneath - is now refused rather than joined, which is the 10:27Z clobber
# of the same day; and the periodic re-check breaks the orphan wedge. The
# fairness given up is one queue exit a minute, not thirty.
#
# THE BUDGET IS INFINITE HERE AND THAT IS DELIBERATE. A bare flock waits
# forever; `take()`'s default gives up after 100 minutes and exits; and these
# rounds are launched unattended behind queues that have run past three hours
# on this fleet, so the default would turn a long wait into a round that
# never ran. Either env dial still bounds it for a caller that wants one.
log("waiting for the rig lock")
if os.environ.get("RIGLOCK_BUDGET_S") or os.environ.get("RIGLOCK_TRIES"):
    lock_fd = riglock.take("spillnas")      # take() reads both dials itself
else:
    lock_fd = riglock.take("spillnas", budget_s=float("inf"))
# Released by process exit, exactly as the bare flock was: there is no
# try/finally around a flat script, and a round that dies leaves an identity
# line naming a dead pid, which is a takeable orphan by riglock_state's rule.
log("rig lock TAKEN: %s" % uptime())

# The 1 GiB fixture is written UNDER the lock: it is a sustained array write a
# neighbour's timed legs would read as their own disk.
os.makedirs(PRISTINE, exist_ok=True)
for i in range(1, 17):
    fp = os.path.join(PRISTINE, "m%02d.bin" % i)
    if not os.path.exists(fp):
        with open(fp + ".tmp", "wb") as f:
            for _ in range(64):
                f.write(os.urandom(1 << 20))
        os.rename(fp + ".tmp", fp)
members = sorted(f for f in os.listdir(PRISTINE) if f.endswith(".bin"))
assert len(members) == 16, members
if not os.path.exists(os.path.join(PRISTINE, "set.par2")):
    t0 = time.monotonic()
    subprocess.run([BINS["main"], "c", "-q", "-t4", "-s65536", "-c4096", "set.par2"] + members,
                   cwd=PRISTINE, check=True)
    log("par2 created in %.1f s" % (time.monotonic() - t0))
goldp = os.path.join(S, "fix", "gold.sha")
if not os.path.exists(goldp):
    with open(goldp, "w") as f:
        for mname in members:
            f.write("%s  %s\n" % (sha(os.path.join(PRISTINE, mname)), mname))
gold = {}
for line in open(goldp):
    h, name = line.split()
    gold[name.lstrip("*")] = h
if not os.path.isdir(WORK):
    subprocess.run(["cp", "-R", PRISTINE, WORK], check=True)
KEEP = set(os.listdir(PRISTINE))
PAR2 = sorted(f for f in KEEP if f.endswith(".par2"))


def gate():
    return all(sha(os.path.join(WORK, mname)) == gold[mname] for mname in members)


if not gate():
    raise SystemExit("work copy is not pristine at start")


def drop():
    subprocess.run(["sync"], check=True)
    out = subprocess.run([UNCACHE] + [os.path.join(WORK, f) for f in members + PAR2],
                         stdout=subprocess.PIPE, universal_newlines=True, check=True).stdout
    before = after = pages = 0
    for ln in out.splitlines():
        b, a, p, _ = ln.split(None, 3)
        before += int(b)
        after += int(a)
        pages += int(p)
    with open(os.path.join(S, "dropcache.log"), "a") as f:
        f.write("uncache: %d files, %d pages were resident, %d now, of %d\n"
                % (len(members) + len(PAR2), before, after, pages))
    return before, after


def run_leg(arm, rep, attempt, picks):
    which, extra = ARMS[arm]
    env = dict(os.environ, NZBFAST_REPAIR_TIMING="1", NZBFAST_NO_ENRICH="1",
               NZBFAST_REPAIR_SOLVE_BUDGET=BUDGET, NZBFAST_NTT_BUDGET=BUDGET)
    env.pop("NZBFAST_SPILL_FLUSH", None)
    env.update(extra)
    argv = [BINS[which], "r", "-t4", "-q", "-m192", "set.par2"]
    tag = "%s-r%d-a%d" % (arm, rep, attempt)
    errp = os.path.join(LOGDIR, tag + ".err")
    strays = [f for f in os.listdir(WORK) if f not in KEEP]
    for f in strays:
        os.unlink(os.path.join(WORK, f))
    apply_damage(WORK, members, SLICE, picks, 1000 + M)
    rb, ra = drop()
    if ra != 0:
        raise SystemExit("cache drop left %d resident pages before %s" % (ra, tag))
    up0 = uptime()
    j0 = busy_jiffies()
    t0 = time.monotonic()
    with open(errp, "wb") as fe:
        p = subprocess.Popen(argv, cwd=WORK, stdout=subprocess.DEVNULL, stderr=fe, env=env)
        _, status, ru = os.wait4(p.pid, 0)
    wall = time.monotonic() - t0
    j1 = busy_jiffies()
    up1 = uptime()
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
    cpu = ru.ru_utime + ru.ru_stime
    foreign = max(0.0, (j1 - j0) / HZ - cpu) / wall
    ok = rc == 0 and gate()
    restore_slices(WORK, PRISTINE, members, SLICE, picks)
    if not gate():
        for mname in members:
            if sha(os.path.join(WORK, mname)) != gold[mname]:
                shutil.copyfile(os.path.join(PRISTINE, mname), os.path.join(WORK, mname))
        if not gate():
            raise SystemExit("restore failed at " + tag)
    err = open(errp, encoding="utf-8", errors="replace").read()
    flushes = [(int(b), dur_s(v, u)) for b, v, u in FLUSH_RE.findall(err)]
    rec = {
        "arm": arm, "rep": rep, "attempt": attempt, "rc": rc, "ok": ok,
        "wall": round(wall, 3), "cpu": round(cpu, 2),
        "shape_ok": SHAPE in err and "output Spill" in err,
        "flush_n": len(flushes), "flush_bytes": sorted({b for b, _ in flushes}),
        "flush_s": [round(t, 4) for _, t in flushes],
        "flush_sum": round(sum(t for _, t in flushes), 4),
        "foreign_cores": round(foreign, 2), "uptime_before": up0, "uptime_after": up1,
        "strays_removed": len(strays), "resident_before_drop": rb,
        "discard": foreign > FOREIGN_MAX,
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    log("LEG %-12s rc=%d ok=%s wall=%6.2f cpu=%6.1f flush n=%d sum=%.2f foreign=%.2f%s | %s | %s"
        % (tag, rc, ok, wall, cpu, len(flushes), rec["flush_sum"], foreign,
           " DISCARD" if rec["discard"] else "", up0.split("load average:")[1][:18],
           up1.split("load average:")[1][:18]))
    if not rec["shape_ok"]:
        raise SystemExit("SHAPE MISMATCH at %s - stopping, see %s" % (tag, errp))
    if not ok:
        raise SystemExit("leg failed its gate at %s (rc %d)" % (tag, rc))
    if arm == "flush1" and len(flushes) != 4:
        raise SystemExit("flush1 leg %s logged %d flushes, not 4" % (tag, len(flushes)))
    if arm != "flush1" and flushes:
        raise SystemExit("%s leg %s logged a flush" % (arm, tag))
    return rec


done = set()
if os.path.exists(OUT):
    for line in open(OUT):
        r = json.loads(line)
        if not r.get("discard"):
            done.add((r["arm"], r["rep"]))
picks = damage_picks(WORK, members, SLICE, M, 1000 + M)
for rep in range(1, REPS + 1):
    order = ARM_ORDER[(rep - 1) % 3:] + ARM_ORDER[:(rep - 1) % 3]
    for arm in order:
        if (arm, rep) in done:
            log("SKIP %s-r%d, already in %s" % (arm, rep, os.path.basename(OUT)))
            continue
        for attempt in range(1, RETRIES + 2):
            if not run_leg(arm, rep, attempt, picks)["discard"]:
                break
            time.sleep(60)
        else:
            raise SystemExit("box stayed loaded through %d attempts at %s-r%d" % (RETRIES + 1, arm, rep))
for f in [f for f in os.listdir(WORK) if f not in KEEP]:
    os.unlink(os.path.join(WORK, f))
log("ALL DONE: %s" % uptime())
reduce(OUT)
