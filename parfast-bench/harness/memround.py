#!/usr/bin/env python3
"""memround.py - solve-window peak per arm, shipped (whole) vs NZBFAST_REPAIR_OUTPUT=inplace.

Written for an internal note (sections 5
and 6); the owed spinning-disk round is an internal note.

Holds the parfast rig flock (~/.parfast-rig.lock) for the whole round, blocking
until it is free. Builds the fixture's par2 if absent. Every leg SHA-gated and
restored by slice (pdrv). -t4 -m128, 64 KiB, n = 16,384.

FIXTURE, once, under $SCRATCH (NEVER inside the repo - it is 1 GiB of random
bytes, and each leg leaves `parfast r`'s `mNN.bin.N` backups beside the work
copy, ~9 GB over the two rounds of the note; delete $SCRATCH/fix/work after):

    mkdir -p $SCRATCH/fix/pristine && cd $SCRATCH/fix/pristine
    for i in $(seq -w 1 16); do dd if=/dev/urandom of=m$i.bin bs=1048576 count=64; done
    shasum -a 256 m*.bin > ../gold.sha

RUN:   SCRATCH=/dir BIN_BASE=/path/parfast BIN_INPLACE=/path/parfast [REPS=2]
       [OUT=round.jsonl] [PLAN='[[m,"auto"|"fold",[arms]],...]']
       [EXTRA_ARMS='{"label": ["base"|"inplace", {env}, {"m": 256|null, "t": 1}]}']
       [DROP_CACHE_CMD='sync; echo 3 | sudo tee /proc/sys/vm/drop_caches'] memround.py

  BIN_BASE and BIN_INPLACE may be the same binary: the switch is an env var,
  so two builds are only needed to A/A a code change. DROP_CACHE_CMD runs
  before every leg (after the damage is applied) when set - the spinning-disk
  round needs it, or every sweep after the first reads page cache.
  Reduce per phase with phases.py; the plan arithmetic is slabwindow.py.

  An EXTRA_ARMS entry's optional third element sets that arm's `-m` (MB, or
  null for no `-m` at all, which is the host-derived budget) and `-t`; both
  default to the round's -m128 -t4. Added for the Nibble slab-width round
  (note section 9), which sweeps the budget and the pool width as arms.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import riglock  # noqa: E402
from pdrv import apply_damage, damage_picks, harness_facts, restore_slices  # noqa: E402

S = os.environ["SCRATCH"]
BASE = os.environ["BIN_BASE"]
INPL = os.environ.get("BIN_INPLACE", BASE)
DROP_CACHE_CMD = os.environ.get("DROP_CACHE_CMD")
PRISTINE = os.path.join(S, "fix", "pristine")
WORK = os.path.join(S, "fix", "work")
SLICE = 65536
LOGDIR = os.path.join(S, "legs")
OUT = os.path.join(S, os.environ.get("OUT", "round.jsonl"))
REPS = int(os.environ.get("REPS", "2"))
os.makedirs(LOGDIR, exist_ok=True)

# (label, binary, env, opts)
ARMS = {
    "joint": (BASE, {}, {}),
    "twostage": (BASE, {"NZBFAST_FORNEY_JOINT": "0"}, {}),
    "dense": (BASE, {"NZBFAST_BACKSUB": "dense"}, {}),
    "inplace": (INPL, {"NZBFAST_REPAIR_OUTPUT": "inplace"}, {}),
    "aa-whole": (INPL, {}, {}),
}
# EXTRA_ARMS='{"label": ["base"|"inplace", {env}, {"m": 256|null, "t": 1}]}'
for label, spec in json.loads(os.environ.get("EXTRA_ARMS", "{}")).items():
    which, env = spec[0], spec[1]
    ARMS[label] = (BASE if which == "base" else INPL, env, spec[2] if len(spec) > 2 else {})
# (m, syndrome path, arms)
PLAN = [
    (2048, "auto", ["joint", "aa-whole", "inplace", "twostage", "dense"]),
    (2048, "fold", ["joint", "inplace", "twostage"]),
    (4096, "auto", ["joint", "aa-whole", "inplace", "twostage"]),
]
if os.environ.get("PLAN"):
    PLAN = json.loads(os.environ["PLAN"])


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def uptime():
    return os.getloadavg()[0]


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
# The HARNESS's own provenance, and the round-start twin of the
# per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
# banked log cannot be traced to the harness revision that wrote
# it (census an internal note).
harness_facts()
log("waiting for the rig lock")
if os.environ.get("RIGLOCK_BUDGET_S") or os.environ.get("RIGLOCK_TRIES"):
    lock_fd = riglock.take("memround")      # take() reads both dials itself
else:
    lock_fd = riglock.take("memround", budget_s=float("inf"))
# Released by process exit, exactly as the bare flock was: there is no
# try/finally around a flat script, and a round that dies leaves an identity
# line naming a dead pid, which is a takeable orphan by riglock_state's rule.
log("rig lock TAKEN, load %.0f" % uptime())

members = sorted(f for f in os.listdir(PRISTINE) if f.endswith(".bin"))
if not os.path.exists(os.path.join(PRISTINE, "set.par2")):
    t0 = time.monotonic()
    subprocess.run([BASE, "c", "-q", "-s65536", "-c4096", "set.par2"] + members, cwd=PRISTINE, check=True)
    log("fixture created in %.1f s" % (time.monotonic() - t0))
if not os.path.isdir(WORK):
    subprocess.run(["cp", "-R", PRISTINE, WORK], check=True)
keep = set(os.listdir(PRISTINE))

gold = {}
for line in open(os.path.join(S, "fix", "gold.sha")):
    h, name = line.split()
    gold[name.lstrip("*")] = h


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def gate():
    return all(sha(os.path.join(WORK, m)) == gold[m] for m in members)


if not gate():
    raise SystemExit("work copy is not pristine at start")


def busy_jiffies():
    # Linux only: every core's non-idle time, so a leg can report the CPU
    # the rest of the box spent beside it (busy delta less the child's own).
    try:
        with open("/proc/stat") as fh:
            v = [int(x) for x in fh.readline().split()[1:]]
    except (OSError, ValueError):
        return None
    return sum(v) - v[3] - v[4]


def num(pat, s, cast=float):
    mm = re.search(pat, s)
    return cast(mm.group(1)) if mm else None


def run_leg(m, path, arm, rep, picks):
    binary, extra, opts = ARMS[arm]
    env = dict(os.environ, NZBFAST_REPAIR_TIMING="1", NZBFAST_MEM_FLOOR_SERIES="1")
    env.update(extra)
    if path == "fold":
        env["NZBFAST_NTT"] = "0"
    mem = opts.get("m", 128)
    argv = [binary, "r", "-t%d" % opts.get("t", 4), "-q"] + (["-m%d" % mem] if mem else []) + ["set.par2"]
    tag = "m%d-%s-%s-r%d" % (m, path, arm, rep)
    errp = os.path.join(LOGDIR, tag + ".err")
    apply_damage(WORK, members, SLICE, picks, 1)
    if DROP_CACHE_CMD:
        subprocess.run(DROP_CACHE_CMD, shell=True, check=True)
    l0 = uptime()
    j0 = busy_jiffies()
    t0 = time.monotonic()
    with open(errp, "wb") as fe:
        p = subprocess.Popen(argv, cwd=WORK, stdout=subprocess.DEVNULL, stderr=fe, env=env)
        _, status, ru = os.wait4(p.pid, 0)
    wall = time.monotonic() - t0
    j1 = busy_jiffies()
    l1 = uptime()
    # os.waitstatus_to_exitcode is 3.9+; DSM ships 3.8.
    rc = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (
        os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status))
    ok = rc == 0 and gate()
    # `parfast r` leaves `mNN.bin.N` backups; drop them so a long round
    # does not fill the volume and the next leg's scan does not read them.
    for name in os.listdir(WORK):
        if name not in keep:
            os.unlink(os.path.join(WORK, name))
    restore_slices(WORK, PRISTINE, members, SLICE, picks)
    if not gate():
        raise SystemExit("restore failed at " + tag)
    err = open(errp, errors="replace").read()
    series = [(float(t), int(fp), int(wk)) for t, fp, wk in
              re.findall(r"mem-floor series: ([0-9.]+)s fp (\d+) MB work (\d+) MB", err)]
    hw = re.search(r"mem-floor: live high-water .*?footprint (\d+) MB .*?repair work (\d+) MB \(own peak (\d+)\)", err)
    sp = re.search(r"mem-floor: sampled peak rss .*?rss (\d+) MB .*?footprint (\d+) MB .*?repair work (\d+) MB \(own peak (\d+)\)", err)
    slabs = re.search(r"in (\d+) slab\(s\) of (\d+) B,\s+output (\w+)", err)
    uses = [int(x) for x in re.findall(r"(\d+) stripe use", err)]
    stripes = sorted({int(x) for x in re.findall(r"stripe (\d+)w", err)})
    rec = {
        "m": m, "path": path, "arm": arm, "rep": rep, "rc": rc, "ok": ok,
        "wall": round(wall, 2), "cpu": round(ru.ru_utime + ru.ru_stime, 2),
        # ru_maxrss is BYTES on macOS and KiB on Linux.
        "maxrss_mb": round(ru.ru_maxrss / 1e6) if sys.platform == "darwin" else round(ru.ru_maxrss / 1024),
        "argv": argv[1:],
        "foreign_cpu_s": (round((j1 - j0) / os.sysconf("SC_CLK_TCK") - (ru.ru_utime + ru.ru_stime), 2)
                          if j0 is not None and j1 is not None else None),
        "hw_footprint_mb": int(hw.group(1)) if hw else None,
        "hw_work_mb": int(hw.group(2)) if hw else None,
        "work_own_peak_mb": int(hw.group(3)) if hw else None,
        "series_max_fp_mb": max((fp for _, fp, _ in series), default=None),
        "series_max_work_mb": max((wk for _, _, wk in series), default=None),
        "slabs": int(slabs.group(1)) if slabs else 1,
        "slab_width": int(slabs.group(2)) if slabs else SLICE,
        "staging": slabs.group(3) if slabs else "Whole",
        "backsub": re.findall(r"back-substitution \(([^)]*)\)", err)[:1],
        "stripe_uses": max(uses) if uses else None,
        "stripe_w": stripes,
        "ntt_windows": len(re.findall(r"ntt window \(", err)),
        "load": [round(l0), round(l1)],
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    log("LEG %-34s rc=%d ok=%s wall=%6.2f cpu=%7.2f maxrss=%5s work_peak=%5s fp_hw=%5s slabs=%d/%s %s uses=%s w=%s load=%.1f/%.1f foreign=%s"
        % (tag, rc, ok, wall, rec["cpu"], rec["maxrss_mb"], rec["work_own_peak_mb"], rec["hw_footprint_mb"],
           rec["slabs"], rec["staging"], rec["backsub"], rec["stripe_uses"], rec["stripe_w"], l0, l1, rec["foreign_cpu_s"]))


# A leg already recorded in OUT is skipped, so a round that died (a refused
# cache drop, a lost ssh) resumes where it stopped instead of re-running - and
# overwriting the .err of - every leg before the failure.
done = set()
if os.path.exists(OUT):
    for line in open(OUT):
        r = json.loads(line)
        done.add((r["m"], r["path"], r["arm"], r["rep"]))
for rep in range(1, REPS + 1):
    for m, path, arms in PLAN:
        picks = damage_picks(WORK, members, SLICE, m, 1000 + m)
        for arm in arms:
            if (m, path, arm, rep) in done:
                log("SKIP m%d-%s-%s-r%d, already in %s" % (m, path, arm, rep, os.path.basename(OUT)))
                continue
            run_leg(m, path, arm, rep, picks)
log("ALL DONE, load %.0f" % uptime())
