#!/usr/bin/env python3
"""memladder.py - parfast repair under a memory budget: fold vs transform vs auto.

Written for an internal note and
kept here (14 Sep 2026, lane parfast-small-budget-dispatch-14sep) so the next
round does not rebuild it.

FIXTURE (build once under $SCRATCH/fix; the random payload is ~1 GiB):

    mkdir -p fix/pristine && cd fix/pristine
    for i in $(seq -w 1 16); do dd if=/dev/urandom of=m$i.bin bs=1048576 count=64; done
    shasum -a 256 m*.bin > ../gold.sha
    parfast c -q -s65536 -c4096 set.par2 m*.bin
    mkdir ../work && cp * ../work/

(n = 16,384 source blocks at 64 KiB, 4,096 recovery.)

RUN:   BIN=/path/to/parfast SCRATCH=/dir [RUNGS=..] [ARMS=fold,force,auto]
       [BUDGETS=128,big] [REPS=2] [THREADS=4] [TAG=x] [OUT=legs.jsonl]
       [EXTRA_ENV='{"NZBFAST_NTT_W":"128"}'] memladder.py

  peak:    `peak_mb` is ru_maxrss; `footprint_mb` / `rss_over_footprint_mb` /
           `repair_work_mb` come from the mem-floor line (None when the binary
           prints none). Quote the footprint beside ru_maxrss on macOS.
  arms:    fold = NZBFAST_NTT=0, force = NZBFAST_NTT=force, auto = nothing set
           THE ORDER ROTATES ONE STEP A REP (17 Sep 2026) and is banked:
           `arm_order=rotating-by-rep` on the ROUND line, `arm_pos=` on every
           LEG line and in every record. Until then `fold` ran FIRST at every
           rung, rep and budget, and this driver's deliverable is a CROSSOVER
           RUNG - the one place in this repo where a percent of position drift
           moves the ANSWER rather than a digit, because at a crossover the
           arms are equal by construction. The 14 Sep m=192 `-m128` cell was
           decided by 0.93% (fold 10.7 against force 10.8 CPU-s). Set REPS to
           a multiple of len(ARMS) or the rotation does not balance; the
           driver warns when it is not.
  quiet:   guarded at `round-start` AND before EVERY leg with
           `pdrv.require_quiet_box`, which waits ten times thirty seconds and
           then exits 18 rather than time against somebody else's load, and
           `foreign_cpu` is banked either side of every leg (`fgn=` on the LEG
           line, `foreign_cpu` / `foreign_after` / `foreign_top` in the
           record). ADDED 17 Sep 2026 and it was NOT here before: this driver
           imports the damage helpers from `pdrv` and defines its own
           `run_leg`, so it never reached the guard, and the arm-order census
           recorded it as "quiet-gated (pdrv)" on the strength of the import
           alone. Still take the rig lock around the round - the guard answers
           "is the box quiet", never "may I have it".
           `force` is a CPU ceiling, NEVER a memory reference: it retains the
           whole budget and spends the worker arenas on top, unpriced, where
           `auto` prices them inside it - 34-145 MiB over `auto` at -m128 on
           this fixture (an internal note)
  budgets: a number is `-m<N>` (MiB; 128 is what a 512 MB box derives as
           RAM/4), `big` is no -m at all

Every leg is damaged with pdrv's scattered picks (seed 1000+m, identical across
arms and binaries at a rung), SHA-256 gated against the pristine members - so
`ok` IS "the output bytes are the pristine bytes" - and restored by slice.
Timing lines come from NZBFAST_REPAIR_TIMING=1 stderr, kept per leg under
$SCRATCH/legs/.

A/A:   memladder.py aa BASE.jsonl NEW.jsonl [BUDGET]
  prints the DISPATCH per (m, budget, arm) for both files - syndrome path, NTT
  stripe width and threads, windows, slabs, Forney stripe uses, output gate -
  and exits 1 if any differs. Timings are not compared.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

DECISION = ("path", "ntt_w", "ntt_threads", "ntt_windows", "slabs", "slab_width", "stripe_uses", "ok")


def aa(base_path, new_path, budget=None):
    def load(p):
        out = {}
        for line in open(p):
            r = json.loads(line)
            if budget and r["budget"] != budget:
                continue
            out.setdefault((r["m"], r["budget"], r["arm"]), r)  # first rep
        return out

    a, b = load(base_path), load(new_path)
    bad = 0
    for key in sorted(set(a) | set(b)):
        ra, rb = a.get(key), b.get(key)
        da = tuple(ra.get(k) for k in DECISION) if ra else None
        db = tuple(rb.get(k) for k in DECISION) if rb else None
        same = da == db
        bad += not same
        print("%-5s m=%-5d %-4s %-5s  base=%s  new=%s" % ("same" if same else "DIFF", key[0], key[1], key[2], da, db))
    print("A/A: %d cell(s) differ" % bad)
    return 1 if bad else 0


if len(sys.argv) > 1 and sys.argv[1] == "aa":
    sys.exit(aa(*sys.argv[2:]))

from pdrv import apply_damage, damage_picks, foreign_cpu, require_quiet_box, restore_slices  # noqa: E402

S = os.environ["SCRATCH"]
BIN = os.environ["BIN"]
FIX = os.environ.get("FIX", "fix")
PRISTINE = os.path.join(S, FIX, "pristine")
WORK = os.path.join(S, FIX, "work")
SLICE = int(os.environ.get("SLICE", "65536"))
EXTRA_ENV = json.loads(os.environ.get("EXTRA_ENV", "{}"))
TAG = os.environ.get("TAG", "")
OUT = os.environ.get("OUT", "legs.jsonl")
LOGDIR = os.path.join(S, "legs")
os.makedirs(LOGDIR, exist_ok=True)

RUNGS = [int(x) for x in os.environ.get("RUNGS", "192,256,384,512,768,1024,1536,2048,3072,4096").split(",")]
REPS = int(os.environ.get("REPS", "2"))
ARMS = os.environ.get("ARMS", "fold,force,auto").split(",")
BUDGETS = os.environ.get("BUDGETS", "128,big").split(",")
THREADS = os.environ.get("THREADS", "4")
ARM_ORDER_LABEL = "rotating-by-rep"

members = sorted(f for f in os.listdir(PRISTINE) if f.endswith(".bin"))
gold = {}
for line in open(os.path.join(S, FIX, "gold.sha")):
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


def secs(v, u):
    return float(v) * {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}[u]


def run_leg(m, rep, budget, arm, picks, pos):
    env = dict(os.environ, NZBFAST_REPAIR_TIMING="1")
    env.update(EXTRA_ENV)
    if arm == "fold":
        env["NZBFAST_NTT"] = "0"
    elif arm == "force":
        env["NZBFAST_NTT"] = "force"
    argv = [BIN, "r", "-t" + THREADS, "-q"]
    if budget != "big":
        argv.append("-m" + budget)
    argv.append("set.par2")
    tag = "m%d-%s-%s-r%d%s" % (m, budget, arm, rep, ("-" + TAG) if TAG else "")
    errp = os.path.join(LOGDIR, tag + ".err")
    # Refuse rather than publish a number measured against somebody else's
    # load, and bank what WAS on the box either side of the leg - the
    # `pdrv.py:637` shape every other timing driver on this fleet uses. This
    # was missing until 17 Sep 2026 and nothing said so: the arm-order census
    # recorded this driver as "quiet-gated (pdrv)" on the strength of the
    # import above, and the re-run lane had to `ps` the box by hand to find
    # spotlightknowledged.updater at 99% of a core through all 576 of its legs.
    # `load_before`/`load_after` stay, because a load average and a foreign-CPU
    # sample answer different questions: the first is the box's queue over the
    # last minute, the second is WHO is on it right now.
    require_quiet_box(tag)
    foreign_before, _ = foreign_cpu()
    apply_damage(WORK, members, SLICE, picks, 1)
    l0 = os.getloadavg()[0]
    t0 = time.monotonic()
    with open(errp, "wb") as fe:
        p = subprocess.Popen(argv, cwd=WORK, stdout=subprocess.DEVNULL, stderr=fe, env=env)
        _, status, ru = os.wait4(p.pid, 0)
    wall = time.monotonic() - t0
    rc = os.waitstatus_to_exitcode(status)
    l1 = os.getloadavg()[0]
    foreign_after, top_after = foreign_cpu()
    ok = rc == 0 and gate()
    restore_slices(WORK, PRISTINE, members, SLICE, picks)
    if not gate():
        raise SystemExit("restore failed at " + tag)
    err = open(errp, errors="replace").read()

    def phase(label):
        mm = re.search(r"%s: \+([0-9.]+)(µs|ms|s)" % re.escape(label), err)
        return secs(mm.group(1), mm.group(2)) if mm else None

    ntt_syn = re.findall(r"ntt syndromes \(m=\d+, needed=\d+, n=(\d+), W=(\d+), threads=(\d+)\): ([0-9.]+)(µs|ms|s)", err)
    ntt_windows = re.findall(r"ntt window \((\d+) bytes, (\d+) slices, (\w+)\): ([0-9.]+)(µs|ms|s)", err)
    slabs = re.search(r"in (\d+) slab\(s\) of (\d+) B", err)
    prof = re.findall(r"ntt profile \(inclusive thread-seconds\): depth0 ([0-9.]+) depth1 ([0-9.]+) depth2 ([0-9.]+) leaves ([0-9.]+)", err)
    bs = re.search(r"back-substitution \(([^)]*)\): ([0-9.]+)(µs|ms|s)", err)
    forney = re.search(r"forney solve: ([0-9.]+)(µs|ms|s|ns) over (\d+) solve", err)
    uses = [int(x) for x in re.findall(r"(\d+) stripe use", err)]
    # ru_maxrss alone misleads on macOS: freed arena pages can stay resident
    # without being charged to the footprint (+163 MiB ru_maxrss but +33 MB
    # footprint on the in-place m=4096 -m128 cell, SOLVE-WINDOW-HALVING section 7).
    floor = re.search(r"mem-floor: sampled peak rss .*?footprint (\d+) MB · rss over footprint (\d+) MB · "
                      r"repair work (\d+) MB \(own peak (\d+)\)", err)
    rec = {
        "tag": TAG, "bin": BIN, "extra_env": EXTRA_ENV, "m": m, "rep": rep, "budget": budget, "arm": arm,
        "rc": rc, "ok": ok, "wall": round(wall, 2), "cpu": round(ru.ru_utime + ru.ru_stime, 2),
        "arm_pos": pos, "arm_order": ARM_ORDER_LABEL,
        "peak_mb": round(ru.ru_maxrss / 1048576.0, 0),  # macOS reports bytes
        "footprint_mb": int(floor.group(1)) if floor else None,
        "rss_over_footprint_mb": int(floor.group(2)) if floor else None,
        "repair_work_mb": int(floor.group(3)) if floor else None,
        "repair_work_own_peak_mb": int(floor.group(4)) if floor else None,
        "load_before": round(l0, 1), "load_after": round(l1, 1),
        "foreign_cpu": round(foreign_before, 1), "foreign_after": round(foreign_after, 1),
        "foreign_top": " ".join("%s(%d)=%.0f%%" % (c, pid, pc) for pc, pid, c in top_after[:2]),
        "feed_fold_solve": phase("feed+fold+solve"),
        "final_verify": phase("final verify"),
        "path": "ntt" if ntt_syn else "fold",
        "transform_s": round(sum(secs(v, u) for (_, _, _, v, u) in ntt_syn), 3) if ntt_syn else None,
        "transform_calls": len(ntt_syn),
        "ntt_w": sorted({int(w) for (_, w, _, _, _) in ntt_syn}),
        "ntt_threads": sorted({int(t) for (_, _, t, _, _) in ntt_syn}),
        "ntt_windows": len(ntt_windows),
        "window_slices": [int(s) for (_, s, _, _, _) in ntt_windows][:3],
        "slabs": int(slabs.group(1)) if slabs else 1,
        "slab_width": int(slabs.group(2)) if slabs else SLICE,
        "backsub": bs.group(1) if bs else None,
        "backsub_s": round(secs(bs.group(2), bs.group(3)), 3) if bs else None,
        "forney_s": round(secs(forney.group(1), forney.group(2)), 3) if forney else None,
        "stripe_uses": max(uses) if uses else None,
        "profile": [[float(x) for x in t] for t in prof],
    }
    with open(os.path.join(S, OUT), "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("LEG %-26s arm_pos=%d rc=%d ok=%s wall=%6.2f cpu=%7.2f peak=%5.0fMB fp=%sMB path=%-4s W=%s slabs=%d win=%d uses=%s forney=%s load=%.1f/%.1f fgn=%.0f/%.0f%%"
          % (tag, pos, rc, ok, wall, rec["cpu"], rec["peak_mb"], rec["footprint_mb"], rec["path"], rec["ntt_w"], rec["slabs"],
             rec["ntt_windows"], rec["stripe_uses"], rec["forney_s"], l0, l1, foreign_before, foreign_after), flush=True)
    return rec


if __name__ == "__main__":
    if not gate():
        raise SystemExit("work copy is not pristine at start")
    require_quiet_box("round-start")
    print("ROUND tag=%s bin=%s arm_order=%s arms=%s rungs=%s budgets=%s reps=%d threads=%s slice=%d load=%.2f/%.2f/%.2f"
          % (TAG or "(none)", BIN, ARM_ORDER_LABEL, ",".join(ARMS), ",".join(str(r) for r in RUNGS),
             ",".join(BUDGETS), REPS, THREADS, SLICE, *os.getloadavg()), flush=True)
    if REPS % len(ARMS):
        print("WARN reps=%d is not a multiple of %d arms, so the rotation does not balance"
              % (REPS, len(ARMS)), flush=True)
    for rep in range(1, REPS + 1):
        # Rotate one step a rep, so no arm keeps a position in the order. A
        # FIXED order is what fabricated a +4.29% cpu delta on 17 Sep 2026
        # with the silent control arm reading +4.15% beside it
        # (an internal note; the crossover this
        # driver hunts is the one place a percent of drift moves the ANSWER,
        # because at a crossover the two arms are equal by construction).
        # NEVER reversed(): with three arms that leaves the middle one - here
        # `force`, the arm under test - in the middle forever.
        order = ARMS[(rep - 1) % len(ARMS):] + ARMS[:(rep - 1) % len(ARMS)]
        for m in RUNGS:
            picks = damage_picks(WORK, members, SLICE, m, 1000 + m)
            for budget in BUDGETS:
                for pos, arm in enumerate(order):
                    run_leg(m, rep, budget, arm, picks, pos)
    print("ALL DONE")
