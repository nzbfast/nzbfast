#!/usr/bin/env python3
"""nttwork.py - where does parfast's single-window transform stop losing to the
fold, on (n_present, n_missing), at a chosen block size? The mac/BSD rig for
an internal note (lane
parfast-ntt-min-work-small-sets-14sep), kept so the next sweep of
`fastpar::NTT_MIN_WORK` does not rebuild it. The Windows half of the same round
is nttwork-i5.ps1 beside it.

FIXTURE, per cell, the 7 Sep 2026 shape (an internal note-
2026-09-07.md): f0.bin carries EXACTLY m blocks and is the only damaged member
(zeroed whole); eight peers carry EXACTLY n_present between them. So the two
counts move independently, and every set is built with m + m/10 recovery
blocks so the exponent span stays ~m and neither the row gate nor the span gate
is what moves. Every block is its own urandom draw.

ARMS (one binary): force = NZBFAST_NTT=force, fold = NZBFAST_NTT=0, mirrored
within each rep; auto = nothing set, rep 1 only, which records the shipped
dispatch's verdict for the cell. No -m: this is the single-window gate.

GATES, every leg, and a leg failing any of them aborts the round:
  - rc 0 and every member SHA-256-identical to the pristine member
  - the damage was real: f0 is re-zeroed and re-hashed before every leg
  - the path, ASSERTED: a force leg must print `ntt syndromes (m=<m>, ...)` and
    a fold leg must not print it at all (NZBFAST_REPAIR_TIMING=1)

LOAD: loadavg and foreign CPU (pdrv.foreign_cpu, i.e. not our process tree) are
taken before AND after every leg and travel on the leg record. The guard WAITS
out a busy box (pdrv's budget) but does not abort a round for it; read the CPU
column, and drop or re-run legs whose foreign reading says so.

RUN:  BIN=target/release/parfast SCRATCH=/dir BLOCK=1048576 \
      CELLS='192:512,768;256:384,512' [REPS=3] [THREADS=] [OUT=legs.jsonl] \
      [LABEL=1m] nttwork.py
READ: nttwork.py read legs.jsonl   (per-cell medians and the crossovers)
"""
import hashlib
import json
import math
import os
import re
import shutil
import statistics as st
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

UNITS = {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}
SYN = re.compile(r"ntt syndromes \(m=(\d+), needed=(\d+), n=(\d+), W=(\d+), threads=(\d+)\): ([0-9.]+)(ns|µs|ms|s)")


def secs(v, u):
    return float(v) * UNITS[u]


def phase(err, label):
    mm = re.search(r"%s: \+([0-9.]+)(ns|µs|ms|s)" % re.escape(label), err)
    return round(secs(mm.group(1), mm.group(2)), 4) if mm else None


# ---------------------------------------------------------------- reader --

def cross(pts):
    """Log-interpolated P at which y (fold minus transform) first turns >= 0,
    reading upward in P. The 7 Sep reader's rule."""
    for (p0, y0), (p1, y1) in zip(pts, pts[1:]):
        if y0 < 0 <= y1:
            return math.exp(math.log(p0) + (0 - y0) / (y1 - y0) * (math.log(p1) - math.log(p0)))
    if pts and pts[0][1] >= 0:
        return "<%d" % pts[0][0]
    if pts and pts[-1][1] < 0:
        return ">%d" % pts[-1][0]
    return None


def read(paths):
    cells = {}
    for p in paths:
        for line in open(p):
            r = json.loads(line)
            cells.setdefault((r["label"], r["m"], r["present"]), {}).setdefault(r["arm"], []).append(r)
    series = {}
    print("%-6s %5s %5s %8s | %8s %8s %6s | %7s %7s %6s | %4s | %s" % (
        "label", "m", "P", "P*m", "cpu_T", "cpu_F", "F/T", "wall_T", "wall_F", "F/T", "n", "auto"))
    for (label, m, pres) in sorted(cells):
        c = cells[(label, m, pres)]
        if "force" not in c or "fold" not in c:
            continue
        cT = st.median(r["cpu"] for r in c["force"])
        cF = st.median(r["cpu"] for r in c["fold"])
        wT = st.median(r["wall"] for r in c["force"])
        wF = st.median(r["wall"] for r in c["fold"])
        auto = ",".join(sorted({r["path"] for r in c.get("auto", [])})) or "-"
        print("%-6s %5d %5d %7dk | %8.2f %8.2f %6.3f | %7.2f %7.2f %6.3f | %4d | %s" % (
            label, m, pres, pres * m // 1000, cT, cF, cF / cT, wT, wF, wF / wT,
            min(len(c["force"]), len(c["fold"])), auto))
        s = series.setdefault((label, m), {"cpu": [], "wall": []})
        s["cpu"].append((pres, math.log(cF / cT)))
        s["wall"].append((pres, math.log(wF / wT)))
    print()
    print("%-6s %5s | %10s %10s | %10s %10s" % ("label", "m", "Pcross CPU", "x m", "Pcross wall", "x m"))
    for (label, m) in sorted(series):
        s = series[(label, m)]
        out = []
        for k in ("cpu", "wall"):
            x = cross(sorted(s[k]))
            if isinstance(x, float):
                out += ["%.0f" % x, "%.0fk" % (x * m / 1000)]
            else:
                out += [str(x), "-"]
        print("%-6s %5d | %10s %10s | %10s %10s" % ((label, m) + tuple(out)))


if len(sys.argv) > 1 and sys.argv[1] == "read":
    read(sys.argv[2:])
    sys.exit(0)

# ---------------------------------------------------------------- driver --

from pdrv import RigLock, bin_facts, box_facts, foreign_cpu, harness_facts, rig_stamp, rig_token  # noqa: E402

BIN = os.path.abspath(os.environ["BIN"])
SCRATCH = os.environ["SCRATCH"]
BLOCK = int(os.environ.get("BLOCK", "1048576"))
REPS = int(os.environ.get("REPS", "3"))
THREADS = os.environ.get("THREADS", "")
LABEL = os.environ.get("LABEL", "%dk" % (BLOCK // 1024))
OUT = os.path.abspath(os.environ.get("OUT", os.path.join(SCRATCH, "legs.jsonl")))
CELLS = []
for part in os.environ["CELLS"].split(";"):
    m, ps = part.split(":")
    CELLS += [(int(m), int(p)) for p in ps.split(",")]
MEMBERS = ["f0.bin"] + ["p%d.bin" % i for i in range(1, 9)]


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def hashes(d):
    with ThreadPoolExecutor(max_workers=9) as ex:
        return dict(zip(MEMBERS, ex.map(lambda n: sha(os.path.join(d, n)), MEMBERS)))


def write_blocks(path, n):
    with open(path, "wb") as f:
        for _ in range(n):
            f.write(os.urandom(BLOCK))


def zero_f0(d, m):
    z = bytes(BLOCK)
    with open(os.path.join(d, "f0.bin"), "r+b") as f:
        for _ in range(m):
            f.write(z)


def build(root, m, pres):
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    if pres % 8:
        raise SystemExit("n_present %d is not a multiple of 8" % pres)
    write_blocks(os.path.join(root, "f0.bin"), m)
    for i in range(1, 9):
        write_blocks(os.path.join(root, "p%d.bin" % i), pres // 8)
    rec = m + m // 10
    t0 = time.monotonic()
    p = subprocess.run([BIN, "c", "-q", "-q", "-s%d" % BLOCK, "-c%d" % rec, "set.par2"] + MEMBERS,
                       cwd=root, capture_output=True)
    if p.returncode != 0:
        raise SystemExit("create failed at m=%d P=%d: %s" % (m, pres, p.stderr[-400:]))
    gold = hashes(root)
    keep = set(os.listdir(root))
    print("CORPUS label=%s m=%d present=%d block=%d recovery=%d create_s=%.2f files=%d"
          % (LABEL, m, pres, BLOCK, rec, time.monotonic() - t0, len(keep)), flush=True)
    return gold, keep


def run_leg(root, gold, keep, m, pres, rep, arm):
    for name in os.listdir(root):
        if name not in keep:
            os.unlink(os.path.join(root, name))
    zero_f0(root, m)
    if sha(os.path.join(root, "f0.bin")) == gold["f0.bin"]:
        raise SystemExit("damage did not take at m=%d P=%d" % (m, pres))
    env = dict(os.environ, NZBFAST_REPAIR_TIMING="1", NZBFAST_NO_ENRICH="1")
    env.pop("NZBFAST_NTT", None)
    if arm == "force":
        env["NZBFAST_NTT"] = "force"
    elif arm == "fold":
        env["NZBFAST_NTT"] = "0"
    argv = [BIN, "r", "-q"] + (["-t" + THREADS] if THREADS else []) + ["set.par2"]
    tag = "%s-m%d-P%d-r%d-%s" % (LABEL, m, pres, rep, arm)
    errp = os.path.join(SCRATCH, "legs", tag + ".err")
    _guard(tag)
    f0, _ = foreign_cpu()
    l0 = os.getloadavg()
    t0 = time.monotonic()
    with open(errp, "wb") as fe:
        proc = subprocess.Popen(argv, cwd=root, stdout=subprocess.DEVNULL, stderr=fe, stdin=subprocess.DEVNULL, env=env)
        _, status, ru = os.wait4(proc.pid, 0)
    wall = time.monotonic() - t0
    l1 = os.getloadavg()
    f1, _ = foreign_cpu()
    rc = os.waitstatus_to_exitcode(status)
    err = open(errp, errors="replace").read()
    got = hashes(root)
    ok = rc == 0 and got == gold
    syn = SYN.findall(err)
    path = "ntt" if syn else "fold"
    if not ok:
        raise SystemExit("GATE-FAIL %s rc=%d sha=%s (stderr %s)" % (tag, rc, got == gold, errp))
    if arm == "force" and (not syn or int(syn[0][0]) != m):
        raise SystemExit("PATH-FAIL %s: force leg did not run the transform over m=%d (%s)" % (tag, m, syn))
    if arm == "fold" and syn:
        raise SystemExit("PATH-FAIL %s: fold leg printed an ntt syndromes line" % tag)
    rec = {
        "label": LABEL, "block": BLOCK, "m": m, "present": pres, "rep": rep, "arm": arm,
        "threads": THREADS or "default",
        # THE STAMP BELONGS IN THE RECORD, not only on the LEG line. margins.py
        # refuses to pool legs whose `rig` differs, and it reads this field: a
        # leg that only PRINTS its stamp reads `?` there, so the guard sees one
        # distinct value and passes trivially - inert on every mac leg until
        # 16 Sep 2026 (owed item 1 of
        # an internal note). `rig_stamp` and not
        # `rig_token`: the token is the printable form, with a leading space and
        # a first-writer-wins suppression, which is not a JSON value.
        #
        # NO `stripe_w` OR `env` HERE, though the x86 record carries both.
        # `stripe_w` there is the REQUESTED pin (`NZBFAST_NTT_W` out of an arm's
        # env, `default` when unpinned) and `env` is that arm-env joined; this
        # driver's arms set only NZBFAST_NTT and pin no width, so both would be
        # constants. The width this harness actually measures is `ntt_W`, read
        # off the force arm's `ntt syndromes` line below - a second name for it
        # would be the second copy of a single-source value this repo refuses.
        "rig": rig_stamp(),
        "rc": rc, "ok": ok, "path": path,
        "wall": round(wall, 3), "cpu": round(ru.ru_utime + ru.ru_stime, 3),
        "peak_mb": round(ru.ru_maxrss / 1048576.0, 0),
        "load_before": [round(x, 2) for x in l0], "load_after": [round(x, 2) for x in l1],
        "foreign_before": round(f0, 1), "foreign_after": round(f1, 1),
        "ffs_s": phase(err, "feed+fold+solve"),
        "syn_s": round(sum(secs(v, u) for (*_, v, u) in syn), 4) if syn else None,
        "ntt_n": int(syn[0][2]) if syn else None, "ntt_W": int(syn[0][3]) if syn else None,
        "ntt_threads": int(syn[0][4]) if syn else None,
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("LEG %-28s rc=%d sha=OK path=%-4s wall=%7.3f cpu=%8.3f ffs=%s syn=%s n=%s load=%.1f/%.1f foreign=%.0f/%.0f%s"
          % (tag, rc, path, wall, rec["cpu"], rec["ffs_s"], rec["syn_s"], rec["ntt_n"],
             l0[0], l1[0], f0, f1, rig_token()), flush=True)


def main():
    lock = RigLock(os.path.join(SCRATCH, "nttwork.lock"))
    import pdrv
    pdrv.require_quiet_box = lambda where, tries=None, wait=None: _guard(where)
    lock.take()
    try:
        box_facts()
        bin_facts([BIN])
        harness_facts()
        os.makedirs(os.path.join(SCRATCH, "legs"), exist_ok=True)
        print("ROUND label=%s block=%d reps=%d threads=%s cells=%d out=%s ts=%s"
              % (LABEL, BLOCK, REPS, THREADS or "default", len(CELLS), OUT, pdrv.utcnow()), flush=True)
        for (m, pres) in CELLS:
            root = os.path.join(SCRATCH, "c-%s-m%d-P%d" % (LABEL, m, pres))
            gold, keep = build(root, m, pres)
            for rep in range(1, REPS + 1):
                order = ["force", "fold"] if rep % 2 else ["fold", "force"]
                if rep == 1:
                    order.append("auto")
                for arm in order:
                    run_leg(root, gold, keep, m, pres, rep, arm)
            shutil.rmtree(root)
        print("ALL DONE ts=%s" % pdrv.utcnow(), flush=True)
    finally:
        lock.release()


def _guard(where):
    """pdrv's wait-then-abort guard, minus the abort: waits out a busy box on
    pdrv's budget, then carries on with a WARN, because the reading travels on
    the leg record either way and this round reads CPU."""
    import pdrv
    # Two tries, not pdrv's ten: on a desktop whose idle baseline sits AT the
    # ceiling (14 Sep 2026: ~330% of a 320% ceiling from indexers, Time
    # Machine and browsers), ten tries is five minutes a leg over ~430 legs.
    tries = int(os.environ.get("NTW_QUIET_TRIES", "2"))
    for attempt in range(tries + 1):
        total, top = foreign_cpu()
        if total < pdrv.foreign_ceiling():
            return
        if attempt < tries:
            print("BOX-BUSY-WAIT try=%d foreign_cpu=%.0f%% at=%s" % (attempt + 1, total, where), flush=True)
            time.sleep(pdrv.QUIET_WAIT)
    print("WARN-BUSY-CONTINUE foreign_cpu=%.0f%% at=%s top=%s" % (total, where, top), flush=True)


if __name__ == "__main__":
    main()
