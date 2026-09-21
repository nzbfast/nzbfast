#!/usr/bin/env python3
"""adoptfloor.py - the end-to-end half of the adoption chunk-floor round
(claim `adoption-fanout-constants-measure-16sep`,
an internal note). Two real parfast
release binaries differing ONLY in `min_scan_chunk`'s block multiple, over one
fixture, reading the `adoption` phase mark. No knob is added to production for
this, which is why the arms are binaries.

FIXTURE, the 7 Sep shape (nttwork.py beside this): f0.bin carries exactly m
blocks and is the only damaged member (zeroed whole), eight peers, m + m/10
recovery. The point of THIS round is the large-block corner the within-candidate
split misses - BLOCK=16 MiB with m=12, a 192 MiB member of 12 blocks - so the
zeroed f0 is the single unidentified candidate the sliding scan walks, and it
donates nothing, which is the deterministic full-pass case.

GATES, every leg, and a leg failing any aborts the round: rc 0, every member
SHA-256-identical to pristine, and the damage re-applied and re-checked before
every leg.

LOAD: loadavg is taken before and after every leg and travels on the record.
Read it. A wall or phase figure from a box at several times oversubscription is
a FLOOR, not a best case.

RUN:  A=parfast-M8 B=parfast-M4 SCRATCH=/dir [BLOCK=16777216] [M=12] [REPS=5] \
      [OUT=legs.jsonl] adoptfloor.py
READ: adoptfloor.py read legs.jsonl
"""
import hashlib, json, os, re, shutil, statistics as st, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pdrv  # noqa: E402

UNITS = {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}


def phase(err, label):
    m = re.search(r"%s: \+([0-9.]+)(ns|µs|ms|s)" % re.escape(label), err)
    return round(float(m.group(1)) * UNITS[m.group(2)], 5) if m else None


def read(paths):
    legs = [json.loads(l) for p in paths for l in open(p)]
    by = {}
    for r in legs:
        by.setdefault(r["arm"], []).append(r)
    print("%-6s %4s | %9s %9s %9s | %8s %8s | %s" % (
        "arm", "n", "adopt med", "adopt min", "adopt max", "wall med", "wall min", "load"))
    for arm in sorted(by):
        rs = [r for r in by[arm] if r["adoption"] is not None]
        if not rs:
            print("%-6s %4d | no `adoption` mark on any leg" % (arm, len(by[arm])))
            continue
        a = sorted(r["adoption"] for r in rs)
        w = sorted(r["wall"] for r in rs)
        print("%-6s %4d | %9.4f %9.4f %9.4f | %8.3f %8.3f | %.0f-%.0f" % (
            arm, len(rs), st.median(a), a[0], a[-1], st.median(w), w[0],
            min(r["load0"] for r in rs), max(r["load0"] for r in rs)))
    if len(by) == 2:
        (x, xs), (y, ys) = sorted(by.items())
        ax = sorted(r["adoption"] for r in xs if r["adoption"] is not None)
        ay = sorted(r["adoption"] for r in ys if r["adoption"] is not None)
        if ax and ay:
            print("\n%s / %s on the adoption mark: %.2fx on the median, %.2fx on the min"
                  % (x, y, st.median(ax) / st.median(ay), ax[0] / ay[0]))


if len(sys.argv) > 1 and sys.argv[1] == "read":
    read(sys.argv[2:])
    sys.exit(0)

A, B = os.path.abspath(os.environ["A"]), os.path.abspath(os.environ["B"])
SCRATCH = os.environ["SCRATCH"]
BLOCK = int(os.environ.get("BLOCK", 16 << 20))
M = int(os.environ.get("M", "12"))
REPS = int(os.environ.get("REPS", "5"))
OUT = os.path.abspath(os.environ.get("OUT", os.path.join(SCRATCH, "legs.jsonl")))
ARMS = {"M8": A, "M4": B}
MEMBERS = ["f0.bin"] + ["p%d.bin" % i for i in range(1, 9)]
root = os.path.join(SCRATCH, "corpus")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 22), b""):
            h.update(c)
    return h.hexdigest()


def hashes(d):
    with ThreadPoolExecutor(max_workers=9) as ex:
        return dict(zip(MEMBERS, ex.map(lambda n: sha(os.path.join(d, n)), MEMBERS)))


def blocks(p, n):
    with open(p, "wb") as f:
        for _ in range(n):
            f.write(os.urandom(BLOCK))


if os.path.exists(root):
    shutil.rmtree(root)
os.makedirs(root)
blocks(os.path.join(root, "f0.bin"), M)
for i in range(1, 9):
    blocks(os.path.join(root, "p%d.bin" % i), 1)
rec = M + M // 10
p = subprocess.run([A, "c", "-q", "-q", "-s%d" % BLOCK, "-c%d" % rec, "set.par2"] + MEMBERS,
                   cwd=root, capture_output=True)
if p.returncode != 0:
    raise SystemExit("create failed: %s" % p.stderr[-400:])
gold = hashes(root)
keep = set(os.listdir(root))
# The HARNESS's own provenance, and the round-start twin of the
# per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
# banked log cannot be traced to the harness revision that wrote
# it (census an internal note).
pdrv.harness_facts()
print("CORPUS block=%d m=%d recovery=%d files=%d" % (BLOCK, M, rec, len(keep)), flush=True)

out = open(OUT, "a")
for rep in range(REPS):
    order = ["M8", "M4"] if rep % 2 == 0 else ["M4", "M8"]
    for arm in order:
        for n in os.listdir(root):
            if n not in keep:
                os.unlink(os.path.join(root, n))
        with open(os.path.join(root, "f0.bin"), "r+b") as f:
            for _ in range(M):
                f.write(bytes(BLOCK))
        if sha(os.path.join(root, "f0.bin")) == gold["f0.bin"]:
            raise SystemExit("damage did not take")
        env = dict(os.environ, NZBFAST_REPAIR_TIMING="1", NZBFAST_NO_ENRICH="1")
        errp = os.path.join(SCRATCH, "r%d-%s.err" % (rep, arm))
        l0 = os.getloadavg()[0]
        t0 = time.monotonic()
        with open(errp, "wb") as fe:
            rc = subprocess.call([ARMS[arm], "r", "-q", "set.par2"], cwd=root,
                                 stdout=subprocess.DEVNULL, stderr=fe, env=env)
        wall = time.monotonic() - t0
        err = open(errp, errors="replace").read()
        if rc != 0 or hashes(root) != gold:
            raise SystemExit("GATE-FAIL rep=%d arm=%s rc=%d (stderr %s)" % (rep, arm, rc, errp))
        r = {"arm": arm, "rep": rep, "block": BLOCK, "m": M, "rc": rc, "wall": round(wall, 3),
             "adoption": phase(err, "adoption"), "load0": l0, "load1": os.getloadavg()[0]}
        out.write(json.dumps(r) + "\n")
        out.flush()
        print("LEG " + json.dumps(r), flush=True)
