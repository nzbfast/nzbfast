#!/usr/bin/env python3
"""Single-member repair phase breakdown - the fixture and damage of the
13 Sep tier rounds' `--single` shape, reduced to one tool and one rung so a
phase split is cheap.  Mirrors ladder.py: same member bytes, slice, parity,
same seeded scattered-slice overwrite, same warm of the recovery set, same
argv.  Adds NZBFAST_REPAIR_TIMING=1 and an optional COLD arm.
"""
import argparse, hashlib, os, platform, random, shutil, subprocess, sys, time

MEMBER_BYTES = 8858370048
SLICE = 4429188
RBLK = 100
GIB = 1 << 30
IS_WIN = os.name == "nt"

def now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(16 << 20)
            if not b: return h.hexdigest()
            h.update(b)

def harness_lines(paths):
    """The round-start harness stamp, `plib.ps1` / `pdrv.py` format exactly:
    one `HARNESS <basename> sha256=... bytes=...` per file the round sources,
    then `HARNESS-RIG <basename>:<sha16>+...` sorted by basename.

    COMPOSED HERE RATHER THAN CALLED FROM `pdrv.harness_facts`, and that is
    the whole reason this exists: this driver tees its log through `say`,
    writing the banked file AND stdout, where `pdrv.harness_facts` uses a bare
    `print` - so calling it would put the stamp on stdout and leave the BANKED
    log unstamped, which is the exact defect being fixed
    (an internal note). Returns the lines for
    the caller to `say`; it prints nothing itself.

    An unreadable file is stamped `unreadable` rather than left off, for
    pdrv.rig_stamp's reason: an absent token is indistinguishable from a
    harness older than this block, which never had one.
    """
    out, parts = [], []
    for p in sorted((os.path.abspath(q) for q in paths), key=os.path.basename):
        nm = os.path.basename(p)
        try:
            sha, n = sha256_file(p), os.path.getsize(p)
        except OSError:
            out.append(f"HARNESS {nm} sha256=unreadable bytes=0")
            parts.append(f"{nm}:unreadable")
            continue
        out.append(f"HARNESS {nm} sha256={sha} bytes={n}")
        parts.append(f"{nm}:{sha[:16]}")
    out.append("HARNESS-RIG " + ("+".join(parts) if parts else "unknown"))
    return out


def warm(paths):
    for p in paths:
        try:
            with open(p, "rb") as f:
                while f.read(64 << 20): pass
        except FileNotFoundError: pass


class RigLock:
    """ladder.py's per-box lock, same path and same ordering rules."""
    def __init__(self, round_name):
        self.round = round_name
        self.path = os.path.join(os.path.expanduser("~"), ".parfast-rig.lock")
        self.fh = None
    def take(self, wait_secs=0):
        """Non-blocking by default; `wait_secs` re-queues like the fleet's
        riglock.py rather than exiting, because this box's queue is three
        lanes deep and a one-shot taker simply loses."""
        deadline = time.time() + wait_secs
        while True:
            try:
                self._take_once(); return
            except SystemExit:
                if time.time() >= deadline: raise
                time.sleep(20)
    def _take_once(self):
        if IS_WIN:
            try: self.fh = open(self.path, "x")
            except FileExistsError:
                raise SystemExit(f"rig lock held: {self.path} - another round owns this box")
        else:
            import fcntl
            for _ in range(5):
                fh = open(self.path, "a")
                try: fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    fh.close()
                    raise SystemExit(f"rig lock held: {self.path} - another round owns this box")
                try: cur = os.stat(self.path).st_ino
                except OSError: cur = None
                if cur == os.fstat(fh.fileno()).st_ino:
                    self.fh = fh; break
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN); fh.close()
            else:
                raise SystemExit(f"rig lock unstable: {self.path}")
        self.fh.seek(0); self.fh.truncate(0)
        self.fh.write(f"pid={os.getpid()} round={self.round} started={now()}\n")
        self.fh.flush()
    def release(self):
        if not self.fh: return
        if IS_WIN:
            self.fh.close()
            try: os.remove(self.path)
            except OSError: pass
        else:
            import fcntl
            try:
                if os.stat(self.path).st_ino == os.fstat(self.fh.fileno()).st_ino:
                    os.unlink(self.path)
            except OSError: pass
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN); self.fh.close()
        self.fh = None
        print(f"RIG-LOCK-RELEASED {self.path}", flush=True)

def gen_payload(pay):
    os.makedirs(pay, exist_ok=True)
    p = os.path.join(pay, "p00.bin")
    if os.path.exists(p) and os.path.getsize(p) == MEMBER_BYTES: return p
    rng = random.Random(20260913 * 1000 + 0)
    with open(p, "wb") as f:
        left = MEMBER_BYTES
        while left > 0:
            n = min(64 << 20, left); f.write(rng.randbytes(n)); left -= n
    return p

def damage(work, nm, m, dseed):
    fl = os.path.getsize(os.path.join(work, nm))
    total = -(-fl // SLICE)
    order = list(range(total)); random.Random(dseed).shuffle(order)
    picks = sorted(order[:m])
    frng = random.Random(dseed + 1)
    with open(os.path.join(work, nm), "r+b") as f:
        for si in picks:
            off = si * SLICE; n = min(SLICE, fl - off)
            f.seek(off); f.write(frng.randbytes(SLICE)[:n])
    return picks, fl

def restore(work, pristine, nm, picks, fl):
    with open(os.path.join(pristine, nm), "rb") as src, open(os.path.join(work, nm), "r+b") as dst:
        for si in picks:
            off = si * SLICE; n = min(SLICE, fl - off)
            src.seek(off); dst.seek(off); dst.write(src.read(n))

def drop_caches(cold_cmd):
    """Run the box's page-cache eviction and return ITS OWN proof line.

    A cold arm that does not report a before/after cache reading is not a
    cold arm - on Windows a fresh fixture copy is still warm, and on Linux a
    drop_caches that silently failed reads exactly like one that worked
    (memory topic nzbfast-windows-standby-purge-and-no-scan-residue)."""
    r = subprocess.run(cold_cmd, shell=True, capture_output=True, text=True)
    return ((r.stdout or "") + (r.stderr or "")).strip().replace("\n", " | ") or "no-proof"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rig", required=True)
    ap.add_argument("--payload", required=True)
    ap.add_argument("--parfast", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--round", default="fixedcost-16sep")
    ap.add_argument("--wait-lock", type=float, default=0, help="seconds to keep re-queueing for the rig lock")
    ap.add_argument("--rungs", default="1,100")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--threads", type=int, default=os.cpu_count())
    ap.add_argument("--file-threads", type=int, default=16)
    ap.add_argument("--cold-cmd", default="", help="shell command that evicts the page cache; empty = warm only")
    ap.add_argument("--verify-too", action="store_true")
    ap.add_argument("--extra-env", default="", help="k=v,k=v applied to every leg")
    a = ap.parse_args()

    rig = RigLock(a.round)
    rig.take(a.wait_lock)
    out = open(a.log, "a")
    def say(s): out.write(s + "\n"); out.flush(); print(s, flush=True)

    extra = dict(kv.split("=", 1) for kv in a.extra_env.split(",") if kv)
    say(f"PHASE-START {now()} host={platform.node()} os={platform.platform()} cores={os.cpu_count()} extra_env={extra}")
    # The HARNESS's own provenance, so a banked round can be traced to the
    # harness revision that wrote it. This driver imports nothing from
    # harness/, so it is the whole harness set.
    for _l in harness_lines([__file__]): say(_l)
    pristine = os.path.join(a.rig, "pristine"); work = os.path.join(a.rig, "work")
    src = gen_payload(a.payload)
    if not os.path.isdir(pristine) or not os.path.exists(os.path.join(pristine, "f.par2")):
        shutil.rmtree(a.rig, ignore_errors=True); os.makedirs(pristine)
        shutil.copy2(src, os.path.join(pristine, "p00.bin"))
        argv = [a.parfast, "c", "-q", f"-t{a.threads}", f"-T{a.file_threads}",
                f"-s{SLICE}", f"-c{RBLK}", "f.par2", "p00.bin"]
        t0 = time.perf_counter()
        r = subprocess.run(argv, cwd=pristine, capture_output=True)
        say(f"CREATE wall={time.perf_counter()-t0:.3f} rc={r.returncode}")
    parfiles = sorted(f for f in os.listdir(pristine) if f.endswith(".par2"))
    gold = sha256_file(os.path.join(pristine, "p00.bin"))
    say(f"FIXTURE member_bytes={MEMBER_BYTES} slice={SLICE} rblk={RBLK} "
        f"source_blocks={-(-MEMBER_BYTES//SLICE)} par2files={len(parfiles)} "
        f"par2bytes={sum(os.path.getsize(os.path.join(pristine,f)) for f in parfiles)} gold={gold[:16]}")
    shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
    for f in ["p00.bin"] + parfiles: shutil.copy2(os.path.join(pristine, f), os.path.join(work, f))

    env = dict(os.environ); env["NZBFAST_REPAIR_TIMING"] = "1"; env.update(extra)
    arms = ["warm"] + (["cold"] if a.cold_cmd else [])

    def leg(kind, m, rep, arm):
        picks, fl = ([], MEMBER_BYTES) if kind == "v" else damage(work, "p00.bin", m, 20260910 + m * 7 + rep)
        proof = ""
        if arm == "cold":
            proof = drop_caches(a.cold_cmd)
        else:
            warm([os.path.join(work, f) for f in ["p00.bin"] + parfiles])
        argv = [a.parfast, kind, "-q", f"-t{a.threads}", f"-T{a.file_threads}", "f.par2"]
        t0 = time.perf_counter()
        p = subprocess.run(argv, cwd=work, capture_output=True, env=env)
        wall = time.perf_counter() - t0
        txt = (p.stderr or b"").decode("utf-8", "replace") + (p.stdout or b"").decode("utf-8", "replace")
        phases = []
        for line in txt.splitlines():
            if "repair-timing" in line or ": +" in line:
                phases.append(line.strip())
        say(f"LEG kind={kind} m={m} rep={rep} arm={arm} wall={wall:.3f} rc={p.returncode} cold_proof=\"{proof}\" ts={now()}")
        for ph in phases: say("  PH " + ph)
        if kind != "v":
            ok = sha256_file(os.path.join(work, "p00.bin")) == gold
            say(f"  GATE restored={ok}")
            if not ok:
                for si in picks: pass
                restore(work, pristine, "p00.bin", picks, fl)
                if sha256_file(os.path.join(work, "p00.bin")) != gold:
                    shutil.copy2(os.path.join(pristine, "p00.bin"), os.path.join(work, "p00.bin"))
        for f in parfiles: shutil.copy2(os.path.join(pristine, f), os.path.join(work, f))
        for f in os.listdir(work):
            if f not in set(["p00.bin"] + parfiles): os.remove(os.path.join(work, f))

    rungs = [int(x) for x in a.rungs.split(",")]
    leg("r", rungs[0], 0, "warm")           # untimed warm-up
    for rep in range(1, a.reps + 1):
        for arm in arms:
            if a.verify_too: leg("v", 0, rep, arm)
            for m in rungs: leg("r", m, rep, arm)
    say(f"PHASE-END {now()}")
    out.close()
    rig.release()

main()
