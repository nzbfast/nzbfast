#!/usr/bin/env python3
"""oram-mac-lock.py - TODO 345 D: does a Mac's mapped create collapse once the
member exceeds available memory, and does the macOS reading gate it?

    harness/oram-mac-lock.py --bin <parfast> --dir <scratch dir> \
        --plan 0:main:2,40:main:2,40:fitoff:1,20:main:3,20:fitoff:2 \
        [--gib 24] [--pct 5] [--par2 /opt/homebrew/bin/par2] [--tag macram1]

The macOS counterpart of oramx.ps1 + ramlock.ps1 (the Windows sweep1/cand1
rounds). A plan cell is `avail_gb:arm:reps`. `avail_gb` 0 runs with no
lock; otherwise ramlock-mac.py wires memory until the shipped reading sits
at that many GB, ONE lock per level (all of a level's cells share it, and
it is released before the next level is pinned). Arms, all ONE binary:

- main    the binary's default. On macOS that was the mapped route while
          `available_ram()` was None; since 16 Sep 2026 it is the GATE, so
          on a post-flip binary read this arm as the gated one.
- macread `NZBFAST_MACOS_AVAILABLE_RAM=1`: the gate over the macOS reading -
          the arm TODO 345 D's knee round was about. SINCE 16 SEP 2026 THAT
          VARIABLE IS GONE and the reading is the Mac default, so against a
          binary built after the flip this arm is `main` by another name.
          The airknee1 logs here are from the binary that still read it.
          Use `fitoff` for the mapped route and `nomap` for the copied
          windows; both are still live overrides.
- fitoff  `NZBFAST_PAR2GEN_MAP_FIT=off`: the mapped route whatever memory says
- nomap   `NZBFAST_PAR2GEN_MAP=0`: the copied windows whatever memory says

ON A BIG-RAM MAC THE PIN IS THE WRONG TOOL (section 6.3 of the research
record: it wires ever slower, and a small-machine level is hours away).
On a Mac whose RAM is smaller than the member, run every cell at level 0:
no pin, the member simply does not fit.

Within a level the arms interleave rep by rep, mirrored (ABBA). Before every
leg the member is read end to end, so each leg starts from the same cache
state, as oram.ps1 does.

It takes the per-box rig lock (~/.parfast-rig.lock) after waiting out any
lock or running tool, the same rule as mqueue.py and oram-mac-ab.py, and
releases it (and any memory lock) however it exits. Per leg: `uptime`
before AND after; wall, user and system CPU, max RSS and hard page faults
from `/usr/bin/time -l`; the system-wide page-in delta in GB (what the
leg read back off the disk through faults and reads, the neighbours'
included); both available readings before the leg (`avail` = the shipped
sum, `common` = free + inactive + speculative + purgeable) and the shipped
one after; compressor occupancy and the swapout delta; whether the gate
refused the mapping; every `NZBFAST_REPAIR_TIMING` line; and a digest over
the recovery set's per-file SHA-256. One set digest per member is the
identity line, and the last set is verified by the binary and par2cmdline.

A leg is killed at --leg-timeout (its own process group, by pid) and logged
rc=timeout rather than stalling the round on a collapse.
"""
import argparse
import hashlib
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pdrv  # noqa: E402
LOCK = os.path.expanduser("~/.parfast-rig.lock")
TOOLS = ("parfast", "par2turbo", "par2j", "par2")
ARMS = {
    "main": {},
    "macread": {"NZBFAST_MACOS_AVAILABLE_RAM": "1"},
    "fitoff": {"NZBFAST_PAR2GEN_MAP_FIT": "off"},
    "nomap": {"NZBFAST_PAR2GEN_MAP": "0"},
}


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def busy():
    if os.path.exists(LOCK):
        return "lock"
    out = subprocess.run(["ps", "-Ao", "pid=,comm="], capture_output=True, text=True).stdout
    for line in out.splitlines():
        f = line.split(None, 1)
        if len(f) == 2 and os.path.basename(f[1].strip()) in TOOLS:
            return "tool %s pid=%s" % (os.path.basename(f[1].strip()), f[0])
    return None


def load():
    out = subprocess.run(["uptime"], capture_output=True, text=True).stdout
    m = re.search(r"load averages?: ([\d.]+)[, ]+([\d.]+)[, ]+([\d.]+)", out)
    return "/".join(m.groups()) if m else "?"


def vm():
    out = subprocess.run(["vm_stat"], capture_output=True, text=True).stdout
    page = int(re.search(r"page size of (\d+) bytes", out).group(1))
    d = {}
    for line in out.splitlines()[1:]:
        m = re.match(r'\s*"?([^":]+)"?:\s+(\d+)\.?\s*$', line)
        if m:
            d[m.group(1).strip()] = int(m.group(2))
    return page, d


def avail(page, d):
    return (d["Pages free"] + d["File-backed pages"] + d["Pages purgeable"]) * page


def common(page, d):
    return (d["Pages free"] + d["Pages inactive"] + d["Pages speculative"] + d["Pages purgeable"]) * page


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def warm(path):
    with open(path, "rb") as f:
        while f.read(64 << 20):
            pass


def clear_sets(d):
    for p in os.listdir(d):
        if p.startswith("k") and p.endswith(".par2"):
            os.remove(os.path.join(d, p))


def plan_levels(plan):
    """[(level, [(arm, rep), ...])] in first-appearance order, arms mirrored."""
    levels = []
    for cell in plan.split(","):
        lv, arm, reps = cell.split(":")
        lv, reps = float(lv), int(reps)
        if arm not in ARMS:
            raise SystemExit("unknown arm %r" % arm)
        for entry in levels:
            if entry[0] == lv:
                entry[1].append((arm, reps))
                break
        else:
            levels.append((lv, [(arm, reps)]))
    out = []
    for lv, arms in levels:
        legs = []
        for rep in range(1, max(r for _, r in arms) + 1):
            order = arms if rep % 2 else list(reversed(arms))
            legs.extend((arm, rep) for arm, reps in order if rep <= reps)
        out.append((lv, legs))
    return out


class Locker:
    """One ramlock-mac.py for one level. It is killed, by its own pid, on
    EVERY path out of here that is not a ready lock: the first version
    raised without doing so and orphaned a pin holding 386 GB wired (see
    ramlock-mac.py's header)."""

    WIRE_SECS = 240

    def __init__(self, tag, level, scratch):
        self.ready = os.path.join(scratch, "%s-lock-ready.txt" % tag)
        self.stop = os.path.join(scratch, "%s-lock-stop.txt" % tag)
        self.trace = os.path.join(scratch, "%s-lock-l%g.trace" % (tag, level))
        for p in (self.ready, self.stop):
            if os.path.exists(p):
                os.remove(p)
        with open(self.trace, "w") as tf:
            self.proc = subprocess.Popen([
                sys.executable, os.path.join(HERE, "ramlock-mac.py"), "--target-gb", str(level),
                "--ready", self.ready, "--stop", self.stop, "--parent-pid", str(os.getpid()),
                "--wire-secs", str(self.WIRE_SECS)], stderr=tf)
        try:
            t0 = time.time()
            while not os.path.exists(self.ready):
                if self.proc.poll() is not None or time.time() - t0 > self.WIRE_SECS + 60:
                    raise RuntimeError("ramlock-mac did not come ready (rc=%s)" % self.proc.poll())
                time.sleep(1)
            time.sleep(0.5)
            with open(self.ready) as f:
                self.report = f.read().strip()
        except BaseException:
            self.release()
            raise
        m = re.search(r"avail_after_gb=([\d.]+)", self.report)
        self.reached = bool(m) and float(m.group(1)) <= level + 1.0

    def alive(self):
        return self.proc.poll() is None

    def release(self):
        with open(self.stop, "w") as f:
            f.write("stop")
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--gib", type=int, default=24)
    ap.add_argument("--pct", type=int, default=5)
    ap.add_argument("--par2", default="")
    ap.add_argument("--tag", default="macram")
    ap.add_argument("--leg-timeout", type=int, default=900)
    a = ap.parse_args()
    # A SIGTERM must still run the `finally` that stops the memory pin and
    # frees the rig lock; Python's default for it is to die on the spot.
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(143))
    os.makedirs(a.dir, exist_ok=True)
    binp = os.path.abspath(a.bin)
    levels = plan_levels(a.plan)
    print("BIN path=%s sha256=%s" % (binp, sha256(binp)), flush=True)
    # The HARNESS's own provenance, and the round-start twin of the
    # per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
    # banked log cannot be traced to the harness revision that wrote
    # it (census an internal note).
    pdrv.harness_facts()
    print("PLAN %s" % " | ".join("%g: %s" % (lv, " ".join("%s#%d" % l for l in legs)) for lv, legs in levels), flush=True)

    waited = 0
    while busy():
        if waited % 600 == 0:
            print("ORAMLOCK-WAIT %s (%dm)" % (busy(), waited // 60), flush=True)
        time.sleep(60)
        waited += 60
    fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    os.write(fd, ("round=oram-mac-lock tag=%s pid=%d started=%s" % (a.tag, os.getpid(), utc())).encode())
    os.close(fd)
    print("RIG-LOCK-TAKEN %s %s" % (LOCK, utc()), flush=True)
    locker = None
    try:
        name = "f%dg.bin" % a.gib
        path = os.path.join(a.dir, name)
        want = a.gib << 30
        if os.path.exists(path) and os.path.getsize(path) == want:
            print("FIXTURE-KEPT %s" % path, flush=True)
        else:
            t0 = time.time()
            with open(path, "wb") as f:
                left = want
                while left:
                    n = min(64 << 20, left)
                    f.write(os.urandom(n))
                    left -= n
            print("FIXTURE-WROTE %s bytes=%d secs=%.1f" % (path, want, time.time() - t0), flush=True)

        digests = set()
        for lv, legs in levels:
            if lv > 0:
                page, d = vm()
                if avail(page, d) <= lv * 1e9:
                    print("LEVEL-SKIP level=%g avail already %.2f GB" % (lv, avail(page, d) / 1e9), flush=True)
                    continue
                locker = Locker(a.tag, lv, a.dir)
                print("LOCK level=%g reached=%d %s ts=%s" % (lv, locker.reached, locker.report, utc()), flush=True)
                if not locker.reached:
                    print("LEVEL-UNREACHED level=%g - the pin stopped short of the target, so this level "
                          "and every lower one would be timed at a memory figure nobody asked for; "
                          "ending the round" % lv, flush=True)
                    break
            for arm, rep in legs:
                if locker and not locker.alive():
                    print("ORAMLOCK-FAIL the memory lock exited mid-level", flush=True)
                    return 8
                clear_sets(a.dir)
                warm(path)
                env = dict(os.environ)
                for k in list(env):
                    if k.startswith("NZBFAST_"):
                        del env[k]
                env["NZBFAST_REPAIR_TIMING"] = "1"
                env.update(ARMS[arm])
                page, d0 = vm()
                l0 = load()
                t0 = time.time()
                proc = subprocess.Popen(
                    ["/usr/bin/time", "-l", binp, "c", "-q", "-b32768", "-r%d" % a.pct, "k.par2", name],
                    cwd=a.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    start_new_session=True)
                try:
                    _, err = proc.communicate(timeout=a.leg_timeout)
                    rc = str(proc.returncode)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    _, err = proc.communicate()
                    rc = "timeout"
                wall = time.time() - t0
                page, d1 = vm()
                l1 = load()
                m_rt = re.search(r"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", err)
                m_rss = re.search(r"(\d+)\s+maximum resident set size", err)
                m_flt = re.search(r"(\d+)\s+page faults", err)
                pars = sorted(p for p in os.listdir(a.dir) if p.startswith("k") and p.endswith(".par2"))
                listing = "\n".join("%s:%s" % (p, sha256(os.path.join(a.dir, p))) for p in pars)
                digest = hashlib.sha256(listing.encode()).hexdigest()[:16]
                if rc == "0":
                    digests.add(digest)
                refused = "create map refused" in err
                print("LEG gib=%d pct=%d level=%g arm=%s rep=%d rc=%s wall=%.3f user=%s sys=%s maxrss_mb=%s "
                      "majflt=%s pagein_gb=%.1f avail_gb=%.2f common_gb=%.2f avail_after_gb=%.2f "
                      "compressor_gb=%.2f swapouts_d=%d refused=%d set=%s parfiles=%d "
                      "load_before=%s load_after=%s ts=%s" % (
                          a.gib, a.pct, lv, arm, rep, rc, wall,
                          m_rt.group(2) if m_rt else "?", m_rt.group(3) if m_rt else "?",
                          str(int(m_rss.group(1)) >> 20) if m_rss else "?",
                          m_flt.group(1) if m_flt else "?",
                          (d1["Pageins"] - d0["Pageins"]) * page / 1e9,
                          avail(page, d0) / 1e9, common(page, d0) / 1e9, avail(page, d1) / 1e9,
                          d1.get("Pages occupied by compressor", 0) * page / 1e9,
                          d1.get("Swapouts", 0) - d0.get("Swapouts", 0), int(refused),
                          digest, len(pars), l0, l1, utc()), flush=True)
                for line in err.splitlines():
                    if "repair-timing" in line:
                        print("TIMING leg=l%g-%s-rep%d %s" % (lv, arm, rep, line.strip()), flush=True)
                if rc != "0" and rc != "timeout":
                    print("ORAMLOCK-FAIL rc=%s stderr=%s" % (rc, err[-400:]), flush=True)
                    return 9
            if locker:
                locker.release()
                locker = None
                print("UNLOCK level=%g ts=%s" % (lv, utc()), flush=True)

        print("SET-IDENTITY gib=%d distinct=%d digests=%s" % (a.gib, len(digests), "/".join(sorted(digests))), flush=True)
        if os.path.exists(os.path.join(a.dir, "k.par2")):
            r = subprocess.run([binp, "v", "-q", "k.par2"], cwd=a.dir, capture_output=True, text=True)
            print("VERIFY parfast rc=%d" % r.returncode, flush=True)
            if a.par2:
                r = subprocess.run([a.par2, "v", "-q", "k.par2"], cwd=a.dir, capture_output=True, text=True)
                print("VERIFY par2cmdline rc=%d %s" % (r.returncode, r.stdout.strip().splitlines()[-1:] or ""), flush=True)
        clear_sets(a.dir)
        print("ALL DONE %s" % utc(), flush=True)
        return 0
    finally:
        if locker:
            locker.release()
            print("UNLOCK (exit) ts=%s" % utc(), flush=True)
        os.remove(LOCK)
        print("RIG-LOCK-RELEASED %s" % utc(), flush=True)


if __name__ == "__main__":
    sys.exit(main())
