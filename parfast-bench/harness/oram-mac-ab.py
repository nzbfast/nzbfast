#!/usr/bin/env python3
"""oram-mac-ab.py - the unix no-regression A/B for TODO 345's create gate.

    harness/oram-mac-ab.py --base <parfast> --cand <parfast> \
        --dir <scratch dir> [--sizes 8,24] [--reps 3] [--pct 5]

The gate (`par2gen::mapped_payload_fits_memory`) asks `mem::available_ram()`,
which answers None on macOS, so on a Mac the gate never refuses and the
create's route is unchanged BY CONSTRUCTION. This round is the measurement
that says so rather than the argument: the pre-change and post-change
binaries over the same members, one member per size cut at `-b32768` (the
reporter's granularity), ABBA-mirrored rep to rep.

That premise held for the binaries this round compared, and NO LONGER holds
by default: macOS got a reading on 15 Sep 2026, opt-in behind
`NZBFAST_MACOS_AVAILABLE_RAM=1`, and since 16 Sep 2026 that reading is the
Mac DEFAULT and the variable is gone (TODO 345 D, the knee round in
an internal note section 6.5). So on a Mac
this script's plain arm now carries the gate. A round that wants the mapped
route regardless sets `NZBFAST_PAR2GEN_MAP_FIT=off`.

It takes the per-box rig lock (~/.parfast-rig.lock, exclusive create) after
waiting out any lock or running tool, the same rule as mqueue.py, and
releases it however it exits. Per leg: `uptime` before AND after (a load
reading only before a leg is blind to a neighbour that starts mid-leg),
wall, user and system CPU and max RSS from `/usr/bin/time -l`, every
`NZBFAST_REPAIR_TIMING` line, and a digest over the recovery set's per-file
SHA-256 - both binaries must print one digest per size.
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys
import time

LOCK = os.path.expanduser("~/.parfast-rig.lock")
TOOLS = ("parfast", "par2turbo", "par2j", "par2")


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--cand", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--sizes", default="8,24")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--pct", type=int, default=5)
    a = ap.parse_args()
    os.makedirs(a.dir, exist_ok=True)
    bins = {"base": os.path.abspath(a.base), "cand": os.path.abspath(a.cand)}
    for k, b in bins.items():
        print("BIN arm=%s path=%s sha256=%s" % (k, b, sha256(b)), flush=True)

    waited = 0
    while busy():
        if waited % 600 == 0:
            print("ORAMMAC-WAIT %s (%dm)" % (busy(), waited // 60), flush=True)
        time.sleep(60)
        waited += 60
    fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    os.write(fd, ("round=oram-mac-ab pid=%d started=%s" % (os.getpid(), utc())).encode())
    os.close(fd)
    print("RIG-LOCK-TAKEN %s %s" % (LOCK, utc()), flush=True)
    try:
        sizes = [int(s) for s in a.sizes.split(",")]
        for g in sizes:
            path = os.path.join(a.dir, "f%dg.bin" % g)
            want = g << 30
            if os.path.exists(path) and os.path.getsize(path) == want:
                print("FIXTURE-KEPT %s" % path, flush=True)
                continue
            t0 = time.time()
            with open(path, "wb") as f:
                left = want
                while left:
                    n = min(64 << 20, left)
                    f.write(os.urandom(n))
                    left -= n
            print("FIXTURE-WROTE %s bytes=%d secs=%.1f" % (path, want, time.time() - t0), flush=True)

        digests = {}
        for rep in range(1, a.reps + 1):
            arms = ["base", "cand"] if rep % 2 else ["cand", "base"]
            for g in (sizes if rep % 2 else list(reversed(sizes))):
                for arm in arms:
                    name = "f%dg.bin" % g
                    for p in os.listdir(a.dir):
                        if p.startswith("k") and p.endswith(".par2"):
                            os.remove(os.path.join(a.dir, p))
                    warm(os.path.join(a.dir, name))
                    l0 = load()
                    env = dict(os.environ, NZBFAST_REPAIR_TIMING="1")
                    for k in list(env):
                        if k.startswith("NZBFAST_") and k != "NZBFAST_REPAIR_TIMING":
                            del env[k]
                    t0 = time.time()
                    r = subprocess.run(
                        ["/usr/bin/time", "-l", bins[arm], "c", "-q", "-b32768", "-r%d" % a.pct, "k.par2", name],
                        cwd=a.dir, env=env, capture_output=True, text=True)
                    wall = time.time() - t0
                    l1 = load()
                    err = r.stderr
                    m_rt = re.search(r"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", err)
                    m_rss = re.search(r"(\d+)\s+maximum resident set size", err)
                    pars = sorted(p for p in os.listdir(a.dir) if p.startswith("k") and p.endswith(".par2"))
                    listing = "\n".join("%s:%s" % (p, sha256(os.path.join(a.dir, p))) for p in pars)
                    digest = hashlib.sha256(listing.encode()).hexdigest()[:16]
                    digests.setdefault(g, set()).add(digest)
                    print("LEG gib=%d pct=%d arm=%s rep=%d rc=%d wall=%.3f user=%s sys=%s maxrss_mb=%s set=%s parfiles=%d load_before=%s load_after=%s ts=%s" % (
                        g, a.pct, arm, rep, r.returncode, wall,
                        m_rt.group(2) if m_rt else "?", m_rt.group(3) if m_rt else "?",
                        str(int(m_rss.group(1)) >> 20) if m_rss else "?",
                        digest, len(pars), l0, l1, utc()), flush=True)
                    for line in err.splitlines():
                        if "repair-timing" in line or "create " in line:
                            print("TIMING leg=g%d-%s-rep%d %s" % (g, arm, rep, line.strip()), flush=True)
                    if r.returncode != 0:
                        print("ORAMMAC-FAIL rc=%d stderr=%s" % (r.returncode, err[-400:]), flush=True)
                        return 9
        for g, d in sorted(digests.items()):
            print("SET-IDENTITY gib=%d distinct=%d digests=%s" % (g, len(d), "/".join(sorted(d))), flush=True)
        for p in os.listdir(a.dir):
            if p.startswith("k") and p.endswith(".par2"):
                os.remove(os.path.join(a.dir, p))
        print("ALL DONE %s" % utc(), flush=True)
        return 0
    finally:
        os.remove(LOCK)
        print("RIG-LOCK-RELEASED %s" % utc(), flush=True)


if __name__ == "__main__":
    sys.exit(main())
