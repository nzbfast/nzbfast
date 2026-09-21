#!/usr/bin/env python3
"""One-batch bands against the copied windows, on one binary and one fixture.

Claim `stripe-first-bands-one-batch-refusal`. `stripe_first::admissible`'s
BANDS arm admits a one-batch create whose bands do not hold the corpus, where
its MAPPED arm refuses every one-batch create. This harness measures the two
routes at that admission, over a ladder of shapes, so the refusal can be
widened, re-predicated or left alone on evidence rather than on the batch
count.

ARMS are env on ONE binary, so nothing about the comparison is a build:
`bands` is the shipped default over copies (`NZBFAST_PAR2GEN_MAP=0`), `nowin`
adds `NZBFAST_CREATE_STRIPE_BANDS=0` and is the copied windows the refusal
would fall to. Legs are interleaved ABBA within a rep so a drifting box
cannot separate the arms, and the SET DIGEST of every leg is recorded: any
rule change here must keep the recovery bytes identical.

READ CPU, NOT WALL, on the dev Mac - it carries other lanes and the 1-minute
load runs 30-60 on 32 cores (memory topic
`nzbfast-create-width-step-sign-is-the-arms`). Wall is reported and is noise.

CELL - THE READ SIDE, added 16 Sep 2026 for claim
`stripe-first-bands-sweep-ladder-overram`. The M3 round this file was written
for could not price the term that actually decides the two routes: 512 GB of
RAM holds any corpus it can build, so its band read was 0.14-0.29 s and every
one of its 15 cells measured the TRANSFORM side alone
(an internal note section 4's stated
limit). CELL=cg<N> runs the leg inside a docker memory cgroup of <N>, which
is a small-memory box for the purpose at hand - the page cache is charged to
the cgroup and reclaimed under its limit, so a corpus several times the limit
is read from the DISK in both arms, at each arm's own access pattern. That is
the whole point: bands read the corpus in strided sweeps of `bs / sweeps`
contiguous bytes per slice, the copied windows read it sequentially, and both
read it exactly once.

  CELL=host    bare, no container - what the M3 round did (the default, so
               that round reproduces unchanged)
  CELL=cg2g    docker run -m 2g --memory-swap 2g

THE FIXTURE IS DROPPED FROM THE PAGE CACHE BEFORE EVERY LEG on Linux
(per-file POSIX_FADV_DONTNEED with a mincore verify, `cgmap.uncache`,
recorded per leg as `resident_before`) so the first sweep of every leg is
cold and neither arm inherits its predecessor's cache. NO drop_caches at any
point: these boxes are shared and one carries a production service. macOS has
no per-file equivalent, so on the dev Mac this is skipped and recorded as
`resident_before: null` - which is another way of saying the dev Mac cannot
host a read-priced round at all.

THE RUNG LADDER IS THE SHAPES LIST, and `-m` is the lever: the band arena is
`create_ntt_window`'s window, `budget / bs` slices capped at `n_slices`, so
moving the third field of a shape moves `sweeps` and therefore the run
length. NOTE THE HARD CEILING ON THAT LADDER, which is structural and not a
harness limit: `create_ntt_window` refuses a window below NTT_WINDOW_MIN =
1,024 slices and `MAX_INPUT_SLICES` is 32,768, so `sweeps <= 32` and
`run = bs / sweeps >= bs / 32` for every create that reaches this arm at all.
Ask for a budget below `1024 * bs` and the transform is not admitted, both
arms fall to the fold, and the leg measures nothing - which is why the
admitting range is probed with cheap single legs before a round is spent.

RUN:  R=<workdir> MEMBER=f2g.bin SHAPES=... REPS=3 OUT=x.jsonl python3 bandone.py
      R=/root/bandorx-16sep CELL=cg2g MEMBER=f8g.bin \
        SHAPES=32768:2:256,32768:2:512,32768:2:1024,32768:2:1536 \
        REPS=3 TAG=o1 OUT=orx.jsonl python3 bandone.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time

R = os.environ["R"]
BIN = os.environ["BIN"]
MEMBER = os.environ.get("MEMBER", "f2g.bin")
REPS = int(os.environ.get("REPS", "3"))
OUT = os.environ.get("OUT", os.path.join(R, "bandone.jsonl"))
TAG = os.environ.get("TAG", "b1")
TIMEOUT = int(os.environ.get("TIMEOUT", "1800"))
# "blocks:pct:mb[:threads]" per shape.
SHAPES = os.environ.get("SHAPES", "32768:5:2048").split(",")
ARMS = os.environ.get("ARMS", "bands,nowin").split(",")
CELL = os.environ.get("CELL", "host")
IMAGE = os.environ.get("IMAGE", "debian:bookworm")

# `uncache` and the cgroup counter script are cgmap.py's, imported rather
# than re-spelled: that file is the round that earned them (the mincore
# verify, ACCESS_COPY rather than PROT_READ, and the no-drop_caches rule are
# each a note in its own header), and a second spelling of a hygiene step is
# how two rounds come to disagree about what "cold" meant.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cgmap  # noqa: E402
import pdrv   # noqa: E402 - for harness_facts; see main()

ARM_ENV = {
    "bands": {"NZBFAST_PAR2GEN_MAP": "0"},
    "nowin": {"NZBFAST_PAR2GEN_MAP": "0", "NZBFAST_CREATE_STRIPE_BANDS": "0"},
}


def say(*a):
    print(*a, flush=True)


def clean():
    for p in os.listdir(R):
        if p.startswith("k") and p.endswith(".par2"):
            os.remove(os.path.join(R, p))


def digest():
    """One hash over every recovery file, name-ordered: the SET identity."""
    h = hashlib.sha256()
    for p in sorted(x for x in os.listdir(R) if x.startswith("k") and x.endswith(".par2")):
        h.update(p.encode())
        with open(os.path.join(R, p), "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
    return h.hexdigest()[:16]


def leg(shape, arm, rep):
    parts = shape.split(":")
    blocks, pct, mb = int(parts[0]), int(parts[1]), int(parts[2])
    threads = int(parts[3]) if len(parts) > 3 else 0
    clean()
    # Cold before EVERY leg, so neither arm inherits the other's cache and
    # the first sweep is a real disk read. Linux only; see the header.
    resident = None
    if sys.platform.startswith("linux"):
        try:
            resident = cgmap.uncache(os.path.join(R, MEMBER))
        except OSError as e:
            resident = "uncache-failed: %s" % e
    args = ["c", "-q", "-b%d" % blocks, "-r%d" % pct, "-m%d" % mb]
    if threads:
        args += ["-t%d" % threads]
    args += ["k.par2", MEMBER]
    t0 = time.time()
    if CELL == "host":
        env = dict(os.environ)
        for k in list(env):
            if k.startswith("NZBFAST_"):
                del env[k]
        env["NZBFAST_REPAIR_TIMING"] = "1"
        env.update(ARM_ENV[arm])
        # `-l` is the BSD/macOS spelling and `-v` the GNU one; the M3
        # round was macOS-only and had no reason to know the difference.
        argv = ["/usr/bin/time",
                "-v" if sys.platform.startswith("linux") else "-l", BIN] + args
        r = subprocess.run(argv, cwd=R, env=env, capture_output=True, text=True,
                           timeout=TIMEOUT)
        rc, log = r.returncode, r.stdout + r.stderr
        cg = {}
    else:
        # The binary and the fixture are both under $R, which is bind-mounted
        # at /w; cgmap.cg_script reads this cgroup's own counters either side
        # of the create and prints the inner wall, so a leg's I/O and its
        # reclaim are the CGROUP's rather than the host's.
        lim = CELL[2:] if CELL.startswith("cg") else None
        dargs = ["docker", "run", "--rm", "-v", "%s:/w" % R, "-w", "/w"]
        if lim and CELL != "cgnone":
            dargs += ["-m", lim, "--memory-swap", lim]
        script = cgmap.cg_script(ARM_ENV[arm],
                                 ["/w/" + os.path.basename(BIN)] + args)
        # Two surgical edits to cgmap's script and no more, so the counter
        # reads stay the ones that file documents:
        #  - it cd's into /w/work; this harness keeps the fixture at $R
        #    itself, which is mounted at /w;
        #  - debian:bookworm carries no /usr/bin/time, so the CPU the M3
        #    round said to read is taken from the CGROUP's own cpu.stat
        #    usage_usec either side of the create - the same place every
        #    other counter here comes from. NOT the shell's `times`
        #    builtin: `$(times)` runs in a subshell whose own child times
        #    are zero, and it duly reported 0.0 for every leg of the first
        #    probe on amd-epyc-vm. CPU is the secondary column in any
        #    case - the create prints its own `read` and transform totals
        #    on the timing channel, and THAT decomposition is the round.
        script = script.replace("cd /w/work", "cd /w")
        script = script.replace('S=$(date +%s.%N)',
                                'echo "CPU0 $(awk \'/usage_usec/{print $2}\' $G/cpu.stat)"\n'
                                'S=$(date +%s.%N)')
        script = script.replace('echo "RC $RC"',
                                'echo "CPU1 $(awk \'/usage_usec/{print $2}\' $G/cpu.stat)"\n'
                                'echo "RC $RC"')
        dargs += ["--entrypoint", "/bin/sh", IMAGE, "-c", script]
        r = subprocess.run(dargs, capture_output=True, text=True, timeout=TIMEOUT)
        rc, log = r.returncode, r.stdout + r.stderr
        cg = {}
        g = {}
        for line in r.stdout.splitlines():
            k, _, v = line.partition(" ")
            g[k] = v
        if "STAT0" in g and "STAT1" in g:
            s0, s1 = cgmap.parse_stat(g["STAT0"]), cgmap.parse_stat(g["STAT1"])
            for k in cgmap.CG_KEYS:
                if k in s0 and k in s1:
                    cg["d_" + k] = s1[k] - s0[k]
        if "IO0" in g and "IO1" in g:
            cg["read_mb"] = (cgmap.parse_io(g["IO1"]) - cgmap.parse_io(g["IO0"])) >> 20
        for k, name in (("CGMAX", "cg_max"), ("CGPEAK", "cg_peak")):
            if g.get(k, "?").isdigit():
                cg[name] = int(g[k])
        if g.get("INNERWALL"):
            cg["inner_wall"] = float(g["INNERWALL"])
        if g.get("RC", "").lstrip("-").isdigit():
            rc = int(g["RC"])
        if g.get("CPU0", "").isdigit() and g.get("CPU1", "").isdigit():
            cg["cpu"] = round((int(g["CPU1"]) - int(g["CPU0"])) / 1e6, 2)
    wall = time.time() - t0
    rec = {
        "tag": TAG, "shape": shape, "arm": arm, "rep": rep, "rc": rc,
        "cell": CELL, "resident_before": resident,
        "wall": round(wall, 3), "blocks": blocks, "pct": pct, "mb": mb,
        "threads": threads,
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    rec.update(cg)
    m = re.search(r"([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys", log)
    if m:
        rec["real"] = float(m.group(1))
        rec["user"] = float(m.group(2))
        rec["sys"] = float(m.group(3))
        rec["cpu"] = round(float(m.group(2)) + float(m.group(3)), 2)
    else:
        # GNU `time -v`.
        u = re.search(r"User time \(seconds\): ([\d.]+)", log)
        sy = re.search(r"System time \(seconds\): ([\d.]+)", log)
        if u and sy:
            rec["user"], rec["sys"] = float(u.group(1)), float(sy.group(1))
            rec["cpu"] = round(rec["user"] + rec["sys"], 2)
    m = re.search(r"(\d+)\s+maximum resident set size", log)
    if m:
        rec["maxrss_mb"] = int(m.group(1)) >> 20
    else:
        m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", log)
        if m:
            rec["maxrss_mb"] = int(m.group(1)) >> 10
    m = re.search(r"Major \(requiring I/O\) page faults: (\d+)", log)
    if m:
        rec["majflt"] = int(m.group(1))
    # The arm on the record rather than inferred: admissible() names it.
    m = re.search(r"create stripe-first (admitted|refused): (.*)", log)
    if m:
        rec["admit"] = m.group(1)
        rec["admit_why"] = m.group(2).strip()
    m = re.search(r"create stripe-first: (\d+) rows in (\d+) chunk\(s\) of (\d+) stripes.*?"
                  r"bands of (\d+) B over copies, read ([\d.]+)(ms|s), probe ([\d.]+)(ms|s|µs).*?: "
                  r"([\d.]+)(ms|s)", log)
    if m:
        rec["chunks"] = int(m.group(2))
        rec["chunk_stripes"] = int(m.group(3))
        rec["band_bytes"] = int(m.group(4))
        rec["read_s"] = secs(m.group(5), m.group(6))
        rec["transform_s"] = secs(m.group(9), m.group(10))
    m = re.search(r"create ntt rows (\d+)\+(\d+) \(n=(\d+), (\d+) window\(s\) of (\d+), "
                  r"W=(\d+), (\d+) stripe\(s\), threads=(\d+), probe ok\): ([\d.]+)(ms|s)", log)
    if m:
        rec["windows"] = int(m.group(4))
        rec["window_slices"] = int(m.group(5))
        rec["slice_stripes"] = int(m.group(7))
        rec["transform_s"] = secs(m.group(9), m.group(10))
    m = re.search(r"create arms: n=(\d+) rows=(\d+) batches=(\d+)", log)
    if m:
        rec["n"] = int(m.group(1))
        rec["rows"] = int(m.group(2))
        rec["batches"] = int(m.group(3))
    # THE PROXY THE ROUND IS A LADDER OVER: how long a contiguous run each
    # sweep takes from one slice, `run = band_bytes / n_slices = bs / sweeps`
    # (the identity is derived in section 3 of
    # an internal note). Read off the
    # binary's OWN lines and never from the `-m` that was asked for: the
    # budget is clamped by MemBudget - and inside a cell by the cgroup -
    # before create_ntt_window ever sees it, so the rung you asked for and
    # the rung you got are two different numbers.
    n = rec.get("n")
    if rec.get("band_bytes") and n:
        rec["sweeps"] = rec.get("chunks")
        rec["run_bytes"] = rec["band_bytes"] // n
    # The binary's own create lines, kept verbatim on the record. Section 7
    # of the write-up is emphatic about why: a round's two arms can refuse
    # for two DIFFERENT reasons from two different arms of admissible(), and
    # no reading of the source afterwards recovers which.
    rec["timing"] = [l.strip() for l in log.splitlines()
                     if "repair-timing" in l or "create map refused" in l
                     or l.strip().startswith("create ")]
    if rc == 0:
        rec["digest"] = digest()
    else:
        rec["err"] = log[-1200:]
    return rec


def secs(v, unit):
    v = float(v)
    return round(v / 1000.0 if unit == "ms" else v / 1e6 if unit == "µs" else v, 4)


def main():
    say("BANDONE start %s reps=%d shapes=%s arms=%s" % (TAG, REPS, SHAPES, ARMS))
    # The HARNESS's own provenance, and the round-start twin of the
    # per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
    # banked log cannot be traced to the harness revision that wrote
    # it (census an internal note).
    # NAMED EXPLICITLY rather than defaulted: this round's legs are built by
    # cgmap.py's uncache and cgroup-counter helpers, so a stamp that omitted
    # cgmap.py would not name what ran.
    pdrv.harness_facts([os.path.abspath(__file__), cgmap.__file__, pdrv.__file__])
    with open(OUT, "a") as f:
        for shape in SHAPES:
            for rep in range(REPS):
                # ABBA within the rep: the second half runs the arms reversed.
                order = ARMS if rep % 2 == 0 else list(reversed(ARMS))
                for arm in order:
                    rec = leg(shape, arm, rep)
                    f.write(json.dumps(rec) + "\n")
                    f.flush()
                    say("LEG %s %s rep%d rc=%s wall=%.2f inner=%s cpu=%s "
                        "read=%s transform=%s chunks/windows=%s run=%s "
                        "readmb=%s resident=%s admit=%s digest=%s" % (
                            shape, arm, rep, rec["rc"], rec["wall"],
                            rec.get("inner_wall"), rec.get("cpu"),
                            rec.get("read_s"), rec.get("transform_s"),
                            rec.get("chunks") or rec.get("windows"),
                            rec.get("run_bytes"), rec.get("read_mb"),
                            rec.get("resident_before"),
                            rec.get("admit"), rec.get("digest")))
                    for t in rec.get("timing", []):
                        say("TIMING %s/%s/r%d %s" % (shape, arm, rep, t))
    clean()
    say("BANDONE done -> %s" % OUT)


if __name__ == "__main__":
    main()
