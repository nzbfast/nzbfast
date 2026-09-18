#!/usr/bin/env python3
"""cgmap.py - is the over-RAM create map gate blind to a CGROUP limit?
(claim par2gen-gate-cgroup-blind-16sep,
an internal note).

`par2gen::mapped_payload_fits_memory` gates the mapped transform on
`mem::available_ram()`, whose Linux arm reads /proc/meminfo MemAvailable.
That file is not namespaced, so inside a memory-limited container it reports
the HOST's figure and the gate admits a mapping the cgroup cannot hold. This
script measures that: one member, one binary, three arms x three cells.

CELLS - the point is a small CGROUP, not a small machine, so the member is
the same in all three and only the limit moves:

  cg<L>    docker run -m <L> --memory-swap <L>     (cg512m, cg1g, cg2g, ...:
                                                    the limit is READ OUT OF
                                                    THE CELL NAME, so CELLS is
                                                    a ladder)
  cgnone   docker run, no -m                       (container, no limit:
                                                    separates "a container
                                                    did it" from "the limit
                                                    did it")
  host     bare, no container at all               (the control the gate was
                                                    designed against)

A LADDER IS NOT OPTIONAL HERE, and the first round (13:21-13:26Z 16 Sep
2026) is why: at 512 MiB the create never reaches the transform at all.
`create_ntt_window` needs NTT_WINDOW_MIN = 1,024 slices of budget and the
budget comes from `MemBudget`, which IS cgroup-aware - so a limit small
enough to make the mapping interesting is already small enough to route
around the gate entirely, and all three arms collapse onto the direct fold.
The gate can only be reached in the band where the budget admits the
transform and the WHOLE payload still exceeds what the cgroup can hold.

ARMS, by env on ONE binary:

  def      no env             - what the gate decides today
  fitoff   NZBFAST_PAR2GEN_MAP_FIT=off - the mapped route forced (what
                                thrash looks like here; = def wherever the
                                gate does not refuse)
  nomap    NZBFAST_PAR2GEN_MAP=0      - the copied windows, the wall to beat

XENV=NAME=VALUE[,NAME=VALUE] is set on every leg on top of the arm's env,
for a round that moves the SHAPE rather than the arm (see the constant's own
note below). Recorded per leg as "xenv"; give such a round its own TAG.

COUNTERS. Per-process majflt is NOT what is read here: the quantity the
claim is about is charged to the CGROUP, so every leg reads its own
memory.stat pgmajfault / workingset_refault_file / pgscan deltas,
memory.peak, memory.events and io.stat rbytes from INSIDE the cgroup
(docker defaults to cgroupns=private on cgroup v2, so /sys/fs/cgroup in the
container is the container's own). The `host` cell has no cgroup of its own,
so it reports process majflt from /usr/bin/time and leaves the cgroup
columns empty - it is the wall/identity control, not a fault comparison.

The fixture is dropped from the page cache before EVERY leg with per-file
POSIX_FADV_DONTNEED and a mincore verify. NO drop_caches at any point -
this box is shared and carries a production service.

RUN (as root on a cgroup v2 + docker Linux box, INSIDE the rig lock - this
script does not take it; see cg512.py's header for the take/release rule,
and RELEASE BY TRUNCATING, never unlinking):

    R=/root/cgmap-16sep REPS=3 TAG=c1 OUT=cgmap.jsonl python3 cgmap.py

LAYOUT under $R: parfast (the binary, cross-built elsewhere), work/ (the
fixture and the par2 output). BINNAME picks another binary in $R, which is
how the candidate is A/B'd against the baseline on one rig and one fixture.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time

R = os.environ.get("R", "/root/cgmap-16sep")
WORK = os.path.join(R, "work")
BINNAME = os.environ.get("BINNAME", "parfast")
BIN = os.path.join(R, BINNAME)
IMAGE = os.environ.get("IMAGE", "debian:bookworm")
GIB = int(os.environ.get("GIB", "2"))
BLOCKS = int(os.environ.get("BLOCKS", "32768"))
PCT = int(os.environ.get("PCT", "5"))
REPS = int(os.environ.get("REPS", "3"))
TAG = os.environ.get("TAG", "c1")
OUT = os.environ.get("OUT", os.path.join(R, "cgmap.jsonl"))
TIMEOUT = int(os.environ.get("TIMEOUT", "900"))
CELLS = os.environ.get("CELLS", "cg512m,cg1g,cg2g,cgnone,host").split(",")
ARMS = os.environ.get("ARMS", "def,fitoff,nomap").split(",")
MEMBER = "f%dg.bin" % GIB

ARM_ENV = {
    "def": {},
    "fitoff": {"NZBFAST_PAR2GEN_MAP_FIT": "off"},
    "nomap": {"NZBFAST_PAR2GEN_MAP": "0"},
}

# XENV (comma list of NAME=VALUE) is set on EVERY leg of the round, on top
# of the arm's own env, and is how a round changes the SHAPE rather than the
# arm - added 16 Sep 2026 for claim map-gate-headroom-accumulator-only, whose
# whole question is whether the headroom term's two halves are separable.
# They are not separable by any of the knobs above: the accumulator
# (`count * bs`) and the arenas (`ntt_range::worker_arenas`) both scale with
# the row count, so -r and -b move both together. `NZBFAST_NTT_THREADS` moves
# the arena half ALONE and linearly, which is the only lever that can tell a
# term from a curve fit here. Give an XENV round its own TAG: the cell and arm
# names do not carry it, so two rounds in one OUT file are otherwise
# indistinguishable.
XENV = dict(
    kv.split("=", 1) for kv in os.environ.get("XENV", "").split(",") if "=" in kv
)


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def say(*a):
    print(*a, flush=True)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fixture():
    os.makedirs(WORK, exist_ok=True)
    p = os.path.join(WORK, MEMBER)
    want = GIB << 30
    if os.path.exists(p) and os.path.getsize(p) == want:
        say("FIXTURE-KEPT %s bytes=%d" % (p, want))
        return p
    t0 = time.time()
    with open(p, "wb") as f:
        left = want
        while left:
            n = min(64 << 20, left)
            f.write(os.urandom(n))
            left -= n
    say("FIXTURE-WROTE %s bytes=%d secs=%.1f" % (p, want, time.time() - t0))
    return p


def uncache(path):
    """POSIX_FADV_DONTNEED the whole file, then verify with mincore that
    (nearly) nothing of it is resident. Never drop_caches: shared box."""
    import ctypes
    import mmap

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        libc.posix_fadvise(
            ctypes.c_int(fd), ctypes.c_long(0), ctypes.c_long(size), ctypes.c_int(4)
        )
        # ACCESS_COPY, not PROT_READ: ctypes.from_buffer needs a
        # writable buffer to hand back an address, and a private
        # mapping never dirties the file. mincore over a private
        # file mapping still answers page-cache residency.
        mm = mmap.mmap(fd, size, access=mmap.ACCESS_COPY)
        try:
            npages = (size + 4095) // 4096
            vec = (ctypes.c_ubyte * npages)()
            addr = ctypes.c_void_p(
                ctypes.addressof(ctypes.c_char.from_buffer(mm))
            )
            rc = libc.mincore(addr, ctypes.c_size_t(size), vec)
            resident = sum(v & 1 for v in vec) if rc == 0 else -1
        finally:
            mm.close()
    finally:
        os.close(fd)
    return resident


CG_KEYS = ("pgmajfault", "workingset_refault_file", "pgscan", "pgsteal", "file", "anon")


def cg_script(cmd_env, argv):
    """The in-container leg: read this cgroup's counters either side of the
    create. `cmd_env` is prefixed as `K=V` words so the env applies to the
    create only and the counter reads are never gated by it."""
    envw = " ".join("%s=%s" % (k, v) for k, v in sorted(cmd_env.items()))
    return r"""
cd /w/work
G=/sys/fs/cgroup
echo "CGMAX $(cat $G/memory.max 2>/dev/null || echo ?)"
echo "CGCUR0 $(cat $G/memory.current 2>/dev/null || echo ?)"
echo "STAT0 $(cat $G/memory.stat 2>/dev/null | tr '\n' ';')"
echo "IO0 $(cat $G/io.stat 2>/dev/null | tr '\n' ';')"
[ -w $G/memory.peak ] && echo 0 > $G/memory.peak 2>/dev/null
S=$(date +%%s.%%N)
%s NZBFAST_REPAIR_TIMING=1 %s
RC=$?
E=$(date +%%s.%%N)
echo "RC $RC"
echo "INNERWALL $(awk "BEGIN{printf \"%%.3f\", $E-$S}")"
echo "CGPEAK $(cat $G/memory.peak 2>/dev/null || echo ?)"
echo "CGCUR1 $(cat $G/memory.current 2>/dev/null || echo ?)"
echo "STAT1 $(cat $G/memory.stat 2>/dev/null | tr '\n' ';')"
echo "IO1 $(cat $G/io.stat 2>/dev/null | tr '\n' ';')"
echo "EVENTS $(cat $G/memory.events 2>/dev/null | tr '\n' ';')"
exit $RC
""" % (envw, " ".join(argv))


def parse_stat(line):
    out = {}
    for item in line.split(";"):
        p = item.split()
        if len(p) == 2 and p[0] in CG_KEYS:
            try:
                out[p[0]] = int(p[1])
            except ValueError:
                pass
    return out


def parse_io(line):
    rb = 0
    for item in line.split(";"):
        m = re.search(r"\brbytes=(\d+)", item)
        if m:
            rb += int(m.group(1))
    return rb


def clean_par2():
    for p in os.listdir(WORK):
        if p.startswith("k") and p.endswith(".par2"):
            os.remove(os.path.join(WORK, p))


def leg(cell, arm, rep):
    clean_par2()
    resident = uncache(os.path.join(WORK, MEMBER))
    env = dict(ARM_ENV[arm])
    env.update(XENV)
    argv = [
        "/w/" + BINNAME if cell != "host" else BIN,
        "c", "-q", "-b%d" % BLOCKS, "-r%d" % PCT, "k.par2", MEMBER,
    ]
    t0 = time.time()
    if cell == "host":
        e = dict(os.environ, NZBFAST_REPAIR_TIMING="1")
        for k in list(e):
            if k.startswith("NZBFAST_") and k != "NZBFAST_REPAIR_TIMING":
                del e[k]
        e.update(env)
        r = subprocess.run(
            ["/usr/bin/time", "-v"] + argv, cwd=WORK, env=e,
            capture_output=True, text=True, timeout=TIMEOUT)
        out, err, rc = r.stdout, r.stderr, r.returncode
        rec = {}
        m = re.search(r"Major \(requiring I/O\) page faults: (\d+)", err)
        if m:
            rec["majflt"] = int(m.group(1))
        m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", err)
        if m:
            rec["maxrss_mb"] = int(m.group(1)) >> 10
    else:
        dargs = ["docker", "run", "--rm", "-v", "%s:/w" % R, "-w", "/w/work"]
        if cell.startswith("cg") and cell != "cgnone":
            lim = cell[2:]
            dargs += ["-m", lim, "--memory-swap", lim]
        dargs += ["--entrypoint", "/bin/sh", IMAGE, "-c", cg_script(env, argv)]
        r = subprocess.run(dargs, capture_output=True, text=True, timeout=TIMEOUT)
        out, err, rc = r.stdout, r.stderr, r.returncode
        rec = {}
        g = {}
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            g[k] = v
        if "STAT0" in g and "STAT1" in g:
            s0, s1 = parse_stat(g["STAT0"]), parse_stat(g["STAT1"])
            for k in CG_KEYS:
                if k in s0 and k in s1:
                    rec["d_" + k] = s1[k] - s0[k]
            rec["file_end_mb"] = s1.get("file", 0) >> 20
        if "IO0" in g and "IO1" in g:
            rec["read_mb"] = (parse_io(g["IO1"]) - parse_io(g["IO0"])) >> 20
        for k, name in (("CGMAX", "cg_max"), ("CGPEAK", "cg_peak"),
                        ("CGCUR1", "cg_cur_end")):
            if g.get(k, "?").isdigit():
                rec[name] = int(g[k])
        rec["events"] = g.get("EVENTS", "")
        if g.get("INNERWALL"):
            rec["inner_wall"] = float(g["INNERWALL"])
    wall = time.time() - t0
    pars = sorted(p for p in os.listdir(WORK)
                  if p.startswith("k") and p.endswith(".par2"))
    listing = "\n".join("%s:%s" % (p, sha256(os.path.join(WORK, p))) for p in pars)
    digest = hashlib.sha256(listing.encode()).hexdigest()[:16] if pars else "none"
    timing = [l.strip() for l in (out + err).splitlines()
              if "repair-timing" in l or "create map refused" in l
              or l.strip().startswith("create ")]
    rec.update(dict(tag=TAG, cell=cell, arm=arm, rep=rep, rc=rc, wall=round(wall, 3),
                    xenv=",".join("%s=%s" % kv for kv in sorted(XENV.items())),
                    set=digest, parfiles=len(pars), resident_before=resident,
                    ts=utc(), timing=timing))
    return rec


def main():
    if not os.path.exists(BIN):
        say("NO BINARY at %s" % BIN)
        return 2
    say("BOX %s" % subprocess.run(["uname", "-a"], capture_output=True,
                                  text=True).stdout.strip())
    say("BINARY %s sha256=%s" % (BIN, sha256(BIN)))
    fixture()
    say("MEMAVAIL-HOST %s" % next(
        (l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemAvailable")), "?"))
    digests, rows = {}, []
    with open(OUT, "a") as f:
        for rep in range(1, REPS + 1):
            cells = CELLS if rep % 2 else list(reversed(CELLS))
            arms = ARMS if rep % 2 else list(reversed(ARMS))
            for cell in cells:
                for arm in arms:
                    try:
                        rec = leg(cell, arm, rep)
                    except subprocess.TimeoutExpired:
                        rec = dict(tag=TAG, cell=cell, arm=arm, rep=rep, rc="timeout",
                                   wall=float(TIMEOUT), set="timeout", ts=utc())
                    rows.append(rec)
                    f.write(json.dumps(rec) + "\n")
                    f.flush()
                    say("LEG cell=%s arm=%s rep=%d rc=%s wall=%.1f set=%s "
                        "majflt=%s refault=%s read_mb=%s peak_mb=%s" % (
                            cell, arm, rep, rec["rc"], rec["wall"], rec["set"],
                            rec.get("d_pgmajfault", rec.get("majflt", "-")),
                            rec.get("d_workingset_refault_file", "-"),
                            rec.get("read_mb", "-"),
                            (rec.get("cg_peak", 0) >> 20) or rec.get("maxrss_mb", "-")))
                    for t in rec.get("timing", []):
                        say("TIMING %s/%s/r%d %s" % (cell, arm, rep, t))
                    if rec["set"] not in ("none", "timeout"):
                        digests.setdefault("all", set()).add(rec["set"])
    say("SET-IDENTITY legs=%d distinct=%d digests=%s" % (
        len(rows), len(digests.get("all", ())), "/".join(sorted(digests.get("all", ())))))
    clean_par2()
    say("ALL DONE %s" % utc())
    return 0


if __name__ == "__main__":
    sys.exit(main())
