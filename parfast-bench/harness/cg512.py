#!/usr/bin/env python3
"""cg512.py - parfast r inside a real cgroup v2 memory limit (claim
parfast-512mb-cgroup-repair-15sep). memladder.py's leg shape, with every leg
run in its own transient systemd scope:

    systemd-run --scope --unit cg512-<tag> -p MemoryMax=512M -p MemorySwapMax=0
                -p OOMPolicy=continue sh -c 'nice -n 19 parfast r ...; <read cgroup>'

OOMPolicy=continue keeps the wrapper shell alive after a kernel OOM kill of
parfast, so it can still read memory.peak / memory.events of the scope. The
control arm is the same scope with no MemoryMax (cgroup_mem_limit then finds
none). The driver samples memory.current / memory.stat every 25 ms from
outside the scope for the anon / file split.

Written for an internal note (claim
parfast-512mb-cgroup-repair-15sep) and kept so the attribution follow-up does
not rebuild it. Linux + cgroup v2 + systemd only; runs as root.

LAYOUT under $R (default /root/cg512-15sep): parfast (the binary),
fix/{pristine,work,gold.sha} with the 64 KiB set and fix1m/... with the 1 MiB
set, built as that note section 1 says; pdrv.py (an internal note) beside
this file.

RUN (inside a wrapper that holds the rig lock - this script does NOT take it,
because pdrv.RigLock refuses a loaded box and a memory round does not need a
quiet one). TAKE and RELEASE both need an inode check beside the flock, for
the same reason pdrv.RigLock.take()/release() do: flock() locks the fd's
INODE, not the path, and the two come apart exactly when a releaser unlinks
and someone else recreates the path around us. Copy this pair rather than a
bare `flock -n 9 || exit 17` with no release rule - that shape (no check
either side) is what let one round delete another's live lock file on
amd-epyc-vm at 19:06:55Z on 15 Sep 2026
(an internal note):

    exec 9>>~/.parfast-rig.lock; flock -n 9 || exit 17
    [ "$(stat -c %i ~/.parfast-rig.lock)" = "$(stat -L -c %i /proc/$$/fd/9)" ] || { exec 9>&-; exit 17; }
    held=$(sed -n 's/.*pid=\([0-9]\{1,\}\).*/\1/p' ~/.parfast-rig.lock | head -1)
    if [ -n "$held" ] && [ "$held" != "$$" ] && kill -0 "$held" 2>/dev/null; then exec 9>&-; exit 17; fi
    trap '[ "$(stat -c %i ~/.parfast-rig.lock 2>/dev/null)" = "$(stat -L -c %i /proc/$$/fd/9)" ] && rm -f ~/.parfast-rig.lock; exec 9>&-' EXIT
    REPS=3 SERIES_ALL=1 LIMITS=512M SETS=fix RUNGS=4096 BUDGETS=128,192,256 \
        ARMS=auto TAG=a3 OUT=attrib.jsonl python3 cg512.py

  THE `held=`/`kill -0` PAIR ABOVE IS THE ORPHAN TEST, added 16 Sep 2026
  (an internal note). Winning the flock
  only proves nobody ELSE HOLDING A FLOCK is on this box - a `set -o
  noclobber` shell taker has none to lose, so the flock alone cannot tell that
  holder from a genuine orphan. `harness/riglock_state.py` is the ONE
  rule every taker in this fleet answers "is it held?" from now
  (liveness comes from the holder, never the clock; no age bound; no
  `--force`) - reimplemented here as two lines of shell rather than imported,
  because a shell script cannot import Python cheaply and both `cg512.py`'s
  own two forms here and `spillslow2-run.sh`'s actual implementation made that
  same choice, so a reader who has seen one recognises the other. A pid field
  that is empty, unparseable, or fails `kill -0` is a genuine orphan and the
  taker proceeds; anything else is a live holder and the taker refuses -
  `exit 17` for a runner that means to give up, `continue` (go round again)
  for one that means to queue, matching each shape's own release rule.

  THAT TAKE IS FOR A RUNNER THAT MEANS TO GIVE UP. A runner that means to
  QUEUE must not copy it, and both halves of why are measured incidents on
  amd-epyc-vm on 16 Sep 2026. (a) `exit 17` on the inode mismatch is wrong
  for a waiter: a releaser UNLINKS the path, so every waiter that already had
  it open wakes holding a flock on an orphaned inode, and that mismatch is the
  NORMAL handover rather than an error - refusing the lock is right, exiting
  on it is what dropped `musl-static-memops-residue-15sep` out of the queue at
  00:49:30Z after it had waited since 00:17Z (COORDINATION-vps 00:52:00Z).
  pdrv's take() goes round again five times for exactly this; the shell form
  above does not go round at all. (b) A POLL of `flock -n` with a sleep loses
  every handover to a lane queued on a BLOCKING flock, because the kernel
  hands the lock straight to a blocked waiter:
  `parfast-fold-percall-cost-avx512gfni-15sep` lost four that way and stood
  down at 00:56Z having run no leg in 3h13m (COORDINATION-vps 00:55:39Z), and
  this script's own `parfast-spill-flush-throttled-disk-cgroup-15sep` sat
  unserved from 22:10Z 15 Sep to 02:08Z 16 Sep on the same shape. Queue with a
  BLOCKING flock in a REOPEN-recheck loop:

    L=~/.parfast-rig.lock; got=no
    for _try in $(seq 1 2000); do
      exec 9>>$L
      if flock -w 300 9 && [ "$(stat -c %i $L 2>/dev/null)" = "$(stat -L -c %i /proc/$$/fd/9)" ]; then
        held=$(sed -n 's/.*pid=\([0-9]\{1,\}\).*/\1/p' $L | head -1)
        if [ -n "$held" ] && [ "$held" != "$$" ] && kill -0 "$held" 2>/dev/null; then
          exec 9>&-; sleep 2; continue
        fi
        got=yes; break
      fi
      exec 9>&-; sleep 2
    done
    [ $got = yes ] || { echo "never got the rig lock"; exit 1; }

  then the same `trap ... EXIT` release as above, unchanged: the release rule
  is identical for both shapes and is the half that must never be dropped.
  The `held=`/`kill -0` pair inside the `if` is the same orphan test as the
  give-up form above, moved inside the win branch and spelled with `continue`
  instead of `exit 17` so a refusal re-joins the queue rather than leaving it -
  a waiter that gives up on a live holder is exactly the failure this whole
  paragraph exists to prevent.

  BUT DO NOT READ THAT AS A FAIR QUEUE - it is not one, and an earlier draft
  of this paragraph claimed it "joins by arrival and jumps nobody", which is
  measurably false. Because the release UNLINKS the path, every waiter is
  blocked on an inode that is about to be orphaned; at the handover they all
  wake, each finds the mismatch, and whoever gets through reopen-and-recreate
  first takes the lock. Arrival order does not survive that. Measured at the
  02:28:20Z handover on 16 Sep 2026: `muslpurge0-15sep` had been queued since
  00:51:08Z and `d512purge-16sep` since 01:52Z, and d512purge took it while
  muslpurge0 logged the orphan and went round again. Blocking is still
  strictly better than polling - a poller never wins while any blocking waiter
  exists, whereas a blocking waiter wins sometimes - but a lane that MUST run
  next needs the holder to hand off explicitly, not a flock. Budget a waiter's
  deadline for the whole queue and then some, and re-check that a long-queued
  runner is still in `fuser`'s list rather than assuming its turn is coming.

  AND NOTE WHAT THAT UNFAIRNESS IS ACTUALLY CAUSED BY: the UNLINK in the
  release, not the flock. `flock()` queues per INODE, so as long as the inode
  is stable the kernel's own wait queue is the queue and it is ordered. Every
  problem above - the orphan a waiter wakes holding, the recheck that has to
  loop, the scramble to recreate the path, the lost arrival order - exists
  only because the releaser deletes the file. `daemon-512m-purge-delay-arm-16sep`
  released at 03:09:25Z on 16 Sep 2026 "by TRUNCATING and unlocking and never
  unlinking", the next taker had it the same second, and the longest-queued
  waiter won the handover after it. So the better release is:

      truncate fd 9 to 0, write your round= line, and at the end truncate and
      unlock - never unlink.

  The flock state stays correct whatever happens, because the kernel drops it
  when the holder dies; all a stale file costs is a stale descriptive line,
  which is a far smaller problem than the orphan class. DO NOT, HOWEVER, make
  a queued runner the place you first try this, and do not change
  pdrv.RigLock.release() (which unlinks) while lanes are queued on that lock:
  a mixed fleet is safe ONLY because every taker still does the inode recheck,
  so the recheck loop stays mandatory either way and the release change is one
  to make when the box is idle.

  The trap's check runs BEFORE the rm and while fd 9 (and so the flock) is
  still held, so nobody can be a legitimate holder of this inode while the
  check-and-remove is in flight; `exec 9>&-` (which drops the flock) only
  happens after. Linux-only (the `/proc/$$/fd` read), matching this script.

  env: REPS, SETS (fix,fix1m), RUNGS, BUDGETS (MiB or none), ARMS (auto,fold),
       LIMITS, SERIES_ALL (series on every rep, not only rep 1), TAG, OUT,
       LEG_TIMEOUT (s, default 900; a timed-out leg is killed by UNIT name),
       XENV (comma list of NAME=VALUE set on every leg, e.g.
       XENV=NZBFAST_REPAIR_OUTPUT=inplace; recorded as "xenv" - give the arm
       its own TAG, the leg name does not carry it)

  BIN (the parfast binary, default $R/parfast, so two binaries can share one
       fixture), NICE (nice level inside the scope, default 19; set 0 for a
       TIMED round - a niced leg on a shared box times the box, not the arm),
       IOMAX=DEV:RBPS:WBPS:RIOPS:WIOPS (systemd IOReadBandwidthMax /
       IOWriteBandwidthMax / IOReadIOPSMax / IOWriteIOPSMax on the leg's scope,
       each field empty = uncapped, e.g. IOMAX=/dev/sda:160M:160M:: ; the
       scope's io.stat is read at the end so the throttled bytes are COUNTED),
       UNCACHE (path to bench/component/uncache.c built for the box: after the
       damage, `sync` then POSIX_FADV_DONTNEED over every member and par2 file,
       and the leg is REFUSED unless mincore reads 0 pages after it - a per-file
       drop, because drop_caches would flatten every other lane's round too).
       Added for claim parfast-spill-flush-throttled-disk-cgroup-15sep.

Every leg also writes legs/<tag>.samp, one line per 25 ms sample (t_s,
memory.current, anon, file, file_dirty, file_writeback, kernel, pgscan, all
bytes), so a kill's last second can be read without rerunning it. Added for
claim parfast-512mb-m192-kill-attribution-15sep.

Per leg it records exit status, oom_kill / oom / max events, memory.peak,
ru_maxrss, the 25 ms sampled maxima of anon, file, file_dirty and
file_writeback, wall, CPU-seconds, load, and the dispatch parsed off the
NZBFAST_REPAIR_TIMING lines (path, W, slabs, windows, largest window,
mem-floor attribution).
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import apply_damage, damage_picks, remove_strays, restore_slices  # noqa: E402

R = os.environ.get("R", "/root/cg512-15sep")
BIN = os.environ.get("BIN") or os.path.join(R, "parfast")
NICE = os.environ.get("NICE", "19")
IOMAX = os.environ.get("IOMAX")
UNCACHE = os.environ.get("UNCACHE")
OUT = os.path.join(R, os.environ.get("OUT", "cg512.jsonl"))
LOGDIR = os.path.join(R, "legs")
os.makedirs(LOGDIR, exist_ok=True)
REPS = int(os.environ.get("REPS", "2"))
LEG_TIMEOUT = float(os.environ.get("LEG_TIMEOUT", "900"))
ONLY = os.environ.get("ONLY")  # optional "fix:m:budget:arm:limit" single-leg filter
TAG = os.environ.get("TAG", "")
SERIES_ALL = bool(os.environ.get("SERIES_ALL"))
XENV = [kv for kv in os.environ.get("XENV", "").split(",") if kv]
# LIMITS: comma list of systemd sizes and/or "free"; unset = 512M plus a free
# control on rep 1 and 512M alone after it
LIMITS = [None if x == "free" else x for x in os.environ["LIMITS"].split(",")] if os.environ.get("LIMITS") else None

SETS = [
    ("fix", 65536, [192, 256, 1024, 2048, 4096]),
    ("fix1m", 1048576, [192, 448]),
]
if os.environ.get("SETS"):
    keep = os.environ["SETS"].split(",")
    SETS = [s for s in SETS if s[0] in keep]
if os.environ.get("RUNGS"):
    rr = [int(x) for x in os.environ["RUNGS"].split(",")]
    SETS = [(a, b, [m for m in c if m in rr]) for (a, b, c) in SETS]
BUDGETS = os.environ.get("BUDGETS", "128,none").split(",")
ARMS = os.environ.get("ARMS", "auto,fold").split(",")

SCRIPT = (
    'nice -n "$CG_NICE" "$@"; rc=$?; d=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); '
    '{ echo "rc $rc"; echo "peak $(cat $d/memory.peak)"; echo "max $(cat $d/memory.max)"; '
    'echo "swapmax $(cat $d/memory.swap.max)"; sed "s/^/ev /" $d/memory.events; '
    'sed "s/^/st /" $d/memory.stat; echo "iomax $(tr \'\\n\' \'|\' < $d/io.max)"; '
    'sed "s/^/io /" $d/io.stat; } > "$CG_OUTF"; exit $rc'
)


def iomax_props():
    """systemd-run properties for IOMAX=DEV:RBPS:WBPS:RIOPS:WIOPS."""
    if not IOMAX:
        return []
    dev, rbps, wbps, riops, wiops = IOMAX.split(":")
    out = []
    for name, val in (("IOReadBandwidthMax", rbps), ("IOWriteBandwidthMax", wbps),
                      ("IOReadIOPSMax", riops), ("IOWriteIOPSMax", wiops)):
        if val:
            out += ["-p", "%s=%s %s" % (name, dev, val)]
    return out


def uncache(work, keep):
    """Cold start for one leg without a global drop: returns resident pages after."""
    subprocess.run(["sync"], check=True)
    paths = [os.path.join(work, n) for n in sorted(keep)]
    out = subprocess.run([UNCACHE] + paths, stdout=subprocess.PIPE, universal_newlines=True, check=True).stdout
    before = after = 0
    for ln in out.splitlines():
        b, a, _, _ = ln.split(None, 3)
        before, after = before + int(b), after + int(a)
    return before, after


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def secs(v, u):
    return float(v) * {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}[u]


def read_int(p):
    try:
        with open(p) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def read_stat(p):
    out = {}
    try:
        with open(p) as f:
            for line in f:
                k, v = line.split()
                out[k] = int(v)
    except (OSError, ValueError):
        pass
    return out


def cell_setup(fixname):
    fix = os.path.join(R, fixname)
    pristine, work = os.path.join(fix, "pristine"), os.path.join(fix, "work")
    members = sorted(f for f in os.listdir(pristine) if f.endswith(".bin"))
    gold = {}
    for line in open(os.path.join(fix, "gold.sha")):
        h, name = line.split()
        gold[name.lstrip("*")] = h
    keep = set(os.listdir(pristine))
    return pristine, work, members, gold, keep


def gate(work, members, gold):
    return [m for m in members if sha(os.path.join(work, m)) != gold[m]]


def restore(work, pristine, members, gold, keep, slicesize, picks, tag):
    names = sorted(n for n in os.listdir(work) if n not in keep)
    remove_strays(work, keep)
    strays = {"n": len(names), "sample": names[:4],
              "bytes": 0}
    for nm in keep:  # par2 volumes too: a killed repair must not leave them changed
        if not nm.endswith(".bin") and os.path.getsize(os.path.join(work, nm)) != os.path.getsize(os.path.join(pristine, nm)):
            shutil.copyfile(os.path.join(pristine, nm), os.path.join(work, nm))
    restore_slices(work, pristine, members, slicesize, picks)
    bad = gate(work, members, gold)
    full = 0
    for m in bad:
        shutil.copyfile(os.path.join(pristine, m), os.path.join(work, m))
        full += 1
    if gate(work, members, gold):
        raise SystemExit("restore failed at " + tag)
    return strays, full


def run_leg(fixname, slicesize, m, rep, budget, arm, limit, picks, series):
    # limit: None (free) or a systemd size string ("512M", "768M", "1G")
    pristine, work, members, gold, keep = cell_setup(fixname)
    lname = ("L512" if limit == "512M" else "L" + limit) if limit else "free"
    tag = "%s-m%d-%s-%s-%s-r%d%s" % (fixname, m, budget, arm, lname, rep, ("-" + TAG) if TAG else "")
    unit = "cg512-" + tag
    errp = os.path.join(LOGDIR, tag + ".err")
    cgout = os.path.join(LOGDIR, tag + ".cg")
    env = dict(os.environ, NZBFAST_REPAIR_TIMING="1", NZBFAST_NO_ENRICH="1", CG_OUTF=cgout, CG_NICE=NICE)
    env.pop("NZBFAST_MEM_FLOOR_SERIES", None)
    env.pop("NZBFAST_NTT", None)
    env.pop("NZBFAST_REPAIR_OUTPUT", None)
    env.pop("XENV", None)
    for kv in XENV:
        k, v = kv.split("=", 1)
        env[k] = v
    if series:
        env["NZBFAST_MEM_FLOOR_SERIES"] = "1"
    if arm == "fold":
        env["NZBFAST_NTT"] = "0"
    props = ["-p", "OOMPolicy=continue"]
    if limit:
        props += ["-p", "MemoryMax=" + limit, "-p", "MemorySwapMax=0"]
    props += iomax_props()
    argv = ["systemd-run", "--scope", "--quiet", "--unit", unit] + props + ["sh", "-c", SCRIPT, "sh", BIN, "r", "-t4", "-q"]
    if budget != "none":
        argv.append("-m" + budget)
    argv.append("set.par2")

    apply_damage(work, members, slicesize, picks, 1)
    drop = None
    if UNCACHE:
        remove_strays(work, keep)
        drop = uncache(work, keep)
        if drop[1]:
            raise SystemExit("cache drop left %d resident pages before %s" % (drop[1], tag))
    if os.path.exists(cgout):
        os.unlink(cgout)
    cgdir = "/sys/fs/cgroup/system.slice/%s.scope" % unit
    l0 = os.getloadavg()[0]
    t0 = time.monotonic()
    samp = {"n": 0, "cur_max": 0, "anon_max": 0, "file_max": 0, "anon_at_cur_max": 0, "file_at_cur_max": 0,
            "shmem_max": 0, "kernel_max": 0, "file_at_end": None,
            "dirty_max": 0, "writeback_max": 0, "dirty_at_cur_max": 0, "writeback_at_cur_max": 0,
            "last": None}
    trace = []
    timed_out = False
    with open(errp, "wb") as fe:
        p = subprocess.Popen(argv, cwd=work, stdout=subprocess.DEVNULL, stderr=fe, env=env)
        while True:
            pid, status, ru = os.wait4(p.pid, os.WNOHANG)
            if pid:
                break
            cur = read_int(cgdir + "/memory.current")
            if cur is not None:
                st = read_stat(cgdir + "/memory.stat")
                samp["n"] += 1
                a, f = st.get("anon", 0), st.get("file", 0)
                samp["anon_max"] = max(samp["anon_max"], a)
                samp["file_max"] = max(samp["file_max"], f)
                samp["shmem_max"] = max(samp["shmem_max"], st.get("shmem", 0))
                samp["kernel_max"] = max(samp["kernel_max"], st.get("kernel", 0))
                samp["file_at_end"] = f
                d, wb = st.get("file_dirty", 0), st.get("file_writeback", 0)
                samp["dirty_max"] = max(samp["dirty_max"], d)
                samp["writeback_max"] = max(samp["writeback_max"], wb)
                ts = round(time.monotonic() - t0, 3)
                samp["last"] = [ts, cur >> 20, a >> 20, f >> 20, d >> 20, wb >> 20]
                trace.append((ts, cur, a, f, d, wb, st.get("kernel", 0), st.get("pgscan", 0)))
                if cur > samp["cur_max"]:
                    samp.update(cur_max=cur, anon_at_cur_max=a, file_at_cur_max=f, dirty_at_cur_max=d, writeback_at_cur_max=wb)
            if time.monotonic() - t0 > LEG_TIMEOUT and not timed_out:
                timed_out = True
                subprocess.run(["systemctl", "kill", "--signal=KILL", unit + ".scope"])
            time.sleep(0.025)
    wall = time.monotonic() - t0
    l1 = os.getloadavg()[0]
    with open(os.path.join(LOGDIR, tag + ".samp"), "w") as fs:
        fs.write("t_s current anon file file_dirty file_writeback kernel pgscan\n")
        for row in trace:
            fs.write(" ".join(str(x) for x in row) + "\n")
    rc = os.waitstatus_to_exitcode(status)

    cg = {"events": {}, "stat": {}, "io": {}}
    try:
        for line in open(cgout):
            parts = line.split()
            if parts[0] == "ev":
                cg["events"][parts[1]] = int(parts[2])
            elif parts[0] == "st":
                cg["stat"][parts[1]] = int(parts[2])
            elif parts[0] == "io":
                for kv in parts[2:]:
                    k, v = kv.split("=")
                    cg["io"][k] = cg["io"].get(k, 0) + int(v)
            elif parts[0] == "iomax":
                cg["iomax"] = " ".join(parts[1:])
            elif parts[0] in ("rc", "peak"):
                cg[parts[0]] = int(parts[1])
            else:
                cg[parts[0]] = parts[1]
    except OSError:
        cg["missing"] = True
    inner_rc = cg.get("rc")
    bad = gate(work, members, gold)
    ok = inner_rc == 0 and rc == 0 and not bad
    strays, full = restore(work, pristine, members, gold, keep, slicesize, picks, tag)
    err = open(errp, errors="replace").read()

    def phase(label):
        mm = re.search(r"%s: \+([0-9.]+)(µs|ms|s)" % re.escape(label), err)
        return secs(mm.group(1), mm.group(2)) if mm else None

    ntt_syn = re.findall(r"ntt syndromes \(m=\d+, needed=\d+, n=(\d+), W=(\d+), threads=(\d+)\): ([0-9.]+)(µs|ms|s)", err)
    ntt_windows = re.findall(r"ntt window \((\d+) bytes, (\d+) slices, (\w+)\): ([0-9.]+)(µs|ms|s)", err)
    slabs = re.search(r"in (\d+) slab\(s\) of (\d+) B", err)
    # One line per construction when the feed is budgeted; its "under ..."
    # names where the budget came from (published -m, or the cgroup quarter
    # since the feed-shape cgroup fallback). Absent = the unbudgeted constants.
    feed_lines = re.findall(r"feed shape under ([^:]+): batch ([0-9.]+) MB, channel (\d+), merge cap ([0-9.]+) MB", err)
    floors = {}
    for which, body in re.findall(r"mem-floor: (live high-water|sampled peak rss) · (.*)", err):
        nums = dict((k.strip(), float(v)) for v, k in re.findall(r"([0-9.]+) MB([^·(]*)", body))
        fields = re.findall(r"(ru_maxrss|rss|footprint|rss over footprint|repair work|scan reads|verifier tables|unattributed) ([0-9.]+) MB", body)
        floors[which] = {k: float(v) for k, v in fields}
        own = re.findall(r"(repair work|scan reads) [0-9.]+ MB \(own peak ([0-9.]+)\)", body)
        for k, v in own:
            floors[which][k + " own peak"] = float(v)
    series = re.findall(r"mem-floor series: ([0-9.]+)s fp (\d+) MB work (\d+) MB scan (\d+) MB", err)
    nonseries = [ln for ln in err.splitlines() if "mem-floor series" not in ln and ln.strip()]
    rec = {
        "tag": tag, "set": fixname, "slice": slicesize, "m": m, "rep": rep, "budget": budget, "arm": arm,
        "limit": limit, "series": series_flag(series),
        "rc": rc, "inner_rc": inner_rc, "ok": ok, "bad_members": len(bad), "strays": strays, "full_restores": full,
        "timed_out": timed_out,
        "oom_kill": cg["events"].get("oom_kill"), "oom": cg["events"].get("oom"), "ev_max": cg["events"].get("max"),
        "ev_high": cg["events"].get("high"), "cg_peak_mib": round(cg["peak"] / 1048576.0, 1) if "peak" in cg else None,
        "cg_max": cg.get("max"), "cg_swapmax": cg.get("swapmax"),
        "cg_end_anon_mib": round(cg["stat"].get("anon", 0) / 1048576.0, 1),
        "cg_end_file_mib": round(cg["stat"].get("file", 0) / 1048576.0, 1),
        "cg_end_dirty_mib": round(cg["stat"].get("file_dirty", 0) / 1048576.0, 1),
        "cg_end_writeback_mib": round(cg["stat"].get("file_writeback", 0) / 1048576.0, 1),
        "cg_end_kernel_mib": round(cg["stat"].get("kernel", 0) / 1048576.0, 1),
        "xenv": XENV, "bin": BIN, "nice": NICE, "iomax_env": IOMAX, "iomax_cg": cg.get("iomax"),
        "io_stat": cg["io"], "drop_before_after": drop,
        "flush_s": [round(secs(v, u), 4) for _, v, u in re.findall(r"spill flush \((\d+) B\): ([0-9.]+)(µs|ms|s)\b", err)],
        "samp_tail_t_cur_anon_file_dirty_wb_kernel_mib": [
            [r[0]] + [round(x / 1048576.0, 1) for x in r[1:7]] for r in trace[-8:]],
        "pgscan": cg["stat"].get("pgscan"), "pgsteal": cg["stat"].get("pgsteal"),
        "workingset_refault_file": cg["stat"].get("workingset_refault_file"),
        "samp_n": samp["n"],
        "samp_dirty_max_mib": round(samp["dirty_max"] / 1048576.0, 1),
        "samp_writeback_max_mib": round(samp["writeback_max"] / 1048576.0, 1),
        "samp_dirty_at_cur_max_mib": round(samp["dirty_at_cur_max"] / 1048576.0, 1),
        "samp_writeback_at_cur_max_mib": round(samp["writeback_at_cur_max"] / 1048576.0, 1),
        "samp_last_t_cur_anon_file_dirty_wb_mib": samp["last"],
        "samp_cur_max_mib": round(samp["cur_max"] / 1048576.0, 1),
        "samp_anon_max_mib": round(samp["anon_max"] / 1048576.0, 1),
        "samp_file_max_mib": round(samp["file_max"] / 1048576.0, 1),
        "samp_anon_at_cur_max_mib": round(samp["anon_at_cur_max"] / 1048576.0, 1),
        "samp_file_at_cur_max_mib": round(samp["file_at_cur_max"] / 1048576.0, 1),
        "wall": round(wall, 2), "cpu": round(ru.ru_utime + ru.ru_stime, 2),
        "maxrss_mib": round(ru.ru_maxrss / 1024.0, 1),  # Linux: KiB
        "load_before": round(l0, 1), "load_after": round(l1, 1),
        "feed_fold_solve": phase("feed+fold+solve"), "final_verify": phase("final verify"),
        "path": "ntt" if ntt_syn else "fold",
        "transform_calls": len(ntt_syn),
        "ntt_w": sorted({int(w) for (_, w, _, _, _) in ntt_syn}),
        "ntt_threads": sorted({int(t) for (_, _, t, _, _) in ntt_syn}),
        "ntt_windows": len(ntt_windows),
        "ntt_window_max_bytes": max([int(b) for (b, _, _, _, _) in ntt_windows], default=None),
        "slabs": int(slabs.group(1)) if slabs else 1,
        "slab_width": int(slabs.group(2)) if slabs else slicesize,
        "feed_shape_lines": len(feed_lines),
        "feed_shape": sorted({"%s / batch %s MB / channel %s / cap %s MB" % l for l in feed_lines}),
        "diverged": "diverged" in err,
        "floors": floors,
        "series_n": len(series),
        "series_last": series[-1] if series else None,
        "series_fp_max": max([int(s[1]) for s in series], default=None),
        "tail": nonseries[-4:],
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("LEG %-38s rc=%s/%s ok=%s oomk=%s evmax=%s cgpeak=%6s maxrss=%6s anon=%6s dirty/wb max=%s/%s file@peak=%6s wall=%6.2f cpu=%6.1f path=%s W=%s slabs=%d win=%d feed=%d%s load=%.0f/%.0f"
          % (tag, rc, inner_rc, ok, rec["oom_kill"], rec["ev_max"], rec["cg_peak_mib"], rec["maxrss_mib"],
             rec["samp_anon_max_mib"], rec["samp_dirty_max_mib"], rec["samp_writeback_max_mib"], rec["samp_file_at_cur_max_mib"], wall, rec["cpu"], rec["path"], rec["ntt_w"],
             rec["slabs"], rec["ntt_windows"], len(feed_lines), rec["feed_shape"], l0, l1), flush=True)
    return rec


def series_flag(s):
    return bool(s)


def main():
    for fixname, _, _ in SETS:
        pristine, work, members, gold, keep = cell_setup(fixname)
        if gate(work, members, gold):
            raise SystemExit("work copy of %s is not pristine at start" % fixname)
    for rep in range(1, REPS + 1):
        for fixname, slicesize, rungs in SETS:
            _, work, members, _, _ = cell_setup(fixname)
            for m in rungs:
                picks = damage_picks(work, members, slicesize, m, 1000 + m)
                for budget in BUDGETS:
                    for arm in ARMS:
                        limits = LIMITS if LIMITS else (["512M", None] if rep == 1 else ["512M"])
                        for limit in limits:
                            key = "%s:%d:%s:%s:%s" % (fixname, m, budget, arm, limit or "free")
                            if ONLY and ONLY != key:
                                continue
                            run_leg(fixname, slicesize, m, rep, budget, arm, limit, picks, series=(rep == 1 or SERIES_ALL))
    print("ALL DONE", flush=True)


if __name__ == "__main__":
    main()
