#!/usr/bin/env python3
"""wstagefs.py - is `STAGE_MAX_ARTICLE_DEFAULT` = 256 KiB in the right place,
measured on a filesystem that is not RAM?

Claim `wstage-real-filesystem-cell-16sep`, section 6 of
an internal note. That round proved the memcpy a
128 KB-article download spends a third of its client CPU in IS the one-pass
writer's write-coalescing window (`nzbkit_base::disk::stage::WriteStage::offer`)
and changed nothing, for one stated reason: **both its rigs wrote to RAM**, an
HFS RAM disk and `/dev/shm`. On tmpfs the 4-5x drop in `pwrite` count that the
window BUYS is nearly free - `sys` was 1.0095 across its arms - so that round
priced the window's COST honestly and its BENEFIT at approximately zero. The
same blindness applies to round 41's ladder quoted at the constant itself
(`crates/nzbkit-base/src/disk/stage.rs`), which is retired INSTRUCTIONS on
tmpfs, and instructions is the column the 16 Sep round showed reads a copy
that costs 15 G cycles as 1.3%.

So this runner is `wstage.py` with three things changed - plus, since 17 Sep
2026, a burnt first leg per cell, which is the fourth and is described at the
site in `main()` rather than here:

  1. **OUTDIR IS ON A REAL FILESYSTEM.** `wstage.py` hard-codes
     `/dev/shm/wstage-out`; here it is `OUT_ROOT`, which must be on disk.
     The runner REFUSES to start if `OUT_ROOT` is a tmpfs, because that
     refusal is the entire point of the round and a silent fallback to RAM
     would reproduce the blindness with extra steps.

  2. **THE PAGE CACHE IS A DECLARED REGIME, NOT AN ACCIDENT.** An 8.19 GB
     write to a box with 31 GB of RAM never reaches the device inside the
     leg, so a buffered-write leg on ext4 is a tmpfs leg wearing a hat. Two
     regimes, both run, both reported:
       `warm`  - ordinary buffered writes, the whole payload absorbed by the
                 page cache, plus a `sync` TIMED SEPARATELY after the leg so
                 the writeback the leg deferred is at least visible.
       `tight` - the client runs in a cgroup v2 with `memory.max` = `MEM_MAX`
                 (default 2 GiB) against an 8.19 GB payload, so dirty pages
                 must be written back and reclaimed continuously INSIDE the
                 leg and the device is in the loop. `io.stat`'s `wbytes`
                 delta is read per leg and is the proof that it was: a leg
                 whose cgroup wrote ~0 device bytes is a `warm` leg and is
                 reported as one rather than quoted as a `tight` result.
     Neither regime touches a sysctl. `vm.dirty_bytes` would have been the
     obvious lever and is refused on purpose: it is box-wide, and this box
     runs somebody else's service.

  3. **AN ARTICLE-SIZE LADDER, because the constant is a THRESHOLD.** What
     decides a threshold is where the curve crosses, not one probe either
     side of it. The rungs are the modes of the live index (section 5 of the
     16 Sep write-up): ~80 K, ~110 K, ~128 K, ~190 K and ~250 K inside the
     bound, ~360 K outside it - and 360 K is not a control here, it is the
     RAISE test, because `NZBFAST_WRITE_COALESCE_MAX_ART_KB` stages it
     without a rebuild. That knob is what makes every comparison in this
     round a `staged` vs `not staged` A/B AT ONE ARTICLE SIZE, which is a
     cleaner contrast than moving the article size between arms.

`perf stat` also counts `syscalls:sys_enter_pwrite64` here, which `wstage.py`
did not: the window's whole claimed benefit is the CALL COUNT, and a round
that argues about what calls cost should show how many there were.

Everything else - the quiet gate, the client/server core pin, the arm
rotation, the A/A arm, `perf stat` on the CLIENT only, one binary for every
arm - is `wstage.py`'s and is not optional.

**A discarded leg is not a leg you may quote.** The burnt first leg prints
with `DISCARD` and is deliberately NOT written to the jsonl, so an analysis
that reads the raw legs cannot accidentally take a median over one. If you
change that, change the reason too: it exists because round 43 published two
legs at 222.93 s and 422.23 s in its raw set and had to exclude them in
prose, which is an exclusion every later reader has to know about.

env: BIN       the ONE binary (client and server alike)
     R         rig root; OUT_ROOT (must NOT be tmpfs); REPS
     REGIME    warm | tight
     MEM_MAX   cgroup memory.max for `tight` (default 2G)
     CELLS     comma subset of the ladder below
     ARMS      comma subset of ARM_ENV
"""
import json, os, shutil, signal, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import require_quiet_box, foreign_cpu  # noqa: E402

R = os.environ.get("R", "/root/wstagefs-17sep")
BIN = os.environ["BIN"]
REPS = int(os.environ.get("REPS", "3"))
OUT_ROOT = os.environ.get("OUT_ROOT", os.path.join(R, "out"))
OUTDIR = os.path.join(OUT_ROOT, "leg")
REGIME = os.environ.get("REGIME", "tight")
MEM_MAX = os.environ.get("MEM_MAX", "2G")
CG = "/sys/fs/cgroup/wstagefs"
CLIENT_CPUS = os.environ.get("CLIENT_CPUS", "0-3")
SERVER_CPUS = os.environ.get("SERVER_CPUS", "4-7")
CONNS = os.environ.get("CONNS", "8")
FILES = int(os.environ.get("FILES", "16"))

# The ladder. name: (port, article size). a80..a250 are the live index's
# modes; a360 is the rung the `stage` arm carries ACROSS the bound; a20 and
# a50 are BELOW every mode and exist because a threshold that loses at every
# rung of the population still has to be asked where it stops losing - round
# 41's own ladder read its largest instruction WIN at 50 K.
CELLS = {
    "a20":  (11958, "20K"),
    "a50":  (11959, "50K"),
    "a80":  (11960, "80K"),
    "a110": (11961, "110K"),
    "a128": (11962, "128K"),
    "a190": (11963, "190K"),
    "a250": (11964, "250K"),
    "a360": (11965, "360K"),
}
ARM_ENV = {
    "on": {},                                          # shipped
    "off": {"NZBFAST_WRITE_COALESCE_KB": "0"},         # window off entirely
    # NOT STAGED, WINDOW STILL ON: the bound is dropped below the article so
    # `offer` declines it and the article takes its own positioned write,
    # exactly as a 360 K one does today. This is the arm that isolates the
    # BOUND from the window, which `off` cannot: `off` removes the window's
    # machinery as well as its staging.
    "nostage": {"NZBFAST_WRITE_COALESCE_MAX_ART_KB": "8"},
    # STAGED ABOVE THE BOUND: 1 MiB is the shipped `run_cap`, which
    # `Caps::sized` clamps against, so this is "stage everything the run cap
    # can hold". On the a360 rung this is the RAISE test.
    "stage": {"NZBFAST_WRITE_COALESCE_MAX_ART_KB": "1024"},
    # THE COALESCING-RATIO LADDER, at ONE article size (a128), which is what
    # separates the staging COPY from the serialised WRITE. `run_cap` sets how
    # many articles share a `pwrite`; `Caps::sized` makes `max_article` =
    # min(stage_max_article, run), so the run cap must exceed the article for
    # the article to be staged at all - 129 KB is the smallest run that still
    # stages a 128 KB article, and it packs exactly two. With 384 it packs
    # three and with the shipped 1 MiB about five. Every one of these arms
    # pays the copy in full; only the call count moves. If wall tracks the
    # call count rather than the copy, the cost is the write and not the byte.
    "run129": {"NZBFAST_WRITE_COALESCE_RUN_KB": "129"},
    "run384": {"NZBFAST_WRITE_COALESCE_RUN_KB": "384"},
    "aa": {},                                          # the noise floor
}
ORDER_CELLS = os.environ.get("CELLS", "a20,a50,a80,a110,a128,a190,a250,a360").split(",")
ARMS = os.environ.get("ARMS", "on,nostage,aa").split(",")
LOG = os.path.join(R, os.environ.get("OUT", "wstagefs-%s.jsonl" % REGIME))
LEGDIR = os.path.join(R, "legs")
os.makedirs(LEGDIR, exist_ok=True)


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def refuse_ram_disk():
    """The one refusal this runner exists for. `statfs.f_type` 0x01021994 is
    TMPFS_MAGIC; RAMFS is 0x858458f6. Failing to find is failing: an
    unreadable fstype is refused too."""
    os.makedirs(OUT_ROOT, exist_ok=True)
    st = os.statvfs(OUT_ROOT)
    fstype = subprocess.run(["findmnt", "-no", "FSTYPE", "--target", OUT_ROOT],
                            capture_output=True, text=True).stdout.strip()
    if not fstype:
        raise SystemExit("cannot read the filesystem type of %s - refusing" % OUT_ROOT)
    if fstype in ("tmpfs", "ramfs"):
        raise SystemExit("OUT_ROOT=%s is %s. THIS ROUND EXISTS BECAUSE THE LAST "
                         "ONE WROTE TO RAM." % (OUT_ROOT, fstype))
    free_gb = st.f_bavail * st.f_frsize / 1e9
    if free_gb < 30:
        raise SystemExit("only %.1f GB free under %s - refusing" % (free_gb, OUT_ROOT))
    print("OUT_ROOT %s fstype=%s free=%.1fGB regime=%s mem_max=%s"
          % (OUT_ROOT, fstype, free_gb, REGIME, MEM_MAX if REGIME == "tight" else "-"),
          flush=True)
    return fstype


def cg_setup():
    if REGIME != "tight":
        return
    os.makedirs(CG, exist_ok=True)
    for f, v in (("memory.max", MEM_MAX), ("memory.swap.max", "0")):
        with open(os.path.join(CG, f), "w") as fh:
            fh.write(v)
    print("cgroup %s memory.max=%s" % (CG, MEM_MAX), flush=True)


def cg_teardown():
    if REGIME != "tight":
        return
    try:
        os.rmdir(CG)
    except OSError as e:
        print("cgroup rmdir: %s (leave it, it is empty and inert)" % e, flush=True)


def cg_read(name):
    try:
        with open(os.path.join(CG, name)) as f:
            return f.read()
    except OSError:
        return ""


def io_wbytes():
    """Device bytes written, summed over every backing device, from the
    cgroup's io.stat. This is the proof that `tight` is tight."""
    tot = 0
    for line in cg_read("io.stat").splitlines():
        for tok in line.split()[1:]:
            k, _, v = tok.partition("=")
            if k == "wbytes":
                tot += int(v)
    return tot


def mem_stat(key):
    for line in cg_read("memory.stat").splitlines():
        k, _, v = line.partition(" ")
        if k == key:
            return int(v)
    return 0


def tree_bytes(d):
    n = 0
    for root, _dirs, files in os.walk(d):
        for name in files:
            n += os.path.getsize(os.path.join(root, name))
    return n


def wait_port(port, pid, secs=180):
    end = time.time() + secs
    while time.time() < end:
        if pid.poll() is not None:
            raise SystemExit("server exited rc=%s before listening" % pid.returncode)
        s = socket.socket()
        s.settimeout(1.0)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return
        except OSError:
            s.close()
            time.sleep(1.0)
    raise SystemExit("server never listened on %d" % port)


def start_server(cell):
    port, asize = CELLS[cell]
    nzb = os.path.join(R, "%s.nzb" % cell)
    cfg = os.path.join(R, "%s.json" % cell)
    log = open(os.path.join(R, "server-%s.log" % cell), "w")
    cmd = ["taskset", "-c", SERVER_CPUS, BIN, "mockserve",
           "--port", str(port), "--bind", "127.0.0.1", "--files", str(FILES),
           "--file-size", "512M", "--article-size", asize, "--nzb", nzb]
    p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    wait_port(port, p)
    with open(cfg, "w") as f:
        f.write('{"servers":[{"host":"127.0.0.1","port":%d,"tls":false,"connections":%s}]}'
                % (port, CONNS))
    return p, nzb, cfg


def stop_server(p):
    # BY PID, never by pattern (CLAUDE.md invariant 2/2a).
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def clear_out():
    """Remove the last leg's 8.19 GB and make the unlink's own writeback
    finish BEFORE the next leg is timed - on tmpfs that was a `sleep`, on
    ext4 it is real metadata and journal traffic."""
    shutil.rmtree(OUTDIR, ignore_errors=True)
    subprocess.call(["sync"])
    os.makedirs(OUTDIR)


def leg(cell, arm, nzb, cfg, rep, keep=True):
    clear_out()
    time.sleep(4)
    require_quiet_box("%s/%s/%s/rep%d" % (REGIME, cell, arm, rep))
    tag = "%s-%s-%s-r%d" % (REGIME, cell, arm, rep)
    perf = os.path.join(LEGDIR, tag + ".perf")
    env = dict(os.environ)
    env["NZBFAST_NO_ENRICH"] = "1"
    env.update(ARM_ENV[arm])
    inner = ["nice", "-n", "19", "perf", "stat", "-x,", "-o", perf,
             "-e", "cycles,instructions,syscalls:sys_enter_pwrite64", "--",
             "taskset", "-c", CLIENT_CPUS, BIN,
             "--config", cfg, "get", nzb, "--out", OUTDIR, "--connections", CONNS]
    if REGIME == "tight":
        # The client joins the cgroup in its own shell before exec, so every
        # page it dirties - and every page of cache behind them - is charged
        # there and must be reclaimed there.
        cmd = ["sh", "-c", 'echo $$ > %s/cgroup.procs; exec "$@"' % CG, "sh"] + inner
    else:
        cmd = inner
    w0, s0 = (io_wbytes(), mem_stat("pgsteal")) if REGIME == "tight" else (0, 0)
    out = open(os.path.join(LEGDIR, tag + ".out"), "w")
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
    _pid, status, ru = os.wait4(p.pid, 0)
    wall = time.time() - t0
    rc = status if status == 0 else (status >> 8 if status & 0xFF == 0 else status)
    # The writeback the leg did NOT do. In `warm` this is most of the payload
    # and is the number that says so; in `tight` it should be small.
    t1 = time.time()
    subprocess.call(["sync"])
    sync_s = time.time() - t1
    wb = (io_wbytes() - w0) if REGIME == "tight" else 0
    steal = (mem_stat("pgsteal") - s0) if REGIME == "tight" else 0
    cycles = insns = pwrites = None
    with open(perf) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) > 2:
                val = None if parts[0].startswith("<") else float(parts[0])
                if parts[2] == "cycles":
                    cycles = val
                elif parts[2] == "instructions":
                    insns = val
                elif parts[2].startswith("syscalls:sys_enter_pwrite64"):
                    pwrites = val
    nbytes = tree_bytes(OUTDIR)
    row = dict(ts=utcnow(), regime=REGIME, cell=cell, arm=arm, rep=rep, rc=rc,
               wall=wall, sync_s=sync_s, utime=ru.ru_utime, stime=ru.ru_stime,
               cpu=ru.ru_utime + ru.ru_stime, maxrss_kb=ru.ru_maxrss,
               minflt=ru.ru_minflt, majflt=ru.ru_majflt, cycles=cycles,
               instructions=insns, pwrites=pwrites, dev_wbytes=wb, pgsteal=steal,
               bytes=nbytes, foreign=foreign_cpu()[0])
    row["keep"] = keep
    if keep:
        with open(LOG, "a") as f:
            f.write(json.dumps(row) + "\n")
    print("LEG %-5s %-7s r%d rc=%s wall=%.2f sync=%.2f cpu=%.2f (u %.2f s %.2f) "
          "cyc=%s pw=%s devW=%.2fGB GB=%.3f%s"
          % (cell, arm, rep, rc, wall, sync_s, row["cpu"], ru.ru_utime, ru.ru_stime,
             "%.3fG" % (cycles / 1e9) if cycles else "-",
             "%d" % pwrites if pwrites else "-", wb / 1e9, nbytes / 1e9,
             "" if keep else " DISCARD"), flush=True)
    shutil.rmtree(OUTDIR, ignore_errors=True)
    return row


def main():
    refuse_ram_disk()
    cg_setup()
    print("wstagefs round start %s R=%s regime=%s reps=%d cells=%s arms=%s bin=%s"
          % (utcnow(), R, REGIME, REPS, ORDER_CELLS, ARMS, BIN), flush=True)
    try:
        for cell in ORDER_CELLS:
            srv, nzb, cfg = start_server(cell)
            try:
                # THE FIRST LEG OF A PHASE IS AN OUTLIER, AND IT IS DISCARDED
                # BY CONSTRUCTION HERE RATHER THAN NAMED AFTERWARDS. Round 43
                # (an internal note section 5)
                # had two legs read 222.93 s and 422.23 s on the SHIPPED arm
                # against ~10 s and ~50 s neighbours, both the leg that runs
                # immediately after a `mockserve` for a new cell materialises
                # its payload; only the arm rotation stopped them being
                # published as a pathology of the window. It excluded them by
                # NAMING them, and the 17 Sep post-pool round then had to drop
                # the first leg of each cell in its own analysis - the same tax,
                # twice. One burnt leg a cell is cheaper than either, and it
                # keeps the exclusion out of the reader's hands: a discarded leg
                # prints with DISCARD and is never written to the jsonl, so no
                # median can accidentally contain one.
                leg(cell, ARMS[0], nzb, cfg, 0, keep=False)
                for rep in range(1, REPS + 1):
                    order = list(ARMS)
                    order = order[(rep - 1) % len(order):] + order[:(rep - 1) % len(order)]
                    if rep % 2 == 0:
                        order = order[::-1]
                    for arm in order:
                        leg(cell, arm, nzb, cfg, rep)
            finally:
                stop_server(srv)
    finally:
        shutil.rmtree(OUTDIR, ignore_errors=True)
        cg_teardown()
    print("wstagefs round done %s" % utcnow(), flush=True)


if __name__ == "__main__":
    main()
