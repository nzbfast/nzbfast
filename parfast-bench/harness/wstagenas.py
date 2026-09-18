#!/usr/bin/env python3
"""wstagenas.py - round 43's write-coalescing ladder on ROTATIONAL media.

Claim `wstage-window-default-second-filesystem-17sep`, section 6 item 3 of
an internal note. That round put the one-pass
writer's write-coalescing window on a filesystem that is not RAM and found it
a wall LOSS at every article size from 20 KB to 360 KB - and named its own
boundary in the same breath: **one KVM guest, one virtio SSD, one kernel.** A
coalescing window exists for seek-bound media, so the case where it should win
biggest is the one nobody had measured. This runner is that case.

It is `wstagefs.py` with everything a NAS appliance does not have taken out,
and nothing else changed. The arms, the cells, the rotation, the quiet gate, the
one-binary rule and the refusal to write to RAM are all its, deliberately, so
the two rounds' rows can be read against each other:

  - **NO cgroup, in either version.** The appliance runs a 4.4 kernel with
    cgroup v1 and root-owned controller directories, so `wstagefs.py`'s `tight` regime -
    a `memory.max` that forces writeback and reclaim inside the leg - cannot be
    built here at all, and `io.stat` cannot be read to prove it if it could.
    The page-cache regime therefore comes from the PAYLOAD instead, which is
    the same lever round 43's own `over` phase used to remove the cgroup from
    its argument: `FILES` x `FILE_SIZE` is set past the box's RAM, so the
    writeback that a smaller payload would defer past the end of the leg has
    to happen inside it. `over` is the regime the verdict is read off; `warm`
    (8.19 GB, the size every other row in round 43 uses) is run beside it as
    the comparable cell and is reported as what it is.
  - **NO `perf`.** So there is no cycles, no instructions and no
    `sys_enter_pwrite64` column here. That costs less than it sounds: round 43
    established on its own rig that wall is bimodal in "staged or not" and
    tracks NEITHER the call count nor the copy's cycles, so the column this
    round needs is the one it can still read. `getrusage` gives user and system
    seconds through `os.wait4`, and they are reported.
  - **NO `findmnt`.** The fstype comes from `/proc/mounts` by longest
    mount-point prefix, and the refusal it feeds is unchanged: a tmpfs or
    ramfs `OUT_ROOT`, or an fstype that cannot be read at all, aborts the
    round. Failing to find is failing.
  - **Device bytes come from `/proc/diskstats`**, summed over `DEVS` (the
    array members, not the dm/md layers above them, which double-count), field
    10 - sectors written - times 512. That is this round's substitute for the
    cgroup's `wbytes` and it is the proof that the spindles were in the loop:
    a leg whose devices wrote ~0 is a page-cache leg and is reported as one
    rather than quoted as a rotational result. It is BOX-WIDE rather than
    per-cgroup, which is why the box must be quiet and held under the rig lock.

The appliance's python is 3.8, so nothing from 3.9 is used here.

env: BIN        the ONE binary (client and server alike), static
     R          round root; OUT_ROOT (must NOT be tmpfs); REPS
     REGIME     warm | over          (labels only; the size is FILES/FILE_SIZE)
     FILES      members per leg      FILE_SIZE  per member
     CELLS      comma subset of the ladder    ARMS  comma subset of ARM_ENV
     DEVS       comma list of block devices to sum diskstats over
"""
import json, os, shutil, signal, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pdrv  # noqa: E402
from pdrv import require_quiet_box, foreign_cpu  # noqa: E402

# THE ONE ADJUSTMENT MADE TO pdrv's QUIET GATE, AND WHY IT IS AT THE SITE.
#
# `foreign_cpu()` means "not this process and not a descendant of it", which
# is the right rule everywhere it is used - and it misreads THIS round on a
# storage appliance. The work under test here is 8 to 61 GB of buffered writes to a
# twelve-disk RAID6, and the CPU that serves those writes is spent in KERNEL
# THREADS, which are nobody's descendants: `md2_raid6` computes the parity for
# my own payload, and the `kworker`/`btrfs`/`kswapd`/`flush` threads are the
# writeback my own dirty pages create. Counted as foreign they are my own leg
# scoring itself as somebody else's load, and at the 120% ceiling this box's
# core count gives they can abort the round in its middle - the heavier the
# write arm, the likelier it aborts, which would bias the comparison toward
# exactly the arm this round is trying to price.
#
# So the gate below subtracts those NAMED threads, and nothing else. It does
# not raise the ceiling, it does not widen to any user process, and the
# unfiltered total is still what every leg records in its `foreign` field, so
# the log carries the number the gate did not act on. The exclusion is safe
# only because the round holds the rig lock: no other lane's I/O is in those
# threads while it does.
KERNEL_IO = ("md2_raid6", "md1_raid1", "md0_raid1", "kworker", "btrfs",
             "kswapd", "flush-", "jbd2", "dm_bufio", "syno_")


def kernel_io_cpu():
    """The part of `foreign_cpu()` that is this round's own writeback."""
    total, _top = foreign_cpu()
    rows = pdrv._ps_snapshot()
    mine = 0.0
    for _pid, _ppid, pcpu, comm in rows:
        if pcpu >= 1.0 and any(comm.startswith(k) for k in KERNEL_IO):
            mine += pcpu
    return total, mine


def quiet_gate(where):
    """pdrv's gate, with `kernel_io_cpu()`'s named threads taken out first.

    Implemented by lowering what the gate SEES rather than by raising what it
    allows: `pdrv.FOREIGN_CPU_CEILING_FRAC` is left exactly where it is, and
    the ceiling is restored before returning, so nothing about this call
    outlives it."""
    total, kio = kernel_io_cpu()
    ceiling = pdrv.foreign_ceiling()
    if kio > 0:
        print("QUIET-GATE at=%s foreign=%.0f%% of which kernel-io=%.0f%% ceiling=%.0f%%"
              % (where, total, kio, ceiling), flush=True)
    saved = pdrv.FOREIGN_CPU_CEILING_FRAC
    try:
        pdrv.FOREIGN_CPU_CEILING_FRAC = (ceiling + kio) / (pdrv.cpu_count() * 100.0)
        return require_quiet_box(where)
    finally:
        pdrv.FOREIGN_CPU_CEILING_FRAC = saved

R = os.environ.get("R", os.path.expanduser("~/wstagenas-17sep"))
BIN = os.environ["BIN"]
REPS = int(os.environ.get("REPS", "3"))
OUT_ROOT = os.environ.get("OUT_ROOT", os.path.join(R, "out"))
OUTDIR = os.path.join(OUT_ROOT, "leg")
REGIME = os.environ.get("REGIME", "over")
CLIENT_CPUS = os.environ.get("CLIENT_CPUS", "0-5")
SERVER_CPUS = os.environ.get("SERVER_CPUS", "6-11")
CONNS = os.environ.get("CONNS", "8")
FILES = int(os.environ.get("FILES", "16"))
FILE_SIZE = os.environ.get("FILE_SIZE", "512M")
DEVS = os.environ.get("DEVS", "sda,sdb,sdc,sdd,sde,sdf,sdg,sdh,sdi,sdj,sdk,sdl").split(",")

# Round 43's ladder, unchanged, so a row here can be read against a row there.
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
    "nostage": {"NZBFAST_WRITE_COALESCE_MAX_ART_KB": "8"},
    "stage": {"NZBFAST_WRITE_COALESCE_MAX_ART_KB": "1024"},
    "run129": {"NZBFAST_WRITE_COALESCE_RUN_KB": "129"},
    "run384": {"NZBFAST_WRITE_COALESCE_RUN_KB": "384"},
    "aa": {},                                          # the noise floor
}
ORDER_CELLS = os.environ.get("CELLS", "a128,a250").split(",")
ARMS = os.environ.get("ARMS", "on,nostage,aa").split(",")
LOG = os.path.join(R, os.environ.get("OUT", "wstagenas-%s.jsonl" % REGIME))
LEGDIR = os.path.join(R, "legs")
os.makedirs(LEGDIR, exist_ok=True)


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fstype_of(path):
    """Longest mount-point prefix in /proc/mounts. There is no `findmnt` here."""
    path = os.path.realpath(path)
    best, best_type = "", ""
    with open("/proc/mounts") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            mp = parts[1].replace("\\040", " ")
            if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) > len(best):
                best, best_type = mp, parts[2]
    return best_type


def refuse_ram_disk():
    os.makedirs(OUT_ROOT, exist_ok=True)
    st = os.statvfs(OUT_ROOT)
    ft = fstype_of(OUT_ROOT)
    if not ft:
        raise SystemExit("cannot read the filesystem type of %s - refusing" % OUT_ROOT)
    if ft in ("tmpfs", "ramfs"):
        raise SystemExit("OUT_ROOT=%s is %s. THE ROUND BEFORE THIS ONE WROTE TO RAM." % (OUT_ROOT, ft))
    free_gb = st.f_bavail * st.f_frsize / 1e9
    need = 2.5 * FILES * (512 if FILE_SIZE.endswith("M") else 1) * int(FILE_SIZE[:-1]) / 1e3
    if free_gb < max(30.0, need):
        raise SystemExit("only %.1f GB free under %s - refusing" % (free_gb, OUT_ROOT))
    rot = []
    for d in DEVS:
        try:
            with open("/sys/block/%s/queue/rotational" % d) as f:
                rot.append(f.read().strip())
        except OSError:
            rot.append("?")
    print("OUT_ROOT %s fstype=%s free=%.1fGB regime=%s files=%dx%s rotational=%s"
          % (OUT_ROOT, ft, free_gb, REGIME, FILES, FILE_SIZE, ",".join(rot)), flush=True)
    return ft


def dev_wsectors():
    """Sectors written, summed over DEVS, from /proc/diskstats field 10."""
    tot = 0
    with open("/proc/diskstats") as f:
        for line in f:
            p = line.split()
            if len(p) >= 10 and p[2] in DEVS:
                tot += int(p[9])
    return tot


def meminfo(key):
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith(key + ":"):
                return int(line.split()[1]) * 1024
    return 0


def tree_bytes(d):
    n = 0
    for root, _dirs, files in os.walk(d):
        for name in files:
            try:
                n += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return n


def wait_port(port, pid, secs=900):
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
           "--file-size", FILE_SIZE, "--article-size", asize, "--nzb", nzb]
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
        p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def clear_out():
    shutil.rmtree(OUTDIR, ignore_errors=True)
    subprocess.call(["sync"])
    os.makedirs(OUTDIR)


def leg(cell, arm, nzb, cfg, rep, keep=True):
    clear_out()
    time.sleep(4)
    quiet_gate("%s/%s/%s/rep%d" % (REGIME, cell, arm, rep))
    tag = "%s-%s-%s-r%d" % (REGIME, cell, arm, rep)
    env = dict(os.environ)
    env["NZBFAST_NO_ENRICH"] = "1"
    env.update(ARM_ENV[arm])
    cmd = ["nice", "-n", "19", "taskset", "-c", CLIENT_CPUS, BIN,
           "--config", cfg, "get", nzb, "--out", OUTDIR, "--connections", CONNS]
    w0 = dev_wsectors()
    dirty0 = meminfo("Dirty")
    out = open(os.path.join(LEGDIR, tag + ".out"), "w")
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
    _pid, status, ru = os.wait4(p.pid, 0)
    wall = time.time() - t0
    rc = status if status == 0 else (status >> 8 if status & 0xFF == 0 else status)
    dirty1 = meminfo("Dirty")
    t1 = time.time()
    subprocess.call(["sync"])
    sync_s = time.time() - t1
    wb = (dev_wsectors() - w0) * 512
    nbytes = tree_bytes(OUTDIR)
    row = dict(ts=utcnow(), regime=REGIME, cell=cell, arm=arm, rep=rep, rc=rc,
               wall=wall, sync_s=sync_s, utime=ru.ru_utime, stime=ru.ru_stime,
               cpu=ru.ru_utime + ru.ru_stime, maxrss_kb=ru.ru_maxrss,
               minflt=ru.ru_minflt, majflt=ru.ru_majflt,
               dev_wbytes=wb, dirty_end=dirty1, dirty_start=dirty0,
               files=FILES, file_size=FILE_SIZE, bytes=nbytes,
               keep=keep, foreign=foreign_cpu()[0])
    if keep:
        with open(LOG, "a") as f:
            f.write(json.dumps(row) + "\n")
    print("LEG %-5s %-7s r%d rc=%s wall=%.2f sync=%.2f cpu=%.2f (u %.2f s %.2f) "
          "devW=%.2fGB GB=%.3f%s"
          % (cell, arm, rep, rc, wall, sync_s, row["cpu"], ru.ru_utime, ru.ru_stime,
             wb / 1e9, nbytes / 1e9, "" if keep else " DISCARD"), flush=True)
    shutil.rmtree(OUTDIR, ignore_errors=True)
    return row


def main():
    refuse_ram_disk()
    ram = meminfo("MemTotal")
    payload = FILES * int(FILE_SIZE[:-1]) * (1 << 20 if FILE_SIZE.endswith("M") else 1 << 30)
    print("wstagenas round start %s R=%s regime=%s reps=%d cells=%s arms=%s "
          "payload=%.2fGB ram=%.2fGB bin=%s"
          % (utcnow(), R, REGIME, REPS, ORDER_CELLS, ARMS, payload / 1e9, ram / 1e9, BIN),
          flush=True)
    if REGIME == "over" and payload < ram:
        print("WARN regime=over but the payload is SMALLER than RAM - this leg can "
              "be absorbed by the page cache and is not an over-RAM result", flush=True)
    try:
        for cell in ORDER_CELLS:
            srv, nzb, cfg = start_server(cell)
            try:
                # THE FIRST LEG OF A PHASE IS AN OUTLIER (round 43 section 5):
                # two legs there read 223 s and 422 s against ~10 s and ~50 s
                # neighbours, both the leg that runs straight after a mockserve
                # for a new cell materialises its payload. Discarded by
                # CONSTRUCTION here rather than by naming it afterwards.
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
    print("wstagenas round done %s" % utcnow(), flush=True)


if __name__ == "__main__":
    main()
