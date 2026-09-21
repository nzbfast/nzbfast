#!/usr/bin/env python3
"""dmem.py - timed A/B/A of nzbfast DAEMON-side static-musl builds on one
Linux box (claim `memops-daemon-round-16sep`). The `nzbfast` half of the
question `harness/muslspeed.py` answered for `parfast`: the two
landed memops rounds measured PAR2 cells only, and the download's daemon
gets the identical primitives by the identical weak-symbol mechanism.

The workload is the one this repo already has for the daemon's byte path:
`nzbfast mockserve` on loopback, and `nzbfast get` against it. That reaches
the NNTP wire read, the yEnc decode, the CRC32, the live PAR2 verify (in the
`--par2` cells), the rustls record layer (in the TLS cell) and mimalloc. It
does NOT reach RAR extraction or PAR2 repair - mockserve serves a synthetic
set of bare files, so there is no container and no recovery slice. That
limit is the note's, not a bug here, and it is stated in the write-up.

Method inherited from muslspeed.py and NOT optional: three arms (a control
with `fast_mem_ops!()` gated off, the candidate, and an A/A byte-identical
copy of the control), order rotated by rep and reversed on even reps,
`nice -n 19`, a quiet gate before every leg, and every ratio has to beat the
A/A spread.

Two things here are specific to a CLIENT/SERVER workload and are why this is
not just muslspeed with different cells:

  - **The server is a FIXED binary and is pinned away from the client.**
    `taskset -c 0-3` for the client and `4-7` for the server, which is the
    split the 2 Aug 2026 TLS/kTLS round used on this same 8-core box (the
    perf notebook carries that round; this repo's own tls rig driver carries
    the dials). Without it the server's CPU lands in the same cores as the
    leg under test and every wall figure is a measurement of whichever arm
    the scheduler favoured. The server never changes between
    arms, so it is a constant even for wall.
  - **The primary metric is the CLIENT's own perf counters**, not wall.
    `perf stat` wraps the client process only, so the server's cost is
    outside the measurement entirely; wall is reported and is secondary,
    because loopback is transport-bound and a faster client can simply wait
    on the server instead.

The server is spawned as a CHILD of this driver on purpose: pdrv's quiet
gate excludes the driver's own descendants, so the gate prices foreign load
and not our own server.

env: ARMS "name=path,name=path,..." (order is the base rotation)
     SERVER  path to the ONE binary that serves every cell
     REPS, CELLS (comma subset), R (rig root), OUT (jsonl name)
"""
import hashlib, json, os, shutil, signal, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import require_quiet_box, foreign_cpu, harness_facts  # noqa: E402

R = os.environ.get("R", "/root/dmem-16sep")
REPS = int(os.environ.get("REPS", "5"))
OUTDIR = "/dev/shm/dmem-out"
ARMS = [tuple(kv.split("=", 1)) for kv in os.environ["ARMS"].split(",")]
SERVER = os.environ["SERVER"]
CLIENT_CPUS = os.environ.get("CLIENT_CPUS", "0-3")
SERVER_CPUS = os.environ.get("SERVER_CPUS", "4-7")
CONNS = os.environ.get("CONNS", "8")
# The set size is an env dial because the two rigs have different tmpfs: the
# x86_64 box has 16 GB of /dev/shm and takes the 2 Aug round's 16 x 512M =
# 8.19 GB set; armbench has 7.8 GB and does not.
FILES = int(os.environ.get("FILES", "16"))
# armbench has no PMU (Apple Virtualization exposes none), so `perf stat`
# there counts nothing at all. Time is all there is on that rig; PERF=0 drops
# the wrapper rather than publishing a column of "<not supported>".
PERF = os.environ.get("PERF", "1") == "1"

# name: (port, files, file_size, article_size, par2, tls)
CELLS = {
    # The byte path with nothing else on it: wire read, yEnc decode, CRC32,
    # write. 16 x 512M = 8.19 GB, the 2 Aug round's set on this box.
    "plain": (11930, FILES, "512M", "740K", False, False),
    # ...plus live PAR2 verify (MD5 + CRC over every slice), which is what
    # mockserve's --par2 exists to add.
    "par2":  (11931, FILES, "512M", "740K", True, False),
    # ...plus the rustls record layer, which is what every real provider is.
    "tls":   (11932, FILES, "512M", "740K", False, True),
    # The same bytes in 5.8x as many articles: the per-article fixed cost,
    # where the small-size end of the memcpy/memset ladders lives.
    "small": (11933, FILES, "512M", "128K", False, False),
}
ORDER = os.environ.get("CELLS", ",".join(CELLS)).split(",")
LOG = os.path.join(R, os.environ.get("OUT", "dmem.jsonl"))
LEGDIR = os.path.join(R, "legs")
os.makedirs(LEGDIR, exist_ok=True)


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha_tree(d):
    """One hash over the whole output set, names included, so two arms
    differing in a single byte OR in which file got it both show up."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(d):
        dirs.sort()
        for name in sorted(files):
            p = os.path.join(root, name)
            h.update(os.path.relpath(p, d).encode())
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 22), b""):
                    h.update(chunk)
    return h.hexdigest()


def tree_bytes(d):
    n = 0
    for root, _dirs, files in os.walk(d):
        for name in files:
            n += os.path.getsize(os.path.join(root, name))
    return n


def wait_port(port, pid, secs=180):
    """The server hashes a PAR2 index before it listens, so this waits
    minutes and not seconds - and it watches the pid, because a server that
    DIED must not read as a server that is still hashing."""
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
    port, files, fsize, asize, par2, tls = CELLS[cell]
    nzb = os.path.join(R, "%s.nzb" % cell)
    cfg = os.path.join(R, "%s.json" % cell)
    log = open(os.path.join(R, "server-%s.log" % cell), "w")
    cmd = ["taskset", "-c", SERVER_CPUS, SERVER, "mockserve",
           "--port", str(port), "--bind", "127.0.0.1", "--files", str(files),
           "--file-size", fsize, "--article-size", asize, "--nzb", nzb]
    if par2:
        cmd.append("--par2")
    if tls:
        cmd += ["--tls-cert", os.path.join(R, "leaf.pem"),
                "--tls-key", os.path.join(R, "leaf.key")]
    p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    wait_port(port, p)
    with open(cfg, "w") as f:
        # "localhost" and not the literal for the TLS cell: the leaf's SAN
        # carries both, but the host is what rustls checks the name against.
        f.write('{"servers":[{"host":"%s","port":%d,"tls":%s,"connections":%s}]}'
                % ("localhost" if tls else "127.0.0.1", port,
                   "true" if tls else "false", CONNS))
    return p, nzb, cfg


def stop_server(p):
    # BY PID, never by pattern (CLAUDE.md invariant 2/2a) - this box is
    # shared and other lanes run the same command lines.
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def leg(cell, arm, path, nzb, cfg, rep, want_sha):
    shutil.rmtree(OUTDIR, ignore_errors=True)
    os.makedirs(OUTDIR)
    # Let the previous leg's 8 GB of tmpfs pages finish being reclaimed. The
    # sys term is dominated by page allocation and overlapping the two
    # doubles it (the 2 Aug round's note, kept).
    time.sleep(4)
    require_quiet_box("%s/%s/rep%d" % (cell, arm, rep))
    tag = "%s-%s-r%d" % (cell, arm, rep)
    perf = os.path.join(LEGDIR, tag + ".perf")
    env = dict(os.environ)
    env["NZBFAST_NO_ENRICH"] = "1"
    env["NZBFAST_KTLS"] = "0"
    env["NZBFAST_EXTRA_CA"] = os.path.join(R, "ca.pem")
    cmd = ["nice", "-n", "19"]
    if PERF:
        cmd += ["perf", "stat", "-x,", "-o", perf,
                "-e", "cycles,instructions", "--"]
    cmd += ["taskset", "-c", CLIENT_CPUS, path,
            "--config", cfg, "get", nzb, "--out", OUTDIR,
            "--connections", CONNS]
    out = open(os.path.join(LEGDIR, tag + ".out"), "w")
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
    _pid, status, ru = os.wait4(p.pid, 0)
    wall = time.time() - t0
    rc = status if status == 0 else (status >> 8 if status & 0xFF == 0 else status)
    cycles = insns = None
    with open(perf if PERF else os.devnull) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) > 2 and parts[2] == "cycles":
                cycles = None if parts[0].startswith("<") else float(parts[0])
            if len(parts) > 2 and parts[2] == "instructions":
                insns = None if parts[0].startswith("<") else float(parts[0])
    nbytes = tree_bytes(OUTDIR)
    digest = sha_tree(OUTDIR) if want_sha else None
    row = dict(ts=utcnow(), cell=cell, arm=arm, rep=rep, rc=rc, wall=wall,
               utime=ru.ru_utime, stime=ru.ru_stime,
               cpu=ru.ru_utime + ru.ru_stime, maxrss_kb=ru.ru_maxrss,
               minflt=ru.ru_minflt, majflt=ru.ru_majflt,
               nvcsw=ru.ru_nvcsw, nivcsw=ru.ru_nivcsw,
               cycles=cycles, instructions=insns, bytes=nbytes, sha=digest,
               foreign=foreign_cpu()[0])
    with open(LOG, "a") as f:
        f.write(json.dumps(row) + "\n")
    print("LEG %-6s %-6s r%d rc=%s wall=%.2f cpu=%.2f cyc=%s ins=%s GB=%.3f%s"
          % (cell, arm, rep, rc, wall, row["cpu"],
             "%.3fG" % (cycles / 1e9) if cycles else "-",
             "%.3fG" % (insns / 1e9) if insns else "-",
             nbytes / 1e9, "" if digest is None else " sha=" + digest[:12]),
          flush=True)
    shutil.rmtree(OUTDIR, ignore_errors=True)
    return row


def profile(cell, arm, path, nzb, cfg):
    """One `perf record` leg per arm per cell, AFTER the timed round and under
    the same lock. This is the half that makes a FLAT result readable: the
    parent round's finding started as a profile attribution
    (`compiler_rt.memset` 6.4-13.1% of the musl profiles), and a daemon cell
    that does not move should be able to say whether that is because the
    routines are already cheap here or because the change did not work."""
    if not PERF:
        print("PROFILE skipped: no PMU on this rig", flush=True)
        return
    shutil.rmtree(OUTDIR, ignore_errors=True)
    os.makedirs(OUTDIR)
    time.sleep(4)
    tag = "prof-%s-%s" % (cell, arm)
    data = os.path.join(LEGDIR, tag + ".data")
    env = dict(os.environ)
    env["NZBFAST_NO_ENRICH"] = "1"
    env["NZBFAST_KTLS"] = "0"
    env["NZBFAST_EXTRA_CA"] = os.path.join(R, "ca.pem")
    cmd = ["perf", "record", "-F", "999", "-o", data,
           "--", "taskset", "-c", CLIENT_CPUS, path,
           "--config", cfg, "get", nzb, "--out", OUTDIR,
           "--connections", CONNS]
    with open(os.path.join(LEGDIR, tag + ".out"), "w") as out:
        rc = subprocess.call(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
    rep = subprocess.run(["perf", "report", "-i", data, "--stdio",
                          "--sort", "symbol", "--percent-limit", "0.30"],
                         capture_output=True, text=True)
    txt = rep.stdout
    with open(os.path.join(LEGDIR, tag + ".report"), "w") as f:
        f.write(txt)
    print("PROFILE %s %s rc=%s" % (cell, arm, rc), flush=True)
    for line in txt.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        print("   " + line.strip()[:110], flush=True)
    shutil.rmtree(OUTDIR, ignore_errors=True)


def main():
    require_quiet_box("round-start")
    # The HARNESS's own provenance, and the round-start twin of the
    # per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
    # banked log cannot be traced to the harness revision that wrote
    # it (census an internal note).
    harness_facts()
    print("dmem round start %s R=%s reps=%d cells=%s arms=%s"
          % (utcnow(), R, REPS, ORDER, [a for a, _ in ARMS]), flush=True)
    for ci, cell in enumerate(ORDER):
        srv, nzb, cfg = start_server(cell)
        try:
            if os.environ.get("PROFILE") == "1":
                for arm, path in ARMS:
                    profile(cell, arm, path, nzb, cfg)
                continue
            for rep in range(1, REPS + 1):
                # Rotate by rep AND by cell, reverse on even reps: no arm
                # keeps a position in the cache/thermal order.
                k = (rep - 1 + ci) % len(ARMS)
                order = ARMS[k:] + ARMS[:k]
                if rep % 2 == 0:
                    order = list(reversed(order))
                for arm, path in order:
                    leg(cell, arm, path, nzb, cfg, rep, want_sha=(rep == 1))
        finally:
            stop_server(srv)
    print("dmem round done %s" % utcnow(), flush=True)


if __name__ == "__main__":
    main()
