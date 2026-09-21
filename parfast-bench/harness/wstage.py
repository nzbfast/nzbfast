#!/usr/bin/env python3
"""wstage.py - is the one-pass writer's WRITE-COALESCING WINDOW the memcpy a
small-article download spends a third of its CPU in?

Claim `daemon-small-article-memcpy-share-16sep`, item 2 of
an internal note section 9: that round measured a
128 KB-article `nzbfast get` spending **33.9%** of client CPU in `memcpy`
against **3.9%** for the same 8.19 GB in 740 KB articles, and could not say
where. The attribution is `nzbkit_base::disk::stage::WriteStage::offer` -
`crates/nzbkit-base/src/disk/stage.rs` - which copies every staged byte into a
per-file run so several articles can leave as ONE positioned write, and which
by construction stages nothing at or above `STAGE_MAX_ARTICLE_DEFAULT`
(256 KiB). A 740 KB article is never staged; a 128 KB one always is. That
constant, not anything about the wire or the decoder, is the whole of "only
the article size differs".

**This is not dmem.py with different cells, and the difference is the arm.**
Every arm here is the SAME BINARY under a different environment, because the
window is an env knob (`NZBFAST_WRITE_COALESCE_KB`, 0 = off) and a knob is
the one thing that can be A/B'd with no build, no cross-compile and no
second artifact to sha256. dmem.py's arms are paths and it has nowhere to put
this; everything else here - the quiet gate, the client/server core pin, the
rotation, `perf stat` on the client only, the A/A arm - is inherited from it
unchanged and is not optional.

The A/A arm is the DEFAULT ARM RUN TWICE under a second name. On an
env-only round that is exactly what an A/A is, and it is what says whether a
ratio is real: the 16 Sep round's own cycles column had an A/A of +-5-8% on
this box where its instructions column had +-0.3%.

**AND SINCE 17 SEP AN ARM MAY BE A SECOND BINARY, which is the one thing the
paragraph above says this round did not need.** The follow-up the 16 Sep
round filed as its item 1 - a run-buffer free list, claim
`wstage-run-buffer-pool-16sep` - is a CODE change, and a code change cannot
be an environment. `BIN_B` names a second binary and `ARM_BIN` says which
arms take it; everything else is unchanged, so the two binaries' arms are
still interleaved WITHIN a rep and the ratios are still paired per rep,
which is the property that would have been lost by running two rounds
back to back.

Two things make a cross-binary arm honest, and neither is optional:
- **The SERVER is held constant** (`SERVER_BIN`, defaulting to `BIN`), so
  only the client moves. `mockserve` does not touch the writer, but "the
  same binary, a constant" is what the 16 Sep round said about its server
  and it stays true here by construction rather than by argument.
- **The `plain` cell IS the cross-binary A/A.** A 740 KB article is never
  staged, so no line of the changed code runs in that cell: a `B/A` ratio
  that reads 1.00 there is the two builds saying they are the same binary
  everywhere the change does not reach. The `aa` arm remains the
  within-binary floor. A round with a second binary must run BOTH cells
  for this reason, whatever it is measuring.

env: BIN     the binary every arm uses unless ARM_BIN says otherwise
     BIN_B   a SECOND binary, for arms that are a code change (optional)
     SERVER_BIN  the mockserve binary; defaults to BIN
     R       rig root, REPS, CELLS (comma subset of small,plain)
     ARMS    comma list of arm names from ARM_ENV below
"""
import json, os, shutil, signal, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import require_quiet_box, foreign_cpu, harness_facts  # noqa: E402

R = os.environ.get("R", "/root/wstage-16sep")
BIN = os.environ["BIN"]
REPS = int(os.environ.get("REPS", "5"))
OUTDIR = "/dev/shm/wstage-out"
CLIENT_CPUS = os.environ.get("CLIENT_CPUS", "0-3")
SERVER_CPUS = os.environ.get("SERVER_CPUS", "4-7")
CONNS = os.environ.get("CONNS", "8")
FILES = int(os.environ.get("FILES", "16"))
SERVER_BIN = os.environ.get("SERVER_BIN") or BIN

# name: (port, article_size). The two cells the finding is a contrast
# between, and nothing else - par2 and tls are the parent round's and move
# no part of this question.
CELLS = {"small": (11950, "128K"), "plain": (11951, "740K")}
# The arms are ENVIRONMENTS. `on` is the shipped default (the window at
# 4 MiB per file); `off` is the pre-round-42 write path, one article one
# pwrite; `aa` is `on` again, which is the noise floor.
ARM_ENV = {
    "on": {},
    "off": {"NZBFAST_WRITE_COALESCE_KB": "0"},
    # THE REALLOC ARM, and it needs NO code change - which is why it is
    # here rather than in a second binary. `offer` opens a run at
    # `Vec::with_capacity(run_cap.min(data.len() * 4))` and takes it out
    # once it reaches `run_cap`, so at the shipped 1 MiB run cap a
    # 128 KB article opens a 512 KiB run that must realloc once to
    # 1 MiB - a second copy of half of every run, which the macOS
    # call-graph profile sees as `_mi_theap_realloc_zero -> memmove`,
    # 2.03% of on-CPU against the staging copy's 3.78%. Setting the run
    # cap TO 512 KiB makes the opening capacity and the take threshold
    # the same number, so the run fills exactly and never grows. It
    # halves the coalescing at the same time, so this arm prices the two
    # together and is a bound on the realloc's share, not an isolation
    # of it.
    "norealloc": {"NZBFAST_WRITE_COALESCE_RUN_KB": "512"},
    "aa": {},
    # THE POOL ARM. Shipped environment, SECOND BINARY (`BIN_B`) - the run
    # buffers come from a free list and are minted at the largest a run can
    # reach, so the realloc `norealloc` bounded from above is gone outright
    # and the per-run malloc/free churn with it. Its contrast is `on`; its
    # noise floor is `aa`; its cross-binary null is the whole `plain` cell.
    "pool": {},
    # THE CROSS-BINARY NULL, IN THE CELL THAT MATTERS, and it is the arm a
    # two-binary round on this box turns out to need. `pooloff` is BIN_B with
    # the window switched off, so it takes `write_article_direct` and not one
    # line of `disk::stage` runs - exactly like `off` on BIN. The two are
    # therefore the same work in the same cell on the same articles, and
    # `pooloff`/`off` is the price of the BUILD rather than of the change.
    #
    # The `plain` cell is a null too and is cheaper, but it is a null in a
    # DIFFERENT cell: a 740 KB leg retires 29 G instructions where a 128 KB
    # leg retires 36 G and touches a seventh the pages, so it cannot bound a
    # layout effect in the small cell. The 17 Sep round measured the small
    # cell's cycles moving 5% between two binaries compiled from trees that
    # differ in four files, and nothing but this arm can say how much of a
    # treatment's cycles column that is.
    "pooloff": {"NZBFAST_WRITE_COALESCE_KB": "0"},
}
# Arms whose binary is not BIN. An arm named here with no BIN_B set is a
# configuration error and is refused at startup rather than silently run
# against BIN, which would report a null and look like a result.
ARM_BIN = {a: os.environ.get("BIN_B") for a in ("pool", "pooloff")}
ORDER_CELLS = os.environ.get("CELLS", "small,plain").split(",")
# Which arms get a `perf record` leg after the timed round, intersected with
# ARMS so naming one that is not running is a no-op rather than a crash at
# minute twenty. The default is the 16 Sep round's three; a round whose
# treatment is a CODE arm wants its own arm in here instead of `off`
# (PROFILE_ARMS=on,pool), because the profile is what says the memcpy moved
# rather than merely that the leg got faster.
PROFILE_ARMS = os.environ.get("PROFILE_ARMS", "on,off,norealloc").split(",")
ARMS = os.environ.get("ARMS", "on,off,norealloc,aa").split(",")
LOG = os.path.join(R, os.environ.get("OUT", "wstage.jsonl"))
LEGDIR = os.path.join(R, "legs")
os.makedirs(LEGDIR, exist_ok=True)


def arm_bin(arm):
    """The binary this arm runs. `BIN` unless ARM_BIN names another."""
    return ARM_BIN.get(arm) or BIN


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


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
    cmd = ["taskset", "-c", SERVER_CPUS, SERVER_BIN, "mockserve",
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


def leg(cell, arm, nzb, cfg, rep):
    shutil.rmtree(OUTDIR, ignore_errors=True)
    os.makedirs(OUTDIR)
    # The previous leg's 8 GB of tmpfs pages need to finish being reclaimed;
    # overlapping two legs doubles the sys term (dmem.py's note, kept).
    time.sleep(4)
    require_quiet_box("%s/%s/rep%d" % (cell, arm, rep))
    tag = "%s-%s-r%d" % (cell, arm, rep)
    perf = os.path.join(LEGDIR, tag + ".perf")
    env = dict(os.environ)
    env["NZBFAST_NO_ENRICH"] = "1"
    env.update(ARM_ENV[arm])
    cmd = ["nice", "-n", "19", "perf", "stat", "-x,", "-o", perf,
           "-e", "cycles,instructions", "--",
           "taskset", "-c", CLIENT_CPUS, arm_bin(arm),
           "--config", cfg, "get", nzb, "--out", OUTDIR, "--connections", CONNS]
    out = open(os.path.join(LEGDIR, tag + ".out"), "w")
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
    _pid, status, ru = os.wait4(p.pid, 0)
    wall = time.time() - t0
    rc = status if status == 0 else (status >> 8 if status & 0xFF == 0 else status)
    cycles = insns = None
    with open(perf) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) > 2 and parts[2] == "cycles":
                cycles = None if parts[0].startswith("<") else float(parts[0])
            if len(parts) > 2 and parts[2] == "instructions":
                insns = None if parts[0].startswith("<") else float(parts[0])
    nbytes = tree_bytes(OUTDIR)
    row = dict(ts=utcnow(), cell=cell, arm=arm, rep=rep, rc=rc, wall=wall,
               bin=arm_bin(arm),
               utime=ru.ru_utime, stime=ru.ru_stime,
               cpu=ru.ru_utime + ru.ru_stime, maxrss_kb=ru.ru_maxrss,
               minflt=ru.ru_minflt, cycles=cycles, instructions=insns,
               bytes=nbytes, foreign=foreign_cpu()[0])
    with open(LOG, "a") as f:
        f.write(json.dumps(row) + "\n")
    print("LEG %-6s %-4s r%d rc=%s wall=%.2f cpu=%.2f (u %.2f s %.2f) cyc=%s ins=%s GB=%.3f"
          % (cell, arm, rep, rc, wall, row["cpu"], ru.ru_utime, ru.ru_stime,
             "%.3fG" % (cycles / 1e9) if cycles else "-",
             "%.3fG" % (insns / 1e9) if insns else "-", nbytes / 1e9), flush=True)
    shutil.rmtree(OUTDIR, ignore_errors=True)
    return row


def profile(cell, arm, nzb, cfg):
    """One `perf record` leg per arm, AFTER the timed round and under the
    same lock. The parent round's finding IS a profile attribution, so the
    confirmation has to be one too: `memcpy` must fall out of the `off` arm
    and it must fall to roughly what the 740 KB cell reads."""
    shutil.rmtree(OUTDIR, ignore_errors=True)
    os.makedirs(OUTDIR)
    time.sleep(4)
    tag = "prof-%s-%s" % (cell, arm)
    data = os.path.join(LEGDIR, tag + ".data")
    env = dict(os.environ)
    env["NZBFAST_NO_ENRICH"] = "1"
    env.update(ARM_ENV[arm])
    # -g so the profile names the CALLER: the parent round's 12 profiles were
    # taken without it, which is why they could name `memcpy` and not the
    # site, and is the whole reason this item existed.
    cmd = ["perf", "record", "-F", "999", "-g", "-o", data, "--",
           "taskset", "-c", CLIENT_CPUS, arm_bin(arm),
           "--config", cfg, "get", nzb, "--out", OUTDIR, "--connections", CONNS]
    with open(os.path.join(LEGDIR, tag + ".out"), "w") as out:
        rc = subprocess.call(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
    flat = subprocess.run(["perf", "report", "-i", data, "--stdio", "--no-children",
                           "--sort", "symbol", "--percent-limit", "0.30"],
                          capture_output=True, text=True).stdout
    cg = subprocess.run(["perf", "report", "-i", data, "--stdio", "--no-children",
                         "-g", "graph,0.5,caller", "--percent-limit", "1.0"],
                        capture_output=True, text=True).stdout
    with open(os.path.join(LEGDIR, tag + ".report"), "w") as f:
        f.write(flat + "\n\n===== CALL GRAPH =====\n\n" + cg)
    print("PROFILE %s %s rc=%s" % (cell, arm, rc), flush=True)
    for line in flat.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        print("  " + line.strip()[:150], flush=True)
    shutil.rmtree(OUTDIR, ignore_errors=True)


def main():
    # Refuse an arm whose binary is missing rather than run it against BIN:
    # that would produce a well-formed null and look like a measurement.
    for arm in ARMS:
        if arm in ARM_BIN and not ARM_BIN[arm]:
            raise SystemExit("arm %r needs BIN_B and it is not set" % arm)
        if not os.path.exists(arm_bin(arm)):
            raise SystemExit("arm %r: no such binary %s" % (arm, arm_bin(arm)))
    bins = sorted({arm_bin(a) for a in ARMS} | {SERVER_BIN})
    # The HARNESS's own provenance, and the round-start twin of the
    # per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
    # banked log cannot be traced to the harness revision that wrote
    # it (census an internal note).
    harness_facts()
    print("wstage round start %s R=%s reps=%d cells=%s arms=%s"
          % (utcnow(), R, REPS, ORDER_CELLS, ARMS), flush=True)
    # Every distinct binary's sha256, in the log, because a round with more
    # than one artifact has exactly one new way to be wrong.
    for b in bins:
        sha = subprocess.run(["sha256sum", b], capture_output=True,
                             text=True).stdout.split()[0]
        print("  bin %s %s%s" % (sha, b, "  (server)" if b == SERVER_BIN else ""),
              flush=True)
    for cell in ORDER_CELLS:
        srv, nzb, cfg = start_server(cell)
        try:
            for rep in range(1, REPS + 1):
                order = list(ARMS)
                # Rotate by rep and reverse on even reps - dmem.py's rule,
                # so no arm keeps a fixed neighbour in the thermal order.
                order = order[(rep - 1) % len(order):] + order[:(rep - 1) % len(order)]
                if rep % 2 == 0:
                    order = order[::-1]
                for arm in order:
                    leg(cell, arm, nzb, cfg, rep)
            if cell == "small":
                for arm in [a for a in PROFILE_ARMS if a in ARMS]:
                    profile(cell, arm, nzb, cfg)
        finally:
            stop_server(srv)
    print("wstage round done %s" % utcnow(), flush=True)


if __name__ == "__main__":
    main()
