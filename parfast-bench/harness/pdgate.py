#!/usr/bin/env python3
"""pdgate.py - the TIMED half of the daemon's cgroup-gated mimalloc purge
delay (claim daemon-purge-delay-gate-build-16sep).

daemon512.py measures the same knob's MEMORY on a box with cgroup v2 and
root. This driver measures its COST on a quiet box with neither: the real
daemon downloading and repairing the note's 64 KiB set over a loopback
chaos-serve, fixture on tmpfs so every leg is CPU-bound and an madvise plus
a re-zeroed page on reuse has nowhere to hide behind I/O.

FOUR ARMS, and only one of them is a different binary, deliberately - round
1 of the spill-flush round had an A/A pair of two builds and its floor
swallowed every wall comparison in it:

  base  ctrl binary, default env          the control
  aa    a BYTE COPY of ctrl, default env  the A/A floor: same bytes, same work
  pd10  ctrl binary, MIMALLOC_PURGE_DELAY=10
                                          what the built call does, reached
                                          by the env route (this box has no
                                          cgroup, so the call itself cannot
                                          fire here - see LIMITS)
  cand  the candidate binary, default env the gate INERT: unbounded, it must
                                          read as a second A/A

Per job: total wall (submit to history verdict), the daemon's own utime /
stime / minflt / majflt deltas out of /proc/<pid>/stat, VmHWM, the
REPAIR_TIMING phase lines out of the daemon log slice, every output member
SHA-256 gated against gold, 1-minute load before and after, and foreign
CPU-seconds over the leg from /proc/stat so a neighbour is visible rather
than assumed away.

Arm order is rotated one step per rep so no arm keeps a position, and every
leg waits for the 1-minute load to fall under QUIET (1.5) before it starts.

LIMITS, stated here because they decide what the round can conclude: this
box has no cgroup memory limit and no root, so `cgroup_mem_limit()` answers
None and the BUILT call is a no-op on it. The pd10 arm reaches the identical
mimalloc option with the identical value by the environment, which is how
every arm of the 16 Sep memory round was set; what it does not exercise is
the gate itself, which is what the `cand` arm and the cgroup round cover.

RUN, holding the rig lock (this script does not take it):
    R=/dev/shm/pdgate-16sep REPS=5 RUNGS=2048,4096 python3 pdgate.py
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import apply_damage, damage_picks, remove_strays, restore_slices  # noqa: E402

R = os.environ.get("R", "/dev/shm/pdgate-16sep")
BINDIR = os.environ.get("BINDIR", os.path.join(R, "bin"))
OUT = os.path.join(R, os.environ.get("OUT", "pdgate.jsonl"))
LOGDIR = os.path.join(R, "legs")
REPS = int(os.environ.get("REPS", "5"))
RUNGS = [int(x) for x in os.environ.get("RUNGS", "2048,4096").split(",")]
QUIET = float(os.environ.get("QUIET", "1.5"))
QUIET_TRIES = int(os.environ.get("QUIET_TRIES", "120"))
JOB_TIMEOUT = float(os.environ.get("JOB_TIMEOUT", "1800"))
SETTLE = float(os.environ.get("SETTLE", "8"))
# THE BOUND, and the round is close to meaningless without it. This box has
# no cgroup, so `MemBudget::auto` publishes RAM/4 (~11.5 GB here) and the
# repair solves WHOLE in memory: one slab, no spill, W=512, zero NTT
# windows - measured 06:18Z, and nothing like the dispatch inside a 512 MiB
# container, which is 2 slabs of 32,768 B with output Spill and W=128. The
# purge delay's cost lives in exactly the feed-batch and NTT-window churn
# that only the SLABBED repair does, so the arms have to run it.
# `auto_total` publishes `min(host, cgroup/2)`, so 268435456 (256 MiB) is
# the budget a 512 MiB cgroup would have published, byte for byte
# (`nzbkit-base/src/mem.rs`), and it is checked against the note's dispatch
# per leg rather than assumed.
MEMLIMIT = os.environ.get("MEMLIMIT") or None
DPORT = int(os.environ.get("DPORT", "16731"))
CPORT = int(os.environ.get("CPORT", "16741"))
APIKEY = "pdgate" + "0" * 26
SLICE = 65536
TICK = os.sysconf("SC_CLK_TCK")

# arm -> (binary basename, extra env for the daemon)
ARMS = [
    ("base", "nzbfast-ctrl", {}),
    ("aa", "nzbfast-aa", {}),
    ("pd10", "nzbfast-ctrl", {"MIMALLOC_PURGE_DELAY": "10"}),
    ("cand", "nzbfast-cand", {}),
]
os.makedirs(LOGDIR, exist_ok=True)


def log(msg):
    print("%s %s" % (time.strftime("%H:%M:%SZ", time.gmtime()), msg), flush=True)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def proc_stat(pid):
    """utime, stime, minflt, majflt in one read, as the kernel reports them."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            txt = f.read()
    except OSError:
        return None
    # comm can contain spaces and parentheses: split after the last ')'
    tail = txt[txt.rindex(")") + 2:].split()
    return {
        "minflt": int(tail[7]),
        "majflt": int(tail[9]),
        "utime": int(tail[11]),
        "stime": int(tail[12]),
    }


def vmhwm_kib(pid):
    try:
        for line in open("/proc/%d/status" % pid):
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def cpu_jiffies():
    """busy jiffies of the whole box, for the foreign-CPU column."""
    with open("/proc/stat") as f:
        parts = f.readline().split()[1:]
    vals = [int(x) for x in parts]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return sum(vals) - idle


def wait_quiet(where):
    for i in range(QUIET_TRIES):
        la = os.getloadavg()[0]
        if la < QUIET:
            return la
        if i % 10 == 0:
            log("waiting for a quiet box at %s: load %.2f" % (where, la))
        time.sleep(15)
    raise SystemExit("box never went quiet at " + where)


def api(mode, extra=""):
    url = "http://127.0.0.1:%d/api?mode=%s&apikey=%s&output=json%s" % (DPORT, mode, APIKEY, extra)
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode())


class Fixture:
    def __init__(self):
        fix = os.path.join(R, "fix")
        self.pristine, self.work = os.path.join(fix, "pristine"), os.path.join(fix, "work")
        if not os.path.isdir(self.work):
            shutil.copytree(self.pristine, self.work)
        self.members = sorted(f for f in os.listdir(self.pristine) if f.endswith(".bin"))
        self.par2 = sorted(f for f in os.listdir(self.pristine) if f.endswith(".par2"))
        self.gold = {}
        for line in open(os.path.join(fix, "gold.sha")):
            h, name = line.split()
            self.gold[name.lstrip("*")] = h
        self.keep = set(os.listdir(self.pristine))

    def bad(self, d):
        out = []
        for m in self.members:
            p = os.path.join(d, m)
            if not os.path.exists(p) or sha(p) != self.gold[m]:
                out.append(m)
        return out

    def restore(self, picks):
        remove_strays(self.work, self.keep)
        restore_slices(self.work, self.pristine, self.members, SLICE, picks)
        for m in self.bad(self.work):
            shutil.copyfile(os.path.join(self.pristine, m), os.path.join(self.work, m))
        if self.bad(self.work):
            raise SystemExit("restore failed")


class Daemon:
    n = 0

    def __init__(self, arm, binary, extra_env):
        Daemon.n += 1
        self.arm = arm
        self.seq = Daemon.n
        self.S = os.path.join(R, "d-%s-%d" % (arm, Daemon.n))
        os.makedirs(os.path.join(self.S, "out"), exist_ok=True)
        with open(os.path.join(self.S, "config.json"), "w") as f:
            json.dump(CONFIG, f)
        with open(os.path.join(self.S, "settings.json"), "w") as f:
            json.dump({"index_enabled": False, "index_groups": []}, f)
        self.logp = os.path.join(LOGDIR, "daemon-%s-%d.log" % (arm, Daemon.n))
        self.bin = os.path.join(BINDIR, binary)
        argv = [self.bin, "--config", os.path.join(self.S, "config.json")]
        if MEMLIMIT:
            # a GLOBAL flag, before the subcommand, as daemon512.py places it
            argv += ["--mem-limit", MEMLIMIT]
        argv += ["serve", "--port", str(DPORT), "--bind", "127.0.0.1",
                 "--out", os.path.join(self.S, "out"), "--apikey", APIKEY, "--min-free", "0"]
        env = dict(os.environ, NZBFAST_NO_ENRICH="1", NZBFAST_REPAIR_TIMING="1")
        # the arm is the ONLY MIMALLOC_* the daemon sees: a stray one from the
        # shell would make every arm the same arm
        for k in list(env):
            if k.startswith("MIMALLOC_"):
                env.pop(k)
        env.update(extra_env)
        self.fl = open(self.logp, "ab")
        # nice 0 in both the daemon and the server: this is a TIMED round on a
        # quiet box, and a niced daemon under a less-niced server would put
        # scheduling latency into the wall being measured. Popen gives the
        # daemon's own pid, so nothing here kills by pattern - and nothing
        # needs a port lookup either (this box has no lsof).
        self.p = subprocess.Popen(argv, cwd=self.S, stdout=self.fl,
                                  stderr=subprocess.STDOUT, env=env)
        self.pid = self.p.pid
        t0 = time.monotonic()
        while time.monotonic() - t0 < 180:
            if self.p.poll() is not None:
                raise SystemExit("daemon exited at launch, see " + self.logp)
            try:
                api("version")
                break
            except Exception:
                time.sleep(0.25)
        else:
            raise SystemExit("daemon never answered, see " + self.logp)
        self.jobs = 0
        log("daemon %s (%s) up pid=%d in %.1fs" % (arm, binary, self.pid, time.monotonic() - t0))

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait(timeout=30)
        self.fl.close()
        log("daemon %s pid %d stopped" % (self.arm, self.pid))


def start_chaos(fx, ctrl_bin, m, seed, S):
    nzb = os.path.join(S, "job-m%d-s%d.nzb" % (m, seed))
    clog = os.path.join(S, "chaos-m%d-s%d.log" % (m, seed))
    argv = [ctrl_bin, "chaos-serve", "--profile", "clean", "--bind", "127.0.0.1",
            "--port", str(CPORT), "--port2", str(CPORT + 1), "--files", "0",
            "--per-conn", "100G", "--nzb", nzb, "--seed", str(seed)]
    for f in fx.members:
        argv += ["--media", os.path.join(fx.work, f)]
    for f in fx.par2:
        argv += ["--media", os.path.join(fx.pristine, f)]
    fl = open(clog, "wb")
    # the server is not the subject and is the SAME binary in every arm
    cenv = {k: v for k, v in os.environ.items() if not k.startswith("MIMALLOC_")}
    p = subprocess.Popen(argv, cwd=S, stdout=fl,
                         stderr=subprocess.STDOUT, env=cenv)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 300:
        if p.poll() is not None:
            raise SystemExit("chaos-serve exited, see " + clog)
        if os.path.exists(nzb):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/" % CPORT, timeout=1)
            except Exception:
                pass
            break
        time.sleep(0.25)
    else:
        raise SystemExit("chaos-serve never wrote its nzb, see " + clog)
    time.sleep(1.0)
    return p, nzb


def submit(nzb, name):
    boundary = "pdgateboundary%d" % int(time.time() * 1000)
    body = open(nzb, "rb").read()
    head = ("--%s\r\nContent-Disposition: form-data; name=\"name\"; filename=\"%s.nzb\"\r\n"
            "Content-Type: application/x-nzb\r\n\r\n") % (boundary, name)
    data = head.encode() + body + ("\r\n--%s--\r\n" % boundary).encode()
    url = ("http://127.0.0.1:%d/api?mode=addfile&apikey=%s&output=json&nzbname=%s"
           % (DPORT, APIKEY, name))
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def history_slot(name):
    h = api("history", "&limit=50")
    slots = h.get("history", {}).get("slots", [])
    for s in slots:
        if s.get("name") == name:
            return s
    final = [s for s in slots if s.get("status") in ("Completed", "Failed")]
    if len(final) == 1 and not api("queue").get("queue", {}).get("slots"):
        return final[0]
    return None


def resume_paused():
    n = 0
    for s in api("queue").get("queue", {}).get("slots", []):
        if s.get("status") == "Paused" and s.get("nzo_id"):
            api("queue", "&name=resume&value=%s" % s["nzo_id"])
            n += 1
    return n


def log_slice(path, off):
    # `log_off` comes from os.path.getsize, so it is a BYTE offset - but a
    # text-mode read() returns CHARACTERS, and the daemon log is full of
    # multi-byte ones (`·`, `✔`, `✘`, `µ`, `×`). Slicing the character
    # string by a byte offset starts the slice too far in, by one character
    # per extra byte seen so far, and the error GROWS with the log, so it is
    # invisible on a short round and disqualifying on a long one. Measured
    # in the sibling driver daemon512.py, which had the identical line: a
    # 42-job single-daemon round on 16 Sep 2026 drifted 5,335 characters
    # over a 527,213-byte log, and its late legs lost the "in N slab(s) of
    # ... output ..." line parse_repair reads, reporting NO slab spill at
    # rungs that had spilled all round. This driver's own rounds are short
    # enough that no published leg is known to be affected, and it is fixed
    # here because the defect is the line, not the round length. Only the
    # parsed dispatch fields pass through here. Slice the BYTES, then decode.
    try:
        with open(path, "rb") as f:
            f.seek(off)
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def parse_repair(text):
    """`label: +1.23s (total 4.56s)` - Rust's `{:.2?}` Duration, so the unit
    is one of ns / us / ms / s and can differ line to line."""
    unit = {"ns": 1e-9, "\u00b5s": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}
    marks, totals = {}, []
    for label, dv, du, tv, tu in re.findall(
            r"([a-z+\-]+): \+([0-9.]+)(ns|\u00b5s|us|ms|s) \(total ([0-9.]+)(ns|\u00b5s|us|ms|s)\)", text):
        marks.setdefault(label, []).append(float(dv) * unit[du])
        totals.append(float(tv) * unit[tu])
    out = {"repair_total_s": round(max(totals), 4) if totals else None,
           "mark_n": len(totals)}
    for label, vals in marks.items():
        out["mark_" + label.replace("+", "_").replace("-", "_") + "_s"] = round(sum(vals), 4)
        out["mark_" + label.replace("+", "_").replace("-", "_") + "_n"] = len(vals)
    slabs = re.findall(r"in (\d+) slab\(s\) of (\d+) B,\s*output (\w+)", text)
    budget = re.findall(r"budget ([0-9.]+) GB", text)
    ntt = re.findall(r"ntt syndromes \(m=\d+, needed=\d+, n=\d+, W=(\d+), threads=(\d+)\)", text)
    wins = re.findall(r"ntt window \((\d+) bytes", text)
    feed = re.findall(r"feed shape under ([^:]+): batch ([0-9.]+) MB, channel (\d+), merge cap ([0-9.]+) MB", text)
    out.update({
        "slab_lines": [list(x) for x in sorted(set(slabs))],
        "ntt_w": sorted({int(w) for w, _ in ntt}),
        "ntt_windows": len(wins),
        "ntt_window_bytes": sorted({int(w) for w in wins}),
        "budget_gb": sorted(set(budget)),
        "feed_shape": sorted({"batch %s MB / channel %s / cap %s MB" % (f[1], f[2], f[3]) for f in feed}),
    })
    return out


def run_job(d, fx, ctrl_bin, m, rep, picks):
    tag = "%s-m%d-r%d" % (d.arm, m, rep)
    name = "pdgate-" + tag
    apply_damage(fx.work, fx.members, SLICE, picks, 1)
    chaos, nzb = start_chaos(fx, ctrl_bin, m, 1000 * rep + m, d.S)
    la0 = wait_quiet(tag)
    log_off = os.path.getsize(d.logp)
    st0 = proc_stat(d.pid)
    j0 = cpu_jiffies()
    t0 = time.monotonic()
    slot, resumed = None, 0
    try:
        submit(nzb, name)
        while True:
            if time.monotonic() - t0 > JOB_TIMEOUT:
                break
            if d.p.poll() is not None:
                break
            try:
                slot = history_slot(name)
            except Exception:
                slot = None
            if slot:
                break
            try:
                resumed += resume_paused()
            except Exception:
                pass
            time.sleep(0.25)
    finally:
        wall = time.monotonic() - t0
        st1 = proc_stat(d.pid)
        j1 = cpu_jiffies()
        hwm = vmhwm_kib(d.pid)
        chaos.terminate()
        try:
            chaos.wait(timeout=30)
        except subprocess.TimeoutExpired:
            chaos.kill()
    la1 = os.getloadavg()[0]
    text = log_slice(d.logp, log_off)
    storage = slot.get("storage") if slot else None
    outdir = storage if storage and os.path.isdir(storage) else None
    if outdir is None and slot:
        for root, _, files in os.walk(os.path.join(d.S, "out")):
            if fx.members[0] in files:
                outdir = root
                break
    bad = fx.bad(outdir) if outdir else list(fx.members)
    own_cpu = ((st1["utime"] - st0["utime"]) + (st1["stime"] - st0["stime"])) / float(TICK) if st1 else None
    row = {
        "tag": tag, "arm": d.arm, "m": m, "rep": rep, "binary": os.path.basename(d.bin),
        "memlimit": MEMLIMIT,
        "daemon_seq": d.seq, "daemon_job_index": d.jobs, "daemon_fresh": d.jobs == 0,
        "mimalloc_env": {k: v for k, v in ARM_ENV[d.arm].items()},
        "wall_s": round(wall, 3),
        "utime_s": round((st1["utime"] - st0["utime"]) / float(TICK), 3) if st1 else None,
        "stime_s": round((st1["stime"] - st0["stime"]) / float(TICK), 3) if st1 else None,
        "cpu_s": round(own_cpu, 3) if own_cpu is not None else None,
        "minflt": (st1["minflt"] - st0["minflt"]) if st1 else None,
        "majflt": (st1["majflt"] - st0["majflt"]) if st1 else None,
        "vmhwm_mib": round(hwm / 1024.0, 1) if hwm else None,
        "foreign_cpu_s": round(max(0.0, (j1 - j0) / float(TICK) - (own_cpu or 0.0)), 2),
        "load_before": round(la0, 2), "load_after": round(la1, 2),
        "status": (slot or {}).get("status"), "fail_message": (slot or {}).get("fail_message"),
        "bad_members": bad, "outdir": outdir, "byte_exact": (not bad) and bool(slot),
        "resumed_paused": resumed, "daemon_alive": d.p.poll() is None,
        "repair": parse_repair(text),
    }
    with open(os.path.join(LOGDIR, tag + ".log"), "w") as f:
        f.write(text)
    with open(OUT, "a") as f:
        f.write(json.dumps(row) + "\n")
    log("%s %s wall=%.1fs cpu=%.1fs sys=%s minflt=%s exact=%s fgn=%.1f" %
        (tag, row["status"], row["wall_s"], row["cpu_s"] or -1, row["stime_s"],
         row["minflt"], row["byte_exact"], row["foreign_cpu_s"]))
    d.jobs += 1
    try:
        api("history", "&name=delete&value=all&del_files=1")
    except Exception as e:
        log("history delete failed: %s" % e)
    shutil.rmtree(os.path.join(d.S, "out"), ignore_errors=True)
    os.makedirs(os.path.join(d.S, "out"), exist_ok=True)
    fx.restore(picks)
    return row


ARM_ENV = {a: e for a, _b, e in ARMS}
CONFIG = None


def main():
    global CONFIG
    fx = Fixture()
    CONFIG = {"servers": [{"host": "127.0.0.1", "port": CPORT, "tls": False, "connections": 20}]}
    ctrl_bin = os.path.join(BINDIR, "nzbfast-ctrl")
    picks = {m: damage_picks(fx.work, fx.members, SLICE, m, 1000 + m) for m in RUNGS}
    if fx.bad(fx.work):
        raise SystemExit("work copy is not pristine at start")
    for a, b, e in ARMS:
        log("arm %-5s binary=%-13s sha256=%s env=%s" % (a, b, sha(os.path.join(BINDIR, b))[:16], e or "(defaults)"))
    log("round: reps=%d rungs=%s memlimit=%s order rotates one step a rep; quiet gate load<%.2f"
        % (REPS, RUNGS, MEMLIMIT or "(none: auto)", QUIET))
    for rep in range(1, REPS + 1):
        # rotate one step a rep, so no arm keeps a position in the order
        order = ARMS[(rep - 1) % len(ARMS):] + ARMS[:(rep - 1) % len(ARMS)]
        for arm, binary, extra in order:
            d = Daemon(arm, binary, extra)
            try:
                for m in RUNGS:
                    time.sleep(SETTLE)
                    run_job(d, fx, ctrl_bin, m, rep, picks[m])
            finally:
                d.stop()
    log("round complete, rows in " + OUT)


if __name__ == "__main__":
    main()
