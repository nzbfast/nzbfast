#!/usr/bin/env python3
"""daemon512.py - the nzbfast DAEMON repairing inside a real cgroup v2 memory
limit (claim parfast-daemon-512m-container-headroom-15sep, section 8 first
bullet of an internal note).

cg512.py measured `parfast r -m256`, the budget `MemBudget::auto` publishes
under a 512 MiB cgroup, but not the daemon: its own resident set (HTTP
server, queue, indexer) and its allocator (mimalloc as #[global_allocator])
share the scope, and it has no parfast backup copy. This driver runs the real
thing:

    systemd-run --scope --unit d512-<tag>-<n> -p MemoryMax=512M
        -p MemorySwapMax=0 -p OOMPolicy=continue
        nice -n 19 nzbfast --config S/config.json serve --bind 127.0.0.1 ...

with NO --mem-limit by default (so the budget is MemBudget::auto, as in a
container; MEMLIMIT=<bytes> adds `--mem-limit <bytes>` - parse_size reads
suffixes as DECIMAL, so pass a plain byte count, 134217728 for 128 MiB),
NZBFAST_NO_ENRICH=1, NZBFAST_REPAIR_TIMING=1, and a config naming one
127.0.0.1 server: `nzbfast chaos-serve --profile clean --files 0 --media ...`
OUTSIDE the scope, serving the 64 KiB set's members AFTER pdrv's
deterministic damage plus its par2 volumes. So the daemon downloads a job
whose members carry exactly the note's damage (yEnc CRCs match the damaged
bytes, the PAR2 block checksums do not), and repair runs in its own
post-download path. The daemon lives for the whole round (one per indexer
state) and takes the jobs one after another, so the idle resident set before
each job is its real accumulated state; if a job's leg is OOM-killed the
daemon is relaunched before the next one.

Per job: idle charge / anon / daemon VmRSS before submit; memory.current and
memory.stat (anon, file, file_dirty, file_writeback, kernel) every 25 ms
from submit to the history verdict, into legs/<tag>.samp, with the daemon
log's byte length at each sample so a log line can be placed on the trace
clock; memory.events oom_kill delta; SHA-256 of every output member against
gold; the REPAIR_TIMING dispatch (slabs, output Spill/..., W, windows, feed
shape) out of the daemon log slice for that job.

LAYOUT under $R (default /root/daemon512-15sep): nzbfast (the binary),
fix/{pristine,work,gold.sha} with the 64 KiB set (cg512.py's), pdrv.py
beside this file.

RUN, holding the rig lock (this script does not take it):
    INDEXER=0 REPS=3 RUNGS=1024,2048,4096 TAG=ix0 OUT=d512.jsonl python3 daemon512.py

KNOBS added 15 Sep 2026 (claim parfast-daemon-512m-trim-and-quarter-arms-15sep):
IDLE_SETTLE (seconds slept after the previous job before the idle sample and
submit; 90 clears spawn_memory_trim's 60 s idle wait plus its 15 s tick),
MEMLIMIT (a --mem-limit byte count, default none), NZBFAST_LOG passed through
to the daemon (info,mem=debug prints the "idle trim: footprint" line). Each
JSON row records memlimit, idle_settle_s and the idle-trim lines the daemon
logged since the previous job (idle_trim_lines).

KNOBS added 16 Sep 2026 (claim daemon-512m-purge-delay-arm-16sep): the
daemon's allocator is mimalloc as #[global_allocator], and mimalloc reads its
options from the ENVIRONMENT at process init, so an allocator arm needs no
build - but it does need RECORDING, or a row cannot say which arm it is.
MIMALLOC_PURGE_DELAY (and any other MIMALLOC_* variable) is passed to the
daemon and recorded per row as mimalloc_purge_delay / mimalloc_env; every
MIMALLOC_* variable is STRIPPED from chaos-serve, which runs outside the
scope and must be the same loopback server in every arm.

Also recorded per row, because the three daemon rounds all found it is the
term that decides a kill and all three had to reconstruct it by hand from the
job order afterwards: daemon_seq (which daemon of the round this job ran on),
daemon_job_index (0 for the first job that daemon took) and daemon_fresh
(that index being 0). A fresh daemon carries nothing; a carrying one holds
the previous repair's retained anon, and the two populations must be reported
separately or a round's kill rate is a blend of them.
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

R = os.environ.get("R", "/root/daemon512-15sep")
# BIN defaults to $R/nzbfast, and is overridable so one round can carry TWO
# binaries over ONE fixture and alternate them (the 15 Sep musl arm: the
# SHIPPED static musl artifact against a box-built dynamic glibc build of the
# same commit). TAG already separates each invocation's daemon scratch
# ($R/d-$TAG), its traces and its rows, so the only thing that was per-round
# rather than per-arm was the binary path.
BIN = os.environ.get("BIN") or os.path.join(R, "nzbfast")
OUT = os.path.join(R, os.environ.get("OUT", "d512.jsonl"))
LOGDIR = os.path.join(R, "legs")
os.makedirs(LOGDIR, exist_ok=True)
REPS = int(os.environ.get("REPS", "3"))
RUNGS = [int(x) for x in os.environ.get("RUNGS", "1024,2048,4096").split(",")]
INDEXER = os.environ.get("INDEXER", "0") == "1"
TAG = os.environ.get("TAG", "ix1" if INDEXER else "ix0")
LIMIT = os.environ.get("LIMIT", "512M")
LIMIT_B = int(LIMIT[:-1]) << 20 if LIMIT.endswith("M") else None
JOB_TIMEOUT = float(os.environ.get("JOB_TIMEOUT", "1200"))
IDLE_SETTLE = float(os.environ.get("IDLE_SETTLE", "20"))
MEMLIMIT = os.environ.get("MEMLIMIT") or None
# every MIMALLOC_* the round was invoked with: the daemon inherits them (that
# IS the no-code route to an allocator arm), chaos-serve is stripped of them
MIM_ENV = {k: v for k, v in os.environ.items() if k.startswith("MIMALLOC_")}
PURGE_DELAY = os.environ.get("MIMALLOC_PURGE_DELAY")
DPORT = int(os.environ.get("DPORT", "16512"))
CPORT = int(os.environ.get("CPORT", "16119"))
APIKEY = "d512" + "0" * 28
SLICE = 65536
S = os.path.join(R, "d-" + TAG)


def log(msg):
    print("%s %s" % (time.strftime("%H:%M:%SZ", time.gmtime()), msg), flush=True)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def read_int(p):
    try:
        with open(p) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def read_kv(p):
    out = {}
    try:
        with open(p) as f:
            for line in f:
                k, v = line.split()
                out[k] = int(v)
    except (OSError, ValueError):
        pass
    return out


def listen_pid(port):
    r = subprocess.run(["lsof", "-ti", ":%d" % port, "-sTCP:LISTEN"], capture_output=True, text=True)
    pids = [int(x) for x in r.stdout.split()]
    return pids[0] if pids else None


def kill_port(port):
    # CLAUDE.md invariant 2: by the LISTEN pid on a port this lane owns, never by pattern
    pid = listen_pid(port)
    if pid:
        subprocess.run(["kill", str(pid)])
        for _ in range(200):
            if listen_pid(port) is None:
                break
            time.sleep(0.1)
    return pid


def api(mode, extra=""):
    url = "http://127.0.0.1:%d/api?mode=%s&apikey=%s&output=json%s" % (DPORT, mode, APIKEY, extra)
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode())


def rss_kib(pid):
    try:
        for line in open("/proc/%d/status" % pid):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


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
        return [m for m in self.members if not os.path.exists(os.path.join(d, m)) or sha(os.path.join(d, m)) != self.gold[m]]

    def restore(self, picks):
        remove_strays(self.work, self.keep)
        restore_slices(self.work, self.pristine, self.members, SLICE, picks)
        for m in self.bad(self.work):
            shutil.copyfile(os.path.join(self.pristine, m), os.path.join(self.work, m))
        if self.bad(self.work):
            raise SystemExit("restore failed")


class Daemon:
    n = 0

    def __init__(self):
        Daemon.n += 1
        self.unit = "d512-%s-%d" % (TAG, Daemon.n)
        self.cg = "/sys/fs/cgroup/system.slice/%s.scope" % self.unit
        self.logp = os.path.join(S, "daemon-%d.log" % Daemon.n)
        argv = ["systemd-run", "--scope", "--quiet", "--unit", self.unit, "-p", "OOMPolicy=continue"]
        if LIMIT_B:
            argv += ["-p", "MemoryMax=" + LIMIT, "-p", "MemorySwapMax=0"]
        argv += ["nice", "-n", "19", BIN, "--config", os.path.join(S, "config.json"), "serve",
                 "--port", str(DPORT), "--bind", "127.0.0.1", "--out", os.path.join(S, "out"),
                 "--apikey", APIKEY, "--min-free", "0"]
        if MEMLIMIT:
            # a global flag: before the subcommand, beside --config
            argv[argv.index(BIN) + 1:argv.index(BIN) + 1] = ["--mem-limit", MEMLIMIT]
        if INDEXER:
            argv += ["--index-db", os.path.join(S, "index.db"), "--index-groups", "alt.binaries.bench",
                     "--index-interval", "60", "--index-backfill", "1000"]
        env = dict(os.environ, NZBFAST_NO_ENRICH="1", NZBFAST_REPAIR_TIMING="1", **MIM_ENV)
        for k in ("NZBFAST_NTT", "NZBFAST_REPAIR_OUTPUT", "NZBFAST_MEM_FLOOR_SERIES"):
            env.pop(k, None)
        self.fl = open(self.logp, "ab")
        self.p = subprocess.Popen(argv, cwd=S, stdout=self.fl, stderr=subprocess.STDOUT, env=env)
        t0 = time.monotonic()
        while time.monotonic() - t0 < 120:
            if self.p.poll() is not None:
                raise SystemExit("daemon exited at launch, see " + self.logp)
            try:
                api("version")
                break
            except Exception:
                time.sleep(0.25)
        else:
            raise SystemExit("daemon never answered, see " + self.logp)
        self.pid = listen_pid(DPORT)
        self.trim_mark = 0
        self.seq = Daemon.n
        self.jobs = 0
        log("daemon %s up pid=%s ready in %.1fs" % (self.unit, self.pid, time.monotonic() - t0))

    def alive(self):
        return self.p.poll() is None and listen_pid(DPORT) is not None

    def events(self):
        return read_kv(self.cg + "/memory.events")

    def stop(self):
        pid = kill_port(DPORT)
        try:
            self.p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            subprocess.run(["systemctl", "kill", "--signal=KILL", self.unit + ".scope"])
            self.p.wait(timeout=30)
        self.fl.close()
        log("daemon %s stopped (pid %s by port)" % (self.unit, pid))


def start_chaos(fx, m, seed):
    # --seed goes into every media article's message-id, so a distinct seed
    # per job keeps a resubmitted fixture from matching an earlier job by
    # message-id identity (the duplicate ladder) - the media bytes are the
    # files on disk and do not depend on it
    nzb = os.path.join(S, "job-m%d-s%d.nzb" % (m, seed))
    clog = os.path.join(S, "chaos-m%d-s%d.log" % (m, seed))
    argv = [BIN, "chaos-serve", "--profile", "clean", "--bind", "127.0.0.1", "--port", str(CPORT),
            "--port2", str(CPORT + 1), "--files", "0", "--per-conn", "100G", "--nzb", nzb, "--seed", str(seed)]
    for f in fx.members:
        argv += ["--media", os.path.join(fx.work, f)]
    for f in fx.par2:
        argv += ["--media", os.path.join(fx.pristine, f)]
    fl = open(clog, "wb")
    # the server is not the subject: strip every MIMALLOC_* so an allocator arm
    # changes the DAEMON inside the scope and nothing else
    cenv = {k: v for k, v in os.environ.items() if not k.startswith("MIMALLOC_")}
    p = subprocess.Popen(["nice", "-n", "10"] + argv, cwd=S, stdout=fl, stderr=subprocess.STDOUT, env=cenv)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 300:
        if p.poll() is not None:
            raise SystemExit("chaos-serve exited, see " + clog)
        if listen_pid(CPORT) and os.path.exists(nzb):
            break
        time.sleep(0.25)
    else:
        raise SystemExit("chaos-serve never listened, see " + clog)
    return p, nzb


def submit(nzb, name):
    boundary = "d512boundary%d" % int(time.time() * 1000)
    body = open(nzb, "rb").read()
    data = (("--%s\r\nContent-Disposition: form-data; name=\"name\"; filename=\"%s.nzb\"\r\n"
             "Content-Type: application/x-nzb\r\n\r\n") % (boundary, name)).encode() + body + ("\r\n--%s--\r\n" % boundary).encode()
    url = "http://127.0.0.1:%d/api?mode=addfile&apikey=%s&output=json&nzbname=%s" % (DPORT, APIKEY, name)
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def history_slot(name):
    h = api("history", "&limit=50")
    slots = h.get("history", {}).get("slots", [])
    for s in slots:
        if s.get("name") == name:
            return s
    # the daemon may tidy a job name; the round runs one job at a time and
    # clears history after each, so a lone final slot is this job's
    final = [s for s in slots if s.get("status") in ("Completed", "Failed")]
    if len(final) == 1 and not api("queue").get("queue", {}).get("slots"):
        return final[0]
    return None


def resume_paused():
    # a resubmitted identical NZB can be held as a duplicate (dup = PAUSE);
    # resume it and record that it happened
    n = 0
    for s in api("queue").get("queue", {}).get("slots", []):
        if s.get("status") == "Paused" and s.get("nzo_id"):
            api("queue", "&name=resume&value=%s" % s["nzo_id"])
            n += 1
    return n


def idle_sample(d):
    time.sleep(IDLE_SETTLE)
    cur, anon, rss = [], [], []
    for _ in range(40):
        c = read_int(d.cg + "/memory.current")
        st = read_kv(d.cg + "/memory.stat")
        if c is not None:
            cur.append(c)
            anon.append(st.get("anon", 0))
        r = rss_kib(d.pid) if d.pid else None
        if r:
            rss.append(r)
        time.sleep(0.05)
    st = read_kv(d.cg + "/memory.stat")
    mib = lambda b: round(b / 1048576.0, 1)
    return {"idle_current_mib": mib(max(cur)) if cur else None, "idle_anon_mib": mib(max(anon)) if anon else None,
            "idle_file_mib": mib(st.get("file", 0)), "idle_kernel_mib": mib(st.get("kernel", 0)),
            "idle_rss_mib": round(max(rss) / 1024.0, 1) if rss else None}


def log_slice(path, off):
    # The offsets this driver keeps (log_off, trim_mark) come from
    # os.path.getsize, so they are BYTE offsets - but a text-mode read()
    # returns CHARACTERS, and the daemon log is full of multi-byte ones
    # (`·`, `✔`, `✘`, `µ`, `×`). Slicing the character string by a byte
    # offset therefore starts the slice too far in, by one character per
    # extra byte seen so far, and the error GROWS with the log. It is
    # invisible on a short round and disqualifying on a long one: the
    # 42-job single-daemon round of 16 Sep 2026 accumulated 5,335
    # characters of drift over 527,213 bytes, so its late legs' slices
    # began mid-line and lost the "in N slab(s) of ... output ..." line
    # that parse_repair reads - reporting NO slab spill at rungs that
    # had spilled all round. Only the parsed dispatch fields were
    # affected; every memory number comes from the cgroup trace and none
    # of them passes through here. Slice the BYTES, then decode.
    try:
        with open(path, "rb") as f:
            f.seek(off)
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def parse_repair(text):
    slabs = re.findall(r"in (\d+) slab\(s\) of (\d+) B,\s*output (\w+)", text)
    ntt = re.findall(r"ntt syndromes \(m=\d+, needed=\d+, n=\d+, W=(\d+), threads=(\d+)\)", text)
    wins = re.findall(r"ntt window \((\d+) bytes", text)
    feed = re.findall(r"feed shape under ([^:]+): batch ([0-9.]+) MB, channel (\d+), merge cap ([0-9.]+) MB", text)
    budget = re.findall(r"(?i)[^\n]*mem(?:ory)? budget[^\n]*", text)
    return {"slab_lines": [list(x) for x in sorted(set(slabs))], "ntt_w": sorted({int(w) for w, _ in ntt}),
            "ntt_calls": len(ntt), "ntt_windows": len(wins), "feed_shape": sorted({"%s / batch %s MB / channel %s / cap %s MB" % f for f in feed}),
            "timing_lines": len(re.findall(r"feed\+fold\+solve|back-substitution", text)),
            "budget_lines": budget[:3]}


def run_job(d, fx, m, rep, picks):
    tag = "%s-m%d-r%d" % (TAG, m, rep)
    name = "d512-%s" % tag
    idle = idle_sample(d)
    # what the idle trim said while this job's settle ran (and since the last
    # job's end, which the settle follows): the evidence it fired or did not
    trim_text = log_slice(d.logp, d.trim_mark)
    idle["idle_trim_lines"] = [ln.strip()[-160:] for ln in trim_text.splitlines() if "idle trim" in ln or "retained buffers" in ln]
    ev0 = d.events()
    log_off = os.path.getsize(d.logp)
    apply_damage(fx.work, fx.members, SLICE, picks, 1)
    chaos, nzb = start_chaos(fx, m, 1000 * rep + m)
    l0 = os.getloadavg()[0]
    trace = []
    t0 = time.monotonic()
    sub = submit(nzb, name)
    slot, killed_daemon, i, resumed = None, False, 0, 0
    while True:
        c = read_int(d.cg + "/memory.current")
        if c is not None:
            st = read_kv(d.cg + "/memory.stat")
            trace.append((round(time.monotonic() - t0, 3), c, st.get("anon", 0), st.get("file", 0), st.get("file_dirty", 0),
                          st.get("file_writeback", 0), st.get("kernel", 0), os.path.getsize(d.logp) - log_off))
        i += 1
        if i % 20 == 0:
            if not d.alive():
                killed_daemon = True
                break
            try:
                resumed += resume_paused()
                slot = history_slot(name)
            except Exception:
                slot = None
            if slot and slot.get("status") in ("Completed", "Failed"):
                break
        if time.monotonic() - t0 > JOB_TIMEOUT:
            break
        time.sleep(0.025)
    wall = time.monotonic() - t0
    ev1 = d.events()
    oom_journal = None
    if killed_daemon:
        # the scope is gone once its last process dies, so memory.events can
        # no longer be read: take the verdict from the kernel log by pid
        time.sleep(2)
        jr = subprocess.run(["journalctl", "-k", "--since", "-5min", "--no-pager"], capture_output=True, text=True)
        hits = [ln for ln in jr.stdout.splitlines() if "Killed process %s " % d.pid in ln or "task_memcg=/system.slice/%s.scope" % d.unit in ln]
        oom_journal = hits[-2:] if hits else []
        if hits:
            ev1 = dict(ev0, oom_kill=ev0.get("oom_kill", 0) + 1)
    text = log_slice(d.logp, log_off) if os.path.exists(d.logp) else ""
    kill_port(CPORT)
    chaos.wait(timeout=60)
    d.trim_mark = os.path.getsize(d.logp) if os.path.exists(d.logp) else 0
    storage = slot.get("storage") if slot else None
    outdir = storage if storage and os.path.isdir(storage) else None
    if outdir is None and slot:
        for root, _, files in os.walk(os.path.join(S, "out")):
            if fx.members[0] in files:
                outdir = root
                break
    bad = fx.bad(outdir) if outdir else list(fx.members)
    mib = lambda b: round(b / 1048576.0, 1)
    with open(os.path.join(LOGDIR, tag + ".samp"), "w") as fs:
        fs.write("t_s current anon file file_dirty file_writeback kernel log_bytes\n")
        for row in trace:
            fs.write(" ".join(str(x) for x in row) + "\n")
    with open(os.path.join(LOGDIR, tag + ".log"), "w") as fl:
        fl.write(text)
    tight = max(trace, key=lambda r: r[2] + r[4] + r[5] + r[6]) if trace else None
    peak = max(trace, key=lambda r: r[1]) if trace else None
    anon_peak = max(trace, key=lambda r: r[2]) if trace else None
    dirty_peak = max(trace, key=lambda r: r[4]) if trace else None
    rep_d = parse_repair(text)
    rec = {
        "tag": tag, "indexer": INDEXER, "m": m, "rep": rep, "limit": LIMIT, "daemon_unit": d.unit,
        "memlimit": MEMLIMIT, "idle_settle_s": IDLE_SETTLE,
        "mimalloc_purge_delay": PURGE_DELAY, "mimalloc_env": MIM_ENV,
        "daemon_seq": d.seq, "daemon_job_index": d.jobs, "daemon_fresh": d.jobs == 0,
        "submit": sub, "status": slot.get("status") if slot else None, "fail_message": slot.get("fail_message") if slot else None,
        "storage": storage, "bad_members": len(bad), "ok": bool(slot and slot.get("status") == "Completed" and not bad),
        "daemon_died": killed_daemon, "timed_out": wall > JOB_TIMEOUT, "resumed_paused": resumed,
        "oom_kill": ev1.get("oom_kill", 0) - ev0.get("oom_kill", 0), "oom": ev1.get("oom", 0) - ev0.get("oom", 0),
        "ev_max": ev1.get("max", 0) - ev0.get("max", 0), "ev_high": ev1.get("high", 0) - ev0.get("high", 0),
        **idle,
        "samp_n": len(trace),
        "peak_current_mib": mib(peak[1]) if peak else None,
        "anon_peak_mib": mib(anon_peak[2]) if anon_peak else None,
        "dirty_max_mib": mib(dirty_peak[4]) if dirty_peak else None,
        "writeback_max_mib": mib(max(r[5] for r in trace)) if trace else None,
        "tightest_mib": mib(tight[2] + tight[4] + tight[5] + tight[6]) if tight else None,
        "tightest_split_anon_dirty_wb_kernel_mib": [mib(tight[2]), mib(tight[4]), mib(tight[5]), mib(tight[6])] if tight else None,
        "tightest_t_s": tight[0] if tight else None, "tightest_log_bytes": tight[7] if tight else None,
        "least_headroom_mib": round(LIMIT_B / 1048576.0 - mib(tight[2] + tight[4] + tight[5] + tight[6]), 1) if (tight and LIMIT_B) else None,
        "wall": round(wall, 1), "load_before": round(l0, 1), "load_after": round(os.getloadavg()[0], 1),
        **rep_d,
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")
    log("JOB %-16s %s status=%s ok=%s bad=%d oomk=%s died=%s idle(cur/anon/rss)=%s/%s/%s peak=%s anon=%s dirty=%s tight=%s head=%s slabs=%s W=%s win=%d feed=%s wall=%.0f load=%.0f"
        % (tag, "FRESH" if rec["daemon_fresh"] else "carry", rec["status"], rec["ok"], len(bad), rec["oom_kill"], killed_daemon, idle["idle_current_mib"], idle["idle_anon_mib"],
           idle["idle_rss_mib"], rec["peak_current_mib"], rec["anon_peak_mib"], rec["dirty_max_mib"], rec["tightest_mib"],
           rec["least_headroom_mib"], rep_d["slab_lines"], rep_d["ntt_w"], rep_d["ntt_windows"], rep_d["feed_shape"], wall, l0))
    # clean the job out of the daemon and the disk before the next one
    try:
        api("history", "&name=delete&value=all&del_files=1")
    except Exception as e:
        log("history delete failed: %s" % e)
    if outdir and os.path.isdir(outdir) and outdir.startswith(os.path.join(S, "out")):
        shutil.rmtree(outdir, ignore_errors=True)
    fx.restore(picks)
    d.jobs += 1
    return rec


def wipe_state():
    # a daemon killed mid-job left its queue in .spool and its partial output
    # in out/; a relaunch would restore and resume that job on top of the next
    # leg (seen 15 Sep: "restored 1 queued" beside a new job), so start clean
    for sub in (".spool", "out"):
        shutil.rmtree(os.path.join(S, sub), ignore_errors=True)
    os.makedirs(os.path.join(S, "out"), exist_ok=True)
    log("wiped .spool and out/ before relaunch")


def follow_on():
    # rounds queued AFTER this one started, run under the same rig lock the
    # wrapper holds: one env line per round in R/follow-<TAG>, taken once
    path = os.path.join(R, "follow-" + TAG)
    if not os.path.exists(path):
        return
    taken = path + ".taken"
    os.rename(path, taken)
    for line in open(taken):
        kv = dict(x.split("=", 1) for x in line.split() if "=" in x)
        if not kv:
            continue
        log("FOLLOW %s" % line.strip())
        rc = subprocess.run([sys.executable, os.path.abspath(__file__)], env=dict(os.environ, **kv)).returncode
        log("FOLLOW-DONE rc=%d %s" % (rc, line.strip()))


def main():
    os.makedirs(os.path.join(S, "out"), exist_ok=True)
    with open(os.path.join(S, "config.json"), "w") as f:
        json.dump({"servers": [{"host": "127.0.0.1", "port": CPORT, "tls": False, "connections": 20}]}, f)
    settings = os.path.join(S, "settings.json")
    if not os.path.exists(settings):
        with open(settings, "w") as f:
            json.dump({"index_enabled": INDEXER, "index_groups": ["alt.binaries.bench"] if INDEXER else []}, f)
    for port in (DPORT, CPORT):
        if listen_pid(port):
            raise SystemExit("port %d already has a listener" % port)
    fx = Fixture()
    if fx.bad(fx.work):
        raise SystemExit("work copy is not pristine at start")
    log("R=%s INDEXER=%s REPS=%d RUNGS=%s LIMIT=%s MEMLIMIT=%s IDLE_SETTLE=%s MIMALLOC=%s bin sha256=%s"
        % (R, INDEXER, REPS, RUNGS, LIMIT, MEMLIMIT, IDLE_SETTLE, MIM_ENV or "(defaults)", sha(BIN)[:16]))
    d = Daemon()
    try:
        for rep in range(1, REPS + 1):
            for m in RUNGS:
                if not d.alive():
                    d.stop()
                    wipe_state()
                    d = Daemon()
                picks = damage_picks(fx.work, fx.members, SLICE, m, 1000 + m)
                run_job(d, fx, m, rep, picks)
    finally:
        if d.alive():
            d.stop()
        if listen_pid(CPORT):
            kill_port(CPORT)
    log("ALL DONE")
    follow_on()


if __name__ == "__main__":
    main()
