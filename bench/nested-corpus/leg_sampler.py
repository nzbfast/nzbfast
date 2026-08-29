#!/usr/bin/env python3
"""leg_sampler.py - the nested rig's per-leg instrument: disk high-water,
process-tree peak RSS and CPU, and a client phase timeline.

    leg_sampler.py --out PREFIX --tree DIR [--match REGEX]...
                   [--disk-hz 10] [--ps-hz 0.5] [--phase-hz 2]
                   [--phase-kind nzbget|sab|rustnzb] [--phase-url URL]

Runs until SIGTERM/SIGINT, then writes PREFIX.json (the summary the LEG
line reads) and PREFIX.phases (one line per phase TRANSITION).

RESOLUTION IS THE POINT, AND IT IS NO LONGER TRADED AGAINST
PERTURBATION.  An earlier version of this file sampled CPU and RSS at
0.5 Hz, on the reasoning that a faster `ps` poll moves the very cpu_s it
reports - which is true of `ps` and was measured: the SAME leg cost
41.3-41.7 cpu_s while a sampler polled at 2 Hz and 94.1-98.6 when
nothing polled.  But polling slower fixes the perturbation by giving up
the resolution, and the resolution is what a round needs - a fault
shorter than the sample interval is invisible whatever else is recorded.
Only 7 of that round's 70 cells got 5 or more samples, and against
nzbfast's own exact `[mem]` line a one-sample cell recovered as little
as 2.4% of the true peak.

The cost was never the RATE, it was `ps -axo` forking a process to walk
the whole process table - 47.5 ms per call on this box.  `procsample.py`
reads the same numbers from bounded syscalls at ~0.002 ms per pid and
separates DISCOVERY (which pids are mine) from SAMPLING (what are they
using now), so the expensive half runs rarely and the cheap half runs
fast.  MEASURED, with a positive control, rather than assumed:

    workload                        old ps @2 Hz     this @100 Hz
    bursty/idle - the shape the       +55.8% cpu        -0.1% cpu
      original effect was found on
    CPU-saturated real leg             +0.8% cpu        +0.0% cpu
    full instrument together                            +0.1% cpu
      (proc 100 Hz + disk 50 Hz)

Five interleaved reps per arm against an unsampled reference, with CPU
read from getrusage(RUSAGE_CHILDREN) after the child is reaped, so
nothing trusts the sampler to measure itself.  The `ps` arm is the
POSITIVE CONTROL and is the reason the null result can be believed: it
separates cleanly, so the experiment has the power to detect an effect
and does not find one for the new engine.

  * CPU and RSS: 100 Hz, discovery at 5 Hz.
  * disk high-water: 50 Hz.  It must outrun the LEG, not the byte rate.
    The 27 Aug round polled at 2 Hz and published `hiwater_mb=0` on
    three cells because the leg finished INSIDE one poll; six of its ten
    nzbfast legs ran 0-3 s.
  * phase: 5 Hz, and this one is bounded by FAIRNESS rather than by
    cost - it is an HTTP request to the client under test, so raising it
    loads the thing being measured.  Raise it only with a measurement.
THE DISK WALK DOES NOT FORK `du`.  Sampling at 10 Hz through subprocess
would fork ten processes a second for the length of every leg, which is
the same process-churn class as the `ps` effect above - the instrument
would be perturbing the measurement it exists to protect.  `tree_kb`
reproduces `du -sk` semantics in-process: st_blocks*512/1024 (so sparse
files and preallocation are counted the way du counts them, NOT
apparent size), hardlinks deduped by (st_dev, st_ino), symlinks never
followed.  Verified against `du -sk` on the real corpus trees.

THE ACHIEVED RATE IS RECORDED, NEVER THE REQUESTED ONE.  A poller that
wanted 10 Hz and got 0.4 Hz because the walk was slow is the same class
of silent wrongness this repo keeps writing gates for, and it cannot be
recovered afterwards.  Every loop reports samples, achieved Hz, and its
own worst-case cost, and the disk figure additionally carries
`disk_undersampled` when it took too few samples to trust.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request

import procsample

RUN = True


def stop(*_):
    global RUN
    RUN = False


def tree_kb(root):
    """du -sk semantics, in-process. Returns KB, or None if root is gone."""
    total_blocks = 0
    seen = set()
    stack = [root]
    if not os.path.exists(root):
        return None
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    key = (st.st_dev, st.st_ino)
                    if st.st_nlink > 1:
                        if key in seen:
                            continue
                        seen.add(key)
                    total_blocks += st.st_blocks
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
        except OSError:
            continue
    try:
        st = os.stat(root, follow_symlinks=False)
        total_blocks += st.st_blocks
    except OSError:
        pass
    return total_blocks * 512 // 1024


def cpu_secs(t):
    """ps TIME column: [DD-]HH:MM:SS(.ss) or MM:SS(.ss)."""
    days = 0
    if "-" in t:
        d, t = t.split("-", 1)
        days = int(d)
    parts = [float(p) for p in t.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0.0)
    h, m, s = parts
    return days * 86400 + h * 3600 + m * 60 + s


class Loop:
    """A fixed-cadence sampling loop that records what it ACHIEVED."""

    def __init__(self, hz):
        self.period = 1.0 / hz if hz > 0 else 0.0
        self.requested_hz = hz
        self.samples = 0
        self.cost_sum = 0.0
        self.cost_max = 0.0
        self.t0 = None
        self.t1 = None

    def run(self, body):
        if self.period <= 0:
            return
        self.t0 = time.time()
        while RUN:
            a = time.time()
            try:
                body()
            except Exception:
                pass
            b = time.time()
            self.samples += 1
            self.cost_sum += b - a
            self.cost_max = max(self.cost_max, b - a)
            self.t1 = b
            slack = self.period - (b - a)
            # Sleep in slices so SIGTERM is honoured promptly even at 0.5 Hz.
            end = time.time() + max(0.0, slack)
            while RUN and time.time() < end:
                time.sleep(min(0.05, end - time.time()))

    def stats(self, prefix, window=None):
        # The denominator is the WINDOW THE RESULT IS CLAIMED OVER - the
        # sampler's whole lifetime - and not first-sample-start to
        # last-sample-end. Those differ by N/(N-1), which is nothing at 77
        # samples and 33% at four: the first cut reported a 0.5 Hz ps loop
        # as 0.657 Hz, i.e. the instrument overstating its own coverage on
        # exactly the short legs where coverage is the thing in doubt.
        span = window if window else ((self.t1 - self.t0) if (self.t0 and self.t1) else 0.0)
        return {
            prefix + "_samples": self.samples,
            prefix + "_hz_requested": self.requested_hz,
            prefix + "_hz_achieved": round(self.samples / span, 3) if span > 0.05 else None,
            prefix + "_span_s": round(span, 3),
            prefix + "_cost_ms_mean": round(1000 * self.cost_sum / self.samples, 2) if self.samples else None,
            prefix + "_cost_ms_max": round(1000 * self.cost_max, 2) if self.samples else None,
        }


# ---- phase probes ------------------------------------------------------
# Each returns a short, stable phase string for the client, or None. The
# string is what gets diffed - a transition is written only when it CHANGES,
# so a timeline is a handful of lines rather than a poll log.

def _get(url, timeout=4):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def phase_nzbget(url):
    st = _get(url + "/jsonrpc/status")["result"]
    bits = []
    if st.get("DownloadPaused"):
        bits.append("paused")
    bits.append("dl=%d%%" % _pct(st.get("DownloadedSizeMB"), st.get("RemainingSizeMB")))
    if st.get("PostJobCount"):
        bits.append("post=%d" % st["PostJobCount"])
    try:
        grp = _get(url + "/jsonrpc/listgroups")["result"]
        for g in grp:
            s = g.get("PostInfoStage") or g.get("Status")
            if s:
                bits.append("stage=" + str(s))
                break
    except Exception:
        pass
    return " ".join(bits)


def _pct(done, remain):
    try:
        done = float(done or 0)
        remain = float(remain or 0)
        return int(100 * done / (done + remain)) if (done + remain) > 0 else 0
    except Exception:
        return 0


def phase_sab(url):
    q = _get(url + "&mode=queue")["queue"]
    slots = q.get("slots") or []
    if not slots:
        h = _get(url + "&mode=history")["history"]
        hs = h.get("slots") or []
        if hs:
            return "history:" + str(hs[0].get("status")) + ":" + str(hs[0].get("action_line") or "")[:40]
        return "idle"
    s = slots[0]
    # `labels` is how the a3 ENCRYPTED pause announces itself, and status
    # alone does not carry it - poll for what it is DOING, not for done.
    lab = ",".join(s.get("labels") or [])
    return "q:%s %s%%%s" % (s.get("status"), s.get("percentage"), (" labels=" + lab) if lab else "")


def phase_rustnzb(url):
    try:
        q = _get(url + "?mode=queue&output=json")
        slots = (q.get("queue") or {}).get("slots") or q.get("slots") or []
        if slots:
            s = slots[0]
            return "q:%s %s%%" % (s.get("status"), s.get("percentage"))
    except Exception:
        pass
    try:
        h = _get(url + "?mode=history&output=json")
        slots = (h.get("history") or {}).get("slots") or h.get("slots") or []
        if slots:
            return "history:" + str(slots[0].get("status"))
    except Exception:
        pass
    return "idle"


PROBES = {"nzbget": phase_nzbget, "sab": phase_sab, "rustnzb": phase_rustnzb}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tree", required=True)
    ap.add_argument("--match", action="append", default=[])
    ap.add_argument("--disk-hz", type=float, default=50.0)
    ap.add_argument("--proc-hz", type=float, default=100.0)
    ap.add_argument("--discover-hz", type=float, default=5.0)
    # Still accepted so an older driver keeps running, but it now names the
    # PROCESS sampler's rate: a rig that passes the old 0.5 gets 0.5 and its
    # cells will say so in ps_hz_requested rather than silently getting 100.
    ap.add_argument("--ps-hz", type=float, default=None)
    ap.add_argument("--phase-hz", type=float, default=5.0)
    ap.add_argument("--phase-kind", default="none")
    ap.add_argument("--phase-url", default="")
    a = ap.parse_args()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    t_start = time.time()
    state = {"hiwater_kb": 0, "peak_rss_kb": 0, "cpu_peak": {}, "anomaly": [],
             "load": []}
    pats = [re.compile(p) for p in a.match]

    # Physical RAM: no tree can exceed it. An earlier rig-fault round
    # recorded single ps samples of exactly 2^31 KB and of 990 GB - ps
    # artifacts, not measurements. They are logged and not recorded.
    try:
        ram_kb = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True,
                                    text=True, timeout=5).stdout.strip()) // 1024
    except Exception:
        ram_kb = 1 << 40

    proc_hz = a.ps_hz if a.ps_hz is not None else a.proc_hz
    disk = Loop(a.disk_hz)
    ps_l = Loop(proc_hz)
    disc = Loop(a.discover_hz)
    ph_l = Loop(a.phase_hz if a.phase_kind in PROBES else 0)

    native = procsample.make_native()
    sampler = procsample.ProcSampler(a.match, native)

    def disk_body():
        k = tree_kb(a.tree)
        if k is not None and k > state["hiwater_kb"]:
            state["hiwater_kb"] = k
        # WAS THE BOX BUSY WHILE THIS LEG RAN. Elapsed time is the one
        # measure here that a neighbouring workload moves, and this rig
        # runs on a shared machine, so a wall figure with no idea what
        # else was running is not a measurement a reader can use. Cheap
        # enough to ride along with the disk walk (one sysctl), and it
        # turns "the box was busy" from an apology into a number that can
        # be published beside the timing or used to reject a leg.
        try:
            state["load"].append(os.getloadavg()[0])
        except OSError:
            pass

    def discover_body():
        sampler.discover()

    def ps_body():
        tot = sampler.sample()
        if tot > ram_kb * 1024:
            # No tree can exceed physical RAM. An earlier rig-fault round
            # recorded single samples of exactly 2^31 KB and of 990 GB.
            state["anomaly"].append("tree total %d bytes > RAM" % tot)

    phases = []

    def phase_body():
        probe = PROBES[a.phase_kind]
        try:
            s = probe(a.phase_url)
        except Exception:
            s = None
        if s and (not phases or phases[-1][1] != s):
            phases.append((round(time.time() - t_start, 2), s))

    # Discovery is its own loop and its own cadence: that separation is the
    # whole reason the sampling loop can run at 100 Hz at all.
    threads = [threading.Thread(target=disk.run, args=(disk_body,), daemon=True),
               threading.Thread(target=disc.run, args=(discover_body,), daemon=True),
               threading.Thread(target=ps_l.run, args=(ps_body,), daemon=True)]
    if a.phase_kind in PROBES:
        threads.append(threading.Thread(target=ph_l.run, args=(phase_body,), daemon=True))
    for t in threads:
        t.start()
    while RUN:
        time.sleep(0.05)
    for t in threads:
        t.join(timeout=5)

    res = {
        "hiwater_kb": state["hiwater_kb"],
        "hiwater_mb": state["hiwater_kb"] // 1024,
        "peak_rss_kb": sampler.peak_rss // 1024,
        "peak_rss_mb": sampler.peak_rss // 1048576,
        "cpu_s": round(sampler.cpu_s, 1),
        "cpu_pids": len(sampler.cpu_peak),
        # Which engine produced the two columns above. A caller must be able
        # to tell a high-resolution number from a fallback one rather than
        # quietly being handed the coarse version.
        "proc_engine": "native" if native else "ps",
        # PHYSICAL disk bytes, which answers a different question from the
        # high-water mark above: high-water is how much space the job needed
        # at once, these are how much the disk actually had to move. A client
        # that writes an intermediate and deletes it scores nothing in the
        # first and every byte in the second. Zero on the ps fallback engine,
        # which cannot report them.
        "disk_read_mb": sampler.disk_read // 1048576,
        "disk_write_mb": sampler.disk_write // 1048576,
        "proc_sample_ms_mean": round(1000 * sampler.sample_cost / max(1, sampler.samples), 4),
        "discover_ms_mean": round(1000 * sampler.discover_cost / max(1, sampler.discoveries), 3),
        "wall_s": round(time.time() - t_start, 2),
    }
    if state["load"]:
        ld = state["load"]
        res["load_mean"] = round(sum(ld) / len(ld), 2)
        res["load_min"] = round(min(ld), 2)
        res["load_max"] = round(max(ld), 2)
    window = res["wall_s"]
    res.update(disk.stats("disk", window))
    res.update(ps_l.stats("ps", window))
    res.update(disc.stats("discover", window))
    if a.phase_kind in PROBES:
        res.update(ph_l.stats("phase", window))
    # A disk high-water taken from too few samples is not a measurement.
    # The 27 Aug round's three `hiwater_mb=0` cells are exactly this and
    # nothing in that rig could say so.
    # BOTH loops report whether they had the coverage to mean anything,
    # and the ps one is the subtler of the two. Holding ps at 0.5 Hz is
    # required - a faster poll moves the very cpu_s it reports, by 2.3x -
    # but the cost of that fix is resolution on SHORT legs: six of the ten
    # nzbfast legs in the 27 Aug round ran 0-3 s, which at 0.5 Hz is one or
    # two samples, and a per-pid CPU snapshot that sparse misses a helper
    # (unrar, 7za) that spawned and exited between two of them. The two
    # properties cannot both be had from a `ps` poller, so the answer is to
    # SAY which cells are thin rather than to speed the loop back up and
    # quietly re-perturb every cell. nzbfast's own `[mem]` line is exact
    # and unsampled, so on a short leg our RSS is a measurement and a
    # rival's is an estimate - never set the two against each other
    # without saying so.
    res["disk_undersampled"] = disk.samples < 5
    res["ps_undersampled"] = ps_l.samples < 5
    if state["anomaly"]:
        res["ps_anomalies"] = state["anomaly"][:10]
    with open(a.out + ".json", "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    with open(a.out + ".phases", "w") as f:
        for t, s in phases:
            f.write("%8.2f  %s\n" % (t, s))
    print(json.dumps(res, sort_keys=True))


if __name__ == "__main__":
    main()
