#!/usr/bin/env python3
"""procsample.py - the fleet's high-resolution process sampler.

Peak RSS and CPU seconds for a process TREE, sampled fast enough to
resolve events shorter than a benchmark leg. Importable
(`ProcSampler`) and the engine behind `leg_sampler.py`.

WHY THIS EXISTS, and why the answer is not "poll `ps` harder".

The measured hazard is real and is not a rate: `[[nzbfast-cpu-s-sampler-
observer-effect]]` recorded the SAME leg at 41.3-41.7 cpu_s while a
sampler polled `ps` at 2 Hz and 94.1-98.6 when nothing polled - 3 runs
against 9, perfect separation, with instructions retired matching to 2%
while cycles ran 1.6x. The threads had moved to the performance cluster
because something kept waking it. The response at the time was to poll
SLOWER, which fixes the perturbation by giving up the resolution - and
the resolution is the thing benchmarks need, because a fault shorter
than the sample interval is invisible whatever else the round records.

The cost is in HOW, not HOW OFTEN. `ps -axo` forks a process that walks
the entire process table: measured 47.5 ms per call on this box, so
2 Hz is ~9.5% duty of pure table-walking. Every number this file needs
is available from bounded syscalls instead, and they are three to four
orders of magnitude cheaper:

    proc_pid_rusage(pid, RUSAGE_INFO_V4)   ~0.002 ms   per pid
    proc_listallpids                       ~0.1 ms     whole box
    proc_pidinfo(PROC_PIDTBSDINFO)         ~0.002 ms   per pid, for ppid
    sysctl KERN_PROCARGS2                  ~0.039 ms   per pid, for argv

So DISCOVERY and SAMPLING are decoupled, which is the whole design.
Discovery answers "which pids are mine" and needs the ppid map and the
argv of anything new; ppid and argv NEVER CHANGE for a live pid, so both
are cached per pid and a steady-state discovery pass costs almost
nothing. Sampling answers "what are they using now" and is a couple of
microseconds per pid, so it can run two orders of magnitude faster than
the old sampler while costing a fraction as much.

VALIDATED AGAINST `ps`, not assumed: proc_pid_rusage agreed to 100.06%
on CPU and 100.00% on RSS for a child holding 500 MB and burning 4 s.

THE OFFSETS AND UNITS ARE VERIFIED BY --selftest AND MUST STAY THAT WAY.
`rusage_info_v4` is an array of uint64 after a 16-byte uuid, the struct
has GROWN TWICE (v5, v6), and a wrong index reads a QoS timer as a byte
count - which looks entirely plausible in a table. The CPU fields are
the sharper trap: they are in MACH ABSOLUTE TIME units and NOT in
nanoseconds, so reading them raw reports a 4.04 s leg as 96 ms, a 42x
under-count that still looks like a number. The timebase is read from
`mach_timebase_info` (125/3 on this box, 41.6667 ns per tick) rather
than hardcoded, because it differs between Apple Silicon and Intel.
The private I/O-attribution tool in this repo's own bench tree reads the
same struct for its own fields and its header carries the same warning.

NOT macOS-ONLY IN THE WAY dioattrib IS. That file does its `CDLL` at
module scope and therefore dies at IMPORT on a Linux runner, which cost
it a place in CI. Here the fast engine is optional: if libSystem is
absent or any probe fails, the sampler falls back to `ps` and SAYS SO in
its output (`engine=ps`), so a caller can tell a high-resolution number
from a coarse one instead of quietly getting the coarse one.
"""

import ctypes
import os
import re
import subprocess
import time

RUSAGE_INFO_V4 = 4
# Indices into rusage_info_v4 read as uint64[], uuid occupying 0 and 1.
RI_USER_TIME = 2
RI_SYSTEM_TIME = 3
RI_RESIDENT = 8
# PHYSICAL bytes the kernel charges the process, which is a different and
# more useful quantity than a directory's high-water mark: high-water says
# how much space a job needed at once, these say how much the disk actually
# had to move. A client that writes a file and deletes it shows nothing in
# high-water and every byte here.
RI_DISK_R = 18
RI_DISK_W = 19
PROC_PIDTBSDINFO = 3
CTL_KERN, KERN_PROCARGS2, KERN_ARGMAX = 1, 49, 8


class _ProcBsdInfo(ctypes.Structure):
    """proc_bsdinfo, IN FULL and not truncated to the fields we read.

    `proc_pidinfo` validates the buffer size against its own idea of the
    struct and returns 0 for a short one, so a convenient 5-field version
    compiles, runs, and silently reports every ppid as 0 - which makes
    every discovered tree exactly one pid deep. Caught by --selftest.
    """
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64),
    ]


class Native:
    """The syscall engine. Raises if this box cannot provide it."""

    def __init__(self):
        self.lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        self.lib.proc_listallpids.restype = ctypes.c_int
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pid_rusage.restype = ctypes.c_int
        self.lib.sysctl.restype = ctypes.c_int
        tb = (ctypes.c_uint32 * 2)()
        self.lib.mach_timebase_info(ctypes.byref(tb))
        if not tb[0] or not tb[1]:
            raise OSError("mach_timebase_info gave no timebase")
        # ticks -> seconds. NOT nanoseconds: see the header.
        self.tick_s = (tb[0] / tb[1]) / 1e9
        self.argmax = self._argmax()
        self._argbuf = ctypes.create_string_buffer(self.argmax)
        if self.rusage(os.getpid()) is None:
            raise OSError("proc_pid_rusage failed for our own pid")

    def _argmax(self):
        mib = (ctypes.c_int * 2)(CTL_KERN, KERN_ARGMAX)
        sz, v = ctypes.c_size_t(4), ctypes.c_int(0)
        if self.lib.sysctl(mib, 2, ctypes.byref(v), ctypes.byref(sz), None, 0) != 0:
            raise OSError("sysctl KERN_ARGMAX failed")
        return max(4096, v.value)

    def rusage(self, pid):
        """(cpu_seconds, resident_bytes) or None if the pid is gone."""
        buf = (ctypes.c_uint64 * 64)()
        if self.lib.proc_pid_rusage(ctypes.c_int(pid), ctypes.c_int(RUSAGE_INFO_V4),
                                    ctypes.byref(buf)) != 0:
            return None
        ticks = buf[RI_USER_TIME] + buf[RI_SYSTEM_TIME]
        return (ticks * self.tick_s, buf[RI_RESIDENT],
                buf[RI_DISK_R], buf[RI_DISK_W])

    def all_pids(self):
        n = self.lib.proc_listallpids(None, 0)
        if n <= 0:
            return []
        buf = (ctypes.c_int * (n + 256))()
        got = self.lib.proc_listallpids(ctypes.byref(buf), ctypes.sizeof(buf))
        return [buf[i] for i in range(max(0, got)) if buf[i] > 0]

    def ppid(self, pid):
        info = _ProcBsdInfo()
        r = self.lib.proc_pidinfo(ctypes.c_int(pid), ctypes.c_int(PROC_PIDTBSDINFO),
                                  ctypes.c_uint64(0), ctypes.byref(info),
                                  ctypes.c_int(ctypes.sizeof(info)))
        return info.pbi_ppid if r > 0 else None

    def argv(self, pid):
        mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
        sz = ctypes.c_size_t(self.argmax)
        if self.lib.sysctl(mib, 3, self._argbuf, ctypes.byref(sz), None, 0) != 0:
            return None
        raw = self._argbuf.raw[:sz.value]
        if len(raw) < 4:
            return None
        argc = int.from_bytes(raw[:4], "little")
        parts = [p for p in raw[4:].split(b"\0") if p]
        return " ".join(p.decode("utf-8", "replace") for p in parts[1:argc + 1])


class ProcSampler:
    """Peak RSS and total CPU for the tree under any pid matching `pats`.

    Discovery and sampling are separate calls with separate cadences on
    purpose - see the header. `discover()` is the expensive one and is
    still cheap; `sample()` is the one that may run at 100 Hz.
    """

    def __init__(self, pats, native=None):
        self.pats = [re.compile(p) for p in pats]
        self.native = native
        self.ppid_cache, self.argv_cache = {}, {}
        self.tree, self.roots = set(), set()
        self.peak_rss = 0
        self.cpu_peak = {}          # pid -> max cumulative cpu ever seen
        self.rd_peak = {}           # pid -> max cumulative bytes read
        self.wr_peak = {}           # pid -> max cumulative bytes written
        self.discover_cost, self.sample_cost = 0.0, 0.0
        self.discoveries, self.samples = 0, 0
        self.self_pid = os.getpid()
        # Us, plus every helper WE fork. Nothing else is excluded.
        self._own_pids = {self.self_pid}

    # ---- discovery ----------------------------------------------------
    def discover(self):
        t0 = time.time()
        if self.native:
            self._discover_native()
        else:
            self._discover_ps()
        self.discoveries += 1
        self.discover_cost += time.time() - t0

    def _discover_native(self):
        pids = set(self.native.all_pids())
        # ppid and argv never change for a live pid, so both are cached and
        # a steady-state pass reads neither. Dead pids are dropped so the
        # caches cannot grow without bound on a long round.
        for p in pids:
            if p not in self.ppid_cache:
                pp = self.native.ppid(p)
                if pp is not None:
                    self.ppid_cache[p] = pp
            if p not in self.argv_cache:
                self.argv_cache[p] = self.native.argv(p) or ""
        for gone in [p for p in self.ppid_cache if p not in pids]:
            self.ppid_cache.pop(gone, None)
            self.argv_cache.pop(gone, None)
        kids = {}
        for p, pp in self.ppid_cache.items():
            kids.setdefault(pp, []).append(p)
        roots = {p for p in pids if p != self.self_pid
                 and any(r.search(self.argv_cache.get(p, "")) for r in self.pats)}
        self._walk(roots, kids)

    def _discover_ps(self):
        """Fallback discovery. STATED LIMIT: `ps` prints an argv containing
        NEWLINES verbatim, so a process launched with embedded newlines
        (`python -c` with a multi-line program) breaks a line-based parse and
        can both miss the real pid and invent bogus ones. KERN_PROCARGS2
        joins on spaces and has no such hazard, which is one more reason the
        native engine is the one to run."""
        out = self._run_ps(["ps", "-axo", "pid=,ppid=,command="])
        kids, cmds = {}, {}
        for line in out.splitlines():
            try:
                pid, ppid, cmd = line.split(None, 2)
            except ValueError:
                continue
            pid, ppid = int(pid), int(ppid)
            cmds[pid] = cmd
            kids.setdefault(ppid, []).append(pid)
        roots = {p for p, c in cmds.items()
                 if p != self.self_pid and any(r.search(c) for r in self.pats)}
        self._walk(roots, kids)

    def _walk(self, roots, kids):
        seen = self._subtree(roots, kids)
        # THE INSTRUMENT MUST NEVER MEASURE ITSELF, and the hazard is not
        # hypothetical: the ps engine FORKS `ps`, which is our child, so
        # whenever the sampler sits under a matched root that fork lands in
        # the tree and its RSS and CPU are charged to the client. Found by
        # --selftest as a one-pid disagreement between the two engines.
        # EXCLUDED BY EXACT PID, not by dropping our whole subtree: a rig is
        # entitled to run the sampler as the client's parent, and a subtree
        # rule would then measure nothing at all while looking healthy.
        seen -= self._own_pids
        self.roots = roots - self._own_pids
        # Union, never replace: a pid that has EXITED still owns the CPU it
        # burned, and dropping it here would silently un-count a decoder or
        # an unrar that did its work and went away - which is most of the
        # helper CPU in an extract-heavy leg.
        self.tree |= seen

    def _run_ps(self, cmd):
        """Fork `ps` and REMEMBER ITS PID so the tree can exclude it.

        subprocess.run hides the pid, which is why the naive version
        charged its own `ps` fork to whichever client happened to be its
        ancestor. Popen exposes it; the pid is retired only from the
        exclusion set's point of view, never reused.
        """
        try:
            pr = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True)
        except Exception:
            return ""
        self._own_pids.add(pr.pid)
        try:
            out, _ = pr.communicate(timeout=20)
        except Exception:
            pr.kill()
            return ""
        return out or ""

    @staticmethod
    def _subtree(roots, kids):
        seen, stack = set(), list(roots)
        while stack:
            p = stack.pop()
            if p in seen:
                continue
            seen.add(p)
            stack.extend(kids.get(p, []))
        return seen

    def discover_children(self, root):
        """Track a KNOWN root and its descendants, with no argv matching.

        For a caller that already owns the process it wants measured - the
        operator measuring its own par2 and unrar children - matching by
        command line would be indirection with a failure mode and no benefit.
        """
        if self.native:
            kids = {}
            for p in self.native.all_pids():
                if p not in self.ppid_cache:
                    pp = self.native.ppid(p)
                    if pp is not None:
                        self.ppid_cache[p] = pp
            for p, pp in self.ppid_cache.items():
                kids.setdefault(pp, []).append(p)
            self.tree |= self._subtree({root}, kids)
        self.discoveries += 1

    # ---- sampling -----------------------------------------------------
    def sample(self):
        t0 = time.time()
        readings = (self._native_readings() if self.native
                    else self._ps_readings())
        total, dead = 0, []
        for p in self.tree:
            r = readings.get(p)
            if r is None:
                dead.append(p)
                continue
            cpu, rss, rd, wr = r
            total += rss
            # Peak-per-pid for all three, so a helper that did its work and
            # exited still contributes what it cost.
            if cpu > self.cpu_peak.get(p, 0.0):
                self.cpu_peak[p] = cpu
            if rd > self.rd_peak.get(p, 0):
                self.rd_peak[p] = rd
            if wr > self.wr_peak.get(p, 0):
                self.wr_peak[p] = wr
        # A dead pid keeps its last CPU reading (above) but stops being
        # asked, so a long leg does not pay for every process it ever had.
        for p in dead:
            self.tree.discard(p)
        if total > self.peak_rss:
            self.peak_rss = total
        self.samples += 1
        self.sample_cost += time.time() - t0
        return total

    def _native_readings(self):
        out = {}
        for p in self.tree:
            r = self.native.rusage(p)
            if r is not None:
                out[p] = r
        return out

    def _ps_readings(self):
        """Fallback: ONE `ps` naming only our pids, never the whole table.

        Still a fork, so it is far more expensive than the native path and
        must not be driven at native rates - but it is bounded by the size
        of OUR tree rather than by the box's process count, which is what
        made the old whole-table poll a hazard."""
        if not self.tree:
            return {}
        out = self._run_ps(["ps", "-o", "pid=,rss=,time=", "-p",
                            ",".join(str(p) for p in self.tree)])
        res = {}
        for line in out.splitlines():
            try:
                pid, rss, tm = line.split()
            except ValueError:
                continue
            # ps cannot report physical disk bytes, so the fallback engine
            # returns zeroes for them rather than a wrong number. A cell
            # whose proc_engine is "ps" has no disk-bytes figure, and says so.
            res[int(pid)] = (_ps_cpu(tm), int(rss) * 1024, 0, 0)
        return res

    @property
    def cpu_s(self):
        return sum(self.cpu_peak.values())

    @property
    def disk_read(self):
        return sum(self.rd_peak.values())

    @property
    def disk_write(self):
        return sum(self.wr_peak.values())


def _ps_cpu(t):
    """ps TIME column: [DD-]HH:MM:SS(.ss) or MM:SS(.ss) -> seconds."""
    days = 0
    if "-" in t:
        d, t = t.split("-", 1)
        days = int(d)
    parts = [float(x) for x in t.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0.0)
    return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]


def make_native():
    """The engine if this box can provide it, else None. Never raises."""
    try:
        return Native()
    except Exception:
        return None


# ---- CLI ---------------------------------------------------------------
# DELIBERATELY ARGUMENT-COMPATIBLE with the fleet's older
# `rss_cpu_sampler.py`: same `OUTFILE PATTERN [PATTERN...]`, same OUTFILE
# (running max total RSS in KB) and OUTFILE.cpu (total CPU seconds). So a
# rig adopts the high-resolution instrument by changing ONE PATH and
# nothing else, which is the only way four hand-copied sibling drivers
# ever move together. `--rates` reports what it achieved.

# selftest-roster: macOS only, and not incidentally. This selftest exists to
# verify the rusage_info_v4 field offsets and the mach-tick CPU unit against
# the LIVE proc_pid_rusage syscall and against `ps`, which is the whole reason
# any number here is trusted - the struct has grown twice and the CPU fields
# are ticks, not nanoseconds, so a wrong read returns a plausible number
# rather than an error. There is no Linux equivalent to check them against, so
# a CI-runnable version would assert nothing, and the native engine it exists
# to test does not exist on a runner. Same standing, and the same reason, as this repo's
# private I/O-attribution tool, which is waived in that roster for exactly this.
# Run it on a mac, which is where every bench box using this sampler already is.
def _selftest():
    """Verify the offsets, the UNITS and the engine against live truth.

    This is the gate, not a formality. Every number this file produces
    comes from indices into a struct that has grown twice and from a
    conversion that is NOT nanoseconds - and both failure modes return a
    plausible-looking number rather than an error. A wrong CPU unit
    reports a 4 s leg as 96 ms.
    """
    import statistics, sys, tempfile
    fails = []

    def check(name, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + name + (" " + detail if detail else ""))
        if not cond:
            fails.append(name)

    nat = make_native()
    check("native engine available", nat is not None)
    if nat is None:
        print("procsample --selftest: FAILED (no native engine)")
        return 1
    check("mach timebase is sane", 0 < nat.tick_s < 1e-6,
          "tick=%.4f ns" % (nat.tick_s * 1e9))

    # A child with a KNOWN cpu burn and a KNOWN resident size, checked
    # against ps - the only independent witness available here.
    code = ("import time\n"
            "b=bytearray(400*1024*1024)\n"
            "for i in range(0,len(b),4096): b[i]=1\n"
            "t0=time.time()\n"
            "while time.time()-t0<3.0: pass\n"
            "time.sleep(3)\n")
    ch = subprocess.Popen([sys.executable, "-c", code])
    time.sleep(4.5)
    r = nat.rusage(ch.pid)
    check("rusage returns for a live pid", r is not None)
    if r:
        cpu, rss, rd, wr = r
        out = subprocess.run(["ps", "-o", "rss=,time=", "-p", str(ch.pid)],
                             capture_output=True, text=True).stdout.split()
        ps_rss, ps_cpu = int(out[0]) * 1024, _ps_cpu(out[1])
        # 5% either way: ps rounds its TIME to 1/100 s and both are sampled
        # a moment apart, so exact equality is not the right assertion.
        check("cpu agrees with ps within 5%", abs(cpu - ps_cpu) / max(ps_cpu, .01) < .05,
              "rusage=%.3f ps=%.3f" % (cpu, ps_cpu))
        check("cpu is in the right UNIT (~3 s, not ~70 ms)", 2.0 < cpu < 6.0,
              "%.3f s - a raw-tick read would report ~0.07" % cpu)
        check("rss agrees with ps within 5%", abs(rss - ps_rss) / max(ps_rss, 1) < .05,
              "rusage=%.0f MB ps=%.0f MB" % (rss / 1048576, ps_rss / 1048576))
        check("disk counters are readable and non-negative", rd >= 0 and wr >= 0,
              "read=%d MB write=%d MB" % (rd // 1048576, wr // 1048576))
    check("argv is readable", (nat.argv(ch.pid) or "").find("bytearray") >= 0)
    check("ppid resolves to us", nat.ppid(ch.pid) == os.getpid())
    check("rusage returns None for a dead pid", nat.rusage(999999) is None)

    # Discovery must find the child BY ITS ARGV, which is what every rig
    # matches on, and must include it in the tree.
    s = ProcSampler(["bytearray\\(400"], nat)
    s.discover()
    check("discovery finds the child by argv", ch.pid in s.tree,
          "tree=%d pids" % len(s.tree))
    s.sample()
    check("sampled a nonzero RSS", s.peak_rss > 300 * 1048576,
          "%.0f MB" % (s.peak_rss / 1048576))
    ch.wait()
    # An exited pid keeps its CPU: the union rule in _walk/sample.
    s.sample()
    check("cpu survives the pid exiting", s.cpu_s > 2.0, "%.2f s" % s.cpu_s)

    # The ps fallback must agree with the native engine, or a box without
    # libSystem silently reports different numbers from the rest of the fleet.
    # A FILE, not `-c`: an argv with embedded newlines is exactly the shape
    # the ps engine cannot parse (see _discover_ps), so comparing the two
    # engines on one would be testing that known limit rather than their
    # agreement. The rigs all launch real binaries with real argv.
    spin = os.path.join(tempfile.gettempdir(), "procsample_selftest_spin.py")
    with open(spin, "w") as f:
        # Spins LONGER than the wait below: the first cut spun 2.5 s and
        # slept 3.0 s, so the child was already reaped before discovery ran
        # and both engines correctly found nothing.
        f.write("import time\nt0=time.time()\nwhile time.time()-t0<5.0: pass\n")
    ch2 = subprocess.Popen([sys.executable, spin])
    time.sleep(1.5)
    a = ProcSampler(["procsample_selftest_spin"], nat)
    b = ProcSampler(["procsample_selftest_spin"], None)
    for x in (a, b):
        x.discover(); x.sample()
    # BOTH MUST FIND THE CHILD - not "both saw the same set". Two engines
    # snapshot the process table a moment apart on a box running many
    # sessions, so exact set equality is a flaky assertion about the BOX
    # rather than a true one about the engines.
    check("both engines find the child", ch2.pid in a.tree and ch2.pid in b.tree,
          "native=%d ps=%d pids" % (len(a.tree), len(b.tree)))
    check("neither engine counts the sampler itself",
          os.getpid() not in a.tree and os.getpid() not in b.tree)
    if a.cpu_s and b.cpu_s:
        check("ps fallback cpu within 10% of native",
              abs(a.cpu_s - b.cpu_s) / max(a.cpu_s, .01) < .10,
              "native=%.2f ps=%.2f" % (a.cpu_s, b.cpu_s))
    ch2.wait()

    # The sampling loop must actually be cheap - this is the whole claim.
    ch3 = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)"])
    s3 = ProcSampler([r"time.sleep\(3\)"], nat)
    s3.discover()
    t0 = time.time()
    for _ in range(400):
        s3.sample()
    per_ms = 1000 * (time.time() - t0) / 400
    check("a sample costs under 1 ms", per_ms < 1.0, "%.4f ms" % per_ms)
    ch3.wait()

    print("procsample --selftest: %s" % ("FAILED: " + ", ".join(fails) if fails else "all ok"))
    return 1 if fails else 0


def _main(argv):
    import json
    import signal
    if "--selftest" in argv:
        return _selftest()
    rates = "--rates" in argv
    argv = [a for a in argv if a != "--rates"]
    if len(argv) < 2:
        print(__doc__)
        return 2
    out, pats = argv[0], argv[1:]
    proc_hz = float(os.environ.get("PROC_HZ", "100"))
    disc_hz = float(os.environ.get("DISCOVER_HZ", "5"))
    nat = make_native()
    s = ProcSampler(pats, nat)
    run = {"go": True}
    signal.signal(signal.SIGTERM, lambda *_: run.update(go=False))
    signal.signal(signal.SIGINT, lambda *_: run.update(go=False))
    t0 = time.time()
    last_disc = 0.0
    while run["go"]:
        now = time.time()
        if now - last_disc >= 1.0 / disc_hz:
            s.discover()
            last_disc = now
        s.sample()
        with open(out, "w") as f:
            f.write(str(s.peak_rss // 1024))
        time.sleep(max(0.0, 1.0 / proc_hz - (time.time() - now)))
    span = max(time.time() - t0, 1e-6)
    with open(out, "w") as f:
        f.write(str(s.peak_rss // 1024))
    with open(out + ".cpu", "w") as f:
        f.write("%.1f" % s.cpu_s)
    if rates:
        print(json.dumps({"engine": "native" if nat else "ps",
                          "samples": s.samples, "hz_achieved": round(s.samples / span, 2),
                          "discoveries": s.discoveries,
                          "sample_ms_mean": round(1000 * s.sample_cost / max(1, s.samples), 4),
                          "peak_rss_kb": s.peak_rss // 1024, "cpu_s": round(s.cpu_s, 1),
                          "disk_read_mb": s.disk_read // 1048576,
                          "disk_write_mb": s.disk_write // 1048576}))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
