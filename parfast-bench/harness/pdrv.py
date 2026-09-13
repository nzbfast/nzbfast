#!/usr/bin/env python3
"""pdrv.py - the mac/BSD half of the parfast publication harness.

Written in python rather than shell for one reason: /usr/bin/time writes to
STDERR, so a `2>file` on that command line redirects TIME's stderr and not the
child's. That silently produced an empty wall= field on about 120 legs of an
earlier round while every other field looked healthy. os.wait4 returns the
child's OWN rusage, so nothing has to be parsed out of a stream at all.

Also here, and for the same reason each one faked a result somewhere:
  - the rig LOCK is an flock held for the process lifetime, and callers count
    LOCKS, not processes (pgrep counts subshells, which inherit the parent's
    command line)
  - rc AND stderr are kept for every leg; a refusal must never read as a fast
    success
  - every repair is gated on SHA-256 restoration, never on an exit code
  - tool backups are removed after every leg (they reached 157 GB once)
"""
import fcntl, hashlib, json, os, random, resource, signal, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

SLICE_DEFAULT = 768000


class RigLock:
    def __init__(self, path):
        # PER BOX, not per round, and the path is ABSOLUTE for that reason.
        # Each script used to lock its own file, which excluded a second copy
        # of the SAME round and nothing about a different one; on 10 Sep 2026
        # that let three rounds run at once on one box and contaminated a whole
        # ladder. The first fix derived the lock from the LOG's directory,
        # which is per-DIRECTORY and not per-box: the same day, a lane running
        # out of ~/gaterun and this one running out of ~/pubrun took two
        # different "per-box" locks and measured each other. One fixed path in
        # $HOME is the only thing that is actually one per box. The round's
        # name goes INSIDE the file so a human can see who holds it.
        self.round = os.path.splitext(os.path.basename(path))[0]
        self.path = os.path.expanduser("~/.parfast-rig.lock")
        self.fh = None

    def take(self):
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            print("LOCK-BUSY %s" % self.path, flush=True)
            sys.exit(17)
        self.fh.write("round=%s pid=%d started=%s\n" % (self.round, os.getpid(), utcnow()))
        self.fh.flush()
        print("RIG-LOCK-TAKEN %s pid=%d" % (self.path, os.getpid()), flush=True)
        # And refuse at the TOP as well as before each leg: a round that starts
        # on a loaded box wastes its whole fixture build before the first leg
        # finds out.
        require_quiet_box("round-start")

    def release(self):
        if self.fh:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()
            self.fh = None
        try:
            os.unlink(self.path)
        except OSError:
            pass
        print("RIG-LOCK-RELEASED %s" % self.path, flush=True)


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cpu_count():
    return os.cpu_count() or 1


# A leg measured on a box carrying somebody else's work is not slow, it is
# WRONG, and nothing downstream can tell the difference: the rc is 0, the SHA
# gate passes 23/23, and only the shape of the numbers gives it away. On
# 10 Sep 2026 a lane running a deliberate 74-process spin load out of
# ~/gaterun overlapped this round in ~/pubrun for ten minutes at load 161 on
# an 18-core box - parfast's cpu/wall read 7.2 where it should read ~14 and
# turbo's read 0.88, so both tools and therefore the RATIO were junk. The rig
# lock cannot see that lane, because a lock only excludes rounds that agreed to
# take it. Load can be seen whoever caused it, so this guard does not depend on
# the other lane's cooperation.
#
# It must measure FOREIGN cpu and not load average. The first cut of this guard
# read os.getloadavg()[0], which on a healthy box is dominated by THIS round's
# own previous leg - antigua sat at load 32.25 of 32 cores while running
# exactly one correct round, so a loadavg guard would have refused every leg it
# was supposed to protect. Per-process %CPU minus our own process tree is the
# quantity that actually means "somebody else is on the box": between legs our
# own tools are gone, so our share is the driver's ~0%.
FOREIGN_CPU_CEILING_FRAC = 0.10   # of the whole box, in cores
FOREIGN_CPU_FLOOR_PCT = 100.0     # never refuse under one full core


def _ps_snapshot():
    out = subprocess.run(["ps", "-Ao", "pid=,ppid=,pcpu=,comm="],
                         capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        f = line.split(None, 3)
        if len(f) < 4:
            continue
        try:
            rows.append((int(f[0]), int(f[1]), float(f[2]), f[3]))
        except ValueError:
            continue
    return rows


def cpu_stat_jiffies():
    """(steal, total) jiffies across all cores from /proc/stat, or None.

    LINUX ONLY, and that is not a shortfall - it is the whole point. Steal is
    time the guest was RUNNABLE and the hypervisor ran somebody else, so it
    exists only under virtualisation and only Linux exports it. macOS returns
    None and every caller prints `n/a` rather than a zero.

    WHY A ROUND NEEDS IT. `foreign_cpu` answers "what else on this box is
    running", which is the right question on a desktop and the wrong one on a
    shared guest: a co-tenant on the same physical host is invisible to it,
    because that load is in another VM and never appears in this kernel's
    process table. On 11 Sep 2026 the Zen 4 sign round (JOINT-FACTOR-MIN-M-X86
    section 19) voided with `foreign_cpu` reading a quiet 13.9% of one core
    across all 75 legs and an A/A floor of 13.6-36.9% - the guard said quiet
    and the arm-against-itself said otherwise, and nothing in the round could
    separate the two. This is the reading that would have.

    Fields are user nice system idle iowait irq softirq steal ... - steal is
    the 8th, and the total is their sum, so the ratio is steal as a share of
    ALL cpu time across every core in the sample window."""
    try:
        with open("/proc/stat") as fh:
            parts = fh.readline().split()
    except OSError:
        return None
    if not parts or parts[0] != "cpu" or len(parts) < 9:
        return None
    try:
        vals = [int(x) for x in parts[1:]]
    except ValueError:
        return None
    return vals[7], sum(vals)


def foreign_cpu():
    """Total %CPU on the box that is not ours, plus the biggest contributors.

    Ours means this process and every descendant of it - the driver, the tool
    under test, the warm reader, the hash lanes."""
    rows = _ps_snapshot()
    parent = {pid: ppid for pid, ppid, _, _ in rows}
    mine = os.getpid()

    def is_mine(pid):
        seen = 0
        while pid > 1 and seen < 64:
            if pid == mine:
                return True
            pid = parent.get(pid, 0)
            seen += 1
        return pid == mine

    total, top = 0.0, []
    for pid, _ppid, pcpu, comm in rows:
        if pcpu < 1.0 or is_mine(pid):
            continue
        total += pcpu
        top.append((pcpu, pid, comm))
    top.sort(reverse=True)
    return total, top[:4]


def foreign_ceiling():
    return max(FOREIGN_CPU_FLOOR_PCT, cpu_count() * 100.0 * FOREIGN_CPU_CEILING_FRAC)


# HOW LONG THE GUARD WAITS, as module state so a LONG round can buy more
# patience than a short one without every caller growing a parameter.
#
# The defaults are 10 x 30 s = five minutes, and five minutes is calibrated for
# a spike, not a STORM. Measured on apple-m3-ultra, 11 Sep 2026: a `contactsd`
# contacts-sync storm with FaceTime beside it held 832% of a 320% ceiling, the
# guard spent its whole budget, aborted at 22:49:04Z - and the box was quiet
# again by 22:50. That threw away 90 minutes of completed legs to outlast a
# disturbance by ONE MINUTE, because an aborted jcross round loses its partial.
#
# The asymmetry is the point: waiting costs wall clock on a box nobody else is
# timing on, and aborting costs the whole round. So a round whose ladder is
# hours long should raise this; a calibration run should not bother.
QUIET_TRIES = 10
QUIET_WAIT = 30


def set_quiet_budget(tries, wait):
    global QUIET_TRIES, QUIET_WAIT
    QUIET_TRIES, QUIET_WAIT = tries, wait
    print("QUIET-BUDGET tries=%d wait=%ds max=%.1f min"
          % (tries, wait, tries * wait / 60.0), flush=True)


def require_quiet_box(where, tries=None, wait=None):
    """Called at the top of every round AND before every timed leg. Refuses
    rather than publishing a number measured against somebody else's load. A
    reading under the ceiling but well over the noise floor is printed as a
    WARN, so a contaminated stretch is visible in the log even where the guard
    chose to continue.

    It WAITS before it gives up, like the Windows half. That half had the retry
    from the start and this one did not, and the asymmetry cost three rounds on
    11 Sep 2026: macOS fired Spotlight's indexer and mobileassetd mid-round,
    both transient, and the Mac guard aborted on the first sample while the
    Windows guard would have waited them out. A background daemon that runs for
    a minute should cost a minute, not a night.

    The defaults are `Require-QuietBox`'s, deliberately: ten retries at thirty
    seconds. WHAT THAT COSTS, because a round's wall time is what gets
    published. A box that is genuinely, permanently busy pays the full five
    minutes ONCE and then aborts with 18 as before - the round dies at its
    first guarded point, so the cost is bounded by five minutes per ROUND, not
    per leg. The case that does accumulate is a box busy at every leg boundary
    and quiet again within five minutes each time: forty legs could then carry
    forty waits. That is the trade this function exists to make, and it is the
    right way round, because every one of those forty legs ABORTED THE ROUND
    under the old signature. Pass `tries=0` for the old behaviour - one sample,
    no wait - at any call site that would rather die than wait.

    The WARN arm reads the LAST sample, not the first, which is the one the leg
    will actually run under. The Windows half learned the same thing the
    expensive way and records it against $script:lastforeign: a guard that
    reports its pre-wait spike describes a stretch that no longer exists."""
    tries = QUIET_TRIES if tries is None else tries
    wait = QUIET_WAIT if wait is None else wait
    for attempt in range(tries + 1):
        total, top = foreign_cpu()
        ceiling = foreign_ceiling()
        if total < ceiling:
            break
        if attempt == tries:
            break
        print("BOX-BUSY-WAIT try=%d foreign_cpu=%.0f%% ceiling=%.0f%% at=%s ts=%s"
              % (attempt + 1, total, ceiling, where, utcnow()), flush=True)
        time.sleep(wait)
    if total >= ceiling:
        who = " ".join("%s(%d)=%.0f%%" % (c, pid, pc) for pc, pid, c in top)
        print("BOX-BUSY foreign_cpu=%.0f%% ceiling=%.0f%% cores=%d top=[%s]"
              % (total, ceiling, cpu_count(), who), flush=True)
        print("ABORT-LOAD at=%s ts=%s" % (where, utcnow()), flush=True)
        sys.exit(18)
    if total >= ceiling / 3.0:
        who = " ".join("%s(%d)=%.0f%%" % (c, pid, pc) for pc, pid, c in top)
        print("WARN-FOREIGN-CPU at=%s foreign_cpu=%.0f%% ceiling=%.0f%% top=[%s]"
              % (where, total, ceiling, who), flush=True)


_LIVE_CHILDREN = set()


def _terminate_children(signum, _frame):
    for proc in list(_LIVE_CHILDREN):
        try:
            proc.terminate()
        except OSError:
            pass
    for proc in list(_LIVE_CHILDREN):
        try:
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except OSError:
                pass
    print("DRIVER-TERMINATED sig=%d ts=%s" % (signum, utcnow()), flush=True)
    sys.exit(143)


for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    # NEVER take over a signal the parent deliberately IGNORED. `nohup` protects
    # a detached round by setting SIGHUP to SIG_IGN; installing a handler on top
    # of that un-protects it, and the round then takes the hangup when the ssh
    # session that launched it closes. Two Mac rounds sat for hours at 0.04 s of
    # CPU with an empty log because of this line. Checking the existing
    # disposition first keeps the guard for signals we are actually meant to
    # handle and leaves an inherited SIG_IGN alone.
    try:
        if signal.getsignal(_sig) is signal.SIG_IGN:
            continue
        signal.signal(_sig, _terminate_children)
    except (OSError, ValueError):
        pass


def run_leg(exe, argv, cwd, logbase, env_extra=None):
    """One tool invocation. Returns rc, wall, child CPU seconds and peak RSS.

    `env_extra` overlays the child's environment. It exists for the joint Forney
    solver ("fast mode"), which ships BOTH as a CLI switch and as
    NZBFAST_FORNEY_JOINT: an A/B of it is then two arms of the SAME binary, so
    no rebuild is needed and the two arms cannot differ by anything except the
    switch. Whatever is passed here is echoed into the leg line by the caller,
    because an arm nobody can see in the log is an arm nobody can reproduce.

    **THE BASELINE ARM MUST NAME `NZBFAST_FORNEY_JOINT=0`.** It did not used to
    have to: the switch was default-off everywhere, so "pass nothing" and "pass
    off" were the same arm. Since 11 Sep 2026 (`e5aa098878`) the joint solve is
    the DEFAULT on aarch64, so on any Apple box a baseline arm that passes
    nothing is a second copy of the ON arm - and the failure is silent, because
    both arms run, both restore, both print a wall, and the A/B simply reports
    a dead heat. Three round scripts on this fleet carried that hole on the day
    of the flip. Grep a suspect log's `BIN` line for the build it ran: a log
    whose binary predates the flip is unaffected."""
    require_quiet_box(os.path.basename(logbase))
    foreign_before, _ = foreign_cpu()
    stat_before = cpu_stat_jiffies()
    child_env = None
    if env_extra:
        child_env = dict(os.environ)
        child_env.update({k: str(v) for k, v in env_extra.items()})
    with open(logbase + ".out", "wb") as fo, open(logbase + ".err", "wb") as fe:
        t0 = time.monotonic()
        proc = subprocess.Popen([exe] + argv, cwd=cwd, stdout=fo, stderr=fe,
                                stdin=subprocess.DEVNULL, env=child_env)
        # A driver killed mid-leg used to leave the tool running with ppid 1.
        # On 10 Sep 2026 that left a par2turbo repair of a 23 GiB set orphaned
        # on the M5 after its round was stopped - it kept a share of the box
        # for minutes, and only an lsof of its cwd could tell whose it was.
        # Registering it means a TERM on the driver takes the leg with it.
        _LIVE_CHILDREN.add(proc)
        try:
            pid, status, ru = os.wait4(proc.pid, 0)
        finally:
            _LIVE_CHILDREN.discard(proc)
        wall = time.monotonic() - t0
    # SAMPLED AFTER THE LEG, and both of these are new on 11 Sep 2026.
    #
    # `foreign_cpu` alone describes the box in the instant BEFORE the tool
    # started, which is the one moment a leg is guaranteed not to be running
    # in. Load that arrives once the leg is under way is invisible to it, and
    # the Windows half has carried a `foreign_after` since it was written -
    # so on unix `s2sum.py` could not even reduce a round (fixed at
    # e984b7b8cd), and no unix round could say whether the box stayed quiet.
    foreign_after, _ = foreign_cpu()
    stat_after = cpu_stat_jiffies()
    proc.returncode = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (
        os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status))
    # macOS reports ru_maxrss in bytes; linux in kilobytes.
    peak = ru.ru_maxrss if sys.platform == "darwin" else ru.ru_maxrss * 1024
    return {
        "rc": proc.returncode,
        "wall": round(wall, 3),
        "cpu": round(ru.ru_utime + ru.ru_stime, 3),
        "peak_mb": round(peak / (1024.0 * 1024.0), 1),
        "errlen": os.path.getsize(logbase + ".err"),
        "outlen": os.path.getsize(logbase + ".out"),
        # Published beside the timing on purpose: a leg that ran clean and a leg
        # that shared the box are indistinguishable in wall, rc and the SHA
        # gate, so the reading has to travel WITH the number or a reader cannot
        # check it. Sampled just before the tool started.
        "foreign_cpu": round(foreign_before, 1),
        "foreign_after": round(foreign_after, 1),
        # Steal ACROSS THE LEG, as a share of all cpu time on every core in
        # that window - never a cumulative figure, which on a box up for weeks
        # dilutes a 40-minute round to nothing and reads as a quiet machine
        # whatever happened. `n/a` off Linux, never 0.0: a zero would assert a
        # bare-metal box that nothing measured.
        "steal_pct": _steal_pct(stat_before, stat_after),
    }


def _steal_pct(before, after):
    """Steal as a % of all cpu time between two /proc/stat samples."""
    if not before or not after:
        return "n/a"
    d_steal = after[0] - before[0]
    d_total = after[1] - before[1]
    if d_total <= 0 or d_steal < 0:
        return "n/a"
    return round(100.0 * d_steal / d_total, 2)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def gate(directory, members, gold, lanes=8):
    """SHA-256 restoration gate. MultiPar returns exit 16 on a SUCCESSFUL
    repair, so an exit code can never stand in for this."""
    paths = [os.path.join(directory, m) for m in members]
    with ThreadPoolExecutor(max_workers=lanes) as ex:
        hashes = list(ex.map(sha256_file, paths))
    good, bad = 0, []
    for m, h in zip(members, hashes):
        if gold[m] == h:
            good += 1
        else:
            bad.append(m)
    return good, bad


def damage_picks(directory, members, slicesize, m, seed):
    """Deterministic scattered damage plan. Depends only on the set shape, m and
    the seed, so every tool at a rung repairs byte-identical damage."""
    counts, lens, total = [], [], 0
    for nm in members:
        n = os.path.getsize(os.path.join(directory, nm))
        c = -(-n // slicesize)
        counts.append(c)
        lens.append(n)
        total += c
    if m > total:
        raise SystemExit("damage %d exceeds %d slices" % (m, total))
    order = list(range(total))
    rng = random.Random(seed)
    rng.shuffle(order)
    bym = {}
    for g in order[:m]:
        mi = 0
        while g >= counts[mi]:
            g -= counts[mi]
            mi += 1
        bym.setdefault(mi, []).append(g)
    for k in bym:
        bym[k].sort()
    return {"bym": bym, "lens": lens, "total": total}


def apply_damage(directory, members, slicesize, picks, seed):
    rng = random.Random(seed + 1)
    written = 0
    for mi in sorted(picks["bym"]):
        path = os.path.join(directory, members[mi])
        with open(path, "r+b") as f:
            for si in picks["bym"][mi]:
                off = si * slicesize
                n = min(slicesize, picks["lens"][mi] - off)
                f.seek(off)
                f.write(rng.randbytes(n))
                written += 1
    return written


def restore_slices(work, pristine, members, slicesize, picks):
    """Undo a leg by writing back exactly the slices it changed. The caller MUST
    re-gate afterwards and fall back to a full copy for anything still wrong."""
    for mi in sorted(picks["bym"]):
        nm = members[mi]
        with open(os.path.join(pristine, nm), "rb") as src, \
             open(os.path.join(work, nm), "r+b") as dst:
            for si in picks["bym"][mi]:
                off = si * slicesize
                n = min(slicesize, picks["lens"][mi] - off)
                src.seek(off)
                buf = src.read(n)
                dst.seek(off)
                dst.write(buf)


def remove_strays(work, keep):
    n = 0
    for name in os.listdir(work):
        if name not in keep:
            os.unlink(os.path.join(work, name))
            n += 1
    return n


def warm(directory):
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), "rb") as f:
            while f.read(1 << 23):
                pass


def box_facts():
    """Print what machine this is. Platform-aware on purpose: the first VPS run
    printed `cpu=? cores=? os=macOS ?` because this was mac-only, on the one box
    in the fleet whose figures MUST carry a label (it is a VM slice). A log that
    cannot say what it ran on is the same defect as a binary that cannot say
    what it was built from."""
    st = os.statvfs(os.path.expanduser("~"))
    free_gb = round(st.f_bavail * st.f_frsize / (1024 ** 3), 1)
    if sys.platform == "darwin":
        def sysctl(k):
            try:
                return subprocess.check_output(["sysctl", "-n", k], text=True).strip()
            except Exception:
                return "?"
        try:
            mem_gb = round(int(sysctl("hw.memsize")) / (1024 ** 3), 1)
        except ValueError:
            mem_gb = "?"
        try:
            osver = "macOS " + subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
        except Exception:
            osver = "macOS ?"
        cpu, cores = sysctl("machdep.cpu.brand_string"), sysctl("hw.ncpu")
    else:
        cpu, cores, mem_gb, osver = "?", str(os.cpu_count() or "?"), "?", "?"
        try:
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
        try:
            for line in open("/proc/meminfo"):
                if line.startswith("MemTotal"):
                    mem_gb = round(int(line.split()[1]) / (1024 ** 2), 1)
                    break
        except OSError:
            pass
        try:
            rel = dict(
                l.rstrip("\n").split("=", 1)
                for l in open("/etc/os-release") if "=" in l
            )
            osver = rel.get("PRETTY_NAME", "?").strip('"')
        except OSError:
            pass
        osver = "%s (kernel %s)" % (osver, os.uname().release)
    print("BOX host=%s cpu=%s cores=%s ram_gb=%s os=%s free_gb=%s"
          % (os.uname().nodename, cpu, cores, mem_gb, osver, free_gb), flush=True)


# --------------------------------------------------------------------------
# WHICH CUT OF THE HARNESS PRODUCED THIS ROUND, AND THIS LEG?
# --------------------------------------------------------------------------
# Two questions, two mechanisms, and neither answers the other. `harness_facts`
# below is the ROUND-START half: every file the round sources, hashed once, in
# the log the round writes. `rig_stamp` is the PER-LEG half, ported from
# the bench rig library's `rig_gen` (TODO 236 item 1, 23 Aug 2026), and it
# exists because a hash taken once at round start cannot see a file that changes
# at leg 40 - which is exactly what happened on intel-i5-10600kf on 11 Sep 2026, where
# the deployed harness diverged from origin/main for about twenty minutes and
# came back (an internal note). A DRIFT THAT
# REVERTS IS INVISIBLE TO EVERY CHECK THAT RUNS AT A POINT IN TIME, so the
# identity has to travel on the LINE.
#
# THE SET IS WHAT THIS PROCESS CAN ESTABLISH WITH CERTAINTY, and nothing else.
# Same honesty rule as rig-lib.sh's: the running driver module and this library
# are both files whose paths the interpreter hands us, so they are facts; the
# other twenty scripts in the directory beside them are not, and a confidently
# wrong generation is worse than no token. A round that sources something else
# NAMES it, by passing it to `harness_facts`.
#
# SORTED BY BASENAME so the value is stable across legs and across platforms
# (`plib.ps1`'s `Get-RigStamp` sorts the same way): a reader comparing two legs
# is comparing one string, which is what lets `jsum.py` and `s2sum.py` refuse a
# fold whose legs came from two different harnesses.
#
# NO CACHE, DELIBERATELY - and this is the one place this port differs from
# rig-lib.sh, which memoises into `_RIG_GEN`. There, a leg is a fresh
# `bench2.sh` process, so a per-process cache is still per-leg; here the driver
# is ONE process for the whole round, and a cache would silently turn this back
# into the round-start stamp it exists to complement. Two ~20 KB sha256s per leg
# against a leg measured in minutes.
_HARNESS_SET = []


def _default_harness_set():
    """The driver module that is running, plus this library. No guessing."""
    out = []
    main = sys.modules.get("__main__")
    mainfile = getattr(main, "__file__", None)
    if mainfile:
        out.append(os.path.abspath(mainfile))
    out.append(os.path.abspath(__file__))
    return out


def _harness_set():
    return _HARNESS_SET or _default_harness_set()


def rig_stamp():
    """`<basename>:<sha16>` per harness file, `+`-joined. RE-READ on every call.

    sha16 is the first 16 hex of the sha256, the same truncation the throughput
    rig prints, so a reader resolves a token with one command and no box access:

        git show origin/main:harness/pdrv.py | shasum -a 256 | cut -c1-16

    AN UNREADABLE FILE IS STAMPED `unreadable` RATHER THAN LEFT OFF. "this leg
    could not establish its harness" is a fact a reader wants, and an absent
    token is indistinguishable from a harness older than this block, which
    never had one - the ambiguity this whole section exists to end.
    """
    out = []
    for p in _harness_set():
        try:
            sha = sha256_file(p)[:16]
        except OSError:
            sha = "unreadable"
        out.append("%s:%s" % (os.path.basename(p), sha))
    return "+".join(out) if out else "unknown"


def rig_token(line=""):
    """The LEG-line token, with a leading space. FIRST WRITER WINS.

    Suppressed on a line that already carries `rig=`, for rig-lib.sh's reason: a
    second copy of the key is not an error anyone SEES, it is one value silently
    overwriting another in every reader that dicts the tail - the quiet class
    this token exists to close.
    """
    if " rig=" in line:
        return ""
    return " rig=%s" % rig_stamp()


def harness_facts(paths=None):
    """Stamp the DRIVER's own provenance into the round log, beside the binary's.

    `bin_facts` answers "which build did this round measure". Nothing answered
    "which driver measured it", and when this function landed on 11 Sep 2026
    nothing on the parfast rigs could: the throughput farm stamps
    `rig=<basename>:<sha16>` on every LEG line, and `tools/bench-deploy-check.py`
    knew only that farm's three boxes - it REFUSED intel-i5-10600kf, the Apple rigs,
    the Windows boxes and every ad hoc machine by name - so a parfast round had
    no drift evidence of any kind at all.

    BOTH OF THOSE GAPS ARE CLOSED NOW, and the three mechanisms are not
    substitutes for each other. That tool covers every rig box on both
    platforms as of `a5556ee721` (same day), which answers "was the deployed
    copy current BEFORE the round". This function answers "what did the round
    source", from the round's own banked log, months later, without the box.
    And `rig_stamp` above answers the one neither can reach - "did it change
    while the round was RUNNING" - which is why the token is on the LEG line
    and this is not enough on its own.

    It is not theoretical. On 11 Sep 2026 a lane watched its box's harness copy
    drift mid-session and back again, and separately this fleet spent a day
    measuring a binary 31 minutes older than the gate that changed the answer -
    the same class of defect one level up, and unanswerable from wall times
    alone once the logs are banked and the box has moved on.

    So: every file the round SOURCES, hashed at round start, in the log the
    round writes. That does not by itself say the copy was current - comparing
    it against `git show origin/main:<path> | shasum -a 256` is still a hand
    step before the round - but it is what makes the comparison possible
    AFTERWARDS, from the banked log alone, which is the half that was missing.

    Called with no argument it stamps `_default_harness_set()`, so wiring a
    driver in is a one-line call; a round that sources anything else passes the
    whole list. Either way the set is REGISTERED, and every LEG line's
    `rig_stamp` then re-reads exactly the files the HARNESS lines named.
    """
    global _HARNESS_SET
    paths = [os.path.abspath(p) for p in (paths if paths is not None
                                          else _default_harness_set())]
    seen, ordered = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    _HARNESS_SET = sorted(ordered, key=lambda q: (os.path.basename(q), q))
    for p in _HARNESS_SET:
        if not os.path.exists(p):
            print("PREFLIGHT-FAIL missing %s" % p, flush=True)
            sys.exit(9)
        print("HARNESS %s sha256=%s bytes=%d"
              % (os.path.basename(p), sha256_file(p), os.path.getsize(p)),
              flush=True)
    # The token the legs will carry, printed ONCE at round start too, so a
    # reader who greps the head of a log sees the same string the legs carry
    # and does not have to compose it from the HARNESS lines by hand.
    print("HARNESS-RIG %s" % rig_stamp(), flush=True)


def rig_vol_facts(rig):
    """The FIXTURE VOLUME's headroom and snapshot exposure, at round start.

    A round that fills its own volume measures the volume. Apple SSDs carve
    the SLC write cache out of FREE SPACE, and on a volume inside the Time
    Machine backup set every hourly local snapshot additionally PINS the
    blocks a repair leg's damage-and-restore churn replaced - so free space
    falls all round even though the round creates no new files after its
    fixture, and deleting a previous fixture returns nothing.

    Measured on apple-m3-ultra, 11 Sep 2026, a 1 MiB n = 16,384 ladder: 159.7 GB
    free at the start, 69 GB of it the round's own fixture, ~59 GB more to
    snapshot-pinned churn, last reps running at 1.7% free. The read-only
    `verify targets + volume scan` phase stayed FLAT at 0.97 s (+0.2%) across
    all five reps while the median leg wall went 12.71 s to 25.42 s - CPU and
    reads fine, writes throttled - and the deep rungs' A/A floors blew out to
    8-29% against 4-11% on the roomier run of the same evening.

    None of that is visible in a LEG line, and all of it is fatal to a table.
    So it goes in the log, at the top, where the A/A floor and the negative
    control already are."""
    try:
        d = os.path.dirname(os.path.abspath(rig)) or "/"
        while not os.path.isdir(d) and d != "/":
            d = os.path.dirname(d)
        st = os.statvfs(d)
        free_gb = st.f_bavail * st.f_frsize / 1e9
        total_gb = st.f_blocks * st.f_frsize / 1e9
        snaps = subprocess.run(["tmutil", "listlocalsnapshots", d],
                               capture_output=True, text=True)
        nsnap = sum(1 for l in (snaps.stdout or "").splitlines()
                    if "com.apple.TimeMachine" in l)
        excl = subprocess.run(["tmutil", "isexcluded", d],
                              capture_output=True, text=True)
        ex = "yes" if "[Excluded]" in (excl.stdout or "") else "no"
        print("RIGVOL dir=%s free_gb=%.1f total_gb=%.1f free_pct=%.1f "
              "tm_excluded=%s local_snapshots=%d"
              % (d, free_gb, total_gb, free_gb / max(total_gb, 1) * 100.0,
                 ex, nsnap), flush=True)
    except Exception as e:                      # never let provenance kill a round
        print("RIGVOL unavailable (%s)" % e, flush=True)


def bin_facts(paths):
    for p in paths:
        if not os.path.exists(p):
            print("PREFLIGHT-FAIL missing %s" % p, flush=True)
            sys.exit(9)
        # -VV, not -V: parfast stamps the commit it was built from on the
        # SECOND line, and a benchmark log that cannot name the source of its
        # own binary is the defect that voided a day of rounds on 10 Sep.
        ver = subprocess.run([p, "-VV"], capture_output=True, text=True)
        line = (ver.stdout + ver.stderr).strip().splitlines()
        stamp = next((l.strip() for l in line if l.startswith("built from ")), "built from ?")
        print("BIN %s sha256=%s bytes=%d version=%s %s"
              % (os.path.basename(p), sha256_file(p), os.path.getsize(p),
                 line[0] if line else "?", stamp), flush=True)
