#!/usr/bin/env python3
"""pdrv.py - the mac/BSD/Linux/Windows driver library of the parfast
publication harness.

It was "the mac/BSD half" until 17 Sep 2026, and the rename is the finding
rather than tidying: it could not be IMPORTED on Windows, and both of this
fleet's bare-metal `KernelClass::Avx512Gfni` parts ARE Windows (windows-gaming-pc-b and
amd-ryzen-9800x3d, AMD Ryzen 7 9800X3D - `.claude/MACHINES.md`, "Windows boxes"). So
there was no route to a bare-metal GFNI number on this fleet at all, and
sections 8.13.2 and 8.18 of an internal note
each hit that wall and routed to a KVM guest, where 8.18 then measured
hypervisor steal displacing a fitted breakpoint by 20%. The Windows arms live
beside each POSIX one, with `harness/winproc.py` holding the ctypes;
every POSIX path is unchanged, because 8.11 through 8.18 are that note's
provenance and their legs must stay comparable.

Written in python rather than shell for one reason: /usr/bin/time writes to
STDERR, so a `2>file` on that command line redirects TIME's stderr and not the
child's. That silently produced an empty wall= field on about 120 legs of an
earlier round while every other field looked healthy. os.wait4 returns the
child's OWN rusage, so nothing has to be parsed out of a stream at all - and
`_run_leg_win` reads the child's own process handle for the same reason, since
`os.wait4` does not exist on Windows.

Also here, and for the same reason each one faked a result somewhere:
  - the rig LOCK is an flock held for the process lifetime, and callers count
    LOCKS, not processes (pgrep counts subshells, which inherit the parent's
    command line)
  - rc AND stderr are kept for every leg; a refusal must never read as a fast
    success
  - every repair is gated on SHA-256 restoration, never on an exit code
  - tool backups are removed after every leg (they reached 157 GB once)
"""
import hashlib, json, os, platform, random, shutil, signal, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

# THE WINDOWS ARM, ADDED 17 Sep 2026, AND WHY THE IMPORTS MOVED.
#
# This module was POSIX-only and could not be IMPORTED on Windows at all -
# `fcntl` and `resource` do not exist there, and neither does `signal.SIGHUP`,
# which the handler loop below names in a tuple. Both of this fleet's
# bare-metal `KernelClass::Avx512Gfni` parts are Windows (windows-gaming-pc-b and amd-ryzen-9800x3d,
# AMD Ryzen 7 9800X3D - `.claude/MACHINES.md`, "Windows boxes"), so sections
# 8.13.2 and 8.18 of an internal note each had
# to route their GFNI round to a KVM guest, where 8.18 then measured
# hypervisor steal displacing a fitted breakpoint by 20%. There was no route to
# a bare-metal GFNI number on this fleet at all, and that is what this closes.
#
# EVERY POSIX PATH BELOW IS UNCHANGED, and that is the constraint the whole
# port is written under rather than a hope: sections 8.11 through 8.18 are this
# note's provenance and their legs must stay comparable, so the Windows work is
# NEW BRANCHES ONLY. Where the two platforms could have been unified on the
# better rule and were not, the site says so and names what moving it would
# cost (see `foreign_cpu_window` and `winproc.foreign_delta`).
IS_WIN = os.name == "nt"
if IS_WIN:
    fcntl = None
    resource = None
else:
    import fcntl
    import resource

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import riglock_state   # noqa: E402 - needs the sys.path line above, since a
                       # round script may import pdrv from any cwd
import winproc         # noqa: E402 - same reason; a no-op off Windows

SLICE_DEFAULT = 768000


class RigLock:
    def __init__(self, path, lock_path=None):
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
        #
        # `lock_path` overrides the real per-box path - for rig_lock_selftest.py
        # only, so a test can race two holders over a temp file instead of the
        # live ~/.parfast-rig.lock. Every real caller leaves it unset.
        self.round = os.path.splitext(os.path.basename(path))[0]
        # `os.path.join`, not `expanduser("~/.parfast-rig.lock")`: on POSIX the
        # two produce the identical string, and on Windows the second yields
        # `<rig> That mixed separator opens the
        # SAME NTFS entry, so exclusion against `plib.ps1`'s
        # `Join-Path $env:USERPROFILE` spelling is unaffected - but it is what
        # a human reads out of a RIG-LOCK-TAKEN line when deciding whether to
        # clear somebody's lock, and `ladder.RigLock` and `plib.ps1` both print
        # the backslash form. One spelling, so two logs of the same box compare.
        self.path = lock_path or os.path.join(os.path.expanduser("~"), ".parfast-rig.lock")
        self.fh = None

    def take(self):
        # "a", NEVER "w", and truncate only once the lock is OURS. Opening "w"
        # truncated the file before the flock was even tried, so every
        # LOCK-BUSY probe wiped the HOLDER's round name and pid out of it - on
        # 14 Sep 2026 a lane waiting for this lock blanked a live rssleg.py
        # round's identity, and the next reader found an empty file under a
        # held lock with nothing saying whose.
        #
        # Winning the flock is not enough on its own: flock() locks the INODE
        # our fd points at, not the PATH, and those can come apart. If a
        # releaser unlinked the path and someone else has since recreated it
        # (or the path was unlinked and nothing recreated it yet), we can win
        # a flock on an orphaned inode nothing else will ever look at while a
        # different process legitimately holds the live path. Re-check that
        # the path still resolves to the inode we just locked before trusting
        # it, and retry (bounded) rather than proceed on a phantom lock. See
        # release() below for the matching half of this fix.
        #
        # Whether the file was there BEFORE we touched it, because take()
        # opens with "a" and so creates it - without this, a perfectly ordinary
        # first take on a free box reads as a zero-byte orphan and announces
        # one.
        pre_existing = os.path.exists(self.path)
        if IS_WIN:
            self._take_win(pre_existing)
            require_quiet_box("round-start")
            return
        for _attempt in range(5):
            fh = open(self.path, "a")
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                fh.close()
                print("LOCK-BUSY %s" % self.path, flush=True)
                sys.exit(17)
            try:
                current_ino = os.stat(self.path).st_ino
            except OSError:
                current_ino = None
            if current_ino == os.fstat(fh.fileno()).st_ino:
                self.fh = fh
                break
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            fh.close()
        else:
            print("LOCK-BUSY %s (inode churn, gave up after 5 tries)" % self.path, flush=True)
            sys.exit(17)
        # WINNING THE FLOCK IS NOT THE SAME AS THE BOX BEING FREE, because not
        # every taker on this box has an flock to lose: a shell round takes
        # this same path with `set -o noclobber`, which is an exclusive CREATE
        # and nothing more. On 16 Sep 2026 a lane took it that way at
        # 10:21:09Z and nttwork.py - through this very class - won the flock at
        # 10:27:42Z, truncated the line below, and wrote its own over a LIVE
        # round's. So before truncating anything, ask riglock_state whether the
        # identity already in the file names somebody who is still alive.
        # Refusing here is what makes the two idioms one lock.
        state, who = riglock_state.lock_state(self.path, probe_flock=False)
        if state == "held":
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()
            self.fh = None
            print("LOCK-BUSY %s held by: %s" % (self.path, who), flush=True)
            sys.exit(17)
        if state == "orphan" and pre_existing:
            # Provably nobody's - a dead or unnamed holder. Take it, and SAY
            # SO: two lanes cleared exactly this by hand on 16 Sep and neither
            # left a trace, so the next lane re-derived the judgement from
            # scratch. No age bound is involved in that verdict and none may be
            # added; see riglock_state's docstring.
            riglock_state.announce_orphan(self.path, who, "cleared by round=%s pid=%d" % (self.round, os.getpid()))
        self.fh.truncate(0)
        self.fh.write("round=%s pid=%d started=%s\n" % (self.round, os.getpid(), utcnow()))
        self.fh.flush()
        print("RIG-LOCK-TAKEN %s pid=%d" % (self.path, os.getpid()), flush=True)
        # And refuse at the TOP as well as before each leg: a round that starts
        # on a loaded box wastes its whole fixture build before the first leg
        # finds out.
        require_quiet_box("round-start")

    def _take_win(self, pre_existing):
        """The Windows arm. IT IS THE SAME LOCK `plib.ps1` TAKES, and that is
        the whole requirement rather than a nicety.

        `plib.ps1`'s `Try-TakeRigLock` opens `%USERPROFILE%\\.parfast-rig.lock`
        with `FileMode::CreateNew` and `FileShare::Read`, and python's
        `open(path, "x")` is CreateFile with CREATE_NEW under a share mode
        that likewise excludes FILE_SHARE_DELETE. So on NTFS "the path is
        taken" and "the file is open" are the SAME fact in both spellings:
        neither side's create can succeed while the other's handle is open,
        and neither can replace the other's file, because replacing it needs a
        delete that the open handle refuses. That is why Windows needs none of
        the inode re-checking the POSIX arm above does - there, `flock` locks
        an INODE while `unlink` frees the PATH, and the two coming apart is
        what let one round delete another's live lock on amd-epyc-vm on
        15 Sep 2026.

        THE EQUIVALENCE HAS ONE EDGE AND IT IS THE EXPENSIVE ONE. It holds only
        while the holder's HANDLE is open. A holder that dies without releasing
        takes the handle with it and leaves the directory entry, after which
        CREATE_NEW refuses every round forever and the file names nobody - the
        apple-m3-ultra orphan of 16 Sep 2026, in its Windows spelling, which cost
        eight hours. So the verdict goes to `riglock_state`, which reads
        liveness off the holder's own pid and never off the file's age, exactly
        as the POSIX arm does. There is no age bound here and none may be added.

        This is `ladder.RigLock`'s Windows arm, rule for rule, and the two are
        deliberately NOT a fourth spelling of the idiom: `ladder.py` already
        runs on Windows and had to solve this, and `harness/riglock.py`
        is a fifth (POSIX-only: `fcntl` plus `SIGALRM`). Folding all of them
        onto one implementation is real work and belongs with the lane holding
        `riglock-linux-fairness-and-bare-waiters-17sep`, not with a port that
        must not change any POSIX behaviour. Until then the invariant to hold
        is behavioural: exclusive CREATE, refuse a live holder at any age,
        clear and ANNOUNCE a provable orphan, and try exactly ONCE more.
        """
        try:
            self.fh = open(self.path, "x")
        except FileExistsError:
            state, who = riglock_state.lock_state(self.path)
            if state == "held":
                print("LOCK-BUSY %s held by: %s" % (self.path, who), flush=True)
                sys.exit(17)
            if pre_existing:
                riglock_state.announce_orphan(
                    self.path, who,
                    "cleared by round=%s pid=%d" % (self.round, os.getpid()))
            try:
                os.remove(self.path)
            except OSError as exc:
                print("LOCK-BUSY %s - orphan (%s) could not be removed: %s"
                      % (self.path, who, exc), flush=True)
                sys.exit(17)
            try:
                # A SECOND COLLISION IS A REFUSAL, NEVER A SECOND ORPHAN. A
                # live taker racing us through the window we just opened looks
                # identical to the orphan we just cleared, and looping would
                # hand it away.
                self.fh = open(self.path, "x")
            except FileExistsError:
                print("LOCK-BUSY %s - another round took it as we cleared an orphan"
                      % self.path, flush=True)
                sys.exit(17)
        self.fh.write("round=%s pid=%d started=%s\n"
                      % (self.round, os.getpid(), utcnow()))
        self.fh.flush()
        print("RIG-LOCK-TAKEN %s pid=%d" % (self.path, os.getpid()), flush=True)

    def release(self):
        # THE WINDOWS ARM CLOSES THEN REMOVES, WITH NO CHECK, and that is safe
        # for the reason `plib.ps1`'s `Release-RigLock` gives at length rather
        # than by omission: the race the POSIX ordering below defends against
        # needs "locked" and "exists" to be separable, and on NTFS under a
        # share mode without FILE_SHARE_DELETE they are the same fact. Nobody
        # can have replaced our file before this line, because replacing it
        # requires deleting it, which requires our handle to already be closed.
        if IS_WIN:
            if self.fh:
                self.fh.close()
                self.fh = None
                try:
                    os.remove(self.path)
                except OSError:
                    pass
            print("RIG-LOCK-RELEASED %s" % self.path, flush=True)
            return
        # Unlink FIRST, still holding the flock, and only if the path still
        # points at OUR inode - then unlock and close. That ordering is what
        # makes this race-free: while we still hold LOCK_EX, nobody can win a
        # non-blocking flock on our inode, so nobody can be a legitimate
        # holder of it; and once we unlink, any waiter who already has the
        # (now-orphaned) inode open will fail take()'s inode re-check above
        # rather than trust the lock it wins after we unlock. The PREVIOUS
        # order here - unlock, close, THEN unlink with no check at all - left
        # a window between unlock and unlink wide enough for a fresh take() to
        # legitimately re-lock the same still-existing path, after which this
        # unlink deleted THEIR file out from under them: that is what let
        # `parfast-feed-batch-reuse-across-slabs-15sep` delete
        # `parfast-glibc-mmap-threshold-15sep`'s live lock file on
        # amd-epyc-vm at 19:06:55Z on 15 Sep 2026 (two inodes, one holder
        # each, ~2m44s overlap) - see
        # an internal note.
        if self.fh:
            try:
                if os.stat(self.path).st_ino == os.fstat(self.fh.fileno()).st_ino:
                    os.unlink(self.path)
            except OSError:
                pass
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()
            self.fh = None
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
    if IS_WIN:
        # `winproc.foreign_cpu_lifetime` reproduces what `pcpu` MEANS on
        # Linux - cumulative cpu time over elapsed - so the box-wide ceiling
        # below, `waitquiet.py` and every banked `foreign_cpu` field keep one
        # definition across all three platforms. The tight per-core arm does
        # NOT use it; see `foreign_cpu_window`.
        return winproc.foreign_cpu_lifetime()
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


# THE SECOND ARM, AND WHY THE CEILING ABOVE CANNOT BE THE ONLY ONE.
#
# `foreign_ceiling()` is 10% of the whole box floored at one core, so ONE
# saturated core passes it on a box of ANY size - the floor guarantees it
# independently of core count, and that is the floor doing exactly what its
# comment says. By 16 Sep 2026 that arithmetic had hidden five distinct
# things: a foreign lane's pinned single-core round on intel-core-ultra-9-386h, Windows
# Search at 87% of one core, SignalRgb resident on amd-ryzen-9800x3d at 31.7%, any
# `rars` / `cargo` / `nextest` run in principle, and - measured from this box
# on 16 Sep while writing this - `spotlightknowledged.updater` at 100.2% of
# one core on apple-m3-ultra, whose 181.5% total sat comfortably under its 320%
# ceiling. The full record is
# an internal note.
#
# DO NOT LOWER THE BOX-WIDE CEILING TO CATCH THESE. It is aimed at somebody
# else's whole ROUND, and one low enough to catch a single core aborts (exit
# 18) on boxes that are merely normally busy. Two failures, two mechanisms,
# two thresholds - which is what `Wait-FixtureSettle` in plib.ps1 already says
# at length and what this arm is the unix half of.
#
# THE THRESHOLD IS 25% OF ONE CORE, carried over from `Wait-FixtureSettle`
# deliberately so the platforms do not diverge on a quantity that has been
# identical by construction until now. Its calibration is that function's and
# is quoted here rather than re-derived: clean ladders sat at 9% and 13% of a
# core with after-leg medians of 16-17%, so 25 clears a quiet box's jitter;
# the contaminated ones sat at 36%, 77% and 88%, so 25 is well below anything
# this failure has presented at. SignalRgb's 31.7% is a fourth point inside
# that gap from the other side - a real, resident, relaunching consumer that
# every deployed gate waves through and 25 catches.
#
# IT NEVER ABORTS, AND THAT IS MEASURED RATHER THAN TIMID. mred.py's note
# records a 135-leg round on a real bench box at a foreign_cpu median of 25.8%
# and a p90 of 133.5% - "real and spiky" - so an arm at 25 that called
# sys.exit(18) would have killed about half of that round's legs. A gate that
# takes a round down over load it cannot outwait is a gate lanes switch off.
# So this one WAITS on the same budget as the ceiling, and past that says so
# on a line, names the biggest foreign consumers, and lets the leg run. The
# contamination reaches the bank either way: the reading comes back to the
# caller so the leg line can carry it, and the reducers already take per-ladder
# medians of that field. Set PER_CORE_ABORTS to make it fatal in a round that
# would rather die than publish.
PER_CORE_CEILING_PCT = 25.0   # of ONE core, NOT of the box
PER_CORE_ABORTS = False


def per_core_ceiling():
    return PER_CORE_CEILING_PCT


def _cputimes_proc():
    """{pid: cumulative cpu seconds} from /proc - Linux, 10 ms resolution."""
    tick = os.sysconf("SC_CLK_TCK")
    out = {}
    for ent in os.listdir("/proc"):
        if not ent.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % ent) as fh:
                raw = fh.read()
        except OSError:
            continue
        # comm can contain spaces AND parentheses, so split after the LAST ')'.
        rp = raw.rfind(")")
        if rp < 0:
            continue
        f = raw[rp + 2:].split()
        try:
            out[int(ent)] = (int(f[11]) + int(f[12])) / float(tick)
        except (IndexError, ValueError):
            continue
    return out


def _cputimes_ps():
    """{pid: cumulative cpu seconds} from ps - macOS, 10 ms resolution.

    `ps -o time` is [[dd-]hh:]mm:ss.cc here, so the centiseconds are real and a
    one second window resolves 1% of a core."""
    out = subprocess.run(["ps", "-Ao", "pid=,time="],
                         capture_output=True, text=True).stdout
    res = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) < 2:
            continue
        try:
            pid = int(f[0])
        except ValueError:
            continue
        head, _, tail = f[1].rpartition("-")   # strip a leading days field
        try:
            secs = 0.0
            for part in tail.split(":"):
                secs = secs * 60.0 + float(part)
            if head:
                secs += float(head) * 86400.0
        except ValueError:
            continue
        res[pid] = secs
    return res


_CPUTIMES = None if IS_WIN else (
    _cputimes_proc if os.path.exists("/proc/self/stat") else _cputimes_ps)


def foreign_cpu_window(window=1.0):
    """Foreign CPU over a WINDOW, in % of one core. Returns (total, top).

    NOT a second way of spelling `foreign_cpu()`, and the difference is the
    whole reason this exists. `foreign_cpu()` reads `ps -o pcpu`, and pcpu
    MEANS TWO DIFFERENT THINGS on the two platforms this module runs on -
    measured 16 Sep 2026 by burning one core for 8 s and then watching an idle
    process:

        macOS  99.9 -> 0.0 within ten seconds        (a short decaying average)
        Linux  99.8 -> 50.0 -> 22.2 -> 12.1 -> 6.3   (cpu_time / elapsed, exactly)

    The Linux row is a LIFETIME average: 8/16, 8/36, 8/66, 8/128. So on Linux
    `foreign_cpu()` answers "what has this process averaged since it started",
    which at a 100%-floored ceiling is close enough to harmless - you need
    something substantial either way - and at 25% is not: a process that used
    ten seconds of CPU forty seconds ago reads 25 while sitting idle, and one
    that saturated a core for five minutes an hour ago reads 8 while doing it
    again. A per-core arm on that sampler would fire on history and miss the
    present.
    
    So the tight arm gets a DELTA sampler, which is what the Windows half's
    `Get-ForeignCpu` has always used (a one second window over
    TotalProcessorTime) - this is the unix half catching up to it, not a new
    idea. Validated 16 Sep 2026 on amd-epyc-vm: quiet reads 0.0-3.0, one
    spinner reads 99.5-100.3.

    `foreign_cpu()` is deliberately left alone. It is what the box-wide
    ceiling, `waitquiet.py` and every banked `foreign_cpu` field are defined
    against, and re-pointing those at a different sampler would silently move a
    quantity a year of logs is expressed in.

    THE WINDOWS ARM IS `winproc.foreign_cpu_window`, which is `plib.ps1`'s
    `Get-ForeignCpu` ported rule for rule - the same one second window over the
    same delta of process CPU times, the same 25%-of-one-core threshold at the
    caller, and the same measured-not-assumed window span. It differs from the
    unix arm below in ONE rule, at `winproc.foreign_delta`: a pid absent from
    the before snapshot is charged in full when it was BORN inside the window
    and zero otherwise, where this arm charges it zero unconditionally. That
    difference is not accidental and the unix side is not being left behind -
    it is that this sampler defines every banked unix `foreign_1core` reading
    on the fleet, and moving it would silently restate them."""
    if IS_WIN:
        return winproc.foreign_cpu_window(window)
    a = _CPUTIMES()
    t0 = time.monotonic()
    time.sleep(window)
    b = _CPUTIMES()
    dt = max(time.monotonic() - t0, 1e-6)

    # Ours means this process and every descendant, same as foreign_cpu().
    rows = _ps_snapshot()
    parent = {pid: ppid for pid, ppid, _, _ in rows}
    comm = {pid: c for pid, _, _, c in rows}
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
    for pid, tb in b.items():
        d = tb - a.get(pid, tb)
        if d <= 0 or is_mine(pid):
            continue
        pct = d / dt * 100.0
        total += pct
        top.append((pct, pid, comm.get(pid, "?")))
    top.sort(reverse=True)
    return total, top[:4]


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
#
# Both are ENV DIALS as well as module state, because the wrapper the module
# state forces is a real cost: a 54-leg ladder on a shared VPS wanted the raise
# this comment recommends, could not reach `set_quiet_budget` from a committed
# driver that never calls it, and ran the driver through a `runpy` shim to get
# it (section 8.13 of an internal note). A dial
# a runner can set beside its other env costs nothing and keeps the driver
# byte-identical to the one the previous cell ran. The DEFAULTS DO NOT MOVE -
# an unset environment is the same ten tries at thirty seconds it has always
# been - so no existing round changes behaviour by this.
QUIET_TRIES = int(os.environ.get("PDRV_QUIET_TRIES", "10"))
QUIET_WAIT = float(os.environ.get("PDRV_QUIET_WAIT", "30"))


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
    return _require_quiet_per_core(where)


def _require_quiet_per_core(where):
    """The per-core arm. See PER_CORE_CEILING_PCT above for the threshold, the
    five things the box-wide ceiling hid, and why this one does not abort.

    CONFIRM BY MINIMUM, AND ONLY WHEN THE FIRST SAMPLE IS SUSPICIOUS. A one
    second window cannot tell a core pinned for ninety seconds from a process
    that lived for one and a half, and at a 25% threshold that difference is
    most of the traffic. Reported by the create-width-additive-kernel-gfni-16sep
    lane from intel-core-ultra-9-386h and reproduced on amd-ryzen-9800x3d 16 Sep 2026: a WATCHING
    session polling a box over ssh spawns a shell outside the round's process
    tree by construction, and on Windows that is about a core-second of module
    autoload. Measured there, same script, one box, ten samples each:

        undisturbed          min 26.6  median 43.8  max  84.4
        under an ssh poll    min 92.2  median 253.1 max 339.1

    The observer is the contaminant. The unix half has the same hazard in a
    milder form - an ssh login, a `ps`, another lane's editor - so the answer
    is the same: take the MINIMUM of three samples, because a transient spike
    is in at most one of them and a resident consumer is in all three.

    THE EXTRA SAMPLES ARE ONLY PAID WHEN THE FIRST IS OVER. This runs before
    EVERY timed leg, so three unconditional one-second windows would add two
    seconds a leg - about 22 minutes on a 672-leg round like the one that
    produced the finding. A quiet box returns on its first sample.

    NO RETRY LOOP, unlike the box-wide arm. Waiting is what that arm does about
    somebody else's ROUND, which ends. The consumers THIS arm is for are
    resident: SignalRgb relaunches at logon, an indexer runs for the length of
    its pass, WindowServer never leaves. Ten thirty second sleeps a leg would
    buy nothing and cost the round hours.

    Returns the reading in % of ONE core so the caller can put it on the leg
    line - a contaminated leg that still ran has to be judgeable afterwards,
    which is the same bargain `Wait-FixtureSettle` strikes on the other half."""
    per = per_core_ceiling()
    total, top = foreign_cpu_window()
    if total < per:
        return total
    for _ in range(2):
        time.sleep(0.7)
        v, vtop = foreign_cpu_window()
        if v < total:
            total, top = v, vtop
        if total < per:
            return total
    who = " ".join("%s(%d)=%.0f%%" % (c, pid, pc) for pc, pid, c in top)
    print("BOX-ONE-CORE-BUSY at=%s foreign_1core=%.0f%% thresh=%.0f%% cores=%d top=[%s]"
          % (where, total, per, cpu_count(), who), flush=True)
    if PER_CORE_ABORTS:
        print("ABORT-ONE-CORE at=%s ts=%s" % (where, utcnow()), flush=True)
        sys.exit(18)
    print("BOX-ONE-CORE-NOTE the leg RUNS; read its foreign_1core and the "
          "reducers' per-ladder median before trusting a number from it",
          flush=True)
    return total


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


# SIGHUP DOES NOT EXIST ON WINDOWS, and naming it in this tuple is what made
# the module unimportable there: the AttributeError fires while the tuple is
# being BUILT, before any of the guarding below can run. `getattr` keeps the
# POSIX set byte-identical and drops the one signal Windows has no concept of.
for _sig in [_s for _s in (getattr(signal, _n, None)
                           for _n in ("SIGTERM", "SIGINT", "SIGHUP")) if _s is not None]:
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
    if IS_WIN:
        return _run_leg_win(exe, argv, cwd, logbase, child_env,
                            foreign_before, stat_before)
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


def _run_leg_win(exe, argv, cwd, logbase, child_env, foreign_before, stat_before):
    """The Windows arm of `run_leg`. Same record, same keys, same units.

    `os.wait4` IS THE WHOLE PROBLEM AND IT DOES NOT EXIST HERE. On POSIX it
    hands back the child's OWN rusage, which is why this harness was written in
    python in the first place (see the module docstring: `/usr/bin/time` writes
    to stderr, so a `2>file` on that command line redirects TIME's stderr and
    not the child's, and about 120 legs of an earlier round banked an empty
    `wall=`). The Windows equivalent is the child's own process handle:
    `GetProcessTimes` for kernel+user CPU and `K32GetProcessMemoryInfo` for the
    peak. Both keep answering AFTER the child has exited, as long as the handle
    is open - the kernel holds the process object for it - and
    `subprocess.Popen` keeps that handle in `_handle` until the object is
    collected, which is what makes this readable at all without re-launching
    anything. Nothing is parsed out of a stream here either.

    THE HANDLE IS READ BEFORE `Popen` CAN BE COLLECTED, deliberately: `proc` is
    live on the stack for the whole function. If either read fails - a handle
    already closed, a ctypes failure, a box that will not answer - the field is
    -1.0 and NEVER 0.0, because a zero asserts a measurement that did not
    happen and a leg line that cannot be told from a real one is the class this
    whole harness exists to refuse.

    TWO STATED LIMITS, both on the LINE rather than in a footnote:

      - `cpu` is the DIRECT child's CPU only, and so is the POSIX arm's
        `ru_utime + ru_stime` from `wait4`. parfast is one process, so the two
        agree; a tool that forks workers would under-report on both platforms
        identically, which is the right kind of wrong. MEASURED 17 Sep 2026 on
        intel-core-ultra-9-386h while porting this: running the stub through a `.cmd`
        wrapper put the real work a generation down and `cpu` read 0.0 on
        eleven legs of sixteen. A `BIN` that is a script and not an executable
        therefore measures the SCRIPT HOST. Real rounds pass `parfast.exe`.
      - `GetProcessTimes` CARRIES THE WINDOWS CLOCK'S ~15.625 ms GRANULARITY,
        so a child that lives less than one tick reads 0.0 and not "too small
        to see". Measured on the same box, same day. A real leg on this ladder
        is seconds - section 8.18's were 9-14 s, which is 600 to 900 ticks - so
        this floor is nowhere near anything a round publishes; it matters only
        to a test that launches something trivial, and
        `harness/nttladder_smoke.py` buys its margin by burning
        200 ms on purpose rather than by asserting around it.
      - `peak_mb` is PeakWorkingSetSize, which is not `ru_maxrss`. See
        `winproc.peak_working_set_bytes` - it is a memory ceiling to read, not
        a figure to put in a table beside a Mac's.

    `steal_pct` comes back `n/a` here, which is CORRECT AND IS THE POINT:
    steal exists only under virtualisation and only Linux exports it, and the
    reason this port was written is that windows-gaming-pc-b and amd-ryzen-9800x3d are BARE METAL. A
    round that reads `n/a` on this box is reading the absence of a hypervisor,
    not a missing counter - and `n/a` rather than 0.0 keeps it from being
    quoted as a measured zero.
    """
    with open(logbase + ".out", "wb") as fo, open(logbase + ".err", "wb") as fe:
        t0 = time.monotonic()
        proc = subprocess.Popen([exe] + argv, cwd=cwd, stdout=fo, stderr=fe,
                                stdin=subprocess.DEVNULL, env=child_env)
        _LIVE_CHILDREN.add(proc)
        try:
            rc = proc.wait()
            times = winproc.process_times(int(proc._handle))
            peak = winproc.peak_working_set_bytes(int(proc._handle))
        finally:
            _LIVE_CHILDREN.discard(proc)
        wall = time.monotonic() - t0
    foreign_after, _ = foreign_cpu()
    return {
        "rc": rc,
        "wall": round(wall, 3),
        "cpu": round(times[1], 3) if times else -1.0,
        "peak_mb": round(peak / (1024.0 * 1024.0), 1) if peak else -1.0,
        "errlen": os.path.getsize(logbase + ".err"),
        "outlen": os.path.getsize(logbase + ".out"),
        "foreign_cpu": round(foreign_before, 1),
        "foreign_after": round(foreign_after, 1),
        "steal_pct": _steal_pct(stat_before, cpu_stat_jiffies()),
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
                # getrandbits(8n).to_bytes(n, "little") IS randbytes in CPython 3.9+,
                # so a 3.8 box (DSM) damages byte-identically to the others.
                f.write(rng.randbytes(n) if hasattr(rng, "randbytes") else rng.getrandbits(n * 8).to_bytes(n, "little"))
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
    # `shutil.disk_usage`, not `os.statvfs`: statvfs does not exist on Windows,
    # and this is the same free-space figure on every platform. `.free` is the
    # unprivileged caller's free space, which is what `f_bavail` meant here.
    free_gb = round(shutil.disk_usage(os.path.expanduser("~")).free / (1024 ** 3), 1)
    if IS_WIN:
        # WMI VIA ctypes IS NOT AVAILABLE AND `powershell` IS NOT WANTED per
        # leg - but this runs ONCE, at round start, so the cost argument that
        # keeps the quiet gate in-process (see `winproc`'s module docstring)
        # does not apply and the accurate answer is worth one process.
        cpu = os.environ.get("PROCESSOR_IDENTIFIER", "?")
        cores = str(os.cpu_count() or "?")
        mem_gb = "?"
        osver = platform.platform()
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "(Get-CimInstance Win32_Processor).Name; "
                 "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; "
                 "(Get-CimInstance Win32_OperatingSystem).Caption"],
                capture_output=True, text=True, timeout=60)
            rows = [r.strip() for r in (out.stdout or "").splitlines() if r.strip()]
            if len(rows) >= 3:
                cpu = rows[0]
                mem_gb = round(int(rows[1]) / (1024 ** 3), 1)
                osver = "%s (%s)" % (rows[2], platform.version())
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    elif sys.platform == "darwin":
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
    # `socket.gethostname()`, not `os.uname().nodename`: `os.uname` is POSIX
    # only. It is the same string on every box in this fleet.
    print("BOX host=%s cpu=%s cores=%s ram_gb=%s os=%s free_gb=%s"
          % (socket.gethostname(), cpu, cores, mem_gb, osver, free_gb), flush=True)


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
        d = os.path.dirname(os.path.abspath(rig)) or os.sep
        # Walk to the nearest existing ancestor. The stopping rule is a FIXED
        # POINT and not the literal "/": `os.path.dirname` of a Windows drive
        # root (`C:\\`) is itself, so a `d != "/"` test never terminates there
        # and this loop would spin forever on the one platform this port is for.
        while not os.path.isdir(d):
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        usage = shutil.disk_usage(d)
        free_gb = usage.free / 1e9
        total_gb = usage.total / 1e9
        # THE SNAPSHOT HALF IS macOS-ONLY AND SAYS SO RATHER THAN READING ZERO.
        # `tmutil` is what makes this function worth calling on an Apple box -
        # every hourly local snapshot PINS the blocks a repair leg's
        # damage-and-restore churn replaced, which is invisible in a LEG line
        # and fatal to a table. Windows and Linux have no equivalent exposure
        # through this path, and `local_snapshots=0` there would assert a
        # measured absence; `n/a` states that nothing was asked.
        nsnap, ex = "n/a", "n/a"
        if sys.platform == "darwin":
            snaps = subprocess.run(["tmutil", "listlocalsnapshots", d],
                                   capture_output=True, text=True)
            nsnap = sum(1 for l in (snaps.stdout or "").splitlines()
                        if "com.apple.TimeMachine" in l)
            excl = subprocess.run(["tmutil", "isexcluded", d],
                                  capture_output=True, text=True)
            ex = "yes" if "[Excluded]" in (excl.stdout or "") else "no"
        print("RIGVOL dir=%s free_gb=%.1f total_gb=%.1f free_pct=%.1f "
              "tm_excluded=%s local_snapshots=%s"
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
