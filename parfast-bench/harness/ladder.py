#!/usr/bin/env python3
"""ladder.py - the parfast repair ladder and the single-file round, in one
cross-platform driver (macOS, Linux, Windows with a real Python).

Reproduces the PROTOCOL of website/parfast-bench/harness/lad2.ps1 and the Mac
rounds behind an internal note so the log feeds the extractor's
ladder() unchanged: ten 1 GiB members each from its own seeded stream, one
recovery set created by parfast (750 KiB slices, 15% parity), every tool
repairing the SAME set at every rung from the SAME seeded scattered-slice
damage, a SHA-256 gate over every member before and after each leg, the
recovery set warmed before each leg, an untimed rep=0 warm-up, and one LEG /
VERIFY / CREATE line per timed leg in the loader's field names.

What is deliberately NOT byte-identical to the PowerShell rounds: the damage
picks come from Python's Random rather than .NET's, so a rung's picks differ
from the Windows rounds' picks (they are identical across tools and reps
within THIS round, which is the property the ladder rests on). cpu and peak
memory ARE recorded on every platform - POSIX off `getrusage(RUSAGE_CHILDREN)`,
Windows off the child's own process handle (`Leg.run` and `_run_win` below
carry what each one does and does not measure) - but the page still reads
wall, and a Windows `peak` is a working set rather than `ru_maxrss`, so the two
platforms' peaks are not one column.

  ladder.py --log applad2.log --round applad2 --rig ~/lad --payload ~/lad/pay \
            --tool parfast=/path/parfast --tool parfast-beta2=/path/parfast-beta2 \
            --tool par2turbo=/path/par2turbo [--single]
"""
import argparse, hashlib, os, platform, random, shutil, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import riglock_state   # noqa: E402 - after the sys.path line it needs
import winproc         # noqa: E402 - same; a no-op off Windows, where nothing
                       # in it is called

GIB = 1 << 30
IS_WIN = os.name == "nt"

def now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class RigLock:
    """The per-box lock at ~/.parfast-rig.lock, cross-platform.

    POSIX gets pdrv.RigLock's shape verbatim (this file cannot import that
    module directly - pdrv.py imports fcntl unconditionally, which does not
    exist on Windows, and this driver has to run there too): flock() locks
    the INODE our fd points at, not the PATH, so a taker must re-check the
    path still resolves to the inode it just locked before trusting it
    (retrying, bounded, rather than proceeding on a lock nothing else can
    see), and a releaser must unlink the path only while STILL holding the
    flock and only if the path is still ours, THEN unlock. Getting that
    ordering backwards - unlock first, unlink after with no check - is what
    let one round delete another's live lock file on amd-epyc-vm on
    15 Sep 2026 (an internal note).

    Windows does not share the hazard: `open(path, "x")` is CreateFile with
    CREATE_NEW, and Python's default share mode does not include
    FILE_SHARE_DELETE, so the file cannot be deleted by anyone else while our
    handle is open and cannot be recreated by anyone else until it is gone -
    "locked" and "exists" are the same fact, unlike POSIX where flock and the
    directory entry are decoupled. So Windows needs no inode re-check on
    either side; it gets the exclusive-create idiom plib.ps1's
    Take-RigLock/Release-RigLock already use for the same lock file.

    That equivalence has one edge, and it is the one that cost apple-m3-ultra eight
    hours on 16 Sep 2026: it holds only while the holder's handle is OPEN. A
    holder that dies without releasing takes its handle with it and leaves the
    directory entry, after which CREATE_NEW refuses every round forever and the
    file names nobody. So BOTH arms now put the verdict to riglock_state, which
    reads liveness off the holder's own pid and never off the file's age - see
    that module's docstring for why an age bound is not available here.
    """
    def __init__(self, round_name, lock_path=None):
        self.round = round_name
        # `lock_path` overrides the real per-box path - for
        # rig_lock_selftest.py only, so a test can race two holders over a
        # temp file instead of the live ~/.parfast-rig.lock. Every real
        # caller leaves it unset.
        self.path = lock_path or os.path.join(os.path.expanduser("~"), ".parfast-rig.lock")
        self.fh = None

    def take(self):
        # Whether the file predates us, so an ordinary first take on a free box
        # is not mistaken for a zero-byte orphan (the POSIX arm below opens
        # with "a", which creates).
        pre_existing = os.path.exists(self.path)
        if IS_WIN:
            try:
                self.fh = open(self.path, "x")
            except FileExistsError:
                # WINDOWS HAS NO ORPHAN RECOVERY FOR FREE, and this is where it
                # is bought. The docstring's "exists and locked are the same
                # fact" holds only while the holder's HANDLE is open: once the
                # holder dies without releasing, the handle goes but the
                # directory entry stays, and CREATE_NEW then refuses every
                # round forever. That is the apple-m3-ultra orphan of 16 Sep 2026 in
                # its Windows spelling. Ask who it names; if that pid is alive
                # on this box the refusal above stands at any age, and if it is
                # dead or unnamed the file is provably nobody's - clear it,
                # announce it, and try exactly ONCE more (a second collision is
                # a live taker racing us, which is a refusal, not an orphan).
                state, who = riglock_state.lock_state(self.path)
                if state == "held":
                    raise SystemExit(f"rig lock held: {self.path} - held by: {who}")
                riglock_state.announce_orphan(
                    self.path, who, f"cleared by round={self.round} pid={os.getpid()}")
                try:
                    os.remove(self.path)
                except OSError as exc:
                    raise SystemExit(f"rig lock held: {self.path} - orphan ({who}) "
                                     f"could not be removed: {exc}")
                try:
                    self.fh = open(self.path, "x")
                except FileExistsError:
                    raise SystemExit(f"rig lock held: {self.path} - another round took it "
                                     f"as we cleared an orphan")
        else:
            # THIS CLASS DOES NOT QUEUE, and that is what makes it immune to
            # the handover lottery riglock.take() carried until 17 Sep 2026
            # (an internal note).
            # That defect is a WAITER's: closing the fd and reopening on a
            # timer drops the waiter out of the kernel's flock wait queue, so
            # its place is discarded every cycle. Here the flock is LOCK_NB
            # and a refusal exits immediately - the loop below bounds INODE
            # CHURN, not waiting, and never blocks - so there is no place to
            # lose. Deliberately left as a second implementation rather than
            # routed through riglock.take(): take() is fd-based and POSIX-
            # only (SIGALRM), this class has a Windows arm above it, and
            # converting it would also change its contract from "refuse" to
            # "queue", which every caller of ladder.py is written against.
            # If it is ever given a wait, it inherits the whole problem and
            # must stay blocked rather than re-check on a short timer.
            import fcntl
            for _attempt in range(5):
                fh = open(self.path, "a")
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    fh.close()
                    raise SystemExit(f"rig lock held: {self.path} - another round owns this box")
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
                raise SystemExit(f"rig lock unstable: {self.path} (inode churn, gave up after 5 tries)")
            # An flock we won says no FLOCKING holder is up; it says nothing
            # about a shell round that took this same file with an exclusive
            # create and has no flock to lose. One of those was clobbered on
            # 16 Sep 2026 by a driver that had, correctly, won the flock. So
            # the identity line decides, exactly as it does on the Windows arm.
            state, who = riglock_state.lock_state(self.path, probe_flock=False)
            if state == "held":
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
                self.fh.close()
                self.fh = None
                raise SystemExit(f"rig lock held: {self.path} - held by: {who}")
            if state == "orphan" and pre_existing:
                riglock_state.announce_orphan(
                    self.path, who, f"cleared by round={self.round} pid={os.getpid()}")
        self.fh.seek(0)
        self.fh.truncate(0)
        self.fh.write(f"pid={os.getpid()} round={self.round} started={now()}\n")
        self.fh.flush()

    def release(self):
        if not self.fh:
            return
        if IS_WIN:
            self.fh.close()
            try:
                os.remove(self.path)
            except OSError:
                pass
        else:
            import fcntl
            try:
                if os.stat(self.path).st_ino == os.fstat(self.fh.fileno()).st_ino:
                    os.unlink(self.path)
            except OSError:
                pass
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()
        self.fh = None
        print(f"RIG-LOCK-RELEASED {self.path}", flush=True)

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(8 << 20)
            if not b: break
            h.update(b)
    return h.hexdigest()

def warm(paths):
    for p in paths:
        try:
            with open(p, "rb") as f:
                while f.read(64 << 20): pass
        except FileNotFoundError: pass

def load_now():
    if IS_WIN:
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-c", "(Get-CimInstance Win32_Processor).LoadPercentage"], capture_output=True, text=True, timeout=30)
            return r.stdout.strip() or "na"
        except Exception: return "na"
    try: return "%.2f" % os.getloadavg()[0]
    except Exception: return "na"

def quiet(max_load):
    if max_load <= 0: return 0
    waited = 0
    while waited < 900:
        try: cur = float(load_now())
        except ValueError: return waited
        if cur <= max_load: return waited
        time.sleep(5); waited += 5
    return waited

def harness_lines(paths):
    """The round-start harness stamp, `plib.ps1` / `pdrv.py` format exactly:
    one `HARNESS <basename> sha256=... bytes=...` per file the round sources,
    then `HARNESS-RIG <basename>:<sha16>+...` sorted by basename.

    COMPOSED HERE RATHER THAN CALLED FROM `pdrv.harness_facts`, and that is
    the whole reason this exists: this driver tees its log through `say`,
    writing the banked file AND stdout, where `pdrv.harness_facts` uses a bare
    `print` - so calling it would put the stamp on stdout and leave the BANKED
    log unstamped, which is the exact defect being fixed
    (an internal note). Returns the lines for
    the caller to `say`; it prints nothing itself.

    An unreadable file is stamped `unreadable` rather than left off, for
    pdrv.rig_stamp's reason: an absent token is indistinguishable from a
    harness older than this block, which never had one.
    """
    out, parts = [], []
    for p in sorted((os.path.abspath(q) for q in paths), key=os.path.basename):
        nm = os.path.basename(p)
        try:
            sha, n = sha256_file(p), os.path.getsize(p)
        except OSError:
            out.append(f"HARNESS {nm} sha256=unreadable bytes=0")
            parts.append(f"{nm}:unreadable")
            continue
        out.append(f"HARNESS {nm} sha256={sha} bytes={n}")
        parts.append(f"{nm}:{sha[:16]}")
    out.append("HARNESS-RIG " + ("+".join(parts) if parts else "unknown"))
    return out


def box_line():
    host = socket.gethostname()
    cpu = platform.processor() or platform.machine()
    try:
        if sys.platform == "darwin":
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
            ram = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout) / GIB
            osn = "macOS " + platform.mac_ver()[0]
        elif IS_WIN:
            q = subprocess.run(["powershell", "-NoProfile", "-c", "(Get-CimInstance Win32_Processor).Name; (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; (Get-CimInstance Win32_OperatingSystem).Caption"], capture_output=True, text=True).stdout.split("\n")
            cpu = q[0].strip(); ram = int(q[1]) / GIB; osn = q[2].strip()
        else:
            cpu = [l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")][0]
            ram = [int(l.split()[1]) for l in open("/proc/meminfo") if l.startswith("MemTotal")][0] / (1 << 20)
            osn = platform.platform()
    except Exception:
        ram = 0; osn = platform.platform()
    free = shutil.disk_usage(os.getcwd()).free / GIB
    return f"BOX host={host} cpu={cpu} cores={os.cpu_count()} ram_gb={ram:.1f} os={osn} free_gb={free:.1f}"

def bin_line(name, path):
    ver = ""
    for flag in ("--version", "-V"):
        try:
            r = subprocess.run([path, flag], capture_output=True, text=True, timeout=20)
            ver = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else ""
            if ver: break
        except Exception: continue
    return f"BIN {name} sha256={sha256_file(path)} bytes={os.path.getsize(path)} version={ver}"

class _WinRun:
    """What `subprocess.run` hands back, plus the child accounting that POSIX
    gets free from `wait4`'s rusage. Only the fields `Leg.run` reads."""
    __slots__ = ("returncode", "stdout", "stderr", "cpu_s", "peak_bytes")


def _run_win(exe, argv, cwd, env):
    """`subprocess.run(capture_output=True)` on Windows, WITH the child's own
    CPU and peak memory read off its process handle.

    `Popen` RATHER THAN `run` FOR ONE REASON: the handle. `resource` does not
    exist on Windows and neither does `os.wait4`, so the child's own accounting
    has to come from the process object the kernel keeps alive for an open
    handle - `GetProcessTimes` for kernel+user CPU, `K32GetProcessMemoryInfo`
    for the peak - and `subprocess.run` closes its Popen before returning.
    Both calls keep answering AFTER the child has exited as long as the handle
    is open, which is why this can be read here and not at launch. `proc` is
    live on the stack across both reads, deliberately.

    `harness/pdrv.py`'s `_run_leg_win` is the same mechanism for the
    publication driver and landed first (17 Sep 2026, `a4774eb01`); this is
    that shape, not a second derivation of it. Its docstring carries the
    measurements at length. In brief, the three things that bite:

      - `GetProcessTimes` covers the DIRECT CHILD ONLY, exactly as the POSIX
        arm's `wait4` rusage does. parfast is one process so the two agree; a
        `--tool` pointed at a `.cmd` or `.bat` wrapper measures the SCRIPT
        HOST instead and reads ~0.0 (measured on intel-core-ultra-9-386h, eleven legs of
        sixteen). Real rounds pass `parfast.exe`.
      - it carries the Windows clock's ~15.625 ms granularity, so a child that
        lives less than one tick reads 0.0 rather than "too small to see". A
        ladder leg is seconds, so this floor only reaches a test that launches
        something trivial - `ladder_win_accounting_selftest.py` beside this
        burns measurable CPU on purpose rather than asserting around it.
      - `peak` is PeakWorkingSetSize, which is NOT `ru_maxrss`. The working
        set includes shareable pages backed by mapped files; `ru_maxrss` is
        peak resident. Close enough to read as a memory ceiling, NOT close
        enough to sit in a table beside a Mac's figure - see
        `winproc.peak_working_set_bytes`. It keeps the same `peak` key because
        every reducer reads that key, and the BOX line names the platform.

    A read that fails leaves the field at -1.0 and NEVER 0.0: a zero asserts a
    measurement that did not happen, and a leg line that cannot be told from a
    real one is the class this harness exists to refuse. -1.0 is also exactly
    what this arm recorded before today, so a reducer that already tolerates it
    is unaffected.

    MEASURED ON intel-core-ultra-9-386h, 17 Sep 2026, python 3.12.10, against a child that
    burns 2.0 s of CPU and touches a 256 MiB allocation:
    `{'wall': 2.072, 'cpu': 2.0625, 'peak': 265.7, 'rc': 0, 'errlen': 6}`.
    Note `cpu` is 132 clock ticks exactly - that is the 15.625 ms granularity
    above, visible even on a two-second leg, and it is a floor on resolution
    and not on accuracy.
    """
    proc = subprocess.Popen([exe] + argv, cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    times = winproc.process_times(int(proc._handle))
    peak = winproc.peak_working_set_bytes(int(proc._handle))
    r = _WinRun()
    r.returncode = proc.returncode
    r.stdout = out
    r.stderr = err
    r.cpu_s = times[1] if times else None
    r.peak_bytes = peak
    return r


class Leg:
    def __init__(self):
        self.ru0 = None
    def run(self, exe, argv, cwd, env=None):
        """One timed child, with wall, CPU and peak memory.

        THE POSIX ARM IS UNCHANGED AND MUST STAY THAT WAY. The banked Mac and
        Linux rounds behind an internal note and the published page are this
        driver's provenance, so the Windows accounting added 17 Sep 2026 is a
        NEW BRANCH ONLY - same keys, same units (`peak` is MiB on every
        platform), same `-1.0` sentinel when a read fails. What the header
        still says about the damage picks differing from the PowerShell rounds
        is untouched; what it said about cpu and peak being unavailable here is
        not true any more, and it no longer says it.
        """
        e = dict(os.environ); e.update(env or {})
        if not IS_WIN:
            import resource
            r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
        t0 = time.perf_counter()
        try:
            p = _run_win(exe, argv, cwd, e) if IS_WIN else subprocess.run([exe] + argv, cwd=cwd, env=e, capture_output=True)
        except OSError as ex:
            print(f"LAUNCH-FAIL exe={exe} exe_isfile={os.path.isfile(exe)} cwd={cwd} cwd_isdir={os.path.isdir(cwd)} parent_entries={sorted(os.listdir(os.path.dirname(cwd)))[:12]} err={ex}", flush=True)
            time.sleep(2)
            p = _run_win(exe, argv, cwd, e) if IS_WIN else subprocess.run([exe] + argv, cwd=cwd, env=e, capture_output=True)
        wall = time.perf_counter() - t0
        cpu = -1.0; peak = -1.0
        if not IS_WIN:
            r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu = (r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime)
            peak = r1.ru_maxrss / (1 << 20) if sys.platform == "darwin" else r1.ru_maxrss / 1024.0
        else:
            if p.cpu_s is not None:
                cpu = p.cpu_s
            if p.peak_bytes:
                peak = p.peak_bytes / (1 << 20)
        return dict(wall=wall, cpu=cpu, peak=peak, rc=p.returncode, errlen=len(p.stderr))

def gen_payload(pay, members, size):
    os.makedirs(pay, exist_ok=True)
    for i in range(members):
        p = os.path.join(pay, f"p{i:02d}.bin")
        if os.path.exists(p) and os.path.getsize(p) == size: continue
        rng = random.Random(20260913 * 1000 + i)
        with open(p, "wb") as f:
            left = size
            while left > 0:
                n = min(64 << 20, left); f.write(rng.randbytes(n)); left -= n

def gate(work, members, gold):
    with ThreadPoolExecutor(max_workers=min(10, len(members))) as ex:
        res = list(ex.map(lambda nm: (nm, sha256_file(os.path.join(work, nm))), members))
    good = [nm for nm, h in res if gold[nm] == h]
    bad = [nm for nm, h in res if gold[nm] != h]
    return len(good), bad

def damage_picks(work, members, slice_, m, dseed):
    counts = []; lens = []
    for nm in members:
        fl = os.path.getsize(os.path.join(work, nm)); lens.append(fl); counts.append(-(-fl // slice_))
    total = sum(counts)
    if m > total: raise SystemExit(f"damage {m} exceeds {total} slices")
    order = list(range(total)); random.Random(dseed).shuffle(order)
    by = {}
    for g in order[:m]:
        mi = 0
        while g >= counts[mi]: g -= counts[mi]; mi += 1
        by.setdefault(mi, []).append(g)
    return by, lens

def write_damage(work, members, slice_, by, lens, dseed):
    frng = random.Random(dseed + 1); written = 0
    for mi in sorted(by):
        with open(os.path.join(work, members[mi]), "r+b") as f:
            for si in sorted(by[mi]):
                off = si * slice_; n = min(slice_, lens[mi] - off)
                f.seek(off); f.write(frng.randbytes(slice_)[:n]); written += 1
    return written

def restore_slices(work, pristine, members, slice_, by, lens):
    for mi in sorted(by):
        with open(os.path.join(pristine, members[mi]), "rb") as src, open(os.path.join(work, members[mi]), "r+b") as dst:
            for si in sorted(by[mi]):
                off = si * slice_; n = min(slice_, lens[mi] - off)
                src.seek(off); dst.seek(off); dst.write(src.read(n))

def remove_strays(work, wanted):
    n = 0
    for f in os.listdir(work):
        if f not in wanted:
            os.remove(os.path.join(work, f)); n += 1
    return n

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True); ap.add_argument("--round", required=True)
    ap.add_argument("--rig", required=True); ap.add_argument("--payload", required=True)
    ap.add_argument("--tool", action="append", required=True, help="name=path; names parfast* take the par2cmdline dialect, par2j64 its own, parpar create-only")
    ap.add_argument("--members", type=int, default=10); ap.add_argument("--member-bytes", type=int, default=GIB)
    ap.add_argument("--slice", type=int, default=768000); ap.add_argument("--rblk", type=int, default=2098)
    ap.add_argument("--rungs", default="1,16,64,256,512,640,704,768,896,1024,1152,1280,1408,1600,1792,2048,2098")
    ap.add_argument("--reps", type=int, default=3); ap.add_argument("--threads", type=int, default=os.cpu_count())
    ap.add_argument("--file-threads", type=int, default=16); ap.add_argument("--max-load", type=float, default=0.0)
    ap.add_argument("--single", action="store_true", help="one member, the single-file round: --members 1 --member-bytes 8858370048 --slice 4429188 --rblk 100 --rungs 1,50,100 and every tool's create timed")
    ap.add_argument("--warmup-rung", type=int, default=64)
    ap.add_argument("--create-sweep", action="store_true", help="the create sweep instead of the ladder: every tool creates a set for each (size, redundancy) - CC lines in the page's format")
    ap.add_argument("--sizes", default="1,4,10,20", help="create sweep: set sizes in GiB, as that many 1 GiB members (1 = the single-member shape)")
    ap.add_argument("--reds", default="10,20", help="create sweep: redundancy percentages")
    a = ap.parse_args()
    if a.create_sweep:
        return create_sweep(a)
    if a.single:
        a.members, a.member_bytes, a.slice, a.rblk = 1, 8858370048, 4429188, 100
        if a.rungs == ap.get_default("rungs"): a.rungs = "1,50,100"
    rungs = [int(x) for x in a.rungs.split(",")]
    tools = dict(t.split("=", 1) for t in a.tool)
    rig_lock = RigLock(a.round)
    rig_lock.take()
    lock = rig_lock.path
    out = open(a.log, "a")
    def say(s): out.write(s + "\n"); out.flush(); print(s, flush=True)
    try:
        say(f"RIG-LOCK-TAKEN {lock} pid={os.getpid()}")
        say(f"LAD-START {now()}")
        # The HARNESS's own provenance, so a banked round can be traced to
        # the harness revision that wrote it. riglock_state.py and winproc.py
        # are named because this driver imports them, the way plib.ps1 hashes
        # both itself and its caller.
        for _l in harness_lines([__file__, riglock_state.__file__,
                                 winproc.__file__]): say(_l)
        say(box_line())
        for nm, p in tools.items(): say(bin_line(nm, p))
        src_blocks = a.members * (-(-a.member_bytes // a.slice))
        say(f"PROTOCOL slice={a.slice} recovery_blocks={a.rblk} source_blocks={src_blocks} redundancy_pct={100.0*a.rblk/src_blocks:.3f} damage=scattered-seeded-slice-overwrite reps={a.reps} gate=sha256-all-members prewarm=recovery-set-read driver=ladder.py")
        T, F = a.threads, a.file_threads
        def dialect(nm, cmd, extra=""):
            if nm == "par2j64": return {"r": "r f.par2", "v": "v f.par2"}[cmd]
            return f"{cmd} -q -t{T} -T{F} f.par2"
        repair_tools = [t for t in tools if t != "parpar"]
        say("ARGV " + " ".join(f"{t}='{dialect(t,'r')}'" for t in repair_tools))
        say("VARGV " + " ".join(f"{t}='{dialect(t,'v')}'" for t in repair_tools))
        pristine = os.path.join(a.rig, "pristine"); work = os.path.join(a.rig, "work")
        shutil.rmtree(a.rig, ignore_errors=True); os.makedirs(pristine); os.makedirs(work)
        gen_payload(a.payload, a.members, a.member_bytes)
        members = sorted(f for f in os.listdir(a.payload) if f.endswith(".bin"))[:a.members]
        for nm in members: shutil.copy2(os.path.join(a.payload, nm), os.path.join(pristine, nm))
        gold = {nm: sha256_file(os.path.join(pristine, nm)) for nm in members}
        say(f"FIXTURE members={len(members)} distinct_member_sha={len(set(gold.values()))}/{len(members)} bytes={sum(os.path.getsize(os.path.join(pristine, nm)) for nm in members)}")
        for nm in members: say(f"GOLD {nm} {gold[nm]}")
        leg = Leg()
        # creates: parfast's set is THE set every tool repairs; with --single every tool's own create is timed too
        create_tools = ["parfast"] + ([t for t in tools if t != "parfast"] if a.single else [])
        for ct in create_tools:
            cdir = pristine if ct == "parfast" else os.path.join(a.rig, "create-" + ct)
            if ct != "parfast":
                os.makedirs(cdir, exist_ok=True)
                for nm in members:
                    try: os.link(os.path.join(pristine, nm), os.path.join(cdir, nm))
                    except OSError: shutil.copy2(os.path.join(pristine, nm), os.path.join(cdir, nm))
            warm([os.path.join(cdir, nm) for nm in members]); quiet(a.max_load)
            if ct == "parpar":
                argv = [f"-s{a.slice}b", f"-r{a.rblk}", "-q", "-t", str(T), "-o", "f.par2"] + members
            elif ct == "par2j64":
                argv = ["c", f"/ss{a.slice}", f"/rn{a.rblk}", "f.par2"] + members
            else:
                argv = ["c", "-q", f"-t{T}", f"-T{F}", f"-s{a.slice}", f"-c{a.rblk}", "f.par2"] + members
            r = leg.run(tools[ct], argv, cdir)
            pf = [f for f in os.listdir(cdir) if f.endswith(".par2")]
            say(f"CREATE round={a.round} tool={ct} argv='{' '.join(argv[:-len(members)])} ...' rc={r['rc']} wall={r['wall']:.3f} cpu={r['cpu']:.3f} peak_mb={r['peak']:.1f} par2files={len(pf)} par2bytes={sum(os.path.getsize(os.path.join(cdir, f)) for f in pf)} errlen={r['errlen']} ts={now()}")
            if ct != "parfast": shutil.rmtree(cdir, ignore_errors=True)
        parfiles = sorted(f for f in os.listdir(pristine) if f.endswith(".par2"))
        if not parfiles: raise SystemExit("parfast create left no .par2")
        for f in members + parfiles: shutil.copy2(os.path.join(pristine, f), os.path.join(work, f))
        wanted = set(members + parfiles)
        def run_rung(tool, rung, rep, dseed):
            warm([os.path.join(work, f) for f in parfiles])
            by, lens = damage_picks(work, members, a.slice, rung, dseed)
            wrote = write_damage(work, members, a.slice, by, lens, dseed)
            pre_good, _ = gate(work, members, gold)
            waited = quiet(a.max_load); l0 = load_now()
            argv = dialect(tool, "r").split()
            r = leg.run(tools[tool], argv, work)
            l1 = load_now()
            post_good, _ = gate(work, members, gold)
            strays = remove_strays(work, wanted)
            say(f"LEG round={a.round} rep={rep} m={rung} tool={tool} argv='{' '.join(argv)}' wall={r['wall']:.3f} cpu={r['cpu']:.3f} cpu_over_wall={r['cpu']/max(r['wall'],0.001):.2f} peak_mb={r['peak']:.1f} rc={r['rc']} restored={post_good}/{len(members)} damaged_members={len(members)-pre_good} touched_members={len(by)} blocks_written={wrote} strays={strays} seed={dseed} foreign_cpu={l0} foreign_after={l1} waited={waited}s errlen={r['errlen']} ts={now()}")
            restore_slices(work, pristine, members, a.slice, by, lens)
            g, bad = gate(work, members, gold)
            if bad:
                for nm in bad: shutil.copy2(os.path.join(pristine, nm), os.path.join(work, nm))
                g2, bad2 = gate(work, members, gold)
                say(f"RESET rep={rep} m={rung} tool={tool} slice_restore_left={len(bad)} after_full_copy={g2}/{len(members)}")
                if bad2: raise SystemExit("work dir unrecoverable")
            for f in parfiles: shutil.copy2(os.path.join(pristine, f), os.path.join(work, f))
        # rep 0: the untimed warm-up at one rung, logged like any other and filtered by the loader
        for tool in repair_tools: run_rung(tool, a.warmup_rung if a.warmup_rung in rungs else rungs[0], 0, 20260913)
        for rep in range(1, a.reps + 1):
            # THE VERIFY BLOCK ALTERNATES TOO, and until 17 Sep 2026 it did not:
            # the repair block below has alternated by rep since it was written,
            # and this loop ran `repair_tools` in declaration order every rep, so
            # the first tool paid whatever the top of a rep costs on every single
            # one. That is the defect that fabricated a +4.29% cpu delta in the
            # GH #88 create-meter round (an internal note-
            # 2026-09-17.md sections 6-8); the census that found this instance is
            # an internal note, which ranks it harmless
            # HERE - verify deltas on this fixture are 1.7 s against 4.3 s - and
            # fixes it anyway, because "the effect is big enough to survive it"
            # is a property of today's fixture, not of the driver.
            #
            # It is the repair block's `reversed`, deliberately, so the two
            # blocks cannot drift apart. Note what that buys and what it does
            # not: reversing THREE tools balances each one's mean position but
            # leaves the middle tool in the middle forever, so it is weaker than
            # the one-step rotation `jcross.py` moved to on 12 Sep 2026 after a
            # reversal-of-three reported +42.75% for an arm that could not
            # engage. Moving both blocks to a rotation is the right next change
            # and is NOT made here, because it alters a published driver's
            # protocol for a defect nothing has measured on this fixture.
            for tool in (repair_tools if rep % 2 else list(reversed(repair_tools))):
                warm([os.path.join(work, f) for f in parfiles]); waited = quiet(a.max_load); l0 = load_now()
                argv = dialect(tool, "v").split()
                r = leg.run(tools[tool], argv, work); l1 = load_now()
                g, _ = gate(work, members, gold)
                say(f"VERIFY round={a.round} rep={rep} tool={tool} argv='{' '.join(argv)}' wall={r['wall']:.3f} cpu={r['cpu']:.3f} cpu_over_wall={r['cpu']/max(r['wall'],0.001):.2f} peak_mb={r['peak']:.1f} rc={r['rc']} intact={g}/{len(members)} foreign_cpu={l0} foreign_after={l1} waited={waited}s errlen={r['errlen']} ts={now()}")
                remove_strays(work, wanted)
            for rung in rungs:
                dseed = 20260910 + rung * 7 + rep
                order = repair_tools if rep % 2 else list(reversed(repair_tools))
                for tool in order: run_rung(tool, rung, rep, dseed)
        say(f"LAD-END {now()}")
    finally:
        rig_lock.release()
        out.close()

def create_sweep(a):
    sizes = [int(x) for x in a.sizes.split(",")]; reds = [int(x) for x in a.reds.split(",")]
    tools = dict(t.split("=", 1) for t in a.tool)
    rig_lock = RigLock(a.round)
    rig_lock.take()
    lock = rig_lock.path
    out = open(a.log, "a")
    def say(s): out.write(s + "\n"); out.flush(); print(s, flush=True)
    try:
        say(f"RIG-LOCK-TAKEN {lock} pid={os.getpid()}")
        say(f"CSWP-START {now()}")
        say(box_line())
        for nm, p in tools.items(): say(bin_line(nm, p))
        T, F = a.threads, a.file_threads
        say(f"PROTOCOL sizes_gib={sizes} redundancy_pct={reds} threads={T} file_threads={F} base_slice={a.slice} slice_cap=32768 reps={a.reps} members=1GiB-each driver=ladder.py")
        gen_payload(a.payload, max(sizes), GIB)
        members_all = sorted(f for f in os.listdir(a.payload) if f.endswith(".bin"))
        say(f"PAYLOAD-READY members={len(members_all)} bytes={sum(os.path.getsize(os.path.join(a.payload, m)) for m in members_all)}")
        leg = Leg()
        for size in sizes:
            members = members_all[:size]
            blocks_per = -(-GIB // a.slice); blocks = blocks_per * size
            bs = a.slice
            while blocks > 32768:
                bs *= 2; blocks = size * (-(-GIB // bs))
            for red in reds:
                rblk = max(1, round(blocks * red / 100))
                for rep in range(1, a.reps + 1):
                    order = list(tools) if rep % 2 else list(reversed(tools))
                    for tool in order:
                        cdir = os.path.join(a.rig, f"c-{size}-{red}-{tool}")
                        shutil.rmtree(cdir, ignore_errors=True); os.makedirs(cdir)
                        for nm in members:
                            try: os.link(os.path.join(a.payload, nm), os.path.join(cdir, nm))
                            except OSError: shutil.copy2(os.path.join(a.payload, nm), os.path.join(cdir, nm))
                        warm([os.path.join(cdir, nm) for nm in members]); waited = quiet(a.max_load); l0 = load_now()
                        if tool == "parpar":
                            argv = [f"-s{bs}b", f"-r{rblk}", "-q", "-t", str(T), "-o", "f.par2"] + members
                        elif tool == "par2j64":
                            argv = ["c", f"/ss{bs}", f"/rn{rblk}", "f.par2"] + members
                        else:
                            argv = ["c", "-q", f"-t{T}", f"-T{F}", f"-s{bs}", f"-c{rblk}", "f.par2"] + members
                        r = leg.run(tools[tool], argv, cdir); l1 = load_now()
                        pf = [f for f in os.listdir(cdir) if f.endswith(".par2")]
                        rec = sum(os.path.getsize(os.path.join(cdir, f)) for f in pf)
                        say(f"CC size={size} red={red} bs={bs} blocks={blocks} arm={tool} rep={rep} wall={r['wall']:.3f} cpu={r['cpu']:.3f} cpu_over_wall={r['cpu']/max(r['wall'],0.001):.2f} peak_mb={r['peak']:.1f} recovery_mb={rec//(1<<20)} files={len(pf)} rc={r['rc']} foreign_cpu={l0} foreign_after={l1} waited={waited}s errlen={r['errlen']} ts={now()}")
                        shutil.rmtree(cdir, ignore_errors=True)
        say(f"CSWP-END {now()}")
    finally:
        rig_lock.release()
        out.close()

if __name__ == "__main__":
    main()
