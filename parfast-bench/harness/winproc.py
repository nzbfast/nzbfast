#!/usr/bin/env python3
"""winproc.py - the Windows half of "what else is running on this box", and
the child accounting `os.wait4` gives POSIX for free.

WHY THIS FILE EXISTS. `harness/pdrv.py` is the parfast publication
driver and was POSIX-only: `/proc/stat` steal, `/proc/vmstat` swap,
`fcntl.flock`, `ps -Ao`, `os.wait4`, `os.statvfs`, `signal.SIGHUP`. Both of
this fleet's bare-metal `KernelClass::Avx512Gfni` parts are WINDOWS (windows-gaming-pc-b and
amd-ryzen-9800x3d, AMD Ryzen 7 9800X3D - `.claude/MACHINES.md`, "Windows boxes"), so
until this landed there was no route to a bare-metal GFNI number on this fleet
at all: sections 8.13.2 and 8.18 of
an internal note each hit that wall and each
routed its round to a KVM guest, where 8.18 measured hypervisor steal
displacing a fitted breakpoint by 20%. That is the gap this closes.

WHY NOT SHELL OUT TO `plib.ps1`, WHICH ALREADY HAS ALL OF THIS. Its
`Get-ForeignCpu` / `Require-QuietBox` / `Require-QuietCore` are the hardened
Windows spelling and are reused here - their THRESHOLDS, their window, their
delta arithmetic and their birth rule are reproduced below rather than
re-invented, and where this file departs from them it says so. What is not
reused is the PROCESS: `pdrv.require_quiet_box` runs before EVERY timed leg,
and `Require-QuietCore`'s own docstring measured what an out-of-tree shell
costs on Windows - a watching ssh poll took a box's per-core foreign reading
from a min of 26.6 to a min of 92.2, "about a core-second of module autoload",
and it names the observer as the contaminant. Spawning `powershell -NoProfile`
two or three times a leg would put exactly that contaminant INSIDE the gate
built to detect it, and would do it on the quiet arm whose threshold is 25% of
one core. So the sampler is in-process ctypes and spawns nothing.

WHY Toolhelp32 + GetProcessTimes AND NOT `NtQuerySystemInformation`. One
`NtQuerySystemInformation(SystemProcessInformation)` would hand back every
field in a single call and is what a profiler would use. It is also
undocumented, and reading it means hand-computing struct offsets that Windows
is free to move. `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` (pid,
ppid, image name) followed by `OpenProcess` + `GetProcessTimes` per pid is all
documented, has a stable ABI, and costs about three syscalls per process -
under 300 processes that is a few milliseconds, against the hundreds of
milliseconds .NET's `Get-Process` enumeration costs `plib.ps1` for the same
answer. Cheaper AND documented, so there is no trade to make here.

WHAT IT DOES NOT DO. A process this user cannot open - `System`, the protected
anti-malware services - is SKIPPED, exactly as `Get-ForeignCpu` skips a process
whose CPU counter throws, and for its stated reason: recorded as zero in the
before snapshot it would read as a birth in the after one, which is the defect
that made a quiet box read 267% of a core. A skipped process is therefore
invisible to the foreign-CPU reading, which is the honest limit of both halves
and is not new here.
"""
import os
import time

IS_WIN = os.name == "nt"

# FILETIME is 100 ns units since 1601-01-01; this is the offset to the unix
# epoch in those units.
_FT_EPOCH_DELTA = 116444736000000000
_FT_PER_SEC = 1e7

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = -1
MAX_PATH = 260


def _k32():
    import ctypes
    return ctypes.WinDLL("kernel32", use_last_error=True)


def available():
    """True when this box can be sampled at all. Every caller must have a
    non-Windows path anyway, so a False here is a fact and not an error."""
    if not IS_WIN:
        return False
    try:
        _k32()
    except (ImportError, AttributeError, OSError):
        return False
    return True


def _processentry32():
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * MAX_PATH),
        ]
    return PROCESSENTRY32W


def _proc_list():
    """[(pid, ppid, image name)] for every process Toolhelp will enumerate."""
    import ctypes
    from ctypes import wintypes
    k32 = _k32()
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    entry_t = _processentry32()
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(entry_t)]
    k32.Process32NextW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(entry_t)]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(INVALID_HANDLE_VALUE).value:
        return []
    out = []
    try:
        entry = entry_t()
        entry.dwSize = ctypes.sizeof(entry_t)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            out.append((int(entry.th32ProcessID),
                        int(entry.th32ParentProcessID),
                        str(entry.szExeFile)))
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return out


def process_times(handle):
    """(create_epoch_s, cpu_seconds) for an OPEN process handle, or None.

    Valid after the process has EXITED as long as the handle is still open,
    which is what makes this the `os.wait4` rusage replacement in
    `pdrv.run_leg`: the kernel keeps the process object alive for the handle
    and GetProcessTimes keeps answering.
    """
    import ctypes
    from ctypes import wintypes
    try:
        k32 = _k32()
        k32.GetProcessTimes.restype = wintypes.BOOL
        k32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        creation, exit_, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not k32.GetProcessTimes(ctypes.c_void_p(handle), ctypes.byref(creation),
                                   ctypes.byref(exit_), ctypes.byref(kernel),
                                   ctypes.byref(user)):
            return None
    except (AttributeError, OSError, ValueError):
        return None

    def as_int(ft):
        return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)

    created = (as_int(creation) - _FT_EPOCH_DELTA) / _FT_PER_SEC
    cpu = (as_int(kernel) + as_int(user)) / _FT_PER_SEC
    return created, cpu


def peak_working_set_bytes(handle):
    """PeakWorkingSetSize for an open process handle, or None.

    THIS IS NOT `ru_maxrss` AND MUST NOT BE LABELLED AS ONE WITHOUT SAYING SO.
    `ru_maxrss` is the peak RESIDENT set; PeakWorkingSetSize is the peak
    working set, which on Windows includes shareable pages backed by mapped
    files. For a repair leg - a large private arena plus mapped payload - the
    two answer the same question closely enough to be read as a memory ceiling
    and NOT closely enough to be put in a table beside a Mac's figure. The leg
    record keeps it under the same `peak_mb` key because every reducer on this
    fleet reads that key, and the platform is on the same line.
    """
    import ctypes
    from ctypes import wintypes

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]
    try:
        k32 = _k32()
        # K32GetProcessMemoryInfo lives in kernel32 from Windows 7 on, so this
        # needs no psapi.dll load and no version branch.
        fn = k32.K32GetProcessMemoryInfo
        fn.restype = wintypes.BOOL
        fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        if not fn(ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb):
            return None
        return int(counters.PeakWorkingSetSize)
    except (AttributeError, OSError, ValueError):
        return None


def snapshot():
    """{pid: {"ppid", "name", "cpu", "start"}} for every readable process.

    `cpu` is cumulative CPU seconds and `start` is a unix epoch float. A
    process we cannot OPEN is omitted - see the module docstring for why that
    is the same choice `Get-ForeignCpu` makes and not a shortfall here.
    """
    import ctypes
    from ctypes import wintypes
    k32 = _k32()
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    out = {}
    for pid, ppid, name in _proc_list():
        if pid == 0:
            continue
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            times = process_times(handle)
        finally:
            k32.CloseHandle(ctypes.c_void_p(handle))
        if times is None:
            continue
        start, cpu = times
        out[pid] = {"ppid": ppid, "name": name, "cpu": cpu, "start": start}
    return out


def own_tree(snap, mine=None):
    """Every pid in `snap` that is us or a descendant of us.

    DELIBERATELY NOT `plib.ps1`'s `Resolve-OwnPidSet`, which also walks UP
    from our own pid to adopt an ancestor shell. That is right for a
    PowerShell round, whose `Invoke-Leg` children are launched by the shell
    that also hosts the driver; here the driver IS the python process and its
    children are its own, so walking up would exclude a foreign parent's other
    children from the reading - which is the guard going blind, not being
    tolerant.
    """
    mine = os.getpid() if mine is None else mine
    kids = {}
    for pid, row in snap.items():
        kids.setdefault(row["ppid"], []).append(pid)
    seen, stack = {mine}, [mine]
    while stack:
        cur = stack.pop()
        for kid in kids.get(cur, ()):
            # A recycled pid can name a parent that started AFTER it, which
            # would otherwise let an unrelated process be adopted into our
            # tree and drop out of the foreign reading. Only adopt a child
            # that started at or after its claimed parent.
            if kid in seen:
                continue
            parent_start = snap.get(cur, {}).get("start")
            kid_start = snap[kid].get("start")
            if parent_start is not None and kid_start is not None and kid_start < parent_start:
                continue
            seen.add(kid)
            stack.append(kid)
    return seen


def foreign_delta(before, after, window_s, window_start, cores, mine=None):
    """(total % of ONE core, [(pct, pid, name)]) outside our own process tree.

    THE ARITHMETIC IS `plib.ps1`'s `Measure-ForeignDelta`, PORTED RULE FOR RULE
    rather than re-derived, including the two defects that function's header
    records fixing on 16 Sep 2026 (they made an idle box read 25-544% of a
    core, median 267):

      - a pid absent from `before` is decided by its START TIME, never by its
        absence. Born inside the window -> charged in full, because its whole
        lifetime CPU genuinely was spent in there, and because a neighbouring
        round's freshly spawned `parfast` is precisely the thing this guard
        exists to catch. Born before the window, or start time unreadable ->
        charged ZERO, since we have no before reading and must not invent one;
        the next sample a second later measures it exactly.
      - the window is MEASURED and passed in, never assumed to be the sleep.
        Two enumerations bracket the sleep and each costs real wall time, so
        dividing a 1.4 s measurement by 1.0 s overstates every reading by 1.4x
        forever. Start-to-start, not start-to-end: each process's two readings
        are one enumeration apart.

    Pid reuse is the third case and is handled the same way: same pid,
    different start time, is a DIFFERENT process and is a birth, not a delta.

    THIS DIFFERS FROM THE POSIX ARM IN `pdrv.foreign_cpu_window`, DELIBERATELY.
    That one charges zero to any pid absent from `before`, unconditionally,
    and it is left exactly as it is: it is the sampler every banked unix
    `foreign_1core` reading on this fleet was produced by, and re-pointing it
    at a different rule would silently move a quantity months of logs are
    expressed in. The Windows arm is new, so it gets the better rule from the
    start. A reader comparing the two platforms' readings should know that the
    Windows one can charge a newborn process in full one sample earlier.
    """
    mine = os.getpid() if mine is None else mine
    if window_s <= 0:
        return -1.0, []
    cores = max(int(cores), 1)
    cap = window_s * cores
    ours = own_tree(after, mine) | own_tree(before, mine)
    total, top = 0.0, []
    for pid, row in after.items():
        if pid in ours:
            continue
        prev = before.get(pid)
        delta = None
        if prev is not None and prev.get("start") == row.get("start"):
            delta = row["cpu"] - prev["cpu"]
            if delta <= 0:
                continue
        else:
            start = row.get("start")
            if start is None or start < window_start:
                continue
            delta = min(row["cpu"], cap)
            if delta <= 0:
                continue
        pct = delta / window_s * 100.0
        total += pct
        top.append((pct, pid, row.get("name", "?")))
    top.sort(reverse=True)
    return round(total, 1), top[:4]


def foreign_cpu_window(window=1.0, mine=None):
    """Foreign CPU over a measured window, in % of one core. (total, top)."""
    t0 = time.time()
    before = snapshot()
    mono0 = time.monotonic()
    time.sleep(window)
    after = snapshot()
    span = max(time.monotonic() - mono0, 1e-6)
    return foreign_delta(before, after, span, t0, os.cpu_count() or 1, mine)


def foreign_cpu_lifetime(mine=None):
    """The LIFETIME-average analogue of `ps -o pcpu`, summed over foreign
    processes, in % of one core. (total, top).

    This is what `pdrv.foreign_cpu()` means on unix - Linux's pcpu is
    cpu_time/elapsed exactly, and that is reproduced here - so the box-wide
    ceiling, `waitquiet.py` and every banked `foreign_cpu` field keep their
    definition on this platform too. The tight per-core arm does NOT use it,
    for the reason `pdrv.foreign_cpu_window`'s docstring gives: a lifetime
    average fires on history and misses the present.
    """
    mine = os.getpid() if mine is None else mine
    snap = snapshot()
    ours = own_tree(snap, mine)
    now = time.time()
    total, top = 0.0, []
    for pid, row in snap.items():
        if pid in ours:
            continue
        elapsed = now - row.get("start", now)
        if elapsed <= 0:
            continue
        pct = row["cpu"] / elapsed * 100.0
        if pct < 1.0:
            continue
        total += pct
        top.append((pct, pid, row.get("name", "?")))
    top.sort(reverse=True)
    return total, top[:4]
