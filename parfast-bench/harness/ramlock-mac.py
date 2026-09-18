#!/usr/bin/env python3
"""ramlock-mac.py - pin physical memory on a Mac so a big box behaves like a
smaller one for the FILE CACHE (TODO 345 D). The macOS twin of ramlock.ps1.

    harness/ramlock-mac.py --target-gb 20 --ready <file> \
        --stop <file> --parent-pid <pid> [--wire-secs 240] \
        [--max-compress-gb 4] [--max-secs 3600]

Why wiring and not just allocating: a process that only TOUCHES anonymous
memory is compressed or swapped when the file cache wants room back, so the
cache does not shrink. A WIRED page cannot be reclaimed at all, so the
kernel has to evict file cache to replenish the free pool. This process
mmaps anonymous memory in 1 GiB regions and mlock()s each one, until the
available-memory reading (free non-speculative + file-backed + purgeable
pages, the same sum `mem::available_ram()` ships) sits at the target.

No system setting is changed: an unprivileged mlock is bounded by
`vm.user_wire_limit` (480 GiB on the 512 GiB M3 Ultra, with `ulimit -l`
unlimited), and every wired page is returned the moment this process exits.

THE FIRST VERSION OF THIS SCRIPT STARVED A SHARED MAC FOR FIFTEEN MINUTES
(15 Sep 2026, round macram1). Its wiring loop checked nothing until the
target was reached - no deadline, no parent check, no pressure stop past
swapouts - and the target was never reached: the kernel fed the last
hundreds of GiB by compressing other programs' memory (26 GB into the
compressor) rather than evicting file cache, each mlock slowed to a crawl,
the round gave up waiting, and this process was orphaned holding 386 GB
wired with 123 MB free until it was killed by pid. So now, on EVERY wiring
step, it checks the stop file, its parent and a wiring deadline, and it
STOPS WIRING the moment the compressor grows by --max-compress-gb since it
started: compression means the pin is being paid for out of other
programs' memory, not out of the file cache, which is both the harm and
the point past which the pin no longer models a smaller machine. A stop
is reported (`capped=`) in the ready file and the round decides; a stop
file or a vanished parent ends the process at once. Every step is traced
on stderr.
"""
import argparse
import ctypes
import ctypes.util
import os
import re
import subprocess
import sys
import time


def vm():
    """(page size, {vm_stat label: pages})."""
    out = subprocess.run(["vm_stat"], capture_output=True, text=True).stdout
    page = int(re.search(r"page size of (\d+) bytes", out).group(1))
    d = {}
    for line in out.splitlines()[1:]:
        m = re.match(r'\s*"?([^":]+)"?:\s+(\d+)\.?\s*$', line)
        if m:
            d[m.group(1).strip()] = int(m.group(2))
    return page, d


def readings(page, d):
    """The shipped sum and the common alternative, in bytes."""
    shipped = (d["Pages free"] + d["File-backed pages"] + d["Pages purgeable"]) * page
    common = (d["Pages free"] + d["Pages inactive"] + d["Pages speculative"] + d["Pages purgeable"]) * page
    return shipped, common


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-gb", type=float, required=True)
    ap.add_argument("--ready", required=True)
    ap.add_argument("--stop", required=True)
    ap.add_argument("--parent-pid", type=int, required=True)
    ap.add_argument("--wire-secs", type=int, default=240)
    ap.add_argument("--max-compress-gb", type=float, default=4.0)
    ap.add_argument("--max-secs", type=int, default=3600)
    a = ap.parse_args()
    for p in (a.ready, a.stop):
        if os.path.exists(p):
            os.remove(p)

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    PROT_RW, MAP_ANON_PRIVATE, MAP_FAILED = 0x3, 0x1002, (1 << 64) - 1

    t0 = time.time()
    page, d0 = vm()
    target = int(a.target_gb * 1e9)
    before, before_common = readings(page, d0)
    swap0 = d0.get("Swapouts", 0)
    comp0 = d0.get("Pages occupied by compressor", 0)
    gb = lambda b: "%.2f" % (b / 1e9)
    locked = 0
    capped = ""

    def trace(what, page, d):
        now, com = readings(page, d)
        print("WIRE t=%.1f %s locked_gb=%s avail_gb=%s common_gb=%s compressor_gb=%s swapouts_d=%d" % (
            time.time() - t0, what, gb(locked), gb(now), gb(com),
            gb(d.get("Pages occupied by compressor", 0) * page), d.get("Swapouts", 0) - swap0),
            file=sys.stderr, flush=True)

    def gone():
        return os.path.exists(a.stop) or not alive(a.parent_pid)

    def check(page, d):
        """A reason to stop wiring, or ''."""
        if gone():
            return "stop file or parent gone"
        if time.time() - t0 > a.wire_secs:
            return "wire deadline %ds" % a.wire_secs
        if d.get("Swapouts", 0) > swap0:
            return "swapouts rose %d" % (d["Swapouts"] - swap0)
        grew = (d.get("Pages occupied by compressor", 0) - comp0) * page
        if grew > a.max_compress_gb * 1e9:
            return "compressor grew %s GB" % gb(grew)
        return ""

    def wire(n):
        nonlocal locked
        n = (n // page) * page
        if n <= 0:
            return ""
        p = libc.mmap(None, n, PROT_RW, MAP_ANON_PRIVATE, -1, 0)
        if p is None or p == MAP_FAILED:
            return "mmap errno=%d" % ctypes.get_errno()
        if libc.mlock(p, n) != 0:
            err = ctypes.get_errno()
            libc.munmap(p, n)
            return "mlock errno=%d at=%d" % (err, locked)
        locked += n
        return ""

    settled = 0
    while not capped:
        page, d = vm()
        capped = check(page, d)
        if capped:
            break
        now, _ = readings(page, d)
        trace("step", page, d)
        if now <= target + (512 << 20):
            settled += 1
            if settled >= 3:
                break
            time.sleep(1)
            continue
        settled = 0
        # Big steps while far off, then small ones to let eviction settle.
        capped = wire(min(1 << 30, now - target))
        if now - target < (4 << 30):
            time.sleep(1)

    page, d1 = vm()
    trace("done capped=[%s]" % capped, page, d1)
    if gone():
        return 3
    after, after_common = readings(page, d1)
    with open(a.ready, "w") as f:
        f.write("target_gb=%s avail_before_gb=%s common_before_gb=%s locked_gb=%s capped=[%s] "
                "avail_after_gb=%s common_after_gb=%s compressor_gb=%s swapouts_d=%d wire_secs=%.1f pid=%d" % (
                    a.target_gb, gb(before), gb(before_common), gb(locked), capped,
                    gb(after), gb(after_common), gb(d1.get("Pages occupied by compressor", 0) * page),
                    d1.get("Swapouts", 0) - swap0, time.time() - t0, os.getpid()))
    while not gone() and time.time() - t0 < a.max_secs:
        time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
