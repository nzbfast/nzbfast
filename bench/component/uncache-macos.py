#!/usr/bin/env python3
"""uncache-macos - drop a file's clean pages from the page cache on macOS,
without root. The Mac sibling of this directory's `uncache.c`.

Written 16 Sep 2026 (claim `macos-uncache-shared-tool-16sep`) because
`uncache.c` is `POSIX_FADV_DONTNEED`, which is Linux-only - macOS has no
`posix_fadvise` at all - so every Mac cold round has had to re-derive the
macOS equivalent. On 16 Sep 2026 THREE separate lanes derived it inside a
few hours of each other, two of them near-identical down to the constant
line and a shared `_mapped` helper:

  - research/nzbfast-rr-repair-cold-2026-09-16/cold.py
  - research/rarbench-2026-09-16/rc-ab.py
  - the digest-cache cold round's scratch driver, which was in a
    scratchpad and is gone (claim parfast-digest-cache-cold-second-box-16sep,
    research/DESIGN-DIGEST-CACHE-2026-09-15.md section 9b-3b)

That is CLAUDE.md item 1a's most repeated defect, three times in one day.
This is the one copy, in the place the Linux one already lives.

WHY NOT THE OBVIOUS ALTERNATIVES. There is no `drop_caches` on a Mac, and
`sudo purge` is NOT available on this fleet: plain `purge` answers
`Unable to purge disk buffers: Operation not permitted`, and `sudo` asks
for a password on every Apple box in this fleet (`sudo -n` refuses; the
only NOPASSWD entries anywhere are the bench shaper's `dnctl` and
`pfctl`). Establishing a cold start by reading other data until the
payload falls out costs a read of the whole of RAM per rep - minutes per
arm on a 256 GB box, and it flattens every other lane's working set on a
machine a dozen sessions share.

THE MECHANISM, established and not to be re-derived: a `PROT_READ` /
`MAP_SHARED` mapping plus `msync(addr, len, MS_INVALIDATE)`, which on
Darwin reaches `ubc_msync(..., UBC_INVALIDATE)` and drops the file's
clean cached pages. That is a per-FILE drop rather than a global one,
which is what a round wants anyway: it makes ONE payload cold and leaves
the unrelated working set alone.

    uncache-macos.py FILE...  -> per file: <resident_before> <resident_after> <total_pages> <path>
    uncache-macos.py --selftest

Same CLI shape and same four columns as `uncache.c`, so the two read the
same way. The counts come from `mincore(2)`, which macOS does have, and
the residency loop is kept identical in shape to `resident.c`'s and to
`uncache.c`'s on purpose: three tools disagreeing about what "resident"
means would be worse than any one of them being wrong. So the drop is
VERIFIED rather than assumed - a file somebody else holds dirty or
mapped reports a nonzero `after` and the caller can see it and refuse the
leg. **Do not assume this worked - read the second number.**

`--selftest` is the arm that makes the tool trustworthy, and it is not
optional paranoia: a probe that always reads zero is indistinguishable
from a perfect eviction. It proves the probe swings BOTH ways - write a
temp file (expect ~100% resident), evict (expect exactly 0.00%), read it
back (expect ~100% again) - and exits non-zero on any leg. The same three
readings are on record from the round that found this method, on an M3
Ultra and an M1 Ultra: 100.00% -> 0.00% -> 100.00% on a 512 MiB file, with a cold
`dd` at 6.5-6.9 GB/s against ~21 GB/s warm as an independent second
instrument. Never weaken an assertion here to make it pass; a real
failure is a finding about the platform.

Importable, because that is how the existing drivers used their copies:

    from uncache_macos import evict, residency, resident
    evict(path)            # drop path's clean pages; raises on failure
    residency(path)        # (resident_pages, total_pages)
    resident(path)         # resident FRACTION, 0.0-1.0 - the two 16 Sep
                           # drivers' spelling, kept so they can drop this in

Reads nothing, writes nothing, creates nothing, unlinks nothing (outside
`--selftest`, which works only in its own temp file): it opens O_RDONLY
and maps read-only. It is pointed at other people's files.
"""

import ctypes
import ctypes.util
import os
import sys

# libc on Darwin is libSystem; find_library resolves it, and the explicit
# path is the fallback for an environment where the dyld cache lookup
# comes back empty.
_LIBC_PATH = ctypes.util.find_library("c") or "/usr/lib/libSystem.B.dylib"
_libc = ctypes.CDLL(_LIBC_PATH, use_errno=True)
_libc.mmap.restype = ctypes.c_void_p
_libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                       ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
_libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libc.msync.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]

PROT_READ, MAP_SHARED, MS_INVALIDATE = 0x1, 0x0001, 2
MAP_FAILED = ctypes.c_void_p(-1).value
PAGE = os.sysconf("SC_PAGE_SIZE")

# One mapping at a time is capped rather than mapping the whole file: a
# multi-hundred-GB payload is a real shape on the bench boxes, and a
# single mapping of it also means a single mincore vector of one byte per
# page. 1 GiB is a whole number of pages at both 4 KiB and 16 KiB, which
# is what mmap needs of an offset.
CHUNK = 1 << 30


def _chunks(size):
    """Page-aligned (offset, length) spans covering a file of `size`."""
    off = 0
    while off < size:
        yield off, min(CHUNK, size - off)
        off += CHUNK


def _over_chunk(fd, path, off, length, fn):
    addr = _libc.mmap(None, length, PROT_READ, MAP_SHARED, fd, off)
    if addr == MAP_FAILED or addr is None:
        raise OSError(ctypes.get_errno(),
                      "mmap failed on %s at offset %d" % (path, off))
    try:
        return fn(addr, length)
    finally:
        _libc.munmap(ctypes.c_void_p(addr), length)


def evict(path):
    """Drop path's clean cached pages. Unprivileged; see the header.

    A zero-length file has no mapping to make, so it is a no-op rather
    than an error - macOS refuses mmap of length 0.
    """
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        for off, length in _chunks(size):
            def go(addr, ln):
                if _libc.msync(ctypes.c_void_p(addr), ln, MS_INVALIDATE) != 0:
                    raise OSError(ctypes.get_errno(),
                                  "msync(MS_INVALIDATE) failed on %s at offset %d"
                                  % (path, off))
            _over_chunk(fd, path, off, length, go)
    finally:
        os.close(fd)


def residency(path):
    """(resident_pages, total_pages) for path, via mincore(2).

    This is the CHECK that an eviction happened, rather than the
    assumption that it did. A zero-length file is (0, 0).
    """
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        total = (size + PAGE - 1) // PAGE
        res = 0
        for off, length in _chunks(size):
            def go(addr, ln):
                n = (ln + PAGE - 1) // PAGE
                vec = ctypes.create_string_buffer(n)
                if _libc.mincore(ctypes.c_void_p(addr), ln, vec) != 0:
                    raise OSError(ctypes.get_errno(),
                                  "mincore failed on %s at offset %d" % (path, off))
                # Bit 0 is MINCORE_INCORE on macOS as on Linux - the same
                # test resident.c and uncache.c make.
                return sum(1 for b in vec.raw[:n] if b & 1)
            res += _over_chunk(fd, path, off, length, go)
        return res, total
    finally:
        os.close(fd)


def resident(path):
    """Resident FRACTION of path, 0.0-1.0; 0.0 for a zero-length file.

    The spelling the two 16 Sep 2026 round drivers used, kept so either
    can import this module in place of its own copy with no other edit.
    """
    res, total = residency(path)
    return (res / total) if total else 0.0


# selftest-roster: macOS only, and not incidentally - the thing under test
# is a Darwin kernel behaviour, so there is no runner that could check it.
# The mechanism is `msync(MS_INVALIDATE)` reaching `ubc_msync(...,
# UBC_INVALIDATE)`, which drops a file's clean cached pages; on Linux that
# same call does NOT drop them, so this selftest on a runner would not
# assert something weaker, it would FAIL - and it would be right to, about
# a platform this tool does not claim. Nor would passing it there mean
# anything: `find_library("c")` resolves libc.so.6 happily, so the import
# survives and every number afterwards is measuring the wrong kernel. The
# Linux equivalent is a different mechanism and already has its own tool
# beside this one, `uncache.c` (POSIX_FADV_DONTNEED), which declares no
# selftest and so asks this roster for nothing. Same standing and the same
# reason as `bench/nested-corpus/procsample.py`, and as this repo's private
# I/O-attribution sampler, both waived in this roster for exactly this.
# Run it on a mac, which is where every box that needs a cold macOS page
# cache already is.
def _selftest():
    """Prove the probe swings BOTH ways. Returns 0 on success.

    A probe that always reads zero is indistinguishable from a perfect
    eviction, so every leg here is load-bearing. Do not weaken one to
    make it pass.
    """
    import tempfile

    mib = 64
    size = mib << 20
    fd, path = tempfile.mkstemp(prefix="uncache-macos-selftest-")
    rc = 0
    try:
        block = os.urandom(1 << 20)
        with os.fdopen(fd, "wb") as f:
            for _ in range(mib):
                f.write(block)
            f.flush()
            os.fsync(f.fileno())

        def leg(name, want_lo, want_hi):
            nonlocal rc
            res, total = residency(path)
            frac = (res / total) if total else 0.0
            ok = want_lo <= frac <= want_hi
            print("%-22s resident=%d/%d pages (%.2f%%)  expect %.2f-%.2f%%  %s"
                  % (name, res, total, frac * 100.0,
                     want_lo * 100.0, want_hi * 100.0, "OK" if ok else "FAIL"))
            if not ok:
                rc = 1
            return frac

        print("selftest: %d MiB at %s, page size %d" % (mib, path, PAGE))
        # Just written, so the page cache is holding all of it. Anything
        # below ~99% here means the probe is under-reporting and every
        # "cold" reading it takes later is worthless.
        leg("after write", 0.99, 1.0)
        evict(path)
        # EXACTLY zero. This is the one assertion with no tolerance: a
        # partial drop is a cold arm that is not cold, and a round must
        # refuse the leg rather than average it in.
        leg("after evict", 0.0, 0.0)
        with open(path, "rb") as f:
            while f.read(1 << 20):
                pass
        # And back up again - which is what separates a working probe
        # from one that reads zero unconditionally.
        leg("after read back", 0.99, 1.0)

        # The zero-length case: no mapping to make, and neither call may
        # raise. macOS refuses mmap of length 0, which is how a naive
        # copy of this tool breaks on an empty file.
        empty = path + ".empty"
        open(empty, "wb").close()
        try:
            evict(empty)
            res, total = residency(empty)
            ok = (res, total) == (0, 0)
            print("%-22s resident=%d/%d pages                        %s"
                  % ("zero-length file", res, total, "OK" if ok else "FAIL"))
            if not ok:
                rc = 1
        finally:
            os.unlink(empty)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    print("selftest: %s" % ("PASS" if rc == 0 else "FAIL"))
    return rc


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: %s FILE...\n       %s --selftest\n"
                         % (argv[0], argv[0]))
        return 2
    if argv[1] == "--selftest":
        return _selftest()
    if sys.platform != "darwin":
        sys.stderr.write("%s: this is the macOS evictor; on Linux use "
                         "bench/component/uncache.c\n" % argv[0])
        return 2
    rc = 0
    for path in argv[1:]:
        try:
            before, total = residency(path)
            evict(path)
            after, _ = residency(path)
        except OSError as e:
            sys.stderr.write("%s: %s\n" % (path, e))
            rc = 1
            continue
        print("%d %d %d %s" % (before, after, total, path))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
