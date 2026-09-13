#!/usr/bin/env python3
"""Gap a PAR2 set's RECOVERY exponents, so a repair cannot find a
consecutive run and has to fall back to Gauss-Jordan.

    par2-gap-recovery.py <dir> --max-run N [--seed S] [--dry-run]

WHY THIS IS NOT "DELETE SOME RECOVERY VOLUMES". That was the first
attempt and its own selftest disproved it: the legs came back reporting
`arm=vandermonde`, the fast path, because the repair does not need the
WHOLE recovery set to be intact - it needs ONE CONSECUTIVE RUN of `m`
exponents, and it deliberately looks for one (`par2repair`: "select a
consecutive run of recovery exponents, not just the smallest"). Our
creator emits doubling volumes (1, 2, 4, ... 16,384 blocks), so deleting
any one of them leaves runs of thousands and the structured solve is
still available. Deleting enough volumes to break every run means
deleting nearly the whole set, which is a DIFFERENT leg - a set that
cannot repair at all.

So the gap has to be cut at SLICE granularity, and this walks the
packets to do it: kill scattered individual recovery slices so that the
longest surviving consecutive run is under `--max-run`, while leaving
far more than `m` slices alive in total. That is the real shape too - a
thinned provider fill loses articles, not whole volumes.

WHAT "KILL" MEANS. One byte of the packet body is flipped, which breaks
the packet MD5, so a conformant reader rejects that packet and the slice
is simply not there. It is exactly what a torn article produces, and it
is deliberately NOT a truncation: `have` counts slices that are both
present and MD5-valid, so a corrupt slice contributes nothing while the
file around it stays readable.

THE GAPS ARE IRREGULAR ON PURPOSE. `progression_parameters` relabels an
arithmetic progression of exponents back into a consecutive run and the
repair stays on the fast path, so a regular "kill every Nth" would
quietly measure the thing it was written to avoid. The spacing is jittered
between 60% and 95% of `--max-run` from a seeded RNG, which keeps the
longest run under the bound and keeps the survivors off any constant
stride.

Packet layout, as in par2-ifsc-surgery.py: magic(8) len(8) pkt_md5(16)
setid(16) type(16) body. `pkt_md5` covers bytes 32.., and here it is
deliberately left STALE - that is the whole mechanism.
RecvSlic body: exponent(4, LE) then the slice data.
"""
import argparse
import glob
import os
import random
import struct
import sys

MAGIC = b"PAR2\x00PKT"
RECVSLIC = b"PAR 2.0\x00RecvSlic"


def packets(buf):
    """Yield (offset, length, type) for every packet in a .par2 file."""
    i = 0
    n = len(buf)
    while True:
        i = buf.find(MAGIC, i)
        if i < 0 or i + 64 > n:
            return
        (length,) = struct.unpack_from("<Q", buf, i + 8)
        if length < 64 or i + length > n:
            # A malformed or truncated tail: step past this magic rather
            # than trusting its length field.
            i += 8
            continue
        yield i, length, buf[i + 48 : i + 64]
        i += length


def survey(d):
    """Every recovery slice in the directory, as (path, offset, exponent)."""
    found = []
    for path in sorted(glob.glob(os.path.join(d, "*.par2"))):
        with open(path, "rb") as f:
            buf = f.read()
        for off, length, typ in packets(buf):
            if typ == RECVSLIC and length >= 68:
                (exp,) = struct.unpack_from("<I", buf, off + 64)
                found.append((path, off, exp, length))
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--max-run", type=int, required=True,
                    help="longest consecutive run of surviving exponents to allow")
    ap.add_argument("--seed", type=int, default=20260908)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    slices = survey(a.dir)
    if not slices:
        print(f"no recovery slices found in {a.dir}", file=sys.stderr)
        return 2
    by_exp = {}
    for path, off, exp, length in slices:
        by_exp[exp] = (path, off, length)
    exps = sorted(by_exp)
    print(f"   {len(exps)} recovery slices, exponents {exps[0]}..{exps[-1]}")

    rng = random.Random(a.seed)
    lo = max(1, a.max_run * 60 // 100)
    hi = max(lo + 1, a.max_run * 95 // 100)
    kill = []
    run = 0
    target = rng.randrange(lo, hi)
    for e in exps:
        run += 1
        if run >= target:
            kill.append(e)
            run = 0
            target = rng.randrange(lo, hi)

    survivors = [e for e in exps if e not in set(kill)]
    # Report the property the leg actually depends on, rather than
    # asserting it in a comment: the longest consecutive run left.
    longest = cur = 0
    prev = None
    for e in survivors:
        cur = cur + 1 if prev is not None and e == prev + 1 else 1
        longest = max(longest, cur)
        prev = e
    print(f"   killing {len(kill)} slices, {len(survivors)} survive, "
          f"longest consecutive run {longest} (max-run {a.max_run})")
    if longest >= a.max_run:
        print("REFUSED: the longest surviving run still reaches max-run - "
              "a repair at that m would find a consecutive run and stay on "
              "the structured path.", file=sys.stderr)
        return 2
    if a.dry_run:
        return 0

    # Group the edits by file so each one is opened once.
    per_file = {}
    for e in kill:
        path, off, length = by_exp[e]
        per_file.setdefault(path, []).append(off + 68)
    for path, offsets in per_file.items():
        with open(path, "r+b") as f:
            for off in offsets:
                f.seek(off)
                b = f.read(1)
                f.seek(off)
                f.write(bytes([b[0] ^ 0xFF]))
    print(f"   edited {len(per_file)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
