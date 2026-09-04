#!/usr/bin/env python3
"""Corrupt N distinct blocks of a PAR2 rig's payload, seeded and spread
across its files - the input to a crossover sweep (fold against the
transform at a range of missing-block counts).

    par2-mkdamage.py <rig-root> <N> [seed] [block-size]

Builds <rig-root>/damaged-m<N> from <rig-root>/pristine-heavy, which
par2-round.sh drives as leg `m<N>`. Seeded, so two boxes damage the same
blocks and their sweeps are comparable; spread over every file, so the
repair is not one file's problem.

Method and results: research/PAR2-PERF-AUDIT-2026-09-02.md section 7.
"""
import os
import random
import shutil
import sys

root = sys.argv[1]
n = int(sys.argv[2])
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 20260902
bs = int(sys.argv[4]) if len(sys.argv) > 4 else 65536

src = os.path.join(root, "pristine-heavy")
dst = os.path.join(root, f"damaged-m{n}")
if os.path.exists(dst):
    shutil.rmtree(dst)
shutil.copytree(src, dst)

payload = sorted(f for f in os.listdir(dst) if not f.endswith(".par2"))
blocks = []
for f in payload:
    nb = (os.path.getsize(os.path.join(dst, f)) + bs - 1) // bs
    blocks += [(f, i) for i in range(nb)]
if n > len(blocks):
    raise SystemExit(f"{n} blocks asked of a {len(blocks)}-block corpus")

# A fixed 4 KiB pattern 17 bytes into the block: inside the block on any
# block size this rig uses, and not a run of zeros (which a fold can
# cancel against and a lazy verifier can miss).
for f, i in random.Random(seed).sample(blocks, n):
    with open(os.path.join(dst, f), "r+b") as fh:
        fh.seek(i * bs + 17)
        fh.write(bytes([0xA5, 0x5A, 0xC3, 0x3C]) * 1024)
print(f"damaged-m{n}: {n} blocks over {len(payload)} files (seed {seed}, bs {bs})")
