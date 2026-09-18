#!/usr/bin/env python3
"""Reduce helper-pass HLEG lines: the enrolment helper's OWN finish per rung.

The number `reduce-enrol.py` prints as `enrolled_at` is
`Active::started.elapsed()` read in `finish()`, which is max(chain, helper) and
SATURATES - it reports the chain whenever the helper finished first, which on
every part measured so far is every rung. This reads the helper's own timer
(the second probe) instead, and prints it beside the chain it has to fit
inside: `helper/chain` is the fraction of the create's critical path the
enrolment actually occupies, and it is the margin the constant buys.
"""
import re, statistics, sys

MEMBER_GB = 8858370048 / 1e9

for path in sys.argv[1:]:
    rows, chains = {}, []
    shas = set()
    for line in open(path, errors="replace"):
        if not line.startswith("HLEG "):
            continue
        d = dict(re.findall(r"(\w+)=([^\s\[]+)", line))
        rows.setdefault(int(d["rung"]), []).append(float(d["helper_own_s"]))
        chains.append(float(d["chain_alone"].rstrip("s")))
        shas.add(d["sha"])
    if not rows:
        continue
    cm = statistics.median(chains)
    print("=== %s  (%d legs)" % (path, sum(len(v) for v in rows.values())))
    print("    set sha(s): %s%s" % (", ".join(sorted(shas)),
                                    "" if len(shas) == 1 else "   <-- VOID, legs disagree"))
    print("    chain alone median %.2f s (%.3f GB/s) - the window the helper must fit inside" % (cm, MEMBER_GB / cm))
    base = None
    for r in sorted(rows):
        m = statistics.median(rows[r])
        if base is None:
            base = m
        print("  rung %-2d own=%s median=%.3f s  %.3f GB/s  %.2fx vs 1 thread  helper/chain=%.1f%%"
              % (r, ["%.3f" % x for x in rows[r]], m, MEMBER_GB / m, base / m, 100 * m / cm))
