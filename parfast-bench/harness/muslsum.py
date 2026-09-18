#!/usr/bin/env python3
"""muslsum.py <time.jsonl> - muslspeed.py's reducer: per cell x arm medians of wall,
CPU, user, sys, cycles, instructions and faults, the A/A spread every ratio has to
beat, and same-rep ratios over every copy pairing. Claim
parfast-musl-allocator-speed-15sep (an internal note, the musl-allocator addendum).

env SUMARMS: comma list of BASE arm names in reference-first order (default
"musl,glibc,mim"); the ratio columns are every later arm over every earlier
one, so putting the reference first makes each read "candidate / reference". Each base arm `x`
is paired with its A/A copy, which muslspeed.py must have been given as the
arm named `x_aa` - that suffix is the pairing, not a convention, so a round
whose ARMS spell the copies any other way reduces with no A/A column at all
and every ratio here becomes uncontrolled. Added for claim
musl-static-memops-residue-15sep, whose arms are musl/fast/glibc: the list
was hard-coded to the allocator round's three, so a later round either
renamed its arms to match or silently lost its own.
"""
import itertools, json, os, statistics, sys
from collections import defaultdict

rows = [json.loads(l) for l in open(sys.argv[1])]
bad = [r for r in rows if not r["ok"]]
print("legs=%d failed=%d" % (len(rows), len(bad)))
cells = []
for r in rows:
    if r["cell"] not in cells:
        cells.append(r["cell"])
by = defaultdict(list)
rep = {}
for r in rows:
    by[(r["cell"], r["arm"])].append(r)
    rep[(r["cell"], r["arm"], r["rep"])] = r
med = lambda xs: statistics.median(xs)
rng = lambda xs: "%.2f-%.2f" % (min(xs), max(xs))
base = [a for a in os.environ.get("SUMARMS", "musl,glibc,mim").split(",") if a]
# Every ordered pair in SUMARMS order, later arm over earlier, so listing
# the reference arm first makes every column read "candidate / reference".
PAIRS = [(n, d) for n, d in itertools.permutations(base, 2) if base.index(n) > base.index(d)]
# "instructions" was named in the docstring and MISSING from this tuple until
# 16 Sep 2026, so the one metric that separates "more work" from "the same
# work, stalled" had to be reduced by hand every time - including by the
# allocator round this file was written for, and by the memops round that
# turned entirely on it (claim musl-static-memops-residue-15sep).
for metric in ("wall", "cpu", "utime", "stime", "cycles", "instructions", "nvcsw", "minflt"):
    print("\n== %s: median (range) per arm; A/A = |base - base_aa| / base median" % metric)
    print("%-5s " % "cell" + " ".join("%-24s" % a for a in base)
          + " A/A " + "/".join(base) + "     " + "  ".join("%s/%s" % p for p in PAIRS))
    for c in cells:
        line = "%-5s " % c
        aa = []
        m = {}
        for a in base:
            xs = [r[metric] for r in by[(c, a)] if r.get(metric) is not None]
            ys = [r[metric] for r in by[(c, a + "_aa")] if r.get(metric) is not None]
            if not xs:
                line += "%-24s" % "-"
                continue
            m[a] = med(xs + ys)
            line += "%-24s" % ("%.4g (%s)" % (m[a], rng(xs + ys)) if metric not in ("cycles", "instructions") else "%.4g" % (m[a] / 1e9))
            aa.append("%+.1f%%" % (100.0 * (med(ys) - med(xs)) / med(xs)) if ys else "-")
        line += " " + "/".join(aa)
        for num, den in PAIRS:
            if num in m and den in m and m[den]:
                line += "   %.3f" % (m[num] / m[den])
        print(line)
# same-rep pairwise ratios (both copies of each arm), wall and cpu
print("\n== same-rep ratios min/median/max over all copy pairings; A/A pairs for reference")
for metric in ("wall", "cpu"):
    for num, den in PAIRS + [(a, a + "_aa") for a in base]:
        out = []
        for c in cells:
            rs = []
            for (cc, a, k), r in rep.items():
                if cc != c or a.replace("_aa", "") != num.replace("_aa", ""):
                    continue
                if num.endswith("_aa") or den.endswith("_aa"):
                    if a != num:
                        continue
                for d in ([den] if den.endswith("_aa") else [den, den + "_aa"]):
                    o = rep.get((c, d, k))
                    if o and o[metric]:
                        rs.append(r[metric] / o[metric])
            if rs:
                out.append("%s %.2f/%.2f/%.2f" % (c, min(rs), med(rs), max(rs)))
        print("%-4s %-6s/%-8s %s" % (metric, num, den, "  ".join(out)))
loads = [float(r["load0"][0]) for r in rows] + [float(r["load1"][0]) for r in rows]
steal = [r["steal_pct"] for r in rows if isinstance(r["steal_pct"], (int, float))]
print("\nload1 at leg start/end: %.2f-%.2f  steal%%: %s  foreign_cpu max: %.0f"
      % (min(loads), max(loads), rng(steal) if steal else "n/a", max(r["foreign_cpu"] for r in rows)))
hashes = defaultdict(set)
for r in rows:
    if "out_hash" in r:
        hashes[r["cell"]].add(r["out_hash"])
print("create output hashes per cell (1 = byte-identical across arms):", {k: len(v) for k, v in hashes.items()})
