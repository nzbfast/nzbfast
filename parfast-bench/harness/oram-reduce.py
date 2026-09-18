#!/usr/bin/env python3
"""Reduce an oram.ps1 round log: per (gib, pct, arm) the median of wall,
cpu, GB/s, peak working set, hard page reads and disk read, plus each
shape's set-digest identity and the timing lines of one leg per cell."""
import re
import statistics
import sys
from collections import defaultdict

legs = defaultdict(list)
timing = defaultdict(list)
other = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.rstrip("\n")
    if line.startswith("LEG "):
        kv = dict(re.findall(r"(\w+)=(\S*)", line))
        legs[(int(kv["gib"]), int(kv["pct"]), kv["arm"])].append(kv)
    elif line.startswith("TIMING "):
        m = re.match(r"TIMING leg=(\S+) (.*)", line)
        if m:
            timing[m.group(1)].append(m.group(2))
    elif line.startswith(("VERIFY", "SET-IDENTITY", "BUILD", "FIXTURE", "BOX", "ORAM", "ROUND", "ALL DONE", "BOX-BUSY")):
        other.append(line)


def med(rows, key):
    vals = [float(r[key]) for r in rows if r.get(key) not in (None, "", "-1")]
    return statistics.median(vals) if vals else float("nan")


print(f"{'gib':>4} {'pct':>3} {'arm':<6} {'n':>2} {'wall':>8} {'min':>8} {'max':>8} {'cpu':>8} {'GB/s':>6} {'peakMB':>8} {'pgreads':>9} {'pagesin':>10} {'diskGB':>7} {'sets'}")
for (gib, pct, arm), rows in sorted(legs.items()):
    walls = [float(r["wall"]) for r in rows]
    sets = sorted({r["set"] for r in rows})
    print(
        f"{gib:>4} {pct:>3} {arm:<6} {len(rows):>2} {med(rows,'wall'):>8.1f} {min(walls):>8.1f} {max(walls):>8.1f}"
        f" {med(rows,'cpu'):>8.1f} {med(rows,'gbps'):>6.3f} {med(rows,'peak_mb'):>8.0f}"
        f" {med(rows,'page_reads'):>9.0f} {med(rows,'pages_in'):>10.0f} {med(rows,'disk_read_gb'):>7.1f} {'/'.join(sets)}"
    )
print()
for (gib, pct, arm), rows in sorted(legs.items()):
    loads = [(r["load_before"], r["load_after"], r["foreign_cpu"], r["foreign_after"]) for r in rows]
    print(f"load g{gib} r{pct} {arm}: " + " ".join("/".join(x) for x in loads))
print()
for line in other:
    print(line)
print()
for leg, lines in sorted(timing.items()):
    if leg.endswith("-rep1"):
        print(f"== {leg}")
        for t in lines:
            if "create" in t or "scan" in t or "stripe" in t or "memory" in t or "peak" in t:
                print("   " + t)
