#!/usr/bin/env python3
"""pdsum.py - reduce a pdgate.py round.

Medians per arm and cell, and the PAIRED ratio that is the actual verdict:
each rep's arm leg over that same rep's base leg, min-max over the reps. The
candidate has to beat the A/A arm's paired range, not the medians - which is
the whole reason an A/A arm is mandatory.
"""
import json
import sys
from collections import defaultdict


def med(v):
    v = sorted(x for x in v if x is not None)
    if not v:
        return None
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2.0


rows = [json.loads(l) for l in open(sys.argv[1])]
arms, cells = [], []
for r in rows:
    if r["arm"] not in arms:
        arms.append(r["arm"])
    if r["m"] not in cells:
        cells.append(r["m"])
by = {(r["arm"], r["m"], r["rep"]): r for r in rows}

exact = sum(1 for r in rows if r["byte_exact"])
print("%d legs, byte-exact %d, not-exact %s" %
      (len(rows), exact, [r["tag"] for r in rows if not r["byte_exact"]] or "none"))
fgn = [r["foreign_cpu_s"] for r in rows if r.get("foreign_cpu_s") is not None]
print("load at leg start %.2f-%.2f; foreign CPU over a leg %.1f-%.1f s against %.0f-%.0f s of leg CPU"
      % (min(r["load_before"] for r in rows), max(r["load_before"] for r in rows),
         min(fgn), max(fgn),
         min(r["cpu_s"] for r in rows if r["cpu_s"]), max(r["cpu_s"] for r in rows if r["cpu_s"])))
disp = [r["repair"].get("slab_lines") for r in rows]
uniq = sorted({json.dumps(d) for d in disp})
print("dispatch shapes seen: %s" % uniq)

fields = [("wall_s", "wall"), ("cpu_s", "cpu"), ("stime_s", "sys"),
          ("utime_s", "user"), ("minflt", "minflt"), ("vmhwm_mib", "rss"),
          ("repair_total_s", "repair")]
for m in cells:
    print("\n=== m = %d ===" % m)
    hdr = "%-6s" % "arm" + "".join("%12s" % n for _f, n in fields) + "   paired wall / cpu vs base"
    print(hdr)
    for arm in arms:
        legs = [by[k] for k in by if k[0] == arm and k[1] == m]
        vals = []
        for f, _n in fields:
            if f == "repair_total_s":
                vals.append(med([l["repair"].get("repair_total_s") for l in legs]))
            else:
                vals.append(med([l[f] for l in legs]))
        line = "%-6s" % arm
        for v in vals:
            line += "%12s" % ("-" if v is None else ("%.0f" % v if v and v > 10000 else "%.2f" % v))
        pw, pc = [], []
        for rep in sorted({k[2] for k in by if k[0] == arm and k[1] == m}):
            b = by.get(("base", m, rep))
            a = by.get((arm, m, rep))
            if b and a and b["wall_s"] and a["wall_s"]:
                pw.append(a["wall_s"] / b["wall_s"])
                if b["cpu_s"]:
                    pc.append(a["cpu_s"] / b["cpu_s"])
        if arm != "base" and pw:
            line += "   %.3f-%.3f / %.3f-%.3f" % (min(pw), max(pw), min(pc), max(pc))
        print(line)
    b = [by[k]["minflt"] for k in by if k[0] == "base" and k[1] == m]
    for arm in arms:
        if arm == "base":
            continue
        a = [by[k]["minflt"] for k in by if k[0] == arm and k[1] == m]
        if med(b):
            print("  %-5s minor faults %.2fx base" % (arm, med(a) / float(med(b))))
