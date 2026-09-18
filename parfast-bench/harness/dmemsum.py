#!/usr/bin/env python3
"""dmemsum.py - reduce dmem.py's jsonl to the tables the write-up carries.

Medians per (cell, arm), the candidate against the control, and the A/A pair
against each other so a ratio can be read against the noise it has to beat.
`aa` is a byte-identical copy of `musl`, so `aa/musl` IS the noise floor for
that cell and any `fast/musl` inside it is flat, not a win.
"""
import json, statistics, sys

rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
bad = [r for r in rows if r["rc"] != 0]
cells, arms = [], []
for r in rows:
    if r["cell"] not in cells:
        cells.append(r["cell"])
    if r["arm"] not in arms:
        arms.append(r["arm"])

print("legs=%d  non-zero exits=%d  cells=%s  arms=%s"
      % (len(rows), len(bad), cells, arms))
shas = {}
for r in rows:
    if r.get("sha"):
        shas.setdefault(r["cell"], {})[r["arm"]] = r["sha"]
for c, d in shas.items():
    same = len(set(d.values())) == 1
    print("  output identity %-6s %s  %s" % (c, "IDENTICAL" if same else "DIVERGED",
                                             sorted(set(v[:12] for v in d.values()))))


def med(cell, arm, key):
    v = [r[key] for r in rows if r["cell"] == cell and r["arm"] == arm
         and r["rc"] == 0 and r[key] is not None]
    return statistics.median(v) if v else None


for key, unit in (("instructions", "G"), ("cycles", "G"), ("cpu", "s"),
                  ("wall", "s"), ("maxrss_kb", "kB"), ("minflt", "")):
    if not any(r.get(key) for r in rows):
        continue
    scale = 1e9 if unit == "G" else 1
    print("\n== %s ==" % key)
    print("| cell | musl | fast | aa | fast/musl | aa/musl |")
    print("|---|---:|---:|---:|---:|---:|")
    for c in cells:
        m, f, a = (med(c, x, key) for x in ("musl", "fast", "aa"))
        if m is None:
            continue
        print("| %s | %.3f | %.3f | %.3f | **%.4f** | %.4f |"
              % (c, m / scale, f / scale, a / scale, f / m, a / m))


# PAIRED ratios: the three arms of one rep run back to back, so a rep that
# ran under heavier load carries all three arms up together. A median of
# per-ARM medians throws that pairing away; a median of per-REP ratios keeps
# it, and on a rig whose HOST is shared (armbench) it is the only statistic
# that separates the arms from the box. Reported alongside the unpaired
# tables above, never instead of them: if the two disagree, say so.
print("\n== paired per-rep ratios (median [min..max] over reps) ==")
for key in ("instructions", "cycles", "cpu", "wall"):
    if not any(r.get(key) for r in rows):
        continue
    print("| cell | fast/musl | aa/musl |   (%s)" % key)
    print("|---|---:|---:|")
    for c in cells:
        cell_line = []
        for num in ("fast", "aa"):
            rs = []
            for rep in sorted({r["rep"] for r in rows if r["cell"] == c}):
                d = {r["arm"]: r for r in rows
                     if r["cell"] == c and r["rep"] == rep and r["rc"] == 0}
                if num in d and "musl" in d and d["musl"].get(key):
                    rs.append(d[num][key] / d["musl"][key])
            cell_line.append("%.4f [%.3f..%.3f]"
                             % (statistics.median(rs), min(rs), max(rs))
                             if rs else "-")
        print("| %s | %s | %s |" % (c, cell_line[0], cell_line[1]))
    print()
