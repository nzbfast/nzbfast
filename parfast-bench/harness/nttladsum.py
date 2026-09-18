#!/usr/bin/env python3
"""nttladsum.py - reduce a `nttladder.py` round: per-rung table, the A/A floor
of the day per rep, and the two fits that answer the round's question.

    nttladsum.py legs.jsonl [legs2.jsonl ...]

WHAT IT FITS, and why there are two of them.

1. THE LADDER FIT, over rung totals. Per rung the transform's whole syndrome
   pass should cost `c_l * S_total + k * (c_w * m)` if the per-window upper
   tree is a flat charge and the leaves are linear in the sources - `S_total`
   is the same 3,700 at every rung, so that reduces to a straight line in the
   WINDOW COUNT `k`. Its slope IS the per-window charge and its intercept the
   leaves. A straight line says linear; curvature says the charge moves with
   the window count (something caches, or the leaves get dearer as the windows
   narrow), and the SIGN of the curvature says which.

2. THE WINDOW FIT, over every window's own `(S, t)`. Each window prints its own
   `ntt syndromes (... n=<S> ...): <t>`, so the round hands back one point per
   window per leg across a wide range of S. Under the shipped model
   (`fastpar::ntt_window_row_gate`) every one of those lies on ONE line
   `t = c_l * S + c_w * m` whatever rung it came from, with `c_l` a CONSTANT.
   `NTT_WINDOW_COMBINE_X86`'s own 16 Sep docstring doubts exactly that - "a
   transform over 1,040 sources is not the same transform per source as one
   over 7,900" - so the per-rung residual against the pooled line is the
   finding, in either direction.

Fits are ordinary least squares with no weighting: the points are one
measurement each and a weighting would be a claim about their variance that
nothing here measured.

REMAINDER WINDOWS, AND WHY BOTH FITS SET THEM ASIDE. A rung's greedy fill can
leave a last window holding a handful of sources - 3, 19, 22, 25, 33, 35, 38
and 41 sources in the 1 MiB ladder of 17 Sep 2026, 1, 3, 4 and 64 in the 4 MiB
one. Section 8.16.5 of an internal note
measured what one costs: 10-12% of the flat charge when it holds a single
source, rising to 30-56% once it holds tens. So a remainder is neither a window
nor free, and the one-parameter model does not price it. Until 17 Sep 2026 this
reducer counted every `ntt syndromes` line as a window and mis-fitted BOTH fits
because of it: the ladder fit plotted a rung with a near-free extra window one
window to the right of where it belongs, and the window fit pooled a point at
`S = 3` whose `t` is near zero, which drags the intercept down and the slope
up. On the banked 1 MiB ladder the pooled fit returns c_l = 2.418 ms/source and
a 7.15 s per-window charge where the same data without remainders gives 2.233
and 7.64.

Both fits therefore run on FULL windows only, the ladder fit counts FULL
windows rather than `ntt_syn_calls`, and the remainders are printed as their
own table with their own `(S, t)` - they are a measured cost and 8.16.5's table
is the only record of it, so a reducer that silently dropped them would trade
one blindness for another.

THE THRESHOLD IS ONE HALF of that leg's widest window, and it is per LEG rather
than per rung because the fill can differ between reps. 8.16 used two: "under a
tenth" for its tables and "under a half" for its fits. Half is the default here
because it is the one that classifies the 4 MiB `w10` rung correctly - a 64 in
a rung of 404s is 16% of full, so a tenth leaves it in the fit, and 8.16.5
measured that same window at 14.59-17.74 s against a full window's 31.7, which
is about HALF a window and emphatically not a full one. A tenth is still
reachable: set `REMAINDER_FRAC` in the environment. Nothing between the two
changes any rung of the three banked ladders.
"""
import json
import os
import sys
from collections import defaultdict

REMAINDER_FRAC = float(os.environ.get("REMAINDER_FRAC", "0.5"))


def med(xs):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def split_windows(leg):
    """(full, remainder) window points of one leg, by REMAINDER_FRAC."""
    pts = leg["win_points"]
    if not pts:
        return [], []
    cut = REMAINDER_FRAC * max(p["n"] for p in pts)
    return ([p for p in pts if p["n"] >= cut], [p for p in pts if p["n"] < cut])


def ols(xs, ys):
    """(slope, intercept, r2) or None when fewer than two distinct x."""
    n = len(xs)
    if n < 2 or len(set(xs)) < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    b = sxy / sxx
    a = my - b * mx
    sst = sum((y - my) ** 2 for y in ys)
    sse = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return (b, a, (1 - sse / sst) if sst else 1.0)


legs = []
for path in sys.argv[1:]:
    for line in open(path):
        line = line.strip()
        if line:
            legs.append(json.loads(line))
if not legs:
    raise SystemExit("no legs")

bad = [l for l in legs if not l["ok"]]
if bad:
    print("!! %d leg(s) NOT byte-exact - this round is damage, not data" % len(bad))

order = []
for l in legs:
    if l["rung"] not in order:
        order.append(l["rung"])

print("legs=%d  rungs=%d  reps=%s  seed-one-plan  m=%d slice=%d"
      % (len(legs), len(order), sorted({l["rep"] for l in legs}), legs[0]["m"], legs[0]["slice"]))
print()
print("%-12s %3s %5s %5s %9s %9s %9s %9s %8s %7s %s"
      % ("rung", "n", "wins", "slab", "wall med", "cpu med", "syn med", "bsub med",
         "peak MB", "path", "window sources"))
rung_rows = {}
for rung in order:
    ls = [l for l in legs if l["rung"] == rung]
    wins = sorted({l["ntt_syn_calls"] for l in ls})
    ns = sorted({tuple(p["n"] for p in l["win_points"]) for l in ls})
    row = {
        "n": len(ls),
        "k": med([len(split_windows(l)[0]) for l in ls]),
        "k_all": med([l["ntt_syn_calls"] for l in ls]),
        "wall": med([l["wall"] for l in ls]),
        "cpu": med([l["cpu"] for l in ls]),
        "syn": med([l["syn_total"] for l in ls]),
        "bsub": med([l["back_sub"] for l in ls if l["back_sub"] is not None]),
        "peak": med([l["peak_mb"] for l in ls]),
        "path": sorted({l["path"] for l in ls}),
        "slabs": sorted({l["slabs"] for l in ls}),
    }
    rung_rows[rung] = row
    print("%-12s %3d %5s %5s %9.2f %9.2f %9.2f %9.2f %8.0f %7s %s"
          % (rung, row["n"], ",".join(str(w) for w in wins), ",".join(str(s) for s in row["slabs"]),
             row["wall"], row["cpu"], row["syn"], row["bsub"], row["peak"],
             "/".join(row["path"]), ns[0] if len(ns) == 1 else ns))
print()

# REMAINDER WINDOWS - set aside by both fits below, printed here so the reader
# sees exactly what was set aside and what it cost. See the header.
rem_rows = defaultdict(list)
for l in legs:
    full, rem = split_windows(l)
    ft = med([p["t"] for p in full]) if full else float("nan")
    for p in rem:
        rem_rows[l["rung"]].append((p["n"], p["t"], ft))
print("REMAINDER windows (S < %.2f x that leg's widest), excluded from both fits"
      % REMAINDER_FRAC)
if rem_rows:
    print("%-12s %5s %9s %9s %9s %9s"
          % ("rung", "pts", "S med", "t med", "full t", "of full"))
    for rung in order:
        if rung not in rem_rows:
            continue
        rs = rem_rows[rung]
        sm, tm = med([s for s, _, _ in rs]), med([t for _, t, _ in rs])
        fm = med([f for _, _, f in rs])
        print("%-12s %5d %9.0f %9.2f %9.2f %8.0f%%"
              % (rung, len(rs), sm, tm, fm, tm / fm * 100.0 if fm else float("nan")))
        print("%-12s %5s   %s" % ("", "", " ".join(
            "%d:%.2f" % (s, t) for s, t, _ in sorted(rs))))
else:
    print("  none - every window in this round is a full one")
print()

# A/A floor per rep per rung: the two arms are the SAME binary at a second path.
print("A/A floor (|a - a_aa| / min), per rep")
print("%-12s %4s %9s %9s %9s" % ("rung", "rep", "wall %", "cpu %", "syn %"))
for rung in order:
    for rep in sorted({l["rep"] for l in legs if l["rung"] == rung}):
        ls = [l for l in legs if l["rung"] == rung and l["rep"] == rep]
        by = {l["arm"]: l for l in ls}
        if "a" in by and "a_aa" in by:
            def pct(f):
                x, y = f(by["a"]), f(by["a_aa"])
                return abs(x - y) / min(x, y) * 100.0 if min(x, y) else float("nan")
            print("%-12s %4d %9.2f %9.2f %9.2f"
                  % (rung, rep, pct(lambda l: l["wall"]), pct(lambda l: l["cpu"]),
                     pct(lambda l: l["syn_total"])))
print()

# 1. the ladder fit: rung syndrome total against FULL window count.
lad = [(rung_rows[r]["k"], rung_rows[r]["syn"]) for r in order
       if rung_rows[r]["path"] == ["ntt"]]
fit = ols([k for k, _ in lad], [t for _, t in lad])
if fit:
    b, a, r2 = fit
    print("LADDER FIT  syn_total = %.3f * k + %.3f   (r2=%.5f, %d rungs, k = FULL windows)"
          % (b, a, r2, len(lad)))
    # ...and the same fit over the three WIDEST rungs alone. The departure below
    # roughly 500 sources a window (8.16.5) is a finding in its own right and it
    # bends the all-rungs line, so the flat charge is read off the top of the
    # ladder, which is where the model is not in doubt.
    wide = sorted(lad)[:3]
    fitw = ols([k for k, _ in wide], [t for _, t in wide])
    if fitw and len(lad) > 3:
        bw, aw, r2w = fitw
        print("            widest 3 rungs only: %.3f * k + %.3f   (r2=%.5f, k=%s)"
              % (bw, aw, r2w, ",".join("%.0f" % k for k, _ in wide)))
    print("%-12s %5s %9s %9s %9s" % ("rung", "k", "syn med", "fitted", "resid"))
    for rung in order:
        if rung_rows[rung]["path"] != ["ntt"]:
            continue
        k, t = rung_rows[rung]["k"], rung_rows[rung]["syn"]
        print("%-12s %5.0f %9.2f %9.2f %+9.2f" % (rung, k, t, a + b * k, t - (a + b * k)))
print()

# 2. the window fit: every window's own (S, t), pooled across the whole ladder.
pts = [(p["n"], p["t"], l["rung"]) for l in legs for p in split_windows(l)[0]]
fit2 = ols([s for s, _, _ in pts], [t for _, t, _ in pts])
if fit2:
    b2, a2, r22 = fit2
    print("WINDOW FIT  t = %.6f * S + %.3f   (c_l = %.3f ms/source, per-window %.2f s, "
          "r2=%.5f, %d FULL windows)" % (b2, a2, b2 * 1000.0, a2, r22, len(pts)))
    print("%-12s %6s %9s %9s %9s %9s" % ("rung", "pts", "S med", "t med", "fitted", "resid"))
    byr = defaultdict(list)
    for s, t, r in pts:
        byr[r].append((s, t))
    for rung in order:
        if rung not in byr:
            continue
        ss = [s for s, _ in byr[rung]]
        ts = [t for _, t in byr[rung]]
        sm, tm = med(ss), med(ts)
        print("%-12s %6d %9.0f %9.2f %9.2f %+9.2f"
              % (rung, len(byr[rung]), sm, tm, a2 + b2 * sm, tm - (a2 + b2 * sm)))
    print()
    print("per-window charge implied by each window, t - c_l*S (flat if the model holds)")
    print("%-12s %6s %9s %9s %9s" % ("rung", "pts", "S med", "implied", "spread"))
    for rung in order:
        if rung not in byr:
            continue
        imp = [t - b2 * s for s, t in byr[rung]]
        print("%-12s %6d %9.0f %9.2f %9.2f"
              % (rung, len(imp), med([s for s, _ in byr[rung]]), med(imp), max(imp) - min(imp)))
