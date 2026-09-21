#!/usr/bin/env python3
"""nttmsum.py - reduce an `m`-LADDER round of `nttladder.py`: is the NTT's
per-window upper-tree charge linear in `m`, and does it plateau where the code
assumes it does?

    nttmsum.py legs.jsonl [legs2.jsonl ...]

WHY THIS IS NOT `nttladsum.py`. That reducer is section 8.11's and holds `m`
fixed while the WINDOW COUNT moves, so the leaf term `c_l * S_total` is the
same at every rung and cancels into a straight line's intercept. Here `m` moves,
so `S_total = sources - m` moves with it and no single line in the window count
exists. The two reducers answer opposite halves of one question and neither's
fit is valid on the other's round.

THE ESTIMATOR, and it needs no fitting at all. Per window the transform costs
`c_l * S` for the leaves plus a per-window tree charge `T(m)` that the shipped
model prices as `c_w * min(m, 4369)`
(`par2ntt::FlatPlan::scratch_bytes`, `NTT_WINDOW_COMBINE_NEON`'s docstring). A
leg taken in `k` windows therefore costs

    syn(k) = c_l * S_total + k * T(m)

whatever the sources are split into - which section 8.11 measured directly
(two windows split 2,964 + 736 and 1,904 + 1,796 cost 93.03 and 93.16 s, 0.15%
apart). So a PAIR of rungs at the same `m`, one at `k = 1` and one at `k = 2`,
differences straight to

    T(m) = syn(k2) - syn(k1),      c_l(m) = (syn(k1) - T(m)) / S_total

with the leaf term cancelled rather than fitted. `T(m)` against `m` IS the
round's answer, and `c_l(m)` against `m` is the third claim - whether the leaf
term moves with the rows, which it must not.

THE WITHIN-LEG CROSS-CHECK. Each `k = 2` leg also prints its two windows'
own `(S, t)`, which solves the same two constants inside ONE leg
(`t_i = c_l * S_i + T`) with no between-leg noise at all. It is the poorer
estimator when the two windows are close in size - the solve divides by
`S1 - S2` - and it is quoted as a check on the difference, never instead of it.

THE PLATEAU. `min(m, 4369)` is a structural claim (the depth-2 tile: the plan's
levels hold `min(m, 4369)`, `min(m, 21845)` and `min(m, 65535)` rows over 255,
15 and 3 nodes, so almost all the marginal work is the depth-2 one), not a
measured one. The fit is therefore taken TWICE - over the rungs below 4,369 and
over the rungs above it - and the answer is the RATIO of the two slopes, which
the structure says should be small and the docstring says should be zero. A
single fit through the knee would hide it, which is the discipline section
8.11.4 had to learn about its own saturation.

THERE IS MORE THAN ONE KNEE, AND THIS REDUCER TAKES A LIST OF THEM (17 Sep
2026, with section 8.15's depth-1 round). The tree saturates ONCE PER LEVEL -
at `min(m, 4369)`, then `min(m, 21845)`, then `min(m, 65535)` - so an `m`
ladder that reaches past 21,845 has THREE regimes and two knees, and a
two-way split would put the middle regime and the top one in one fit and
report a slope belonging to neither. `KNEES` is a comma-separated list of
saturation points, DEFAULT `4369`, so every invocation written before this
date is unchanged: one knee, two fits, the same wording, the same numbers.

AND THE RUNG ON A TILE BELONGS TO NEITHER LINE. Sections 8.12 and 8.14 both
excluded the m = 4,369 rung from both fits by hand in a scratch side-reducer,
because a rung sitting exactly on a saturation point is mid-bend; this
reducer's own default carried it in the LOWER fit, which is a real difference
between the numbers it printed and the numbers those sections published (8.14
recorded the gap: 0.6831 against 0.6859 ms/row). `EXCLUDE` names rungs to
leave out of every fit - they are still measured, still tabulated and still
shown in the departure table, just not fitted. Unset, nothing is excluded and
the old behaviour stands.

    KNEES=4369,21845 EXCLUDE=4369,21845 nttmsum.py legs.jsonl

THE CROSSING IS BIASED WHERE THE PRE-KNEE SLOPE RISES, AND THE BIAS IS AWAY
FROM THE TRUE KNEE (17 Sep 2026, section 8.17.5). The measured knee printed
below is where two fitted lines cross, which assumes the measurement is
STRAIGHT right up to the bend. Where the quantity being fitted turns UP just
before it saturates, both lines tilt and the crossing lands past the real
knee: section 8.17 measured a leaf-term break whose kernel census puts it at
16,384 to 16,896 sources and whose two-line crossing read **17,761**, 5% out,
because the paired leaf's own marginal cost climbs over the last few points
before the additive leaf takes over.

So, before quoting a crossing: look at the secants either side of the bend.
If the last few BELOW the knee are larger than the fitted below-knee slope,
the crossing is an overestimate and **the bracket between the last rung on
the line and the first rung off it is the honest statement**. This is a
FAILURE MODE and not a claim about any published number - the `m`-ladder
rounds this reducer was written for (8.12's 4,383, 8.14's 4,396, 8.15's
4,334 and 22,074) fit a tree charge against `m`, which is a different
quantity from 8.17's leaf term against `S`, and none of them has been
re-examined for a pre-knee rise. Check yours; do not assume either way.

AND MERGE NEAR-IDENTICAL x VALUES BEFORE TAKING ANY SECANT. Two rungs a
handful of units apart divide an A/A pair's noise by that handful and report
an absurd slope - 8.17's first reduction printed 10 and -20 ms/source off
window widths 1 apart, which were one rung reached two ways. The window
capacity quantises to `8 MiB / blocksize` sources; merge inside the quantum.
an internal note carries both guards
(`MERGE`, `MINDS`) if you want the shape.
"""
import json
import os
import sys
from collections import defaultdict

KNEES = sorted(int(x) for x in os.environ.get("KNEES", "4369").split(",") if x.strip())
EXCLUDE = frozenset(int(x) for x in os.environ.get("EXCLUDE", "").split(",") if x.strip())
PLATEAU = KNEES[0]


def med(xs):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


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

print("legs=%d rungs=%d reps=%s slice=%d m=%s"
      % (len(legs), len(order), sorted({l["rep"] for l in legs}), legs[0]["slice"],
         sorted({l["m"] for l in legs})))
print()

# DISPATCH FIRST, because a rung that slabbed or re-struck its stripe is not on
# the same ladder as the rest and no amount of fitting fixes it.
print("%-12s %4s %6s %4s %5s %5s %5s %9s %9s %9s %9s %8s %7s %s"
      % ("rung", "n", "m", "k", "slab", "W", "thr", "wall med", "cpu med", "syn med",
         "bsub med", "peak MB", "path", "window sources"))
rows = {}
for rung in order:
    ls = [l for l in legs if l["rung"] == rung]
    ns = sorted({tuple(p["n"] for p in l["win_points"]) for l in ls})
    ws = sorted({w for l in ls for w in l["ntt_w"]})
    th = sorted({p["threads"] for l in ls for p in l["win_points"]})
    row = {
        "n": len(ls), "m": ls[0]["m"],
        "k": med([l["ntt_syn_calls"] for l in ls]),
        "wall": med([l["wall"] for l in ls]),
        "cpu": med([l["cpu"] for l in ls]),
        "syn": med([l["syn_total"] for l in ls]),
        "bsub": med([l["back_sub"] for l in ls if l["back_sub"] is not None]),
        "peak": med([l["peak_mb"] for l in ls]),
        "path": sorted({l["path"] for l in ls}),
        "slabs": sorted({l["slabs"] for l in ls}),
        "S": med([l["win_sources"] for l in ls]),
        "threads": th[0] if th else None,
        "legs": ls,
    }
    rows[rung] = row
    print("%-12s %4d %6d %4.0f %5s %5s %5s %9.2f %9.2f %9.2f %9.2f %8.0f %7s %s"
          % (rung, row["n"], row["m"], row["k"],
             ",".join(str(s) for s in row["slabs"]), ",".join(str(w) for w in ws),
             ",".join(str(t) for t in th), row["wall"], row["cpu"], row["syn"],
             row["bsub"], row["peak"], "/".join(row["path"]),
             ns[0] if len(ns) == 1 else ns))
print()

print("A/A floor (|a - a_aa| / min), per rep")
print("%-12s %4s %9s %9s %9s" % ("rung", "rep", "wall %", "cpu %", "syn %"))
aa = defaultdict(list)
for rung in order:
    for rep in sorted({l["rep"] for l in legs if l["rung"] == rung}):
        by = {l["arm"]: l for l in legs if l["rung"] == rung and l["rep"] == rep}
        if "a" in by and "a_aa" in by:
            def pct(f, by=by):
                x, y = f(by["a"]), f(by["a_aa"])
                return abs(x - y) / min(x, y) * 100.0 if min(x, y) else float("nan")
            w, c, s = (pct(lambda l: l["wall"]), pct(lambda l: l["cpu"]),
                       pct(lambda l: l["syn_total"]))
            aa["wall"].append(w); aa["cpu"].append(c); aa["syn"].append(s)
            print("%-12s %4d %9.2f %9.2f %9.2f" % (rung, rep, w, c, s))
if aa:
    print("%-12s %4s %9.2f %9.2f %9.2f  <- median over %d pair(s)"
          % ("MEDIAN", "", med(aa["wall"]), med(aa["cpu"]), med(aa["syn"]), len(aa["wall"])))
    print("%-12s %4s %9.2f %9.2f %9.2f  <- worst"
          % ("WORST", "", max(aa["wall"]), max(aa["cpu"]), max(aa["syn"])))
print()

# The estimator: pair k=1 against k=2 at each m.
bym = defaultdict(dict)
for rung in order:
    r = rows[rung]
    if r["path"] != ["ntt"]:
        continue
    bym[r["m"]][int(r["k"])] = r

print("PER-WINDOW TREE CHARGE, by difference   T(m) = syn(k=2) - syn(k=1)")
print("%6s %8s %9s %9s %9s %9s %9s %9s"
      % ("m", "S_total", "syn k=1", "syn k=2", "T(m) s", "T/m ms", "c_l ms/src", "nonxf cpu"))
pts = []
for m in sorted(bym):
    d = bym[m]
    if 1 not in d or 2 not in d:
        continue
    t = d[2]["syn"] - d[1]["syn"]
    S = d[1]["S"]
    c_l = (d[1]["syn"] - t) / S if S else float("nan")
    thr = d[1]["threads"] or 8
    nonxf = med([l["cpu"] - thr * l["syn_total"] for l in d[1]["legs"] + d[2]["legs"]])
    pts.append((m, t, c_l))
    print("%6d %8.0f %9.2f %9.2f %9.3f %9.4f %9.3f %9.1f"
          % (m, S, d[1]["syn"], d[2]["syn"], t, t / m * 1000.0, c_l * 1000.0, nonxf))
print()

if pts:
    # ONE REGIME PER LEVEL THE TREE SATURATES AT, and a rung ON a tile is in
    # none of them. With the default KNEES=[4369] and no EXCLUDE this is the
    # same two fits, under the same two names, over the same rungs as before.
    if EXCLUDE:
        print("EXCLUDED from every fit (on a tile, so mid-bend): %s"
              % ", ".join(str(x) for x in sorted(EXCLUDE)))
    bounds = [None] + KNEES + [None]
    regimes = []
    for i in range(len(KNEES) + 1):
        lo_b, hi_b = bounds[i], bounds[i + 1]
        if lo_b is None:
            name = "BELOW %d" % hi_b
        elif hi_b is None:
            name = "ABOVE %d" % lo_b
        else:
            name = "%d-%d" % (lo_b, hi_b)
        sel = [(m, t) for m, t, _ in pts
               if m not in EXCLUDE
               and (lo_b is None or m > lo_b) and (hi_b is None or m <= hi_b)]
        regimes.append((name, sel, ols([m for m, _ in sel], [t for _, t in sel])))
    for name, sel, f in regimes:
        if f:
            b, a, r2 = f
            print("FIT %-12s T = %.6f * m %+.3f   (c_w = %.4f ms/row, r2=%.5f, %d rung(s))"
                  % (name, b, a, b * 1000.0, r2, len(sel)))
        else:
            print("FIT %-12s not enough rungs (%d)" % (name, len(sel)))
    # The ratio between ADJACENT regimes, and the crossing of their two lines -
    # which is the measured knee, read off the fits rather than off the rung
    # spacing, and is what sections 8.12 and 8.14 computed in a scratch
    # side-reducer because this one never printed it.
    for i in range(len(regimes) - 1):
        (n1, _, f1), (n2, _, f2) = regimes[i], regimes[i + 1]
        if not (f1 and f2 and f1[0]):
            continue
        tag = ("the model says 0 - a flat plateau at %d" % KNEES[i]) if i == 0 \
            else ("the structure says 3/18 = 0.1667 at %d" % KNEES[i])
        print("SLOPE RATIO %s / %s = %.4f   (%s)" % (n2, n1, f2[0] / f1[0], tag))
        if f1[0] != f2[0]:
            cross = (f2[1] - f1[1]) / (f1[0] - f2[0])
            print("KNEE        %s x %s cross at m = %.1f, against the tile's %d (%+.2f%%)"
                  % (n1, n2, cross, KNEES[i], (cross - KNEES[i]) / KNEES[i] * 100.0))
    flo = regimes[0][2]
    if flo:
        print()
        print("%6s %9s %11s %9s   (against the BELOW-plateau line, extrapolated)"
              % ("m", "T meas", "line", "departure"))
        for m, t, _ in pts:
            pred = flo[1] + flo[0] * m
            print("%6d %9.3f %11.3f %+8.3f (%+.1f%%)" % (m, t, pred, t - pred, (t - pred) / pred * 100.0))
    # AND ONE TABLE PER INTERIOR REGIME, for the same reason the first exists:
    # the SECOND knee is a departure from the MIDDLE line, and a table drawn
    # only against the bottom line shows every rung above the first tile as a
    # large negative and hides it. Printed only when there is more than one
    # knee, so a one-knee round's output is unchanged.
    for i in range(1, len(regimes) - 1):
        name, _, f = regimes[i]
        above = [(m, t) for m, t, _ in pts if m > KNEES[i]]
        if not (f and above):
            continue
        print()
        print("%6s %9s %11s %9s   (against the %s line, extrapolated)"
              % ("m", "T meas", "line", "departure", name))
        for m, t in above:
            pred = f[1] + f[0] * m
            print("%6d %9.3f %11.3f %+8.3f (%+.1f%%)"
                  % (m, t, pred, t - pred, (t - pred) / pred * 100.0))
    print()
    fc = ols([m for m, _, _ in pts], [c * 1000.0 for _, _, c in pts])
    if fc:
        b, a, r2 = fc
        print("LEAF TERM  c_l = %.6f * m %+.4f ms/source  (r2=%.5f) - flat if the model holds"
              % (b, a, r2))
        print("           c_l spans %.4f to %.4f ms/source, %.1f%% of the median"
              % (min(c * 1000 for _, _, c in pts), max(c * 1000 for _, _, c in pts),
                 (max(c for _, _, c in pts) - min(c for _, _, c in pts))
                 / med([c for _, _, c in pts]) * 100.0))
print()

# The within-leg cross-check: solve c_l and T from one k=2 leg's own windows.
print("WITHIN-LEG CROSS-CHECK (k=2 legs only; solves t_i = c_l*S_i + T inside one leg)")
print("%6s %6s %9s %9s %9s %9s" % ("m", "legs", "S1", "S2", "c_l ms", "T s"))
for m in sorted(bym):
    d = bym[m]
    if 2 not in d:
        continue
    cls, ts = [], []
    for l in d[2]["legs"]:
        p = l["win_points"]
        if len(p) != 2 or p[0]["n"] == p[1]["n"]:
            continue
        c = (p[0]["t"] - p[1]["t"]) / (p[0]["n"] - p[1]["n"])
        cls.append(c * 1000.0)
        ts.append(p[0]["t"] - c * p[0]["n"])
    if cls:
        p = d[2]["legs"][0]["win_points"]
        print("%6d %6d %9d %9d %9.3f %9.3f"
              % (m, len(cls), p[0]["n"], p[1]["n"], med(cls), med(ts)))


# ---------------------------------------------------------------------------
# THE STEAL LADDER. OPT-IN, off unless STEAL is set, so every invocation
# written before 17 Sep 2026 - which is sections 8.11 through 8.19, this note's
# whole provenance - prints byte-identical output.
#
#     STEAL=auto nttmsum.py legs.jsonl        # thresholds from the round itself
#     STEAL=none,8,6.2,5,4 nttmsum.py legs.jsonl
#     STEAL=auto STEAL_NULL=0 nttmsum.py legs.jsonl    # ladder without the null
#
# AND IT RUNS THE NULL BY DEFAULT, because the ladder is worth nothing without
# it. Every rung throws legs away and throwing legs away moves a fitted knee on
# its own, so a displacement is evidence only against the displacement that
# dropping the SAME NUMBER OF LEGS AT RANDOM produces. `STEAL_NULL` is that draw
# count (default 200, 0 to skip) and the ladder prints an empirical
# P(random >= observed) beside every rung. A rung inside its own null is a
# shrinking sample and NOT a removed bias, whatever its r2 did.
#
# WHY IT IS HERE AND NOT ONLY IN `stealsub.py`. That tool is the general form
# and is what the other reducers use, because it edits nothing. This arm exists
# because the answer nttmsum publishes is a LOCATION - a knee in m - and a
# location is precisely the kind of answer a guest cannot carry: symmetric
# noise cancels out of a RATIO of two fitted slopes and does not cancel out of
# a fitted BREAKPOINT, because a breakpoint is located by where the residual
# stops improving and inflated legs pull it toward wherever they sit. Section
# 8.18.6 watched one move 3,500 -> 4,275 (20%) on a box whose steal median was
# 3.41%. See `harness/stealsub.py`'s header for how to read the ladder
# and for the two answers that are NOT "filter and believe the cleanest rung".
#
# The knee here is the DIFFERENCE estimator's two-line crossing, not 8.18's
# joint fit, so its rungs are not that section's numbers and are not meant to
# be. What transfers is the SHAPE: stationary, or monotone-with-r2, or neither.
if os.environ.get("STEAL"):
    import importlib.util as _ilu
    _sp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stealsub.py")
    _spec = _ilu.spec_from_file_location("stealsub", _sp)
    _ss = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_ss)

    def _knee_at(sel):
        """(knee, r2_below, r2_above, ratio, rungs) over one filtered leg set,
        by the same difference estimator the body above uses."""
        bm = defaultdict(dict)
        for rg in {l["rung"] for l in sel}:
            ls = [l for l in sel if l["rung"] == rg]
            if sorted({l["path"] for l in ls}) != ["ntt"]:
                continue
            k = int(med([l["ntt_syn_calls"] for l in ls]))
            bm[ls[0]["m"]][k] = (med([l["syn_total"] for l in ls]), len(ls))
        p = [(m, d[2][0] - d[1][0]) for m, d in sorted(bm.items())
             if 1 in d and 2 in d and m not in EXCLUDE]
        lo = [(m, t) for m, t in p if m <= PLATEAU]
        hi = [(m, t) for m, t in p if m > PLATEAU]
        f1 = ols([m for m, _ in lo], [t for _, t in lo])
        f2 = ols([m for m, _ in hi], [t for _, t in hi])
        if not (f1 and f2) or f1[0] == f2[0]:
            return (None, f1[2] if f1 else None, f2[2] if f2 else None, None, len(p))
        return ((f2[1] - f1[1]) / (f1[0] - f2[0]), f1[2], f2[2],
                f2[0] / f1[0] if f1[0] else None, len(p))

    _NULL = int(os.environ.get("STEAL_NULL", "200"))
    _vals = _ss.measured(legs, sys.argv[1:])
    _st = _ss.stats(_vals)
    _spec_thr = os.environ["STEAL"]
    if _spec_thr.strip().lower() == "auto":
        _rungs = _ss.ladder_for(_vals)
    else:
        _rungs = [None if x.strip().lower() == "none" else float(x)
                  for x in _spec_thr.split(",") if x.strip()]
    print()
    print("STEAL LADDER - does this box locate the knee, or does the knee locate this box?")
    # cellguard-roster: this min/med/sd/p90/max is the hypervisor STEAL
    # PERCENTAGE distributed across measured legs, not a wall-clock time
    # distributed across repeated runs of one arm - there is no "arm" here,
    # only a per-leg noise reading, so the bimodal-cell rule (a min far under
    # the median meaning the box was demoted mid-cell) does not apply. The
    # spelling matches cellguard's pattern by coincidence.
    print("round steal%%: min=%.2f med=%.2f sd=%.2f p90=%.2f max=%.2f over %d measured leg(s)"
          % (_st["min"], _st["med"], _st["sd"], _st["p90"], _st["max"], _st["n"]))
    print("%-10s %6s %6s %10s %9s %9s %9s %9s"
          % ("threshold", "legs", "pairs", "knee m", "r2 below", "r2 above", "ratio",
             "P(null)" if _NULL else ""))
    _row = []
    for _thr in _rungs:
        _sel = [l for l in legs
                if _ss.steal_of(l) is not None
                and (_thr is None or _ss.steal_of(l) < _thr)]
        _k, _r1, _r2v, _ra, _np = _knee_at(_sel)
        _row.append((_thr, _k))
        _p = "-"
        if _NULL and _thr is not None and _k is not None:
            import random as _rnd
            _pool = [l for l in legs if _ss.steal_of(l) is not None]
            _draws = []
            for _sd in range(1, _NULL + 1):
                _dk = _knee_at(_rnd.Random(_sd).sample(_pool, len(_sel)))[0]
                if _dk is not None:
                    _draws.append(_dk)
            if _draws:
                _base = _row[0][1]
                _far = (sum(1 for v in _draws if v >= _k) if _base is None or _k >= _base
                        else sum(1 for v in _draws if v <= _k))
                _p = "%.3f" % (_far / len(_draws))
        print("%-10s %6d %6d %10s %9s %9s %9s %9s"
              % ("none" if _thr is None else "< %.2f" % _thr, len(_sel), _np,
                 "%.1f" % _k if _k is not None else "-",
                 "%.5f" % _r1 if _r1 is not None else "-",
                 "%.5f" % _r2v if _r2v is not None else "-",
                 "%.4f" % _ra if _ra is not None else "-", _p))
    _ks = [k for _, k in _row if k is not None]
    if len(_ks) >= 3:
        _mono = all(a <= b for a, b in zip(_ks, _ks[1:])) or \
                all(a >= b for a, b in zip(_ks, _ks[1:]))
        _span = (max(_ks) - min(_ks)) / min(_ks) * 100.0 if min(_ks) else float("nan")
        print("knee spans %.1f to %.1f (%.1f%% of the smallest), %s across the ladder"
              % (min(_ks), max(_ks), _span, "MONOTONE" if _mono else "NOT monotone"))
        print("  monotone + rising r2 = the box is in the answer, and the cleanest rung is")
        print("  the better estimate. Not monotone, or falling r2 = a shrinking sample and")
        print("  not a removed bias; report that and do NOT pick the flattering rung.")
        if _NULL:
            print("  P(null) is one-sided against %d random draws of the SAME leg count, in the"
                  % _NULL)
            print("  direction the rung moved from the unfiltered answer. Large = the move is")
            print("  what dropping that many legs does anyway, and is not a finding.")
