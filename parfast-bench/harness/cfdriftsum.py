#!/usr/bin/env python3
"""cfdriftsum.py - the WITHIN-SITTING DRIFT table: how far two cells that
should be IDENTICAL actually sit apart, fitted in CPU and in WALL side by side.

    cfdriftsum.py --rungs 192,512,1024,2048,4096 LABEL=LOG[,LOG...] [LABEL=...]
    cfdriftsum.py --rungs 192,512,1024,2048 --by-rep LABEL=LOG

WHY IT EXISTS. `cfloadsum.py` compares arms that differ by a variable under
test - a load level, a binary - and prints the ratio as that variable's effect.
That reading is only worth anything if two arms which differ by NOTHING would
read zero, and until 18 Sep 2026 nothing in this harness had ever measured
that. The 18 Sep load round measured it by accident: it ran `q1`+`q2` at the
start of a sitting and `qp` at the end, all three quiet, all three the same
cell, and at `-t4` they disagreed by 6.8% - about half the size of the load
effect the round was built to measure. This script turns that accident into a
census, so every banked comparison can be read against its own sitting's noise
floor rather than against an assumption.

THE UNIT OF COMPARISON IS THE LEGSET, or with `--by-rep` the REP. Both are
"the same cell measured twice with nothing changed", at two different time
scales - reps are back to back within one ladder, legsets are tens of minutes
apart - and the two answer differently, so the flag says which you asked for.
Every argument is one unit; the FIRST is the baseline, exactly as in
`cfloadsum.py`, and the SPREAD row is max/min over all units, which is the
figure a later round should quote as its noise floor.

BOTH METRICS, ALWAYS, AND SIDE BY SIDE. `cfloadsum.py` fits CPU alone.
A standing rule (memory topic `nzbfast-wall-time-is-the-deciding-metric`) makes
wall the deciding metric where the two disagree, and the drift question is
exactly where a disagreement would matter: a drift that is CPU-side only is an
accounting artefact, and one that moves both is the box really running slower.
So this prints them together and never makes the reader ask for the second.
**They must be fitted the same way to be compared.** The 18 Sep round reported
`c_f` +6.8% against wall +0.8% and read that as CPU-side drift; it is not. That
CPU figure is a slope through MINIMUM-over-reps cells and that wall figure is a
MEDIAN over the same reps, so the two are different estimators of different
quantities. Fitted like for like, the same pair is +6.6% CPU and +7.3% wall.

GIVE EVERY UNIT THE SAME NUMBER OF LOGS when the units are arms of one
comparison. Each unit's cells come from `wcombsum.best`, which takes a
MINIMUM, so a unit built from three legsets sits lower than one built from two
of the same cell for no reason but the extra draw - and the gap reads as an
effect of whatever the arms differ by. Either pass equal counts, or pass every
legset as its own unit and compare the mean of the per-legset fits, which is
what the two-binary control did and is free of the bias entirely. `best`'s own
docstring carries the measurement.

`--rungs` is REQUIRED, passed through to the same fit `wcombsum.measure` does,
for the reason that file's docstring gives at length: `c_f` is a least-squares
slope over a fold that is not linear in m, so the rung set is a free parameter
of every figure printed here. A rung a log does not carry is REFUSED, never
dropped.

THIS IS A REPORT AND MUST NOT BECOME A GATE. It has no pass condition: drift is
a property of a box on a night, and a threshold on it would either red every
narrow-pool round on this fleet or be loose enough to say nothing. It is not in
`tools/preflight.py`'s roster and must not be added to it - the same rule
`cfloadsum.py` carries, for the same reason.
"""
import statistics
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import wcombsum  # noqa: E402

METRICS = ("cpu", "wall")


def unit(label, paths, rungs, rep=None):
    rows = wcombsum.legs(paths)
    N, BLOCK = wcombsum.shape(rows)
    width = BLOCK / 65536.0
    out = {"label": label, "pools": {}, "n": N, "block": BLOCK}
    fo = [float(r.get("foreign_cpu") or 0) for r in rows]
    out["foreign_med"] = statistics.median(fo)
    for t in sorted({int(r["threads"]) for r in rows}):
        fold = [r for r in rows if r["arm"] == "fold" and r["budget"] == "big"
                and int(r["threads"]) == t]
        if rep is not None:
            fold = [r for r in fold if r.get("rep") == str(rep)]
        cells = wcombsum.best(fold, lambda r: int(r["m"]))
        missing = [m for m in rungs if m not in cells]
        if missing:
            if rep is not None and not cells:
                continue
            sys.exit("REFUSED: unit %s pool t%d is missing rungs %s - a fit quietly "
                     "taken over fewer rungs than asked for is the defect --rungs "
                     "exists to prevent" % (label, t, missing))
        p = {"cells": {m: cells[m] for m in rungs}}
        for metric in METRICS:
            _a, b, _r = wcombsum.slope([float(m) for m in rungs],
                                       [float(cells[m][metric]) for m in rungs])
            p["cf_" + metric] = b / N / width
        out["pools"][t] = p
    return out


def report(units, rungs):
    pools = sorted(set.intersection(*[set(u["pools"]) for u in units]))
    print("# units, in the order given; the FIRST is the baseline every ratio is against")
    for u in units:
        print("#   %-10s foreign median %3.0f%% of one core   n=%d block=%d"
              % (u["label"], u["foreign_med"], u["n"], u["block"]))
    print("# c_f fitted over rungs m = %s on every unit, in BOTH metrics"
          % ",".join(str(m) for m in rungs))
    for t in pools:
        print()
        print("### -t%d" % t)
        print()
        print("| unit | foreign | `c_f` CPU | vs base | `c_f` WALL | vs base |")
        print("|---|---:|---:|---:|---:|---:|")
        base = units[0]["pools"][t]
        for u in units:
            p = u["pools"][t]
            print("| %s | %.0f%% | %.3fe-6 | %+.1f%% | %.3fe-7 | %+.1f%% |"
                  % (u["label"], u["foreign_med"], p["cf_cpu"] * 1e6,
                     100.0 * (p["cf_cpu"] / base["cf_cpu"] - 1.0),
                     p["cf_wall"] * 1e7,
                     100.0 * (p["cf_wall"] / base["cf_wall"] - 1.0)))
        for metric in METRICS:
            vs = [u["pools"][t]["cf_" + metric] for u in units]
            print("| **SPREAD %s** | | | | | **%.1f%%** |"
                  % (metric.upper(), 100.0 * (max(vs) / min(vs) - 1.0)))
        print()
        print("Per rung, %s, and %% against the baseline unit - "
              "which rung carries the spread is the whole question, because the "
              "top rung is the slope's longest lever:" % "/".join(METRICS))
        print()
        print("| unit | metric | " + " | ".join("m=%d" % m for m in rungs) + " |")
        print("|---|---|" + "".join("---:|" for _ in rungs))
        for u in units:
            for metric in METRICS:
                v = [float(u["pools"][t]["cells"][m][metric]) for m in rungs]
                b = [float(units[0]["pools"][t]["cells"][m][metric]) for m in rungs]
                print("| %s | %s | " % (u["label"], metric)
                      + " | ".join("%.2f (%+.1f%%)" % (x, 100.0 * (x / y - 1.0))
                                   for x, y in zip(v, b)) + " |")


def main(argv):
    rungs, by_rep, args = None, False, []
    i = 0
    while i < len(argv):
        if argv[i] == "--rungs":
            rungs = [int(x) for x in argv[i + 1].split(",") if x.strip()]
            i += 2
            continue
        if argv[i] == "--by-rep":
            by_rep = True
            i += 1
            continue
        args.append(argv[i])
        i += 1
    if rungs is None or len(rungs) < 2 or not args:
        sys.exit(__doc__)
    units = []
    for a in args:
        label, _, paths = a.partition("=")
        if not paths:
            sys.exit("REFUSED: %r is not LABEL=LOG[,LOG...]" % a)
        ps = paths.split(",")
        if by_rep:
            reps = sorted({r.get("rep") for r in wcombsum.legs(ps) if r.get("rep")},
                          key=int)
            if len(reps) < 2:
                sys.exit("REFUSED: --by-rep on %s, which carries reps %s - there is "
                         "no pair to compare" % (label, reps or "none"))
            for rp in reps:
                units.append(unit("%s.r%s" % (label, rp), ps, rungs, rep=rp))
        else:
            units.append(unit(label, ps, rungs))
    report(units, rungs)
    print()
    print("# c_f rungs: m = %s. A figure here is comparable ONLY with another fitted"
          % ",".join(str(m) for m in rungs))
    print("# on the same set - see wcombsum.py's --rungs docstring. REPORT, not a gate.")


if __name__ == "__main__":
    main(sys.argv[1:])
