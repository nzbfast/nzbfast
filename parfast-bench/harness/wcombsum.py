#!/usr/bin/env python3
"""wcombsum.py - reduce wcomb.ps1 LEG lines to the windowed-transform constants.

    wcombsum.py measure  LOG [LOG...]     c_f, c_l, c_w and k = c_w / c_f per thread count
    wcombsum.py validate LOG [LOG...]     fold / force / auto per m, and what auto chose

    --rungs 192,512,1024,2048   fit `c_f` over THESE m rungs only (measure only)

Written 14 Sep 2026 for lane parfast-x86-window-combine-measure-14sep; the
definitions are an internal note
section 3a's, so a number printed here is comparable with the NEON one there.
All three constants are per 64 KiB of width (a slab's width scales a window's
combine and a block's width scales the fold, so each is divided by its own
width / 65,536). **Both halves of that normalisation are load-bearing and the
fold's half was missing until 16 Sep 2026**: `c_f` was divided by n alone, so
on a fixture whose block is not 64 KiB it came out per BLOCK-row while `c_w`
was per 64 KiB, and `k = c_w / c_f` - the ratio this file exists to print -
was understated by exactly the width ratio (16x on a 1 MiB fixture). Every
64 KiB log reduces to the same numbers it always did (width = 1); a 1 MiB one
did not exist before that date. `n` comes off the LEG lines for the same
reason it has to: it is 16,384 only on the original fixture.

  c_f  the fold, CPU-s per SOURCE-ROW per 64 KiB: the least-squares slope of
       whole-process CPU in m over the `fold`, no-`-m` legs, divided by n and
       by the fixture's block / 65,536. That is
       the NEON constant's convention (n, not the n - m present); the slope in
       m * (n - m) is printed beside it so the size of that choice is visible.
  c_l  the leaves, CPU-s per source: leaves / (n - m), one-window legs only.
  c_w  the combine, CPU-s per ROW per WINDOW: each window's depth0 - leaves
       (the profile counters are swapped to zero at every report, so each
       `ntt profile` line is one window), averaged over the leg's windows and
       divided by min(m, 4369) rows - the depth-2 tile is where it plateaus.

Every cell is the MINIMUM over reps (the best estimate of the quiet cost), and
a leg whose SHA gate did not restore every member, or whose rc is not 0, is
refused rather than reduced.

**THE RUNG SET IS A FREE PARAMETER OF `c_f`, AND `--rungs` IS WHERE IT IS
STATED.** `c_f` is a least-squares SLOPE in m, so it is a constant only if the
fold is linear in m - and on the i5 nibble part it is not: fold CPU per row
falls from 0.120 at m = 192 to 0.072 at m = 4,096. A slope is most sensitive to
its extreme points, so WHICH rungs the fit happened to see moves the answer.
Refitting the 14 Sep i5 `-t12` legs over 192..2048 instead of 192..4096 - the
same legs, the same log, the same night - moves `c_f` 18% and takes
`k` from 312 to 264 (an internal note, the
16 Sep nibble section, and the 16 Sep estimator section under it). Nobody
recorded that choice as a choice, which is the whole reason this flag exists:
a fit quoted without its rung set cannot be reproduced or compared, and two
fitted figures must never be compared across different rung sets without
refitting both on the rungs they SHARE. The commonest reason two rounds cannot
share one is the fixture: a `-c2048` 1 MiB fixture has 2,048 recovery blocks
and cannot host an m = 4,096 rung at all.

`--rungs` scopes to the `c_f` SLOPE FIT ONLY and deliberately not to `c_w`,
which is a per-cell ratio rather than a fit and so does not inherit the rung
set the same way; `k = c_w / c_f` then moves only through the half that is
actually rung-sensitive. The rung set used is printed beside every `c_f` and
every `k`, with or without the flag, so a number copied out of this reducer
carries its own provenance. A rung named in `--rungs` that the log does not
carry is REFUSED and named, never silently dropped - a fit quietly taken over
fewer rungs than asked for is the exact defect the flag exists to prevent.
"""
import re
import statistics
import sys

TILE = 4369


def legs(paths):
    out = []
    for p in paths:
        for line in open(p, encoding="utf-8", errors="replace"):
            line = line.strip().lstrip("﻿")
            if not line.startswith("LEG "):
                continue
            kv = dict(t.split("=", 1) for t in line[4:].split() if "=" in t)
            if kv.get("rc") != "0" or kv.get("restored") != "16/16":
                sys.exit("REFUSED: leg did not restore: " + line[:200])
            kv["_src"] = p
            out.append(kv)
    if not out:
        sys.exit("REFUSED: no LEG lines in " + " ".join(paths))
    return out


# A log is called out when its median foreign CPU is both this many times the
# quietest log's IN THE SAME INVOCATION and past an absolute floor, on
# rowgate.py's numbers and for its reasons - see the `foreign` docstring there.
# A PRINTED WARNING and never a refusal.
NOISY_RATIO = 3.0
NOISY_FLOOR = 25.0


def foreign_by_log(rows):
    """Foreign CPU per SOURCE LOG, which is per ladder the way these are banked.

    The per-cell `foreign=` fields `measure` already prints are one leg each,
    and a whole ladder run under an indexer pass prints a column of
    unremarkable ones with no total. That is what let the 16 Sep 2026
    windowed-ask round reduce two ladders at 77% and 88% of a core alongside a
    clean one at 9% and say nothing
    (an internal note, "The windowed ask's
    FORM"). Printed before the reduction rather than after it, so a reader
    knows which numbers to distrust before reading any of them.
    """
    by = {}
    for r in rows:
        by.setdefault(r["_src"], []).append(r)
    stats = {}
    for src, rs in by.items():
        b = [float(r.get("foreign_cpu") or 0) for r in rs]
        a = [float(r.get("foreign_after") or 0) for r in rs]
        stats[src] = (statistics.median(b), max(b), statistics.median(a), len(rs))
    quietest = min(v[0] for v in stats.values())
    print("# foreign CPU per log, % of ONE core (median over the legs, then max, then after-leg median)")
    for src in sorted(stats):
        med, mx, after, n = stats[src]
        print("#   %-58s %3d legs  median %3.0f%%  max %3.0f%%  after %3.0f%%"
              % (src.split("/")[-1].split("\\")[-1], n, med, mx, after))
        if len(stats) > 1 and med >= NOISY_FLOOR and med >= NOISY_RATIO * max(quietest, 1.0):
            print("#     NOISY: %.1fx the quietest log here (%.0f%%) - this log's constants are suspect"
                  % (med / max(quietest, 1.0), quietest))


def fnum(s):
    return float(s) if s not in (None, "") else None


def best(rows, key):
    cells = {}
    for r in rows:
        k = key(r)
        if k not in cells or float(r["cpu"]) < float(cells[k]["cpu"]):
            cells[k] = r
    return cells


def slope(xs, ys):
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    resid = max(abs(y - (a + b * x)) for x, y in zip(xs, ys))
    return a, b, resid


def shape(rows):
    """The fixture's (n, block) - refused rather than guessed if a run mixes two.

    A LEG line carried neither field until 15 Sep 2026 (`slice=`/`n=` came with
    the rowgate phase), and every log written before that is the one fixture
    this script was written for: 16 x 64 MiB at 64 KiB, n = 16,384. So an
    absent field falls back to that shape and SAYS it did, rather than reducing
    a log whose width nobody can read.
    """
    ns = {int(r["n"]) for r in rows if "n" in r}
    bs = {int(r["slice"]) for r in rows if "slice" in r}
    if len(ns) > 1 or len(bs) > 1:
        sys.exit("REFUSED: logs mix fixtures (n=%s slice=%s) - reduce one shape at a time"
                 % (sorted(ns), sorted(bs)))
    if not ns or not bs:
        print("# no slice=/n= on these LEG lines (pre-15 Sep 2026): assuming the "
              "original fixture, n = 16,384 at 64 KiB")
    return (ns.pop() if ns else 16384), (bs.pop() if bs else 65536)


def measure(rows, rungs=None):
    N, BLOCK = shape(rows)
    fold_width = BLOCK / 65536.0
    print("# fixture n=%d block=%d B (fold normalised by %.4g x 64 KiB)" % (N, BLOCK, fold_width))
    for t in sorted({int(r["threads"]) for r in rows}):
        tr = [r for r in rows if int(r["threads"]) == t]
        fold = best([r for r in tr if r["arm"] == "fold" and r["budget"] == "big"], lambda r: int(r["m"]))
        print("== threads=%d" % t)
        if len(fold) < 2:
            print("  fold: fewer than two rungs, no slope")
            continue
        ms = sorted(fold)
        if rungs is not None:
            missing = [m for m in rungs if m not in fold]
            if missing:
                sys.exit("REFUSED: --rungs names m=%s, which this log's threads=%d fold legs do not carry "
                         "(it has %s). A fit taken over fewer rungs than asked for is the defect --rungs exists "
                         "to prevent." % (",".join(str(m) for m in missing), t, ",".join(str(m) for m in ms)))
            if len(rungs) < 2:
                sys.exit("REFUSED: --rungs needs at least two rungs to fit a slope")
            ms = sorted(rungs)
        rungtxt = ",".join(str(m) for m in ms)
        cpus = [float(fold[m]["cpu"]) for m in ms]
        a, b, res = slope(ms, cpus)
        _, bp, resp = slope([m * (N - m) for m in ms], cpus)
        for m in ms:
            r = fold[m]
            print("  fold m=%-5d cpu=%7.2f wall=%6.2f path=%s reps=%d load=%s/%s foreign=%s/%s"
                  % (m, float(r["cpu"]), float(r["wall"]), r["path"],
                     sum(1 for x in tr if x["arm"] == "fold" and x["budget"] == "big" and int(x["m"]) == m),
                     r["load_before"], r["load_after"], r["foreign_cpu"], r["foreign_after"]))
        c_f = b / N / fold_width
        print("  c_f = %.3e CPU-s per source-row per 64 KiB (slope %.4f CPU-s/row over n=%d, block %d B, intercept %.2f, worst residual %.2f)"
              % (c_f, b, N, BLOCK, a, res))
        print("  c_f FITTED OVER RUNGS m = %s%s - a c_f quoted without this cannot be compared with another"
              % (rungtxt, " (--rungs)" if rungs is not None else " (every fold rung in the log)"))
        print("  c_f' = %.3e per PRESENT source-row per 64 KiB (slope in m*(n-m), worst residual %.2f)"
              % (bp / fold_width, resp))
        force = best([r for r in tr if r["arm"] == "force"], lambda r: (r["budget"], int(r["m"])))
        cws, cls = [], []
        for (budget, m) in sorted(force, key=lambda k: (k[0] != "big", k[1])):
            r = force[(budget, m)]
            cm = fnum(r.get("combine_mean"))
            width = int(r["slab_width"]) / 65536.0
            if r["path"] != "ntt" or cm is None:
                print("  force %-3s m=%-5d path=%s - NO PROFILE, not reduced" % (budget, m, r["path"]))
                continue
            cw = cm / (min(m, TILE) * width)
            cws.append((budget, m, cw))
            cl = ""
            if r["slabs"] == "1" and int(r["prof_lines"]) == 1:
                clv = float(r["leaves_sum"]) / ((N - m) * width)
                cls.append(clv)
                cl = " c_l=%.3e" % clv
            print("  force %-3s m=%-5d cpu=%6.2f wall=%5.2f windows=%s prof=%s slabs=%s w=%s W=%s combine/win=%.3f (list %s) c_w=%.3e%s"
                  % (budget, m, float(r["cpu"]), float(r["wall"]), r["windows"], r["prof_lines"], r["slabs"],
                     r["slab_width"], r["ntt_w"], cm, r["combine_list"], cw, cl))
        if cws:
            med = statistics.median(c for (_, _, c) in cws)
            print("  c_w median over %d cells = %.3e (range %.3e .. %.3e)"
                  % (len(cws), med, min(c for (_, _, c) in cws), max(c for (_, _, c) in cws)))
            print("  k = c_w / c_f = %.0f   (per present source-row: %.0f)   [c_f rungs m = %s]"
                  % (med / c_f, med / (bp / fold_width), rungtxt))
            if cls:
                print("  c_l median = %.3e; single-window crossover c_l/c_f = %.0f rows" % (statistics.median(cls), statistics.median(cls) / c_f))


def validate(rows):
    for t in sorted({int(r["threads"]) for r in rows}):
        tr = [r for r in rows if int(r["threads"]) == t and r["budget"] == "128"]
        cells = best(tr, lambda r: (int(r["m"]), r["arm"]))
        print("== threads=%d, -m128, CPU-s best of reps (wall)" % t)
        # `autoalt` is auto on wcomb.ps1's -AltBin (the binary before a change).
        print("  %5s  %15s  %15s  %15s  %-4s  %9s  %15s  %-4s  %s" % (
            "m", "fold", "force", "auto", "path", "auto/best", "autoalt", "path", "auto W, windows, slabs"))
        for m in sorted({k[0] for k in cells}):
            def cell(arm):
                r = cells.get((m, arm))
                return ("%7.2f (%5.2f)" % (float(r["cpu"]), float(r["wall"]))) if r else "-"
            au, alt = cells.get((m, "auto")), cells.get((m, "autoalt"))
            fo, fc = cells.get((m, "fold")), cells.get((m, "force"))
            ratio = ""
            if au and fo and fc:
                ratio = "%.2f" % (float(au["cpu"]) / min(float(fo["cpu"]), float(fc["cpu"])))
            print("  %5d  %15s  %15s  %15s  %-4s  %9s  %15s  %-4s  %s" % (
                m, cell("fold"), cell("force"), cell("auto"), au["path"] if au else "-", ratio,
                cell("autoalt"), alt["path"] if alt else "-",
                ("%s, %s, %s" % (au["ntt_w"], au["windows"], au["slabs"])) if au else ""))


if __name__ == "__main__":
    argv = sys.argv[1:]
    rungs = None
    if "--rungs" in argv:
        i = argv.index("--rungs")
        if i + 1 >= len(argv):
            sys.exit("REFUSED: --rungs needs a comma-separated list of m values")
        try:
            rungs = [int(x) for x in argv[i + 1].split(",") if x.strip()]
        except ValueError:
            sys.exit("REFUSED: --rungs takes integers, e.g. --rungs 192,512,1024,2048")
        del argv[i:i + 2]
    if len(argv) < 2 or argv[0] not in ("measure", "validate"):
        sys.exit(__doc__)
    if rungs is not None and argv[0] != "measure":
        sys.exit("REFUSED: --rungs scopes the c_f slope fit, which only `measure` does")
    rows = legs(argv[1:])
    foreign_by_log(rows)
    if argv[0] == "measure":
        measure(rows, rungs)
    else:
        validate(rows)
