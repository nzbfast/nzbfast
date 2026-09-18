#!/usr/bin/env python3
"""cfloadsum.py - the LOAD TERM table: one `wcomb.ps1 -Phase measure` arm per row.

    cfloadsum.py --rungs 192,512,1024,2048,4096 LABEL=LOG[,LOG...] [LABEL=...]

Each argument is one ARM - a label and the logs that reduce to it - and the
output is three tables across the arms: the fold's CPU per row at each rung,
the fitted `c_f`, and `c_w`, each beside that arm's median `foreign_cpu`.
Ratios against the FIRST arm are printed under each table, because the question
this exists for is "how much does load move the number", which is a ratio and
not a pair of numbers a reader has to divide by eye.

WHY IT IS A SEPARATE SCRIPT AND NOT A FLAG ON wcombsum.py. wcombsum reduces ONE
sitting: it takes a set of logs, calls them a cell, and prints that cell's
constants. Everything here is a comparison ACROSS cells, and the two questions
want opposite things from the same logs - wcombsum's `foreign CPU per log`
block is a warning that a number may be unusable, while here foreign CPU is the
INDEPENDENT VARIABLE and a high one is the point. Keeping them apart stops the
second reading contaminating the first.

`--rungs` is passed straight through to wcombsum's fit and is REQUIRED here
rather than optional, for the reason wcombsum's own docstring gives at length:
`c_f` is a least-squares slope over a fold that is not linear in m, so the rung
set is a free parameter of the answer, and two fitted figures must never be
compared across different rung sets. This script exists to compare fitted
figures, so it will not let the set be implicit.

WHAT A RATIO PRINTED HERE MAY AND MAY NOT BE USED FOR. It is a coefficient
against ONE PARTICULAR synthetic load on ONE box. A busy loop, a compiler and
an Adobe updater do not stress the same resource, and this repo has already
been bitten by reading an aggregate difference as evidence for one mechanism
(memory topic `nzbfast-tls-receive-path`, its METHOD ERROR section). What a
number here licenses is a THRESHOLD - above roughly X% of a core, stop fitting
and quiet the box first - and never a post-hoc correction applied to a round
that was measured dirty. No banked cell is ever to be retro-corrected from it.
"""
import statistics
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import wcombsum  # noqa: E402


def arm(label, paths, rungs):
    rows = wcombsum.legs(paths)
    N, BLOCK = wcombsum.shape(rows)
    fold_width = BLOCK / 65536.0
    out = {"label": label, "paths": paths, "pools": {}}
    fo = [float(r.get("foreign_cpu") or 0) for r in rows]
    out["foreign_med"] = statistics.median(fo)
    out["foreign_max"] = max(fo)
    out["legs"] = len(rows)
    for t in sorted({int(r["threads"]) for r in rows}):
        tr = [r for r in rows if int(r["threads"]) == t]
        fold = wcombsum.best(
            [r for r in tr if r["arm"] == "fold" and r["budget"] == "big"],
            lambda r: int(r["m"]))
        ms = sorted(fold)
        missing = [m for m in rungs if m not in fold]
        if missing:
            sys.exit("REFUSED: arm %s pool t%d is missing rungs %s - a fit quietly "
                     "taken over fewer rungs than asked for is the defect --rungs "
                     "exists to prevent" % (label, t, missing))
        xs = [float(m) for m in rungs]
        ys = [float(fold[m]["cpu"]) for m in rungs]
        _a, b, _r = wcombsum.slope(xs, ys)
        cf = b / N / fold_width
        # c_w: the median over the force cells, which is the reducer's PUBLISHED
        # cell and the less noisy of the two readings wcombsum prints - the
        # single resident m = 1,024 cell disagrees between binaries where the
        # medians do not (the two-binary control's stated limits). Computed the
        # same way wcombsum.measure computes it, off `combine_mean` and the
        # slab width, because a LEG line does not carry `c_w` - it carries the
        # counters c_w is derived from, and deriving it twice two ways is how
        # two reducers drift.
        force = wcombsum.best([r for r in tr if r["arm"] == "force"],
                              lambda r: (r["budget"], int(r["m"])))
        cws = []
        for (budget, m) in force:
            r = force[(budget, m)]
            cm = wcombsum.fnum(r.get("combine_mean"))
            if r["path"] != "ntt" or cm is None:
                continue
            width = int(r["slab_width"]) / 65536.0
            cws.append(cm / (min(m, wcombsum.TILE) * width))
        out["pools"][t] = {
            "cf": cf,
            "per_row": {m: float(fold[m]["cpu"]) / m for m in ms},
            "cw": statistics.median(cws) if cws else None,
            "rungs_avail": ms,
        }
    return out


def table(arms, pools, rungs, title, get, fmt, ratio=True):
    print()
    print("### " + title)
    print()
    head = "| arm | foreign med | " + " | ".join("m=%d" % m for m in rungs) + " |"
    print(head)
    print("|---|---:|" + "".join("---:|" for _ in rungs))
    for t in pools:
        print("| **-t%d** | | " % t + " | ".join("" for _ in rungs) + " |")
        base = None
        for a in arms:
            vals = [get(a, t, m) for m in rungs]
            if base is None:
                base = vals
            print("| %s | %.0f%% | " % (a["label"], a["foreign_med"])
                  + " | ".join(fmt % v if v is not None else "-" for v in vals) + " |")
            if ratio and a is not arms[0]:
                rr = ["%+.1f%%" % (100.0 * (v / b - 1.0)) if v and b else "-"
                      for v, b in zip(vals, base)]
                print("| %s vs %s | | " % (a["label"], arms[0]["label"])
                      + " | ".join(rr) + " |")


def main(argv):
    rungs = None
    args = []
    i = 0
    while i < len(argv):
        if argv[i] == "--rungs":
            rungs = [int(x) for x in argv[i + 1].split(",")]
            i += 2
            continue
        args.append(argv[i])
        i += 1
    if rungs is None or not args:
        sys.exit(__doc__)
    arms = []
    for a in args:
        label, _, paths = a.partition("=")
        if not paths:
            sys.exit("REFUSED: %r is not LABEL=LOG[,LOG...]" % a)
        arms.append(arm(label, paths.split(","), rungs))
    pools = sorted(set.intersection(*[set(a["pools"]) for a in arms]))

    print("# arms, in the order given; the FIRST is the baseline every ratio is against")
    for a in arms:
        print("#   %-10s %3d legs  foreign median %3.0f%% of one core, max %3.0f%%   %s"
              % (a["label"], a["legs"], a["foreign_med"], a["foreign_max"],
                 " ".join(p.split("/")[-1] for p in a["paths"])))
    print("# c_f fitted over rungs m = %s on every arm" % ",".join(str(m) for m in rungs))

    table(arms, pools, rungs,
          "Fold CPU per row (`cpu`/m, minimum over reps) - flat for a linear fold",
          lambda a, t, m: a["pools"][t]["per_row"].get(m), "%.4f")

    print()
    print("### The fitted constants")
    print()
    print("| arm | foreign med | " + " | ".join("`c_f` -t%d | `c_w` -t%d | `k` -t%d" % (t, t, t)
                                                for t in pools) + " |")
    print("|---|---:|" + "".join("---:|---:|---:|" for _ in pools))
    for a in arms:
        cells = []
        for t in pools:
            p = a["pools"][t]
            cells.append("%.3fe-6" % (p["cf"] * 1e6))
            cells.append("%.3fe-4" % (p["cw"] * 1e4) if p["cw"] else "-")
            cells.append("%d" % round(p["cw"] / p["cf"]) if p["cw"] else "-")
        print("| %s | %.0f%% | " % (a["label"], a["foreign_med"]) + " | ".join(cells) + " |")
    base = arms[0]
    for a in arms[1:]:
        cells = []
        for t in pools:
            p, q = a["pools"][t], base["pools"][t]
            cells.append("%+.1f%%" % (100.0 * (p["cf"] / q["cf"] - 1.0)))
            cells.append("%+.1f%%" % (100.0 * (p["cw"] / q["cw"] - 1.0)) if p["cw"] and q["cw"] else "-")
            cells.append("")
        print("| %s vs %s | | " % (a["label"], base["label"]) + " | ".join(cells) + " |")
    print()
    print("# c_f rungs: m = %s. A figure here is comparable ONLY with another fitted"
          % ",".join(str(m) for m in rungs))
    print("# on the same set - see wcombsum.py's --rungs docstring.")


if __name__ == "__main__":
    main(sys.argv[1:])
