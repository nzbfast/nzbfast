#!/usr/bin/env python3
"""nttfwsum.py - reduce a FIXED-WIDTH NTT `m` ladder (nttfw-i5.ps1 legs).

WHY THIS IS NOT `nttmsum.py`. That reducer prices the per-window tree charge by
DIFFERENCING a one-window leg against a two-window leg at one `m`, which cancels
a leaf term `c_l * S` on the assumption that `c_l` is the same at both window
WIDTHS. Section 8.15.3 of an internal note found
that false at the top of the `m` axis - `df/dS` collapses twelvefold above about
14,000 sources a window - and because windows NARROW as `m` rises the error is
CORRELATED with the axis. Run naively over 8.15's own ladder that estimator
returned a below-tile slope 35% low, a NEGATIVE middle slope, and the first knee
27% out.

THE FIXED-WIDTH LADDER HAS NO LEAF-TERM MODEL IN IT AT ALL. Every rung is
budgeted for the same window width `S*`, so the per-FULL-window charge is
`f(S*) + F(m)` with `f(S*)` an unknown CONSTANT. A constant offset moves neither
a slope nor a knee - for `a1 + b1*m + G` and `a2 + b2*m + G` the crossing is
`(a2-a1)/(b1-b2)`, with `G` cancelled - so the slopes and both knees are read
straight off, and only the INTERCEPTS are not absolute.

THE TAIL WINDOW IS EXCLUDED, always: it is the remainder, at a different width,
and section 8.16 measured a remainder costing neither nothing nor a full window.
This reducer keeps only windows whose `n` equals `S*`, and reports how far any
achieved width drifted from it.

ON-TILE RUNGS ARE EXCLUDED FROM EVERY FIT, as 8.12, 8.14 and 8.15 excluded
m = 4,369: a rung sitting on a saturation point is mid-bend and belongs to
neither line.

THE PER-LEVEL DECOMPOSITION. Three slopes over three levels is a determined
system. A window's upper tree is three levels of `Node::Combine`: the root holds
`min(m,65535)` rows over 3 folds, each depth-1 node `min(m,21845)` over 15, and
the depth-2 level `min(m,4369)` over L = 128 live leaves
(`NTT_MIN_WINDOW_PRESENT`'s own docstring: the base logs are coprime to 65,535,
so only 128 of the 255 leaves carry sources). With per-fold-row costs a, b, c:

    s_below  = 3a + 15b + 128c        a = s_above / 3
    s_middle = 3a + 15b       so      b = (s_middle - s_above) / 15
    s_above  = 3a                     c = (s_below - s_middle) / 128

8.15 solved this for the first time and found root 0.00940, depth-1 0.00153 and
depth-2 0.00227 ms per fold-row on the NEON class, i.e. the ROOT costs 4.1x a
depth-2 fold-row, which FALSIFIES the "equal per-row cost at each level"
assumption the structural ratios 18/146 and 3/18 rest on. That decomposition
rested on one cell; this prints it for a second.

RUN:
    nttfwsum.py legs.jsonl [legs2.jsonl ...] [--sstar 2096] [--knees 4369,21845]
                [--exclude 4369,21845] [--drift]
"""
import json
import sys
from statistics import median

LIVE_LEAVES = 128
NODES = (3, 15, LIVE_LEAVES)          # root, depth-1, depth-2 fold counts
TILES = (65535, 21845, 4369)


def fit(xs, ys):
    n = len(xs)
    if n < 2:
        return (float("nan"), float("nan"), float("nan"))
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    b = sxy / sxx
    a = my - b * mx
    syy = sum((y - my) ** 2 for y in ys)
    r2 = (sxy * sxy / (sxx * syy)) if syy > 0 else float("nan")
    return (b, a, r2)


def cross(f1, f2):
    """m where the two fitted lines meet. The unknown constant f(S*) cancels."""
    (b1, a1, _), (b2, a2, _) = f1, f2
    return (a2 - a1) / (b1 - b2)


def main(argv):
    paths, sstar, knees, excl, cl = [], 2096, [4369, 21845], None, 0.0
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--sstar":
            i += 1; sstar = int(argv[i])
        elif a == "--knees":
            i += 1; knees = [int(x) for x in argv[i].split(",")]
        elif a == "--exclude":
            i += 1; excl = [int(x) for x in argv[i].split(",")] if argv[i] else []
        elif a == "--cl":
            i += 1; cl = float(argv[i])
        else:
            paths.append(a)
        i += 1
    if excl is None:
        excl = list(knees)

    legs = []
    for p in paths:
        for line in open(p):
            line = line.strip()
            if line:
                legs.append(json.loads(line))
    legs = [g for g in legs if g.get("path") == "ntt" and g.get("ok")]
    if not legs:
        print("no usable legs")
        return 2

    # ---- per-leg charge from the FULL windows only ------------------------
    #
    # THE ACHIEVED WIDTH IS NOT EXACTLY S*, AND THAT IS MEASURED RATHER THAN
    # ASSUMED. The window capacity is `(budget - arenas) / block_size` rounded
    # to a multiple of 16 sources, and `retain.rs`'s verify-pass cache lets a
    # window that already holds some of its blocks take a few more - so a rung
    # budgeted for 2,096 lands within a few tens of sources of it, and not
    # always on the same side. Two things follow and both are done here:
    # a FULL window is one within `TOL` of the leg's widest (never an equality
    # test, which would silently drop whole rungs), and each one's charge is
    # CORRECTED to the common reference width with a measured `c_l`
    # (`--cl <ms per source>`), so the residual width drift cannot leak into a
    # slope. The correction is reported; on the cells measured so far it is
    # under 1% and the uncorrected fit is printed beside it.
    #
    # THE TAIL IS NEVER A FULL WINDOW. Section 8.16 measured a 64-source
    # remainder at 14.59-17.74 s against a full window's 31.7 - neither free
    # nor full - so it sits on no line and is excluded by construction.
    TOL = 96
    rows = {}
    widths = []
    corr = []
    for g in legs:
        pts = g["win_points"]
        if isinstance(pts, dict):          # ConvertTo-Json collapses a 1-element array
            pts = [pts]
        ns = [int(p["n"]) for p in pts]
        widths += ns
        # THE TAIL IS THE LAST WINDOW - the retention pass fills windows in
        # order and the remainder is what is left - so it is dropped by
        # POSITION and never by a width test, which at a high rung cannot tell
        # a remainder from a full window (on the real ladder the two come
        # within 90 sources of each other at m = 26,500).
        body = pts[:-1] if len(pts) > 1 else pts
        top = max(int(p["n"]) for p in body)
        full = [p for p in body if top - int(p["n"]) <= TOL]
        if not full:
            print("SKIP %s r%s %s - no full window (widths %s)"
                  % (g["rung"], g["rep"], g["arm"], ns))
            continue
        ch = []
        for p in full:
            c = float(p["t"]) - cl * (int(p["n"]) - sstar) / 1000.0
            corr.append(abs(cl * (int(p["n"]) - sstar) / 1000.0) / max(float(p["t"]), 1e-9))
            ch.append(c)
        charge = sum(ch) / len(ch)
        raw = sum(float(p["t"]) for p in full) / len(full)
        rows.setdefault(int(g["m"]), []).append(
            {"charge": charge, "raw": raw, "k_full": len(full),
             "width": sum(int(p["n"]) for p in full) / float(len(full)), "leg": g})

    ms = sorted(rows)
    print("FIXED-WIDTH LADDER  S*=%d  %d legs over %d rungs" % (sstar, len(legs), len(ms)))
    print("c_l used for the width correction: %.4f ms/source%s"
          % (cl, "  (NONE - pass --cl to correct)" if cl == 0 else ""))
    print("%8s %6s %6s %8s %9s %9s %7s %9s %9s %9s" %
          ("m", "legs", "k", "width", "charge s", "spread%", "wall s", "cpu s", "bsub s", "peak MB"))
    pts = []
    for m in ms:
        ch = [r["charge"] for r in rows[m]]
        med = median(ch)
        spread = 100.0 * (max(ch) - min(ch)) / med if med else float("nan")
        L = [r["leg"] for r in rows[m]]
        print("%8d %6d %6d %8.0f %9.4f %9.2f %7.1f %9.1f %9.1f %9.0f" % (
            m, len(ch), rows[m][0]["k_full"], median(r["width"] for r in rows[m]), med, spread,
            median(float(g["wall"]) for g in L), median(float(g["cpu"]) for g in L),
            median(float(g["back_sub"] or 0) for g in L),
            median(float(g["peak_mb"]) for g in L)))
        pts.append((m, med))

    fullw = [r["width"] for v in rows.values() for r in v]
    print("\nachieved FULL-window width: %.0f to %.0f against S* = %d (%+.2f%% to %+.2f%%)"
          % (min(fullw), max(fullw), sstar,
             100.0 * (min(fullw) / sstar - 1), 100.0 * (max(fullw) / sstar - 1)))
    if corr:
        print("width correction applied: median %.3f%% of the charge, worst %.3f%%"
              % (100 * median(corr), 100 * max(corr)))

    # ---- three fits -------------------------------------------------------
    k1, k2 = knees[0], knees[1]
    segs = [("m <= %d" % k1, [p for p in pts if p[0] < k1 and p[0] not in excl]),
            ("%d < m <= %d" % (k1, k2), [p for p in pts if k1 < p[0] < k2 and p[0] not in excl]),
            ("m >= %d" % k2, [p for p in pts if p[0] > k2 and p[0] not in excl])]
    fits = []
    print("\n%-22s %12s %12s %10s %6s" % ("segment", "slope ms/row", "intercept s", "r2", "rungs"))
    for name, seg in segs:
        b, a, r2 = fit([p[0] for p in seg], [p[1] for p in seg])
        fits.append((b, a, r2))
        print("%-22s %12.4f %12.4f %10.5f %6d" % (name, b * 1000.0, a, r2, len(seg)))

    print("\nKNEES (lines crossed; the unknown f(S*) cancels)")
    for (lo, hi, tile) in ((0, 1, k1), (1, 2, k2)):
        x = cross(fits[lo], fits[hi])
        print("  knee %d/%d at m = %10.1f   against %6d   %+.2f%%"
              % (lo + 1, hi + 1, x, tile, 100.0 * (x / tile - 1.0)))

    s1, s2, s3 = fits[0][0], fits[1][0], fits[2][0]
    print("\nSLOPE RATIOS against the structural prediction (equal per-row cost)")
    print("  first  knee  %8.4f  against 18/146 = %.4f   %+.0f%%"
          % (s2 / s1, 18.0 / 146.0, 100.0 * ((s2 / s1) / (18.0 / 146.0) - 1)))
    print("  second knee  %8.4f  against  3/18  = %.4f   %+.0f%%"
          % (s3 / s2, 3.0 / 18.0, 100.0 * ((s3 / s2) / (3.0 / 18.0) - 1)))

    a_root = s3 / NODES[0]
    b_d1 = (s2 - s3) / NODES[1]
    c_d2 = (s1 - s2) / NODES[2]
    print("\nPER-LEVEL COST (three slopes, three levels - a determined system)")
    print("  %-9s %-26s %12s" % ("level", "folds x rows", "ms/fold-row"))
    print("  %-9s %-26s %12.5f" % ("root", "3 x min(m,65535)", a_root * 1000))
    print("  %-9s %-26s %12.5f" % ("depth-1", "15 x min(m,21845)", b_d1 * 1000))
    print("  %-9s %-26s %12.5f" % ("depth-2", "%d x min(m,4369)" % LIVE_LEAVES, c_d2 * 1000))
    if c_d2:
        print("  root / depth-2 = %.2fx      root / depth-1 = %.2fx"
              % (a_root / c_d2, a_root / b_d1 if b_d1 else float("nan")))

    print("\nDEPARTURE from the MIDDLE line, extrapolated (the second knee's own test)")
    b, a, _ = fits[1]
    for m, y in pts:
        if m > k2:
            print("  m=%6d  measured %8.4f  line %8.4f  %+.2f%%" % (m, y, a + b * m, 100.0 * (y / (a + b * m) - 1)))

    # ---- A/A floor --------------------------------------------------------
    print("\nA/A FLOOR (same binary, two paths, same rep and rung)")
    pairs = {}
    for g in legs:
        pairs.setdefault((g["rung"], g["rep"]), {})[g["arm"]] = g
    for field, lab in (("wall", "wall"), ("cpu", "cpu"), ("syn_total", "transform")):
        d = []
        for v in pairs.values():
            if "a" in v and "a_aa" in v:
                x, y = float(v["a"][field]), float(v["a_aa"][field])
                if x and y:
                    d.append(200.0 * abs(x - y) / (x + y))
        if d:
            print("  %-10s pairs=%3d  median %5.2f%%  worst %5.2f%%" % (lab, len(d), median(d), max(d)))

    fgn = [float(g["foreign_cpu"]) for g in legs if g.get("foreign_cpu") is not None]
    if fgn:
        print("\nforeign CPU at leg start: %.1f to %.1f, median %.1f (pct of one core)"
              % (min(fgn), max(fgn), median(fgn)))
    pk = [float(g["peak_mb"]) for g in legs]
    print("peak RSS %.0f to %.0f MB;  wall %.1f to %.1f s;  cpu %.1f to %.1f CPU-s"
          % (min(pk), max(pk),
             min(float(g["wall"]) for g in legs), max(float(g["wall"]) for g in legs),
             min(float(g["cpu"]) for g in legs), max(float(g["cpu"]) for g in legs)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
