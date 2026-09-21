#!/usr/bin/env python3
"""floornull.py - a random-drop null over the A/A FLOOR, not over a crossover.

    floornull.py                 # the per-rung table (exhaustive enumeration)
    floornull.py --joint         # the whole table, d-matched, exact (no draws)
    floornull.py --global 200 7  # the whole-file draw, 200 draws at seed 7
    floornull.py --selftest      # pins this reduction to rowgate.py's own output

Written 18 Sep 2026 for lane `rowgate-64k-verdict-flip-null-18sep`, commissioned
by item 2 of
an internal note.
Reduction over banked data: no leg was run, no box or rig lock taken, no
constant moved, nothing under crates/ touched.

WHAT IS DIFFERENT HERE, AND IT IS THE WHOLE POINT. Every random-drop null on
this fleet so far - the guest-steal retrospective's and the filtered-fit
audit's - has been over a CROSSOVER or a fitted LOCATION. A rowgate per-rung
verdict is neither. `rowgate.py`'s read_ladder compares the fold/force CPU
ratio at a rung against that rung's A/A floor, and that floor is

    floor = max(aa["fold"], aa["force"]),  aa[b] = max over reps of
            |cpu(b, rep) - cpu(b2, rep)| / min(...)

a WORST over reps. A worst can only SHRINK when legs are dropped, so ANY
filter mechanically loosens the bar every verdict is measured against. The
retrospective's section 4.1 says that is almost certainly all the 64 KiB
verdict flips are, and records that nobody has shown it is ONLY that. This
file is the showing.

WHY THIS NULL IS ENUMERATED AND NOT SAMPLED. A rowgate cell is exactly eight
legs - {fold, force, force2, fold2} x {rep 1, rep 2} - and the steal filter
removes d of them, d in 0..3 over this round. C(8,1) = 8, C(8,2) = 28,
C(8,3) = 56. So the null family is enumerated IN FULL at every rung: there is
no seed to argue about and no unstable tail, which is the one weakness the
retrospective names about its own method (one cell read P = 0.01 on 100 draws
and 0.095 on 200). The exhaustive count is also the headline result on its own
- a one-leg drop has a null of EIGHT MEMBERS, so its smallest attainable P is
0.125 and it cannot be significant at any conventional level however the
arithmetic falls.

WHY THE PER-CELL FAMILY IS THE RIGHT ONE. The floor and the verdict at a rung
are computed from that rung's eight legs and nothing else, so a whole-file draw
reaches a rung ONLY through the legs it happens to remove from that rung: the
whole-file null is a MIXTURE of these per-cell families over how many legs the
draw took from the cell. Conditioning on d - the number the steal filter
actually removed there - is therefore the exact null for the question asked,
and the mixture is the looser instrument. `--global` runs the mixture anyway,
as the cross-check the filtered-fit lane ran between its enumeration and its
samples.

READ THE WIDTH, NEVER THE PERCENTILE. A filter chosen for a purpose lands at
the extreme of its own null by construction, so an extreme percentile is the
filter working, not a result (the filtered-fit lane's 8.17 cell sits at
percentile 100.0 and is the SURVIVING one). What separates a real result from
a shrinking sample is how wide the null is relative to the quantity - and here
the quantity is a floor in per cent and the bar it is compared against is a
ratio a few per cent from 1.0, so a null tens of per cent wide is an instrument
that cannot resolve a rung whatever it prints.

THE DECOMPOSITION COLUMNS. A steal filter moves TWO things: the floor (down,
always) and the arm medians (either way), hence the F/T ratio. So the table
carries both counterfactuals - the filtered ratio judged against the UNFILTERED
floor, and the unfiltered ratio judged against the FILTERED floor - which says
directly which half of the filter produced a flip. This is not a null; it is
the mechanism the null then prices.

THE SELFTEST PINS THE REDUCTION, and REFUSES rather than skipping. A null over
a reduction that is not the published one is a null over nothing, so
`--selftest` re-runs `rowgate.py read` over the banked legs at both the
unfiltered and the `< 8.00` steal settings, parses its printed table, and
requires this file's floor and verdict to match every row. It refuses if the
legs, the reducer or a parsed row are missing, and refuses if it reached zero
rows - failing to find is failing, and a green line over zero cases is the
shape of every rubber-stamp incident in this repo.

PATHS ARE RESOLVED RELATIVE TO THIS FILE so the copy that
website/tools/export_parfast_evidence.py mirrors into
website/parfast-bench/rounds/ runs unchanged: both the legs
(../rowgate-2026-09-15/) and the reducer (../../harness/) are mirrored beside
it.
"""
import itertools
import json
import os
import random
import re
import statistics as st
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEGS = os.path.join(HERE, "..", "rowgate-2026-09-15", "epyc9354p-avx512-64k.jsonl")
ROWGATE = os.path.join(HERE, "..", "..", "harness", "rowgate.py")
STEALSUB = os.path.join(HERE, "..", "..", "harness", "stealsub.py")
THRESHOLD = 8.00          # the steal rung the retrospective's 4.1 table quotes
BASES = ("fold", "force")


def load():
    if not os.path.exists(LEGS):
        sys.exit("REFUSED: the banked legs are not at %s - failing to find is failing" % LEGS)
    legs = [json.loads(l) for l in open(LEGS) if l.strip()]
    lad = [r for r in legs if r["phase"] in ("ladder", "rowgate", "create")]
    if not lad:
        sys.exit("REFUSED: %s carries no ladder leg" % LEGS)
    return lad


def cells(lad):
    """{(label, path, threads, m): [legs]} - rowgate.py's own grouping."""
    out = {}
    for r in lad:
        k = (r["label"], "create" if r["phase"] == "create" else "repair", r["threads"], r["m"])
        out.setdefault(k, []).append(r)
    return out


def reduce_cell(c):
    """rowgate.py read_ladder's per-cell arithmetic, re-implemented.

    Returns (floor, ratio, verdict) or None where read_ladder `continue`s -
    an arm group emptied by the drop, which is not a verdict and must not be
    counted as one."""
    def arm(a):
        return [r for r in c if r["arm"] == a]
    fold, force = arm("fold") + arm("fold2"), arm("force") + arm("force2")
    if not fold or not force:
        return None
    aa = {"fold": 0.0, "force": 0.0}
    for base in BASES:
        for rep in {r["rep"] for r in c}:
            a = [r["cpu"] for r in arm(base) if r["rep"] == rep]
            b = [r["cpu"] for r in arm(base + "2") if r["rep"] == rep]
            if a and b:
                aa[base] = max(aa[base], abs(a[0] - b[0]) / min(a[0], b[0]))
    cF, cT = st.median(r["cpu"] for r in fold), st.median(r["cpu"] for r in force)
    floor = max(aa.values())
    return floor, cF / cT, call(cF / cT, floor)


def call(ratio, floor):
    if ratio - 1 > floor:
        return "ntt"
    if 1 / ratio - 1 > floor:
        return "fold"
    return "unres"


def kept(c, thr=None):
    thr = THRESHOLD if thr is None else thr
    return [r for r in c if isinstance(r.get("steal_pct"), (int, float)) and r["steal_pct"] < thr]


def effect(ratio):
    """The rung's effect as a positive per-unit figure, on the same scale as
    the floor it is compared against. THIS is the number the null's width has
    to be read against: a null of floors that straddles it means the verdict
    is decided by which legs happened to survive and not by the arms."""
    return max(ratio - 1.0, 1.0 / ratio - 1.0)


def pct_le(nulls, obs):
    """Share of the null family at or below the observed value, in per cent.

    The observed IS a member of the family (the steal filter drops d legs and
    the family is every way of dropping d), so `<=` is the well-defined
    reading and no interpolation is wanted."""
    return 100.0 * sum(1 for v in nulls if v <= obs + 1e-12) / len(nulls)


def quant(vals, q):
    v = sorted(vals)
    if len(v) == 1:
        return v[0]
    i = q * (len(v) - 1)
    lo = int(i)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (i - lo) * (v[hi] - v[lo])


def enumerate_cell(c):
    """Every way of dropping the SAME NUMBER of legs the steal filter drops."""
    k = kept(c)
    d = len(c) - len(k)
    fam = [reduce_cell(list(s)) for s in itertools.combinations(c, len(k))]
    return d, [f for f in fam if f is not None], len(fam)


def table():
    lad = load()
    cs = cells(lad)
    print("floornull - the A/A FLOOR under a random drop of the same size as the "
          "steal filter's, 64 KiB EPYC guest, steal < %.2f%%" % THRESHOLD)
    print("legs %d, %d cells of %d; the null at each rung is EXHAUSTIVE - every "
          "C(8, d) way of dropping d legs" % (len(lad), len(cs), 8))
    print()
    print("  %-5s %4s %2s | %6s %-6s | %6s %6s %-6s | %6s %6s %6s %6s %5s | %5s %5s | %-5s %-5s | %s"
          % ("cell", "m", "d", "floor0", "v0", "effS", "floorS", "vS", "nmed", "np5", "np95",
             "pctl", "n", "P(vS)", "P(fl)", "ratio", "floor", "reading"))
    rows = []
    for key in sorted(cs, key=lambda k: (k[2], k[3])):
        c = cs[key]
        base = reduce_cell(c)
        d, fam, nfam = enumerate_cell(c)
        sf = reduce_cell(kept(c))
        if d and not fam:
            sf = None
        if base is None:
            sys.exit("REFUSED: cell %s does not reduce over its whole 8 legs - "
                     "unexpected shape" % (key,))
        f0, r0, v0 = base
        if sf is None:
            # The filter emptied an arm group, so rowgate.py drops the rung
            # from its table entirely. That is not a flip and must not be
            # counted as one: it is a rung with no verdict at all.
            rows.append((key, d, f0, v0, 0.0, 0.0, "GONE", None, None, None, None, nfam,
                         None, None, "-", "-", "the filter left no %s leg" %
                         ("fold" if not [r for r in kept(c) if r["arm"].startswith("fold")] else "force")))
            continue
        fS, rS, vS = sf
        if d == 0:
            rows.append((key, d, f0, v0, effect(rS), fS, vS, None, None, None, None, nfam, None, None,
                         "-", "-", "no leg dropped"))
            continue
        floors = [f for f, _, _ in fam]
        verds = [v for _, _, v in fam]
        pv = 100.0 * sum(1 for v in verds if v == vS) / len(verds)
        pf = 100.0 * sum(1 for v in verds if v != v0) / len(verds)
        # Which half of the filter moved the verdict: the ratio, or the floor?
        only_ratio = call(rS, f0)     # filtered medians, UNFILTERED floor
        only_floor = call(r0, fS)     # unfiltered medians, FILTERED floor
        reading = read_row(v0, vS, only_ratio, only_floor, pf, floors)
        rows.append((key, d, f0, v0, effect(rS), fS, vS, st.median(floors), quant(floors, 0.05),
                     quant(floors, 0.95), pct_le(floors, fS), len(fam), pv, pf,
                     only_ratio, only_floor, reading))
    for (key, d, f0, v0, eS, fS, vS, nmed, np5, np95, pctl, n, pv, pf, orat, oflr, reading) in rows:
        flip = "*" if vS != v0 else " "
        if vS == "GONE":
            print("  %-5s %4d %2d | %5.1f%% %-6s | %6s %6s %-6s%s| %6s %6s %6s %6s %5s | %5s %5s | %-5s %-5s | %s"
                  % ("t%d" % key[2], key[3], d, 100 * f0, v0, "-", "-", "GONE", " ",
                     "-", "-", "-", "-", "-", "-", "-", orat, oflr, reading))
            continue
        if nmed is None:
            print("  %-5s %4d %2d | %5.1f%% %-6s | %5.1f%% %5.1f%% %-6s%s| %6s %6s %6s %6s %5d | %5s %5s | %-5s %-5s | %s"
                  % ("t%d" % key[2], key[3], d, 100 * f0, v0, 100 * eS, 100 * fS, vS, flip,
                     "-", "-", "-", "-", n, "-", "-", orat, oflr, reading))
        else:
            straddle = "!" if np5 <= eS <= np95 else " "
            print("  %-5s %4d %2d | %5.1f%% %-6s | %5.1f%% %5.1f%% %-6s%s| %5.1f%% %5.1f%% %5.1f%%%s%5.1f%% %5d | %4.0f%% %4.0f%% | %-5s %-5s | %s"
                  % ("t%d" % key[2], key[3], d, 100 * f0, v0, 100 * eS, 100 * fS, vS, flip,
                     100 * nmed, 100 * np5, 100 * np95, straddle, pctl, n, pv, pf, orat, oflr, reading))
    print()
    print("  cell/m/d      the (threads, m) rung and how many of its 8 legs steal < %.2f%% removes" % THRESHOLD)
    print("  floor0/v0     the A/A floor and verdict over all 8 legs (the PUBLISHED reading)")
    print("  effS          the filtered rung's EFFECT, max(F/T, T/F) - 1, on the floor's")
    print("                own scale; `!` after np95 marks a null of floors that STRADDLES")
    print("                it, which is a rung whose verdict is decided by which legs")
    print("                survived rather than by the arms")
    print("  floorS/vS     the floor and verdict after the steal filter; `*` marks a FLIP")
    print("  nmed/np5/np95 the enumerated null of floors under a random d-leg drop")
    print("  pctl          where floorS sits in that null (share of members at or below it)")
    print("  n             the null's size - C(8, d), the WHOLE family, not a sample")
    print("  P(vS)         share of random d-drops that reach the steal filter's verdict")
    print("  P(fl)         share of random d-drops that flip the verdict AT ALL")
    print("  ratio/floor   counterfactuals: the filtered ratio against the UNFILTERED")
    print("                floor, and the unfiltered ratio against the FILTERED floor -")
    print("                which half of the filter the flip is attributable to")
    return rows


def read_row(v0, vS, only_ratio, only_floor, pf, floors):
    if vS == v0:
        return "no flip"
    bits = []
    if only_floor == vS and only_ratio != vS:
        bits.append("FLOOR alone")
    elif only_ratio == vS and only_floor != vS:
        bits.append("RATIO alone")
    elif only_ratio == vS and only_floor == vS:
        bits.append("either half")
    else:
        bits.append("needs both")
    bits.append("%.0f%% of drops flip" % pf)
    return "; ".join(bits)


def global_null(ndraw, seed):
    """The whole-file draw - the MIXTURE the per-rung enumeration conditions.

    Kept because it is the spelling `stealsub.py sample n seed` offers and the
    one the retrospective used, so the two instruments can be compared. It is
    the looser of the two: a draw removes a random NUMBER of legs from each
    rung, so a rung's reading here mixes d = 0 (no change at all) with d = 3."""
    lad = load()
    n = len(kept(lad))
    print("floornull --global: %d draws of %d legs from %d, seed %d "
          "(the steal filter keeps %d)" % (ndraw, n, len(lad), seed, n))
    base = {k: reduce_cell(c) for k, c in cells(lad).items()}
    steal = {k: reduce_cell(kept(c)) for k, c in cells(lad).items()}
    acc = {k: {"floor": [], "v": []} for k in base}
    perdraw = []
    rng = random.Random(seed)
    for _ in range(ndraw):
        draw = rng.sample(lad, n)
        flips = 0
        for k, c in cells(draw).items():
            r = reduce_cell(c)
            if r is not None:
                acc[k]["floor"].append(r[0])
                acc[k]["v"].append(r[2])
                flips += r[2] != base[k][2]
        perdraw.append(flips)
    nsteal = sum(1 for k in base if steal[k][2] != base[k][2])
    print("  %-5s %4s | %6s %-6s | %6s %-6s | %6s %6s %6s %6s | %5s %5s"
          % ("cell", "m", "floor0", "v0", "floorS", "vS", "nmed", "np5", "np95", "pctl", "P(vS)", "P(fl)"))
    for k in sorted(base, key=lambda k: (k[2], k[3])):
        f0, _, v0 = base[k]
        fS, _, vS = steal[k]
        fl, vv = acc[k]["floor"], acc[k]["v"]
        if not fl:
            sys.exit("REFUSED: rung %s reduced in none of the %d draws" % (k, ndraw))
        print("  %-5s %4d | %5.1f%% %-6s | %5.1f%% %-6s%s| %5.1f%% %5.1f%% %5.1f%% %5.1f%% | %4.0f%% %4.0f%%"
              % ("t%d" % k[2], k[3], 100 * f0, v0, 100 * fS, vS, "*" if vS != v0 else " ",
                 100 * st.median(fl), 100 * quant(fl, 0.05), 100 * quant(fl, 0.95),
                 pct_le(fl, fS), 100.0 * sum(1 for v in vv if v == vS) / len(vv),
                 100.0 * sum(1 for v in vv if v != v0) / len(vv)))
    # THE SUMMARY LINE, and it is the one a reader should take away. A random
    # drop of the steal filter's own size flips verdicts at rungs the steal
    # filter leaves alone, and flips about as MANY of them. Flipping is a
    # property of dropping legs from a worst-over-reps floor; it is not a
    # property of steal.
    print()
    print("  the steal filter flips %d of the %d rungs." % (nsteal, len(base)))
    print("  a random drop of the SAME SIZE flips %.2f rungs on average (min %d, "
          "median %d, max %d over %d draws);"
          % (st.fmean(perdraw), min(perdraw), st.median(perdraw), max(perdraw), ndraw))
    print("  %.0f%% of random draws flip AT LEAST as many rungs as the steal filter does."
          % (100.0 * sum(1 for f in perdraw if f >= nsteal) / len(perdraw)))


def joint():
    """The whole TABLE under the d-MATCHED null, exactly.

    `--global` answers a different question badly: a uniform draw over the file
    removes a RANDOM number of legs from each rung, so a rung that the steal
    filter left whole can lose three, and one it emptied by three can lose
    none. The fair aggregate holds every rung's d at what the steal filter
    actually removed there and randomises only WHICH legs. The cells are
    disjoint sets of legs, so under that null they are independent by
    construction and the distribution of the total flip count is the
    convolution of the per-cell Bernoullis - exact, no draws, no seed."""
    lad = load()
    cs = cells(lad)
    ps, nsteal = [], 0
    print("floornull --joint: the whole table under the d-matched null "
          "(every rung's drop size held at the steal filter's, only WHICH legs randomised)")
    print()
    print("  %-5s %4s %2s | %5s | %-6s -> %-6s | %s" % ("cell", "m", "d", "n", "v0", "vS", "P(a random d-drop flips this rung)"))
    for key in sorted(cs, key=lambda k: (k[2], k[3])):
        c = cs[key]
        d, fam, _ = enumerate_cell(c)
        base, sf = reduce_cell(c), reduce_cell(kept(c))
        if base is None:
            sys.exit("REFUSED: cell %s does not reduce over its whole 8 legs" % (key,))
        v0 = base[2]
        # A rung the filter emptied carries no verdict, so it is not a flip.
        vS = sf[2] if sf is not None else "GONE"
        # `fam` can be EMPTY - at a tight threshold a rung can be cut to so
        # few legs that every way of dropping that many empties an arm group.
        # Such a rung has no null and no verdict; it contributes nothing.
        pf = 0.0 if (d == 0 or not fam) else sum(1 for _, _, v in fam if v != v0) / len(fam)
        ps.append(pf)
        nsteal += vS != v0
        print("  %-5s %4d %2d | %5d | %-6s -> %-6s%s| %.4f"
              % ("t%d" % key[2], key[3], d, len(fam) if d else 1, v0, vS,
                 "*" if vS != v0 else " ", pf))
    dist = [1.0]
    for pf in ps:
        nxt = [0.0] * (len(dist) + 1)
        for i, w in enumerate(dist):
            nxt[i] += w * (1 - pf)
            nxt[i + 1] += w * pf
        dist = nxt
    exp = sum(i * w for i, w in enumerate(dist))
    tail = sum(w for i, w in enumerate(dist) if i >= nsteal)
    print()
    print("  the steal filter flips %d of %d rungs." % (nsteal, len(ps)))
    print("  under the d-matched null the EXPECTED number of flips is %.2f, "
          "sd %.2f," % (exp, (sum((i - exp) ** 2 * w for i, w in enumerate(dist))) ** 0.5))
    print("  and P(a random same-size drop flips %d or more) = %.4f." % (nsteal, tail))
    print()
    print("  distribution of the flip count under that null:")
    print("    " + "  ".join("%d:%.3f" % (i, w) for i, w in enumerate(dist) if w >= 5e-4))
    print()
    print("  READ THIS AGAINST THE PER-RUNG TABLE AND NOT INSTEAD OF IT. The two")
    print("  answer different questions and both answers are real: no INDIVIDUAL")
    print("  flip is established (every one is reproduced by chance 21% to 82% of")
    print("  the time, and three of them sit in 8-member nulls whose smallest")
    print("  attainable P is 0.125), while the SET of them is not chance - which")
    print("  says steal predicts WHICH leg owns the A/A worst, and nothing about")
    print("  whether any one rung's verdict can now be read.")
    print()
    print("  AND THIS IS A CALIBRATION, NOT A SIZED HYPOTHESIS TEST. The statistic")
    print("  is computed on the round that raised the question, so 0.0032 prices")
    print("  the coincidence and does not license a decision - the same limit the")
    print("  guest-steal retrospective states about its own nulls.")


ROW = re.compile(r"^\s+(\d+) \|\s+([\d.]+)\s+([\d.]+)\s+([\d.]+) \|\s+([\d.]+)%\s+([\d.]+)%"
                 r"\s+([\d.]+)% \| (\S+)\s+\|")
HDR = re.compile(r"^== (\S+) (repair|create) threads=(\d+)\b")


def parse_rowgate(path):
    """rowgate.py read's printed ladder as {(threads, m): (floor_pct, verdict)}."""
    out = subprocess.run([sys.executable, ROWGATE, "read", path],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("REFUSED: rowgate.py read exited %d: %s" % (out.returncode, out.stderr.strip()))
    got, t = {}, None
    for line in out.stdout.splitlines():
        h = HDR.match(line)
        if h:
            t = int(h.group(3))
            continue
        m = ROW.match(line)
        if m and t is not None:
            got[(t, int(m.group(1)))] = (float(m.group(7)), m.group(8))
    return got


def selftest():
    """Pin this file's reduction to rowgate.py's OWN printed table, at both the
    unfiltered and the steal-filtered setting, and REFUSE on anything missing."""
    fails = []

    def check(name, ok, detail=""):
        print("%-4s %s%s" % ("ok" if ok else "FAIL", name, "" if ok else "   <- " + str(detail)))
        if not ok:
            fails.append(name)

    for p, what in ((LEGS, "the banked legs"), (ROWGATE, "rowgate.py"), (STEALSUB, "stealsub.py")):
        if not os.path.exists(p):
            sys.exit("REFUSED: %s is not at %s - a selftest that cannot find its "
                     "subject must refuse, never skip" % (what, p))
    lad = load()
    check("the round is the banked 64 KiB EPYC ladder", len(lad) == 160, len(lad))
    check("every cell is 8 legs (4 arms x 2 reps)",
          set(len(c) for c in cells(lad).values()) == {8},
          sorted(set(len(c) for c in cells(lad).values())))

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "lt8.jsonl")
        with open(f, "w") as fh:
            sub = subprocess.run([sys.executable, STEALSUB, "keep", "%.2f" % THRESHOLD, LEGS],
                                 capture_output=True, text=True)
            if sub.returncode != 0:
                sys.exit("REFUSED: stealsub.py keep exited %d: %s" % (sub.returncode, sub.stderr.strip()))
            fh.write(sub.stdout)
        check("stealsub keeps the 179 legs the retrospective's 4.1 table names",
              len(sub.stdout.strip().splitlines()) == 179, len(sub.stdout.strip().splitlines()))
        for label, path, legs in (("unfiltered", LEGS, lad),
                                  ("steal < 8.00", f, [json.loads(l) for l in open(f) if l.strip()])):
            want = parse_rowgate(path)
            if not want:
                sys.exit("REFUSED: parsed ZERO rows out of rowgate.py read %s - the "
                         "table regex has stopped matching, which is the failure a "
                         "selftest exists to catch" % path)
            lad2 = [r for r in legs if r["phase"] in ("ladder", "rowgate", "create")]
            mine = {}
            for k, c in cells(lad2).items():
                r = reduce_cell(c)
                if r is not None:
                    mine[(k[2], k[3])] = r
            check("%s: every rowgate row is reproduced here (%d rows)" % (label, len(want)),
                  set(want) == set(mine), (sorted(set(want) ^ set(mine))))
            bad = [(k, want[k], mine[k]) for k in want if k in mine
                   and (abs(100 * mine[k][0] - want[k][0]) > 0.051 or mine[k][2] != want[k][1])]
            check("%s: floor to rowgate's own 0.1%% and verdict exact" % label, not bad, bad[:3])
            check("%s: reached a non-trivial number of rows" % label, len(want) >= 19, len(want))

    # The enumeration itself.
    c = cells(lad)[("64k", "repair", 8, 224)]
    d, fam, nfam = enumerate_cell(c)
    check("t8 m=224 drops ONE leg, so its whole null is EIGHT members",
          (d, nfam) == (1, 8), (d, nfam))
    check("every member of an 8-choose-7 family still reduces", len(fam) == 8, len(fam))
    d2, fam2, n2 = enumerate_cell(cells(lad)[("64k", "repair", 8, 128)])
    check("t8 m=128 drops TWO, so C(8,2) = 28", (d2, n2) == (2, 28), (d2, n2))
    check("the full-8 reduction is not a member of a d>0 family",
          reduce_cell(c) not in fam, "full cell appeared in the drop family")
    # Exact binary fractions on purpose: 1.10 and 0.10 are not representable
    # and the boundary test would be testing float rounding rather than call().
    check("call() is strict - an effect EQUAL to the floor is unresolved",
          call(1.25, 0.25) == "unres" and call(1.5, 0.25) == "ntt")
    check("call() is symmetric about 1.0",
          call(1 / 1.25, 0.25) == "unres" and call(1 / 1.5, 0.25) == "fold")
    check("a drop that empties an arm group is not a verdict",
          reduce_cell([r for r in c if r["arm"] in ("fold", "fold2")]) is None)
    check("pct_le puts a maximum at 100 and a unique minimum at its share",
          pct_le([1.0, 2.0, 3.0, 4.0], 4.0) == 100.0 and pct_le([1.0, 2.0, 3.0, 4.0], 1.0) == 25.0)

    # C(8,4) = 70, but two of those subsets keep one whole arm group and
    # nothing of the other, which rowgate.py drops from its table rather than
    # calling. The enumeration must not count them as verdicts.
    n4 = len([x for x in (reduce_cell(list(t)) for t in
                          itertools.combinations(cells(lad)[("64k", "repair", 8, 96)], 4))
              if x is not None])
    check("of the C(8,4) = 70 four-leg keeps, exactly 68 are a verdict", n4 == 68, n4)

    # The published-threshold finding, pinned: the rungs that FLIP are exactly
    # the rungs whose null of floors straddles their own effect. If the legs or
    # rowgate.py ever move, this goes red on the author's own preflight run
    # rather than leaving a landed claim quietly false.
    flips, strad = set(), set()
    for key, c in cells(lad).items():
        b, sf = reduce_cell(c), reduce_cell(kept(c))
        d, fam, _ = enumerate_cell(c)
        if d == 0 or sf is None or not fam:
            continue
        fl = [f for f, _, _ in fam]
        if sf[2] != b[2]:
            flips.add((key[2], key[3]))
        if quant(fl, 0.05) <= effect(sf[1]) <= quant(fl, 0.95):
            strad.add((key[2], key[3]))
    check("SEVEN rungs flip at steal < 8.00%, not the three the handoff names",
          len(flips) == 7, sorted(flips))
    check("the flipping rungs are EXACTLY the straddled ones", flips == strad,
          sorted(flips ^ strad))
    check("the three the handoff names are among them",
          {(8, 128), (8, 160), (8, 224)} <= flips, sorted(flips))
    check("no flip is reproduced by chance less than 20% of the time",
          min(sum(1 for _, _, v in enumerate_cell(cells(lad)[("64k", "repair", t, m)])[1]
                  if v != reduce_cell(cells(lad)[("64k", "repair", t, m)])[2])
              / len(enumerate_cell(cells(lad)[("64k", "repair", t, m)])[1])
              for (t, m) in flips) >= 0.20)

    # A rung the filter cuts below a fittable shape is GONE, not a flip. At
    # steal < 5.00% the t8 m=160 rung keeps one leg, so rowgate.py drops it
    # from the table entirely and every member of its family does too.
    c160 = cells(lad)[("64k", "repair", 8, 160)]
    k160 = kept(c160, 5.00)
    check("at steal < 5.00% t8 m=160 keeps one leg", len(k160) == 1, len(k160))
    check("a rung cut to one leg has NO verdict and NO null",
          reduce_cell(k160) is None and
          all(reduce_cell(list(t)) is None for t in itertools.combinations(c160, 1)))

    if fails:
        print("---\nFAILED %d: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("---\nfloornull selftest green on %s: the reduction reproduces rowgate.py's "
          "own table at both settings." % sys.platform)
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    # `--thr` re-runs the whole table at another rung of stealsub.py's ladder.
    # The banked table is the < 8.00% rung, which is the one the retrospective's
    # section 4.1 quotes; the others are here so a reader can check that the
    # shape of the answer does not turn on that choice.
    if a and a[0] == "--selftest":
        raise SystemExit(selftest())
    if a and a[0] == "--thr":
        THRESHOLD = float(a[1])
        a = a[2:]
    if a and a[0] == "--joint":
        joint()
        raise SystemExit(0)
    if a and a[0] == "--global":
        global_null(int(a[1]) if len(a) > 1 else 200, int(a[2]) if len(a) > 2 else 7)
        raise SystemExit(0)
    if a:
        raise SystemExit("floornull: unknown argument %r (--thr X, --joint, --global N SEED, --selftest)" % a[0])
    table()
